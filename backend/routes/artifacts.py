#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes artefacts : upload de fichiers, listing et outil de hachage."""

import datetime
import hashlib
import json
import os

from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.utils import secure_filename

from auth import require_auth
from database import get_db, log_audit
from helpers import allowed_file, compute_file_hashes, paginate_query
from extensions import ALLOWED_EXTENSIONS

bp = Blueprint('artifacts', __name__)


@bp.route('/api/upload', methods=['POST'])
@require_auth
def upload_file():
    """Upload de fichier pour analyse avec validation d'extension et calcul de hashes"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Aucun fichier fourni'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nom de fichier vide'}), 400

        # Securiser le nom de fichier
        filename = secure_filename(file.filename)

        # Valider l'extension
        if not allowed_file(filename):
            return jsonify({
                'error': f'Extension de fichier non autorisee. Extensions valides: {", ".join(sorted(ALLOWED_EXTENSIONS))}'
            }), 400

        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp_str}_{filename}"

        # Sauvegarder le fichier
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)

        # Calculer les empreintes
        md5_hash, sha1_hash, sha256_hash = compute_file_hashes(filepath)
        file_size = os.path.getsize(filepath)

        # Inserer l'artefact dans la base si une investigation_id est fournie
        investigation_id = request.form.get('investigation_id')
        artifact_id = None

        if investigation_id:
            db = get_db()
            inv_exists = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
            if inv_exists:
                ext = os.path.splitext(filename)[1].lower()
                cursor = db.execute(
                    "INSERT INTO artifacts (investigation_id, filename, original_filename, file_path, file_size, file_hash_md5, file_hash_sha1, file_hash_sha256, file_type, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (investigation_id, unique_filename, filename, filepath, file_size, md5_hash, sha1_hash, sha256_hash, ext, g.user_id)
                )
                db.execute("UPDATE investigations SET updated_at=? WHERE id=?", (datetime.datetime.now().isoformat(), investigation_id))
                db.commit()
                artifact_id = cursor.lastrowid

                # Journaliser l'upload
                log_audit(
                    g.user_id, g.username, 'upload_artifact',
                    target_type='artifact', target_id=str(artifact_id),
                    details=json.dumps({'filename': filename, 'investigation_id': investigation_id, 'sha256': sha256_hash}),
                    ip_address=request.remote_addr
                )

        return jsonify({
            'filename': unique_filename,
            'original_filename': filename,
            'filepath': filepath,
            'size': file_size,
            'artifact_id': artifact_id,
            'hashes': {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash
            },
            'message': 'Fichier uploade avec succes'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/investigations/<investigation_id>/artifacts', methods=['GET'])
@require_auth
def get_investigation_artifacts(investigation_id):
    """Recuperer la liste paginee des artefacts d'une enquete"""
    try:
        db = get_db()
        existing = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        result = paginate_query(
            "SELECT * FROM artifacts WHERE investigation_id=? ORDER BY uploaded_at DESC",
            (investigation_id,),
            "SELECT COUNT(*) FROM artifacts WHERE investigation_id=?",
            (investigation_id,)
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/tools/hash', methods=['POST'])
@require_auth
def calculate_file_hash():
    """Calculer les empreintes MD5, SHA1 et SHA256 d'un fichier uploade"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Aucun fichier fourni'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nom de fichier vide'}), 400

        # Lire le contenu du fichier en memoire pour calculer les empreintes
        file_content = file.read()

        md5_hash = hashlib.md5(file_content).hexdigest()
        sha1_hash = hashlib.sha1(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()

        return jsonify({
            'filename': secure_filename(file.filename),
            'size': len(file_content),
            'hashes': {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
