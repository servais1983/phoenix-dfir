#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes artefacts : upload de fichiers, listing et outil de hachage."""

import datetime
import hashlib
import json
import os
import uuid

from flask import Blueprint, current_app, g, jsonify, request
from werkzeug.utils import secure_filename

import access
import custody
from auth import require_auth, require_role
from database import get_db, log_audit
from helpers import allowed_file, paginate_query, server_error
from extensions import ALLOWED_EXTENSIONS

bp = Blueprint('artifacts', __name__)

CHUNK_SIZE = 1024 * 1024


def _stream_hashes(stream, out=None):
    """Lire un flux par blocs : empreintes MD5/SHA1/SHA256, taille, copie optionnelle.

    Le fichier n'est jamais charge entierement en memoire.
    """
    md5 = hashlib.md5(usedforsecurity=False)  # nosec B324 - empreinte forensique, pas un usage cryptographique
    sha1 = hashlib.sha1(usedforsecurity=False)  # nosec B324
    sha256 = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(CHUNK_SIZE)
        if not chunk:
            break
        size += len(chunk)
        md5.update(chunk)
        sha1.update(chunk)
        sha256.update(chunk)
        if out is not None:
            out.write(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), size


@bp.route('/api/upload', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def upload_file():
    """Upload de fichier pour analyse avec validation d'extension et calcul de hashes"""
    try:
        # Enquete cible : acces en ecriture verifie AVANT d'ecrire le fichier
        investigation_id = request.form.get('investigation_id') or None
        if investigation_id:
            denied = access.require_investigation_access(investigation_id, write=True)
            if denied:
                return denied

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

        # Nom stocke unique (horodatage + uuid) : deux uploads simultanes du
        # meme fichier ne s'ecrasent jamais ('xb' = creation exclusive O_EXCL).
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp_str}_{uuid.uuid4().hex[:12]}_{filename}"

        # Sauvegarder le fichier par blocs en calculant les empreintes
        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
        with open(filepath, 'xb') as out:
            md5_hash, sha1_hash, sha256_hash, file_size = _stream_hashes(file.stream, out)

        # Inserer l'artefact dans la base si une investigation_id est fournie
        artifact_id = None

        if investigation_id:
            db = get_db()
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
            custody.safe_record(
                'evidence_acquired', g.username, investigation_id=investigation_id,
                agent='Agent Triage & Collecte', artifact_ref=filename,
                summary=f'Evidence uploadee ({file_size} octets)',
                details={'artifact_id': artifact_id, 'md5': md5_hash, 'sha1': sha1_hash,
                         'source': 'upload'},
                payload_sha256=sha256_hash)

        # Le chemin absolu sur le serveur n'est jamais renvoye au client
        return jsonify({
            'filename': unique_filename,
            'original_filename': filename,
            'size': file_size,
            'artifact_id': artifact_id,
            'investigation_id': investigation_id,
            'hashes': {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash
            },
            'message': 'Fichier uploade avec succes'
        })

    except Exception as e:
        return server_error(e)


@bp.route('/api/investigations/<investigation_id>/artifacts', methods=['GET'])
@require_auth
def get_investigation_artifacts(investigation_id):
    """Recuperer la liste paginee des artefacts d'une enquete"""
    try:
        denied = access.require_investigation_access(investigation_id)
        if denied:
            return denied

        result = paginate_query(
            "SELECT * FROM artifacts WHERE investigation_id=? ORDER BY uploaded_at DESC",
            (investigation_id,),
            "SELECT COUNT(*) FROM artifacts WHERE investigation_id=?",
            (investigation_id,)
        )
        # Ne jamais exposer le chemin absolu des evidences sur le serveur
        for item in result['items']:
            item.pop('file_path', None)

        return jsonify(result)

    except Exception as e:
        return server_error(e)


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

        # Hachage par blocs depuis le flux : jamais tout le fichier en memoire
        md5_hash, sha1_hash, sha256_hash, size = _stream_hashes(file.stream)

        return jsonify({
            'filename': secure_filename(file.filename),
            'size': size,
            'hashes': {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash
            }
        })

    except Exception as e:
        return server_error(e)
