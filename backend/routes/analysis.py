#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes analyse : lancement asynchrone d'analyses d'artefacts et suivi de progression."""

import datetime
import json
import logging
import os
import uuid

from flask import Blueprint, current_app, g, jsonify, request

import access
import evidence_vault
from auth import require_auth, require_role
from database import get_db, log_audit, dict_from_row
from extensions import analysis_progress, emit_secure, executor
from helpers import path_within, resolve_upload_path, server_error
from parsers import analyze_file_standalone, extract_iocs
import phoenix_compat

bp = Blueprint('analysis', __name__)
_logger = logging.getLogger('phoenix')

# analysis_id -> (user_id, investigation_id) : controle d'acces du suivi
_analysis_owners = {}


def _artifact_file(row, upload_folder):
    """Chemin d'un artefact en base, uniquement s'il est dans les uploads ou le coffre."""
    path = row['file_path']
    if not path:
        path = resolve_upload_path(upload_folder, row['filename'] or '')
    if not path or not os.path.isfile(path):
        return None
    if path_within(path, upload_folder) or evidence_vault.contains(path):
        return os.path.realpath(path)
    return None


@bp.route('/api/analyze', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def analyze_file():
    """Analyser un artefact (artifact_id) ou un upload (filename) via Phoenix ou le parser standalone"""
    try:
        data = request.get_json(silent=True) or {}
        artifact_id = data.get('artifact_id')
        filename = data.get('filename')
        query = str(data.get('query') or 'Analyse generale du fichier')
        investigation_id = data.get('investigation_id') or None
        event_id_filter = data.get('event_id_filter')
        upload_folder = current_app.config['UPLOAD_FOLDER']
        db = get_db()

        if artifact_id is not None:
            # Mode recommande : l'artefact est resolu en base, jamais depuis un
            # chemin fourni par le client.
            try:
                artifact_id = int(artifact_id)
            except (TypeError, ValueError):
                return jsonify({'error': 'artifact_id invalide'}), 400
            row = db.execute("SELECT * FROM artifacts WHERE id=?", (artifact_id,)).fetchone()
            if not row or not access.can_access_investigation(g.user_id, g.role, row['investigation_id'], db):
                return jsonify({'error': 'Artefact non trouve'}), 404
            if investigation_id and investigation_id != row['investigation_id']:
                return jsonify({'error': 'L\'artefact n\'appartient pas a cette enquete'}), 400
            investigation_id = row['investigation_id']
            filename = row['filename']
            filepath = _artifact_file(row, upload_folder)
            if not filepath:
                return jsonify({'error': 'Fichier non trouve'}), 404
        else:
            # Retro-compat : nom de fichier stocke, strictement dans le dossier d'uploads
            if not filename:
                return jsonify({'error': 'artifact_id ou nom de fichier requis'}), 400
            filepath = resolve_upload_path(upload_folder, filename)
            if not filepath:
                return jsonify({'error': 'Fichier non trouve'}), 404
            # Un fichier rattache a une enquete inaccessible reste invisible
            owners = db.execute("SELECT DISTINCT investigation_id FROM artifacts WHERE filename=?",
                                (filename,)).fetchall()
            if owners and not any(access.can_access_investigation(g.user_id, g.role, o[0], db)
                                  for o in owners):
                return jsonify({'error': 'Fichier non trouve'}), 404

        if investigation_id:
            denied = access.require_investigation_access(investigation_id, write=True)
            if denied:
                return denied

        # Generer un ID d'analyse unique
        analysis_id = str(uuid.uuid4())
        analysis_progress[analysis_id] = {'progress': 0, 'status': 'starting'}
        _analysis_owners[analysis_id] = (g.user_id, investigation_id)

        # Capturer les infos utilisateur et l'application pour le thread
        user_id = g.user_id
        username = g.username
        app = current_app._get_current_object()

        def emit_progress(payload):
            payload = dict(payload, analysis_id=analysis_id)
            if investigation_id:
                payload['investigation_id'] = investigation_id
            emit_secure('analysis_progress', payload, investigation_id=investigation_id, user_id=user_id)

        # Lancer l'analyse dans le pool de threads
        def run_analysis():
            try:
                emit_progress({'progress': 10, 'status': 'Chargement du fichier...'})
                emit_progress({'progress': 30, 'status': 'Analyse en cours...'})

                # Effectuer l'analyse
                if phoenix_compat.PHOENIX_AVAILABLE:
                    # Charger les donnees d'investigation pour Phoenix
                    investigation_data = {}
                    if investigation_id:
                        with app.app_context():
                            db = get_db()
                            inv_row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
                            if inv_row:
                                investigation_data = dict_from_row(inv_row)

                    result = phoenix_compat.analyse_fichier(filepath, query, investigation_data, event_id_filter)
                    result_text = str(result)

                    # Extraire et sauvegarder les conclusions via Phoenix
                    if investigation_data:
                        phoenix_compat.extraire_et_sauvegarder_conclusions(
                            investigation_data, result_text, filename
                        )
                else:
                    # Mode standalone : parser natif sans IA
                    parsed = analyze_file_standalone(filepath, event_id_filter)
                    result_text = parsed.get('summary', 'Aucun resultat')

                    if parsed.get('error'):
                        result_text = f"Erreur: {parsed['error']}\n{result_text}"

                    # Extraction automatique des IoCs et insertion en base
                    if investigation_id and parsed.get('iocs'):
                        with app.app_context():
                            db = get_db()
                            for ioc in parsed['iocs']:
                                try:
                                    db.execute(
                                        "INSERT OR IGNORE INTO iocs (investigation_id, type, value, source) VALUES (?, ?, ?, ?)",
                                        (investigation_id, ioc['type'], ioc['value'], ioc.get('source', 'auto-extract'))
                                    )
                                except Exception:
                                    pass
                            db.execute("UPDATE investigations SET updated_at=? WHERE id=?", (datetime.datetime.now().isoformat(), investigation_id))
                            db.commit()

                emit_progress({'progress': 70, 'status': 'Extraction des IoCs...'})

                # Extraire les IoCs du resultat textuel et les inserer en base
                if investigation_id and result_text:
                    text_iocs = extract_iocs(result_text)
                    if text_iocs:
                        with app.app_context():
                            db = get_db()
                            for ioc in text_iocs:
                                try:
                                    db.execute(
                                        "INSERT OR IGNORE INTO iocs (investigation_id, type, value, source) VALUES (?, ?, ?, ?)",
                                        (investigation_id, ioc['type'], ioc['value'], ioc.get('source', 'auto-extract'))
                                    )
                                except Exception:
                                    pass
                            db.commit()

                # Mettre a jour le resultat d'analyse de l'artefact en base
                if investigation_id:
                    with app.app_context():
                        db = get_db()
                        db.execute(
                            "UPDATE artifacts SET analysis_result=? WHERE investigation_id=? AND filename=?",
                            (result_text[:50000], investigation_id, filename)
                        )
                        db.commit()

                emit_progress({'progress': 100, 'status': 'Analyse terminee', 'result': result_text})

                analysis_progress[analysis_id] = {
                    'progress': 100,
                    'status': 'completed',
                    'result': result_text
                }

                # Journaliser l'analyse (dans le contexte applicatif)
                with app.app_context():
                    log_audit(
                        user_id, username, 'analyze_file',
                        target_type='artifact', target_id=filename,
                        details=json.dumps({'investigation_id': investigation_id, 'query': query[:200]}),
                        ip_address=None
                    )

            except Exception:
                # Detail dans les logs serveur uniquement
                _logger.exception('analysis_failed', extra={'analysis_id': analysis_id})
                emit_progress({'progress': 100, 'status': 'error', 'error': "Erreur pendant l'analyse"})
                analysis_progress[analysis_id] = {
                    'progress': 100,
                    'status': 'error',
                    'error': "Erreur pendant l'analyse"
                }

        # Soumettre au pool de threads
        executor.submit(run_analysis)

        return jsonify({
            'analysis_id': analysis_id,
            'message': 'Analyse demarree',
            'status': 'started'
        })

    except Exception as e:
        return server_error(e)


@bp.route('/api/analysis/<analysis_id>/status', methods=['GET'])
@require_auth
def get_analysis_status(analysis_id):
    """Recuperer le statut d'une analyse (lanceur, membres de l'enquete ou admin)"""
    owner = _analysis_owners.get(analysis_id)
    if analysis_id not in analysis_progress or not owner:
        return jsonify({'error': 'Analyse non trouvee'}), 404
    owner_id, investigation_id = owner
    allowed = (g.role == 'admin' or owner_id == g.user_id
               or (investigation_id and access.can_access_investigation(g.user_id, g.role, investigation_id)))
    if not allowed:
        return jsonify({'error': 'Analyse non trouvee'}), 404
    return jsonify(analysis_progress[analysis_id])
