#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes analyse : lancement asynchrone d'analyses d'artefacts et suivi de progression."""

import datetime
import json
import os
import uuid

from flask import Blueprint, current_app, g, jsonify, request

from auth import require_auth
from database import get_db, log_audit, dict_from_row
from extensions import analysis_progress, executor, socketio
from parsers import analyze_file_standalone, extract_iocs
import phoenix_compat

bp = Blueprint('analysis', __name__)


@bp.route('/api/analyze', methods=['POST'])
@require_auth
def analyze_file():
    """Analyser un fichier via Phoenix ou le parser standalone"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        query = data.get('query', 'Analyse generale du fichier')
        investigation_id = data.get('investigation_id')
        event_id_filter = data.get('event_id_filter')

        if not filename:
            return jsonify({'error': 'Nom de fichier requis'}), 400

        filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

        if not os.path.exists(filepath):
            return jsonify({'error': 'Fichier non trouve'}), 404

        # Generer un ID d'analyse unique
        analysis_id = str(uuid.uuid4())
        analysis_progress[analysis_id] = {'progress': 0, 'status': 'starting'}

        # Capturer les infos utilisateur et l'application pour le thread
        user_id = g.user_id
        username = g.username
        app = current_app._get_current_object()

        # Lancer l'analyse dans le pool de threads
        def run_analysis():
            try:
                # Progression: chargement
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 10,
                    'status': 'Chargement du fichier...'
                })

                # Progression: analyse en cours
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 30,
                    'status': 'Analyse en cours...'
                })

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

                # Progression: extraction des IoCs
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 70,
                    'status': 'Extraction des IoCs...'
                })

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

                # Progression: termine
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 100,
                    'status': 'Analyse terminee',
                    'result': result_text
                })

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

            except Exception as e:
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 100,
                    'status': 'error',
                    'error': str(e)
                })
                analysis_progress[analysis_id] = {
                    'progress': 100,
                    'status': 'error',
                    'error': str(e)
                }

        # Soumettre au pool de threads
        executor.submit(run_analysis)

        return jsonify({
            'analysis_id': analysis_id,
            'message': 'Analyse demarree',
            'status': 'started'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/analysis/<analysis_id>/status', methods=['GET'])
@require_auth
def get_analysis_status(analysis_id):
    """Recuperer le statut d'une analyse"""
    if analysis_id in analysis_progress:
        return jsonify(analysis_progress[analysis_id])
    else:
        return jsonify({'error': 'Analyse non trouvee'}), 404
