#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes de l'enqueteur DFIR autonome (GitHub Copilot + boite a outils MCP)."""

from flask import Blueprint, current_app, g, jsonify, request

import autonomous
import watcher
from auth import require_auth
from database import get_db

bp = Blueprint('autonomous', __name__)


@bp.route('/api/autonomous/status', methods=['GET'])
@require_auth
def autonomous_status():
    """Etat de l'enqueteur autonome : Copilot, dossier de depot, jobs."""
    running = sum(1 for j in autonomous.autonomous_jobs.values() if j.get('status') == 'running')
    return jsonify({
        'copilot_configured': autonomous.copilot_configured(),
        'model': autonomous.copilot_model(),
        'inbox_dir': watcher.inbox_dir(),
        'inbox_watcher_active': watcher.is_active(),
        'jobs_running': running,
    })


@bp.route('/api/autonomous/investigate', methods=['POST'])
@require_auth
def start_autonomous_investigation():
    """Lancer l'investigation autonome sur les artefacts d'une enquete."""
    data = request.get_json() or {}
    investigation_id = data.get('investigation_id')
    question = (data.get('question') or '').strip()[:2000] or None

    if not investigation_id:
        return jsonify({'error': "ID d'enquete requis"}), 400
    if not autonomous.copilot_configured():
        return jsonify({'error': ("GitHub Copilot non configure : definissez GITHUB_TOKEN "
                                  "(jeton GitHub, permission Models: read) puis redemarrez le backend.")}), 400

    db = get_db()
    inv = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
    if not inv:
        return jsonify({'error': 'Enquete non trouvee'}), 404
    count = db.execute("SELECT COUNT(*) FROM artifacts WHERE investigation_id=?",
                       (investigation_id,)).fetchone()[0]
    if count == 0:
        return jsonify({'error': "Aucun artefact dans cette enquete : uploadez d'abord les evidences."}), 400

    app = current_app._get_current_object()
    job_id = autonomous.start_job(app, investigation_id, question=question,
                                  user_id=g.user_id, username=g.username)
    return jsonify({
        'job_id': job_id,
        'investigation_id': investigation_id,
        'artifacts': count,
        'message': "Investigation autonome demarree - suivez la progression en temps reel.",
        'status': 'started',
    })


@bp.route('/api/autonomous/jobs/<job_id>', methods=['GET'])
@require_auth
def get_autonomous_job(job_id):
    """Recuperer l'etat / le resultat d'un job autonome."""
    job = autonomous.autonomous_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job non trouve'}), 404
    return jsonify(job)
