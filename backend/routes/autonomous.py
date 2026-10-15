#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes de l'enqueteur DFIR autonome (GitHub Copilot + boite a outils MCP)."""

import os

from flask import Blueprint, current_app, g, jsonify, request

import access
import autonomous
import watcher
from auth import require_auth, require_role
from database import get_db

bp = Blueprint('autonomous', __name__)


def max_jobs_per_user():
    """Quota de jobs autonomes simultanes par utilisateur (PHOENIX_MAX_JOBS_PER_USER)."""
    try:
        return max(1, int(os.environ.get('PHOENIX_MAX_JOBS_PER_USER', '2')))
    except ValueError:
        return 2


def _running_jobs_for(user_id):
    return sum(1 for j in list(autonomous.autonomous_jobs.values())
               if j.get('status') == 'running' and j.get('user_id') == user_id)


def _can_read_job(job):
    if g.role == 'admin':
        return True
    if job.get('user_id') is not None and job.get('user_id') == g.user_id:
        return True
    inv_id = job.get('investigation_id')
    return bool(inv_id) and access.can_access_investigation(g.user_id, g.role, inv_id)


@bp.route('/api/autonomous/status', methods=['GET'])
@require_auth
def autonomous_status():
    """Etat de l'enqueteur autonome : Copilot, dossier de depot, jobs."""
    running = sum(1 for j in list(autonomous.autonomous_jobs.values()) if j.get('status') == 'running')
    data = {
        'copilot_configured': autonomous.copilot_configured(),
        'llm_provider': autonomous.llm_provider(),
        'llm_label': autonomous.llm_label(),
        'model': autonomous.copilot_model(),
        'inbox_watcher_active': watcher.is_active(),
        'jobs_running': running,
        'my_jobs_running': _running_jobs_for(g.user_id),
        'max_jobs_per_user': max_jobs_per_user(),
    }
    # Chemin serveur du dossier de depot : information d'administration
    data['inbox_dir'] = watcher.inbox_dir() if g.role == 'admin' else None
    return jsonify(data)


@bp.route('/api/autonomous/investigate', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def start_autonomous_investigation():
    """Lancer l'investigation autonome sur les artefacts d'une enquete."""
    data = request.get_json(silent=True) or {}
    investigation_id = data.get('investigation_id')
    question = (data.get('question') or '').strip()[:2000] or None

    if not investigation_id:
        return jsonify({'error': "ID d'enquete requis"}), 400

    denied = access.require_investigation_access(investigation_id, write=True)
    if denied:
        return denied

    if not autonomous.copilot_configured():
        return jsonify({'error': ("LLM non configure : definissez GITHUB_TOKEN (jeton GitHub, "
                                  "permission Models: read), PHOENIX_LLM_PROVIDER=ollama "
                                  "(LLM local), ou OPENAI_API_KEY puis redemarrez le backend.")}), 400

    limit = max_jobs_per_user()
    if _running_jobs_for(g.user_id) >= limit:
        return jsonify({'error': f'Quota atteint : {limit} investigation(s) autonome(s) en cours '
                                 'maximum par utilisateur.'}), 429

    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM artifacts WHERE investigation_id=?",
                       (investigation_id,)).fetchone()[0]
    if count == 0:
        return jsonify({'error': "Aucun artefact dans cette enquete : uploadez d'abord les evidences."}), 400

    app = current_app._get_current_object()
    job_id = autonomous.start_job(app, investigation_id, question=question,
                                  user_id=g.user_id, username=g.username)
    job = autonomous.autonomous_jobs.get(job_id)
    if job is not None:
        # Proprietaire du job : quota et controle d'acces en lecture
        job.setdefault('user_id', g.user_id)
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
    """Recuperer l'etat / le resultat d'un job autonome (proprietaire, membres ou admin)."""
    job = autonomous.autonomous_jobs.get(job_id)
    if not job or not _can_read_job(job):
        return jsonify({'error': 'Job non trouve'}), 404
    return jsonify(job)
