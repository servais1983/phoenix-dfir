#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes de l'enqueteur DFIR autonome (GitHub Copilot + boite a outils MCP).

Les jobs sont persistes dans la file durable SQLite (jobqueue.py) :
- POST /api/autonomous/investigate           mettre une investigation en file
- GET  /api/autonomous/jobs?investigation_id= lister (controle d'acces par enquete)
- GET  /api/autonomous/jobs/<id>             etat / resultat (y compris apres redemarrage)
- POST /api/autonomous/jobs/<id>/cancel      annuler (proprietaire, analyst membre, admin)
"""

from flask import Blueprint, current_app, g, jsonify, request

import access
import autonomous
import jobqueue
import watcher
from auth import require_auth, require_role
from database import get_db, log_audit

bp = Blueprint('autonomous', __name__)

_LIST_STATUSES = {
    'queued': jobqueue.QUEUED, 'running': jobqueue.RUNNING, 'done': jobqueue.DONE,
    'completed': jobqueue.DONE, 'failed': jobqueue.FAILED, 'error': jobqueue.FAILED,
    'cancelled': jobqueue.CANCELLED,
}


def max_jobs_per_user():
    """Quota de jobs autonomes simultanes par utilisateur (PHOENIX_MAX_JOBS_PER_USER)."""
    return jobqueue.max_jobs_per_user()


def _running_jobs_for(user_id):
    """Jobs actifs (en file ou en cours) de l'utilisateur : base du quota."""
    return len(autonomous.active_job_ids(user_id))


def _can_read_job(job):
    if g.role == 'admin':
        return True
    if job.get('user_id') is not None and job.get('user_id') == g.user_id:
        return True
    inv_id = job.get('investigation_id')
    return bool(inv_id) and access.can_access_investigation(g.user_id, g.role, inv_id)


def _can_cancel_job(job):
    """Admin, proprietaire du job, ou analyst membre de l'enquete du job."""
    if g.role == 'admin':
        return True
    if job.get('user_id') is not None and job.get('user_id') == g.user_id:
        return g.role in access.WRITE_ROLES
    inv_id = job.get('investigation_id')
    return bool(inv_id) and access.can_write_investigation(g.user_id, g.role, inv_id)


@bp.route('/api/autonomous/status', methods=['GET'])
@require_auth
def autonomous_status():
    """Etat de l'enqueteur autonome : Copilot, dossier de depot, jobs."""
    data = {
        'copilot_configured': autonomous.copilot_configured(),
        'llm_provider': autonomous.llm_provider(),
        'llm_label': autonomous.llm_label(),
        'model': autonomous.copilot_model(),
        'inbox_watcher_active': watcher.is_active(),
        'jobs_running': autonomous.count_jobs('running'),
        'jobs_queued': autonomous.count_jobs('queued'),
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
    """Mettre en file l'investigation autonome des artefacts d'une enquete."""
    data = request.get_json(silent=True) or {}
    investigation_id = data.get('investigation_id')
    question = (data.get('question') or '').strip()[:2000] or None

    if not investigation_id:
        return jsonify({'error': "ID d'enquete requis"}), 400

    denied = access.require_investigation_access(investigation_id, write=True)
    if denied:
        return denied

    if not autonomous.copilot_configured():
        return jsonify({'error': ("LLM not configured: use a local LLM (PHOENIX_LLM_PROVIDER=ollama "
                                  "or llamacpp). Cloud providers (OpenAI with OPENAI_API_KEY, GitHub "
                                  "Models with GITHUB_TOKEN) also require PHOENIX_ALLOW_CLOUD_LLM=1. "
                                  "Restart the backend afterwards.")}), 400

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
    job = dict.get(autonomous.autonomous_jobs, job_id)
    if job is not None:
        # Proprietaire du job : quota et controle d'acces en lecture
        job.setdefault('user_id', g.user_id)
    return jsonify({
        'job_id': job_id,
        'investigation_id': investigation_id,
        'artifacts': count,
        'message': "Investigation autonome en file - suivez la progression en temps reel.",
        'status': 'started',
        'state': (job or {}).get('state', jobqueue.QUEUED),
    })


@bp.route('/api/autonomous/jobs', methods=['GET'])
@require_auth
def list_autonomous_jobs():
    """Lister les jobs persistes : ceux d'une enquete accessible, sinon tous
    ceux que l'utilisateur peut voir (les siens + ses enquetes ; admin : tous)."""
    investigation_id = request.args.get('investigation_id') or None
    try:
        limit = max(1, min(int(request.args.get('limit', 50)), 200))
    except ValueError:
        limit = 50
    statuses = None
    raw_status = request.args.get('status')
    if raw_status:
        statuses = tuple({_LIST_STATUSES[s] for s in raw_status.split(',') if s in _LIST_STATUSES})
        if not statuses:
            return jsonify({'error': 'Statut inconnu'}), 400

    if investigation_id:
        denied = access.require_investigation_access(investigation_id)
        if denied:
            return denied
        items = autonomous.list_jobs(investigation_id=investigation_id, statuses=statuses, limit=limit)
    elif g.role == 'admin':
        items = autonomous.list_jobs(statuses=statuses, limit=limit)
    else:
        items = autonomous.list_jobs(owner_id=g.user_id,
                                     investigation_ids=access.accessible_investigation_ids(),
                                     statuses=statuses, limit=limit)
    return jsonify({'items': items, 'total': len(items),
                    'max_jobs_per_user': max_jobs_per_user()})


@bp.route('/api/autonomous/jobs/<job_id>', methods=['GET'])
@require_auth
def get_autonomous_job(job_id):
    """Recuperer l'etat / le resultat d'un job autonome (proprietaire, membres ou admin)."""
    job = autonomous.get_job(job_id)
    if not job or not _can_read_job(job):
        return jsonify({'error': 'Job non trouve'}), 404
    return jsonify(job)


@bp.route('/api/autonomous/jobs/<job_id>/cancel', methods=['POST'])
@require_auth
def cancel_autonomous_job(job_id):
    """Annuler un job en file (immediat) ou en cours (cooperatif)."""
    job = autonomous.get_job(job_id)
    if not job or not _can_read_job(job):
        return jsonify({'error': 'Job non trouve'}), 404
    if not _can_cancel_job(job):
        return jsonify({'error': 'Acces refuse - role insuffisant'}), 403
    if job.get('status') not in autonomous.ACTIVE_LEGACY:
        return jsonify({'error': 'Job deja termine', 'status': job.get('status')}), 409
    status = autonomous.cancel_job(job_id, actor=g.username)
    if status is None:
        return jsonify({'error': 'Job non trouve'}), 404
    log_audit(g.user_id, g.username, 'autonomous_job_cancel', target_type='job', target_id=job_id,
              details=f"investigation={job.get('investigation_id')} status={status}",
              ip_address=request.remote_addr)
    return jsonify({'job_id': job_id, 'status': status,
                    'cancel_requested': True,
                    'message': ('Job annule.' if status == 'cancelled'
                                else "Annulation demandee : arret au prochain point de controle.")})
