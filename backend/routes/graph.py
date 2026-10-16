#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Graphe d'attaque : graphe d'entites d'une enquete / d'un job autonome.

GET /api/investigations/<id>/graph       (membres de l'enquete ; viewer en lecture)
GET /api/autonomous/jobs/<job_id>/graph  (memes regles que le job)

Le moteur ecrit <case_dir>/entity_graph.json ; tant qu'il n'existe pas, 404
avec un message explicite. Mise a jour temps reel : un veilleur leger compare
l'mtime du fichier des enquetes ayant un job autonome et diffuse
'graph_updated' (salle de l'enquete) quand il change.
"""

import os
import threading

from flask import Blueprint, current_app, g, jsonify

import access
import attack_graph
import autonomous
from auth import require_auth
from extensions import emit_secure, socketio

bp = Blueprint('graph', __name__)

NOT_BUILT = ("Graphe d'attaque pas encore construit pour cette enquete : il est produit par "
             "l'Enqueteur IA au fil de l'analyse (entity_graph.json).")
WATCH_INTERVAL = 5

_watch_lock = threading.Lock()
_watch_started = False
_last_mtimes = {}


def cases_root(app=None):
    app = app or current_app
    return os.path.join(app.config['UPLOAD_FOLDER'], 'cases')


def case_dir_for(investigation_id, app=None):
    """Dossier de cas d'une enquete, ou None s'il sortirait du dossier des cas."""
    root = os.path.realpath(cases_root(app))
    target = os.path.realpath(os.path.join(root, str(investigation_id)))
    if os.path.dirname(target) != root:
        return None
    return target


def _graph_response(investigation_id, job_id=None):
    case_dir = case_dir_for(investigation_id)
    if not case_dir:
        return jsonify({'error': NOT_BUILT, 'code': 'graph_not_built'}), 404
    try:
        graph, mtime = attack_graph.load(case_dir)
    except FileNotFoundError:
        return jsonify({'error': NOT_BUILT, 'code': 'graph_not_built'}), 404
    except attack_graph.GraphError as e:
        return jsonify({'error': f"Graphe d'attaque invalide : {e}", 'code': 'graph_invalid'}), 422
    graph['investigation_id'] = investigation_id
    graph['job_id'] = job_id
    graph['file_mtime'] = mtime
    return jsonify(graph)


@bp.route('/api/investigations/<investigation_id>/graph', methods=['GET'])
@require_auth
def investigation_graph(investigation_id):
    denied = access.require_investigation_access(investigation_id)
    if denied:
        return denied
    _ensure_watcher()
    return _graph_response(investigation_id)


@bp.route('/api/autonomous/jobs/<job_id>/graph', methods=['GET'])
@require_auth
def job_graph(job_id):
    from routes.autonomous import _can_read_job
    job = autonomous.autonomous_jobs.get(job_id)
    if not job or not _can_read_job(job):
        return jsonify({'error': 'Job non trouve'}), 404
    inv_id = job.get('investigation_id')
    # Le graphe reste une donnee d'enquete : acces a l'enquete exige
    if not inv_id or not access.can_access_investigation(g.user_id, g.role, inv_id):
        return jsonify({'error': 'Job non trouve'}), 404
    _ensure_watcher()
    return _graph_response(inv_id, job_id=job_id)


# ============================================================================
# Veilleur : 'graph_updated' quand entity_graph.json change
# ============================================================================

def check_graph_updates(app):
    """Comparer l'mtime du graphe des enquetes ayant un job autonome connu et
    diffuser 'graph_updated' a la salle de l'enquete. Retourne les evenements."""
    events = []
    jobs = list(autonomous.autonomous_jobs.values())
    seen = set()
    for job in jobs:
        inv_id = job.get('investigation_id')
        if not inv_id or inv_id in seen:
            continue
        seen.add(inv_id)
        case_dir = case_dir_for(inv_id, app)
        if not case_dir:
            continue
        mtime = attack_graph.mtime(case_dir)
        if mtime is None or _last_mtimes.get(inv_id) == mtime:
            continue
        _last_mtimes[inv_id] = mtime
        payload = {'investigation_id': inv_id, 'job_id': job.get('job_id'),
                   'job_status': job.get('status'), 'file_mtime': mtime}
        emit_secure('graph_updated', payload, investigation_id=inv_id)
        events.append(payload)
    return events


def _watch_loop(app):
    while True:
        socketio.sleep(WATCH_INTERVAL)
        try:
            check_graph_updates(app)
        except Exception as e:  # pragma: no cover - ne doit jamais tuer le veilleur
            print(f'Veilleur du graphe : {e}')


def _ensure_watcher():
    """Demarrer le veilleur une seule fois (hors tests, desactivable)."""
    global _watch_started
    app = current_app._get_current_object()
    if _watch_started or app.testing or os.environ.get('PHOENIX_GRAPH_WATCH', '1') == '0':
        return
    with _watch_lock:
        if _watch_started:
            return
        _watch_started = True
    socketio.start_background_task(_watch_loop, app)


@bp.before_app_request
def _start_watcher_on_first_request():
    _ensure_watcher()
