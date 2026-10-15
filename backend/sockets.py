#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phoenix DFIR - Evenements WebSocket (Socket.IO).

Seuls les clients presentant un jeton d'acces valide (payload d'auth
Socket.IO ou header Authorization, jamais la query string qui finit dans les
logs) peuvent se connecter. Chaque socket rejoint :
- inv:<id> pour chaque enquete accessible (membre, ou toutes pour un admin) ;
- user:<id> pour ses propres evenements ;
- admins s'il est administrateur.

Le jeton est conserve par socket : a chaque evenement client et avant chaque
diffusion (extensions.emit_secure), les sockets dont le jeton a expire, a ete
revoque ou dont la token_version a change sont deconnectes.
"""

import threading
import time

from flask import request
from flask_socketio import emit, join_room

import access
from auth import decode_token
from extensions import (ADMIN_ROOM, _pre_emit_hooks, investigation_room, socketio,
                        user_room)

NAMESPACE = '/'
# Re-verification complete (revocation, token_version) au plus toutes les N s
REVALIDATE_INTERVAL = 30

# sid -> {'user_id', 'role', 'exp', 'token', 'checked_at'}
_sessions = {}
_lock = threading.Lock()
_last_full_check = [0.0]


def _extract_token(auth=None):
    """Jeton JWT : payload d'auth Socket.IO, sinon header Authorization."""
    if isinstance(auth, dict) and auth.get('token'):
        return str(auth['token'])
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    return ''


def _drop(sid):
    with _lock:
        _sessions.pop(sid, None)
    try:
        socketio.server.disconnect(sid, namespace=NAMESPACE)
    except Exception:
        pass


def _session_valid(info, full_check):
    if info['exp'] <= time.time():
        return False
    if full_check:
        payload = decode_token(info['token'], expected_type='access')
        if not payload or payload.get('role') != info['role']:
            return False
    return True


def prune_sessions(force_full=False):
    """Deconnecter les sockets dont le jeton n'est plus valide.

    L'expiration est verifiee a chaque appel (cout negligeable) ; la
    revocation et la token_version (acces base) au plus toutes les
    REVALIDATE_INTERVAL secondes, ou immediatement avec force_full=True.
    """
    now = time.time()
    full = force_full or (now - _last_full_check[0] >= REVALIDATE_INTERVAL)
    if full:
        _last_full_check[0] = now
    with _lock:
        snapshot = list(_sessions.items())
    for sid, info in snapshot:
        if not _session_valid(info, full):
            _drop(sid)


_pre_emit_hooks.append(prune_sessions)


def _current_session():
    """Session du socket courant, ou None (et deconnexion) si invalide."""
    with _lock:
        info = _sessions.get(request.sid)
    if not info or not _session_valid(info, full_check=True):
        _drop(request.sid)
        return None
    return info


def sids_for_user(user_id):
    with _lock:
        return [sid for sid, info in _sessions.items() if info['user_id'] == user_id]


def grant_investigation_room(user_id, investigation_id):
    """Faire rejoindre la salle d'une enquete aux sockets ouverts d'un utilisateur."""
    for sid in sids_for_user(user_id):
        try:
            socketio.server.enter_room(sid, investigation_room(investigation_id), namespace=NAMESPACE)
        except Exception:
            pass


def revoke_investigation_room(user_id, investigation_id):
    """Retirer les sockets d'un utilisateur de la salle d'une enquete."""
    for sid in sids_for_user(user_id):
        try:
            socketio.server.leave_room(sid, investigation_room(investigation_id), namespace=NAMESPACE)
        except Exception:
            pass


@socketio.on('connect')
def handle_connect(auth=None):
    """Connexion WebSocket : refusee sans jeton d'acces valide."""
    token = _extract_token(auth)
    payload = decode_token(token, expected_type='access') if token else None
    if not payload:
        # Refus : un client anonyme ne doit recevoir aucune donnee d'enquete
        return False
    user_id, role = payload['user_id'], payload['role']
    with _lock:
        _sessions[request.sid] = {'user_id': user_id, 'role': role, 'exp': payload.get('exp', 0),
                                  'token': token, 'checked_at': time.time()}
    join_room(user_room(user_id))
    if role == 'admin':
        join_room(ADMIN_ROOM)
    for inv_id in (access.accessible_investigation_ids(user_id, role) or []):
        join_room(investigation_room(inv_id))
    emit('connected', {'message': 'Connexion etablie avec Phoenix DFIR', 'authenticated': True})
    return None


@socketio.on('disconnect')
def handle_disconnect():
    """Deconnexion WebSocket"""
    with _lock:
        _sessions.pop(request.sid, None)


@socketio.on('join_investigation')
def handle_join_investigation(data):
    """Rejoindre la salle d'une enquete : uniquement si l'utilisateur y a acces."""
    info = _current_session()
    if not info:
        return
    investigation_id = (data or {}).get('investigation_id') if isinstance(data, dict) else None
    if not investigation_id or not access.can_access_investigation(
            info['user_id'], info['role'], investigation_id):
        # Meme reponse qu'une enquete inexistante (anti-enumeration)
        emit('join_investigation_error', {'investigation_id': investigation_id,
                                          'error': 'Enquete non trouvee'})
        return
    join_room(investigation_room(investigation_id))
    emit('joined_investigation', {'investigation_id': investigation_id})
