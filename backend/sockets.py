#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phoenix DFIR - Evenements WebSocket (Socket.IO).

Seuls les clients presentant un jeton d'acces valide peuvent se connecter :
ils rejoignent la salle AUTHENTICATED_ROOM, seule destinataire des
evenements temps reel (voir extensions.emit_secure). Une connexion anonyme
est refusee.
"""

from flask import request
from flask_socketio import emit, join_room

from auth import decode_token
from extensions import AUTHENTICATED_ROOM, socketio


def _extract_token(auth=None):
    """Jeton JWT : payload d'auth Socket.IO, puis query string, puis header."""
    if isinstance(auth, dict) and auth.get('token'):
        return str(auth['token'])
    token = request.args.get('token', '')
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
    return token


@socketio.on('connect')
def handle_connect(auth=None):
    """Connexion WebSocket : refusee sans jeton d'acces valide."""
    token = _extract_token(auth)
    payload = decode_token(token, expected_type='access') if token else None
    if not payload:
        # Refus : un client anonyme ne doit recevoir aucune donnee d'enquete
        return False
    join_room(AUTHENTICATED_ROOM)
    emit('connected', {'message': 'Connexion etablie avec Phoenix DFIR', 'authenticated': True})
    return None


@socketio.on('disconnect')
def handle_disconnect():
    """Deconnexion WebSocket"""


@socketio.on('join_investigation')
def handle_join_investigation(data):
    """Rejoindre une enquete pour les notifications temps reel"""
    investigation_id = (data or {}).get('investigation_id')
    if investigation_id:
        emit('joined_investigation', {'investigation_id': investigation_id})
