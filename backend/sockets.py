#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phoenix DFIR - Evenements WebSocket (Socket.IO)."""

from flask import request
from flask_socketio import emit

from auth import decode_token
from extensions import socketio


def _extract_token():
    """Recuperer le token JWT depuis la query string ou le header Authorization"""
    token = request.args.get('token', '')
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
    return token


@socketio.on('connect')
def handle_connect():
    """Connexion WebSocket avec verification d'authentification"""
    token = _extract_token()

    if token:
        payload = decode_token(token)
        if payload:
            print(f"Client connecte: {payload.get('username', 'inconnu')}")
            emit('connected', {'message': 'Connexion etablie avec Phoenix DFIR', 'authenticated': True})
            return

    # Permettre la connexion mais signaler l'absence d'authentification
    print('Client connecte sans authentification')
    emit('connected', {'message': 'Connexion etablie avec Phoenix DFIR', 'authenticated': False})


@socketio.on('disconnect')
def handle_disconnect():
    """Deconnexion WebSocket"""
    print('Client deconnecte')


@socketio.on('join_investigation')
def handle_join_investigation(data):
    """Rejoindre une enquete pour les notifications temps reel"""
    token = _extract_token()
    payload = decode_token(token) if token else None

    investigation_id = data.get('investigation_id')
    if investigation_id:
        username = payload.get('username', 'anonyme') if payload else 'anonyme'
        emit('joined_investigation', {
            'investigation_id': investigation_id,
            'user': username
        })
