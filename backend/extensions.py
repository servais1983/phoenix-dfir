#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR - Objets et constantes partages entre l'application et les blueprints.

Les instances sont creees ici sans application Flask ; app.py les attache via
socketio.init_app(app). Les blueprints les importent sans dependre de app.py
(pas d'import circulaire).
"""

import os
from concurrent.futures import ThreadPoolExecutor

from flask_socketio import SocketIO

PHOENIX_VERSION = '4.0'

# Extensions de fichiers autorisees a l'upload (formats forensiques inclus)
ALLOWED_EXTENSIONS = {
    '.evtx', '.csv', '.json', '.log', '.txt', '.xml', '.pcap', '.pcapng',
    '.pf', '.lnk', '.sqlite', '.db', '.ps1', '.bat', '.sh', '.hve', '.dat',
}

# Types d'IoC valides
VALID_IOC_TYPES = {'ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email', 'filename', 'registry_key', 'cve'}

# Origines CORS autorisees : localhost (dev) + origines supplementaires via
# PHOENIX_CORS_ORIGINS (liste separee par des virgules, ex pour un acces
# equipe : "http://10.0.0.5:5173,https://phoenix.mon-soc.local").
# PHOENIX_CORS_ORIGINS=* autorise toutes les origines (deconseille en prod).
_DEFAULT_CORS = [
    # Frontend de developpement (Vite)
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5174",
    # Frontend servi par le backend lui-meme (Docker mono-conteneur)
    "http://localhost:5000",
    "http://127.0.0.1:5000",
]
_extra_cors = [o.strip() for o in os.environ.get('PHOENIX_CORS_ORIGINS', '').split(',') if o.strip()]
CORS_ORIGINS = '*' if '*' in _extra_cors else _DEFAULT_CORS + _extra_cors

def _socketio_origin_allowed(origin):
    """Autoriser les origines connues + la propre origine du serveur.

    La meme origine que le serveur couvre le mono-conteneur Docker et
    l'acces equipe via IP (http://10.0.0.5:5000) sans configuration ;
    les origines supplementaires passent par PHOENIX_CORS_ORIGINS.
    """
    if CORS_ORIGINS == '*' or origin in CORS_ORIGINS:
        return True
    try:
        from flask import request
        host = request.host
        return origin in (f'http://{host}', f'https://{host}')
    except Exception:
        return False


socketio = SocketIO(cors_allowed_origins='*' if CORS_ORIGINS == '*' else _socketio_origin_allowed)

# Pool de threads pour les analyses (4 workers max)
executor = ThreadPoolExecutor(max_workers=4)

# Progression des analyses en cours
analysis_progress = {}
