#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR - Objets et constantes partages entre l'application et les blueprints.

Les instances sont creees ici sans application Flask ; app.py les attache via
socketio.init_app(app). Les blueprints les importent sans dependre de app.py
(pas d'import circulaire).
"""

from concurrent.futures import ThreadPoolExecutor

from flask_socketio import SocketIO

PHOENIX_VERSION = '4.0'

# Extensions de fichiers autorisees a l'upload
ALLOWED_EXTENSIONS = {'.evtx', '.csv', '.json', '.log', '.txt', '.xml', '.pcap', '.pcapng'}

# Types d'IoC valides
VALID_IOC_TYPES = {'ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email', 'filename', 'registry_key', 'cve'}

# Origines CORS autorisees (localhost dev)
CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174"
]

socketio = SocketIO(cors_allowed_origins=CORS_ORIGINS)

# Pool de threads pour les analyses (4 workers max)
executor = ThreadPoolExecutor(max_workers=4)

# Progression des analyses en cours
analysis_progress = {}
