#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR - Backend API Flask
Point d'entree de l'application : configuration, middlewares et enregistrement
des blueprints (voir routes/) et des evenements WebSocket (voir sockets.py).
Toutes les donnees sont stockees dans SQLite via database.py
"""

import os
import secrets

from flask import Flask
from flask_cors import CORS

# Import des modules internes
from database import init_db, migrate_json_sessions, close_db
from auth import register_auth_routes
from middleware import register_security_headers, register_request_id
from observability import setup_logging, register_metrics_middleware
from extensions import socketio, CORS_ORIGINS
from phoenix_compat import PHOENIX_AVAILABLE

# Configurer le logging structure le plus tot possible
setup_logging()

from routes import register_blueprints  # noqa: E402
import sockets  # noqa: E402,F401 - enregistre les handlers WebSocket sur socketio

# ============================================================================
# CONFIGURATION FLASK
# ============================================================================

app = Flask(__name__)

# Cle secrete depuis variable d'environnement ou generation aleatoire
app.config['SECRET_KEY'] = os.environ.get('PHOENIX_SECRET_KEY', secrets.token_hex(64))
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max

CORS(app, origins=CORS_ORIGINS)
socketio.init_app(app)

# Creer les dossiers necessaires
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), 'sessions'), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), 'reports'), exist_ok=True)

# Enregistrer les routes d'authentification
register_auth_routes(app)

# Enregistrer les middlewares de securite
register_security_headers(app)
register_request_id(app)
register_metrics_middleware(app)

# Enregistrer les blueprints de l'API
register_blueprints(app)

# ============================================================================
# INITIALISATION BASE DE DONNEES AU DEMARRAGE
# ============================================================================

with app.app_context():
    init_db()
    migrate_json_sessions()

# ============================================================================
# TEARDOWN : FERMETURE CONNEXION DB
# ============================================================================


@app.teardown_appcontext
def teardown_db(exception):
    """Fermer la connexion SQLite a la fin de chaque requete"""
    close_db()

# ============================================================================
# POINT D'ENTREE
# ============================================================================


if __name__ == '__main__':
    from helpers import cleanup_old_files

    print("=" * 60)
    print("Phoenix DFIR - Backend API")
    print("=" * 60)
    print(f"Phoenix Core disponible: {PHOENIX_AVAILABLE}")
    print(f"Dossier uploads: {app.config['UPLOAD_FOLDER']}")
    print(f"Base de donnees: SQLite")
    print("=" * 60)

    # Nettoyer les anciens fichiers au demarrage
    cleanup_old_files(app)

    # Mode debug depuis variable d'environnement (False par defaut)
    debug_mode = os.environ.get('PHOENIX_DEBUG', 'false').lower() in ('true', '1', 'yes')

    # Demarrer le serveur
    socketio.run(
        app,
        host='0.0.0.0',
        port=int(os.environ.get('PHOENIX_PORT', '5000')),
        debug=debug_mode
    )
