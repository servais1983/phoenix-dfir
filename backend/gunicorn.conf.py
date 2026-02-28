"""
Phoenix DFIR - Configuration Gunicorn (Production WSGI Server)
Ce fichier remplace le serveur de developpement Flask pour la production.

Usage:
    gunicorn -c gunicorn.conf.py "app:socketio.wsgi_app"
  ou via Docker CMD.
"""

import multiprocessing
import os

# ============================================================================
# WORKERS
# ============================================================================

# Nombre de workers: (CPU * 2) + 1 est la recommandation classique
# Pour une appli I/O-bound (DB, reseau), on peut augmenter
_cpu_count = multiprocessing.cpu_count()
workers = int(os.environ.get('GUNICORN_WORKERS', min(_cpu_count * 2 + 1, 8)))

# Classe worker: eventlet pour Flask-SocketIO (WebSocket)
worker_class = 'eventlet'

# Threads par worker (utiliser avec gthread si pas de socketio)
threads = 1

# Connexions simultanées par worker
worker_connections = 1000

# ============================================================================
# TIMEOUTS
# ============================================================================

# Timeout des workers (secondes) - tuer si pas de reponse
timeout = 120

# Timeout graceful shutdown
graceful_timeout = 30

# Keepalive des connexions HTTP
keepalive = 5

# ============================================================================
# BINDING
# ============================================================================

bind = f"0.0.0.0:{os.environ.get('PHOENIX_PORT', '5000')}"

# ============================================================================
# LOGGING
# ============================================================================

# Format de log structuré JSON pour production
accesslog = '-'   # stdout
errorlog = '-'    # stderr
loglevel = os.environ.get('GUNICORN_LOG_LEVEL', 'info')

# Format access log JSON
access_log_format = (
    '{"ts":"%(t)s","method":"%(m)s","path":"%(U)s","status":%(s)s,'
    '"resp_bytes":%(B)s,"duration_ms":%(D)s,"ip":"%(h)s",'
    '"referer":"%(f)s","ua":"%(a)s"}'
)

# ============================================================================
# SECURITE
# ============================================================================

# Limiter la taille des headers pour eviter les attaques de type slowloris
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

# Supprimer le header Server de gunicorn
forwarded_allow_ips = os.environ.get('GUNICORN_FORWARDED_IPS', '127.0.0.1')

# ============================================================================
# PERFORMANCE
# ============================================================================

# Pre-charger le code de l'application avant de fork les workers
preload_app = True

# Daemon mode (desactive pour Docker - utiliser tini)
daemon = False

# PID file (optionnel, utile pour orchestration externe)
# pidfile = '/tmp/gunicorn.pid'

# ============================================================================
# HOOKS
# ============================================================================

def on_starting(server):
    """Appele au demarrage du master"""
    server.log.info("Phoenix DFIR - Gunicorn starting")


def on_exit(server):
    """Appele a l'arret du master"""
    server.log.info("Phoenix DFIR - Gunicorn shutting down")


def worker_exit(server, worker):
    """Nettoyage par worker a la sortie"""
    from database import close_db
    try:
        close_db()
    except Exception:
        pass
