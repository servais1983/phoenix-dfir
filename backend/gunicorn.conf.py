"""
Phoenix DFIR - Gunicorn production config
Worker eventlet pour supporter Flask-SocketIO (1 worker = pas de partage de socket).
Pour scaler, mettre Redis devant via flask-socketio message_queue (deja branche).
"""

import multiprocessing
import os

# Bind sur toutes interfaces, port configurable
bind = f"0.0.0.0:{os.environ.get('PHOENIX_PORT', '5000')}"

# Workers : Socket.IO + Flask = 1 worker eventlet par instance (state cote app)
# Pour scaler horizontalement, deployer N replicas + Redis pour le pub/sub
workers = int(os.environ.get('PHOENIX_WORKERS', '1'))
worker_class = 'eventlet'
worker_connections = 1000

# Timeouts
timeout = 120          # uploads d'artefacts peuvent etre lents
graceful_timeout = 30
keepalive = 5

# Limites
max_requests = 10000   # restart worker apres N requetes (limite les fuites memoire)
max_requests_jitter = 1000
limit_request_line = 8192
limit_request_field_size = 16384

# Logging vers stdout (capture par docker logs / k8s)
accesslog = '-'
errorlog = '-'
loglevel = os.environ.get('PHOENIX_LOG_LEVEL', 'info').lower()
# Format compatible avec les logs JSON de l'app
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'

# Process naming
proc_name = 'phoenix-dfir'

# Securite
forwarded_allow_ips = '*'   # nginx fait le filtrage en amont
secure_scheme_headers = {'X-FORWARDED-PROTO': 'https'}
