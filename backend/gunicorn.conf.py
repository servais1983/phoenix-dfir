"""
Phoenix DFIR - Gunicorn production config.

Worker 'gthread' (native threads) with Flask-SocketIO in 'threading' async
mode: WebSocket is served by simple-websocket on the raw socket gunicorn
exposes, long polling by regular request threads. No monkey patching.

A single worker process is required: Socket.IO sessions live in that
process and need sticky routing. Concurrency comes from threads
(PHOENIX_THREADS, default 64). An open WebSocket holds one thread for its
whole lifetime, so size PHOENIX_THREADS above the expected number of
connected browsers plus concurrent HTTP requests.

Heavy jobs (autonomous investigations) do NOT run on these threads: they go
through the durable SQLite job queue (jobqueue.py) and its own bounded pool
(PHOENIX_JOB_WORKERS).
"""

import os


def _env_int(name, default, minimum=0):
    try:
        return max(minimum, int(os.environ.get(name, str(default)) or default))
    except ValueError:
        return default


# Bind on all interfaces, configurable port
bind = f"0.0.0.0:{os.environ.get('PHOENIX_PORT', '5000')}"

# One process (Socket.IO state + job queue workers), N threads
workers = 1
worker_class = 'gthread'
threads = _env_int('PHOENIX_THREADS', 64, minimum=4)

# Timeouts. With gthread, `timeout` is the worker heartbeat towards the
# arbiter (not a per-request limit): long uploads and open WebSockets are fine.
timeout = 120
graceful_timeout = 30
keepalive = 5

# No periodic worker recycling by default: a restart would interrupt running
# investigations (they are re-queued, but lose progress). PHOENIX_MAX_REQUESTS
# re-enables it if needed.
max_requests = _env_int('PHOENIX_MAX_REQUESTS', 0)
max_requests_jitter = min(1000, max_requests // 10) if max_requests else 0
limit_request_line = 8192
limit_request_field_size = 16384

# Logging to stdout (captured by docker logs / k8s)
accesslog = '-'
errorlog = '-'
loglevel = os.environ.get('PHOENIX_LOG_LEVEL', 'info').lower()
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'

# Process naming
proc_name = 'phoenix-dfir'

# gunicorn >= 25.1 control socket (gunicornc) can change the worker count at
# runtime, which would break Socket.IO sessions: off unless explicitly wanted.
control_socket_disable = os.environ.get('PHOENIX_GUNICORN_CONTROL', 'false').lower() not in (
    'true', '1', 'yes')

# Security: nginx filters upstream in the production stack
forwarded_allow_ips = os.environ.get('PHOENIX_FORWARDED_ALLOW_IPS', '*')
secure_scheme_headers = {'X-FORWARDED-PROTO': 'https'}
