"""`phoenix web`: the investigator console on Windows, macOS and Linux.

The backend runs under waitress (pure Python WSGI server, every OS) with
Flask-SocketIO in 'threading' mode: real-time events use HTTP long polling.
Docker on Linux keeps gunicorn (gthread worker), which also serves the
WebSocket transport.

Local first: the console listens on 127.0.0.1 unless --host says otherwise.
"""

import os
import sys

from . import _paths

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 5000
DEFAULT_THREADS = 16


def _threads():
    try:
        return max(4, int(os.environ.get('PHOENIX_THREADS', DEFAULT_THREADS)))
    except ValueError:
        return DEFAULT_THREADS


def load_app():
    """Import the Flask application of the backend."""
    _paths.ensure_backend_importable()
    import app as backend_app
    return backend_app.app


def serve(host=None, port=None, threads=None):
    try:
        import waitress
    except ImportError:
        print('phoenix web needs the web extra: pip install "phoenix-dfir[web]"', file=sys.stderr)
        return 2
    host = host or os.environ.get('PHOENIX_HOST', DEFAULT_HOST)
    port = int(port or os.environ.get('PHOENIX_PORT', DEFAULT_PORT))
    application = load_app()
    print(f'Phoenix DFIR console on http://{host}:{port} (waitress, Socket.IO long polling)', file=sys.stderr)
    waitress.serve(application, host=host, port=port, threads=threads or _threads(), ident='phoenix-dfir')
    return 0
