#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Server mode: gunicorn gthread worker + Flask-SocketIO threading mode.

The end-to-end test boots the real gunicorn server with gunicorn.conf.py and
connects Socket.IO clients over WebSocket and long polling. It is skipped when
gunicorn, python-socketio's client or websocket-client is not installed.
"""

import importlib.util
import io
import os
import runpy
import socket
import subprocess
import sys
import threading
import time

import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(BACKEND)
sys.path.insert(0, BACKEND)


def _conf(env=None):
    saved = dict(os.environ)
    try:
        os.environ.update(env or {})
        return runpy.run_path(os.path.join(BACKEND, 'gunicorn.conf.py'))
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_gunicorn_conf_gthread_un_seul_worker():
    conf = _conf()
    assert conf['worker_class'] == 'gthread'
    assert conf['workers'] == 1                  # Socket.IO needs sticky sessions
    assert conf['threads'] == 64
    assert conf['max_requests'] == 0             # no recycling in the middle of a job
    assert conf['bind'].endswith(':5000')


def test_gunicorn_conf_threads_configurables():
    conf = _conf({'PHOENIX_THREADS': '16', 'PHOENIX_PORT': '5055', 'PHOENIX_MAX_REQUESTS': '5000'})
    assert conf['threads'] == 16
    assert conf['bind'] == '0.0.0.0:5055'
    assert conf['max_requests'] == 5000 and conf['max_requests_jitter'] == 500
    assert _conf({'PHOENIX_THREADS': 'abc'})['threads'] == 64
    assert _conf({'PHOENIX_THREADS': '1'})['threads'] == 4


def test_socketio_mode_threading_sans_eventlet():
    os.environ.setdefault('PHOENIX_SECRET_KEY', 'test-secret-key-for-testing-only')
    import app  # noqa: F401 - init_app attaches the server
    from extensions import socketio
    assert socketio.server.eio.async_mode == 'threading'
    with open(os.path.join(BACKEND, 'requirements.txt'), encoding='utf-8') as f:
        reqs = f.read().lower()
    assert 'eventlet' not in reqs
    assert 'simple-websocket' in reqs
    with open(os.path.join(BACKEND, 'app.py'), encoding='utf-8') as f:
        assert 'monkey_patch' not in f.read()


def test_dockerfile_et_stack_prod_utilisent_gunicorn():
    with open(os.path.join(ROOT, 'Dockerfile'), encoding='utf-8') as f:
        dockerfile = f.read()
    assert 'CMD ["gunicorn", "--config", "/app/backend/gunicorn.conf.py", "app:app"]' in dockerfile
    with open(os.path.join(ROOT, 'docker-compose.prod.yml'), encoding='utf-8') as f:
        assert '"gunicorn", "--config", "/app/backend/gunicorn.conf.py", "app:app"' in f.read()


# ============================================================================
# Real server
# ============================================================================

def _have(module):
    return importlib.util.find_spec(module) is not None


def _gunicorn_has_gthread():
    if not _have('gunicorn'):
        return False
    try:
        import gunicorn.workers.gthread  # noqa: F401
    except Exception:
        return False
    return True


requires_server = pytest.mark.skipif(
    not (_gunicorn_has_gthread() and _have('socketio') and _have('websocket') and _have('requests')
         and _have('simple_websocket')),
    reason='gunicorn (gthread), python-socketio client, websocket-client and simple-websocket required')


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
def live_server(tmp_path):
    import requests
    port = _free_port()
    env = dict(os.environ)
    env.pop('REDIS_URL', None)
    env.update({
        'PHOENIX_PORT': str(port), 'PHOENIX_DB_PATH': str(tmp_path / 'phoenix.db'),
        'PHOENIX_SECRET_KEY': 'server-mode-test-secret-key-0123456789',
        'PHOENIX_ADMIN_USERNAME': 'srv_admin', 'PHOENIX_ADMIN_PASSWORD': 'Srv-Admin-Strong-2026!',
        'PHOENIX_INBOX_ENABLED': 'false', 'PHOENIX_THREADS': '8', 'PHOENIX_JOB_WORKERS': '1',
        # LLM "configured" but unreachable: the job runs in a queue thread and fails fast
        'PHOENIX_LLM_PROVIDER': 'ollama', 'OLLAMA_BASE_URL': 'http://127.0.0.1:9',
        'PHOENIX_LOG_LEVEL': 'warning', 'PHOENIX_DEBUG': 'false',
    })
    log = open(tmp_path / 'gunicorn.log', 'w+')
    proc = subprocess.Popen([sys.executable, '-m', 'gunicorn', '--config', 'gunicorn.conf.py', 'app:app'],
                            cwd=BACKEND, env=env, stdout=log, stderr=subprocess.STDOUT)
    base = f'http://127.0.0.1:{port}'
    try:
        ready = False
        deadline = time.time() + 30
        while not ready and time.time() < deadline and proc.poll() is None:
            try:
                ready = requests.get(f'{base}/livez', timeout=1).status_code == 200
            except requests.RequestException:
                time.sleep(0.2)
        if not ready:
            log.seek(0)
            pytest.fail('gunicorn did not start:\n' + log.read()[-4000:])
        yield base, log
    finally:
        proc.terminate()
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


@requires_server
def test_gunicorn_gthread_websocket_polling_et_origine(live_server):
    import requests
    import socketio

    base, log = live_server
    login = requests.post(f'{base}/api/auth/login', json={
        'username': 'srv_admin', 'password': 'Srv-Admin-Strong-2026!'}, timeout=10)
    assert login.status_code == 200, login.text
    token = login.json()['token']
    auth_h = {'Authorization': f'Bearer {token}'}

    # 1. WebSocket transport only, same origin as the server (HTTP_HOST check)
    events = []
    got_job_event = threading.Event()
    ws = socketio.Client(reconnection=False)

    @ws.on('autonomous_progress')
    def _on_progress(data):
        events.append(('autonomous_progress', data))
        got_job_event.set()

    @ws.on('job_status')
    def _on_status(data):
        events.append(('job_status', data))

    # websocket-client sends Origin: http://127.0.0.1:<port> itself (a true
    # same-origin handshake); adding an Origin header would duplicate it.
    ws.connect(base, auth={'token': token}, transports=['websocket'], wait_timeout=10)
    try:
        assert ws.transport() == 'websocket'

        # 2. Long polling transport
        poll = socketio.Client(reconnection=False)
        poll.connect(base, auth={'token': token}, transports=['polling'],
                     headers={'Origin': base}, wait_timeout=10)
        assert poll.transport() == 'polling'
        poll.disconnect()

        # 3. Origin check on the raw handshakes (single, controlled Origin header)
        import websocket
        ws_url = base.replace('http://', 'ws://') + '/socket.io/?EIO=4&transport=websocket'
        raw = websocket.create_connection(ws_url, origin=base, timeout=5)
        assert raw.recv().startswith('0{')                       # engine.io OPEN packet
        raw.close()
        with pytest.raises(websocket.WebSocketBadStatusException):
            websocket.create_connection(ws_url, origin='https://evil.example', timeout=5)
        foreign = requests.get(f'{base}/socket.io/?EIO=4&transport=polling',
                               headers={'Origin': 'https://evil.example'}, timeout=5)
        assert foreign.status_code == 400

        # 4. Events emitted from a job queue thread reach the WebSocket client
        inv = requests.post(f'{base}/api/investigations', json={'name': 'Cas serveur'},
                            headers=auth_h, timeout=10).json()['id']
        up = requests.post(f'{base}/api/upload', headers=auth_h, timeout=10,
                           data={'investigation_id': inv},
                           files={'file': ('auth.log', io.BytesIO(b'Failed password from 203.0.113.9\n'))})
        assert up.status_code == 200, up.text
        start = requests.post(f'{base}/api/autonomous/investigate', json={'investigation_id': inv},
                              headers=auth_h, timeout=10)
        assert start.status_code == 200, start.text
        job_id = start.json()['job_id']
        assert got_job_event.wait(30), events
        assert any(d.get('job_id') == job_id for _e, d in events)
        listing = requests.get(f'{base}/api/autonomous/jobs?investigation_id={inv}',
                               headers=auth_h, timeout=10).json()['items']
        assert [j['job_id'] for j in listing] == [job_id]
        requests.post(f'{base}/api/autonomous/jobs/{job_id}/cancel', headers=auth_h, timeout=10)
    finally:
        ws.disconnect()
    log.seek(0)
    assert 'Traceback' not in log.read()
