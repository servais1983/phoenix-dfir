"""Smoke test of `phoenix web`: a real server process answers the health probes."""

import json
import os
import socket
import subprocess  # nosec B404 - test launcher, argument list
import sys
import time
import urllib.request
from pathlib import Path

import pytest

pytest.importorskip('waitress', reason='waitress is not installed (pip install "phoenix-dfir[web]")')

ROOT = Path(__file__).resolve().parents[2]


def _free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as resp:  # nosec B310 - local test server
        return resp.status, json.loads(resp.read().decode('utf-8'))


def test_phoenix_web_serves_health_probes(tmp_path):
    port = _free_port()
    env = dict(os.environ,
               PHOENIX_DB_PATH=str(tmp_path / 'phoenix.db'),
               PHOENIX_DATA_DIR=str(tmp_path / 'data'),
               PHOENIX_CUSTODY_DIR=str(tmp_path / 'custody'),
               PHOENIX_SECRET_KEY='smoke-test-secret-key-not-for-production',
               PHOENIX_JOB_WORKERS_ENABLED='false',
               PHOENIX_INBOX_ENABLED='false',
               PYTHONPATH=os.pathsep.join([str(ROOT / 'backend'), str(ROOT / 'mcp-server')]))
    proc = subprocess.Popen([sys.executable, '-m', 'phoenix_dfir_mcp', 'web', '--port', str(port)],  # nosec B603
                            cwd=str(tmp_path), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 60
        while True:
            try:
                status, live = _get(f'http://127.0.0.1:{port}/livez')
                break
            except OSError:
                if proc.poll() is not None or time.monotonic() > deadline:
                    out = proc.stdout.read().decode('utf-8', 'replace') if proc.poll() is not None else ''
                    pytest.fail(f'phoenix web did not start: {out[-2000:]}')
                time.sleep(0.5)
        assert status == 200 and live['status'] == 'alive'
        status, health = _get(f'http://127.0.0.1:{port}/api/health')
        assert status == 200 and health['version'] == live['version']
        # Socket.IO in threading mode: the long polling handshake answers
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/socket.io/?EIO=4&transport=polling',  # nosec B310
                                    timeout=5) as resp:
            assert resp.status == 200 and b'"sid"' in resp.read()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=15)
        proc.stdout.close()
