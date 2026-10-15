#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes sante : /api/health, /healthz, /livez, /readyz (pas d'authentification)."""

import datetime

from flask import Blueprint, jsonify

from cache import cache
from database import get_db
from extensions import PHOENIX_VERSION
from observability import logger
from phoenix_compat import PHOENIX_AVAILABLE

bp = Blueprint('health', __name__)


@bp.route('/api/health', methods=['GET'])
@bp.route('/healthz', methods=['GET'])
def health_check():
    """Health check complet: DB + cache + sondes globales.

    Conserve pour retro-compat. Pour Kubernetes, preferer:
    - /livez : sonde de vivacite (toujours 200 si le process repond)
    - /readyz : sonde de readiness (200 uniquement si toutes deps OK)
    """
    db_ok = False
    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
        db_ok = True
    except Exception as e:
        logger.warning('health_db_check_failed', extra={'error': str(e)})

    cache_ok = False
    try:
        cache_ok = cache.ping()
    except Exception:
        pass

    overall = 'healthy' if db_ok and cache_ok else ('degraded' if db_ok else 'unhealthy')
    status_code = 200 if db_ok else 503
    return jsonify({
        'status': overall,
        'phoenix_available': PHOENIX_AVAILABLE,
        'database': 'connected' if db_ok else 'error',
        'cache': cache.backend_name if cache_ok else 'error',
        'timestamp': datetime.datetime.now().isoformat(),
        'version': PHOENIX_VERSION,
    }), status_code


@bp.route('/livez', methods=['GET'])
def liveness():
    """Liveness probe: 200 si le process est vivant. Pas de dependance externe."""
    return jsonify({'status': 'alive', 'version': PHOENIX_VERSION}), 200


@bp.route('/readyz', methods=['GET'])
def readiness():
    """Readiness probe: 200 uniquement si toutes les dependances repondent."""
    checks = {}

    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
        checks['database'] = 'ok'
    except Exception as e:
        checks['database'] = f'error: {e}'

    try:
        checks['cache'] = 'ok' if cache.ping() else 'error'
    except Exception as e:
        checks['cache'] = f'error: {e}'

    ready = all(v == 'ok' for v in checks.values())
    return jsonify({
        'ready': ready,
        'checks': checks,
        'version': PHOENIX_VERSION,
    }), (200 if ready else 503)
