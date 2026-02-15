"""
Phoenix DFIR - Middleware de securite
Rate limiting, headers de securite, request ID et validation d'entrees
"""

import time
import threading
import uuid
import re
from functools import wraps
from flask import request, jsonify


# ============================================================================
# RATE LIMITER (in-memory, thread-safe)
# ============================================================================

class RateLimiter:
    def __init__(self):
        self._requests = {}  # {ip: [timestamp, ...], ...}
        self._lock = threading.Lock()

    def _cleanup(self, ip, window):
        now = time.time()
        self._requests[ip] = [t for t in self._requests.get(ip, []) if now - t < window]

    def is_limited(self, ip, max_requests, window):
        with self._lock:
            self._cleanup(ip, window)
            hits = self._requests.get(ip, [])
            if len(hits) >= max_requests:
                return True
            self._requests.setdefault(ip, []).append(time.time())
            return False


rate_limiter = RateLimiter()


def rate_limit(max_requests=10, window=60):
    """Decorator: limite le nombre de requetes par IP"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = request.remote_addr or '0.0.0.0'
            if rate_limiter.is_limited(ip, max_requests, window):
                return jsonify({'error': 'Trop de requetes. Reessayez plus tard.'}), 429
            return f(*args, **kwargs)
        return decorated
    return decorator


# ============================================================================
# SECURITY HEADERS MIDDLEWARE
# ============================================================================

def register_security_headers(app):
    """Enregistrer les headers de securite sur toutes les reponses"""
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:"
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        return response


# ============================================================================
# REQUEST ID MIDDLEWARE
# ============================================================================

def register_request_id(app):
    """Enregistrer le middleware de Request ID pour le tracage"""
    @app.before_request
    def add_request_id():
        from flask import g
        g.request_id = request.headers.get('X-Request-ID', str(uuid.uuid4())[:8])

    @app.after_request
    def set_request_id_header(response):
        from flask import g
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        return response


# ============================================================================
# INPUT VALIDATION HELPERS
# ============================================================================

def validate_uuid(value):
    """Valider qu'une valeur est un UUID valide"""
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError):
        return False


def sanitize_string(value, max_length=500):
    """Nettoyer une chaine de caracteres"""
    if not isinstance(value, str):
        return ''
    return value.strip()[:max_length]
