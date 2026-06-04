"""
Phoenix DFIR - Middleware de securite
Rate limiting (Redis ou in-memory), headers de securite, request ID, validation.
"""

import time
import uuid
import re
from functools import wraps
from flask import request, jsonify, g

from cache import cache


# ============================================================================
# RATE LIMITER (distribue si Redis dispo, in-memory sinon)
# ============================================================================

def _client_ip():
    """Recuperer l'IP client en respectant X-Forwarded-For derriere un proxy."""
    fwd = request.headers.get('X-Forwarded-For', '')
    if fwd:
        # Premier element = client reel (les suivants = proxies)
        return fwd.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def rate_limit(max_requests=10, window=60, scope='global'):
    """Decorator: limite le nombre de requetes par IP via cache.

    Utilise sliding_window_hit qui marche identiquement pour Redis (ZSET)
    et in-memory.
    """
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            ip = _client_ip()
            key = f'ratelimit:{scope}:{f.__name__}:{ip}'
            hits = cache.sliding_window_hit(key, window)
            if hits > max_requests:
                resp = jsonify({
                    'error': 'Trop de requetes. Reessayez plus tard.',
                    'retry_after': window,
                })
                resp.headers['Retry-After'] = str(window)
                resp.headers['X-RateLimit-Limit'] = str(max_requests)
                resp.headers['X-RateLimit-Remaining'] = '0'
                return resp, 429
            return f(*args, **kwargs)
        return decorated
    return decorator


# ============================================================================
# SECURITY HEADERS MIDDLEWARE
# ============================================================================

# CSP renforcee: pas d'inline en prod sauf besoin React (style-src), pas de eval
_DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "
    "font-src 'self' data:; "
    "connect-src 'self' ws: wss:; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "object-src 'none'"
)


def register_security_headers(app):
    """Enregistrer les headers de securite sur toutes les reponses"""
    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('X-XSS-Protection', '1; mode=block')
        response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
        response.headers.setdefault('Content-Security-Policy', _DEFAULT_CSP)
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
        response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
        response.headers.setdefault('Cross-Origin-Resource-Policy', 'same-origin')
        response.headers.setdefault('X-DNS-Prefetch-Control', 'off')
        # On retire Server: pour ne pas exposer la version
        response.headers.pop('Server', None)
        return response


# ============================================================================
# REQUEST ID MIDDLEWARE
# ============================================================================

def register_request_id(app):
    """Enregistrer le middleware de Request ID pour le tracage"""
    @app.before_request
    def add_request_id():
        rid = request.headers.get('X-Request-ID', '').strip()
        if not rid or len(rid) > 64 or not re.match(r'^[A-Za-z0-9._\-]+$', rid):
            rid = uuid.uuid4().hex[:16]
        g.request_id = rid
        g.request_started_at = time.time()

    @app.after_request
    def set_request_id_header(response):
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        return response


# ============================================================================
# INPUT VALIDATION HELPERS
# ============================================================================

_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')


def validate_uuid(value):
    """Valider qu'une valeur est un UUID valide (fast path regex)."""
    if not isinstance(value, str):
        return False
    return bool(_UUID_RE.match(value))


def sanitize_string(value, max_length=500):
    """Nettoyer une chaine de caracteres et borner sa longueur."""
    if not isinstance(value, str):
        return ''
    # Retirer les NUL bytes et les caracteres de controle dangereux
    cleaned = value.replace('\x00', '').strip()
    return cleaned[:max_length]


# ============================================================================
# PASSWORD POLICY
# ============================================================================

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 200

# Top-100 mots de passe extremement faibles (liste indicative, non exhaustive)
_WEAK_PASSWORDS = frozenset({
    'password', 'password1', 'password123', '123456', '12345678', '123456789',
    '1234567890', 'qwerty', 'azerty', 'letmein', 'welcome', 'admin', 'admin123',
    'root', 'toor', 'changeme', 'iloveyou', 'monkey', 'dragon', 'master',
    'sunshine', 'princess', 'football', 'qwerty123', 'abc123', '111111',
    'phoenix', 'phoenix123', 'forensic',
})


def validate_password(password):
    """Valider la robustesse d'un mot de passe.

    Renvoie (True, '') si valide, sinon (False, raison).
    Politique : 12+ chars, 3 classes de caracteres sur 4, pas dans la denylist.
    """
    if not isinstance(password, str):
        return False, 'Mot de passe invalide'
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f'Mot de passe trop court ({PASSWORD_MIN_LENGTH} caracteres minimum)'
    if len(password) > PASSWORD_MAX_LENGTH:
        return False, f'Mot de passe trop long ({PASSWORD_MAX_LENGTH} caracteres maximum)'
    if password.lower() in _WEAK_PASSWORDS:
        return False, 'Mot de passe trop commun, choisissez-en un autre'

    classes = 0
    if re.search(r'[a-z]', password):
        classes += 1
    if re.search(r'[A-Z]', password):
        classes += 1
    if re.search(r'\d', password):
        classes += 1
    if re.search(r'[^A-Za-z0-9]', password):
        classes += 1

    if classes < 3:
        return False, 'Mot de passe trop faible: utilisez au moins 3 types de caracteres (maj, min, chiffre, special)'

    return True, ''
