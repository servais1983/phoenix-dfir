"""
Phoenix DFIR - Middleware de securite
Rate limiting, headers de securite, request ID, validation d'entrees
Production-hardened: CORS dynamique, file magic bytes, input sanitization
"""

import time
import threading
import uuid
import re
import os
import logging
from functools import wraps
from flask import request, jsonify

logger = logging.getLogger(__name__)


# ============================================================================
# RATE LIMITER (in-memory, thread-safe, auto-cleanup)
# ============================================================================

class RateLimiter:
    def __init__(self):
        self._requests = {}   # {key: [timestamp, ...]}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def _cleanup(self, key, window):
        now = time.time()
        # Periodically clean all expired entries (every 5 minutes)
        if now - self._last_cleanup > 300:
            keys_to_delete = []
            for k, timestamps in self._requests.items():
                self._requests[k] = [t for t in timestamps if now - t < window * 2]
                if not self._requests[k]:
                    keys_to_delete.append(k)
            for k in keys_to_delete:
                del self._requests[k]
            self._last_cleanup = now
        else:
            self._requests[key] = [t for t in self._requests.get(key, []) if now - t < window]

    def is_limited(self, key, max_requests, window):
        with self._lock:
            self._cleanup(key, window)
            hits = self._requests.get(key, [])
            if len(hits) >= max_requests:
                return True
            self._requests.setdefault(key, []).append(time.time())
            return False


rate_limiter = RateLimiter()


def rate_limit(max_requests=60, window=60):
    """Decorator: limite le nombre de requetes par IP"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Prendre en compte les proxies (X-Forwarded-For avec validation)
            ip = _get_client_ip()
            key = f"{f.__name__}:{ip}"
            if rate_limiter.is_limited(key, max_requests, window):
                logger.warning(f"Rate limited: {ip} on {f.__name__}")
                return jsonify({'error': 'Trop de requetes. Reessayez plus tard.'}), 429
            return f(*args, **kwargs)
        return decorated
    return decorator


def _get_client_ip() -> str:
    """Extraire l'IP cliente de facon securisee"""
    # Verifier si on fait confiance aux headers proxy (configurable)
    trust_proxy = os.environ.get('PHOENIX_TRUST_PROXY', 'false').lower() in ('true', '1')
    if trust_proxy:
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            # Prendre uniquement la premiere IP (client original)
            candidate = forwarded.split(',')[0].strip()
            # Valider que c'est une IP valide
            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', candidate) or re.match(r'^[0-9a-fA-F:]+$', candidate):
                return candidate
    return request.remote_addr or '0.0.0.0'


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
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self' ws: wss:; "
            "font-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), interest-cohort=()'
        response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
        # Supprimer les headers qui revelent des infos sur la stack
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)
        return response


# ============================================================================
# REQUEST ID MIDDLEWARE
# ============================================================================

def register_request_id(app):
    """Enregistrer le middleware de Request ID pour le tracage"""
    @app.before_request
    def add_request_id():
        from flask import g
        # Accepter un X-Request-ID entrant mais valider son format
        incoming = request.headers.get('X-Request-ID', '')
        if incoming and re.match(r'^[a-zA-Z0-9\-_]{1,64}$', incoming):
            g.request_id = incoming
        else:
            g.request_id = str(uuid.uuid4())[:8]

    @app.after_request
    def set_request_id_header(response):
        from flask import g
        if hasattr(g, 'request_id'):
            response.headers['X-Request-ID'] = g.request_id
        return response


# ============================================================================
# FILE MAGIC BYTES VALIDATION
# ============================================================================

# Signatures magiques des types de fichiers autorises
FILE_MAGIC_SIGNATURES = {
    b'ElfChnk\x00': 'evtx',            # Windows EVTX
    b'\xd4\xc3\xb2\xa1': 'pcap',       # PCAP (little endian)
    b'\xa1\xb2\xc3\xd4': 'pcap',       # PCAP (big endian)
    b'\x0a\x0d\x0d\x0a': 'pcapng',     # PCAPng
}

ALLOWED_MIMETYPES = {
    'evtx', 'csv', 'json', 'log', 'txt', 'xml', 'pcap', 'pcapng', 'text'
}


def validate_file_magic(file_bytes: bytes, extension: str) -> bool:
    """
    Valider le contenu reel du fichier par ses magic bytes.
    Retourne True si le fichier est acceptable.
    """
    if not file_bytes:
        return False

    header = file_bytes[:8]
    ext = extension.lower().lstrip('.')

    # Fichiers binaires: verifier la signature exacte
    if ext == 'evtx':
        return header[:8] == b'ElfChnk\x00'
    if ext == 'pcap':
        return header[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    if ext == 'pcapng':
        return header[:4] == b'\x0a\x0d\x0d\x0a'

    # Fichiers texte: verifier l'absence de bytes nuls (heuristique)
    if ext in ('csv', 'log', 'txt'):
        # Accepter UTF-8 BOM
        if file_bytes[:3] == b'\xef\xbb\xbf':
            return True
        # Verifier que c'est du texte lisible (pas de bytes nuls dans les 512 premiers bytes)
        sample = file_bytes[:512]
        null_count = sample.count(b'\x00')
        return null_count == 0

    if ext == 'json':
        # Doit commencer par { ou [ (en ignorant les espaces et BOM)
        text_start = file_bytes.lstrip(b'\xef\xbb\xbf \t\r\n')[:1]
        return text_start in (b'{', b'[')

    if ext == 'xml':
        text_start = file_bytes.lstrip(b'\xef\xbb\xbf \t\r\n')
        return text_start[:1] == b'<' or text_start[:5].lower() == b'<?xml'

    # Par defaut: accepter
    return True


def detect_file_type_magic(file_bytes: bytes) -> str | None:
    """Detecter le type reel du fichier par magic bytes"""
    if len(file_bytes) < 4:
        return None
    header = file_bytes[:8]
    if header[:8] == b'ElfChnk\x00':
        return 'evtx'
    if header[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
        return 'pcap'
    if header[:4] == b'\x0a\x0d\x0d\x0a':
        return 'pcapng'
    # Tenter d'utiliser python-magic si disponible
    try:
        import magic
        mime = magic.from_buffer(file_bytes, mime=True)
        return mime
    except ImportError:
        pass
    return None


# ============================================================================
# INPUT VALIDATION HELPERS
# ============================================================================

def validate_uuid(value) -> bool:
    """Valider qu'une valeur est un UUID valide"""
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError):
        return False


def sanitize_string(value, max_length=500) -> str:
    """Nettoyer une chaine de caracteres"""
    if not isinstance(value, str):
        return ''
    # Supprimer les caracteres de controle dangereux sauf \n, \r, \t
    cleaned = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', value)
    return cleaned.strip()[:max_length]


def validate_investigation_id(value) -> bool:
    """Valider un ID d'investigation (UUID ou ancien format alphanum)"""
    if not value or not isinstance(value, str):
        return False
    if validate_uuid(value):
        return True
    # Accepter les anciens IDs alphanumeriques (migration)
    return bool(re.match(r'^[a-zA-Z0-9_\-]{8,64}$', value))
