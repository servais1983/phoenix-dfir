"""
Phoenix DFIR - Authentication Module (JWT)
Access tokens courts + refresh tokens longs, revocation server-side via cache,
politique de mot de passe robuste.
"""

import os
import hashlib
import hmac
import json
import time
import uuid
import base64
from functools import wraps
from flask import request, jsonify, g

from cache import cache

# Secret key from environment or generated
SECRET_KEY = os.environ.get('PHOENIX_SECRET_KEY', None)
if not SECRET_KEY:
    key_file = os.path.join(os.path.dirname(__file__), '.secret_key')
    if os.path.exists(key_file):
        with open(key_file, 'r') as f:
            SECRET_KEY = f.read().strip()
    else:
        SECRET_KEY = uuid.uuid4().hex + uuid.uuid4().hex
        with open(key_file, 'w') as f:
            f.write(SECRET_KEY)
        try:
            os.chmod(key_file, 0o600)
        except (OSError, NotImplementedError):
            # Windows ne supporte pas chmod POSIX, on ignore
            pass

# Duree des tokens
ACCESS_TOKEN_EXPIRY = int(os.environ.get('PHOENIX_ACCESS_TOKEN_EXPIRY', 900))  # 15 min
REFRESH_TOKEN_EXPIRY = int(os.environ.get('PHOENIX_REFRESH_TOKEN_EXPIRY', 7 * 86400))  # 7 jours
# Retro-compat: PHOENIX_TOKEN_EXPIRY si defini overrides access token
_legacy = os.environ.get('PHOENIX_TOKEN_EXPIRY')
if _legacy:
    try:
        ACCESS_TOKEN_EXPIRY = int(_legacy)
    except ValueError:
        pass

# Iterations PBKDF2 (calibrees pour ~100ms sur CPU moderne)
PBKDF2_ITERATIONS = int(os.environ.get('PHOENIX_PBKDF2_ITERATIONS', 600_000))


def hash_password(password):
    """Hash un mot de passe avec salt aleatoire et PBKDF2-SHA256."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    # Format: iter|salt_hex|key_hex (versionne pour migration future)
    return f'pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${key.hex()}'


def verify_password(stored_hash, password):
    """Verifier un mot de passe contre son hash. Supporte ancien et nouveau format."""
    if not stored_hash or not isinstance(stored_hash, str):
        return False
    try:
        if stored_hash.startswith('pbkdf2_sha256$'):
            _, iters, salt_hex, key_hex = stored_hash.split('$', 3)
            salt = bytes.fromhex(salt_hex)
            stored_key = bytes.fromhex(key_hex)
            new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, int(iters))
            return hmac.compare_digest(stored_key, new_key)
        # Ancien format: salt(32) + key, tout en hex
        stored_bytes = bytes.fromhex(stored_hash)
        salt = stored_bytes[:32]
        stored_key = stored_bytes[32:]
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return hmac.compare_digest(stored_key, new_key)
    except Exception:
        return False


def password_needs_rehash(stored_hash):
    """True si le hash utilise un ancien format/iterations et merite un upgrade."""
    if not isinstance(stored_hash, str):
        return False
    if not stored_hash.startswith('pbkdf2_sha256$'):
        return True
    try:
        _, iters, _, _ = stored_hash.split('$', 3)
        return int(iters) < PBKDF2_ITERATIONS
    except Exception:
        return True


def _b64_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def _b64_decode(s):
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)


def _build_token(payload_data):
    header = _b64_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(',', ':')).encode())
    payload = _b64_encode(json.dumps(payload_data, separators=(',', ':')).encode())
    signature_input = f"{header}.{payload}".encode()
    signature = _b64_encode(hmac.new(SECRET_KEY.encode(), signature_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def create_token(user_id, username, role, token_type='access', expiry=None):
    """Creer un token JWT (access ou refresh) avec jti unique pour revocation."""
    if expiry is None:
        expiry = ACCESS_TOKEN_EXPIRY if token_type == 'access' else REFRESH_TOKEN_EXPIRY
    now = int(time.time())
    payload_data = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "type": token_type,
        "iat": now,
        "exp": now + expiry,
        "jti": uuid.uuid4().hex,
    }
    return _build_token(payload_data)


def decode_token(token, expected_type='access'):
    """Decoder, verifier signature, expiration et revocation d'un token."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header, payload, signature = parts
        signature_input = f"{header}.{payload}".encode()
        expected_sig = _b64_encode(hmac.new(SECRET_KEY.encode(), signature_input, hashlib.sha256).digest())

        if not hmac.compare_digest(signature, expected_sig):
            return None

        payload_data = json.loads(_b64_decode(payload))

        if payload_data.get('exp', 0) < time.time():
            return None

        token_type = payload_data.get('type', 'access')
        if expected_type and token_type != expected_type:
            return None

        # Verifier revocation
        jti = payload_data.get('jti')
        if jti and cache.exists(f'revoked:{jti}'):
            return None

        return payload_data
    except Exception:
        return None


def revoke_token(payload_data):
    """Marquer un token comme revoque jusqu'a son expiration naturelle."""
    jti = payload_data.get('jti')
    if not jti:
        return False
    exp = payload_data.get('exp', 0)
    ttl = max(1, int(exp - time.time()))
    cache.set(f'revoked:{jti}', 1, ttl=ttl)
    return True


def require_auth(f):
    """Decorateur: route necessite authentification."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token requis'}), 401

        token = auth_header[7:]
        payload = decode_token(token, expected_type='access')

        if not payload:
            return jsonify({'error': 'Token invalide ou expire'}), 401

        g.user_id = payload['user_id']
        g.username = payload['username']
        g.role = payload['role']
        g.token_jti = payload.get('jti')
        g.token_payload = payload

        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    """Decorateur: route necessite un role specifique."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'role') or g.role not in roles:
                return jsonify({'error': 'Acces refuse - role insuffisant'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def _issue_token_pair(user_id, username, role):
    """Helper: renvoie access + refresh tokens."""
    access = create_token(user_id, username, role, token_type='access')
    refresh = create_token(user_id, username, role, token_type='refresh')
    return {
        'token': access,                # retro-compat (clients existants)
        'access_token': access,
        'refresh_token': refresh,
        'token_type': 'Bearer',
        'expires_in': ACCESS_TOKEN_EXPIRY,
        'refresh_expires_in': REFRESH_TOKEN_EXPIRY,
    }


def register_auth_routes(app):
    """Enregistrer les routes d'authentification."""
    from database import get_db, log_audit
    from middleware import rate_limit, validate_password, sanitize_string

    @app.route('/api/auth/register', methods=['POST'])
    @rate_limit(max_requests=5, window=60, scope='auth')
    def auth_register():
        data = request.get_json(silent=True) or {}

        username = sanitize_string(data.get('username', ''), max_length=64).strip()
        password = data.get('password', '')
        display_name = sanitize_string(data.get('display_name', ''), max_length=128) or username

        if not username or len(username) < 3:
            return jsonify({'error': 'Nom d\'utilisateur: 3 caracteres minimum'}), 400
        if not username.replace('_', '').replace('-', '').replace('.', '').isalnum():
            return jsonify({'error': 'Nom d\'utilisateur: lettres, chiffres, . _ - uniquement'}), 400

        ok, reason = validate_password(password)
        if not ok:
            return jsonify({'error': reason}), 400

        db = get_db()

        existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            return jsonify({'error': 'Ce nom d\'utilisateur existe deja'}), 409

        # Premier utilisateur = admin
        user_count = db.execute("SELECT COUNT(*) as cnt FROM users").fetchone()['cnt']
        role = 'admin' if user_count == 0 else 'analyst'

        pw_hash = hash_password(password)
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
            (username, pw_hash, display_name, role)
        )
        db.commit()
        user_id = cursor.lastrowid

        tokens = _issue_token_pair(user_id, username, role)
        log_audit(user_id, username, 'register', 'user', str(user_id), ip_address=request.remote_addr)

        return jsonify({
            **tokens,
            'user': {'id': user_id, 'username': username, 'display_name': display_name, 'role': role}
        }), 201

    @app.route('/api/auth/login', methods=['POST'])
    @rate_limit(max_requests=10, window=60, scope='auth')
    def auth_login():
        data = request.get_json(silent=True) or {}

        username = sanitize_string(data.get('username', ''), max_length=64).strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Identifiants requis'}), 400

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if not user or not verify_password(user['password_hash'], password):
            # Log echec pour detection brute force
            log_audit(None, username, 'login_failed', ip_address=request.remote_addr)
            return jsonify({'error': 'Identifiants incorrects'}), 401

        # Upgrade transparent du hash si necessaire
        if password_needs_rehash(user['password_hash']):
            try:
                new_hash = hash_password(password)
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user['id']))
            except Exception:
                pass

        db.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?", (user['id'],))
        db.commit()

        tokens = _issue_token_pair(user['id'], user['username'], user['role'])
        log_audit(user['id'], username, 'login', ip_address=request.remote_addr)

        return jsonify({
            **tokens,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'display_name': user['display_name'],
                'role': user['role']
            }
        })

    @app.route('/api/auth/refresh', methods=['POST'])
    @rate_limit(max_requests=30, window=60, scope='auth')
    def auth_refresh():
        """Echanger un refresh token contre une nouvelle paire."""
        data = request.get_json(silent=True) or {}
        refresh_token = data.get('refresh_token', '')
        if not refresh_token:
            return jsonify({'error': 'refresh_token requis'}), 400

        payload = decode_token(refresh_token, expected_type='refresh')
        if not payload:
            return jsonify({'error': 'Refresh token invalide ou expire'}), 401

        # Verifier que l'utilisateur existe toujours
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (payload['user_id'],)).fetchone()
        if not user:
            return jsonify({'error': 'Utilisateur introuvable'}), 401

        # Rotation: revoque l'ancien refresh, en emet un nouveau
        revoke_token(payload)
        tokens = _issue_token_pair(user['id'], user['username'], user['role'])
        log_audit(user['id'], user['username'], 'token_refresh', ip_address=request.remote_addr)

        return jsonify({
            **tokens,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'display_name': user['display_name'],
                'role': user['role'],
            }
        })

    @app.route('/api/auth/logout', methods=['POST'])
    @require_auth
    def auth_logout():
        """Revoquer le token courant (et eventuellement le refresh fourni)."""
        # Revoquer access token courant
        if hasattr(g, 'token_payload'):
            revoke_token(g.token_payload)

        # Revoquer aussi le refresh si fourni
        data = request.get_json(silent=True) or {}
        refresh_token = data.get('refresh_token', '')
        if refresh_token:
            payload = decode_token(refresh_token, expected_type='refresh')
            if payload:
                revoke_token(payload)

        log_audit(g.user_id, g.username, 'logout', ip_address=request.remote_addr)
        return jsonify({'message': 'Deconnecte'})

    @app.route('/api/auth/me', methods=['GET'])
    @require_auth
    def auth_me():
        db = get_db()
        user = db.execute(
            "SELECT id, username, display_name, role, created_at, last_login FROM users WHERE id=?",
            (g.user_id,)
        ).fetchone()
        if not user:
            return jsonify({'error': 'Utilisateur non trouve'}), 404
        return jsonify(dict(user))

    @app.route('/api/auth/password', methods=['PUT'])
    @require_auth
    def auth_change_password():
        """Changer son propre mot de passe."""
        data = request.get_json(silent=True) or {}
        current = data.get('current_password', '')
        new = data.get('new_password', '')

        if not current or not new:
            return jsonify({'error': 'Mots de passe requis'}), 400

        ok, reason = validate_password(new)
        if not ok:
            return jsonify({'error': reason}), 400

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (g.user_id,)).fetchone()
        if not user or not verify_password(user['password_hash'], current):
            return jsonify({'error': 'Mot de passe actuel incorrect'}), 401

        if verify_password(user['password_hash'], new):
            return jsonify({'error': 'Le nouveau mot de passe doit etre different'}), 400

        new_hash = hash_password(new)
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, g.user_id))
        db.commit()

        # Revoquer le token courant pour forcer un re-login
        if hasattr(g, 'token_payload'):
            revoke_token(g.token_payload)

        log_audit(g.user_id, g.username, 'password_changed', ip_address=request.remote_addr)
        return jsonify({'message': 'Mot de passe modifie. Reconnectez-vous.'})

    @app.route('/api/auth/users', methods=['GET'])
    @require_auth
    @require_role('admin')
    def list_users():
        db = get_db()
        users = db.execute(
            "SELECT id, username, display_name, role, created_at, last_login FROM users ORDER BY created_at DESC"
        ).fetchall()
        return jsonify([dict(u) for u in users])
