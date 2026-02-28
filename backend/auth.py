"""
Phoenix DFIR - Authentication Module (JWT)
Gestion de l'authentification et autorisation
Production-hardened: account lockout, strong passwords, refresh tokens
"""

import os
import re
import hashlib
import hmac
import json
import time
import uuid
import base64
import logging
from functools import wraps
from flask import request, jsonify, g

logger = logging.getLogger(__name__)

# Secret key from environment only - no fallback to file in production
SECRET_KEY = os.environ.get('PHOENIX_SECRET_KEY', None)
if not SECRET_KEY:
    key_file = os.path.join(os.path.dirname(__file__), '.secret_key')
    if os.path.exists(key_file):
        with open(key_file, 'r') as f:
            SECRET_KEY = f.read().strip()
    if not SECRET_KEY:
        import secrets
        SECRET_KEY = secrets.token_hex(64)
        with open(key_file, 'w') as f:
            f.write(SECRET_KEY)
        os.chmod(key_file, 0o600)

TOKEN_EXPIRY = int(os.environ.get('PHOENIX_TOKEN_EXPIRY', 3600))        # 1h default (was 24h)
REFRESH_TOKEN_EXPIRY = int(os.environ.get('PHOENIX_REFRESH_EXPIRY', 604800))  # 7 days

# Account lockout config
MAX_FAILED_ATTEMPTS = int(os.environ.get('PHOENIX_MAX_FAILED_ATTEMPTS', 5))
LOCKOUT_DURATION = int(os.environ.get('PHOENIX_LOCKOUT_DURATION', 900))  # 15 minutes


# ============================================================================
# PASSWORD UTILITIES
# ============================================================================

def validate_password_strength(password: str) -> tuple[bool, str]:
    """Valider la complexite du mot de passe - retourne (ok, message)"""
    if len(password) < 12:
        return False, 'Mot de passe: 12 caracteres minimum'
    if not re.search(r'[A-Z]', password):
        return False, 'Mot de passe: au moins une majuscule requise'
    if not re.search(r'[a-z]', password):
        return False, 'Mot de passe: au moins une minuscule requise'
    if not re.search(r'\d', password):
        return False, 'Mot de passe: au moins un chiffre requis'
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;\'`~]', password):
        return False, 'Mot de passe: au moins un caractere special requis'
    return True, ''


def hash_password(password: str) -> str:
    """Hash un mot de passe avec salt PBKDF2-SHA256 (310000 iterations)"""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 310000)
    return (salt + key).hex()


def verify_password(stored_hash: str, password: str) -> bool:
    """Verifier un mot de passe contre son hash (timing-safe)"""
    try:
        stored_bytes = bytes.fromhex(stored_hash)
        salt = stored_bytes[:32]
        stored_key = stored_bytes[32:]
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 310000)
        return hmac.compare_digest(stored_key, new_key)
    except Exception:
        return False


# ============================================================================
# JWT UTILITIES
# ============================================================================

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def _b64_decode(s: str) -> bytes:
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)


def create_access_token(user_id: int, username: str, role: str) -> str:
    """Creer un access token JWT court (1h)"""
    header = _b64_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_data = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "type": "access",
        "jti": uuid.uuid4().hex,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRY
    }
    payload = _b64_encode(json.dumps(payload_data).encode())
    signature_input = f"{header}.{payload}".encode()
    sig = _b64_encode(hmac.new(SECRET_KEY.encode(), signature_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


# Keep old name for backwards compatibility within the codebase
def create_token(user_id: int, username: str, role: str) -> str:
    return create_access_token(user_id, username, role)


def create_refresh_token(user_id: int) -> tuple[str, str]:
    """Creer un refresh token opaque - retourne (token_raw, token_hash)"""
    import secrets as _sec
    token_raw = _sec.token_urlsafe(64)
    token_hash = hashlib.sha256(token_raw.encode()).hexdigest()
    return token_raw, token_hash


def decode_token(token: str) -> dict | None:
    """Decoder et verifier un access token JWT"""
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

        return payload_data
    except Exception:
        return None


# ============================================================================
# AUTH DECORATORS
# ============================================================================

def require_auth(f):
    """Decorateur: route necessite authentification"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')

        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Token requis'}), 401

        token = auth_header[7:]
        payload = decode_token(token)

        if not payload:
            return jsonify({'error': 'Token invalide ou expire'}), 401

        g.user_id = payload['user_id']
        g.username = payload['username']
        g.role = payload['role']

        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    """Decorateur: route necessite un role specifique"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'role') or g.role not in roles:
                return jsonify({'error': 'Acces refuse - role insuffisant'}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ============================================================================
# AUTH ROUTES
# ============================================================================

def register_auth_routes(app):
    """Enregistrer les routes d'authentification"""
    from database import get_db, log_audit
    from middleware import rate_limit

    @app.route('/api/auth/register', methods=['POST'])
    @rate_limit(max_requests=5, window=60)
    def auth_register():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Donnees requises'}), 400

        username = data.get('username', '').strip()
        password = data.get('password', '')
        display_name = data.get('display_name', username).strip()

        # Validation username
        if not username or len(username) < 3 or len(username) > 32:
            return jsonify({'error': 'Nom d\'utilisateur: 3-32 caracteres'}), 400
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', username):
            return jsonify({'error': 'Nom d\'utilisateur: lettres, chiffres, _, -, . uniquement'}), 400

        # Validation password
        pw_ok, pw_msg = validate_password_strength(password)
        if not pw_ok:
            return jsonify({'error': pw_msg}), 400

        # Validation display_name
        if len(display_name) > 64:
            display_name = display_name[:64]

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

        token = create_access_token(user_id, username, role)
        refresh_raw, refresh_hash = create_refresh_token(user_id)

        expires_at = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time() + REFRESH_TOKEN_EXPIRY))
        db.execute(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, refresh_hash, expires_at)
        )
        db.commit()

        log_audit(user_id, username, 'register', 'user', str(user_id), ip_address=request.remote_addr)
        logger.info(f"User registered: {username} role={role} ip={request.remote_addr}")

        return jsonify({
            'token': token,
            'refresh_token': refresh_raw,
            'expires_in': TOKEN_EXPIRY,
            'user': {'id': user_id, 'username': username, 'display_name': display_name, 'role': role}
        }), 201

    @app.route('/api/auth/login', methods=['POST'])
    @rate_limit(max_requests=10, window=60)
    def auth_login():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Donnees requises'}), 400

        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Identifiants requis'}), 400

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        # Verifier le lockout
        if user and user['locked_until']:
            import datetime as _dt
            locked_until = user['locked_until']
            if isinstance(locked_until, str):
                try:
                    locked_until_dt = _dt.datetime.fromisoformat(locked_until)
                    if locked_until_dt > _dt.datetime.utcnow():
                        remaining = int((locked_until_dt - _dt.datetime.utcnow()).total_seconds())
                        return jsonify({
                            'error': f'Compte verrouille. Reessayez dans {remaining} secondes.'
                        }), 429
                except (ValueError, TypeError):
                    pass

        # Timing-safe: toujours verifier le mot de passe meme si user absent
        dummy_hash = 'a' * 128
        stored_hash = user['password_hash'] if user else dummy_hash
        password_ok = verify_password(stored_hash, password)

        if not user or not password_ok:
            if user:
                attempts = (user['failed_login_attempts'] or 0) + 1
                if attempts >= MAX_FAILED_ATTEMPTS:
                    import datetime as _dt
                    locked_until = (_dt.datetime.utcnow() + _dt.timedelta(seconds=LOCKOUT_DURATION)).isoformat()
                    db.execute(
                        "UPDATE users SET failed_login_attempts=?, locked_until=? WHERE id=?",
                        (attempts, locked_until, user['id'])
                    )
                    db.commit()
                    logger.warning(f"Account locked: {username} after {attempts} failed attempts ip={request.remote_addr}")
                    return jsonify({
                        'error': f'Compte verrouille suite a {attempts} tentatives echouees. Reessayez dans {LOCKOUT_DURATION // 60} minutes.'
                    }), 429
                else:
                    db.execute(
                        "UPDATE users SET failed_login_attempts=? WHERE id=?",
                        (attempts, user['id'])
                    )
                    db.commit()
                    logger.warning(f"Failed login: {username} attempt={attempts} ip={request.remote_addr}")

            return jsonify({'error': 'Identifiants incorrects'}), 401

        # Succes: reinitialiser le compteur d'echecs
        db.execute(
            "UPDATE users SET last_login=CURRENT_TIMESTAMP, failed_login_attempts=0, locked_until=NULL WHERE id=?",
            (user['id'],)
        )
        db.commit()

        token = create_access_token(user['id'], user['username'], user['role'])
        refresh_raw, refresh_hash = create_refresh_token(user['id'])

        expires_at = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time() + REFRESH_TOKEN_EXPIRY))
        db.execute(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user['id'], refresh_hash, expires_at)
        )
        db.commit()

        log_audit(user['id'], username, 'login', ip_address=request.remote_addr)
        logger.info(f"Login success: {username} ip={request.remote_addr}")

        return jsonify({
            'token': token,
            'refresh_token': refresh_raw,
            'expires_in': TOKEN_EXPIRY,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'display_name': user['display_name'],
                'role': user['role']
            }
        })

    @app.route('/api/auth/refresh', methods=['POST'])
    @rate_limit(max_requests=30, window=60)
    def auth_refresh():
        """Echanger un refresh token contre un nouveau access token"""
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'error': 'Donnees requises'}), 400

        refresh_raw = data.get('refresh_token', '')
        if not refresh_raw:
            return jsonify({'error': 'refresh_token requis'}), 400

        refresh_hash = hashlib.sha256(refresh_raw.encode()).hexdigest()
        db = get_db()

        row = db.execute(
            """SELECT rt.*, u.username, u.role, u.locked_until
               FROM refresh_tokens rt
               JOIN users u ON u.id = rt.user_id
               WHERE rt.token_hash=? AND rt.revoked=0""",
            (refresh_hash,)
        ).fetchone()

        if not row:
            return jsonify({'error': 'Refresh token invalide'}), 401

        import datetime as _dt
        try:
            exp_dt = _dt.datetime.fromisoformat(str(row['expires_at']))
            if exp_dt <= _dt.datetime.utcnow():
                return jsonify({'error': 'Refresh token expire'}), 401
        except (ValueError, TypeError):
            return jsonify({'error': 'Refresh token invalide'}), 401

        # Verifier que le compte n'est pas verrouille
        if row['locked_until']:
            try:
                locked_until_dt = _dt.datetime.fromisoformat(str(row['locked_until']))
                if locked_until_dt > _dt.datetime.utcnow():
                    return jsonify({'error': 'Compte verrouille'}), 429
            except (ValueError, TypeError):
                pass

        # Rotation: revoquer l'ancien, creer un nouveau
        db.execute("UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?", (refresh_hash,))

        new_access = create_access_token(row['user_id'], row['username'], row['role'])
        new_raw, new_hash = create_refresh_token(row['user_id'])

        expires_at = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time() + REFRESH_TOKEN_EXPIRY))
        db.execute(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (row['user_id'], new_hash, expires_at)
        )
        db.commit()

        # Nettoyer les vieux refresh tokens (> 30 jours)
        try:
            cutoff = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time() - 30 * 86400))
            db.execute("DELETE FROM refresh_tokens WHERE created_at < ? OR revoked=1 AND created_at < ?", (cutoff, cutoff))
            db.commit()
        except Exception:
            pass

        return jsonify({
            'token': new_access,
            'refresh_token': new_raw,
            'expires_in': TOKEN_EXPIRY
        })

    @app.route('/api/auth/logout', methods=['POST'])
    @require_auth
    def auth_logout():
        """Revoquer le refresh token de la session courante"""
        data = request.get_json(silent=True) or {}
        refresh_raw = data.get('refresh_token', '')

        if refresh_raw:
            refresh_hash = hashlib.sha256(refresh_raw.encode()).hexdigest()
            db = get_db()
            db.execute(
                "UPDATE refresh_tokens SET revoked=1 WHERE token_hash=? AND user_id=?",
                (refresh_hash, g.user_id)
            )
            db.commit()

        log_audit(g.user_id, g.username, 'logout', ip_address=request.remote_addr)
        return jsonify({'message': 'Deconnecte avec succes'})

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

    @app.route('/api/auth/users', methods=['GET'])
    @require_auth
    @require_role('admin')
    def list_users():
        db = get_db()
        users = db.execute(
            "SELECT id, username, display_name, role, created_at, last_login, failed_login_attempts, locked_until FROM users ORDER BY created_at DESC"
        ).fetchall()
        return jsonify([dict(u) for u in users])

    @app.route('/api/auth/users/<int:user_id>/unlock', methods=['POST'])
    @require_auth
    @require_role('admin')
    def unlock_user(user_id):
        """Deverrouiller manuellement un compte (admin seulement)"""
        db = get_db()
        user = db.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            return jsonify({'error': 'Utilisateur non trouve'}), 404

        db.execute(
            "UPDATE users SET failed_login_attempts=0, locked_until=NULL WHERE id=?",
            (user_id,)
        )
        db.commit()
        log_audit(g.user_id, g.username, 'unlock_user', 'user', str(user_id), ip_address=request.remote_addr)
        logger.info(f"Account unlocked: {user['username']} by {g.username}")
        return jsonify({'message': f'Compte {user["username"]} deverrouille'})

    @app.route('/api/auth/users/<int:user_id>/role', methods=['PUT'])
    @require_auth
    @require_role('admin')
    def update_user_role(user_id):
        """Modifier le role d'un utilisateur (admin seulement)"""
        data = request.get_json(silent=True) or {}
        new_role = data.get('role', '')
        if new_role not in ('admin', 'analyst', 'viewer'):
            return jsonify({'error': 'Role invalide'}), 400

        # L'admin ne peut pas changer son propre role
        if user_id == g.user_id:
            return jsonify({'error': 'Impossible de modifier votre propre role'}), 400

        db = get_db()
        user = db.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            return jsonify({'error': 'Utilisateur non trouve'}), 404

        db.execute("UPDATE users SET role=? WHERE id=?", (new_role, user_id))
        db.commit()
        log_audit(g.user_id, g.username, 'update_role', 'user', str(user_id),
                  details=f'new_role={new_role}', ip_address=request.remote_addr)
        return jsonify({'message': 'Role mis a jour'})
