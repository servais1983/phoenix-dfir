"""
Phoenix DFIR - Authentication Module (JWT)
Gestion de l'authentification et autorisation
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
        os.chmod(key_file, 0o600)

TOKEN_EXPIRY = int(os.environ.get('PHOENIX_TOKEN_EXPIRY', 86400))  # 24h default


def hash_password(password):
    """Hash un mot de passe avec salt"""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return (salt + key).hex()


def verify_password(stored_hash, password):
    """Verifier un mot de passe contre son hash"""
    try:
        stored_bytes = bytes.fromhex(stored_hash)
        salt = stored_bytes[:32]
        stored_key = stored_bytes[32:]
        new_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return hmac.compare_digest(stored_key, new_key)
    except Exception:
        return False


def _b64_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def _b64_decode(s):
    padding = 4 - len(s) % 4
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s)


def create_token(user_id, username, role):
    """Creer un token JWT simple (sans dependance externe)"""
    header = _b64_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_data = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + TOKEN_EXPIRY
    }
    payload = _b64_encode(json.dumps(payload_data).encode())
    signature_input = f"{header}.{payload}".encode()
    signature = _b64_encode(hmac.new(SECRET_KEY.encode(), signature_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def decode_token(token):
    """Decoder et verifier un token JWT"""
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


def register_auth_routes(app):
    """Enregistrer les routes d'authentification"""
    from database import get_db, log_audit

    from middleware import rate_limit

    @app.route('/api/auth/register', methods=['POST'])
    @rate_limit(max_requests=10, window=60)
    def auth_register():
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Donnees requises'}), 400

        username = data.get('username', '').strip()
        password = data.get('password', '')
        display_name = data.get('display_name', username)

        if not username or len(username) < 3:
            return jsonify({'error': 'Nom d\'utilisateur: 3 caracteres minimum'}), 400
        if not password or len(password) < 6:
            return jsonify({'error': 'Mot de passe: 6 caracteres minimum'}), 400

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

        token = create_token(user_id, username, role)
        log_audit(user_id, username, 'register', 'user', str(user_id), ip_address=request.remote_addr)

        return jsonify({
            'token': token,
            'user': {'id': user_id, 'username': username, 'display_name': display_name, 'role': role}
        }), 201

    @app.route('/api/auth/login', methods=['POST'])
    @rate_limit(max_requests=10, window=60)
    def auth_login():
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Donnees requises'}), 400

        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Identifiants requis'}), 400

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if not user or not verify_password(user['password_hash'], password):
            return jsonify({'error': 'Identifiants incorrects'}), 401

        db.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?", (user['id'],))
        db.commit()

        token = create_token(user['id'], user['username'], user['role'])
        log_audit(user['id'], username, 'login', ip_address=request.remote_addr)

        return jsonify({
            'token': token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'display_name': user['display_name'],
                'role': user['role']
            }
        })

    @app.route('/api/auth/me', methods=['GET'])
    @require_auth
    def auth_me():
        db = get_db()
        user = db.execute("SELECT id, username, display_name, role, created_at, last_login FROM users WHERE id=?", (g.user_id,)).fetchone()
        if not user:
            return jsonify({'error': 'Utilisateur non trouve'}), 404
        return jsonify(dict(user))

    @app.route('/api/auth/users', methods=['GET'])
    @require_auth
    @require_role('admin')
    def list_users():
        db = get_db()
        users = db.execute("SELECT id, username, display_name, role, created_at, last_login FROM users ORDER BY created_at DESC").fetchall()
        return jsonify([dict(u) for u in users])
