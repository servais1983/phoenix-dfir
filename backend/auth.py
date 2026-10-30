"""
Phoenix DFIR - Authentication Module (JWT)
Access tokens courts + refresh tokens longs (cookie HttpOnly), revocation
server-side via cache et token_version, politique de mot de passe robuste.
"""

import os
import hashlib
import hmac
import json
import logging
import secrets
import sqlite3
import sys
import time
import uuid
import base64
from functools import wraps
from flask import request, jsonify, g, has_app_context, current_app

from cache import cache
import datadirs

_logger = logging.getLogger('phoenix')


def is_production():
    """Mode production explicite (PHOENIX_ENV=production)."""
    return os.environ.get('PHOENIX_ENV', '').strip().lower() in ('production', 'prod')


def _load_secret_key():
    """Cle de signature JWT.

    PHOENIX_SECRET_KEY est obligatoire en production. En developpement, une
    cle est generee dans backend/.secret_key (permissions 0600) avec un
    avertissement explicite dans les logs.
    """
    key = os.environ.get('PHOENIX_SECRET_KEY', '').strip()
    if key:
        return key
    if is_production():
        raise RuntimeError(
            'PHOENIX_SECRET_KEY est obligatoire en production (PHOENIX_ENV=production). '
            'Generez-la avec : python -c "import secrets; print(secrets.token_hex(64))"')
    key_file = datadirs.secret_key_file()
    if os.path.exists(key_file):
        try:
            os.chmod(key_file, 0o600)
        except (OSError, NotImplementedError):
            pass
        with open(key_file, 'r') as f:
            key = f.read().strip()
        if key:
            _logger.warning('PHOENIX_SECRET_KEY absent : cle JWT lue depuis backend/.secret_key '
                            '(mode developpement uniquement)')
            return key
    key = secrets.token_hex(64)
    try:
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(key)
        try:
            os.chmod(key_file, 0o600)
        except (OSError, NotImplementedError):
            # Windows ne supporte pas chmod POSIX, on ignore
            pass
    except OSError:
        pass
    msg = ('!!! PHOENIX_SECRET_KEY absent : cle JWT generee dans backend/.secret_key. '
           'Mode developpement uniquement : definissez PHOENIX_SECRET_KEY en production. !!!')
    _logger.warning(msg)
    print(msg, file=sys.stderr)
    return key


SECRET_KEY = _load_secret_key()

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


def create_token(user_id, username, role, token_type='access', expiry=None, token_version=0):
    """Creer un token JWT (access ou refresh) avec jti unique pour revocation.

    Le claim `tv` (token_version) doit egaler users.token_version : un
    changement de mot de passe, de role ou une desactivation l'incremente et
    invalide toutes les sessions existantes.
    """
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
        "tv": int(token_version or 0),
    }
    return _build_token(payload_data)


def get_user_state(user_id):
    """Etat courant d'un utilisateur (role, token_version, disabled) ou None."""
    if user_id is None:
        return None
    import database
    query = "SELECT id, username, display_name, role, token_version, disabled FROM users WHERE id=?"
    try:
        if has_app_context():
            row = database.get_db().execute(query, (user_id,)).fetchone()
            return dict(row) if row else None
        conn = sqlite3.connect(database.DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(query, (user_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()
    except sqlite3.Error:
        return None


def decode_token(token, expected_type='access', check_user=True):
    """Decoder, verifier signature, expiration, revocation et token_version.

    check_user=True (defaut) verifie aussi que l'utilisateur existe, n'est pas
    desactive et que le claim `tv` correspond a sa token_version courante ;
    le role renvoye est celui de la base.
    """
    try:
        if not isinstance(token, str):
            return None
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

        if check_user:
            state = get_user_state(payload_data.get('user_id'))
            if not state or state.get('disabled'):
                return None
            if int(payload_data.get('tv', -1)) != int(state.get('token_version') or 0):
                return None
            payload_data['role'] = state['role']
            payload_data['username'] = state['username']

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


VALID_ROLES = ('admin', 'analyst', 'viewer')

# Cookie HttpOnly portant le refresh token (jamais expose au JavaScript)
REFRESH_COOKIE_NAME = 'phoenix_refresh'
REFRESH_COOKIE_PATH = '/api/auth'

# Verrouillage par nom d'utilisateur apres echecs de connexion repetes
LOGIN_LOCKOUT_THRESHOLD = int(os.environ.get('PHOENIX_LOGIN_LOCKOUT_THRESHOLD', 10))
LOGIN_LOCKOUT_WINDOW = int(os.environ.get('PHOENIX_LOGIN_LOCKOUT_WINDOW', 15 * 60))

_SETUP_TOKEN_KEY = 'phoenix:setup_token'


def _truthy(value):
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on')


def registration_open():
    """Auto-inscription ouverte ? (desactivee par defaut)."""
    try:
        if has_app_context() and 'PHOENIX_ALLOW_REGISTRATION' in current_app.config:
            return bool(current_app.config['PHOENIX_ALLOW_REGISTRATION'])
    except RuntimeError:
        pass
    return _truthy(os.environ.get('PHOENIX_ALLOW_REGISTRATION', 'false'))


def get_setup_token():
    """Jeton d'installation a usage unique (cree a la demande)."""
    token = cache.get(_SETUP_TOKEN_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        cache.set(_SETUP_TOKEN_KEY, token)
    return str(token)


def _check_setup_token(candidate):
    expected = cache.get(_SETUP_TOKEN_KEY)
    if not expected or not isinstance(candidate, str) or not candidate:
        return False
    return hmac.compare_digest(str(expected).encode(), candidate.encode())


def _consume_setup_token():
    cache.delete(_SETUP_TOKEN_KEY)


def _txn_connection():
    """Connexion dediee en autocommit pour les transactions BEGIN IMMEDIATE."""
    import database
    conn = sqlite3.connect(database.DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def _count_users():
    import database
    return database.get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]


def bootstrap_users():
    """A appeler au demarrage : cree l'admin initial ou publie un jeton d'installation.

    - PHOENIX_ADMIN_USERNAME + PHOENIX_ADMIN_PASSWORD : admin cree si la table
      users est vide ;
    - sinon, si aucun utilisateur : un jeton d'installation a usage unique est
      genere et affiche dans les logs ; il est exige (setup_token) par la
      premiere inscription, qui devient admin.
    """
    from middleware import validate_password
    if _count_users() > 0:
        return None
    username = os.environ.get('PHOENIX_ADMIN_USERNAME', '').strip()
    password = os.environ.get('PHOENIX_ADMIN_PASSWORD', '')
    if username and password:
        ok, reason = validate_password(password)
        if ok:
            pw_hash = hash_password(password)
            conn = _txn_connection()
            try:
                conn.execute('BEGIN IMMEDIATE')
                conn.execute(
                    "INSERT INTO users (username, password_hash, display_name, role) "
                    "SELECT ?, ?, ?, 'admin' WHERE NOT EXISTS (SELECT 1 FROM users)",
                    (username, pw_hash, username))
                conn.execute('COMMIT')
            except Exception:
                conn.execute('ROLLBACK')
                raise
            finally:
                conn.close()
            _logger.warning('bootstrap_admin_created', extra={'username': username})
            return None
        _logger.error('bootstrap_admin_rejected', extra={'reason': reason})
    token = get_setup_token()
    banner = ('=' * 70 + '\n'
              'Phoenix DFIR : aucun utilisateur. Jeton d\'installation (usage unique) :\n'
              f'    {token}\n'
              'Saisissez-le dans le formulaire de premiere inscription pour creer\n'
              'le compte administrateur (ou definissez PHOENIX_ADMIN_USERNAME /\n'
              'PHOENIX_ADMIN_PASSWORD).\n' + '=' * 70)
    _logger.warning('setup_token_generated', extra={'setup_token': token})
    print(banner, file=sys.stderr)
    return token


def _cookie_secure():
    return bool(request.is_secure or _truthy(os.environ.get('PHOENIX_COOKIE_SECURE', 'false')))


def _set_refresh_cookie(response, refresh_token):
    response.set_cookie(
        REFRESH_COOKIE_NAME, refresh_token,
        max_age=REFRESH_TOKEN_EXPIRY, path=REFRESH_COOKIE_PATH,
        httponly=True, secure=_cookie_secure(), samesite='Strict')
    return response


def _clear_refresh_cookie(response):
    response.delete_cookie(REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH,
                           httponly=True, secure=_cookie_secure(), samesite='Strict')
    return response


def _issue_token_pair(user_id, username, role, token_version=0):
    """Helper: (corps JSON, refresh token). Le refresh part en cookie HttpOnly."""
    access = create_token(user_id, username, role, token_type='access', token_version=token_version)
    refresh = create_token(user_id, username, role, token_type='refresh', token_version=token_version)
    body = {
        'token': access,                # retro-compat (clients existants)
        'access_token': access,
        'token_type': 'Bearer',
        'expires_in': ACCESS_TOKEN_EXPIRY,
        'refresh_expires_in': REFRESH_TOKEN_EXPIRY,
    }
    return body, refresh


def _session_response(user, status=200):
    """Reponse de connexion : access token en JSON, refresh token en cookie."""
    body, refresh = _issue_token_pair(user['id'], user['username'], user['role'],
                                      user.get('token_version') or 0)
    body['user'] = {'id': user['id'], 'username': user['username'],
                    'display_name': user.get('display_name'), 'role': user['role']}
    response = jsonify(body)
    response.status_code = status
    return _set_refresh_cookie(response, refresh)


def _validate_username(username):
    if not username or len(username) < 3:
        return 'Nom d\'utilisateur: 3 caracteres minimum'
    if not username.replace('_', '').replace('-', '').replace('.', '').isalnum():
        return 'Nom d\'utilisateur: lettres, chiffres, . _ - uniquement'
    return None


def _bump_token_version(db, user_id):
    db.execute("UPDATE users SET token_version = COALESCE(token_version, 0) + 1 WHERE id=?", (user_id,))


def _public_user(row):
    d = dict(row)
    return {k: d.get(k) for k in ('id', 'username', 'display_name', 'role', 'created_at',
                                  'last_login', 'disabled')}


def register_auth_routes(app):
    """Enregistrer les routes d'authentification."""
    from database import get_db, log_audit
    from middleware import rate_limit, validate_password, sanitize_string

    @app.route('/api/auth/setup-status', methods=['GET'])
    def auth_setup_status():
        """Public : premiere installation et ouverture des inscriptions."""
        return jsonify({
            'needs_setup': _count_users() == 0,
            'registration_open': registration_open(),
        })

    @app.route('/api/auth/register', methods=['POST'])
    @rate_limit(max_requests=5, window=60, scope='auth')
    def auth_register():
        data = request.get_json(silent=True) or {}

        username = sanitize_string(data.get('username', ''), max_length=64).strip()
        password = data.get('password', '')
        display_name = sanitize_string(data.get('display_name', ''), max_length=128) or username
        setup_token = data.get('setup_token', '')

        err = _validate_username(username)
        if err:
            return jsonify({'error': err}), 400

        ok, reason = validate_password(password)
        if not ok:
            return jsonify({'error': reason}), 400

        # Hachage hors transaction : le verrou d'ecriture reste tres court
        pw_hash = hash_password(password)

        conn = _txn_connection()
        try:
            # BEGIN IMMEDIATE : deux inscriptions concurrentes sur une base
            # vide ne peuvent pas devenir admin toutes les deux.
            conn.execute('BEGIN IMMEDIATE')
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if user_count == 0:
                if not _check_setup_token(setup_token):
                    conn.execute('ROLLBACK')
                    return jsonify({'error': 'Jeton d\'installation requis ou invalide '
                                             '(voir les logs du serveur)',
                                    'needs_setup': True}), 403
                role = 'admin'
            else:
                if not registration_open():
                    conn.execute('ROLLBACK')
                    return jsonify({'error': 'Inscriptions fermees : demandez un compte '
                                             'a un administrateur'}), 403
                role = 'viewer'
            if conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
                conn.execute('ROLLBACK')
                return jsonify({'error': 'Ce nom d\'utilisateur existe deja'}), 409
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
                (username, pw_hash, display_name, role))
            user_id = cursor.lastrowid
            conn.execute('COMMIT')
        except Exception:
            try:
                conn.execute('ROLLBACK')
            except sqlite3.Error:
                pass
            raise
        finally:
            conn.close()

        if role == 'admin':
            _consume_setup_token()

        log_audit(user_id, username, 'register', 'user', str(user_id),
                  details=json.dumps({'role': role}), ip_address=request.remote_addr)
        return _session_response({'id': user_id, 'username': username, 'display_name': display_name,
                                  'role': role, 'token_version': 0}, status=201)

    @app.route('/api/auth/login', methods=['POST'])
    @rate_limit(max_requests=10, window=60, scope='auth')
    def auth_login():
        data = request.get_json(silent=True) or {}

        username = sanitize_string(data.get('username', ''), max_length=64).strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Identifiants requis'}), 400

        # Verrouillage par nom d'utilisateur (independant de l'IP) : applique
        # aussi aux comptes inexistants pour ne rien reveler.
        lock_key = f'login_lock:{username.lower()}'
        if cache.exists(lock_key):
            log_audit(None, username, 'login_locked', ip_address=request.remote_addr)
            return jsonify({'error': 'Trop de tentatives. Reessayez plus tard.'}), 429

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if not user or user['disabled'] or not verify_password(user['password_hash'], password):
            # Log echec pour detection brute force
            log_audit(None, username, 'login_failed', ip_address=request.remote_addr)
            hits = cache.sliding_window_hit(f'login_fail:{username.lower()}', LOGIN_LOCKOUT_WINDOW)
            if hits >= LOGIN_LOCKOUT_THRESHOLD:
                cache.set(lock_key, 1, ttl=LOGIN_LOCKOUT_WINDOW)
                log_audit(None, username, 'login_lockout', ip_address=request.remote_addr)
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
        cache.delete(f'login_fail:{username.lower()}')

        log_audit(user['id'], username, 'login', ip_address=request.remote_addr)
        return _session_response(dict(user))

    @app.route('/api/auth/refresh', methods=['POST'])
    @rate_limit(max_requests=30, window=60, scope='auth')
    def auth_refresh():
        """Echanger le refresh token (cookie HttpOnly) contre une nouvelle paire."""
        refresh_token = request.cookies.get(REFRESH_COOKIE_NAME, '')
        if not refresh_token:
            # Retro-compat clients API : refresh token dans le corps JSON
            data = request.get_json(silent=True) or {}
            refresh_token = data.get('refresh_token', '')
        if not refresh_token:
            return jsonify({'error': 'refresh_token requis'}), 401

        payload = decode_token(refresh_token, expected_type='refresh')
        if not payload:
            return _clear_refresh_cookie(jsonify({'error': 'Refresh token invalide ou expire'})), 401

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (payload['user_id'],)).fetchone()
        if not user or user['disabled']:
            return _clear_refresh_cookie(jsonify({'error': 'Utilisateur introuvable'})), 401

        # Rotation: revoque l'ancien refresh, en emet un nouveau
        revoke_token(payload)
        log_audit(user['id'], user['username'], 'token_refresh', ip_address=request.remote_addr)
        return _session_response(dict(user))

    @app.route('/api/auth/logout', methods=['POST'])
    def auth_logout():
        """Revoquer l'access token courant et le refresh token, effacer le cookie."""
        user_id, username = None, None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            payload = decode_token(auth_header[7:], expected_type='access')
            if payload:
                revoke_token(payload)
                user_id, username = payload['user_id'], payload['username']

        data = request.get_json(silent=True) or {}
        for candidate in (request.cookies.get(REFRESH_COOKIE_NAME, ''), data.get('refresh_token', '')):
            if candidate:
                payload = decode_token(candidate, expected_type='refresh', check_user=False)
                if payload:
                    revoke_token(payload)
                    user_id = user_id or payload.get('user_id')
                    username = username or payload.get('username')

        if user_id is None:
            return _clear_refresh_cookie(jsonify({'error': 'Token requis'})), 401
        log_audit(user_id, username, 'logout', ip_address=request.remote_addr)
        return _clear_refresh_cookie(jsonify({'message': 'Deconnecte'}))

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
        """Changer son propre mot de passe (revoque toutes les sessions)."""
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
        # token_version++ : toutes les sessions (access + refresh) sont invalidees
        _bump_token_version(db, g.user_id)
        db.commit()

        if hasattr(g, 'token_payload'):
            revoke_token(g.token_payload)

        log_audit(g.user_id, g.username, 'password_changed', ip_address=request.remote_addr)
        return _clear_refresh_cookie(jsonify({'message': 'Mot de passe modifie. Reconnectez-vous.'}))

    # ------------------------------------------------------------------
    # Administration des utilisateurs (admin uniquement)
    # ------------------------------------------------------------------

    @app.route('/api/auth/users', methods=['GET'])
    @require_auth
    @require_role('admin')
    def list_users():
        db = get_db()
        users = db.execute(
            "SELECT id, username, display_name, role, created_at, last_login, disabled "
            "FROM users ORDER BY created_at DESC"
        ).fetchall()
        return jsonify([_public_user(u) for u in users])

    @app.route('/api/auth/users', methods=['POST'])
    @require_auth
    @require_role('admin')
    def admin_create_user():
        data = request.get_json(silent=True) or {}
        username = sanitize_string(data.get('username', ''), max_length=64).strip()
        password = data.get('password', '')
        display_name = sanitize_string(data.get('display_name', ''), max_length=128) or username
        role = data.get('role', 'analyst')

        err = _validate_username(username)
        if err:
            return jsonify({'error': err}), 400
        if role not in VALID_ROLES:
            return jsonify({'error': f'Role invalide. Valeurs: {", ".join(VALID_ROLES)}'}), 400
        ok, reason = validate_password(password)
        if not ok:
            return jsonify({'error': reason}), 400

        db = get_db()
        if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            return jsonify({'error': 'Ce nom d\'utilisateur existe deja'}), 409
        cursor = db.execute(
            "INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), display_name, role))
        db.commit()
        user_id = cursor.lastrowid
        log_audit(g.user_id, g.username, 'admin_create_user', 'user', str(user_id),
                  details=json.dumps({'username': username, 'role': role}),
                  ip_address=request.remote_addr)
        row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return jsonify(_public_user(row)), 201

    def _active_admin_count(db):
        return db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0").fetchone()[0]

    @app.route('/api/auth/users/<int:user_id>/role', methods=['PUT'])
    @require_auth
    @require_role('admin')
    def admin_set_role(user_id):
        data = request.get_json(silent=True) or {}
        role = data.get('role')
        if role not in VALID_ROLES:
            return jsonify({'error': f'Role invalide. Valeurs: {", ".join(VALID_ROLES)}'}), 400
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            return jsonify({'error': 'Utilisateur non trouve'}), 404
        if user['role'] == role:
            return jsonify(_public_user(user))
        if user['role'] == 'admin' and not user['disabled'] and _active_admin_count(db) <= 1:
            return jsonify({'error': 'Impossible de retirer le dernier administrateur'}), 409
        db.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        _bump_token_version(db, user_id)
        db.commit()
        log_audit(g.user_id, g.username, 'admin_set_role', 'user', str(user_id),
                  details=json.dumps({'old_role': user['role'], 'new_role': role}),
                  ip_address=request.remote_addr)
        return jsonify(_public_user(db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()))

    def _set_disabled(user_id, disabled):
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            return jsonify({'error': 'Utilisateur non trouve'}), 404
        if disabled and user_id == g.user_id:
            return jsonify({'error': 'Impossible de desactiver son propre compte'}), 400
        if (disabled and user['role'] == 'admin' and not user['disabled']
                and _active_admin_count(db) <= 1):
            return jsonify({'error': 'Impossible de desactiver le dernier administrateur'}), 409
        db.execute("UPDATE users SET disabled=? WHERE id=?", (1 if disabled else 0, user_id))
        _bump_token_version(db, user_id)
        db.commit()
        log_audit(g.user_id, g.username, 'admin_disable_user' if disabled else 'admin_enable_user',
                  'user', str(user_id), ip_address=request.remote_addr)
        return jsonify(_public_user(db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()))

    @app.route('/api/auth/users/<int:user_id>/disabled', methods=['PUT'])
    @require_auth
    @require_role('admin')
    def admin_set_disabled(user_id):
        data = request.get_json(silent=True) or {}
        return _set_disabled(user_id, bool(data.get('disabled', True)))

    @app.route('/api/auth/users/<int:user_id>', methods=['DELETE'])
    @require_auth
    @require_role('admin')
    def admin_delete_user(user_id):
        """Desactivation (suppression logique : l'audit et les enquetes restent attribues)."""
        return _set_disabled(user_id, True)
