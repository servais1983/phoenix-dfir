"""
Phoenix DFIR - Database Module (SQLite)
Gestion centralisee de la base de donnees forensique
"""

import sqlite3
import os
import json
import uuid
import datetime
import threading

DB_PATH = os.environ.get('PHOENIX_DB_PATH', os.path.join(os.path.dirname(__file__), 'phoenix.db'))
_local = threading.local()


def get_db():
    """Obtenir une connexion a la base de donnees (thread-safe)"""
    if not hasattr(_local, 'connection') or _local.connection is None:
        _local.connection = sqlite3.connect(DB_PATH, timeout=30)
        _local.connection.row_factory = sqlite3.Row
        _local.connection.execute("PRAGMA journal_mode=WAL")
        _local.connection.execute("PRAGMA foreign_keys=ON")
        _local.connection.execute("PRAGMA synchronous=NORMAL")
        _local.connection.execute("PRAGMA cache_size=-64000")  # 64MB cache
        _local.connection.execute("PRAGMA temp_store=MEMORY")
    return _local.connection


def close_db():
    """Fermer la connexion de ce thread"""
    if hasattr(_local, 'connection') and _local.connection:
        _local.connection.close()
        _local.connection = None


def init_db():
    """Initialiser le schema de la base de donnees"""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            display_name TEXT,
            role TEXT DEFAULT 'analyst' CHECK(role IN ('admin', 'analyst', 'viewer')),
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            revoked INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT DEFAULT 'active' CHECK(status IN ('active', 'closed', 'archived')),
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            filename TEXT NOT NULL,
            original_filename TEXT,
            file_path TEXT,
            file_size INTEGER DEFAULT 0,
            file_hash_md5 TEXT,
            file_hash_sha1 TEXT,
            file_hash_sha256 TEXT,
            file_type TEXT,
            analysis_result TEXT,
            uploaded_by INTEGER REFERENCES users(id),
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            type TEXT NOT NULL CHECK(type IN ('ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email', 'filename', 'registry_key', 'cve')),
            value TEXT NOT NULL,
            source TEXT DEFAULT '',
            severity TEXT DEFAULT 'unknown' CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')),
            enrichment TEXT,
            tags TEXT DEFAULT '[]',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS timeline_events (
            id TEXT PRIMARY KEY,
            investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            severity TEXT DEFAULT 'info' CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
            source TEXT DEFAULT '',
            artifact_id INTEGER REFERENCES artifacts(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            username TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS integration_configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connector_id TEXT NOT NULL UNIQUE,
            enabled INTEGER DEFAULT 0,
            config TEXT DEFAULT '{}',
            last_test_status TEXT,
            last_test_message TEXT,
            last_test_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_iocs_investigation ON iocs(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
        CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
        CREATE INDEX IF NOT EXISTS idx_timeline_investigation ON timeline_events(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_timeline_timestamp ON timeline_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_artifacts_investigation ON artifacts(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_unique ON iocs(investigation_id, type, value);
        CREATE INDEX IF NOT EXISTS idx_integration_connector ON integration_configs(connector_id);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
        CREATE INDEX IF NOT EXISTS idx_users_locked ON users(locked_until);
    """)
    db.commit()
    _run_migrations(db)


def _run_migrations(db):
    """Appliquer les migrations incrementales sur le schema existant"""
    # Migration: ajouter les colonnes de lockout si absentes
    try:
        db.execute("SELECT failed_login_attempts FROM users LIMIT 1")
    except sqlite3.OperationalError:
        db.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0")
        db.execute("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP NULL")
        db.commit()

    # Migration: table refresh_tokens
    try:
        db.execute("SELECT id FROM refresh_tokens LIMIT 1")
    except sqlite3.OperationalError:
        db.execute("""
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                revoked INTEGER DEFAULT 0
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash)")
        db.commit()


def migrate_json_sessions():
    """Migrer les anciennes sessions JSON vers SQLite"""
    sessions_dir = os.path.join(os.path.dirname(__file__), 'sessions')
    if not os.path.isdir(sessions_dir):
        return

    db = get_db()
    migrated = 0

    for filename in os.listdir(sessions_dir):
        if not filename.endswith('.json'):
            continue

        inv_id = filename[:-5]
        existing = db.execute("SELECT id FROM investigations WHERE id=?", (inv_id,)).fetchone()
        if existing:
            continue

        try:
            filepath = os.path.join(sessions_dir, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)

            db.execute(
                "INSERT INTO investigations (id, name, status, created_at, updated_at) VALUES (?, ?, 'active', ?, ?)",
                (inv_id, data.get('nom_du_cas', 'Sans nom'),
                 data.get('date_creation', datetime.datetime.now().isoformat()),
                 data.get('derniere_activite', datetime.datetime.now().isoformat()))
            )

            # Migrate IoCs
            iocs = data.get('iocs', {})
            type_map = {'ips': 'ip', 'domaines': 'domain', 'hashes': 'hash_sha256'}
            for old_type, ioc_list in iocs.items():
                new_type = type_map.get(old_type, old_type)
                for entry in ioc_list:
                    value = entry.get('value', entry) if isinstance(entry, dict) else str(entry)
                    source = entry.get('source', '') if isinstance(entry, dict) else ''
                    enrichment = json.dumps(entry.get('enrichment')) if isinstance(entry, dict) and entry.get('enrichment') else None
                    try:
                        db.execute(
                            "INSERT OR IGNORE INTO iocs (investigation_id, type, value, source, enrichment) VALUES (?, ?, ?, ?, ?)",
                            (inv_id, new_type, value, source, enrichment)
                        )
                    except Exception:
                        pass

            # Migrate timeline
            for event in data.get('timeline_events', []):
                event_id = event.get('id', str(uuid.uuid4()))
                try:
                    db.execute(
                        "INSERT OR IGNORE INTO timeline_events (id, investigation_id, timestamp, event, severity) VALUES (?, ?, ?, ?, ?)",
                        (event_id, inv_id, event.get('timestamp', ''), event.get('event', ''), event.get('severity', 'info'))
                    )
                except Exception:
                    pass

            # Migrate artifacts
            for art in data.get('artefacts_analyses', []):
                art_name = art if isinstance(art, str) else (art.get('filename', art.get('name', str(art))))
                try:
                    db.execute(
                        "INSERT INTO artifacts (investigation_id, filename, original_filename) VALUES (?, ?, ?)",
                        (inv_id, art_name, art_name)
                    )
                except Exception:
                    pass

            migrated += 1
        except Exception as e:
            print(f"Erreur migration {filename}: {e}")
            continue

    db.commit()
    if migrated > 0:
        print(f"Migration: {migrated} sessions JSON importees dans SQLite")


def log_audit(user_id, username, action, target_type=None, target_id=None, details=None, ip_address=None):
    """Enregistrer une action dans le journal d'audit"""
    try:
        db = get_db()
        db.execute(
            "INSERT INTO audit_log (user_id, username, action, target_type, target_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user_id, username, action, target_type, target_id, details, ip_address)
        )
        db.commit()
    except Exception as e:
        print(f"Erreur audit log: {e}")


def dict_from_row(row):
    """Convertir un sqlite3.Row en dictionnaire"""
    if row is None:
        return None
    return dict(row)


def rows_to_list(rows):
    """Convertir une liste de sqlite3.Row en liste de dictionnaires"""
    return [dict(r) for r in rows]
