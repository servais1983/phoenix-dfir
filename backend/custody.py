#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Chaine de preuve (Chain of Custody) et validation humaine (Human-in-the-Loop).

CHAINE DE PREUVE
----------------
Registre append-only, chaine par empreintes SHA-256 : chaque entree scelle
son contenu ET l'empreinte de l'entree precedente (comme un blockchain
minimal). Toute modification, suppression ou insertion a posteriori d'une
entree casse la chaine et est detectee par verify_chain().

    entry_hash = SHA256(JSON canonique {seq, ts, investigation_id, actor,
                         agent, action, artifact_ref, summary, mitre,
                         severity, details, payload_sha256, prev_hash})

Sont scelles : acquisition d'evidences (empreinte du fichier), chaque outil
execute par l'enqueteur autonome (empreinte de sa sortie), constats,
remediations proposees et decisions de l'analyste, rapport final.

VALIDATION HUMAINE (HITL)
-------------------------
L'enqueteur ne fait que PROPOSER des actions de confinement ; elles restent
WAITING_APPROVAL jusqu'a la decision d'un analyste (APPROVED / REJECTED).
Phoenix n'execute jamais l'action : une approbation autorise l'equipe a la
jouer avec ses propres outils de reponse, et la decision est
scellee dans la chaine de preuve.
"""

import datetime
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import uuid

import database
import datadirs
import merkle
import timestamping

GENESIS_HASH = '0' * 64
REMEDIATION_STATUSES = ('WAITING_APPROVAL', 'APPROVED', 'REJECTED')

_lock = threading.Lock()

SCHEMA = """
    CREATE TABLE IF NOT EXISTS custody_chain (
        seq INTEGER PRIMARY KEY,
        ts TEXT NOT NULL,
        investigation_id TEXT,
        actor TEXT NOT NULL,
        agent TEXT DEFAULT '',
        action TEXT NOT NULL,
        artifact_ref TEXT DEFAULT '',
        summary TEXT DEFAULT '',
        mitre TEXT DEFAULT '',
        severity TEXT DEFAULT 'info',
        details TEXT DEFAULT '{}',
        payload_sha256 TEXT DEFAULT '',
        prev_hash TEXT NOT NULL,
        entry_hash TEXT NOT NULL UNIQUE
    );
    CREATE INDEX IF NOT EXISTS idx_custody_investigation ON custody_chain(investigation_id);

    CREATE TABLE IF NOT EXISTS remediation_actions (
        id TEXT PRIMARY KEY,
        investigation_id TEXT,
        job_id TEXT,
        target_host TEXT NOT NULL,
        command TEXT NOT NULL,
        reason TEXT NOT NULL,
        mitre TEXT DEFAULT '',
        severity TEXT DEFAULT 'high',
        status TEXT DEFAULT 'WAITING_APPROVAL'
            CHECK(status IN ('WAITING_APPROVAL', 'APPROVED', 'REJECTED')),
        requested_by TEXT,
        created_at TEXT NOT NULL,
        decided_by TEXT,
        decided_at TEXT,
        decision_note TEXT DEFAULT '',
        case_dir TEXT,
        case_remediation_id INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_remediation_status ON remediation_actions(status);

    CREATE TABLE IF NOT EXISTS custody_checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        scope TEXT NOT NULL,
        investigation_id TEXT,
        tree_size INTEGER NOT NULL,
        first_seq INTEGER,
        last_seq INTEGER,
        root TEXT NOT NULL,
        statement TEXT NOT NULL,
        statement_sha256 TEXT NOT NULL,
        signature_alg TEXT NOT NULL,
        signature TEXT NOT NULL,
        key_id TEXT NOT NULL,
        tsa_status TEXT DEFAULT 'disabled',
        tsa_gen_time TEXT,
        tsa_serial TEXT,
        tsa_error TEXT,
        tsr_file TEXT,
        created_by TEXT,
        ledger_seq INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_checkpoint_scope ON custody_checkpoints(scope);
"""

# Colonnes ajoutees aux remediations pour les playbooks (migration douce)
_REMEDIATION_PLAYBOOK_COLUMNS = (
    ('playbook_id', "TEXT DEFAULT ''"),
    ('playbook_params', "TEXT DEFAULT ''"),
    ('script', "TEXT DEFAULT ''"),
    ('rollback', "TEXT DEFAULT ''"),
    ('prechecks', "TEXT DEFAULT ''"),
    ('script_language', "TEXT DEFAULT ''"),
    ('script_sha256', "TEXT DEFAULT ''"),
    ('rollback_sha256', "TEXT DEFAULT ''"),
)

_HASHED_FIELDS = ('seq', 'ts', 'investigation_id', 'actor', 'agent', 'action', 'artifact_ref',
                  'summary', 'mitre', 'severity', 'details', 'payload_sha256', 'prev_hash')


def _connect():
    """Connexion dediee en autocommit : les transactions IMMEDIATE de la chaine
    ne doivent pas interferer avec la connexion par thread du reste de l'API."""
    conn = sqlite3.connect(database.DB_PATH, timeout=30, isolation_level=None)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(db=None):
    conn = db or _connect()
    try:
        conn.executescript(SCHEMA)
        existing = {r[1] for r in conn.execute('PRAGMA table_info(remediation_actions)').fetchall()}
        for name, decl in _REMEDIATION_PLAYBOOK_COLUMNS:
            if name not in existing:
                # Nom et type issus d'une liste fixe (pas d'entree utilisateur)
                conn.execute(f'ALTER TABLE remediation_actions ADD COLUMN {name} {decl}')  # nosec B608
    finally:
        if db is None:
            conn.close()


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')


def sha256_text(text):
    return hashlib.sha256((text or '').encode('utf-8')).hexdigest()


def sha256_json(obj):
    return sha256_text(json.dumps(obj, ensure_ascii=False, sort_keys=True, default=str))


def compute_entry_hash(entry):
    canonical = {k: entry.get(k) for k in _HASHED_FIELDS}
    return sha256_json(canonical)


def _row_to_entry(row):
    entry = dict(row)
    try:
        entry['details'] = json.loads(entry.get('details') or '{}')
    except (TypeError, ValueError):
        pass
    return entry


def record(action, actor, investigation_id=None, agent='', artifact_ref='', summary='',
           mitre='', severity='info', details=None, payload_sha256=''):
    """Sceller une entree dans la chaine de preuve et la retourner (dict)."""
    details_json = json.dumps(details or {}, ensure_ascii=False, sort_keys=True, default=str)
    with _lock:
        conn = _connect()
        try:
            # IMMEDIATE : verrou d'ecriture pris avant de lire le dernier maillon,
            # la chaine reste lineaire meme avec plusieurs workers.
            conn.execute('BEGIN IMMEDIATE')
            last = conn.execute(
                'SELECT seq, entry_hash FROM custody_chain ORDER BY seq DESC LIMIT 1').fetchone()
            entry = {
                'seq': (last['seq'] + 1) if last else 1,
                'ts': _now(),
                'investigation_id': investigation_id,
                'actor': str(actor or 'system')[:120],
                'agent': str(agent or '')[:120],
                'action': str(action)[:2000],
                'artifact_ref': str(artifact_ref or '')[:1000],
                'summary': str(summary or '')[:2000],
                'mitre': str(mitre or '')[:120],
                'severity': severity if severity in (
                    'critical', 'high', 'medium', 'low', 'info') else 'info',
                'details': details_json,
                'payload_sha256': payload_sha256 or '',
                'prev_hash': last['entry_hash'] if last else GENESIS_HASH,
            }
            entry['entry_hash'] = compute_entry_hash(entry)
            conn.execute(
                'INSERT INTO custody_chain (seq, ts, investigation_id, actor, agent, action, '
                'artifact_ref, summary, mitre, severity, details, payload_sha256, prev_hash, '
                'entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                tuple(entry[k] for k in _HASHED_FIELDS) + (entry['entry_hash'],))
            conn.execute('COMMIT')
        except Exception:
            conn.execute('ROLLBACK')
            raise
        finally:
            conn.close()
    entry['details'] = details or {}
    _maybe_periodic_checkpoint(entry)
    return entry


def safe_record(*args, **kwargs):
    """record() qui ne fait jamais echouer l'operation metier appelante."""
    try:
        return record(*args, **kwargs)
    except Exception as e:  # pragma: no cover - journalise seulement
        print(f'Erreur chaine de preuve: {e}')
        return None


def _in_clause(column, ids):
    """Fragment SQL `column IN (?, ...)` (False si la liste est vide)."""
    ids = list(ids)
    if not ids:
        return '0', []
    return f"{column} IN ({', '.join('?' for _ in ids)})", ids  # nosec B608 - placeholders


def list_entries(investigation_id=None, limit=500, after_seq=0, investigation_ids=None):
    """Entrees de la chaine. investigation_ids (liste) restreint aux enquetes
    accessibles ; None = pas de restriction (admin)."""
    conn = _connect()
    try:
        if investigation_ids is not None and not investigation_id:
            clause, params = _in_clause('investigation_id', investigation_ids)
            rows = conn.execute(
                f'SELECT * FROM custody_chain WHERE {clause} AND seq>? ORDER BY seq LIMIT ?',  # nosec B608
                params + [after_seq, limit]).fetchall()
        elif investigation_id:
            rows = conn.execute(
                'SELECT * FROM custody_chain WHERE investigation_id=? AND seq>? ORDER BY seq LIMIT ?',
                (investigation_id, after_seq, limit)).fetchall()
        else:
            rows = conn.execute('SELECT * FROM custody_chain WHERE seq>? ORDER BY seq LIMIT ?',
                                (after_seq, limit)).fetchall()
        return [_row_to_entry(r) for r in rows]
    finally:
        conn.close()


def stats():
    conn = _connect()
    try:
        row = conn.execute('SELECT COUNT(*) AS n, MAX(seq) AS head FROM custody_chain').fetchone()
        head = conn.execute('SELECT entry_hash FROM custody_chain WHERE seq=?',
                            (row['head'],)).fetchone() if row['head'] else None
        return {'entries': row['n'], 'head_hash': head['entry_hash'] if head else GENESIS_HASH}
    finally:
        conn.close()


def verify_chain():
    """Recalculer toute la chaine. Retourne l'etat d'integrite et le premier
    maillon rompu le cas echeant."""
    conn = _connect()
    try:
        rows = conn.execute('SELECT * FROM custody_chain ORDER BY seq').fetchall()
    finally:
        conn.close()
    prev = GENESIS_HASH
    expected_seq = 1
    for row in rows:
        entry = dict(row)
        if entry['seq'] != expected_seq:
            return {'valid': False, 'entries': len(rows), 'broken_at': entry['seq'],
                    'reason': f"Maillon manquant : seq {expected_seq} attendu, {entry['seq']} trouve"}
        if entry['prev_hash'] != prev:
            return {'valid': False, 'entries': len(rows), 'broken_at': entry['seq'],
                    'reason': "prev_hash ne correspond pas a l'empreinte du maillon precedent"}
        if compute_entry_hash(entry) != entry['entry_hash']:
            return {'valid': False, 'entries': len(rows), 'broken_at': entry['seq'],
                    'reason': 'Contenu altere : empreinte recalculee differente'}
        prev = entry['entry_hash']
        expected_seq += 1
    return {'valid': True, 'entries': len(rows), 'head_hash': prev, 'broken_at': None,
            'verified_at': _now()}


# ============================================================================
# Validation humaine des remediations
# ============================================================================

def create_remediation(target_host, command, reason, investigation_id=None, job_id=None,
                       mitre='', severity='high', requested_by='enqueteur-autonome',
                       case_dir=None, case_remediation_id=None, playbook=None):
    """Proposer une action (WAITING_APPROVAL). `playbook` (dict rendu par
    playbooks.render) ajoute le script, le rollback et les pre-verifications,
    dont les empreintes sont scellees dans la chaine de preuve."""
    action_id = f"ACT-{uuid.uuid4().hex[:6].upper()}"
    action = {
        'id': action_id,
        'investigation_id': investigation_id,
        'job_id': job_id,
        'target_host': str(target_host)[:255],
        'command': str(command)[:1000],
        'reason': str(reason)[:1000],
        'mitre': str(mitre or '')[:120],
        'severity': severity or 'high',
        'status': 'WAITING_APPROVAL',
        'requested_by': requested_by,
        'created_at': _now(),
        'decided_by': None,
        'decided_at': None,
        'decision_note': '',
        'case_dir': case_dir,
        'case_remediation_id': case_remediation_id,
    }
    if playbook:
        action.update({
            'playbook_id': str(playbook.get('template_id') or '')[:80],
            'playbook_params': json.dumps(playbook.get('params') or {}, sort_keys=True),
            'script': playbook.get('script') or '',
            'rollback': playbook.get('rollback') or '',
            'prechecks': playbook.get('prechecks') or '',
            'script_language': playbook.get('language') or '',
            'script_sha256': sha256_text(playbook.get('script') or ''),
            'rollback_sha256': sha256_text(playbook.get('rollback') or ''),
        })
    conn = _connect()
    try:
        cols = ', '.join(action)
        conn.execute(f'INSERT INTO remediation_actions ({cols}) VALUES '  # nosec B608 - colonnes fixes
                     f"({', '.join('?' for _ in action)})", tuple(action.values()))
    finally:
        conn.close()
    entry = safe_record(
        'remediation_requested', requested_by, investigation_id=investigation_id,
        agent='Orchestrateur Lead', artifact_ref=f'{action_id} -> {action["target_host"]}',
        summary=action['reason'], mitre=action['mitre'], severity=action['severity'],
        details=_remediation_details(action),
        payload_sha256=sha256_json({k: action[k] for k in ('id', 'target_host', 'command', 'reason')
                                    + (('script_sha256', 'rollback_sha256') if playbook else ())}))
    action['custody_hash'] = entry['entry_hash'] if entry else None
    action['custody_entry'] = entry
    return _decode_remediation(action)


def _remediation_details(action, **extra):
    details = {'action_id': action['id'], 'command': action['command']}
    if action.get('playbook_id'):
        details.update({
            'playbook_id': action['playbook_id'],
            'playbook_params': _json_or_empty(action.get('playbook_params')),
            'script_sha256': action.get('script_sha256'),
            'rollback_sha256': action.get('rollback_sha256'),
        })
    details.update(extra)
    return details


def _json_or_empty(value):
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value) if value else {}
    except (TypeError, ValueError):
        return {}


def _decode_remediation(action):
    """Remediation prete pour l'API (parametres de playbook decodes)."""
    if action is None:
        return None
    action = dict(action)
    if 'playbook_params' in action:
        action['playbook_params'] = _json_or_empty(action.get('playbook_params'))
    return action


def get_remediation(action_id):
    conn = _connect()
    try:
        row = conn.execute('SELECT * FROM remediation_actions WHERE id=?', (action_id,)).fetchone()
        return _decode_remediation(dict(row)) if row else None
    finally:
        conn.close()


def list_remediations(status=None, investigation_id=None, limit=200, investigation_ids=None):
    query = 'SELECT * FROM remediation_actions WHERE 1=1'
    params = []
    if investigation_ids is not None:
        clause, ids = _in_clause('investigation_id', investigation_ids)
        query += f' AND {clause}'
        params.extend(ids)
    if status:
        query += ' AND status=?'
        params.append(status)
    if investigation_id:
        query += ' AND investigation_id=?'
        params.append(investigation_id)
    query += ' ORDER BY created_at DESC LIMIT ?'
    params.append(limit)
    conn = _connect()
    try:
        return [_decode_remediation(dict(r)) for r in conn.execute(query, params).fetchall()]
    finally:
        conn.close()


def decide_remediation(action_id, approve, decided_by, note=''):
    """Enregistrer la decision de l'analyste. Retourne (action, erreur)."""
    status = 'APPROVED' if approve else 'REJECTED'
    conn = _connect()
    try:
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT * FROM remediation_actions WHERE id=?', (action_id,)).fetchone()
        if not row:
            conn.execute('ROLLBACK')
            return None, 'not_found'
        if row['status'] != 'WAITING_APPROVAL':
            conn.execute('ROLLBACK')
            return _decode_remediation(dict(row)), 'already_decided'
        conn.execute(
            'UPDATE remediation_actions SET status=?, decided_by=?, decided_at=?, decision_note=? '
            'WHERE id=?', (status, decided_by, _now(), str(note or '')[:1000], action_id))
        conn.execute('COMMIT')
        action = dict(conn.execute('SELECT * FROM remediation_actions WHERE id=?',
                                   (action_id,)).fetchone())
    finally:
        conn.close()
    entry = safe_record(
        'remediation_approved' if approve else 'remediation_rejected', decided_by,
        investigation_id=action['investigation_id'], agent='Analyste (HITL)',
        artifact_ref=f"{action_id} -> {action['target_host']}",
        summary=(note or ('Action approuvee par l\'analyste' if approve
                          else 'Action rejetee par l\'analyste')),
        mitre=action['mitre'], severity=action['severity'],
        details=_remediation_details(action, decision=status),
        payload_sha256=sha256_json(
            {'id': action_id, 'decision': status, 'by': decided_by}
            if not action.get('playbook_id') else
            {'id': action_id, 'decision': status, 'by': decided_by,
             'script_sha256': action.get('script_sha256'),
             'rollback_sha256': action.get('rollback_sha256')}))
    action['custody_hash'] = entry['entry_hash'] if entry else None
    action['custody_entry'] = entry
    return _decode_remediation(action), None


# ============================================================================
# Merkle tree, signed checkpoints and RFC 3161 timestamping
# ============================================================================
#
# The hash chain proves the ORDER and INTEGRITY of the ledger; the Merkle
# tree (merkle.py, RFC 6962 layout, leaf = entry_hash bytes) gives compact
# inclusion proofs for a single entry. A checkpoint freezes the tree head of
# a scope (whole ledger, or one investigation), is signed (Ed25519 when the
# `cryptography` package is installed, HMAC-SHA256 otherwise), timestamped by
# an RFC 3161 TSA when PHOENIX_TSA_URL is set, and is itself sealed in the
# ledger (action 'merkle_checkpoint').

_checkpoint_lock = threading.Lock()
CHECKPOINT_ACTION = 'merkle_checkpoint'


def store_dir():
    """Directory holding checkpoint statements, .tsr tokens and the signing key."""
    path = os.environ.get('PHOENIX_CUSTODY_DIR', '').strip() or os.path.join(
        datadirs.runtime_dir('uploads'), 'custody')
    os.makedirs(os.path.join(path, 'checkpoints'), exist_ok=True)
    return path


def checkpoint_every():
    try:
        return max(0, int(os.environ.get('PHOENIX_CHECKPOINT_EVERY', '100')))
    except ValueError:
        return 100


def ledger_entries(investigation_id=None, up_to_seq=None, raw=False):
    """All ledger entries of a scope, ordered by seq (no limit). raw=True keeps
    `details` as the exact JSON string that was hashed (independent checks)."""
    conn = _connect()
    try:
        query = 'SELECT * FROM custody_chain WHERE 1=1'
        params = []
        if investigation_id:
            query += ' AND investigation_id=?'
            params.append(str(investigation_id))
        if up_to_seq is not None:
            query += ' AND seq<=?'
            params.append(int(up_to_seq))
        rows = conn.execute(query + ' ORDER BY seq', params).fetchall()
        return [dict(r) if raw else _row_to_entry(r) for r in rows]
    finally:
        conn.close()


def get_entry(seq):
    conn = _connect()
    try:
        row = conn.execute('SELECT * FROM custody_chain WHERE seq=?', (int(seq),)).fetchone()
        return _row_to_entry(row) if row else None
    finally:
        conn.close()


def _scope(investigation_id):
    return f'investigation:{investigation_id}' if investigation_id else 'global'


def merkle_summary(investigation_id=None):
    entries = ledger_entries(investigation_id)
    summary = merkle.build_ledger_tree(entries)
    summary['scope'] = _scope(investigation_id)
    summary['investigation_id'] = investigation_id
    latest = list_checkpoints(investigation_id, limit=1)
    summary['latest_checkpoint'] = latest[0] if latest else None
    summary['computed_at'] = _now()
    return summary


def merkle_proof(seq, investigation_id=None):
    """Inclusion proof of entry `seq` in the current tree of the scope."""
    proof = merkle.ledger_proof(ledger_entries(investigation_id), int(seq))
    if proof:
        proof['scope'] = _scope(investigation_id)
        proof['investigation_id'] = investigation_id
    return proof


# ---------------------------------------------------------------- signature

def _signing_key():
    """Ed25519 private key (cryptography) or None when unavailable."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        return None
    explicit = os.environ.get('PHOENIX_CUSTODY_SIGNING_KEY', '').strip()
    path = explicit or os.path.join(store_dir(), 'checkpoint_signing_ed25519.pem')
    if os.path.isfile(path):
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:  # cree entre-temps par un autre worker
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    with os.fdopen(fd, 'wb') as f:
        f.write(pem)
    return key


def _hmac_key():
    secret = os.environ.get('PHOENIX_SECRET_KEY', '') or 'phoenix-dfir'
    return hmac.new(secret.encode('utf-8'), b'phoenix-custody-checkpoint-v1', hashlib.sha256).digest()


def signing_info():
    """Public information to verify checkpoint signatures."""
    key = _signing_key()
    if key is None:
        return {'algorithm': 'HMAC-SHA256', 'key_id': hashlib.sha256(_hmac_key()).hexdigest()[:16],
                'public_key_pem': None,
                'note': 'Symmetric signature: verifiable only by the Phoenix server operator.'}
    from cryptography.hazmat.primitives import serialization
    pub = key.public_key()
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {'algorithm': 'Ed25519', 'key_id': hashlib.sha256(raw).hexdigest()[:16],
            'public_key_pem': pub.public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo).decode()}


def sign_statement(statement_bytes):
    key = _signing_key()
    if key is None:
        sig = hmac.new(_hmac_key(), statement_bytes, hashlib.sha256).hexdigest()
        return 'HMAC-SHA256', sig, hashlib.sha256(_hmac_key()).hexdigest()[:16]
    info = signing_info()
    return 'Ed25519', key.sign(statement_bytes).hex(), info['key_id']


def verify_statement_signature(statement_bytes, algorithm, signature_hex):
    try:
        if algorithm == 'HMAC-SHA256':
            expected = hmac.new(_hmac_key(), statement_bytes, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature_hex)
        if algorithm == 'Ed25519':
            key = _signing_key()
            if key is None:
                return False
            key.public_key().verify(bytes.fromhex(signature_hex), statement_bytes)
            return True
    except Exception:
        return False
    return False


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


# -------------------------------------------------------------- checkpoints

def _checkpoint_row(row):
    cp = dict(row)
    try:
        cp['statement'] = json.loads(cp['statement'])
    except (TypeError, ValueError):
        pass
    return cp


def list_checkpoints(investigation_id=None, limit=50):
    conn = _connect()
    try:
        rows = conn.execute(
            'SELECT * FROM custody_checkpoints WHERE scope=? ORDER BY id DESC LIMIT ?',
            (_scope(investigation_id), int(limit))).fetchall()
        return [_checkpoint_row(r) for r in rows]
    finally:
        conn.close()


def get_checkpoint(checkpoint_id):
    conn = _connect()
    try:
        row = conn.execute('SELECT * FROM custody_checkpoints WHERE id=?',
                           (int(checkpoint_id),)).fetchone()
        return _checkpoint_row(row) if row else None
    finally:
        conn.close()


def checkpoint_paths(checkpoint_id):
    base = os.path.join(store_dir(), 'checkpoints', f'checkpoint-{int(checkpoint_id)}')
    return base + '.json', base + '.tsr'


def create_checkpoint(investigation_id=None, actor='system'):
    """Freeze, sign, timestamp and seal the current Merkle head of a scope."""
    with _checkpoint_lock:
        entries = ledger_entries(investigation_id)
        tree = merkle.build_ledger_tree(entries)
        statement = {
            'type': 'phoenix-dfir-custody-checkpoint',
            'version': 1,
            'scope': _scope(investigation_id),
            'investigation_id': investigation_id,
            'tree_size': tree['leaf_count'],
            'first_seq': tree['first_seq'],
            'last_seq': tree['last_seq'],
            'root': tree['root'],
            'hash_algorithm': tree['algorithm'],
            'created_at': _now(),
        }
        statement_bytes = canonical_json(statement)
        digest = hashlib.sha256(statement_bytes).digest()
        alg, signature, key_id = sign_statement(statement_bytes)
        conn = _connect()
        try:
            cur = conn.execute(
                'INSERT INTO custody_checkpoints (created_at, scope, investigation_id, tree_size, '
                'first_seq, last_seq, root, statement, statement_sha256, signature_alg, signature, '
                'key_id, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (statement['created_at'], statement['scope'], investigation_id, statement['tree_size'],
                 statement['first_seq'], statement['last_seq'], statement['root'],
                 statement_bytes.decode('ascii'), digest.hex(), alg, signature, key_id,
                 str(actor or 'system')[:120]))
            cp_id = cur.lastrowid
        finally:
            conn.close()
        json_path, tsr_path = checkpoint_paths(cp_id)
        with open(json_path, 'wb') as f:
            f.write(statement_bytes)
        ts = timestamping.timestamp_digest(digest, tsr_path)
        entry = safe_record(
            CHECKPOINT_ACTION, actor, investigation_id=investigation_id, agent='Chaine de preuve',
            artifact_ref=f'checkpoint-{cp_id}',
            summary=(f"Checkpoint Merkle {statement['scope']} : {statement['tree_size']} feuille(s), "
                     f"racine {statement['root'][:16]}..., horodatage {ts['status']}"),
            details={'checkpoint_id': cp_id, 'root': statement['root'],
                     'tree_size': statement['tree_size'], 'signature_alg': alg,
                     'tsa_status': ts['status'], 'tsa_gen_time': ts.get('gen_time')},
            payload_sha256=digest.hex())
        conn = _connect()
        try:
            conn.execute(
                'UPDATE custody_checkpoints SET tsa_status=?, tsa_gen_time=?, tsa_serial=?, '
                'tsa_error=?, tsr_file=?, ledger_seq=? WHERE id=?',
                (ts['status'], ts.get('gen_time'), ts.get('serial_number'), ts.get('error'),
                 os.path.basename(tsr_path) if ts.get('tsr_path') else None,
                 entry['seq'] if entry else None, cp_id))
        finally:
            conn.close()
    return get_checkpoint(cp_id)


def verify_checkpoint(checkpoint):
    """Recompute the tree head of a checkpoint, check its signature and its
    RFC 3161 token (messageImprint). Returns a report dict."""
    statement = checkpoint['statement']
    statement_bytes = canonical_json(statement)
    last_seq = statement.get('last_seq')
    entries = ledger_entries(statement.get('investigation_id'),
                             up_to_seq=last_seq if last_seq is not None else 0)
    root = merkle.build_ledger_tree(entries)['root']
    report = {
        'checkpoint_id': checkpoint['id'],
        'root_matches': root == statement['root'] and len(entries) == statement['tree_size'],
        'statement_hash_matches': (hashlib.sha256(statement_bytes).hexdigest()
                                   == checkpoint['statement_sha256']),
        'signature_valid': verify_statement_signature(statement_bytes, checkpoint['signature_alg'],
                                                      checkpoint['signature']),
        'timestamp': None,
    }
    _json_path, tsr_path = checkpoint_paths(checkpoint['id'])
    if os.path.isfile(tsr_path):
        with open(tsr_path, 'rb') as f:
            ok, info = timestamping.verify_response(f.read(), hashlib.sha256(statement_bytes).digest())
        report['timestamp'] = {'valid': ok, 'gen_time': info.get('gen_time') if ok else None,
                               'error': None if ok else info}
    report['valid'] = bool(report['root_matches'] and report['statement_hash_matches']
                           and report['signature_valid']
                           and (report['timestamp'] is None or report['timestamp']['valid']))
    return report


def _maybe_periodic_checkpoint(entry):
    """Global checkpoint every PHOENIX_CHECKPOINT_EVERY entries (0 = off)."""
    every = checkpoint_every()
    if not every or entry.get('action') == CHECKPOINT_ACTION or entry['seq'] % every:
        return

    def _run():
        try:
            create_checkpoint(None, actor='system')
        except Exception as e:  # pragma: no cover - journalise seulement
            print(f'Erreur checkpoint Merkle: {e}')

    if timestamping.is_enabled():
        # Appel reseau au TSA : hors du chemin critique de l'appelant
        threading.Thread(target=_run, name='custody-checkpoint', daemon=True).start()
    else:
        _run()


def timestamp_status():
    """Etat de l'horodatage RFC 3161 et des checkpoints (console)."""
    conn = _connect()
    try:
        total = conn.execute('SELECT COUNT(*) AS n FROM custody_checkpoints').fetchone()['n']
        granted = conn.execute(
            "SELECT COUNT(*) AS n FROM custody_checkpoints WHERE tsa_status='granted'").fetchone()['n']
        last = conn.execute(
            "SELECT id, created_at, scope, root, tree_size, tsa_status, tsa_gen_time "
            "FROM custody_checkpoints WHERE scope='global' ORDER BY id DESC LIMIT 1").fetchone()
    finally:
        conn.close()
    info = timestamping.status()
    info.update({
        'checkpoints': total,
        'checkpoints_timestamped': granted,
        'checkpoint_every': checkpoint_every(),
        'last_global_checkpoint': dict(last) if last else None,
        'signature_algorithm': 'Ed25519' if _signing_key() is not None else 'HMAC-SHA256',
    })
    return info


# ------------------------------------------------------------------ reports

def file_sha256(path):
    h = hashlib.sha256()
    size = 0
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
            size += len(chunk)
    return h.digest(), size


def seal_report(path, report_id, investigation_id, actor, agent='Generateur de rapports'):
    """Seal the SHA-256 of a generated report in the ledger and timestamp it
    (<report>.tsr next to the report) when a TSA is configured."""
    digest, size = file_sha256(path)
    entry = safe_record('report_generated', actor, investigation_id=investigation_id, agent=agent,
                        artifact_ref=report_id, summary=f'Rapport genere ({size} octets)',
                        details={'report_id': report_id, 'size': size},
                        payload_sha256=digest.hex())
    ts = timestamping.timestamp_digest(digest, path + '.tsr')
    if ts['status'] != 'disabled':
        safe_record('report_timestamped', actor, investigation_id=investigation_id, agent=agent,
                    artifact_ref=report_id,
                    summary=(f"Horodatage RFC 3161 : {ts['status']} "
                             f"{ts.get('gen_time') or ts.get('error', '')}")[:500],
                    details={'report_id': report_id, 'tsa_status': ts['status'],
                             'gen_time': ts.get('gen_time'), 'serial_number': ts.get('serial_number')},
                    payload_sha256=digest.hex())
    return {'sha256': digest.hex(), 'size': size,
            'custody_seq': entry['seq'] if entry else None,
            'custody_hash': entry['entry_hash'] if entry else None,
            'timestamp': {k: v for k, v in ts.items() if k != 'tsr_path'}}
