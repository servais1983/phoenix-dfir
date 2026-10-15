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
import json
import sqlite3
import threading
import uuid

import database

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
"""

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
    return entry


def safe_record(*args, **kwargs):
    """record() qui ne fait jamais echouer l'operation metier appelante."""
    try:
        return record(*args, **kwargs)
    except Exception as e:  # pragma: no cover - journalise seulement
        print(f'Erreur chaine de preuve: {e}')
        return None


def list_entries(investigation_id=None, limit=500, after_seq=0):
    conn = _connect()
    try:
        if investigation_id:
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
                       case_dir=None, case_remediation_id=None):
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
        details={'action_id': action_id, 'command': action['command']},
        payload_sha256=sha256_json({k: action[k] for k in ('id', 'target_host', 'command', 'reason')}))
    action['custody_hash'] = entry['entry_hash'] if entry else None
    action['custody_entry'] = entry
    return action


def get_remediation(action_id):
    conn = _connect()
    try:
        row = conn.execute('SELECT * FROM remediation_actions WHERE id=?', (action_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_remediations(status=None, investigation_id=None, limit=200):
    query = 'SELECT * FROM remediation_actions WHERE 1=1'
    params = []
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
        return [dict(r) for r in conn.execute(query, params).fetchall()]
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
            return dict(row), 'already_decided'
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
        details={'action_id': action_id, 'command': action['command'], 'decision': status},
        payload_sha256=sha256_json({'id': action_id, 'decision': status, 'by': decided_by}))
    action['custody_hash'] = entry['entry_hash'] if entry else None
    action['custody_entry'] = entry
    return action, None
