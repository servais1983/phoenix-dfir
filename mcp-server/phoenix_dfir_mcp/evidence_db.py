"""Index des preuves du cas (SQLite FTS5) : super-timeline interrogeable.

Chaque sortie d'outil deterministe (parsers EVTX/log/CSV/JSON, Sigma,
Hayabusa, Volatility, EZ Tools...) est normalisee en evenements et indexee
dans ``<case_dir>/.phoenix_evidence.sqlite`` :

- ``runs``    : chaque outil execute sur un artefact (succes, nb d'evenements) —
               base des audits de couverture ;
- ``events``  : evenements normalises (horodatage UTC, hote, utilisateur,
               processus, Event ID, reference de preuve, texte) ;
- ``events_fts`` : index plein texte FTS5 sur le texte des evenements.

L'enqueteur interroge ensuite l'ensemble des artefacts d'un coup
(search_evidence, get_timeline) au lieu de correler de memoire dans sa
fenetre de contexte : c'est ce qui permet de tenir sur de gros cas.
"""

import datetime
import os
import re
import sqlite3
import threading

DB_NAME = '.phoenix_evidence.sqlite'
MAX_EVENTS_PER_RUN = 1_000_000  # default of PHOENIX_INDEX_MAX_EVENTS


def max_events_per_run():
    """Events one tool run indexes at most (PHOENIX_INDEX_MAX_EVENTS); more is reported."""
    try:
        return max(1, int(os.environ.get('PHOENIX_INDEX_MAX_EVENTS', MAX_EVENTS_PER_RUN)))
    except ValueError:
        return MAX_EVENTS_PER_RUN


def event_row_count(result):
    """Events a tool output holds (what record_run would index without a cap)."""
    return len(_event_rows(result)) if isinstance(result, dict) and not result.get('error') else 0
_TEXT_MAX = 2000
_BATCH = 5000
_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    artifact TEXT NOT NULL,
    ok INTEGER NOT NULL,
    events INTEGER NOT NULL DEFAULT 0,
    ran_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    tool TEXT NOT NULL,
    artifact TEXT NOT NULL,
    ts TEXT,
    ts_raw TEXT,
    host TEXT,
    user TEXT,
    process TEXT,
    event_id TEXT,
    ref_kind TEXT,
    ref_value TEXT,
    severity TEXT,
    text TEXT
);
CREATE TABLE IF NOT EXISTS event_refs (
    event_id INTEGER NOT NULL,
    artifact TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refs ON event_refs(kind, value);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_artifact ON events(artifact);
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    text, host, user, process, content='events', content_rowid='id'
);
"""

# ----------------------------------------------------------------------------
# Normalisation
# ----------------------------------------------------------------------------

_MONTHS = {m: i for i, m in enumerate(
    ('jan', 'feb', 'mar', 'apr', 'may', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec'), 1)}
_SYSLOG_RE = re.compile(r'^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})')


def normalize_ts(value, default_year=None):
    """Horodatage -> ISO 8601 UTC ('YYYY-MM-DDTHH:MM:SSZ') ou None.

    Accepte ISO 8601 (avec ou sans fuseau), 'YYYY-MM-DD HH:MM:SS(.f)',
    epoch (s / ms) et syslog sans annee ('Oct 10 03:12:05', annee
    deduite de default_year). Un horodatage sans fuseau est considere UTC.
    """
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
        num = float(value)
        if num > 1e12:
            num /= 1000.0
        if 1e8 < num < 1e10:
            dt = datetime.datetime.fromtimestamp(num, tz=datetime.timezone.utc)
            return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        return None
    text = str(value).strip()
    m = _SYSLOG_RE.match(text)
    if m and m.group(1).lower() in _MONTHS:
        year = default_year or datetime.datetime.now(datetime.timezone.utc).year
        try:
            dt = datetime.datetime(year, _MONTHS[m.group(1).lower()], int(m.group(2)),
                                   int(m.group(3)), int(m.group(4)), int(m.group(5)))
            return dt.strftime('%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            return None
    candidate = text.replace(' ', 'T', 1) if re.match(r'^\d{4}-\d{2}-\d{2} \d', text) else text
    candidate = candidate.replace('Z', '+00:00')
    # Tronquer les fractions > microsecondes (EVTX : 7 decimales)
    candidate = re.sub(r'(\.\d{6})\d+', r'\1', candidate)
    try:
        dt = datetime.datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def _first(d, *keys):
    for k in keys:
        v = d.get(k)
        if v not in (None, ''):
            return v
    return None


# Ordre = priorite de la reference principale citee : RecordID, puis ligne du
# fichier, puis ligne CSV, puis PID (un PID syslog n'identifie pas la ligne).
_REF_FIELDS = (('record_id', 'record_id'), ('RecordID', 'record_id'), ('EventRecordID', 'record_id'),
               ('RecordNumber', 'record_id'), ('line', 'line'), ('row', 'row'), ('inode', 'inode'),
               ('pid', 'pid'), ('PID', 'pid'))
_INODE_RE = re.compile(r'\d+(?:-\d+)*')


def _event_rows(result):
    """Extraire les lignes d'evenements d'une sortie d'outil, quel que soit l'outil."""
    for key in ('events', 'alerts', 'rows', 'entries', 'visits'):
        rows = result.get(key)
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            return rows
    outputs = result.get('outputs')  # EZ Tools : CSV multiples
    if isinstance(outputs, list):
        rows = []
        for out in outputs:
            if isinstance(out, dict) and isinstance(out.get('rows'), list):
                rows.extend(r for r in out['rows'] if isinstance(r, dict))
        return rows
    return []


def normalize_event(row, default_year=None):
    data = row.get('data') if isinstance(row.get('data'), dict) else {}
    merged = dict(data)
    merged.update({k: v for k, v in row.items() if k != 'data'})
    ts_raw = _first(merged, 'timestamp', 'Timestamp', 'TimeCreated', 'time', 'ts', 'CreateTime',
                    'visit_time', 'last_run', 'SourceCreated')
    if merged.get('macb') and merged.get('path'):
        # Evenement de timeline disque : texte lisible pour la recherche
        merged.setdefault('event', f"[{merged['macb'].upper()}] {merged['path']}")
    refs = []
    for field, kind in _REF_FIELDS:
        v = merged.get(field)
        if v in (None, ''):
            continue
        text = str(v).strip()
        if kind == 'inode':
            value = text if _INODE_RE.fullmatch(text) else None
        else:
            value = str(int(text)) if text.isdigit() else None
        if value is not None and (kind, value) not in refs:
            refs.append((kind, value))
    ref_kind, ref_value = refs[0] if refs else (None, None)
    text_parts = []
    for k, v in merged.items():
        if v in (None, '') or isinstance(v, (dict, list)) or k.startswith('_'):
            continue
        text_parts.append(f'{k}={v}')
    return {
        'ts': normalize_ts(ts_raw, default_year),
        'ts_raw': None if ts_raw is None else str(ts_raw)[:64],
        'host': _first(merged, 'host', 'computer', 'Computer', 'src_host', 'Hostname', 'hostname'),
        'user': _first(merged, 'user', 'User', 'TargetUserName', 'SubjectUserName', 'username',
                       'AccountName'),
        'process': _first(merged, 'process', 'Image', 'NewProcessName', 'ImageFileName',
                          'ProcessName', 'executable'),
        'event_id': _first(merged, 'event_id', 'EventID', 'EventId'),
        'ref_kind': ref_kind,
        'ref_value': ref_value,
        'refs': refs,
        'severity': _first(merged, 'severity', 'level', 'Level'),
        'text': ' '.join(text_parts)[:_TEXT_MAX],
    }


# ----------------------------------------------------------------------------
# Acces base
# ----------------------------------------------------------------------------

def db_path(case_dir):
    return os.path.join(case_dir, DB_NAME)


def _connect(case_dir):
    conn = sqlite3.connect(db_path(case_dir), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def exists(case_dir):
    return bool(case_dir) and os.path.isfile(db_path(case_dir))


def record_run(case_dir, tool, artifact, result):
    """Indexer la sortie d'un outil execute sur un artefact. Retourne le nb d'evenements."""
    if not case_dir or not os.path.isdir(case_dir) or not artifact:
        return 0
    ok = isinstance(result, dict) and not result.get('error')
    rows = _event_rows(result) if ok else []
    try:
        year = datetime.datetime.fromtimestamp(os.path.getmtime(artifact)).year
    except OSError:
        year = None
    artifact_rel = _rel(case_dir, artifact)
    with _lock:
        conn = _connect(case_dir)
        try:
            cur = conn.execute(
                'INSERT INTO runs (tool, artifact, ok, events, ran_at) VALUES (?, ?, ?, 0, ?)',
                (tool, artifact_rel, int(ok),
                 datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')))
            run_id = cur.lastrowid
            # Batched inserts in the run's transaction: event ids are given explicitly
            # (the lock keeps them unique), so refs and full text rows need no lookup
            next_id = (conn.execute('SELECT COALESCE(MAX(id), 0) FROM events').fetchone()[0] or 0) + 1
            count = 0
            capped = rows[:max_events_per_run()]
            for start in range(0, len(capped), _BATCH):
                events, refs, fts = [], [], []
                for row in capped[start:start + _BATCH]:
                    ev = normalize_event(row, year)
                    event_id = next_id + count
                    events.append((event_id, run_id, tool, artifact_rel, ev['ts'], ev['ts_raw'], _s(ev['host']),
                                   _s(ev['user']), _s(ev['process']), _s(ev['event_id']), ev['ref_kind'],
                                   ev['ref_value'], _s(ev['severity']), ev['text']))
                    refs.extend((event_id, artifact_rel, kind, value) for kind, value in ev['refs'])
                    fts.append((event_id, ev['text'], _s(ev['host']) or '', _s(ev['user']) or '',
                                _s(ev['process']) or ''))
                    count += 1
                conn.executemany(
                    'INSERT INTO events (id, run_id, tool, artifact, ts, ts_raw, host, user, process, '
                    'event_id, ref_kind, ref_value, severity, text) '
                    'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', events)
                conn.executemany('INSERT INTO event_refs (event_id, artifact, kind, value) '
                                 'VALUES (?, ?, ?, ?)', refs)
                conn.executemany('INSERT INTO events_fts(rowid, text, host, user, process) '
                                 'VALUES (?, ?, ?, ?, ?)', fts)
            conn.execute('UPDATE runs SET events=? WHERE id=?', (count, run_id))
            conn.commit()
            return count
        finally:
            conn.close()


def _s(value):
    return None if value is None else str(value)[:300]


def _rel(case_dir, path):
    try:
        rel = os.path.relpath(path, case_dir)
    except ValueError:
        return path
    return path if rel.startswith('..') else rel


def _event_dict(row):
    out = {k: row[k] for k in row.keys() if row[k] not in (None, '') and k not in ('id', 'run_id')}
    if row['ref_kind']:
        out['ref'] = {'artifact': row['artifact'], 'kind': row['ref_kind'], 'value': row['ref_value']}
    return out


def _fts_query(query):
    """Requete utilisateur -> requete FTS5 sure (mots entre guillemets, ET implicite).
    Les operateurs OR / NOT en majuscules sont conserves."""
    tokens = re.findall(r'"[^"]+"|\S+', query or '')
    parts = []
    for tok in tokens:
        if tok in ('OR', 'NOT', 'AND'):
            parts.append(tok)
            continue
        tok = tok.strip('"').replace('"', '')
        if tok:
            parts.append(f'"{tok}"')
    while parts and parts[-1] in ('OR', 'NOT', 'AND'):
        parts.pop()
    return ' '.join(parts)


def search(case_dir, query, artifact=None, limit=50):
    if not exists(case_dir):
        return {'error': "Aucun index de preuves : analyser d'abord les artefacts (parsers, Sigma...)."}
    fts = _fts_query(query)
    if not fts:
        return {'error': 'Requete vide'}
    limit = max(1, min(int(limit or 50), 500))
    sql = ('SELECT e.* FROM events_fts f JOIN events e ON e.id = f.rowid '
           'WHERE events_fts MATCH ?')
    params = [fts]
    if artifact:
        sql += ' AND e.artifact LIKE ?'
        params.append(f'%{artifact}%')
    sql += ' ORDER BY e.ts IS NULL, e.ts LIMIT ?'
    params.append(limit)
    conn = _connect(case_dir)
    try:
        try:
            rows = conn.execute(sql, params).fetchall()
            total = conn.execute('SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH ?',
                                 (fts,)).fetchone()[0]
        except sqlite3.OperationalError as e:
            return {'error': f'Requete invalide : {e}'}
        return {'query': query, 'total_matches': total, 'returned': len(rows),
                'events': [_event_dict(r) for r in rows]}
    finally:
        conn.close()


def timeline(case_dir, start=None, end=None, host=None, user=None, contains=None, artifact=None,
             limit=200):
    if not exists(case_dir):
        return {'error': "Aucun index de preuves : analyser d'abord les artefacts (parsers, Sigma...)."}
    clauses, params = ['e.ts IS NOT NULL'], []
    for value, clause in ((normalize_ts(start) if start else None, 'e.ts >= ?'),
                          (normalize_ts(end) if end else None, 'e.ts <= ?')):
        if value:
            clauses.append(clause)
            params.append(value)
    for value, column in ((host, 'host'), (user, 'user'), (artifact, 'artifact')):
        if value:
            clauses.append(f'e.{column} LIKE ?')  # nosec B608 - colonne issue d'une liste fixe
            params.append(f'%{value}%')
    if contains:
        clauses.append('e.text LIKE ?')
        params.append(f'%{contains}%')
    limit = max(1, min(int(limit or 200), 1000))
    where = ' AND '.join(clauses)
    conn = _connect(case_dir)
    try:
        total = conn.execute(f'SELECT COUNT(*) FROM events e WHERE {where}', params).fetchone()[0]  # nosec B608
        rows = conn.execute(f'SELECT e.* FROM events e WHERE {where} ORDER BY e.ts, e.id LIMIT ?',  # nosec B608
                            params + [limit]).fetchall()
        return {'total_events': total, 'returned': len(rows), 'truncated': total > len(rows),
                'events': [_event_dict(r) for r in rows]}
    finally:
        conn.close()


def sources(case_dir):
    if not exists(case_dir):
        return {'sources': [], 'total_events': 0}
    conn = _connect(case_dir)
    try:
        rows = conn.execute(
            'SELECT artifact, tool, MAX(ok) AS ok, SUM(events) AS events, COUNT(*) AS runs, '
            'MIN(ran_at) AS first_run FROM runs GROUP BY artifact, tool ORDER BY artifact, tool'
        ).fetchall()
        span = conn.execute('SELECT MIN(ts), MAX(ts), COUNT(*) FROM events').fetchone()
        return {'sources': [dict(r) for r in rows], 'total_events': span[2],
                'time_span': {'first': span[0], 'last': span[1]}}
    finally:
        conn.close()


def runs_by_artifact(case_dir):
    """{artifact_rel: {tool: ok}} pour les audits de couverture."""
    out = {}
    for src in sources(case_dir)['sources']:
        out.setdefault(src['artifact'], {})[src['tool']] = bool(src['ok'])
    return out


def has_ref(case_dir, artifact, kind, value):
    """La reference (record_id/pid/line/row) a-t-elle ete produite par un outil
    sur cet artefact ? (persiste au-dela d'un redemarrage du processus)"""
    if not exists(case_dir):
        return False
    base = os.path.basename(str(artifact).rstrip('/\\'))
    conn = _connect(case_dir)
    try:
        row = conn.execute(
            'SELECT 1 FROM event_refs WHERE kind=? AND value=? '
            'AND (artifact=? OR artifact=? OR artifact LIKE ?) LIMIT 1',
            (kind, str(value), _rel(case_dir, artifact), base, f'%/{base}')).fetchone()
        return row is not None
    finally:
        conn.close()
