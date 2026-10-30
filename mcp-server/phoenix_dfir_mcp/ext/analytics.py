"""Analytique colonnaire sur la super-timeline du cas (dependance optionnelle).

Outils :

- analytics_query          : SQL en LECTURE SEULE sur les evenements du cas (tables
                             `events` et `runs`). Execute par DuckDB s'il est
                             importable (copie en memoire, acces externe coupe),
                             sinon par SQLite sur l'index des preuves ouvert en
                             lecture seule (mode=ro, query_only, autorisateur qui
                             n'admet que SELECT / READ / fonctions sures).
- analytics_stack          : stacking / longue traine : valeurs les MOINS frequentes
                             d'un champ (processus, couple parent-enfant, user agent,
                             destination, utilisateur...) sur une fenetre de temps,
                             globalement ou par hote.
- analytics_export_parquet : export des evenements vers <cas>/analytics/events.parquet
                             (DuckDB requis).

Garde SQL (deux moteurs) : une seule instruction SELECT (ou WITH ... SELECT), aucun
commentaire, aucun mot cle d'ecriture ou d'administration (ATTACH, PRAGMA, COPY,
INSERT...), aucune fonction d'acces fichier ou d'extension (load_extension,
read_csv, *_scan...), plafond de lignes et delai maximal. L'index des preuves
n'est jamais ouvert en ecriture.
"""

import datetime
import json
import os
import re
import sqlite3
import tempfile
import threading
import time
import urllib.parse

from .. import evidence_db, toolkit

AGENT = ('analytics', 'Agent Analytique colonnaire (stacking)')
READONLY = ('analytics_query', 'analytics_stack')
INTERNAL_DIRS = ('analytics',)
PHASE_TOOLS = {
    'correlation': ('analytics_query', 'analytics_stack'),
    'contre_analyse': ('analytics_query', 'analytics_stack'),
}
PHASE_HINTS = {
    'correlation': ("- Longue traine : analytics_stack (field process, parent_child, user_agent, "
                    "destination ; per_host) revele les valeurs rares d'une fenetre de temps ; "
                    "analytics_query (SQL SELECT en lecture seule sur la table events) pour les "
                    "agregations."),
}

ANALYTICS_DIR = 'analytics'
PARQUET_FILE = 'events.parquet'
MAX_SQL_CHARS = 5000
DEFAULT_LIMIT = 200
MAX_LIMIT = 2000
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 60.0
MAX_LOAD_ROWS = 500000
MAX_CELL_CHARS = 1000

EVENT_COLUMNS = ('id', 'run_id', 'tool', 'artifact', 'ts', 'ts_raw', 'host', 'user', 'process',
                 'event_id', 'ref_kind', 'ref_value', 'severity', 'text')
RUN_COLUMNS = ('id', 'tool', 'artifact', 'ok', 'events', 'ran_at')
_EVENT_TYPES = ('BIGINT', 'BIGINT') + ('VARCHAR',) * 12
_RUN_TYPES = ('BIGINT', 'VARCHAR', 'VARCHAR', 'INTEGER', 'BIGINT', 'VARCHAR')


def _duckdb():
    """Module duckdb s'il est installe, sinon None (dependance optionnelle)."""
    try:
        import duckdb
    except ImportError:
        return None
    return duckdb


# ============================================================================
# Garde SQL
# ============================================================================

_DENY_WORDS = (
    'insert', 'update', 'delete', 'merge', 'upsert', 'create', 'drop', 'alter',
    'attach', 'detach', 'pragma', 'vacuum', 'reindex', 'analyze', 'copy', 'export', 'import',
    'install', 'load', 'force', 'checkpoint', 'set', 'reset', 'call', 'begin', 'commit',
    'rollback', 'savepoint', 'release', 'truncate', 'grant', 'revoke', 'execute', 'prepare',
    'deallocate', 'into', 'use', 'transaction',
)
_DENY_FUNCS = re.compile(
    r'\b(load_extension|readfile|writefile|edit|fts3_tokenizer|zipfile|sqlar_\w+|read_\w+|'
    r'\w+_scan|glob|query|query_table|getenv|duckdb_secrets|which_secret|sniff_csv)\s*\(',
    re.IGNORECASE)
_DENY_RE = re.compile(r'\b(' + '|'.join(_DENY_WORDS) + r')\b', re.IGNORECASE)


class SQLRejected(ValueError):
    pass


def _mask(sql):
    """Masquer litteraux et identifiants entre guillemets (le contenu n'est pas
    analyse comme du SQL). Rejette commentaires et litteraux non fermes."""
    out, i, n = [], 0, len(sql)
    while i < n:
        c = sql[i]
        if c in ("'", '"'):
            j = i + 1
            while True:
                if j >= n:
                    raise SQLRejected('Litteral ou identifiant non ferme')
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:  # guillemet double echappe
                        j += 2
                        continue
                    break
                j += 1
            out.append("'S'" if c == "'" else '"I"')
            i = j + 1
            continue
        if c == '`':
            raise SQLRejected('Identifiants entre accents graves interdits')
        if sql.startswith('--', i) or sql.startswith('/*', i):
            raise SQLRejected('Commentaires interdits dans la requete')
        out.append(c)
        i += 1
    return ''.join(out)


def check_sql(sql):
    """Valider une requete analytique. Retourne la requete (sans ';' final) ou leve
    SQLRejected."""
    if not isinstance(sql, str) or not sql.strip():
        raise SQLRejected('Requete vide')
    if len(sql) > MAX_SQL_CHARS:
        raise SQLRejected(f'Requete trop longue (> {MAX_SQL_CHARS} caracteres)')
    if '\x00' in sql:
        raise SQLRejected('Caractere nul interdit')
    masked = _mask(sql)
    stripped = masked.rstrip()
    body = sql.rstrip()
    if stripped.endswith(';'):
        stripped = stripped[:-1].rstrip()
        body = body[:-1].rstrip()
    if ';' in stripped:
        raise SQLRejected('Une seule instruction autorisee')
    first = re.match(r'\s*([A-Za-z]+)', stripped)
    if not first or first.group(1).lower() not in ('select', 'with'):
        raise SQLRejected('Seules les requetes SELECT (ou WITH ... SELECT) sont autorisees')
    word = _DENY_RE.search(stripped)
    if word:
        raise SQLRejected(f"Mot cle interdit : {word.group(1).upper()}")
    func = _DENY_FUNCS.search(stripped)
    if func:
        raise SQLRejected(f"Fonction interdite : {func.group(1)}")
    if re.search(r"\b(from|join)\s*\(?\s*'S'", stripped, re.IGNORECASE):
        raise SQLRejected('Lecture de fichier (litteral en source de donnees) interdite')
    return body.strip()


# ============================================================================
# Moteurs
# ============================================================================

def _ro_connect(case_dir):
    """Connexion SQLite STRICTEMENT en lecture seule sur l'index des preuves."""
    path = os.path.abspath(evidence_db.db_path(case_dir))
    if not os.path.isfile(path):
        return None
    uri = 'file:' + urllib.parse.quote(path) + '?mode=ro'
    conn = sqlite3.connect(uri, uri=True, timeout=5)
    conn.execute('PRAGMA query_only = ON')
    return conn


_SAFE_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
                 getattr(sqlite3, 'SQLITE_RECURSIVE', 33)}
_DENIED_SQLITE_FUNCS = {'load_extension', 'readfile', 'writefile', 'edit', 'fts3_tokenizer',
                        'zipfile', 'sqlar_compress', 'sqlar_uncompress'}


def _authorizer(action, arg1, arg2, _db, _trigger):
    if action not in _SAFE_ACTIONS:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and str(arg2 or '').lower() in _DENIED_SQLITE_FUNCS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _cell(value):
    if value is None or isinstance(value, (int, float, bool)):
        return value
    text = value if isinstance(value, str) else str(value)
    return text[:MAX_CELL_CHARS]


def _run_sqlite(case_dir, sql, limit, timeout):
    conn = _ro_connect(case_dir)
    if conn is None:
        return {'error': "Aucun index de preuves : analyser d'abord les artefacts."}
    deadline = time.monotonic() + timeout
    try:
        conn.set_authorizer(_authorizer)
        conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 5000)
        try:
            cur = conn.execute(sql)
            rows = cur.fetchmany(limit + 1)
        except sqlite3.DatabaseError as exc:
            if time.monotonic() > deadline:
                return {'error': f'Delai depasse ({timeout:.0f}s)'}
            return {'error': f'Requete refusee ou invalide : {exc}'}
        columns = [d[0] for d in cur.description or ()]
    finally:
        conn.close()
    return _table('sqlite', columns, rows, limit)


def _load_duckdb(duckdb, case_dir):
    """Copie en memoire (DuckDB) des tables events / runs, puis coupure de tout
    acces externe. Retourne (connexion, nb_lignes, tronque) ou (None, 0, False)."""
    src = _ro_connect(case_dir)
    if src is None:
        return None, 0, False
    try:
        events = src.execute('SELECT ' + ', '.join(f'"{c}"' for c in EVENT_COLUMNS)  # nosec B608 - colonnes fixes
                             + ' FROM events ORDER BY id LIMIT ?', (MAX_LOAD_ROWS + 1,)).fetchall()
        runs = src.execute('SELECT ' + ', '.join(RUN_COLUMNS) + ' FROM runs').fetchall()  # nosec B608
    finally:
        src.close()
    truncated = len(events) > MAX_LOAD_ROWS
    events = events[:MAX_LOAD_ROWS]
    con = duckdb.connect(':memory:')
    # Chargement en masse via JSON lignes (executemany est trop lent), dans un
    # dossier temporaire prive supprime aussitot ; l'acces externe est coupe ensuite.
    with tempfile.TemporaryDirectory(prefix='phoenix_analytics_') as tmp:
        for table, columns, types, data in (('events', EVENT_COLUMNS, _EVENT_TYPES, events),
                                            ('runs', RUN_COLUMNS, _RUN_TYPES, runs)):
            path = os.path.join(tmp, f'{table}.jsonl')
            with open(path, 'w', encoding='utf-8') as f:
                for row in data:
                    f.write(json.dumps(dict(zip(columns, row)), ensure_ascii=False, default=str))
                    f.write('\n')
            struct = ', '.join(f"'{c}': '{t}'" for c, t in zip(columns, types))
            cols = ', '.join(f'"{c}" {t}' for c, t in zip(columns, types))
            names = ', '.join(f'"{c}"' for c in columns)
            con.execute(f'CREATE TABLE {table} ({cols})')
            if data:
                con.execute(f'INSERT INTO {table} SELECT {names} FROM read_json(?, '  # nosec B608 - schema fixe
                            f"format='newline_delimited', columns={{{struct}}})", [path])
    return con, len(events), truncated


def _lock_duckdb(con):
    con.execute('SET enable_external_access = false')
    con.execute('SET lock_configuration = true')


def _run_duckdb(duckdb, case_dir, sql, limit, timeout):
    con, loaded, truncated = _load_duckdb(duckdb, case_dir)
    if con is None:
        return {'error': "Aucun index de preuves : analyser d'abord les artefacts."}
    timer = threading.Timer(timeout, con.interrupt)
    timer.daemon = True
    try:
        _lock_duckdb(con)
        timer.start()
        try:
            cur = con.execute(sql)
            rows = cur.fetchmany(limit + 1)
        except Exception as exc:  # duckdb.Error et interruptions
            if 'interrupt' in str(exc).lower():
                return {'error': f'Delai depasse ({timeout:.0f}s)'}
            return {'error': f'Requete refusee ou invalide : {exc}'}
        columns = [d[0] for d in cur.description or ()]
    finally:
        timer.cancel()
        con.close()
    out = _table('duckdb', columns, rows, limit)
    out['events_loaded'] = loaded
    if truncated:
        out['load_truncated'] = True
    return out


def _table(engine, columns, rows, limit):
    return {'engine': engine, 'columns': columns,
            'rows': [dict(zip(columns, (_cell(v) for v in row))) for row in rows[:limit]],
            'returned': min(len(rows), limit), 'truncated': len(rows) > limit}


def run_query(case_dir, sql, limit=DEFAULT_LIMIT, timeout=DEFAULT_TIMEOUT, engine='auto'):
    try:
        clean = check_sql(sql)
    except SQLRejected as exc:
        return {'error': f'Requete refusee : {exc}', 'rejected': True}
    limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    timeout = max(0.1, min(float(timeout or DEFAULT_TIMEOUT), MAX_TIMEOUT))
    duckdb = _duckdb() if engine in ('auto', 'duckdb', None) else None
    if engine == 'duckdb' and duckdb is None:
        return {'error': "DuckDB non installe (pip install duckdb) : utiliser engine='sqlite'."}
    if duckdb is not None:
        return _run_duckdb(duckdb, case_dir, clean, limit, timeout)
    return _run_sqlite(case_dir, clean, limit, timeout)


# ============================================================================
# Stacking / longue traine
# ============================================================================

_KV = re.compile(r'(?:^|\s)([A-Za-z_][\w.()\-]*)=')
_PARENT_KEYS = ('parentimage', 'parentprocessname', 'parent_process', 'parent_image', 'parent',
                'parentname', 'ppid_name')
_CHILD_KEYS = ('image', 'newprocessname', 'process', 'imagefilename', 'processname', 'exe',
               'executable')
_UA_KEYS = ('user_agent', 'useragent', 'cs(user-agent)', 'http_user_agent', 'ua', 'useragentstring')
_DEST_KEYS = ('destinationip', 'destinationhostname', 'dst_ip', 'dest_ip', 'dstip', 'dst',
              'dest', 'destination', 'remote_ip', 'remoteaddress', 'dst_host', 'destaddress',
              'server_name', 'sni', 'query')
_PORT_KEYS = ('destinationport', 'dst_port', 'dest_port', 'dport', 'remoteport')
_CMD_KEYS = ('commandline', 'command_line', 'cmdline', 'cmd', 'command')

STACK_FIELDS = ('process', 'parent_child', 'user', 'host', 'event_id', 'user_agent',
                'destination', 'command_line', 'tool', 'artifact')


def parse_text(text):
    """Texte d'evenement 'k=v k=v' -> {cle_minuscule: valeur}."""
    out = {}
    matches = list(_KV.finditer(text or ''))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        value = text[m.end():end].strip()
        if value:
            out.setdefault(m.group(1).lower(), value)
    return out


def _pick(fields, keys):
    for k in keys:
        if fields.get(k):
            return fields[k]
    return None


def _exe(value):
    return re.split(r'[\\/]', str(value).strip().strip('"'))[-1].lower() if value else None


def field_value(field, row):
    """Valeur stackee d'un evenement (None si absente)."""
    if field in ('user', 'host', 'event_id', 'tool', 'artifact'):
        value = row[field]
        return str(value).lower() if field in ('user', 'host') and value else value
    fields = parse_text(row['text'])
    if field == 'process':
        return _exe(row['process'] or _pick(fields, _CHILD_KEYS))
    if field == 'parent_child':
        parent = _exe(_pick(fields, _PARENT_KEYS))
        child = _exe(row['process'] or _pick(fields, _CHILD_KEYS))
        return f'{parent} > {child}' if parent and child else None
    if field == 'user_agent':
        return _pick(fields, _UA_KEYS)
    if field == 'destination':
        dest = _pick(fields, _DEST_KEYS)
        port = _pick(fields, _PORT_KEYS)
        if dest and port and str(port).isdigit():
            return f'{dest}:{port}'
        return dest
    if field == 'command_line':
        return _pick(fields, _CMD_KEYS)
    return None


def _stack(rows, field, limit):
    groups = {}
    for row in rows:
        value = field_value(field, row)
        if value in (None, ''):
            continue
        value = str(value)[:MAX_CELL_CHARS]
        g = groups.setdefault(value, {'value': value, 'count': 0, 'hosts': set(),
                                      'first_seen': None, 'last_seen': None, 'refs': []})
        g['count'] += 1
        if row['host']:
            g['hosts'].add(row['host'])
        ts = row['ts']
        if ts:
            g['first_seen'] = min(filter(None, (g['first_seen'], ts)))
            g['last_seen'] = max(filter(None, (g['last_seen'], ts)))
        if row['ref_kind'] and len(g['refs']) < 3:
            g['refs'].append({'artifact': row['artifact'], 'kind': row['ref_kind'],
                              'value': row['ref_value']})
    ordered = sorted(groups.values(), key=lambda g: (g['count'], g['first_seen'] or '', g['value']))
    for g in ordered:
        g['hosts'] = sorted(g['hosts'])[:5]
    return ordered, sum(g['count'] for g in ordered)


def stack(case_dir, field, start=None, end=None, host=None, artifact=None, per_host=False,
          limit=20):
    if field not in STACK_FIELDS:
        return {'error': f'Champ inconnu : {field}. Champs : {list(STACK_FIELDS)}'}
    conn = _ro_connect(case_dir)
    if conn is None:
        return {'error': "Aucun index de preuves : analyser d'abord les artefacts."}
    clauses, params = [], []
    for value, clause in ((evidence_db.normalize_ts(start) if start else None, 'ts >= ?'),
                          (evidence_db.normalize_ts(end) if end else None, 'ts <= ?')):
        if value:
            clauses.append(clause)
            params.append(value)
    if host:
        clauses.append('host LIKE ?')
        params.append(f'%{host}%')
    if artifact:
        clauses.append('artifact LIKE ?')
        params.append(f'%{artifact}%')
    where = (' WHERE ' + ' AND '.join(clauses)) if clauses else ''
    limit = max(1, min(int(limit or 20), 200))
    try:
        conn.row_factory = sqlite3.Row
        conn.set_authorizer(_authorizer)
        # Clauses fixes, valeurs parametrees
        rows = conn.execute('SELECT tool, artifact, ts, host, user, process, event_id, ref_kind, '  # nosec B608
                            f'ref_value, text FROM events{where} ORDER BY ts, id LIMIT ?',
                            params + [MAX_LOAD_ROWS]).fetchall()
    finally:
        conn.close()
    window = {'start': evidence_db.normalize_ts(start) if start else None,
              'end': evidence_db.normalize_ts(end) if end else None}
    result = {'field': field, 'window': window, 'events_scanned': len(rows),
              'scan_truncated': len(rows) >= MAX_LOAD_ROWS}
    ordered, with_value = _stack(rows, field, limit)
    result.update(events_with_value=with_value, distinct_values=len(ordered),
                  least_frequent=ordered[:limit],
                  most_frequent=sorted(ordered, key=lambda g: (-g['count'], g['value']))[:5])
    if per_host:
        by_host = {}
        for row in rows:
            by_host.setdefault(row['host'] or '(sans hote)', []).append(row)
        result['by_host'] = []
        for name in sorted(by_host):
            host_groups, host_total = _stack(by_host[name], field, limit)
            if host_groups:
                result['by_host'].append({'host': name, 'events_with_value': host_total,
                                          'distinct_values': len(host_groups),
                                          'least_frequent': host_groups[:limit]})
    return result


# ============================================================================
# Export Parquet
# ============================================================================

def export_parquet(case_dir):
    duckdb = _duckdb()
    if duckdb is None:
        return {'error': "Export Parquet indisponible : DuckDB non installe (pip install duckdb).",
                'duckdb': False}
    case_real = os.path.realpath(case_dir)
    out_dir = os.path.join(case_real, ANALYTICS_DIR)
    target = os.path.realpath(os.path.join(out_dir, PARQUET_FILE))
    if not target.startswith(case_real + os.sep):
        return {'error': 'Chemin de sortie hors du dossier du cas'}
    con, loaded, truncated = _load_duckdb(duckdb, case_dir)
    if con is None:
        return {'error': "Aucun index de preuves : analyser d'abord les artefacts."}
    try:
        os.makedirs(out_dir, exist_ok=True)
        literal = target.replace("'", "''")
        # Chemin fixe construit par Phoenix (jamais fourni par l'enqueteur)
        con.execute(f"COPY events TO '{literal}' (FORMAT PARQUET)")
    finally:
        con.close()
    return {'path': os.path.relpath(target, case_real), 'rows': loaded, 'load_truncated': truncated,
            'size_bytes': os.path.getsize(target),
            'exported_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')}


# ============================================================================
# Outils
# ============================================================================

@toolkit.tool(
    'analytics_query',
    "SQL analytique en LECTURE SEULE sur la super-timeline du cas : table events (id, tool, "
    "artifact, ts UTC ISO, host, user, process, event_id, ref_kind, ref_value, severity, text) et "
    "table runs. Une seule instruction SELECT (ou WITH ... SELECT), sans commentaire ; ecritures, "
    "ATTACH, PRAGMA, COPY et acces fichier refuses. DuckDB si installe (sinon SQLite) ; avec "
    "DuckDB, citer la colonne user entre guillemets (\"user\"). Ex: SELECT process, COUNT(*) n "
    "FROM events GROUP BY process ORDER BY n LIMIT 20.",
    {'type': 'object', 'properties': {
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'sql': {'type': 'string', 'description': 'Requete SELECT'},
        'limit': {'type': 'integer', 'description': f'Lignes max (defaut {DEFAULT_LIMIT}, max {MAX_LIMIT})'},
        'timeout': {'type': 'number', 'description': f'Delai max en secondes (defaut {DEFAULT_TIMEOUT:.0f})'},
        'engine': {'type': 'string', 'enum': ['auto', 'duckdb', 'sqlite'],
                   'description': 'Moteur (defaut auto : DuckDB si disponible)'},
    }, 'required': ['case_dir', 'sql']},
)
def analytics_query(case_dir, sql, limit=DEFAULT_LIMIT, timeout=DEFAULT_TIMEOUT, engine='auto'):
    return run_query(case_dir, sql, limit=limit, timeout=timeout, engine=engine)


@toolkit.tool(
    'analytics_stack',
    "Stacking (analyse de longue traine) sur la super-timeline : valeurs les MOINS frequentes d'un "
    "champ, avec nombre d'occurrences, hotes, premiere / derniere apparition et references de "
    "preuve citables. Champs : process, parent_child (parent > enfant), user, host, event_id, "
    "user_agent, destination (ip:port), command_line, tool, artifact. Fenetre start / end (ISO "
    "8601), filtre hote ou artefact, per_host pour une longue traine par hote.",
    {'type': 'object', 'properties': {
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'field': {'type': 'string', 'enum': list(STACK_FIELDS), 'description': 'Champ a stacker'},
        'start': {'type': 'string', 'description': 'Debut de fenetre (ISO 8601)'},
        'end': {'type': 'string', 'description': 'Fin de fenetre (ISO 8601)'},
        'host': {'type': 'string', 'description': 'Filtre hote (partiel)'},
        'artifact': {'type': 'string', 'description': 'Filtre artefact (partiel)'},
        'per_host': {'type': 'boolean', 'description': 'Longue traine calculee par hote'},
        'limit': {'type': 'integer', 'description': 'Valeurs rares retournees (defaut 20)'},
    }, 'required': ['case_dir', 'field']},
)
def analytics_stack(case_dir, field, start=None, end=None, host=None, artifact=None,
                    per_host=False, limit=20):
    return stack(case_dir, field, start=start, end=end, host=host, artifact=artifact,
                 per_host=per_host, limit=limit)


@toolkit.tool(
    'analytics_export_parquet',
    "Exporter les evenements de la super-timeline vers <cas>/analytics/events.parquet (format "
    "colonnaire, pour un notebook ou un outil BI). Necessite DuckDB.",
    {'type': 'object', 'properties': {
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
    }, 'required': ['case_dir']},
)
def analytics_export_parquet(case_dir):
    return export_parquet(case_dir)
