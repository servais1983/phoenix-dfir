"""Sigma rules on Windows events with pySigma and its SQLite backend.

The events of an artifact (EVTX, or a JSON / CSV export) are loaded in an
in-memory SQLite table, one row per event, with the Windows field names
(``EventID``, ``Channel``, ``Image``, ``CommandLine``...). Every rule is
converted by pySigma to SQL and run on that table. A match keeps the
``record_id`` and ``row`` of the event, so every alert cites what a tool
observed. The table is read only while the rules run (SQLite authorizer).

Rules come from, in this order:

1. the SigmaHQ subset shipped with Phoenix (``data/sigma/sigmahq``, Detection
   Rule License 1.1, see the NOTICE file there);
2. the SigmaHQ release synced with ``phoenix rules sync`` and the archives
   imported with ``phoenix rules import`` (``<data dir>/sigma``);
3. the folders of ``PHOENIX_SIGMA_RULES`` (``os.pathsep`` separated) and the
   ``rules_path`` of the Sigma connector.

The 29 built in Phoenix rules (``integrations/sigma_connector.py``) stay the
fallback engine: they always run, with or without pySigma. They are also
published as Sigma YAML in ``data/sigma/phoenix`` (``export_builtin``).

pySigma is optional (``pip install "phoenix-dfir[sigma]"``). Without it the
engine reports "not available" and only the built in rules run.
"""

import hashlib
import io
import os
import re
import sqlite3
import threading
import uuid
import zipfile
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / 'data' / 'sigma'
BUNDLED_DIR = DATA_DIR / 'sigmahq'
BUILTIN_DIR = DATA_DIR / 'phoenix'
SIGMAHQ_TAG = 'r2026-07-01'
SIGMAHQ_URL = f'https://github.com/SigmaHQ/sigma/archive/refs/tags/{SIGMAHQ_TAG}.zip'
SIGMAHQ_BLOB = f'https://github.com/SigmaHQ/sigma/blob/{SIGMAHQ_TAG}/'
RULE_SUFFIXES = ('.yml', '.yaml')
MAX_RULE_BYTES = 256 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_FILES = 20000
SKIPPED_STATUS = ('deprecated', 'unsupported')

# Field names of Windows exports and EVTX EventData, mapped to the names the
# SigmaHQ rules use. The first present source wins, the target is never
# overwritten when the event already has it.
FIELD_ALIASES = (
    ('Image', ('NewProcessName', 'ProcessName', 'Application')),
    ('CommandLine', ('ProcessCommandLine',)),
    ('ParentImage', ('ParentProcessName',)),
    ('Provider_Name', ('Provider', 'ProviderName')),
    ('EventID', ('EventId', 'EventCode', 'event_id')),
    ('Channel', ('channel', 'LogName')),
    ('Computer', ('computer', 'Hostname')),
)

# logsource service -> Channel value(s) of the event
SERVICE_CHANNELS = {
    'security': ('Security',),
    'system': ('System',),
    'application': ('Application',),
    'sysmon': ('Microsoft-Windows-Sysmon/Operational',),
    'powershell': ('Microsoft-Windows-PowerShell/Operational',),
    'powershell-classic': ('Windows PowerShell',),
    'taskscheduler': ('Microsoft-Windows-TaskScheduler/Operational',),
    'wmi': ('Microsoft-Windows-WMI-Activity/Operational',),
    'windefend': ('Microsoft-Windows-Windows Defender/Operational',),
    'firewall-as': ('Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',),
    'bits-client': ('Microsoft-Windows-Bits-Client/Operational',),
    'terminalservices-localsessionmanager':
        ('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',),
}

# logsource category -> (Channel, EventID) pairs that carry it
CATEGORY_EVENTS = {
    'process_creation': (('Microsoft-Windows-Sysmon/Operational', 1), ('Security', 4688)),
    'network_connection': (('Microsoft-Windows-Sysmon/Operational', 3),),
    'process_access': (('Microsoft-Windows-Sysmon/Operational', 10),),
    'image_load': (('Microsoft-Windows-Sysmon/Operational', 7),),
    'file_event': (('Microsoft-Windows-Sysmon/Operational', 11),),
    'registry_set': (('Microsoft-Windows-Sysmon/Operational', 13),),
    'registry_event': (('Microsoft-Windows-Sysmon/Operational', 12), ('Microsoft-Windows-Sysmon/Operational', 13),
                       ('Microsoft-Windows-Sysmon/Operational', 14)),
    'dns_query': (('Microsoft-Windows-Sysmon/Operational', 22),),
    'ps_script': (('Microsoft-Windows-PowerShell/Operational', 4104),),
    'ps_module': (('Microsoft-Windows-PowerShell/Operational', 4103),),
}

_TECHNIQUE_TAG = re.compile(r'^attack\.(t\d{4}(?:\.\d{3})?)$', re.I)
_TACTIC_TAG = re.compile(r'^attack\.([a-z][a-z-]+)$', re.I)
_MISSING_COLUMN = re.compile(r'no such column: (.+)$')

_cache_lock = threading.Lock()
_cache = {}  # (path, mtime_ns, size) -> compiled rule or None


def available():
    """True when pySigma and its SQLite backend are importable."""
    try:
        import sigma.backends.sqlite  # noqa: F401
        import sigma.collection  # noqa: F401
    except ImportError:
        return False
    return True


def status():
    if not available():
        return {'available': False, 'detail': 'not available: pip install "phoenix-dfir[sigma]" (pySigma)'}
    import sigma
    try:
        from importlib.metadata import version
        ver = version('pySigma')
    except Exception:  # metadata missing in some layouts
        ver = getattr(sigma, '__version__', None)
    return {'available': True, 'pysigma': ver, 'dirs': [str(d) for d in rule_dirs()]}


# ----------------------------------------------------------------------------
# Rule folders, sync and import
# ----------------------------------------------------------------------------

def store_dir():
    """Per-user folder of synced and imported rules."""
    from . import _paths
    _paths.ensure_backend_importable()
    import datadirs
    return datadirs.data_dir() / 'sigma'


def rule_dirs(extra=()):
    """Folders the engine loads rules from (existing ones only, no duplicates)."""
    dirs = [BUNDLED_DIR]
    try:
        store = store_dir()
        dirs += [store / SIGMAHQ_TAG / 'rules', store / 'imported']
    except Exception:  # nosec B110 - an unwritable data dir must not break detection
        pass
    env = os.environ.get('PHOENIX_SIGMA_RULES', '')
    dirs += [Path(p) for p in env.split(os.pathsep) if p.strip()]
    dirs += [Path(p) for p in extra if p]
    seen, out = set(), []
    for d in dirs:
        key = os.path.normcase(str(Path(d).resolve()))
        if key not in seen and Path(d).is_dir():
            seen.add(key)
            out.append(Path(d))
    return out


def connector_rules_path():
    """``rules_path`` saved for the Sigma connector in the console database ('' if none)."""
    import json
    try:
        from . import _paths
        _paths.ensure_backend_importable()
        import datadirs
        db = Path(datadirs.default_db_path())
        if not db.is_file():
            return ''
        # A plain connection (query only) removes the WAL files it opened on close
        conn = sqlite3.connect(str(db))
        try:
            conn.execute('PRAGMA query_only = ON')
            row = conn.execute("SELECT config FROM integration_configs WHERE connector_id='sigma'").fetchone()
        finally:
            conn.close()
        return str(json.loads(row[0] or '{}').get('rules_path') or '').strip() if row else ''
    except (sqlite3.Error, ValueError, OSError, ImportError):
        return ''


def count_rules(folder):
    """Rules of one folder pySigma can run, and the invalid ones."""
    if not available() or not folder or not Path(folder).is_dir():
        return {'usable': 0, 'invalid': 0}
    usable = invalid = 0
    for path in _rule_files([Path(folder)]):
        compiled = _compile(path)
        if compiled and 'error' not in compiled:
            usable += 1
        elif compiled:
            invalid += 1
    return {'usable': usable, 'invalid': invalid}


def _safe_member(name):
    """Relative path of an archive member, or None when it would escape the folder."""
    parts = [p for p in re.split(r'[\\/]+', name) if p not in ('', '.')]
    if not parts or any(p == '..' or ':' in p for p in parts):
        return None
    return Path(*parts)


def import_archive(source, name=None, strip_root=False, target=None):
    """Extract the Sigma rules (.yml/.yaml) of a zip archive into the rule store.

    Only rule files and license texts are written, never outside the target
    folder. Returns {'target', 'rules', 'skipped', 'sha256'}."""
    data = source if isinstance(source, bytes) else Path(source).read_bytes()
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError(f'archive larger than {MAX_ARCHIVE_BYTES} bytes')
    digest = hashlib.sha256(data).hexdigest()
    if target is None:
        label = re.sub(r'[^A-Za-z0-9._-]+', '_', name or Path(str(source)).stem)[:80] or 'rules'
        target = store_dir() / 'imported' / label
    target = Path(target)
    written, skipped = 0, 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = archive.infolist()
        if len(members) > MAX_ARCHIVE_FILES:
            raise ValueError(f'archive has more than {MAX_ARCHIVE_FILES} entries')
        for info in members:
            if info.is_dir():
                continue
            rel = _safe_member(info.filename)
            if rel is None:
                skipped += 1
                continue
            if strip_root and len(rel.parts) > 1:
                rel = Path(*rel.parts[1:])
            low = rel.name.lower()
            keep_rule = low.endswith(RULE_SUFFIXES) and info.file_size <= MAX_RULE_BYTES
            keep_text = low in ('license', 'license.md', 'license.txt', 'readme.md') and len(rel.parts) == 1
            if not (keep_rule or keep_text):
                skipped += 1
                continue
            dest = target / rel
            if os.path.commonpath([str(dest.resolve()), str(target.resolve())]) != str(target.resolve()):
                skipped += 1
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(archive.read(info))
            written += keep_rule
    return {'target': str(target), 'rules': written, 'skipped': skipped, 'sha256': digest}


def sync(url=SIGMAHQ_URL, timeout=120, expected_sha256=None):
    """Download the pinned SigmaHQ release into the rule store (explicit command only).

    Only the rule archive is downloaded: nothing about the cases is sent. When
    ``expected_sha256`` (or ``PHOENIX_SIGMAHQ_SHA256``) is set, an archive with
    another digest is refused before anything is written."""
    import json
    import requests
    expected = (expected_sha256 or os.environ.get('PHOENIX_SIGMAHQ_SHA256', '')).strip().lower()
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    digest = hashlib.sha256(resp.content).hexdigest()
    if expected and digest != expected:
        raise ValueError(f'SigmaHQ archive digest {digest} does not match the expected {expected}')
    target = store_dir() / SIGMAHQ_TAG
    result = import_archive(resp.content, strip_root=True, target=target)
    result.update(tag=SIGMAHQ_TAG, url=url)
    (target / 'SOURCE.json').write_text(json.dumps(
        {'tag': SIGMAHQ_TAG, 'url': url, 'sha256': digest, 'rules': result['rules']}, indent=2) + '\n',
        encoding='utf-8')
    return result


# ----------------------------------------------------------------------------
# Rule loading
# ----------------------------------------------------------------------------

def _rule_files(dirs):
    for d in dirs:
        for path in sorted(Path(d).rglob('*')):
            if path.suffix.lower() in RULE_SUFFIXES and path.is_file():
                yield path


def _compile(path):
    """pySigma rule converted to SQL, with its metadata. None if not usable."""
    from sigma.backends.sqlite import sqliteBackend
    from sigma.collection import SigmaCollection
    from sigma.rule import SigmaRule
    stat = path.stat()
    key = (os.path.normcase(str(path)), stat.st_mtime_ns, stat.st_size)
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    compiled = None
    try:
        if stat.st_size <= MAX_RULE_BYTES:
            collection = SigmaCollection.from_yaml(path.read_text(encoding='utf-8'))
            rules = [r for r in collection.rules if isinstance(r, SigmaRule)]
            if len(rules) == 1:
                rule = rules[0]
                status = str(getattr(rule.status, 'name', rule.status or '')).lower()
                if status not in SKIPPED_STATUS:
                    queries = sqliteBackend().convert(SigmaCollection([rule]))
                    if len(queries) == 1:
                        compiled = _metadata(rule, path, queries[0])
    except Exception as e:  # invalid or unsupported rule: skipped, counted
        compiled = {'error': f'{type(e).__name__}: {str(e)[:200]}', 'path': str(path)}
    with _cache_lock:
        _cache[key] = compiled
    return compiled


def _metadata(rule, path, query):
    tags = [f'{t.namespace}.{t.name}' for t in rule.tags or []]
    techniques = sorted({m.group(1).upper() for t in tags for m in [_TECHNIQUE_TAG.match(t)] if m})
    tactics = sorted({m.group(1).replace('-', '_') for t in tags for m in [_TACTIC_TAG.match(t)] if m})
    level = str(getattr(rule.level, 'name', rule.level or 'medium')).lower()
    custom = getattr(rule, 'custom_attributes', None) or {}
    threshold = custom.get('phoenix_threshold')
    return {
        'id': str(rule.id) if rule.id else path.stem,
        'title': rule.title,
        'author': str(rule.author or '').strip() or None,
        'url': _rule_url(path),
        'description': (rule.description or '').strip(),
        'level': level,
        'techniques': techniques,
        'tactics': tactics,
        'logsource': {'product': rule.logsource.product, 'category': rule.logsource.category,
                      'service': rule.logsource.service},
        'threshold': int(threshold) if isinstance(threshold, int) and threshold > 1 else None,
        'phoenix_id': custom.get('phoenix_id'),
        'query': query,
        'path': str(path),
    }


def _rule_url(path):
    """Link to a SigmaHQ rule (bundled or synced), None for other rules."""
    roots = [BUNDLED_DIR]
    try:
        roots.append(store_dir() / SIGMAHQ_TAG)
    except Exception:  # nosec B110 - no data dir: bundled rules only
        pass
    for root in roots:
        try:
            rel = Path(path).resolve().relative_to(Path(root).resolve())
        except ValueError:
            continue
        return SIGMAHQ_BLOB + rel.as_posix()
    return None


def load_rules(extra_dirs=()):
    """Usable rules of every rule folder. Returns (rules, errors)."""
    if not available():
        return [], []
    rules, errors, seen = [], [], set()
    for path in _rule_files(rule_dirs(extra_dirs)):
        compiled = _compile(path)
        if not compiled:
            continue
        if 'error' in compiled:
            errors.append(compiled)
            continue
        if compiled['id'] in seen:  # the same rule synced and bundled: first folder wins
            continue
        seen.add(compiled['id'])
        rules.append(compiled)
    return rules, errors


# ----------------------------------------------------------------------------
# Matching
# ----------------------------------------------------------------------------

def flatten(event):
    """One Windows event as a flat dict of Sigma field names (case insensitive keys)."""
    out = {}

    def put(key, value):
        if value is None or isinstance(value, (dict, list)) or str(key).startswith('_'):
            return
        low = str(key).lower()
        if low not in out:
            out[low] = (str(key), value)

    data = event.get('data') if isinstance(event.get('data'), dict) else {}
    for k, v in data.items():
        put(k, v)
    put('EventID', event.get('event_id'))
    put('Channel', event.get('channel'))
    put('Provider_Name', event.get('provider'))
    put('Computer', event.get('computer'))
    for target, sources in FIELD_ALIASES:
        if target.lower() in out:
            continue
        for src in sources:
            hit = out.get(src.lower())
            if hit and hit[1] not in ('', None):
                out[target.lower()] = (target, hit[1])
                break
    return {name: value for name, value in out.values()}


def _logsource_matches(logsource, fields):
    product = (logsource.get('product') or '').lower()
    if product and product != 'windows':
        return False
    channel = str(fields.get('Channel') or '').lower()
    event_id = str(fields.get('EventID') or '')
    service = (logsource.get('service') or '').lower()
    category = (logsource.get('category') or '').lower()
    if service:
        channels = SERVICE_CHANNELS.get(service)
        if channels is None or channel not in {c.lower() for c in channels}:
            return False
    if category:
        pairs = CATEGORY_EVENTS.get(category)
        if pairs is None or not any(channel == c.lower() and event_id == str(i) for c, i in pairs):
            return False
    return True


def supported_logsource(logsource):
    product = (logsource.get('product') or '').lower()
    service = (logsource.get('service') or '').lower()
    category = (logsource.get('category') or '').lower()
    return (product in ('', 'windows') and (not service or service in SERVICE_CHANNELS)
            and (not category or category in CATEGORY_EVENTS) and bool(product or service or category))


def _regexp(pattern, value):
    if value is None:
        return False
    try:
        import re2 as engine  # linear time: rules may come from anywhere
    except ImportError:  # pragma: no cover - google-re2 is a pySigma dependency
        engine = re
    try:
        return engine.search(pattern, str(value)) is not None
    except Exception:
        return False


_ALLOWED_ACTIONS = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}



def _quote(name):
    return '"' + str(name).replace('"', '""') + '"'


class _EventTable:
    """In-memory SQLite table of the events (read only while rules run)."""

    def __init__(self, events):
        self.conn = sqlite3.connect(':memory:')
        self.conn.create_function('regexp', 2, _regexp, deterministic=True)
        self.rows = [flatten(e) for e in events]
        self.columns = {}
        for row in self.rows:
            for k in row:
                self.columns.setdefault(k.lower(), k)
        cols = ', '.join(f'{_quote(c)} TEXT COLLATE NOCASE' for c in self.columns.values())
        self.conn.execute(f'CREATE TABLE logs (_idx INTEGER PRIMARY KEY{", " + cols if cols else ""})')
        for idx, row in enumerate(self.rows):
            names = ['_idx'] + [self.columns[k.lower()] for k in row]
            marks = ', '.join('?' * len(names))
            # Column names are quoted identifiers, every value is a bound parameter
            sql = f'INSERT INTO logs ({", ".join(_quote(n) for n in names)}) VALUES ({marks})'  # nosec B608
            self.conn.execute(sql, [idx] + [str(v) for v in row.values()])
        # One authorizer for the table's life (set_authorizer(None) needs Python 3.11):
        # only the engine itself may lift it, to add a missing column
        self._writable = False
        self.conn.set_authorizer(self._authorize)

    def _authorize(self, action, *_args):
        if self._writable or action in _ALLOWED_ACTIONS:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY

    def _add_column(self, name):
        self._writable = True
        try:
            self.conn.execute(f'ALTER TABLE logs ADD COLUMN {_quote(name)} TEXT COLLATE NOCASE')
            self.columns[name.lower()] = name
        finally:
            self._writable = False

    def match(self, query):
        """Indexes of the events the rule query selects."""
        sql = re.sub(r'^\s*SELECT \* FROM logs', 'SELECT _idx FROM logs', query, count=1)
        for _attempt in range(64):
            try:
                return [r[0] for r in self.conn.execute(sql).fetchall()]
            except sqlite3.OperationalError as e:
                missing = _MISSING_COLUMN.search(str(e))
                if not missing or missing.group(1).lower() in self.columns:
                    raise
                self._add_column(missing.group(1))  # field absent from every event: NULL
        raise sqlite3.OperationalError('too many missing columns')

    def close(self):
        self.conn.close()


def scan(events, extra_dirs=(), rules=None):
    """Run the Sigma rules on Windows events.

    ``events``: dicts with ``event_id``, ``record_id``, ``row``, ``timestamp``,
    ``channel``, ``provider`` and ``data`` (EventData or export fields)."""
    if not available():
        return {'engine': 'pysigma', 'available': False, 'alerts': [],
                'detail': status()['detail']}
    if rules is None:
        rules, errors = load_rules(extra_dirs)
    else:
        errors = []
    alerts, skipped, failed = [], 0, []
    table = _EventTable(events)
    try:
        for rule in rules:
            if not supported_logsource(rule['logsource']):
                skipped += 1
                continue
            try:
                hits = table.match(rule['query'])
            except sqlite3.Error as e:
                failed.append({'rule': rule['id'], 'error': str(e)[:200]})
                continue
            hits = [i for i in sorted(hits) if _logsource_matches(rule['logsource'], table.rows[i])]
            if rule['threshold']:
                hits = hits[rule['threshold'] - 1:]
            for i in hits:
                evt = events[i]
                alerts.append({
                    'rule_id': rule['phoenix_id'] or rule['id'],
                    'rule_title': rule['title'],
                    'description': rule['description'][:300],
                    'level': rule['level'],
                    'tactic': rule['tactics'][0] if rule['tactics'] else None,
                    'technique': rule['techniques'][0] if rule['techniques'] else None,
                    'techniques': rule['techniques'],
                    'tactics': rule['tactics'],
                    'engine': 'pysigma',
                    'rule_file': Path(rule['path']).name,
                    'rule_author': rule['author'],
                    'rule_url': rule['url'],
                    'event_id': evt.get('event_id'),
                    'record_id': evt.get('record_id'),
                    'timestamp': evt.get('timestamp'),
                    **({'row': evt['row']} if evt.get('row') is not None else {}),
                })
    finally:
        table.close()
    alerts.sort(key=lambda a: (str(a.get('timestamp') or ''), str(a.get('record_id') or ''), a['rule_id']))
    return {'engine': 'pysigma', 'available': True, 'alerts': alerts, 'rules_loaded': len(rules),
            'rules_skipped_logsource': skipped, 'rules_invalid': len(errors), 'rules_failed': failed[:20]}


# ----------------------------------------------------------------------------
# Built in Phoenix rules as Sigma YAML
# ----------------------------------------------------------------------------

_NAMESPACE = uuid.UUID('6f1c3e2a-58b4-4c1e-9d2f-7a0b8c4d5e61')
_CONTAINS = {
    'image_contains': ('Image',),
    'command_line_contains': ('CommandLine',),
    'target_object_contains': ('TargetObject',),
    'service_name_contains': ('ServiceName',),
    'object_name_contains': ('ObjectName',),
    'target_image_contains': ('TargetImage',),
    'properties_contains': ('Properties', 'AccessList', 'ObjectType', 'Message'),
}
_EQUALS = {'logon_type': 'LogonType', 'ticket_encryption': 'TicketEncryptionType'}


def _yaml_scalar(value):
    if isinstance(value, int):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def _yaml_values(values, indent):
    values = values if isinstance(values, (list, tuple)) else [values]
    if len(values) == 1:
        return ' ' + _yaml_scalar(values[0])
    return ''.join(f'\n{indent}- {_yaml_scalar(v)}' for v in values)


def builtin_to_sigma(rule):
    """Sigma YAML text of one built in Phoenix rule (same detection logic)."""
    det = rule['detection']
    lines = [f"title: {_yaml_scalar(rule['title'])}",
             f"id: {uuid.uuid5(_NAMESPACE, rule['id'])}",
             'status: experimental',
             f"description: {_yaml_scalar(rule['description'])}",
             'author: Phoenix DFIR',
             'tags:']
    lines.append(f"    - attack.{rule['tactic'].replace('_', '-')}")
    lines.append(f"    - attack.{rule['technique'].lower()}")
    lines += ['logsource:', '    product: windows', 'detection:', '    selection:',
              f"        EventID:{_yaml_values(det['event_id'], '            ')}"]
    for key, field in _EQUALS.items():
        if key in det:
            lines.append(f'        {field}:{_yaml_values(det[key], "            ")}')
    groups = []
    for key, fields in _CONTAINS.items():
        if key not in det:
            continue
        if len(fields) == 1:
            lines.append(f'        {fields[0]}|contains:{_yaml_values(det[key], "            ")}')
        else:
            groups.append((key, fields))
    condition = 'selection'
    for key, fields in groups:
        for field in fields:
            lines += [f'    {key}_{field.lower()}:',
                      f'        {field}|contains:{_yaml_values(det[key], "            ")}']
        condition += f' and 1 of {key}_*'
    filters = []
    if det.get('service_name_not_endswith'):
        filters.append(('filter_service_suffix', 'ServiceName|endswith', det['service_name_not_endswith']))
    if det.get('service_name_not_in'):
        filters.append(('filter_service_name', 'ServiceName', list(det['service_name_not_in'])))
    if det.get('subject_user_not_endswith'):
        filters.append(('filter_subject_suffix', 'SubjectUserName|endswith', det['subject_user_not_endswith']))
    for name, field, values in filters:
        lines += [f'    {name}:', f'        {field}:{_yaml_values(values, "            ")}']
    if filters:
        condition += ' and not 1 of filter_*'
    lines.append(f'    condition: {condition}')
    lines.append(f"level: {rule['level']}")
    lines.append(f"phoenix_id: {rule['id']}")
    if det.get('threshold'):
        lines.append(f"phoenix_threshold: {int(det['threshold'])}")
    return '\n'.join(lines) + '\n'


def builtin_rules():
    from . import _paths
    _paths.ensure_backend_importable()
    from integrations.sigma_connector import SigmaConnector
    return SigmaConnector.BUILTIN_RULES


def export_builtin(target=BUILTIN_DIR):
    """Write the built in rules as Sigma YAML files. Returns the written paths."""
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)
    paths = []
    for rule in builtin_rules():
        path = target / f"{rule['id'].replace('-', '_')}.yml"
        path.write_text(builtin_to_sigma(rule), encoding='utf-8', newline='\n')
        paths.append(path)
    return paths
