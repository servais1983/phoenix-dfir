"""macOS : detection des artefacts par le contenu et parsers des journaux et bases.

Types reconnus (l'extension ne suffit jamais : TCC.db, la base de quarantaine
et les fichiers FSEvents n'ont pas d'extension fiable) :

    unifiedlog_ndjson  export `log show --style ndjson` (une ligne JSON par entree)
    unifiedlog_json    export `log show --style json` (tableau JSON)
    unifiedlog_text    sortie texte de `log show` (styles default, syslog, compact)
    tracev3            journal unifie natif (format binaire proprietaire : NON
                       decode, il faut un export `log show` produit sur un Mac)
    logarchive         dossier .logarchive (seuls les exports texte / JSON qu'il
                       contient sont exploitables)
    tcc                base TCC.db (autorisations de confidentialite)
    quarantine         base com.apple.LaunchServices.QuarantineEventsV2
    knowledgec         base KnowledgeC.db (usage des applications)
    launchd_plist      LaunchAgent / LaunchDaemon (plist binaire ou XML)
    emond_rules        regles emond (/etc/emond.d/rules/*.plist)
    loginwindow_plist  com.apple.loginwindow.plist (LoginHook / LogoutHook)
    crontab            table cron (/usr/lib/cron/tabs/<user>, /etc/crontab)
    periodic           script periodic (/etc/periodic/daily|weekly|monthly)
    btm                BackgroundItems*.btm / backgrounditems.btm (binaire : non decode)
    fsevents           fichier .fseventsd (pages gzip 1SLD / 2SLD / 3SLD)

References citables :
- 'line' : ligne physique (export ndjson, sortie texte, crontab, script) ;
- 'row'  : rowid SQLite (TCC, quarantaine, KnowledgeC), rang dans un tableau
           JSON, rang d'un enregistrement FSEvents, regle emond, ou 1 pour un
           plist launchd (un seul element par fichier).
"""

import datetime
import gzip
import json
import os
import plistlib
import re
import sqlite3
from urllib.parse import quote, urlsplit

from .. import toolkit
from . import _cloud_formats as cformats

DEFAULT_MAX_EVENTS = 50000
MAX_ROWS = 200000
_SNIFF = 64 * 1024
MAC_EPOCH = 978307200  # 2001-01-01T00:00:00Z (Cocoa / Mac absolute time)

TYPES = {
    'unifiedlog_ndjson': 'Journal unifie macOS (export log show ndjson)',
    'unifiedlog_json': 'Journal unifie macOS (export log show json)',
    'unifiedlog_text': 'Journal unifie macOS (sortie texte log show)',
    'tracev3': 'Journal unifie macOS natif .tracev3 (non decode)',
    'logarchive': 'Archive .logarchive macOS',
    'tcc': 'Base TCC.db macOS (autorisations de confidentialite)',
    'quarantine': 'Base QuarantineEventsV2 macOS (telechargements)',
    'knowledgec': 'Base KnowledgeC.db macOS (usage des applications)',
    'launchd_plist': 'LaunchAgent / LaunchDaemon macOS (plist)',
    'emond_rules': 'Regles emond macOS (plist)',
    'loginwindow_plist': 'Preferences loginwindow macOS (LoginHook)',
    'crontab': 'Table cron',
    'periodic': 'Script periodic macOS',
    'btm': 'Base BackgroundTaskManagement macOS (.btm, non decodee)',
    'fsevents': 'Journal FSEvents macOS (.fseventsd)',
}
UNIFIED_TYPES = ('unifiedlog_ndjson', 'unifiedlog_json', 'unifiedlog_text')
PERSISTENCE_TYPES = ('launchd_plist', 'emond_rules', 'loginwindow_plist', 'crontab', 'periodic', 'btm')
SQLITE_TYPES = ('tcc', 'quarantine', 'knowledgec')


# ============================================================================
# Utilitaires
# ============================================================================

def utc(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ') if dt else None


def from_unix(value):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if v <= 0 or v > 32503680000:
        return None
    return utc(datetime.datetime.fromtimestamp(v, datetime.timezone.utc))


def from_mac(value):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return from_unix(v + MAC_EPOCH) if v > 0 else None


_TS_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(\.\d+)?\s*(Z|[+-]\d{2}:?\d{2})?')


def parse_log_ts(text):
    """'2026-10-14 09:12:03.123456+0200' -> ('2026-10-14T07:12:03Z', tz_connu)."""
    m = _TS_RE.match(str(text or '').strip())
    if not m:
        return None, False
    y, mo, d, hh, mm, ss = (int(m.group(i)) for i in range(1, 7))
    try:
        dt = datetime.datetime(y, mo, d, hh, mm, ss)
    except ValueError:
        return None, False
    tz = m.group(8)
    if tz and tz != 'Z':
        sign = -1 if tz[0] == '-' else 1
        digits = tz[1:].replace(':', '')
        dt -= sign * datetime.timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
    return utc(dt), bool(tz)


def url_host(url):
    try:
        return (urlsplit(str(url or '')).hostname or '').lower() or None
    except ValueError:
        return None


def _head(path, size=_SNIFF):
    with open(path, 'rb') as f:
        return f.read(size)


def _text_head(path, size=_SNIFF):
    raw = _head(path, size)
    if raw[:2] == b'\x1f\x8b':
        try:
            with gzip.open(path, 'rb') as f:
                raw = f.read(size)
        except (OSError, EOFError):
            return ''
    return raw.decode('utf-8', errors='replace').lstrip('\ufeff')


def open_ro(path):
    """Connexion SQLite en LECTURE SEULE sur la preuve (aucun -wal / -shm cree)."""
    uri = 'file:' + quote(os.path.abspath(path)) + '?mode=ro&immutable=1'
    return sqlite3.connect(uri, uri=True)


def sqlite_tables(path):
    conn = open_ro(path)
    try:
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


def _columns(conn, table):
    # Noms de tables constants (jamais issus de l'artefact)
    query = {'access': 'PRAGMA table_info(access)',
             'LSQuarantineEvent': 'PRAGMA table_info(LSQuarantineEvent)',
             'ZOBJECT': 'PRAGMA table_info(ZOBJECT)'}[table]
    return {r[1] for r in conn.execute(query)}


def wal_note(path):
    if os.path.exists(path + '-wal'):
        return ("Fichier -wal present a cote de la base : les transactions recentes qu'il contient "
                "ne sont pas fusionnees (lecture seule de la base principale).")
    return None


def load_plist(path):
    with open(path, 'rb') as f:
        data = f.read(8 << 20)
    fmt = 'binary' if data.startswith(b'bplist00') else 'xml'
    return plistlib.loads(data), fmt


# ============================================================================
# Detection du type d'artefact
# ============================================================================

FSEVENTS_MAGICS = (b'1SLD', b'2SLD', b'3SLD')

_UL_DEFAULT_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3,6}[+-]\d{4}\s+0x[0-9a-fA-F]+\s+[A-Za-z]+\s+'
    r'0x[0-9a-fA-F]+\s+\d+\s+\d+\s+')
_UL_SYSLOG_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3,6}[+-]\d{4}\s+\S+\s+[^\[\s][^\[]*\[\d+\]:\s')
_UL_COMPACT_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}\s+[A-Z][a-z ]\s+[^\[]+\[\d+:[0-9a-fA-F]+\]\s')
_UL_KEYS = ('eventMessage', 'processImagePath')
_CRON_RE = re.compile(r'^\s*(@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|'
                      r'([\d*/,-]+\s+){4}[\d*/,a-zA-Z-]+)\s+\S')


def _norm(path):
    return str(path).replace('\\', '/')


def _is_unified_record(obj):
    return isinstance(obj, dict) and all(k in obj for k in _UL_KEYS)


def _sniff_unified(path):
    text = _text_head(path)
    stripped = text.lstrip()
    if not stripped:
        return None
    if stripped.startswith('{'):
        first = stripped.splitlines()[0]
        try:
            if _is_unified_record(json.loads(first)):
                return 'unifiedlog_ndjson'
        except ValueError:
            pass
    if stripped.startswith('[') and all(f'"{k}"' in stripped for k in _UL_KEYS):
        return 'unifiedlog_json'
    lines = [ln for ln in text.splitlines()[:40] if ln.strip()]
    hits = sum(1 for ln in lines if _UL_DEFAULT_RE.match(ln) or _UL_SYSLOG_RE.match(ln)
               or _UL_COMPACT_RE.match(ln))
    if hits >= 2 or (hits == 1 and len(lines) <= 2):
        return 'unifiedlog_text'
    return None


def _classify_plist(obj):
    if isinstance(obj, dict):
        if obj.get('Label') and (obj.get('ProgramArguments') or obj.get('Program')):
            return 'launchd_plist'
        if 'LoginHook' in obj or 'LogoutHook' in obj:
            return 'loginwindow_plist'
    if isinstance(obj, list) and obj and all(isinstance(r, dict) for r in obj) \
            and any('eventTypes' in r or 'criterion' in r for r in obj) \
            and any('actions' in r for r in obj):
        return 'emond_rules'
    return None


def _fsevents_magic(path, head):
    if head[:4] in FSEVENTS_MAGICS:
        return True
    if head[:2] == b'\x1f\x8b':
        try:
            with gzip.open(path, 'rb') as f:
                return f.read(4) in FSEVENTS_MAGICS
        except (OSError, EOFError):
            return False
    return False


def detect(path):
    """{'type', 'label', 'reason'} d'apres le contenu (type None si non concerne)."""
    out = {'type': None, 'label': None, 'reason': 'contenu non reconnu comme artefact macOS'}
    norm = _norm(path)
    low = norm.lower()
    name = os.path.basename(low)
    if os.path.isdir(path):
        if low.rstrip('/').endswith('.logarchive'):
            out.update(type='logarchive', reason='dossier .logarchive')
        return _label(out)
    if name.endswith('.tracev3'):
        out.update(type='tracev3', reason='extension .tracev3 (format binaire proprietaire)')
        return _label(out)
    if name.endswith('.btm'):
        out.update(type='btm', reason='base BackgroundTaskManagement (.btm)')
        return _label(out)
    try:
        head = _head(path, 4096)
    except OSError as exc:
        out['reason'] = f'lecture impossible : {exc}'
        return out
    if head.startswith(b'SQLite format 3\x00'):
        try:
            tables = sqlite_tables(path)
        except sqlite3.Error as exc:
            out['reason'] = f'base SQLite illisible : {exc}'
            return out
        if 'access' in tables:
            out.update(type='tcc', reason="table 'access' (TCC)")
        elif 'LSQuarantineEvent' in tables:
            out.update(type='quarantine', reason="table 'LSQuarantineEvent'")
        elif 'ZOBJECT' in tables and ('ZSTRUCTUREDMETADATA' in tables or 'ZSOURCE' in tables):
            out.update(type='knowledgec', reason="tables 'ZOBJECT' / 'ZSTRUCTUREDMETADATA' (KnowledgeC)")
        return _label(out)
    if _fsevents_magic(path, head):
        out.update(type='fsevents', reason='signature de page FSEvents (1SLD / 2SLD / 3SLD)')
        return _label(out)
    if head.startswith(b'bplist00') or (b'<plist' in head[:1024] and b'<?xml' in head[:200]):
        try:
            obj, _fmt = load_plist(path)
        except Exception as exc:  # plist corrompu : non concerne
            out['reason'] = f'plist illisible : {type(exc).__name__}'
            return out
        kind = _classify_plist(obj)
        if kind:
            out.update(type=kind, reason='cles du plist : ' + {
                'launchd_plist': 'Label + ProgramArguments / Program',
                'loginwindow_plist': 'LoginHook / LogoutHook',
                'emond_rules': 'regles eventTypes / actions'}[kind])
        return _label(out)
    if b'\x00' in head[:4096] and head[:2] != b'\x1f\x8b':
        return out
    kind = _sniff_unified(path)
    if kind:
        out.update(type=kind, reason='structure d\'un export log show')
        return _label(out)
    text = head.decode('utf-8', errors='replace')
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith('#')]
    if '/periodic/' in low and lines:
        out.update(type='periodic', reason='script dans un dossier periodic')
        return _label(out)
    cron_hint = (name in ('crontab', 'root') and 'cron' in low) or '/cron/' in low or '/tabs/' in low \
        or 'crontab' in name
    if cron_hint and lines and sum(1 for ln in lines if _CRON_RE.match(ln) or
                                   re.match(r'^\s*[A-Z_]+=', ln)) >= max(1, len(lines) // 2):
        out.update(type='crontab', reason='syntaxe cron dans un fichier de table cron')
    return _label(out)


def _label(out):
    if out['type']:
        out['label'] = TYPES[out['type']]
    return out


def logarchive_exports(path, limit=200):
    """Exports texte / JSON exploitables dans un dossier .logarchive."""
    found, natives = [], 0
    for root, _dirs, files in os.walk(path):
        for fname in sorted(files):
            full = os.path.join(root, fname)
            if fname.endswith('.tracev3'):
                natives += 1
                continue
            if len(found) < limit and os.path.getsize(full) > 0:
                try:
                    kind = _sniff_unified(full)
                except OSError:
                    kind = None
                if kind:
                    found.append({'path': full, 'type': kind})
    return found, natives


# ============================================================================
# Journal unifie : exports log show
# ============================================================================

_UL_BODY_RE = re.compile(r'^(?P<proc>[^:\[]+?)(?:\[(?P<pid>\d+)(?::[0-9a-fA-F]+)?\])?:\s(?P<rest>.*)$')
_UL_DEFAULT_FULL = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})\s+(?P<thread>0x[0-9a-fA-F]+)\s+'
    r'(?P<type>[A-Za-z]+)\s+(?P<activity>0x[0-9a-fA-F]+)\s+(?P<pid>\d+)\s+(?P<ttl>\d+)\s+(?P<body>.*)$')
_UL_SYSLOG_FULL = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[+-]\d{4})\s+(?P<host>\S+)\s+'
    r'(?P<proc>[^\[\s][^\[]*?)\[(?P<pid>\d+)\]:\s(?P<rest>.*)$')
_UL_COMPACT_FULL = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(?P<type>[A-Z][a-z ])\s+'
    r'(?P<proc>[^\[]+?)\[(?P<pid>\d+):(?P<thread>[0-9a-fA-F]+)\]\s(?P<rest>.*)$')
_SENDER_RE = re.compile(r'^\((?P<sender>[^)]*)\)\s?(?P<rest>.*)$')
_SUBSYS_RE = re.compile(r'^\[(?P<sub>[^\]:\s]+):(?P<cat>[^\]]*)\]\s?(?P<rest>.*)$')
_COMPACT_TYPES = {'Df': 'Default', 'I ': 'Info', 'Db': 'Debug', 'E ': 'Error', 'F ': 'Fault',
                  'A ': 'Activity', 'Er': 'Error', 'Fa': 'Fault'}


def _split_body(rest):
    sender = subsystem = category = None
    m = _SENDER_RE.match(rest)
    if m:
        sender, rest = m.group('sender') or None, m.group('rest')
    m = _SUBSYS_RE.match(rest)
    if m:
        subsystem, category, rest = m.group('sub'), m.group('cat') or None, m.group('rest')
    return sender, subsystem, category, rest


def _event(ref, ts, process=None, process_path=None, pid=None, subsystem=None, category=None,
           message=None, sender=None, user_id=None, event_type=None, message_type=None, host=None,
           thread=None):
    pid_text = str(pid) if pid not in (None, '') else None
    if pid_text and not pid_text.isdigit():
        pid_text = None
    uid = None if user_id in (None, '') else str(user_id)
    proc = process or (os.path.basename(process_path) if process_path else None)
    ev = {
        ref[0]: ref[1],
        '_ref': ref,
        'timestamp': ts,
        'source': 'macos_unifiedlog',
        'host': host,
        'process': proc,
        'process_path': process_path,
        'pid': int(pid_text) if pid_text else None,
        'user_id': uid,
        'user': ('root' if uid == '0' else f'uid:{uid}') if uid is not None else None,
        'subsystem': subsystem,
        'category': category,
        'sender_image': sender,
        'event_type': event_type,
        'message_type': message_type,
        'thread': thread,
        'message': (message or '')[:4000] or None,
    }
    ev = {k: v for k, v in ev.items() if v not in (None, '')}
    ev['event'] = ' '.join(str(x) for x in (proc, f'[{subsystem}:{category}]' if subsystem else None,
                                            (message or '')[:300]) if x)
    return ev


def _ndjson_event(ref, rec):
    ts, _tz = parse_log_ts(rec.get('timestamp'))
    sender = rec.get('senderImagePath')
    return _event(ref, ts, process_path=rec.get('processImagePath'), pid=rec.get('processID'),
                  subsystem=rec.get('subsystem'), category=rec.get('category'),
                  message=rec.get('eventMessage') or rec.get('formatString'),
                  sender=os.path.basename(sender) if sender else None, user_id=rec.get('userID'),
                  event_type=rec.get('eventType'), message_type=rec.get('messageType'),
                  thread=rec.get('threadID'))


def _text_event(no, line):
    m = _UL_DEFAULT_FULL.match(line)
    if m:
        ts, _tz = parse_log_ts(m.group('ts'))
        body = _UL_BODY_RE.match(m.group('body'))
        proc, rest = (body.group('proc').strip(), body.group('rest')) if body else (None, m.group('body'))
        sender, sub, cat, msg = _split_body(rest)
        return _event(('line', no), ts, process=proc, pid=m.group('pid'), subsystem=sub, category=cat,
                      message=msg, sender=sender, message_type=m.group('type'), thread=m.group('thread'))
    m = _UL_SYSLOG_FULL.match(line)
    if m:
        ts, _tz = parse_log_ts(m.group('ts'))
        sender, sub, cat, msg = _split_body(m.group('rest'))
        return _event(('line', no), ts, process=m.group('proc').strip(), pid=m.group('pid'), subsystem=sub,
                      category=cat, message=msg, sender=sender, host=m.group('host'))
    m = _UL_COMPACT_FULL.match(line)
    if m:
        ts, _tz = parse_log_ts(m.group('ts'))  # style compact : heure locale sans fuseau
        sender, sub, cat, msg = _split_body(m.group('rest'))
        return _event(('line', no), ts, process=m.group('proc').strip(), pid=m.group('pid'), subsystem=sub,
                      category=cat, message=msg, sender=sender,
                      message_type=_COMPACT_TYPES.get(m.group('type'), m.group('type').strip()),
                      thread=m.group('thread'))
    return None


def load_unified(path, kind, max_events=DEFAULT_MAX_EVENTS):
    """Evenements normalises d'un export log show, et statistiques."""
    stats = {'skipped': 0, 'truncated': False, 'notes': []}
    events = []
    if kind == 'unifiedlog_json':
        limit = toolkit._max_json_bytes()
        with cformats._open_text(path) as f:
            text = f.read(limit + 1)
        if len(text) > limit:
            raise ValueError(f'export JSON trop volumineux (> {limit} octets) : '
                             'exporter avec --style ndjson pour une lecture en flux')
        doc = json.loads(text)
        records = doc if isinstance(doc, list) else []
        for i, rec in enumerate(records, 1):
            if len(events) >= max_events:
                stats['truncated'] = True
                break
            if _is_unified_record(rec):
                events.append(_ndjson_event(('row', i), rec))
            else:
                stats['skipped'] += 1
        return events, stats
    with cformats._open_text(path) as f:
        for no, line in enumerate(f, 1):
            line = line.rstrip('\r\n')
            if not line.strip():
                continue
            if len(events) >= max_events:
                stats['truncated'] = True
                break
            if kind == 'unifiedlog_ndjson':
                try:
                    rec = json.loads(line)
                except ValueError:
                    stats['skipped'] += 1
                    continue
                if _is_unified_record(rec):
                    events.append(_ndjson_event(('line', no), rec))
                else:
                    stats['skipped'] += 1
                continue
            ev = _text_event(no, line)
            if ev:
                events.append(ev)
            elif events and not line.startswith(('Timestamp ', 'Filtering the log data', '---')):
                # Message multi-ligne : rattache a l'entree precedente (ref = sa premiere ligne)
                prev = events[-1]
                prev['message'] = (prev.get('message', '') + '\n' + line)[:4000]
            else:
                stats['skipped'] += 1
    if kind == 'unifiedlog_text' and _has_compact(path):
        stats['notes'].append('Style compact : horodatages en heure locale sans fuseau, interpretes comme UTC.')
    return events, stats


def _has_compact(path):
    return any(_UL_COMPACT_FULL.match(ln) for ln in _text_head(path, 8192).splitlines()[:20])


# ============================================================================
# Bases SQLite : TCC, quarantaine, KnowledgeC
# ============================================================================

TCC_AUTH_VALUES = {0: 'denied', 1: 'unknown', 2: 'allowed', 3: 'limited'}
TCC_AUTH_REASONS = {
    0: 'inherited / unknown', 1: 'error', 2: 'user consent', 3: 'user set', 4: 'system set',
    5: 'service policy', 6: 'MDM policy', 7: 'override policy', 8: 'missing usage string',
    9: 'prompt timeout', 10: 'preflight unknown', 11: 'entitled', 12: 'app type policy',
}
TCC_SERVICES = {
    'kTCCServiceSystemPolicyAllFiles': 'Full Disk Access',
    'kTCCServiceScreenCapture': 'Screen Recording',
    'kTCCServiceAccessibility': 'Accessibility',
    'kTCCServiceListenEvent': 'Input Monitoring',
    'kTCCServicePostEvent': 'Synthetic input (PostEvent)',
    'kTCCServiceMicrophone': 'Microphone',
    'kTCCServiceCamera': 'Camera',
    'kTCCServiceAppleEvents': 'Automation (AppleEvents)',
    'kTCCServiceSystemPolicySysAdminFiles': 'Administration files',
    'kTCCServiceSystemPolicyDocumentsFolder': 'Documents folder',
    'kTCCServiceSystemPolicyDesktopFolder': 'Desktop folder',
    'kTCCServiceSystemPolicyDownloadsFolder': 'Downloads folder',
    'kTCCServiceEndpointSecurityClient': 'Endpoint Security client',
    'kTCCServiceDeveloperTool': 'Developer tool',
    'kTCCServiceAddressBook': 'Contacts',
    'kTCCServicePhotos': 'Photos',
    'kTCCServiceCalendar': 'Calendar',
}


def load_tcc(path, max_rows=MAX_ROWS):
    conn = open_ro(path)
    try:
        cols = _columns(conn, 'access')
        has_auth = 'auth_value' in cols
        # Requetes constantes selon le schema (Big Sur et suivants : auth_value ; avant : allowed)
        if has_auth:
            query = ('SELECT rowid, service, client, client_type, auth_value, auth_reason, csreq, '
                     'indirect_object_identifier, last_modified FROM access ORDER BY rowid LIMIT ?')
        else:
            query = ('SELECT rowid, service, client, client_type, allowed, NULL, csreq, '
                     'NULL, last_modified FROM access ORDER BY rowid LIMIT ?')
        if 'indirect_object_identifier' not in cols and has_auth:
            query = query.replace('indirect_object_identifier', 'NULL')
        if 'last_modified' not in cols:
            query = query.replace('last_modified FROM', 'NULL FROM')
        rows = conn.execute(query, (max_rows + 1,)).fetchall()
    finally:
        conn.close()
    events = []
    low = _norm(path).lower()
    if re.search(r'(^|/)users/[^/]+/library/application support/com\.apple\.tcc/', low):
        scope = 'user'
    elif 'library/application support/com.apple.tcc/' in low:
        scope = 'system'
    else:
        scope = 'unknown'
    for rowid, service, client, ctype, value, reason, csreq, indirect, modified in rows[:max_rows]:
        auth = int(value) if value is not None else None
        if not has_auth and auth is not None:
            auth = 2 if auth == 1 else 0
        ev = {
            'row': rowid, '_ref': ('row', rowid),
            'timestamp': from_unix(modified),
            'source': 'macos_tcc',
            'service': service,
            'service_label': TCC_SERVICES.get(service, (service or '').replace('kTCCService', '')),
            'client': client,
            'client_type': 'path' if ctype == 1 else 'bundle_id',
            'auth_value': auth,
            'auth_value_label': TCC_AUTH_VALUES.get(auth, str(auth)),
            'auth_reason': reason,
            'auth_reason_label': TCC_AUTH_REASONS.get(reason) if reason is not None else None,
            'csreq_present': bool(csreq),
            'indirect_object': None if indirect in (None, '', 'UNUSED') else indirect,
            'operation': 'TCC grant' if auth in (2, 3) else 'TCC entry',
            'target': client,
            'tcc_scope': scope,
        }
        ev = {k: v for k, v in ev.items() if v is not None}
        ev['event'] = f"{ev['service_label']} {ev['auth_value_label']} -> {client}"
        events.append(ev)
    return events, {'truncated': len(rows) > max_rows, 'schema': 'auth_value' if has_auth else 'allowed'}


QUARANTINE_TYPES = {0: 'web download', 1: 'other download', 2: 'email attachment',
                    3: 'message attachment', 4: 'calendar attachment', 5: 'other attachment'}


def load_quarantine(path, max_rows=MAX_ROWS):
    conn = open_ro(path)
    try:
        cols = _columns(conn, 'LSQuarantineEvent')
        wanted = ['LSQuarantineEventIdentifier', 'LSQuarantineTimeStamp', 'LSQuarantineAgentBundleIdentifier',
                  'LSQuarantineAgentName', 'LSQuarantineDataURLString', 'LSQuarantineSenderName',
                  'LSQuarantineSenderAddress', 'LSQuarantineTypeNumber', 'LSQuarantineOriginTitle',
                  'LSQuarantineOriginURLString']
        select = ', '.join(c if c in cols else 'NULL' for c in wanted)
        # Colonnes issues d'une liste constante, filtrees par le schema : pas d'injection possible
        rows = conn.execute(f'SELECT rowid, {select} FROM LSQuarantineEvent ORDER BY rowid LIMIT ?',  # nosec B608
                            (max_rows + 1,)).fetchall()
    finally:
        conn.close()
    events = []
    for r in rows[:max_rows]:
        rowid, ident, stamp, agent_id, agent, data_url, sender, sender_addr, qtype, title, origin = r
        ev = {
            'row': rowid, '_ref': ('row', rowid),
            'timestamp': from_mac(stamp),
            'source': 'macos_quarantine',
            'quarantine_id': ident,
            'agent_name': agent,
            'agent_bundle_id': agent_id,
            'data_url': data_url,
            'origin_url': origin,
            'origin_title': title,
            'sender_name': sender,
            'sender_address': sender_addr,
            'quarantine_type': QUARANTINE_TYPES.get(qtype, qtype),
            'download_host': url_host(data_url),
            'origin_host': url_host(origin),
            'operation': 'download',
            'target': data_url,
        }
        ev = {k: v for k, v in ev.items() if v not in (None, '')}
        ev['event'] = f"{agent or agent_id or '?'} download {data_url or ''} (origin {origin or '-'})"
        events.append(ev)
    return events, {'truncated': len(rows) > max_rows}


def load_knowledgec(path, max_rows=MAX_ROWS):
    conn = open_ro(path)
    try:
        cols = _columns(conn, 'ZOBJECT')
        if not {'ZSTREAMNAME', 'ZVALUESTRING', 'ZSTARTDATE', 'ZENDDATE'} <= cols:
            return [], {'truncated': False, 'notes': ['Schema ZOBJECT inattendu : colonnes absentes.']}
        rows = conn.execute(
            "SELECT rowid, ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE FROM ZOBJECT "
            "WHERE ZSTREAMNAME IN ('/app/usage', '/app/inFocus', '/app/activity', '/app/webUsage') "
            "ORDER BY ZSTARTDATE LIMIT ?", (max_rows + 1,)).fetchall()
    finally:
        conn.close()
    events = []
    for rowid, stream, value, start, end in rows[:max_rows]:
        try:
            duration = int(float(end) - float(start)) if start is not None and end is not None else None
        except (TypeError, ValueError):
            duration = None
        ev = {'row': rowid, '_ref': ('row', rowid), 'timestamp': from_mac(start), 'end': from_mac(end),
              'source': 'macos_knowledgec', 'stream': stream, 'bundle_id': value, 'duration_s': duration,
              'operation': stream, 'target': value}
        ev = {k: v for k, v in ev.items() if v not in (None, '')}
        ev['event'] = f'{stream} {value} ({duration}s)'
        events.append(ev)
    return events, {'truncated': len(rows) > max_rows}
