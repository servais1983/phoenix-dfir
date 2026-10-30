"""Deterministic detections on text logs (no LLM).

The detectors read the events ``parsers.parse_log`` produced and return alerts
that cite the ``line`` of the events they are built on, so every alert can be
verified against the evidence index.

- SSH authentication (``sshd``): repeated failures from one source address
  (T1110), then a successful login from that address (T1078).
- Windows events written as text lines (``EventID=`` and ``Key=Value``
  fields): ``windows_events`` turns them into events the Sigma engines read.
- Shell history: an archive created (T1560.001), uploaded to an external
  address (T1048), then deleted with what it holds (T1070.004).
"""

import re
from collections import OrderedDict

BRUTE_FORCE_MIN_FAILURES = 10
MAX_LINES_PER_ALERT = 25

_FAILED = re.compile(r'(?:Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?'
                     r'|Invalid user )(?P<user>\S+) from (?P<src>[0-9a-fA-F:.]+)')
_ACCEPTED = re.compile(r'Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<src>[0-9a-fA-F:.]+)')


def _message(event):
    # 'event' is a 200 character preview: the full line is 'message' (syslog) or 'data.raw'
    return str(event.get('message') or (event.get('data') or {}).get('raw') or event.get('event') or '')


def _is_sshd(event):
    process = str(event.get('process') or '')
    return process == 'sshd' or 'sshd[' in _message(event)


def ssh_alerts(events, min_failures=BRUTE_FORCE_MIN_FAILURES):
    """Brute force and login after brute force, one alert per source address."""
    failures = OrderedDict()  # src -> [(line, user)]
    alerts = []
    flagged = set()
    for event in events:
        if not _is_sshd(event) or event.get('line') is None:
            continue
        text = _message(event)
        failed = _FAILED.search(text)
        if failed:
            failures.setdefault(failed.group('src'), []).append((event['line'], failed.group('user')))
            continue
        accepted = _ACCEPTED.search(text)
        if accepted:
            src = accepted.group('src')
            seen = failures.get(src, [])
            if len(seen) >= min_failures and src not in flagged:
                flagged.add(src)
                alerts.append({
                    'type': 'ssh_login_after_bruteforce', 'severity': 'high', 'technique': 'T1078',
                    'title': f"Connexion SSH reussie de {accepted.group('user')} depuis {src} "
                             f"apres {len(seen)} echecs",
                    'src': src, 'user': accepted.group('user'), 'line': event['line'],
                    'timestamp': event.get('timestamp'),
                    'failed_lines': [ln for ln, _u in seen][-MAX_LINES_PER_ALERT:],
                })
    for src, seen in failures.items():
        if len(seen) < min_failures:
            continue
        users = sorted({u for _ln, u in seen})
        alerts.append({
            'type': 'ssh_bruteforce', 'severity': 'high' if src in flagged else 'medium', 'technique': 'T1110',
            'title': f'Brute force SSH depuis {src} : {len(seen)} echecs sur {len(users)} compte(s)',
            'src': src, 'line': seen[0][0], 'lines': [ln for ln, _u in seen][:MAX_LINES_PER_ALERT],
            'failures': len(seen), 'accounts': users[:20],
        })
    alerts.sort(key=lambda a: (a['line'], a['type']))
    return alerts


# Windows events written as text: "<time> <host> <channel> EventID=<id> Key=Value ..."
_WINDOWS_LINE = re.compile(r'^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<channel>\S+)\s+EventID=(?P<id>\d+)\b\s*(?P<rest>.*)$')
_KV_SPLIT = re.compile(r'\s+(?=[A-Za-z][A-Za-z0-9_]*=)')


def windows_events(events):
    """Windows events of a text log, as the Sigma engines read them (``line`` kept)."""
    out = []
    for event in events:
        if event.get('line') is None:
            continue
        match = _WINDOWS_LINE.match(_message(event).strip())
        if not match:
            continue
        data = {}
        for part in _KV_SPLIT.split(match.group('rest')):
            key, sep, value = part.partition('=')
            if sep and key and key not in data:
                data[key] = value.strip()
        data.update({'EventID': int(match.group('id')), 'Channel': match.group('channel'),
                     'Computer': match.group('host')})
        out.append({'event_id': int(match.group('id')), 'record_id': None, 'timestamp': match.group('ts'),
                    'channel': match.group('channel'), 'computer': match.group('host'),
                    'line': event['line'], 'data': data})
    return out


# Shell history (PSReadLine ConsoleHost_history.txt, bash/zsh history): one command per line
_ARCHIVE = (
    re.compile(r'Compress-Archive\b.*?-Path\s+"?(?P<src>[^"\s]+)"?.*?-DestinationPath\s+"?(?P<dst>[^"\s]+)', re.I),
    re.compile(r'\b(?:7z|7za)\s+a\s+(?:-\S+\s+)*"?(?P<dst>[^"\s]+)"?\s+"?(?P<src>[^"\s]+)', re.I),
    re.compile(r'\bzip\s+(?:-\S+\s+)*"?(?P<dst>[^"\s]+\.zip)"?\s+"?(?P<src>[^"\s]+)', re.I),
    re.compile(r'\btar\s+-?[a-z]*c[a-z]*f\s+"?(?P<dst>[^"\s]+)"?\s+"?(?P<src>[^"\s]+)', re.I),
)
_UPLOAD = (
    re.compile(r'(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b(?=.*-Method\s+(?:Put|Post))(?=.*-InFile\s+"?'
               r'(?P<file>[^"\s]+))(?=.*-Uri\s+"?(?P<url>[^"\s]+))', re.I),
    re.compile(r'\bcurl\b(?=.*(?:-T|--upload-file|-F\s+\S*@|--data-binary\s+@)\s*"?@?(?P<file>[^"\s]+))'
               r'(?=.*(?P<url>https?://[^"\s]+))', re.I),
)
_DELETE = re.compile(r'^(?:Remove-Item|del|erase|rm|shred|sdelete)\b(?:\s+-\S+)*\s+"?(?P<path>[^"\s]+)', re.I)
_URL_HOST = re.compile(r'^[a-z]+://(?:[^@/]*@)?(?P<host>\[[^\]]+\]|[^:/]+)', re.I)


def _same_path(a, b):
    return a.replace('/', '\\').rstrip('\\').lower() == b.replace('/', '\\').rstrip('\\').lower()


def _under(path, folder):
    p, f = path.replace('/', '\\').lower(), folder.replace('/', '\\').rstrip('\\').lower()
    return p == f or p.startswith(f + '\\')


def _external_host(url):
    import ipaddress
    match = _URL_HOST.match(url or '')
    host = match.group('host').strip('[]') if match else ''
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        # A name: external unless it is an internal suffix
        return bool(host) and not host.lower().endswith(('.local', '.lan', '.corp', '.internal', '.intra'))
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def history_alerts(events):
    """Exfiltration chain in a shell history: an archive created, uploaded to an external
    address, then the archive or what it holds deleted. Archiving, uploading or deleting
    alone is routine administration and raises nothing."""
    archives, alerts = [], []
    uploaded = []  # (archive, source folder) sent out
    for event in events:
        if event.get('line') is None:
            continue
        command = _message(event).strip()
        for rx in _ARCHIVE:
            m = rx.search(command)
            if m:
                archives.append({'line': event['line'], 'src': m.group('src'), 'dst': m.group('dst')})
                break
        for rx in _UPLOAD:
            m = rx.search(command)
            if not m or not _external_host(m.group('url')):
                continue
            archive = next((a for a in archives if _same_path(a['dst'], m.group('file'))), None)
            if archive is None:
                continue
            host = _URL_HOST.match(m.group('url')).group('host').strip('[]')
            alerts.append({'type': 'archive_collected', 'severity': 'medium', 'technique': 'T1560.001',
                           'title': f"Archive de donnees avant exfiltration : {archive['dst']}",
                           'path': archive['src'], 'file': archive['dst'], 'line': archive['line']})
            alerts.append({'type': 'archive_uploaded', 'severity': 'high',
                           'technique': 'T1048.003' if m.group('url').lower().startswith('http:') else 'T1048',
                           'title': f"Envoi de l'archive {archive['dst']} vers {host}",
                           'dst': host, 'file': archive['dst'], 'url': m.group('url'), 'line': event['line']})
            uploaded.append(archive)
            break
        deleted = _DELETE.match(command)
        if deleted and uploaded:
            target = deleted.group('path')
            for archive in uploaded:
                if _same_path(target, archive['dst']) or _under(target, archive['src']):
                    alerts.append({'type': 'evidence_removed', 'severity': 'medium', 'technique': 'T1070.004',
                                   'title': f'Suppression apres exfiltration : {target}',
                                   'path': target, 'line': event['line']})
                    break
    alerts.sort(key=lambda a: (a['line'], a['type']))
    return alerts


def detect(events):
    """Every text log detection on the parsed events."""
    return ssh_alerts(events) + history_alerts(events)
