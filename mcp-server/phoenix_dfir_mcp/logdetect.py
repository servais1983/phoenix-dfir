"""Deterministic detections on text logs (no LLM).

The detectors read the events ``parsers.parse_log`` produced and return alerts
that cite the ``line`` of the events they are built on, so every alert can be
verified against the evidence index.

- SSH authentication (``sshd``): repeated failures from one source address
  (T1110), then a successful login from that address (T1078).
- Windows events written as text lines (``EventID=`` and ``Key=Value``
  fields): ``windows_events`` turns them into events the Sigma engines read.
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


def detect(events):
    """Every text log detection on the parsed events."""
    return ssh_alerts(events)
