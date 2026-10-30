"""File system detections on tabular exports (file activity, MFT), no LLM.

- Mass encryption (T1486): one process renames at least
  ``MIN_ENCRYPTED_FILES`` files by appending the same new extension.
- Timestomping (T1070.006): an MFT entry whose $STANDARD_INFORMATION creation
  time is earlier than its $FILE_NAME creation time (the ``SI<FN`` flag of
  MFTECmd, or the two timestamps when the flag is absent).

Every alert cites the ``row`` of the rows it rests on.
"""

import datetime
import os
import re

MIN_ENCRYPTED_FILES = 10
MAX_ROWS_PER_ALERT = 50
_EXTENSION = re.compile(r'^\.[A-Za-z0-9_]{2,16}$')
_KNOWN_EXTENSIONS = {'.bak', '.tmp', '.old', '.orig', '.part', '.crdownload', '.download', '.temp', '.swp'}

_OPERATION = ('operation', 'action', 'event', 'type')
_SOURCE = ('source_path', 'src_path', 'old_path', 'source', 'path')
_TARGET = ('target_path', 'dst_path', 'new_path', 'target', 'destination')
_PROCESS = ('process', 'image', 'process_name', 'Image')
_USER = ('user', 'username', 'account')
_HOST = ('host', 'hostname', 'computer')


def _first(data, keys):
    for k in keys:
        v = data.get(k)
        if v not in (None, ''):
            return str(v)
    return None


def _rows(events):
    for event in events:
        data = event.get('data') if isinstance(event.get('data'), dict) else None
        if data is not None and event.get('row') is not None:
            yield event['row'], data


def encryption_alerts(events):
    groups = {}
    for row, data in _rows(events):
        if (_first(data, _OPERATION) or '').lower() not in ('rename', 'renamed', 'move', 'moved'):
            continue
        source, target = _first(data, _SOURCE), _first(data, _TARGET)
        if not source or not target or not target.startswith(source) or target == source:
            continue
        appended = target[len(source):]
        if not _EXTENSION.match(appended) or appended.lower() in _KNOWN_EXTENSIONS:
            continue
        key = (_first(data, _PROCESS) or '', appended.lower())
        groups.setdefault(key, []).append((row, data, target))
    alerts = []
    for (process, extension), rows in groups.items():
        if len(rows) < MIN_ENCRYPTED_FILES:
            continue
        first_row, data, target = rows[0]
        alerts.append({
            'type': 'mass_encryption', 'severity': 'critical', 'technique': 'T1486',
            'title': f'Chiffrement de masse : {len(rows)} fichiers renommes en *{extension}'
                     + (f' par {os.path.basename(process.replace(chr(92), "/"))}' if process else ''),
            'description': f'{len(rows)} fichiers renommes avec l extension ajoutee {extension}, '
                           f'premier : {target}.',
            'process': process or None, 'user': _first(data, _USER), 'host': _first(data, _HOST),
            'extension': extension, 'files': len(rows), 'row': first_row,
            'rows': [r[0] for r in rows][:MAX_ROWS_PER_ALERT],
        })
    alerts.sort(key=lambda a: a['row'])
    return alerts


def _time(value):
    text = str(value or '').strip().replace('T', ' ').replace('Z', '')
    for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
        try:
            return datetime.datetime.strptime(text[:26], fmt)
        except ValueError:
            continue
    return None


def timestomp_alerts(events):
    alerts = []
    for row, data in _rows(events):
        si, fn = data.get('Created0x10'), data.get('Created0x30')
        if si is None or fn is None:
            continue
        flag = str(data.get('SI<FN', '')).strip().lower()
        si_t, fn_t = _time(si), _time(fn)
        earlier = si_t is not None and fn_t is not None and si_t < fn_t
        if not (flag == 'true' or (flag == '' and earlier)) or not earlier:
            continue
        parent = data.get('ParentPath') or ''
        name = data.get('FileName') or ''
        path = f'{parent}\\{name}' if parent else name
        alerts.append({
            'type': 'timestomping', 'severity': 'high', 'technique': 'T1070.006',
            'title': f'Horodatage falsifie (timestomping) : {name}',
            'description': f'$SI creation {si} anterieure a $FN creation {fn} pour {path}.',
            'path': path, 'file': name, 'si_created': si, 'fn_created': fn, 'row': row,
            'entry_number': data.get('EntryNumber'),
        })
    return alerts


def detect(events):
    return encryption_alerts(events) + timestomp_alerts(events)
