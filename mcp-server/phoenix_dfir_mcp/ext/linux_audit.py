"""Extension Linux auditd : parsing de audit.log et detections.

Un evenement auditd est compose de plusieurs enregistrements (SYSCALL,
EXECVE, CWD, PATH, PROCTITLE...) partageant le meme identifiant
msg=audit(horodatage:serie) : ils sont regroupes en un seul evenement
normalise, cite par la ligne de son PREMIER enregistrement ('line'). Les
valeurs hexadecimales (arguments EXECVE, proctitle, chemins) sont decodees ;
le format enrichi (log_format=ENRICHED, champs AUID="alice" apres le
separateur 0x1d) et la sortie interpretee d'ausearch -i sont acceptes.
"""

import datetime
import os
import re
from collections import Counter

from .. import toolkit
from . import _cloud_formats as formats
from ._cloud_rules import Hunt

AGENT = ('linux_audit', 'Agent Linux (auditd)')
TOOL_NAMES = ('linux_parse_auditd', 'linux_audit_hunt')
READONLY = TOOL_NAMES
INDEXED = TOOL_NAMES
PHASE_TOOLS = {
    'extraction': TOOL_NAMES,
    'correlation': ('linux_audit_hunt',),
    'contre_analyse': TOOL_NAMES,
}
PHASE_HINTS = {
    'extraction': """- Journaux auditd Linux (audit.log, lignes type=... msg=audit(...)) : linux_parse_auditd PUIS
  linux_audit_hunt (execution suspecte, fichiers de comptes / sudoers / authorized_keys, alteration
  d'auditd, effacement de logs).""",
    'correlation': """- Constats auditd : linux_audit_hunt cite la ligne du premier enregistrement de chaque evenement
  (refs 'line') ; correler auid / ses avec les connexions (auth.log, USER_LOGIN).""",
}

# ============================================================================
# Parsing
# ============================================================================

_LINE_RE = re.compile(r'(?:node=(?P<node>\S+)\s+)?type=(?P<type>[A-Z0-9_]+)\s+'
                      r'msg=audit\((?P<stamp>[^)]*?):(?P<serial>\d+)\):\s?(?P<body>.*)$')
_KV_RE = re.compile(r'''([A-Za-z0-9_-]+)=("[^"]*"|'[^']*'|\S+)''')
_SYSLOG_HOST_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+(\S+)\s')
_HEX_RE = re.compile(r'^[0-9A-Fa-f]+$')
_UNSET = ('4294967295', '-1', 'unset')

SYSCALLS_X86_64 = {
    '0': 'read', '1': 'write', '2': 'open', '42': 'connect', '43': 'accept', '49': 'bind',
    '56': 'clone', '57': 'fork', '59': 'execve', '62': 'kill', '76': 'truncate', '77': 'ftruncate',
    '82': 'rename', '83': 'mkdir', '84': 'rmdir', '86': 'link', '87': 'unlink', '88': 'symlink',
    '90': 'chmod', '91': 'fchmod', '92': 'chown', '94': 'lchown', '105': 'setuid', '113': 'setreuid',
    '175': 'init_module', '176': 'delete_module', '257': 'openat', '260': 'fchownat', '263': 'unlinkat',
    '264': 'renameat', '265': 'linkat', '266': 'symlinkat', '268': 'fchmodat', '313': 'finit_module',
    '316': 'renameat2', '322': 'execveat',
}
WRITE_SYSCALLS = {'write', 'truncate', 'ftruncate', 'rename', 'renameat', 'renameat2', 'unlink',
                  'unlinkat', 'link', 'linkat', 'symlink', 'symlinkat', 'chmod', 'fchmod', 'fchmodat',
                  'chown', 'fchownat', 'lchown', 'mkdir', 'rmdir'}


def _value(raw, hexable=False):
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'") and len(raw) >= 2:
        return raw[1:-1]
    if hexable and len(raw) >= 2 and len(raw) % 2 == 0 and _HEX_RE.match(raw):
        try:
            return bytes.fromhex(raw).decode('utf-8', errors='replace').replace('\x00', ' ').strip()
        except ValueError:
            return raw
    return raw


def _fields(body, rtype):
    enriched = {}
    if '\x1d' in body:
        body, extra = body.split('\x1d', 1)
        for k, raw in _KV_RE.findall(extra):
            enriched[k] = _value(raw)
    out = {}
    hex_keys = rtype in ('EXECVE', 'PROCTITLE', 'PATH', 'CWD')
    for k, raw in _KV_RE.findall(body):
        if k == 'msg' and raw.startswith("'"):
            out.update({ik: _value(iv) for ik, iv in _KV_RE.findall(raw[1:-1])})
            continue
        hexable = hex_keys and (k in ('proctitle', 'name', 'cwd') or (rtype == 'EXECVE' and re.fullmatch(r'a\d+', k)))
        out[k] = _value(raw, hexable)
    return out, enriched


def _stamp(text):
    text = text.strip()
    try:
        return formats.to_utc(float(text))
    except ValueError:
        pass
    m = re.match(r'(\d{2})/(\d{2})/(\d{2,4}) (\d{2}):(\d{2}):(\d{2})', text)
    if m:
        mo, d, y, hh, mm, ss = m.groups()
        y = int(y) + (2000 if len(y) == 2 else 0)
        try:
            return datetime.datetime(y, int(mo), int(d), int(hh), int(mm), int(ss)).strftime('%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            return None
    return None


def _open(path):
    return formats._open_text(path)


def iter_groups(path, max_events=formats.DEFAULT_MAX_EVENTS, stats=None):
    """Regrouper les enregistrements par evenement (node, horodatage, serie)."""
    stats = stats if stats is not None else {}
    groups, order = {}, []
    with _open(path) as f:
        for no, line in enumerate(f, 1):
            m = _LINE_RE.search(line.rstrip('\r\n'))
            if not m:
                if line.strip():
                    stats['skipped'] = stats.get('skipped', 0) + 1
                continue
            node = m.group('node')
            if not node:
                hm = _SYSLOG_HOST_RE.match(line)
                node = hm.group(1) if hm else None
            key = (node, m.group('stamp'), m.group('serial'))
            if key not in groups:
                if len(order) >= max_events:
                    stats['truncated'] = True
                    break
                groups[key] = {'line': no, 'lines': [], 'node': node, 'stamp': m.group('stamp'),
                               'serial': m.group('serial'), 'records': []}
                order.append(key)
            fields, enriched = _fields(m.group('body'), m.group('type'))
            groups[key]['lines'].append(no)
            groups[key]['records'].append((m.group('type'), fields, enriched))
    return [groups[k] for k in order]


def _user(fields, enriched):
    for key in ('AUID', 'UID'):
        if enriched.get(key) and enriched[key] not in _UNSET:
            return enriched[key]
    if fields.get('acct') and fields['acct'] not in ('?', '(unknown)'):
        return fields['acct']
    auid = fields.get('auid')
    # Identifiant numerique sans nom resolu : uid 0 = root, sinon 'uid:<n>'
    numeric = auid if auid and auid not in _UNSET else fields.get('uid')
    if numeric is not None:
        return 'root' if numeric == '0' else f'uid:{numeric}'
    return None


def build_event(group):
    types = [t for t, _f, _e in group['records']]
    merged, enriched, argv, paths, cwd, proctitle = {}, {}, [], [], None, None
    for rtype, fields, enr in group['records']:
        enriched.update(enr)
        if rtype == 'EXECVE':
            argv = [fields[f'a{i}'] for i in range(int(fields.get('argc', 0) or 0)) if f'a{i}' in fields]
        elif rtype == 'PATH':
            paths.append((fields.get('name', ''), fields.get('nametype', '')))
        elif rtype == 'CWD':
            cwd = fields.get('cwd')
        elif rtype == 'PROCTITLE':
            proctitle = fields.get('proctitle')
        else:
            for k, v in fields.items():
                merged.setdefault(k, v)
    resolved = []
    for name, nametype in paths:
        if name and name != '(null)':
            full = name if name.startswith('/') or not cwd else os.path.normpath(os.path.join(cwd, name))
            resolved.append((full, nametype))
    syscall = merged.get('syscall')
    syscall_name = enriched.get('SYSCALL') or SYSCALLS_X86_64.get(syscall, syscall)
    if 'EXECVE' in types or syscall_name in ('execve', 'execveat'):
        operation = 'execve'
    elif 'SYSCALL' in types:
        operation = syscall_name
    else:
        operation = types[0]
    res = merged.get('res') or merged.get('success')
    result = None
    if res:
        result = 'success' if str(res).lower() in ('yes', 'success', '1') else 'failure'
    command = ' '.join(argv) if argv else proctitle
    addr = merged.get('addr')
    ev = {
        'line': group['line'],
        '_ref': ('line', group['line']),
        'timestamp': _stamp(group['stamp']),
        'source': 'linux_auditd',
        'host': group['node'],
        'user': _user(merged, enriched),
        'process': merged.get('exe'),
        'operation': operation,
        'result': result,
        'target': ', '.join(p for p, _t in resolved)[:300] or merged.get('unit') or merged.get('acct'),
        'src_ip': addr if addr and re.match(r'^[0-9a-fA-F:.]+$', str(addr)) and ('.' in addr or ':' in addr) else None,
        'record_types': '+'.join(dict.fromkeys(types)),
        'audit_id': f"{group['stamp']}:{group['serial']}",
        'lines': ','.join(str(n) for n in group['lines'][:20]),
        'command': (command or '')[:500] or None,
        'comm': merged.get('comm'),
        'key': merged.get('key') if merged.get('key') not in ('(null)', None) else None,
        'auid': merged.get('auid'), 'uid': merged.get('uid'), 'euid': merged.get('euid'),
        'ses': merged.get('ses'), 'tty': merged.get('tty'), 'ppid': merged.get('ppid'),
        'pid': merged.get('pid'),
        'op': merged.get('op'), 'unit': merged.get('unit'),
        'severity': 'info',
    }
    ev = {k: v for k, v in ev.items() if v not in (None, '')}
    ev['_paths'] = resolved
    ev['_argv'] = argv
    ev['_fields'] = merged
    ev['_syscall'] = syscall_name
    ev['_types'] = types
    ev['event'] = ' '.join(str(x) for x in (ev['record_types'], ev.get('user'), ev.get('process'),
                                            ev.get('command') or ev.get('target'), ev.get('result')) if x)
    return ev


def load_events(path, max_events=formats.DEFAULT_MAX_EVENTS):
    stats = {'skipped': 0}
    events = [build_event(g) for g in iter_groups(path, max_events, stats)]
    return events, stats


# ============================================================================
# Detections
# ============================================================================

_TMP_DIRS = ('/tmp/', '/dev/shm/', '/var/tmp/', '/run/shm/')  # nosec B108 - motifs de detection, rien n'y est ecrit
_ACCOUNT_FILES = ('/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow')
_ACCOUNT_TOOLS = {'useradd', 'usermod', 'userdel', 'groupadd', 'groupmod', 'groupdel', 'passwd',
                  'chpasswd', 'chage', 'vipw', 'vigr', 'adduser', 'deluser', 'addgroup', 'newusers',
                  'chsh', 'chfn', 'gpasswd', 'pwconv', 'grpconv', 'dpkg', 'rpm', 'yum', 'dnf', 'apt',
                  'apt-get', 'systemd-sysusers', 'unix_chkpwd', 'sss_cache'}
_PKG_TOOLS = {'dpkg', 'rpm', 'yum', 'dnf', 'apt', 'apt-get', 'unattended-upgr', 'packagekitd'}
_AUDIT_TOOLS = {'augenrules', 'auditctl', 'auditd'} | _PKG_TOOLS
_LOG_TOOLS = {'logrotate', 'gzip', 'xz', 'bzip2', 'rsyslogd', 'systemd-journald', 'journald', 'savelog',
              'syslog-ng', 'auditd'}

_EXEC_PATTERNS = (
    (re.compile(r'/dev/(tcp|udp)/|\b(ba)?sh -i\b|\bnc(at)?\b[^|;]*\s-e\s|socat\b.*exec:|'
                r'python[23]?\b.*socket.*(subprocess|pty)'), 'T1059.004', 'critical', 'Shell inverse'),
    (re.compile(r'xmrig|minerd|cpuminer|stratum\+tcp|cryptonight'), 'T1496', 'critical', 'Minage de cryptomonnaie'),
    (re.compile(r'(^|/)(chisel|ligolo(-ng)?|frpc|gost|ngrok)\b'), 'T1572', 'high', 'Tunnel / proxy inverse'),
    (re.compile(r'(^|/)(nmap|masscan|zmap)\b'), 'T1046', 'medium', 'Balayage reseau'),
    (re.compile(r'\bbase64\s+(-d|--decode)\b'), 'T1140', 'medium', 'Decodage base64'),
    (re.compile(r'\b(curl|wget)\b[^|;]*\|\s*(ba)?sh\b'), 'T1105', 'critical', 'Telechargement execute (curl | sh)'),
    (re.compile(r'\b(curl|wget)\b.*(https?://\d{1,3}(\.\d{1,3}){3}|\s-[oO]\s*(/tmp|/dev/shm|/var/tmp))'),
     'T1105', 'high', 'Telechargement d\'outil'),
    (re.compile(r'(^|/)(nc|ncat|netcat|socat)\b'), 'T1059.004', 'high', 'Utilitaire reseau brut (netcat)'),
)


def _base(path):
    return os.path.basename(str(path or ''))


def _is_write(ev):
    sc = ev.get('_syscall')
    if sc in WRITE_SYSCALLS:
        return True
    if any(t in ('CREATE', 'DELETE') for _p, t in ev.get('_paths') or []):
        return True
    fields = ev.get('_fields') or {}
    if sc in ('open', 'openat'):
        flags = fields.get('a2' if sc == 'openat' else 'a1', '0')
        try:
            value = int(flags, 16)
        except ValueError:
            return bool(re.search(r'O_(WRONLY|RDWR|CREAT|TRUNC)', flags))
        return bool(value & 0x3 or value & 0x40 or value & 0x200)
    return False


def _truncates(ev):
    fields = ev.get('_fields') or {}
    sc = ev.get('_syscall')
    if sc in ('truncate', 'ftruncate', 'unlink', 'unlinkat', 'rename', 'renameat', 'renameat2'):
        return True
    if any(t == 'DELETE' for _p, t in ev.get('_paths') or []):
        return True
    if sc in ('open', 'openat'):
        try:
            return bool(int(fields.get('a2' if sc == 'openat' else 'a1', '0'), 16) & 0x200)
        except ValueError:
            return 'O_TRUNC' in fields.get('a2' if sc == 'openat' else 'a1', '')
    return False


def _rule_exec(ev, hunt):
    if ev.get('operation') != 'execve':
        return
    cmd = ev.get('command') or ''
    exe = ev.get('process') or ''
    text = f'{exe} {cmd}'
    for regex, mitre, sev, label in _EXEC_PATTERNS:
        if regex.search(text):
            hunt.add('auditd_suspicious_exec', f"{label} : {cmd[:120] or exe}", sev, mitre, [ev],
                     f"Execution par {ev.get('user')} (exe {exe}).")
            return
    if exe.startswith(_TMP_DIRS) or (ev.get('_argv') and str(ev['_argv'][0]).startswith(_TMP_DIRS)):
        hunt.add('auditd_exec_from_tmp', f'Execution depuis un repertoire temporaire : {exe}', 'high',
                 'T1059.004', [ev], 'Binaire lance depuis /tmp, /dev/shm ou /var/tmp.')
        return
    if _base(exe) == 'useradd' and re.search(r'(-u|--uid)\s*0\b', cmd) and re.search(r'(-o|--non-unique)\b', cmd):
        hunt.add('auditd_uid0_account', f'Compte UID 0 cree : {cmd[:120]}', 'critical', 'T1136.001', [ev],
                 'Creation d\'un second compte root (useradd -o -u 0).')


def _rule_files(ev, hunt):
    exe_base = _base(ev.get('process'))
    if not ev.get('_paths') or not _is_write(ev):
        return
    for path, nametype in ev['_paths']:
        if nametype == 'PARENT':
            continue
        if path in _ACCOUNT_FILES or path.startswith(tuple(p + '+' for p in _ACCOUNT_FILES)):
            if exe_base not in _ACCOUNT_TOOLS:
                hunt.add('auditd_account_file', f'{path} modifie directement par {exe_base}', 'high',
                         'T1098', [ev], 'Modification d\'un fichier de comptes hors des outils dedies '
                         '(useradd, passwd...) : ajout de compte ou de mot de passe cache.')
        elif path == '/etc/sudoers' or path.startswith('/etc/sudoers.d/'):
            if exe_base not in ({'visudo'} | _PKG_TOOLS):
                hunt.add('auditd_sudoers', f'{path} modifie par {exe_base}', 'high', 'T1548.003', [ev],
                         'Ecriture dans la configuration sudo hors visudo : elevation de privileges.')
        elif re.search(r'/\.ssh/authorized_keys2?$', path):
            hunt.add('auditd_ssh_authorized_keys', f'Cle SSH ajoutee : {path} ({exe_base})', 'high',
                     'T1098.004', [ev], 'Modification de authorized_keys : acces SSH persistant.')
        elif path == '/etc/ld.so.preload':
            hunt.add('auditd_ld_preload', f'/etc/ld.so.preload modifie par {exe_base}', 'critical',
                     'T1574.006', [ev], 'Bibliotheque prechargee dans tous les processus (rootkit).')
        elif path.startswith(('/etc/cron', '/var/spool/cron')) and exe_base not in ({'crontab'} | _PKG_TOOLS):
            hunt.add('auditd_cron', f'Tache planifiee modifiee : {path} ({exe_base})', 'medium', 'T1053.003',
                     [ev], 'Ecriture directe dans la configuration cron.')
        elif re.match(r'^/(etc|lib|usr/lib)/systemd/system/[^/]+\.(service|timer)$', path) \
                and exe_base not in ({'systemctl', 'systemd'} | _PKG_TOOLS):
            hunt.add('auditd_systemd_unit', f'Unite systemd ecrite : {path} ({exe_base})', 'medium',
                     'T1543.002', [ev], 'Nouveau service systemd : persistance possible.')
        elif path.startswith('/etc/audit/') and exe_base not in _AUDIT_TOOLS:
            hunt.add('auditd_tampering', f'Configuration auditd modifiee : {path} ({exe_base})', 'high',
                     'T1562.012', [ev], 'Alteration des regles ou de la configuration d\'audit.')
        elif path.startswith('/var/log/') and _truncates(ev) and exe_base not in _LOG_TOOLS:
            hunt.add('auditd_log_clearing', f'Journal efface ou tronque : {path} ({exe_base})', 'high',
                     'T1070.002', [ev], 'Suppression ou troncature d\'un journal systeme.')
        elif re.search(r'/\.(bash|zsh|sh)_history$', path) and _truncates(ev):
            hunt.add('auditd_history_clearing', f'Historique shell efface : {path}', 'high', 'T1070.003', [ev],
                     'Effacement de l\'historique des commandes.')


def _rule_tampering(ev, hunt):
    types = ev.get('_types') or []
    fields = ev.get('_fields') or {}
    text = ' '.join(f'{k}={v}' for k, v in fields.items())
    cmd = ev.get('command') or ''
    if 'CONFIG_CHANGE' in types and (fields.get('op') in ('remove_rule', 'remove_watch', 'remove-rule')
                                     or re.search(r'audit_enabled=0\b', text)):
        hunt.add('auditd_tampering', f"Regles d'audit supprimees ou audit desactive ({fields.get('op', 'set')})",
                 'high', 'T1562.012', [ev], 'Modification de la politique auditd en cours d\'execution.')
    elif ev.get('operation') == 'execve' and _base(ev.get('process')) == 'auditctl' and re.search(
            r'\s(-D|-e\s*0)\b', cmd):
        hunt.add('auditd_tampering', f'auditctl : {cmd}', 'high', 'T1562.012', [ev],
                 'Suppression des regles d\'audit ou desactivation du sous-systeme.')
    elif ev.get('operation') == 'execve' and re.search(r'\b(systemctl|service)\b.*\b(stop|disable|mask)\b.*auditd|'
                                                       r'\bservice\s+auditd\s+stop', cmd):
        hunt.add('auditd_tampering', f'Arret du service auditd : {cmd}', 'high', 'T1562.012', [ev],
                 'Arret volontaire de la journalisation d\'audit.')
    elif ev.get('operation') == 'execve' and re.search(r'\b(shred|truncate|rm|unlink|wipe)\b.*\s/var/log/', ' ' + cmd):
        hunt.add('auditd_log_clearing', f'Effacement de journaux : {cmd[:120]}', 'high', 'T1070.002', [ev],
                 'Commande d\'effacement de fichiers de /var/log.')
    elif ev.get('operation') == 'execve' and re.search(r'journalctl\b.*--vacuum|\bhistory\s+-c\b', cmd):
        hunt.add('auditd_log_clearing', f'Purge de journaux : {cmd[:120]}', 'medium', 'T1070.002', [ev],
                 'Purge du journal systemd.')
    elif 'DAEMON_END' in types or ('SERVICE_STOP' in types and fields.get('unit') == 'auditd'):
        hunt.add('auditd_stopped', 'Arret du demon auditd', 'medium', 'T1562.012', [ev],
                 'Arret d\'auditd (redemarrage legitime ou alteration : verifier le contexte).')
    elif 'ADD_USER' in types:
        uid_zero = re.search(r'\bid=0\b', text)
        hunt.add('auditd_add_user', f"Compte ajoute : {fields.get('acct') or fields.get('id')}",
                 'critical' if uid_zero else 'low', 'T1136.001', [ev],
                 'Creation de compte local' + (' avec UID 0.' if uid_zero else ' (administration a corroborer).'))


def hunt_events(events, artifact):
    hunt = Hunt(artifact)
    for ev in events:
        if ev.get('result') == 'failure' and ev.get('operation') != 'execve':
            continue
        _rule_exec(ev, hunt)
        _rule_files(ev, hunt)
        _rule_tampering(ev, hunt)
    findings, alerts = hunt.result()
    return findings, alerts


# ============================================================================
# Outils
# ============================================================================

def _check(file_path):
    det = formats.detect(file_path)
    if det['format'] != 'linux_auditd':
        return {'error': f"Pas un journal auditd ({det.get('reason')}) : utiliser cloud_detect_format.",
                'detection': det}
    return None


def _artifact_name(file_path):
    case = toolkit.active_case()
    rel = toolkit._rel_in_case(file_path, case) if case else None
    return rel if rel not in (None, '.') else os.path.basename(file_path)


@toolkit.tool(
    'linux_parse_auditd',
    "Parser un journal auditd Linux (audit.log) : enregistrements SYSCALL / EXECVE / PATH / CWD / "
    "PROCTITLE / USER_* regroupes par evenement msg=audit(horodatage:serie), arguments hexadecimaux "
    "decodes, utilisateur (auid), executable, commande, fichiers touches. Indexe dans la super-timeline ; "
    "ref citable 'line' = ligne du premier enregistrement de l'evenement.",
    toolkit._schema({
        'file_path': {'type': 'string', 'description': 'Chemin de audit.log'},
        'max_events': {'type': 'integer',
                       'description': f"Nombre max d'evenements (defaut {formats.DEFAULT_MAX_EVENTS})"},
    }, ['file_path']),
)
def linux_parse_auditd(file_path, max_events=formats.DEFAULT_MAX_EVENTS):
    error = _check(file_path)
    if error:
        return error
    events, stats = load_events(file_path, max(1, int(max_events or formats.DEFAULT_MAX_EVENTS)))
    public = [formats.public_view(e) for e in events]
    stamps = sorted(e['timestamp'] for e in events if e.get('timestamp'))
    result = {
        'file': file_path, 'format': 'linux_auditd', 'ref_kind': 'line',
        'total_events': len(public), 'skipped_lines': stats.get('skipped', 0),
        'truncated': bool(stats.get('truncated')),
        'summary': {
            'time_span': {'first': stamps[0], 'last': stamps[-1]} if stamps else None,
            'record_types': dict(Counter(t for e in events for t in e['_types']).most_common(20)),
            'top_users': dict(Counter(e.get('user') for e in events if e.get('user')).most_common(15)),
            'top_executables': dict(Counter(e.get('process') for e in events if e.get('process')).most_common(20)),
            'keys': dict(Counter(e.get('key') for e in events if e.get('key')).most_common(15)),
        },
        'events': public,
    }
    if len(public) > 200:
        result['preview'] = public[:100]
    return result


@toolkit.tool(
    'linux_audit_hunt',
    "Detections deterministes sur auditd : execution suspecte (shell inverse, curl | sh, outils "
    "reseau, mineurs, tunnels, binaire dans /tmp), modification de /etc/passwd /etc/shadow /etc/sudoers "
    "hors outils dedies, nouvelle cle SSH authorized_keys, ld.so.preload, cron / systemd, alteration "
    "d'auditd (auditctl -D, regles supprimees, arret), effacement de journaux et d'historique. Chaque "
    "constat porte severite, technique MITRE ATT&CK et refs 'line' exactes.",
    toolkit._schema({'file_path': {'type': 'string', 'description': 'Chemin de audit.log'}}, ['file_path']),
)
def linux_audit_hunt(file_path):
    error = _check(file_path)
    if error:
        return error
    events, _stats = load_events(file_path, 200000)
    findings, alerts = hunt_events(events, _artifact_name(file_path))
    return {'file': file_path, 'format': 'linux_auditd', 'events_analyzed': len(events),
            'finding_count': len(findings), 'findings': findings, 'alerts': alerts}


def applicable(path):
    try:
        fmt = formats.detect(path)['format']
    except Exception:  # la detection ne doit jamais casser l'audit de couverture
        return None
    if fmt == 'linux_auditd':
        return [('parsing auditd', ('linux_parse_auditd',)), ('detection auditd', ('linux_audit_hunt',))]
    return None
