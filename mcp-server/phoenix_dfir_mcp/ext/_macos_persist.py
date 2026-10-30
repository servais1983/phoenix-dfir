"""Persistance macOS : launchd, emond, LoginHook, cron, periodic.

Chaque element de persistance devient un evenement normalise citable :
- plist launchd (LaunchAgent / LaunchDaemon) : 'row' 1 (un element par fichier) ;
- regles emond : 'row' = rang de la regle dans le tableau (a partir de 1) ;
- LoginHook / LogoutHook : 'row' 1 ;
- crontab et scripts periodic : 'line' = ligne physique de l'entree.
Les bases BackgroundTaskManagement (.btm, elements de connexion de macOS 13+)
sont un format binaire non documente : elles ne sont PAS decodees (note
explicite ; utiliser `sfltool dumpbtm` sur le systeme vivant).
"""

import os
import re

from . import _macos_formats as mf

_SYSTEM_CRONTAB_RE = re.compile(r'(^|/)etc/crontab$')


def _scope(path, plist):
    low = mf._norm(path).lower()
    if 'launchdaemons' in low:
        return 'LaunchDaemon', 'chemin du plist (LaunchDaemons)'
    if 'launchagents' in low:
        return 'LaunchAgent', 'chemin du plist (LaunchAgents)'
    program = _program(plist)[0] or ''
    if program.startswith(('/Users/', '~/')):
        return 'LaunchAgent', 'programme dans un dossier utilisateur'
    if 'LimitLoadToSessionType' in plist:
        return 'LaunchAgent', 'cle LimitLoadToSessionType'
    if 'UserName' in plist or 'GroupName' in plist:
        return 'LaunchDaemon', 'cle UserName / GroupName'
    return 'unknown', 'emplacement inconnu (conserver le chemin d\'origine lors de la collecte)'


def _program(plist):
    args = plist.get('ProgramArguments')
    argv = [str(a) for a in args] if isinstance(args, list) else []
    program = plist.get('Program') or (argv[0] if argv else None)
    return (str(program) if program else None), argv


def _bool_or_cond(value):
    if isinstance(value, dict):
        return 'conditional'
    return bool(value) if value is not None else None


def launchd_event(path, plist, fmt):
    program, argv = _program(plist)
    scope, why = _scope(path, plist)
    ev = {
        'row': 1, '_ref': ('row', 1),
        'source': 'macos_launchd',
        'label': plist.get('Label'),
        'scope': scope,
        'scope_reason': why,
        'program': program,
        'program_arguments': ' '.join(argv) if argv else None,
        'run_at_load': _bool_or_cond(plist.get('RunAtLoad')),
        'keep_alive': _bool_or_cond(plist.get('KeepAlive')),
        'start_interval': plist.get('StartInterval') if isinstance(plist.get('StartInterval'), int) else None,
        'start_calendar': bool(plist.get('StartCalendarInterval')) or None,
        'watch_paths': ', '.join(map(str, plist.get('WatchPaths') or [])) or None,
        'disabled': plist.get('Disabled') if isinstance(plist.get('Disabled'), bool) else None,
        'user_name': plist.get('UserName'),
        'plist_format': fmt,
        'process': os.path.basename(program) if program else None,
        'operation': f'{scope} {plist.get("Label")}',
        'target': program,
    }
    ev = {k: v for k, v in ev.items() if v not in (None, '')}
    ev['_argv'] = argv
    ev['_command'] = ' '.join([program or ''] + argv[1:] if argv else [program or ''])
    ev['event'] = f"{scope} {ev.get('label')} -> {ev.get('program_arguments') or program}"
    return ev


def emond_events(plist):
    events = []
    for i, rule in enumerate(plist, 1):
        if not isinstance(rule, dict):
            continue
        commands = []
        for action in rule.get('actions') or []:
            if isinstance(action, dict) and str(action.get('type', '')).lower() == 'runcommand':
                argv = [str(action.get('command') or '')] + [str(a) for a in action.get('arguments') or []]
                commands.append(' '.join(a for a in argv if a))
        ev = {
            'row': i, '_ref': ('row', i), 'source': 'macos_emond',
            'rule_name': rule.get('name'),
            'enabled': bool(rule.get('enabled')),
            'event_types': ', '.join(map(str, rule.get('eventTypes') or [])) or None,
            'actions': ', '.join(str(a.get('type')) for a in rule.get('actions') or [] if isinstance(a, dict)),
            'commands': ' ; '.join(commands) or None,
            'operation': 'emond rule',
            'target': ' ; '.join(commands) or None,
        }
        ev = {k: v for k, v in ev.items() if v not in (None, '')}
        ev['_commands'] = commands
        state = 'enabled' if ev['enabled'] else 'disabled'
        ev['event'] = f"emond {rule.get('name')} ({state}) {ev.get('commands', '')}"
        events.append(ev)
    return events


def loginwindow_events(plist):
    ev = {'row': 1, '_ref': ('row', 1), 'source': 'macos_loginwindow',
          'login_hook': plist.get('LoginHook'), 'logout_hook': plist.get('LogoutHook'),
          'operation': 'login hook'}
    ev['target'] = ev.get('login_hook') or ev.get('logout_hook')
    ev = {k: v for k, v in ev.items() if v not in (None, '')}
    ev['event'] = f"LoginHook={ev.get('login_hook', '-')} LogoutHook={ev.get('logout_hook', '-')}"
    return [ev]


def cron_events(path):
    events = []
    low = mf._norm(path).lower()
    system = bool(_SYSTEM_CRONTAB_RE.search(low))
    owner = None if system else re.sub(r'\.?crontab$', '', os.path.basename(path)) or None
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for no, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith('#') or re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', line):
                continue
            if line.startswith('@'):
                parts = line.split(None, 2 if system else 1)
                schedule, rest = parts[0], parts[1:]
            else:
                parts = line.split(None, 6 if system else 5)
                schedule, rest = ' '.join(parts[:5]), parts[5:]
            user = owner
            if system and len(rest) == 2:
                user, rest = rest[0], rest[1:]
            command = rest[-1] if rest else ''
            ev = {'line': no, '_ref': ('line', no), 'source': 'macos_cron', 'schedule': schedule,
                  'command': command, 'user': user, 'operation': 'cron', 'target': command}
            ev = {k: v for k, v in ev.items() if v not in (None, '')}
            ev['_command'] = command
            ev['event'] = f'cron {schedule} {command}'
            events.append(ev)
    return events


def periodic_events(path):
    events = []
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for no, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            ev = {'line': no, '_ref': ('line', no), 'source': 'macos_periodic', 'command': line[:500],
                  'operation': 'periodic', 'target': line[:300], 'event': f'periodic {line[:300]}'}
            ev['_command'] = line
            events.append(ev)
    return events


def load(path, kind):
    """(evenements, notes) pour un artefact de persistance."""
    if kind == 'btm':
        return [], ["Base BackgroundTaskManagement (.btm) : format binaire non documente, non decode. "
                    "Elements de connexion et taches de fond a lister avec `sfltool dumpbtm` sur le "
                    "systeme vivant (ou par l'outil de collecte), puis a analyser comme texte."]
    if kind == 'crontab':
        return cron_events(path), []
    if kind == 'periodic':
        return periodic_events(path), []
    plist, fmt = mf.load_plist(path)
    if kind == 'launchd_plist':
        return [launchd_event(path, plist, fmt)], []
    if kind == 'emond_rules':
        return emond_events(plist), []
    if kind == 'loginwindow_plist':
        return loginwindow_events(plist), []
    return [], [f'type non pris en charge : {kind}']
