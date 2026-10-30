"""Detections deterministes macOS (persistance, TCC, quarantaine, journal unifie, FSEvents).

Chaque constat porte une severite, une ou plusieurs techniques MITRE ATT&CK
(identifiants verifies dans la matrice Enterprise courante) et les
references EXACTES des evenements qui le fondent ('row' / 'line').
Les references de base ne declenchent rien : daemons Apple dans /System,
programmes de mise a jour des editeurs courants, autorisations TCC
accordees a des applications signees, telechargements depuis des sites
ordinaires, fichiers temporaires des caches systeme.
"""

import ipaddress
import os
import re
from collections import defaultdict

from . import _macos_fsevents as fse
from . import _macos_formats as mf
from ._cloud_rules import Hunt

MITRE_NAMES = {
    'T1036.005': 'Masquerading: Match Legitimate Resource Name or Location',
    'T1037.002': 'Boot or Logon Initialization Scripts: Login Hook',
    'T1041': 'Exfiltration Over C2 Channel',
    'T1053': 'Scheduled Task/Job',
    'T1053.003': 'Scheduled Task/Job: Cron',
    'T1056.001': 'Input Capture: Keylogging',
    'T1056.002': 'Input Capture: GUI Input Capture',
    'T1059.002': 'Command and Scripting Interpreter: AppleScript',
    'T1059.004': 'Command and Scripting Interpreter: Unix Shell',
    'T1059.006': 'Command and Scripting Interpreter: Python',
    'T1070.002': 'Indicator Removal: Clear Linux or Mac System Logs',
    'T1070.004': 'Indicator Removal: File Deletion',
    'T1105': 'Ingress Tool Transfer',
    'T1113': 'Screen Capture',
    'T1123': 'Audio Capture',
    'T1125': 'Video Capture',
    'T1140': 'Deobfuscate/Decode Files or Information',
    'T1204.002': 'User Execution: Malicious File',
    'T1485': 'Data Destruction',
    'T1486': 'Data Encrypted for Impact',
    'T1543': 'Create or Modify System Process',
    'T1543.001': 'Create or Modify System Process: Launch Agent',
    'T1543.004': 'Create or Modify System Process: Launch Daemon',
    'T1546.014': 'Event Triggered Execution: Emond',
    'T1548.006': 'Abuse Elevation Control Mechanism: TCC Manipulation',
    'T1553.001': 'Subvert Trust Controls: Gatekeeper Bypass',
    'T1555.001': 'Credentials from Password Stores: Keychain',
    'T1564.001': 'Hide Artifacts: Hidden Files and Directories',
    'T1566.001': 'Phishing: Spearphishing Attachment',
}


class MacHunt(Hunt):
    def add(self, rule, title, severity, mitre, events, description='', **extra):
        finding = super().add(rule, title, severity, mitre, events, description, **extra)
        if finding:
            finding['mitre_name'] = ' / '.join(MITRE_NAMES.get(t.strip(), t.strip())
                                               for t in mitre.split(',') if t.strip())
        return finding


# ============================================================================
# Chemins et commandes
# ============================================================================

_TMP_PREFIXES = ('/tmp/', '/private/tmp/', '/var/tmp/', '/private/var/tmp/')  # nosec B108 - motifs de detection
_SHARED_PREFIXES = ('/Users/Shared/',)
_APPLE_DIRS = ('/System/', '/usr/libexec/', '/usr/sbin/', '/usr/bin/', '/usr/lib/', '/sbin/', '/bin/',
               '/Library/Apple/')
_BENIGN_HIDDEN = {'.Trash', '.Trashes', '.fseventsd', '.Spotlight-V100', '.DocumentRevisions-V100',
                  '.TemporaryItems', '.MobileBackups', '.vol', '.localized', '.DS_Store', '.file'}
_NOISY_HIDDEN = _BENIGN_HIDDEN | {'.git', '.cache', '.npm', '.vscode', '.local', '.config', '.docker',
                                  '.zsh_sessions', '.oh-my-zsh', '.nvm', '.pyenv', '.rbenv', '.cargo',
                                  '.rustup', '.gradle', '.m2', '.Spotlight', '.cups', '.android', '.idea'}
_INTERPRETERS = {'sh', 'bash', 'zsh', 'dash', 'ksh', 'tcsh', 'osascript', 'python', 'python3', 'python2',
                 'perl', 'ruby', 'node', 'curl', 'nc', 'ncat', 'php', 'swift'}
_EXEC_EXT = ('.dmg', '.pkg', '.mpkg', '.app', '.zip', '.command', '.scpt', '.sh', '.tool', '.terminal',
             '.jar', '.iso', '.py', '.dylib', '.so', '.bin', '.applescript', '.7z', '.rar')
VENDOR_PREFIXES = ('com.apple.', 'com.google.', 'com.microsoft.', 'com.adobe.', 'us.zoom.', 'org.mozilla.',
                   'com.dropbox.', 'com.oracle.', 'com.docker.', 'com.jetbrains.', 'com.github.', 'com.brave.',
                   'com.spotify.', 'com.citrix.', 'com.cisco.', 'com.vmware.', 'com.parallels.', 'com.jamf',
                   'com.jamfsoftware.', 'com.crowdstrike.', 'com.sentinelone.', 'com.objective-see.',
                   'com.malwarebytes.', 'com.okta.', 'com.tinyspeck.', 'com.slack.', 'org.virtualbox.',
                   'com.logi.', 'com.logitech.', 'com.teamviewer.', 'com.paloaltonetworks.', 'homebrew.')


def hidden_segments(path, allowed=_BENIGN_HIDDEN):
    return [seg for seg in str(path or '').split('/') if seg.startswith('.') and seg not in ('.', '..')
            and seg not in allowed]


def user_writable(path):
    p = str(path or '')
    return p.startswith(_TMP_PREFIXES + _SHARED_PREFIXES) or bool(re.match(r'^/Users/[^/]+/Downloads/', p))


def apple_location(path):
    return str(path or '').startswith(_APPLE_DIRS)


def _is_ip(host):
    try:
        ipaddress.ip_address(str(host or '').strip('[]'))
        return True
    except ValueError:
        return False


# (regle, regex, technique, severite, libelle)
_CMD_PATTERNS = (
    ('download_exec', re.compile(r'\b(curl|wget)\b[^|;\n]*\|\s*(/bin/|/usr/bin/)?(ba|z|k|da)?sh\b', re.I),
     'T1105,T1059.004', 'critical', 'Telechargement execute (curl | sh)'),
    ('reverse_shell', re.compile(r'/dev/(tcp|udp)/|\b(ba|z)?sh -i\b|\bnc(at)?\b[^|;\n]*\s-e\s', re.I),
     'T1059.004', 'critical', 'Shell inverse'),
    ('applescript', re.compile(r'(^|[/\s])osascript\b', re.I), 'T1059.002', 'high',
     'Execution AppleScript (osascript)'),
    ('python_inline', re.compile(r'(^|[/\s])python[23]?(\.\d+)?\s+(-\S*\s+)*-c\b', re.I), 'T1059.006', 'high',
     'Python en ligne (python -c)'),
    ('decode', re.compile(r'\bbase64\s+(-d|-D|--decode)\b|\bopenssl\s+(base64|enc)\s+-d\b', re.I), 'T1140',
     'high', 'Decodage de charge (base64)'),
)


def command_hits(command):
    return [(rule, mitre, sev, label) for rule, regex, mitre, sev, label in _CMD_PATTERNS
            if regex.search(command or '')]


# ============================================================================
# Persistance
# ============================================================================

def _scope_mitre(scope):
    return {'LaunchAgent': 'T1543.001', 'LaunchDaemon': 'T1543.004'}.get(scope, 'T1543')


def rules_launchd(events, hunt):
    for ev in events:
        if ev.get('disabled') is True:
            continue
        program = ev.get('program') or ''
        command = ev.get('_command') or program
        label = str(ev.get('label') or '')
        tech = _scope_mitre(ev.get('scope'))
        kind = ev.get('scope', 'launchd')
        extra = {'label': label, 'program': program, 'scope': ev.get('scope'),
                 'run_at_load': ev.get('run_at_load'), 'keep_alive': ev.get('keep_alive')}
        paths = [program] + [a for a in ev.get('_argv', [])[1:] if a.startswith('/')]
        hidden = sorted({seg for p in paths for seg in hidden_segments(p)})
        if hidden:
            hunt.add('launchd_hidden_binary', f'{kind} {label} execute un binaire cache : {program}', 'high',
                     f'{tech},T1564.001', [ev],
                     f"Element launchd qui lance un programme situe dans un dossier ou fichier cache "
                     f"({', '.join(hidden)}) : persistance typique d'un malware.", **extra)
        if any(user_writable(p) for p in paths):
            hunt.add('launchd_user_writable', f'{kind} {label} execute depuis un dossier modifiable : {program}',
                     'high', tech, [ev], 'Programme lance depuis /tmp, /Users/Shared ou Downloads.', **extra)
        for rule, mitre, sev, text in command_hits(command):
            hunt.add(f'launchd_{rule}', f'{kind} {label} : {text} ({command[:120]})', sev, f'{tech},{mitre}',
                     [ev], 'Commande suspecte dans ProgramArguments.', **extra)
        if label.startswith('com.apple.') and program and not apple_location(program):
            hunt.add('launchd_apple_masquerade', f'{kind} {label} imite Apple mais lance {program}', 'high',
                     f'{tech},T1036.005', [ev],
                     "Label com.apple.* pour un programme hors des emplacements systeme Apple : "
                     "usurpation d'un nom legitime.", **extra)


def rules_emond(events, hunt):
    for ev in events:
        if ev.get('enabled') and ev.get('_commands'):
            hunt.add('emond_run_command', f"Regle emond '{ev.get('rule_name')}' executant {ev['commands'][:120]}",
                     'high', 'T1546.014', [ev],
                     'Regle emond active avec action RunCommand : execution declenchee par evenement '
                     '(mecanisme obsolete, rarement legitime).', rule_name=ev.get('rule_name'),
                     command=ev.get('commands'))


def rules_loginwindow(events, hunt):
    for ev in events:
        hook = ev.get('login_hook') or ev.get('logout_hook')
        if hook:
            hunt.add('login_hook', f'LoginHook / LogoutHook : {hook}', 'high', 'T1037.002', [ev],
                     'Script execute a chaque ouverture / fermeture de session (mecanisme obsolete).',
                     hook=hook)


def rules_scheduled(events, hunt, kind):
    tech = 'T1053.003' if kind == 'crontab' else 'T1053'
    name = 'cron' if kind == 'crontab' else 'periodic'
    for ev in events:
        command = ev.get('_command') or ''
        hits = command_hits(command)
        for rule, mitre, sev, text in hits:
            hunt.add(f'{name}_{rule}', f'{name} : {text} ({command[:120]})', sev, f'{tech},{mitre}', [ev],
                     f'Commande suspecte planifiee ({name}).', command=command[:300])
        paths = re.findall(r'(/[^\s;|&\'"]+)', command)
        if not hits and any(user_writable(p) or hidden_segments(p) for p in paths):
            hunt.add(f'{name}_suspicious_path', f'{name} : execution depuis un emplacement suspect ({command[:120]})',
                     'high', tech, [ev], 'Tache planifiee lancant un programme cache ou dans un dossier temporaire.',
                     command=command[:300])


# ============================================================================
# TCC
# ============================================================================

SENSITIVE_TCC = {
    'kTCCServiceSystemPolicyAllFiles', 'kTCCServiceScreenCapture', 'kTCCServiceAccessibility',
    'kTCCServiceListenEvent', 'kTCCServicePostEvent', 'kTCCServiceMicrophone', 'kTCCServiceCamera',
    'kTCCServiceAppleEvents', 'kTCCServiceSystemPolicySysAdminFiles', 'kTCCServiceEndpointSecurityClient',
}
_TCC_EXTRA = {'kTCCServiceScreenCapture': 'T1113', 'kTCCServiceMicrophone': 'T1123',
              'kTCCServiceCamera': 'T1125', 'kTCCServiceListenEvent': 'T1056.001'}
_NON_USER_REASONS = {4, 5, 7}


def rules_tcc(events, hunt):
    for ev in events:
        service = ev.get('service')
        if service not in SENSITIVE_TCC or ev.get('auth_value') not in (2, 3):
            continue
        client = str(ev.get('client') or '')
        mitre = 'T1548.006' + (f",{_TCC_EXTRA[service]}" if service in _TCC_EXTRA else '')
        extra = {'service': service, 'service_label': ev.get('service_label'), 'client': client,
                 'auth_reason': ev.get('auth_reason_label')}
        label = ev.get('service_label')
        if not client.startswith('/'):
            continue  # identifiant de bundle : application installee, signature verifiee par tccd
        hidden = hidden_segments(client)
        if user_writable(client) or hidden or re.match(r'^/Users/[^/]+/Library/', client):
            direct = ev.get('auth_reason') in _NON_USER_REASONS
            hunt.add('tcc_grant_user_writable', f'TCC {label} accorde a {client}', 'critical' if direct else 'high',
                     mitre + (',T1564.001' if hidden else ''), [ev],
                     f"Autorisation {service} accordee a un binaire situe dans un emplacement modifiable "
                     f"par l'utilisateur" + (" ou cache" if hidden else '') +
                     (f" avec auth_reason '{ev.get('auth_reason_label')}' : une ecriture directe dans TCC.db "
                      "est probable (un consentement legitime donne 'user consent' / 'user set')." if direct
                      else '.'), **extra)
        elif os.path.basename(client) in _INTERPRETERS and service != 'kTCCServiceAppleEvents':
            hunt.add('tcc_grant_interpreter', f'TCC {label} accorde a l\'interpreteur {client}', 'medium', mitre,
                     [ev], 'Un interpreteur avec cette autorisation la transmet a tout script qu\'il execute.',
                     **extra)
        elif not ev.get('csreq_present') and not apple_location(client) and not client.startswith('/Applications/'):
            hunt.add('tcc_grant_unsigned', f'TCC {label} accorde a un binaire sans exigence de signature : {client}',
                     'medium', mitre, [ev], 'Entree sans csreq : aucune exigence de signature de code.', **extra)


# ============================================================================
# Quarantaine
# ============================================================================

SUSPICIOUS_TLDS = {'top', 'xyz', 'zip', 'click', 'shop', 'icu', 'cyou', 'rest', 'country', 'gq', 'tk', 'ml',
                   'cf', 'ga', 'buzz', 'monster', 'sbs', 'cfd', 'lol', 'mov', 'quest', 'bond', 'su'}
FILE_SHARE_HOSTS = ('transfer.sh', 'anonfiles', 'gofile.io', 'pastebin.com', 'paste.ee', 'cdn.discordapp.com',
                    'ngrok', 'trycloudflare.com', 'mega.nz', 'file.io', 'temp.sh', 'bashupload', '0x0.st')
SHORTENERS = ('bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rebrand.ly')


def _suspicious_host(host):
    if not host:
        return None
    if _is_ip(host):
        return 'adresse IP brute'
    if host.rsplit('.', 1)[-1] in SUSPICIOUS_TLDS:
        return f'TLD .{host.rsplit(".", 1)[-1]}'
    if any(host == h or host.endswith('.' + h) or h in host for h in FILE_SHARE_HOSTS):
        return 'hebergement de fichiers anonyme'
    if host in SHORTENERS:
        return 'raccourcisseur d\'URL'
    return None


def _exec_like(url):
    path = str(url or '').split('?', 1)[0].lower()
    return path.endswith(_EXEC_EXT)


def rules_quarantine(events, hunt):
    for ev in events:
        url = ev.get('data_url') or ''
        reason = _suspicious_host(ev.get('download_host')) or _suspicious_host(ev.get('origin_host'))
        extra = {'data_url': url, 'origin_url': ev.get('origin_url'), 'agent': ev.get('agent_name')}
        if reason:
            exe = _exec_like(url)
            hunt.add('quarantine_suspicious_origin', f'Telechargement depuis une origine suspecte ({reason}) : {url}',
                     'high' if exe else 'medium', 'T1204.002', [ev],
                     f"Fichier{' executable / image disque' if exe else ''} telecharge par "
                     f"{ev.get('agent_name') or ev.get('agent_bundle_id')} depuis {ev.get('origin_url') or url} : "
                     "verifier son execution (journal unifie, FSEvents, persistance).", **extra)
        elif ev.get('quarantine_type') == 'email attachment' and _exec_like(url or ev.get('origin_title')):
            hunt.add('quarantine_mail_executable', f'Piece jointe executable recue par messagerie : {url}', 'medium',
                     'T1566.001', [ev], 'Piece jointe de type executable / installeur.', **extra)


# ============================================================================
# Journal unifie
# ============================================================================

_UL_RULES = (
    ('ul_quarantine_removal', re.compile(
        r'\bxattr\b[^\n]*?(-[a-zA-Z]*d[a-zA-Z]*\s+(-[a-zA-Z]+\s+)*com\.apple\.quarantine|\s-[a-zA-Z]*c[a-zA-Z]*\b)'),
     'T1553.001', 'high', 'Attribut de quarantaine supprime (xattr)'),
    ('ul_gatekeeper_disabled', re.compile(r'\bspctl\b[^\n]*--(master-disable|global-disable|disable)\b'),
     'T1553.001', 'high', 'Gatekeeper desactive (spctl)'),
    ('ul_password_prompt', re.compile(
        r'osascript[^\n]*display dialog[^\n]*(hidden answer|password|mot de passe)|'
        r'display dialog[^\n]*(hidden answer)', re.I | re.S),
     'T1059.002,T1056.002', 'high', 'Fausse invite de mot de passe (osascript display dialog)'),
    ('ul_applescript_shell', re.compile(
        r'osascript[^\n]*do shell script[^\n]*(curl|base64|/tmp/|with administrator privileges)', re.I),
     'T1059.002', 'high', 'AppleScript lancant un shell'),
    ('ul_keychain_access', re.compile(
        r'\bsecurity\s+(dump-keychain|find-generic-password\s[^\n]*-[a-z]*[wg]|'
        r'find-internet-password\s[^\n]*-[a-z]*[wg]|export\s[^\n]*-k)|chainbreaker', re.I),
     'T1555.001', 'high', 'Extraction de secrets du trousseau (security)'),
    ('ul_download_exec', re.compile(r'\b(curl|wget)\b[^|;\n]*\|\s*(/bin/|/usr/bin/)?(ba|z|k|da)?sh\b', re.I),
     'T1105', 'critical', 'Telechargement execute (curl | sh)'),
    ('ul_curl_upload', re.compile(
        r'\bcurl\b[^\n]*(\s-F\s|\s--form\s|--data-binary\s+@|\s-T\s|--upload-file\s)[^\n]*'
        r'https?://(\d{1,3}(\.\d{1,3}){3}|[^/\s]+\.(' + '|'.join(sorted(SUSPICIOUS_TLDS)) + r'))\b', re.I),
     'T1041', 'high', 'Envoi de donnees par curl vers une destination suspecte'),
    ('ul_tcc_tamper', re.compile(r'\btccutil\s+reset\b|\bsqlite3\b[^\n]*TCC\.db', re.I),
     'T1548.006', 'high', 'Manipulation de la base TCC'),
    ('ul_log_tamper', re.compile(r'\blog\s+erase\b|\brm\s+-[a-zA-Z]*\s+[^\n]*/(private/)?var/(log|db/diagnostics)/',
                                 re.I),
     'T1070.002', 'high', 'Effacement des journaux systeme'),
    ('ul_silent_screencapture', re.compile(r'\bscreencapture\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*x', re.I),
     'T1113', 'medium', 'Capture d\'ecran silencieuse (screencapture -x)'),
)
_TCC_UPDATE_RE = re.compile(r'Update Access Record:\s*(kTCCService\w+)\s+for\s+(/[^\n]+?)\s+to\s+(Allowed|Limited)',
                            re.I)


def rules_unified(events, hunt):
    for ev in events:
        text = ' '.join(x for x in (ev.get('process_path') or ev.get('process'), ev.get('message')) if x)
        for rule, regex, mitre, sev, label in _UL_RULES:
            if regex.search(text):
                hunt.add(rule, f"{label} : {(ev.get('message') or '')[:140]}", sev, mitre, [ev],
                         f"Processus {ev.get('process')} (pid {ev.get('pid', '?')}).", process=ev.get('process'))
        m = _TCC_UPDATE_RE.search(ev.get('message') or '')
        if m and (user_writable(m.group(2)) or hidden_segments(m.group(2))
                  or re.match(r'^/Users/[^/]+/Library/', m.group(2))):
            service = m.group(1)
            hunt.add('ul_tcc_grant_suspicious', f'tccd : {service} accorde a {m.group(2)}', 'high',
                     'T1548.006' + (f',{_TCC_EXTRA[service]}' if service in _TCC_EXTRA else ''), [ev],
                     'Autorisation TCC enregistree pour un binaire dans un emplacement modifiable ou cache.',
                     service=service, client=m.group(2))


# ============================================================================
# FSEvents
# ============================================================================

MASS_RENAME = 50
MASS_REMOVE = 200
_FSE_IGNORE = ('/private/var/folders/', '/var/folders/', '/System/', '/private/var/db/', '/Library/Caches/',
               '/.Spotlight-V100/', '/.fseventsd/', '/private/var/vm/', '/.DocumentRevisions-V100/')
_COMMON_EXT = {'.tmp', '.db', '.sqlite', '.sqlite-wal', '.sqlite-shm', '.plist', '.json', '.log', '.txt',
               '.png', '.jpg', '.jpeg', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.html', '.js', '.css',
               '.py', '.swift', '.h', '.m', '.c', '.o', '.dylib', '.app', '.part', '.crdownload', '.download',
               '.lock', ''}


def _ignored(path):
    return path.startswith(_FSE_IGNORE) or '/Library/Caches/' in path or '/DerivedData/' in path \
        or '/node_modules/' in path or '/.Trash/' in path


def _staging_path(path):
    if _ignored(path):
        return False
    hidden = hidden_segments(os.path.dirname(path), _NOISY_HIDDEN)
    if hidden:
        return True
    if path.startswith(_TMP_PREFIXES + _SHARED_PREFIXES):
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1].lower()
        return ext in _EXEC_EXT or (not ext and not name.startswith(('com.apple', 'tmp', 'TemporaryItems')))
    return False


def rules_fsevents(events, hunt):
    files = [e for e in events if not fse.has(e, 'IsDirectory')]
    # Fichiers crees puis supprimes dans un dossier temporaire ou cache (staging nettoye)
    by_path = defaultdict(list)
    for ev in files:
        by_path[ev['path']].append(ev)
    staged = []
    for path, evs in by_path.items():
        created = any(fse.has(e, 'Created') for e in evs)
        removed = any(fse.has(e, 'Removed') for e in evs)
        if created and removed and _staging_path(path):
            staged.extend(evs)
    if staged:
        paths = sorted({e['path'] for e in staged})
        hunt.add('fsevents_staging_cleanup', f'{len(paths)} fichier(s) crees puis supprimes en zone '
                 f'temporaire / cachee : {", ".join(paths[:4])}', 'medium', 'T1070.004', staged,
                 'Fichiers de travail effaces apres usage (collecte, archive, charge) : nettoyage de traces.',
                 paths=paths[:30])
    # Renommages massifs vers une meme extension inhabituelle
    renamed = defaultdict(list)
    for ev in files:
        if fse.has(ev, 'Renamed') and not _ignored(ev['path']):
            ext = os.path.splitext(ev['path'])[1].lower()
            if ext not in _COMMON_EXT:
                renamed[ext].append(ev)
    for ext, evs in renamed.items():
        if len({e['path'] for e in evs}) >= MASS_RENAME:
            hunt.add('fsevents_mass_rename', f'{len(evs)} fichiers renommes en {ext}', 'high', 'T1486', evs,
                     'Renommage massif vers une extension commune : chiffrement par rancongiciel probable.',
                     extension=ext, count=len(evs))
    removed = [e for e in files if fse.has(e, 'Removed') and not _ignored(e['path'])
               and not e['path'].startswith(_TMP_PREFIXES)]
    if len({e['path'] for e in removed}) >= MASS_REMOVE:
        hunt.add('fsevents_mass_removal', f'{len(removed)} fichiers supprimes', 'medium', 'T1485', removed,
                 'Suppression massive de fichiers utilisateur (a confronter a une action legitime).',
                 count=len(removed))
    # Attribut etendu supprime sur une application ou un installeur telecharge
    for ev in events:
        p = ev['path']
        if fse.has(ev, 'ExtendedAttrRemoved') and (
                re.search(r'\.app$', p) or (_exec_like(p) and re.match(r'^/(Users/[^/]+/Downloads|Volumes)/', p))):
            hunt.add('fsevents_xattr_removed', f'Attribut etendu supprime sur {p}', 'medium', 'T1553.001', [ev],
                     "Suppression d'un attribut etendu (com.apple.quarantine ?) sur une application : "
                     'contournement de Gatekeeper possible, a confirmer (journal unifie, historique shell).',
                     path=p)
    # Nouveau plist launchd
    for ev in files:
        m = re.search(r'/Library/(LaunchAgents|LaunchDaemons)/([^/]+)\.plist$', ev['path'])
        if not m or not fse.has(ev, 'Created'):
            continue
        name = m.group(2)
        user_dir = ev['path'].startswith('/Users/')
        tech = 'T1543.001' if m.group(1) == 'LaunchAgents' else 'T1543.004'
        if name.startswith('com.apple.') and (user_dir or ev['path'].startswith('/Library/')):
            hunt.add('fsevents_launch_item_apple_name', f'Plist launchd au nom Apple cree hors /System : {ev["path"]}',
                     'medium', f'{tech},T1036.005', [ev],
                     'Apple n\'installe pas ses agents dans /Library ou ~/Library : usurpation probable.',
                     path=ev['path'])
        elif not name.startswith(VENDOR_PREFIXES):
            hunt.add('fsevents_launch_item_created', f'Nouveau plist launchd : {ev["path"]}', 'low', tech, [ev],
                     'Creation d\'un element de persistance launchd : analyser le plist.', path=ev['path'])


# ============================================================================
# Point d'entree
# ============================================================================

def run(kind, events, artifact):
    hunt = MacHunt(artifact)
    notes = []
    if kind in mf.UNIFIED_TYPES:
        rules_unified(events, hunt)
    elif kind == 'tcc':
        rules_tcc(events, hunt)
    elif kind == 'quarantine':
        rules_quarantine(events, hunt)
    elif kind == 'launchd_plist':
        rules_launchd(events, hunt)
    elif kind == 'emond_rules':
        rules_emond(events, hunt)
    elif kind == 'loginwindow_plist':
        rules_loginwindow(events, hunt)
    elif kind in ('crontab', 'periodic'):
        rules_scheduled(events, hunt, kind)
    elif kind == 'fsevents':
        rules_fsevents(events, hunt)
    else:
        notes.append(f'aucune regle de detection pour le type {kind}')
    findings, alerts = hunt.result()
    return findings, alerts, notes
