"""Bac a sable non privilegie pour les binaires forensiques externes.

Les outils externes (Sleuth Kit : mmls, fls, icat, img_stat, fsstat ;
Volatility 3 ; Hayabusa ; EZ Tools) parsent des donnees CONTROLEES PAR
L'ATTAQUANT : une image disque ou un dump memoire forge peut viser une
vulnerabilite du parser. Ce module est le point d'execution unique de ces
binaires ; le mode est choisi par PHOENIX_TOOL_SANDBOX :

- none (defaut)  : execution directe (comportement historique) ;
- docker         : conteneur jetable sans reseau, racine en lecture seule,
                   aucune capability, no-new-privileges, limites pids /
                   memoire / CPU, utilisateur non root, /tmp en tmpfs noexec ;
- bwrap          : bubblewrap, tous les namespaces isoles (reseau inclus),
                   /usr /lib /bin en lecture seule, --die-with-parent,
                   --new-session.

Dans les deux modes isoles, l'outil ne voit que :
    /evidence/<nom>  : chaque preuve, en LECTURE SEULE ;
    /out             : le dossier de sortie du run (seul point d'ecriture) ;
    /tools/<nom>     : dossiers d'outils declares (regles, symboles, DLL), en lecture seule.
Les arguments portant un chemin hote sont reecrits vers ces chemins.

Si le bac a sable demande est indisponible, l'execution est REFUSEE avec une
erreur explicite (fail closed), sauf PHOENIX_TOOL_SANDBOX_FALLBACK=none.

Variables : PHOENIX_SANDBOX_IMAGE (image docker, defaut phoenix-dfir-tools:latest),
PHOENIX_SANDBOX_MEMORY (defaut 4g), PHOENIX_SANDBOX_CPUS (defaut 2),
PHOENIX_SANDBOX_PIDS (defaut 256), PHOENIX_SANDBOX_USER (defaut uid:gid courant),
PHOENIX_SANDBOX_RO_PATHS (dossiers systeme supplementaires montes en lecture
seule au meme chemin, separes par ':').
"""

import os
import re
import secrets
import shutil
import subprocess  # nosec B404 - point d'execution unique, arguments en liste, jamais de shell
import threading
import time

MODES = ('none', 'docker', 'bwrap')
DEFAULT_IMAGE = 'phoenix-dfir-tools:latest'
DEFAULT_MEMORY = '4g'
DEFAULT_CPUS = '2'
DEFAULT_PIDS = '256'

EVIDENCE_ROOT = '/evidence'
OUT_ROOT = '/out'
TOOLS_ROOT = '/tools'
# /tmp DANS le bac a sable : tmpfs prive et jetable (jamais le /tmp de l'hote)
SANDBOX_TMP = '/tmp'  # nosec B108
_DOCKER_TMPFS = SANDBOX_TMP + ':rw,noexec,nosuid,size=512m'

# Images segmentees (E01 -> E02..., .001 -> .002...) : le dossier parent est monte
SEGMENTED_EXT = ('.e01', '.ex01', '.l01', '.lx01', '.s01', '.001')

# Dossiers systeme montes en lecture seule par bubblewrap (lien symbolique
# reproduit tel quel sur les systemes usr-merge)
_BWRAP_SYSTEM = ('/usr', '/lib', '/lib64', '/lib32', '/bin', '/sbin')
_BWRAP_ETC = ('/etc/ld.so.cache', '/etc/ld.so.conf', '/etc/ld.so.conf.d', '/etc/alternatives',
              '/etc/localtime', '/etc/passwd', '/etc/group', '/etc/nsswitch.conf')
_SAFE_PATH = re.compile(r'^[^\x00-\x1f,:]+$')
_PROBE_TTL = 60
_probe_lock = threading.Lock()
_probe_cache = {}


class SandboxUnavailable(OSError):
    """Bac a sable demande indisponible : execution refusee (fail closed)."""


class SandboxError(ValueError):
    """Chemin non montable (caracteres interdits) : execution refusee."""


# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

def requested_mode():
    value = os.environ.get('PHOENIX_TOOL_SANDBOX', 'none').strip().lower() or 'none'
    return value if value in MODES else 'invalid:' + value


def fallback_allowed():
    return os.environ.get('PHOENIX_TOOL_SANDBOX_FALLBACK', '').strip().lower() == 'none'


def image():
    return os.environ.get('PHOENIX_SANDBOX_IMAGE', '').strip() or DEFAULT_IMAGE


def limits():
    return {
        'memory': os.environ.get('PHOENIX_SANDBOX_MEMORY', '').strip() or DEFAULT_MEMORY,
        'cpus': os.environ.get('PHOENIX_SANDBOX_CPUS', '').strip() or DEFAULT_CPUS,
        'pids': os.environ.get('PHOENIX_SANDBOX_PIDS', '').strip() or DEFAULT_PIDS,
    }


def _user():
    explicit = os.environ.get('PHOENIX_SANDBOX_USER', '').strip()
    if explicit:
        return explicit
    getuid = getattr(os, 'getuid', None)
    getgid = getattr(os, 'getgid', None)
    return f'{getuid()}:{getgid()}' if getuid and getgid else '65534:65534'


def _extra_ro_paths():
    raw = os.environ.get('PHOENIX_SANDBOX_RO_PATHS', '')
    return [p for p in raw.split(os.pathsep) if p.strip()]


# ----------------------------------------------------------------------------
# Disponibilite
# ----------------------------------------------------------------------------

def _cached_probe(key, func):
    now = time.monotonic()
    with _probe_lock:
        hit = _probe_cache.get(key)
        if hit and now - hit[0] < _PROBE_TTL:
            return hit[1]
    result = func()
    with _probe_lock:
        _probe_cache[key] = (now, result)
    return result


def reset_cache():
    with _probe_lock:
        _probe_cache.clear()


def _probe_docker():
    docker = shutil.which('docker')
    if not docker:
        return False, "binaire 'docker' introuvable"
    try:
        proc = subprocess.run([docker, 'image', 'inspect', image()], capture_output=True,  # nosec B603
                              text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f'docker injoignable : {exc}'
    if proc.returncode != 0:
        return False, f"image '{image()}' absente ou demon docker injoignable"
    return True, None


def _probe_bwrap():
    bwrap = shutil.which('bwrap')
    if not bwrap:
        return False, "binaire 'bwrap' (bubblewrap) introuvable"
    true_bin = shutil.which('true') or '/bin/true'
    argv, _ = wrap_bwrap([true_bin], bwrap=bwrap)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=20, check=False)  # nosec B603
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f'bubblewrap inutilisable : {exc}'
    if proc.returncode != 0:
        return False, ('bubblewrap inutilisable (namespaces utilisateur desactives ?) : '
                       + (proc.stderr or '').strip()[:200])
    return True, None


def probe(mode=None):
    """(disponible, raison) pour un mode isole (resultat mis en cache 60 s)."""
    mode = mode or requested_mode()
    if mode == 'none':
        return True, None
    if mode == 'docker':
        return _cached_probe(('docker', image()), _probe_docker)
    if mode == 'bwrap':
        return _cached_probe(('bwrap',), _probe_bwrap)
    return False, f"PHOENIX_TOOL_SANDBOX invalide ({mode.split(':', 1)[-1]}) : none, docker ou bwrap"


def effective_mode():
    """Mode reellement applique : le mode demande, 'none' en repli explicite,
    ou SandboxUnavailable (fail closed)."""
    mode = requested_mode()
    if mode == 'none':
        return 'none'
    ok, reason = probe(mode)
    if ok:
        return mode
    if fallback_allowed():
        return 'none'
    raise SandboxUnavailable(
        f"Bac a sable '{mode}' indisponible ({reason}) : execution de l'outil externe refusee. "
        "Installer le bac a sable, ou definir PHOENIX_TOOL_SANDBOX_FALLBACK=none pour autoriser "
        "explicitement l'execution non isolee.")


def status():
    """Etat du bac a sable, expose dans chaque *_status."""
    mode = requested_mode()
    out = {'mode': mode, 'fallback': 'none' if fallback_allowed() else 'refuse'}
    if mode == 'none':
        out.update(available=True, effective='none', isolated=False)
        return out
    ok, reason = probe(mode)
    out['available'] = ok
    if ok:
        out.update(effective=mode, isolated=True)
    else:
        out.update(effective='none' if fallback_allowed() else None, isolated=False, reason=reason)
    if mode == 'docker':
        out['image'] = image()
        out['limits'] = limits()
    return out


def check():
    """None si les outils externes peuvent s'executer, sinon un dict d'erreur."""
    try:
        effective_mode()
    except SandboxUnavailable as exc:
        return {'error': str(exc), 'sandbox': status()}
    return None


# ----------------------------------------------------------------------------
# Reecriture des chemins
# ----------------------------------------------------------------------------

def _safe_name(path):
    name = os.path.basename(os.path.normpath(path)) or 'root'
    return re.sub(r'[^A-Za-z0-9._-]', '_', name)[:80] or 'x'


def _checked(path):
    if not isinstance(path, str) or not _SAFE_PATH.match(path):
        raise SandboxError(f'Chemin non montable dans le bac a sable : {path!r}')
    return os.path.abspath(path)


class Mounts:
    """Table de montage d'un run : chemin hote -> chemin dans le bac a sable."""

    def __init__(self):
        self.binds = []      # (hote, cible, lecture_seule)
        self.mapping = []    # (prefixe hote, prefixe cible) ; plus long en premier
        self._names = set()

    def _unique(self, root, name):
        candidate, n = f'{root}/{name}', 2
        while candidate in self._names:
            candidate = f'{root}/{name}_{n}'
            n += 1
        self._names.add(candidate)
        return candidate

    def _map(self, host, target):
        for variant in {host, os.path.realpath(host)}:
            self.mapping.append((variant.rstrip('/') or '/', target))
        self.mapping.sort(key=lambda m: -len(m[0]))

    def add(self, path, root, readonly=True, same_path=False):
        host = _checked(path)
        if any(h == host for h, _t, _r in self.binds):
            return
        if same_path:
            target = host
        elif root == EVIDENCE_ROOT and host.lower().endswith(SEGMENTED_EXT):
            parent = os.path.dirname(host)
            target_dir = self._unique(root, _safe_name(parent))
            self.binds.append((parent, target_dir, True))
            self._map(parent, target_dir)
            return
        elif root == OUT_ROOT:
            target = OUT_ROOT
        else:
            target = self._unique(root, _safe_name(host))
        self.binds.append((host, target, readonly))
        self._map(host, target)

    def rewrite(self, arg):
        """Reecrire un argument portant un chemin hote monte (egal ou sous-chemin)."""
        if not isinstance(arg, str) or not arg.startswith('/'):
            return arg
        norm = os.path.normpath(arg)
        for host, target in self.mapping:
            if norm == host:
                return target
            if norm.startswith(host + '/'):
                return target + norm[len(host):]
        return arg


def _mounts(evidence, output_dir, tool_paths):
    m = Mounts()
    for path in evidence or ():
        if path:
            m.add(path, EVIDENCE_ROOT)
    if output_dir:
        m.add(output_dir, OUT_ROOT, readonly=False)
    for path in tool_paths or ():
        if path:
            m.add(path, TOOLS_ROOT)
    return m


def _container_argv0(argv0, mounts):
    rewritten = mounts.rewrite(argv0)
    if rewritten != argv0:
        return rewritten
    name = os.path.basename(argv0)
    # Interprete Python de l'hote : 'python3' de l'image
    return 'python3' if re.fullmatch(r'python3(\.\d+)?', name) else name


def wrap_docker(argv, evidence=(), output_dir=None, tool_paths=(), cwd=None, name=None):
    """Commande docker run isolee. Retourne (argv, Mounts). Fonction pure."""
    m = _mounts(evidence, output_dir, tool_paths)
    lim = limits()
    cmd = ['docker', 'run', '--rm', '--init', '--network', 'none', '--read-only',
           '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
           '--pids-limit', lim['pids'], '--memory', lim['memory'], '--cpus', lim['cpus'],
           '--user', _user(), '--tmpfs', _DOCKER_TMPFS,
           '-e', 'HOME=' + SANDBOX_TMP]
    if name:
        cmd += ['--name', name]
    for path in _extra_ro_paths():
        host = _checked(path)
        cmd += ['-v', f'{host}:{host}:ro']
    for host, target, readonly in m.binds:
        cmd += ['-v', f"{host}:{target}:{'ro' if readonly else 'rw'}"]
    if cwd:
        cmd += ['-w', m.rewrite(os.path.abspath(cwd))]
    cmd.append(image())
    cmd.append(_container_argv0(argv[0], m))
    cmd.extend(m.rewrite(a) for a in argv[1:])
    return cmd, m


def wrap_bwrap(argv, evidence=(), output_dir=None, tool_paths=(), cwd=None, bwrap='bwrap'):
    """Commande bubblewrap isolee. Retourne (argv, Mounts). Fonction pure (hors
    lecture des liens symboliques systeme)."""
    m = _mounts(evidence, output_dir, tool_paths)
    cmd = [bwrap, '--unshare-all', '--die-with-parent', '--new-session']
    if getattr(os, 'geteuid', lambda: -1)() == 0:
        cmd += ['--cap-drop', 'ALL']  # root : retirer explicitement toutes les capabilities
    cmd += ['--clearenv', '--setenv', 'PATH', '/usr/local/bin:/usr/bin:/bin',
            '--setenv', 'HOME', SANDBOX_TMP, '--setenv', 'LANG', 'C.UTF-8']
    for path in _BWRAP_SYSTEM:
        if os.path.islink(path):
            cmd += ['--symlink', os.readlink(path), path]
        elif path == '/usr':
            cmd += ['--ro-bind', path, path]
        else:
            cmd += ['--ro-bind-try', path, path]
    for path in _BWRAP_ETC:
        cmd += ['--ro-bind-try', path, path]
    for path in _extra_ro_paths():
        host = _checked(path)
        cmd += ['--ro-bind', host, host]
    cmd += ['--proc', '/proc', '--dev', '/dev', '--tmpfs', SANDBOX_TMP]
    for host, target, readonly in m.binds:
        cmd += ['--ro-bind' if readonly else '--bind', host, target]
    cmd += ['--chdir', m.rewrite(os.path.abspath(cwd)) if cwd else SANDBOX_TMP]
    cmd.append('--')
    cmd.append(m.rewrite(argv[0]))
    cmd.extend(m.rewrite(a) for a in argv[1:])
    return cmd, m


def wrap(argv, evidence=(), output_dir=None, tool_paths=(), cwd=None, mode=None, name=None):
    """(argv_effectif, cwd_hote, nom_conteneur) pour le mode donne."""
    mode = mode or effective_mode()
    if mode == 'docker':
        name = name or f'phoenix-sbx-{secrets.token_hex(6)}'
        cmd, _m = wrap_docker(argv, evidence, output_dir, tool_paths, cwd, name=name)
        cmd[0] = shutil.which('docker') or 'docker'
        return cmd, None, name
    if mode == 'bwrap':
        cmd, _m = wrap_bwrap(argv, evidence, output_dir, tool_paths, cwd,
                             bwrap=shutil.which('bwrap') or 'bwrap')
        return cmd, None, None
    return list(argv), cwd, None


# ----------------------------------------------------------------------------
# Execution
# ----------------------------------------------------------------------------

def _docker_kill(name):
    if not name:
        return
    try:
        subprocess.run([shutil.which('docker') or 'docker', 'kill', name], capture_output=True,  # nosec B603
                       timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


class SandboxedPopen:
    """Popen d'un outil isole : kill() abat aussi le conteneur (le client docker
    tue seul laisserait le conteneur tourner)."""

    def __init__(self, proc, container=None):
        self._proc = proc
        self.container = container

    def __getattr__(self, item):
        return getattr(self._proc, item)

    def kill(self):
        self._proc.kill()
        _docker_kill(self.container)


def popen(argv, evidence=(), output_dir=None, tool_paths=(), cwd=None, **kwargs):
    """subprocess.Popen confine (streaming de stdout conserve dans tous les modes)."""
    mode = effective_mode()
    cmd, host_cwd, name = wrap(argv, evidence, output_dir, tool_paths, cwd, mode=mode)
    if host_cwd:
        kwargs['cwd'] = host_cwd
    proc = subprocess.Popen(cmd, **kwargs)  # nosec B603 - liste d'arguments, pas de shell
    return proc if mode == 'none' else SandboxedPopen(proc, name)


def run(argv, evidence=(), output_dir=None, tool_paths=(), cwd=None, timeout=None, text=True):
    """subprocess.run confine (capture stdout / stderr). Leve TimeoutExpired."""
    mode = effective_mode()
    cmd, host_cwd, name = wrap(argv, evidence, output_dir, tool_paths, cwd, mode=mode)
    if mode == 'none':
        return subprocess.run(cmd, capture_output=True, text=text, timeout=timeout,  # nosec B603
                              check=False, cwd=host_cwd)
    try:
        return subprocess.run(cmd, capture_output=True, text=text, timeout=timeout,  # nosec B603
                              check=False)
    except subprocess.TimeoutExpired:
        _docker_kill(name)
        raise
