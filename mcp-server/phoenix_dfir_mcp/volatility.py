"""Integration de Volatility 3 (analyse forensique de la memoire vive).

Volatility 3 (https://github.com/volatilityfoundation/volatility3) s'installe
via pip (`pip install volatility3`) et fournit la commande `vol`. A defaut,
`python -m volatility3` / `vol.py` sont essayes.

Configuration :
- PHOENIX_VOLATILITY_CMD : commande explicite (ex: "/opt/vol/vol.py").
- PHOENIX_VOLATILITY_SYMBOLS : dossier de tables de symboles (hors-ligne /
  air-gapped ; sinon Volatility telecharge les PDB Microsoft a la demande).

Seuls des plugins en LECTURE de la liste blanche ci-dessous sont autorises
(aucun plugin d'extraction/dump ecrivant sur disque) : l'outil est pilote
par un LLM, la surface est volontairement restreinte. Sortie JSON
(`-r json`) parsee et tronquee.
"""

import json
import os
import shlex
import shutil
import subprocess  # nosec B404 - execution controlee (liste blanche, pas de shell)
import sys

# Plugins autorises -> description. 'pid' : le plugin accepte --pid.
PLUGINS = {
    'windows.info': {'desc': 'Profil du systeme (version, KDBG, horodatage du dump)', 'pid': False},
    'windows.pslist': {'desc': 'Processus actifs (EPROCESS)', 'pid': True},
    'windows.pstree': {'desc': 'Arborescence parent/enfant des processus', 'pid': True},
    'windows.psscan': {'desc': 'Scan des processus (y compris caches / termines)', 'pid': True},
    'windows.cmdline': {'desc': 'Lignes de commande des processus', 'pid': True},
    'windows.dlllist': {'desc': 'DLL chargees par processus', 'pid': True},
    'windows.handles': {'desc': 'Handles ouverts par processus', 'pid': True},
    'windows.malfind': {'desc': 'Regions memoire injectees (RWX, entetes MZ) - process hollowing', 'pid': True},
    'windows.netscan': {'desc': 'Connexions et sockets reseau (C2, beacons)', 'pid': False},
    'windows.netstat': {'desc': 'Connexions reseau actives', 'pid': False},
    'windows.svcscan': {'desc': 'Services Windows (persistance)', 'pid': False},
    'windows.envars': {'desc': "Variables d'environnement des processus", 'pid': True},
    'windows.getsids': {'desc': 'SIDs / comptes associes aux processus', 'pid': True},
    'windows.privileges': {'desc': 'Privileges des processus (SeDebugPrivilege...)', 'pid': True},
    'windows.registry.hivelist': {'desc': 'Ruches de registre presentes en memoire', 'pid': False},
    'windows.filescan': {'desc': 'Objets fichiers en memoire', 'pid': False},
    'linux.pslist': {'desc': 'Processus Linux', 'pid': True},
    'linux.pstree': {'desc': 'Arborescence des processus Linux', 'pid': True},
    'linux.bash': {'desc': 'Historique bash recupere en memoire', 'pid': True},
    'linux.malfind': {'desc': 'Regions memoire injectees (Linux)', 'pid': True},
}

_TIMEOUT_SECONDS = 1800  # les gros dumps (16 Go+) sont longs a traiter


def _find_command():
    """Localiser Volatility 3. Retourne la commande (liste) ou None."""
    explicit = os.environ.get('PHOENIX_VOLATILITY_CMD', '').strip()
    if explicit:
        return shlex.split(explicit)
    for name in ('vol', 'vol.py', 'volatility3'):
        path = shutil.which(name)
        if path:
            return [path]
    try:
        import importlib.util
        if importlib.util.find_spec('volatility3') is not None:
            return [sys.executable, '-m', 'volatility3']
    except (ImportError, ValueError):
        pass
    return None


def status():
    cmd = _find_command()
    return {
        'available': bool(cmd),
        'command': ' '.join(cmd) if cmd else None,
        'symbols_dir': os.environ.get('PHOENIX_VOLATILITY_SYMBOLS') or None,
        'plugins': {name: spec['desc'] for name, spec in sorted(PLUGINS.items())},
        'help': ("Installer Volatility 3 : pip install volatility3 (fournit la commande 'vol'), "
                 "ou definir PHOENIX_VOLATILITY_CMD. Hors-ligne, fournir les tables de symboles "
                 "via PHOENIX_VOLATILITY_SYMBOLS."),
    }


def _flatten(rows, out, max_rows, depth=0):
    """Aplatir la sortie arborescente JSON de Volatility (__children)."""
    for row in rows or []:
        if len(out) >= max_rows:
            return
        if not isinstance(row, dict):
            continue
        children = row.get('__children') or []
        flat = {k: v for k, v in row.items() if k != '__children' and v not in (None, '')}
        if depth:
            flat['_depth'] = depth
        out.append(flat)
        _flatten(children, out, max_rows, depth + 1)


def _count(rows):
    total = 0
    for row in rows or []:
        if isinstance(row, dict):
            total += 1 + _count(row.get('__children'))
    return total


def run(file_path, plugin, pid=None, max_rows=300):
    """Executer un plugin Volatility 3 (liste blanche) sur un dump memoire."""
    spec = PLUGINS.get(plugin)
    if not spec:
        return {'error': f"Plugin Volatility non autorise: {plugin}. Autorises: {sorted(PLUGINS)}"}
    if not os.path.isfile(file_path):
        return {'error': f"Dump memoire introuvable: {file_path}"}

    cmd = _find_command()
    if not cmd:
        st = status()
        return {'error': 'Volatility 3 introuvable.', 'help': st['help']}

    args = cmd + ['-q', '-r', 'json', '-f', file_path]
    symbols = os.environ.get('PHOENIX_VOLATILITY_SYMBOLS', '').strip()
    if symbols:
        args += ['-s', symbols]
    args.append(plugin)
    if pid is not None:
        if not spec['pid']:
            return {'error': f"Le plugin {plugin} n'accepte pas de filtre --pid"}
        pids = pid if isinstance(pid, list) else [pid]
        try:
            pids = [str(int(p)) for p in pids]
        except (TypeError, ValueError):
            return {'error': 'pid doit etre un entier (ou une liste d\'entiers)'}
        args += ['--pid'] + pids

    try:
        proc = subprocess.run(  # nosec B603 - arguments construits depuis une liste blanche
            args, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired:
        return {'error': f'Volatility a depasse le delai de {_TIMEOUT_SECONDS}s ({plugin})'}
    except OSError as e:
        return {'error': f"Impossible d'executer Volatility: {e}"}

    result = {
        'tool': 'volatility3',
        'plugin': plugin,
        'file': file_path,
        'command': ' '.join(args),
        'exit_code': proc.returncode,
    }
    try:
        data = json.loads(proc.stdout or 'null')
    except json.JSONDecodeError:
        data = None
    if isinstance(data, list):
        rows = []
        _flatten(data, rows, max_rows)
        result['total_rows'] = _count(data)
        result['rows'] = rows
        result['truncated'] = result['total_rows'] > len(rows)
    else:
        result['stdout'] = (proc.stdout or '')[-4000:]
        result['stderr'] = (proc.stderr or '')[-2000:]
        if proc.returncode != 0:
            result['error'] = (f"Volatility a echoue (code {proc.returncode}) : verifier le format "
                               "du dump et les tables de symboles.")
    return result
