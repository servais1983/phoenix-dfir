"""Integration des outils forensiques Eric Zimmermann (EZ Tools).

Les EZ Tools (https://ericzimmerman.github.io/) sont des binaires .NET :
sur Windows, les .exe s'executent directement ; sur Linux/macOS, les
versions .dll s'executent via le runtime `dotnet` (net6/net9).

Configuration :
- EZ_TOOLS_PATH : dossier racine contenant les outils (recherche recursive
  des <Outil>.dll / <Outil>.exe). Sans ce chemin, seuls les outils presents
  dans le PATH systeme sont utilises.

Chaque outil est execute avec une sortie CSV vers un dossier temporaire,
puis les CSV produits sont parses et retournes en JSON. En cas
d'indisponibilite, l'appelant est invite a utiliser les parsers natifs.
"""

import csv
import glob
import os
import shutil
import subprocess
import tempfile

# Outils supportes -> construction des arguments.
# '{file}' est remplace par l'artefact, '{out}' par le dossier CSV temporaire.
# 'input' indique si l'outil attend un fichier ('-f') ou un dossier ('-d').
EZ_TOOLS = {
    'EvtxECmd': {'args': ['-f', '{file}', '--csv', '{out}'], 'input': 'file',
                 'desc': 'Journaux Windows EVTX'},
    'PECmd': {'args': ['-f', '{file}', '--csv', '{out}'], 'input': 'file',
              'desc': 'Prefetch Windows (.pf)'},
    'LECmd': {'args': ['-f', '{file}', '--csv', '{out}'], 'input': 'file',
              'desc': 'Raccourcis Windows (.lnk)'},
    'JLECmd': {'args': ['-f', '{file}', '--csv', '{out}'], 'input': 'file',
               'desc': 'JumpLists Windows'},
    'MFTECmd': {'args': ['-f', '{file}', '--csv', '{out}'], 'input': 'file',
                'desc': 'NTFS $MFT / $J / $Boot / $SDS'},
    'AmcacheParser': {'args': ['-f', '{file}', '--csv', '{out}'], 'input': 'file',
                      'desc': 'Amcache.hve (preuves d\'execution)'},
    'AppCompatCacheParser': {'args': ['-f', '{file}', '--csv', '{out}'], 'input': 'file',
                             'desc': 'Shimcache depuis une ruche SYSTEM'},
    'RECmd': {'args': ['-f', '{file}', '--sa', '*', '--csv', '{out}'], 'input': 'file',
              'desc': 'Ruches registre Windows'},
    'SBECmd': {'args': ['-d', '{file}', '--csv', '{out}'], 'input': 'dir',
               'desc': 'ShellBags (dossier de ruches utilisateur)'},
    'SrumECmd': {'args': ['-f', '{file}', '--csv', '{out}'], 'input': 'file',
                 'desc': 'SRUM (SRUDB.dat, activite reseau/processus)'},
    'SQLECmd': {'args': ['-f', '{file}', '--csv', '{out}'], 'input': 'file',
                'desc': 'Bases SQLite (historique navigateurs...)'},
    'WxTCmd': {'args': ['-f', '{file}', '--csv', '{out}'], 'input': 'file',
               'desc': 'Windows Timeline (ActivitiesCache.db)'},
}

_TIMEOUT_SECONDS = 600


def _find_binary(tool):
    """Localiser l'outil : PATH systeme, puis EZ_TOOLS_PATH (recursif).

    Retourne (commande_liste, mode) ou (None, None).
    """
    exe = shutil.which(tool) or shutil.which(f'{tool}.exe')
    if exe:
        return [exe], 'exe'

    root = os.environ.get('EZ_TOOLS_PATH', '')
    if root and os.path.isdir(root):
        for pattern, mode in ((f'**/{tool}.exe', 'exe'), (f'**/{tool}.dll', 'dll')):
            matches = glob.glob(os.path.join(root, pattern), recursive=True)
            if matches:
                path = sorted(matches)[0]
                if mode == 'exe':
                    return [path], 'exe'
                dotnet = shutil.which('dotnet')
                if dotnet:
                    return [dotnet, path], 'dll'
    return None, None


def status():
    """Etat de l'installation EZ Tools : dotnet, chemin, outils disponibles."""
    root = os.environ.get('EZ_TOOLS_PATH', '')
    available, missing = {}, []
    for tool, spec in sorted(EZ_TOOLS.items()):
        cmd, mode = _find_binary(tool)
        if cmd:
            available[tool] = {'command': ' '.join(cmd), 'mode': mode, 'description': spec['desc']}
        else:
            missing.append(tool)
    return {
        'ez_tools_path': root or None,
        'dotnet': shutil.which('dotnet') or None,
        'available': available,
        'missing': missing,
        'help': ('Installer les EZ Tools depuis https://ericzimmerman.github.io/ '
                 "(Get-ZimmermanTools) puis definir EZ_TOOLS_PATH vers le dossier d'installation. "
                 'Sous Linux/macOS, installer aussi le runtime dotnet. En cas d\'absence, '
                 'utiliser les parsers natifs Phoenix (parse_evtx, parse_prefetch, parse_lnk...).'),
    }


def _read_csv_outputs(out_dir, max_rows):
    """Lire les CSV produits par un outil EZ et retourner un apercu structure."""
    outputs = []
    for path in sorted(glob.glob(os.path.join(out_dir, '**/*.csv'), recursive=True)):
        rows = []
        total = 0
        try:
            with open(path, 'r', encoding='utf-8-sig', errors='replace', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    total += 1
                    if len(rows) < max_rows:
                        rows.append({k: v for k, v in row.items() if v})
            outputs.append({'csv': os.path.basename(path), 'total_rows': total, 'rows': rows})
        except Exception as e:
            outputs.append({'csv': os.path.basename(path), 'error': str(e)})
    return outputs


def run(tool, file_path, max_rows=200):
    """Executer un outil EZ sur un artefact et retourner sa sortie CSV parsee."""
    spec = EZ_TOOLS.get(tool)
    if not spec:
        return {'error': f"Outil Zimmermann non supporte: {tool}. Supportes: {sorted(EZ_TOOLS)}"}

    expects_dir = spec['input'] == 'dir'
    if expects_dir and not os.path.isdir(file_path):
        return {'error': f"{tool} attend un dossier, chemin invalide: {file_path}"}
    if not expects_dir and not os.path.isfile(file_path):
        return {'error': f"Fichier introuvable: {file_path}"}

    cmd_prefix, _mode = _find_binary(tool)
    if not cmd_prefix:
        st = status()
        return {
            'error': f"{tool} introuvable (EZ_TOOLS_PATH={st['ez_tools_path']}, dotnet={st['dotnet']}).",
            'help': st['help'],
        }

    out_dir = tempfile.mkdtemp(prefix=f'phoenix_ez_{tool.lower()}_')
    args = [a.replace('{file}', file_path).replace('{out}', out_dir) for a in spec['args']]
    try:
        proc = subprocess.run(
            cmd_prefix + args,
            capture_output=True, text=True, timeout=_TIMEOUT_SECONDS, check=False,
        )
        outputs = _read_csv_outputs(out_dir, max_rows)
        result = {
            'tool': tool,
            'file': file_path,
            'exit_code': proc.returncode,
            'outputs': outputs,
        }
        if not outputs:
            # Pas de CSV : renvoyer la sortie console pour diagnostic
            result['stdout'] = (proc.stdout or '')[-4000:]
            result['stderr'] = (proc.stderr or '')[-2000:]
        return result
    except subprocess.TimeoutExpired:
        return {'error': f'{tool} a depasse le delai de {_TIMEOUT_SECONDS}s sur {file_path}'}
    except OSError as e:
        return {'error': f"Impossible d'executer {tool}: {e}"}
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
