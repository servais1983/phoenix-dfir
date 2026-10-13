"""Integration de Hayabusa (Yamato Security) : timeline de detection EVTX.

Hayabusa (https://github.com/Yamato-Security/hayabusa) applique des milliers
de regles Sigma / Hayabusa sur les journaux Windows et produit une timeline
des alertes. Phoenix l'execute en `json-timeline` (sortie JSONL) puis
retourne les alertes triees par severite.

Configuration :
- PHOENIX_HAYABUSA_CMD : chemin du binaire (sinon `hayabusa` dans le PATH).
- PHOENIX_HAYABUSA_RULES : dossier de regles (sinon `rules/` a cote du binaire).

Le binaire est execute depuis son propre dossier (il y cherche `rules/config`).
"""

import glob
import json
import os
import shutil
import subprocess  # nosec B404 - execution controlee (pas de shell)
import tempfile

MIN_LEVELS = ('informational', 'low', 'medium', 'high', 'critical')
_LEVEL_ORDER = {'crit': 0, 'critical': 0, 'high': 1, 'med': 2, 'medium': 2,
                'low': 3, 'info': 4, 'informational': 4}
_TIMEOUT_SECONDS = 1800


def _find_binary():
    explicit = os.environ.get('PHOENIX_HAYABUSA_CMD', '').strip()
    if explicit and os.path.isfile(explicit):
        return explicit
    for name in ('hayabusa', 'hayabusa.exe'):
        path = shutil.which(name)
        if path:
            return path
    # Binaire versionne (hayabusa-3.x.y-lin-x64-musl) dans le PATH courant
    for directory in os.environ.get('PATH', '').split(os.pathsep):
        matches = sorted(glob.glob(os.path.join(directory, 'hayabusa-*')))
        for match in matches:
            if os.access(match, os.X_OK) and not match.endswith('.zip'):
                return match
    return None


def _rules_dir(binary):
    explicit = os.environ.get('PHOENIX_HAYABUSA_RULES', '').strip()
    if explicit:
        return explicit
    if binary:
        candidate = os.path.join(os.path.dirname(os.path.realpath(binary)), 'rules')
        if os.path.isdir(candidate):
            return candidate
    return None


def status():
    binary = _find_binary()
    return {
        'available': bool(binary),
        'binary': binary,
        'rules_dir': _rules_dir(binary),
        'help': ("Installer Hayabusa depuis https://github.com/Yamato-Security/hayabusa/releases "
                 "(archive lin-x64-musl sous Linux/Docker) puis definir PHOENIX_HAYABUSA_CMD, "
                 "ou utiliser sigma_scan (26 regles Sigma integrees) en repli."),
    }


def _parse_jsonl(path, max_alerts):
    alerts, total, by_level = [], 0, {}
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            total += 1
            level = str(rec.get('Level') or rec.get('level') or 'info').lower()
            by_level[level] = by_level.get(level, 0) + 1
            alerts.append({
                'timestamp': rec.get('Timestamp'),
                'computer': rec.get('Computer'),
                'channel': rec.get('Channel'),
                'event_id': rec.get('EventID'),
                'level': level,
                'rule': rec.get('RuleTitle'),
                'mitre_tactics': rec.get('MitreTactics'),
                'mitre_tags': rec.get('MitreTags'),
                'record_id': rec.get('RecordID'),
                'details': rec.get('Details'),
            })
    alerts.sort(key=lambda a: (_LEVEL_ORDER.get(a['level'], 5), str(a['timestamp'] or '')))
    return {'total_alerts': total, 'by_level': by_level, 'alerts': alerts[:max_alerts],
            'truncated': total > max_alerts}


def run(file_path, min_level='medium', max_alerts=300):
    """Executer Hayabusa json-timeline sur un fichier EVTX ou un dossier d'EVTX."""
    if min_level not in MIN_LEVELS:
        return {'error': f"min_level invalide: {min_level}. Valeurs: {list(MIN_LEVELS)}"}
    is_dir = os.path.isdir(file_path)
    if not is_dir and not os.path.isfile(file_path):
        return {'error': f"Chemin introuvable: {file_path}"}

    binary = _find_binary()
    if not binary:
        st = status()
        return {'error': 'Hayabusa introuvable.', 'help': st['help']}

    out_dir = tempfile.mkdtemp(prefix='phoenix_hayabusa_')
    out_file = os.path.join(out_dir, 'timeline.jsonl')
    args = [binary, 'json-timeline', '-d' if is_dir else '-f', file_path,
            '-L', '-o', out_file, '-m', min_level, '-w', '-q', '-C', '-U']
    rules = _rules_dir(binary)
    if rules:
        args += ['-r', rules]
    try:
        proc = subprocess.run(  # nosec B603 - arguments fixes, pas de shell
            args, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS, check=False,
            cwd=os.path.dirname(os.path.realpath(binary)),
        )
        result = {'tool': 'hayabusa', 'file': file_path, 'min_level': min_level,
                  'command': ' '.join(args), 'exit_code': proc.returncode}
        if os.path.isfile(out_file):
            result.update(_parse_jsonl(out_file, max_alerts))
        else:
            result['stdout'] = (proc.stdout or '')[-4000:]
            result['stderr'] = (proc.stderr or '')[-2000:]
            if proc.returncode != 0:
                result['error'] = f'Hayabusa a echoue (code {proc.returncode}).'
        return result
    except subprocess.TimeoutExpired:
        return {'error': f'Hayabusa a depasse le delai de {_TIMEOUT_SECONDS}s sur {file_path}'}
    except OSError as e:
        return {'error': f"Impossible d'executer Hayabusa: {e}"}
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)
