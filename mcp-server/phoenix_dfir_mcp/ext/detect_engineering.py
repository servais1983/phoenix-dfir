"""Ingenierie de detection : regles Sigma et YARA generees a partir des constats.

- detect_generate_sigma : a partir des evenements qui etayent un constat
  (EventID, Image, fragments de CommandLine, ParentImage, ServiceName,
  ImagePath, TargetObject, ScriptBlockText, message syslog...), une regle
  Sigma par forme d'evenement : title, id (uuid deterministe), status
  experimental, description, references, logsource, detection (selection +
  condition), falsepositives, level, tags attack.tXXXX.
- detect_test_rule : evalue la regle sur la super-timeline du cas (elle doit
  correspondre aux evenements malveillants cites) et sur un corpus benin
  (defaut eval/suite/benign_admin_activity) pour mesurer les faux positifs.
  L'evaluateur couvre le sous-ensemble Sigma genere : modificateurs contains,
  startswith, endswith, all, egalite ; liste = OU, champs d'une selection = ET ;
  conditions 'selection' et 'selection and not filter'. Correspondance
  insensible a la casse, logsource non filtrant.
- detect_generate_yara : regle YARA pour un fichier extrait / carve (chaines
  distinctives ascii / wide absentes du corpus benin, condition N of them,
  en-tete MZ si executable), testee sur les fichiers du cas et le corpus benin.

Les regles sont ecrites dans <case_dir>/detections/ (fichiers
phoenix_detection_*, index phoenix_detection_index.json) et listees dans
l'annexe du rapport.
"""

import datetime
import hashlib
import json
import math
import os
import re
import uuid

from .. import evidence_db, graph, memory, pathpolicy, toolkit
from . import _internal

AGENT = ('detection', 'Agent Ingenierie de detection')
READONLY = ('detect_test_rule',)
PHASE_TOOLS = {
    'contre_analyse': ('detect_generate_sigma', 'detect_test_rule', 'detect_generate_yara'),
    'rapport': ('detect_generate_sigma', 'detect_test_rule', 'detect_generate_yara'),
}

PREFIX = 'phoenix_detection_'
INDEX_FILE = memory.DETECTIONS_INDEX
_internal.register(names=(INDEX_FILE,), prefixes=(PREFIX,))

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DEFAULT_BENIGN = os.path.join(_REPO, 'eval', 'suite', 'benign_admin_activity')
_SKIP_CORPUS = ('ground_truth.json',)
_NAMESPACE = uuid.UUID('5b0e4d1c-7a3f-4f62-9d55-2f6c1e8a9b10')
_LEVELS = {'critical': 'critical', 'high': 'high', 'medium': 'medium', 'low': 'low',
           'info': 'informational'}
MAX_CORPUS_BYTES = 20 * 1024 * 1024


# ============================================================================
# Evenements -> champs
# ============================================================================

_CANON = {
    'Image': ('Image', 'NewProcessName', 'ImageFileName', 'ProcessName'),
    'ParentImage': ('ParentImage', 'ParentProcessName'),
    'CommandLine': ('CommandLine', 'ProcessCommandLine'),
    'EventID': ('EventID', 'event_id', 'EventId'),
    'Computer': ('Computer', 'computer', 'host'),
    'User': ('User', 'TargetUserName', 'SubjectUserName', 'user'),
    'message': ('message', 'raw', 'event'),
}


def event_fields(row):
    """Champs d'un evenement indexe (colonnes + cle=valeur du texte), avec alias canoniques."""
    fields = dict(graph.parse_kv(row.get('text') or ''))
    for col, key in (('host', 'host'), ('user', 'user'), ('process', 'process'),
                     ('event_id', 'event_id')):
        if row.get(col) and key not in fields:
            fields[key] = str(row[col])
    for canon, keys in _CANON.items():
        if canon not in fields:
            for k in keys:
                if fields.get(k):
                    fields[canon] = fields[k]
                    break
    return fields


def corpus_events(directory):
    """Evenements d'un corpus de fichiers (parsers natifs, sans indexation)."""
    events, files = [], []
    for root, _dirs, names in os.walk(directory):
        for name in sorted(names):
            if name in _SKIP_CORPUS or toolkit.is_internal_file(name):
                continue
            path = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()
            tool = {'.evtx': 'parse_evtx', '.csv': 'parse_csv', '.json': 'parse_json_file'}.get(
                ext, 'parse_log_file')
            try:
                if os.path.getsize(path) > MAX_CORPUS_BYTES:
                    continue
                result = toolkit.TOOLS[tool]['func'](file_path=path)
            except Exception:  # nosec B112 - fichier du corpus illisible : ignore
                continue
            if not isinstance(result, dict) or result.get('error'):
                continue
            files.append(os.path.relpath(path, directory))
            for raw in evidence_db._event_rows(result):
                ev = evidence_db.normalize_event(raw)
                ev['artifact'] = os.path.relpath(path, directory)
                events.append(ev)
    return events, files


def _resolve_corpus(benign_dir):
    if not benign_dir:
        if os.path.isdir(DEFAULT_BENIGN):
            return DEFAULT_BENIGN, None  # corpus de reference livre avec Phoenix (lecture seule)
        return None, None
    denied = pathpolicy.check(benign_dir)
    if denied:
        return None, denied
    if not os.path.isdir(benign_dir):
        return None, {'error': f"Corpus benin introuvable : {benign_dir}"}
    return benign_dir, None


# ============================================================================
# Sigma : generation
# ============================================================================

_KEYWORDS = ('-encodedcommand', '-enc', '-noprofile', '-nop', '-windowstyle hidden', '-w hidden',
             '-executionpolicy bypass', '-exec bypass', '-ep bypass', 'bypass', 'hidden',
             'downloadstring', 'downloadfile', 'invoke-expression', 'iex', 'frombase64string',
             'net.webclient', 'invoke-webrequest', 'start-bitstransfer', '-urlcache', '/transfer',
             'javascript:', 'delete shadows', 'shadowcopy', 'sekurlsa', 'lsass', 'comsvcs',
             'minidump', 'reg save', '/create', 'add-mppreference', '-exclusionpath',
             'set-mppreference', 'disablerealtimemonitoring', 'clear-eventlog', 'wevtutil cl',
             'compress-archive', 'invoke-mimikatz', 'new-object net.sockets', 'nc -e', '/dev/tcp/',
             'base64 -d', 'chmod +x', 'curl ', 'wget ')
_IP_RE = re.compile(r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b')
_URL_RE = re.compile(r'https?://[^\s\'"<>()]+', re.IGNORECASE)
_SSH_PHRASE = re.compile(r'\b((?:Accepted|Failed) \S+ for)(?: invalid user)? (\S+) from (\S+)')


def _private(ip):
    return ip.startswith(('10.', '192.168.', '127.')) or re.match(r'172\.(1[6-9]|2\d|3[01])\.', ip)


def _fragments(text, exclude=(), limit=4):
    low = (text or '').lower()
    found = []
    for kw in _KEYWORDS:
        if re.search(rf'(?<![a-z0-9]){re.escape(kw.strip())}(?![a-z0-9])', low):
            found.append(kw.strip())
    for url in _URL_RE.findall(text or ''):
        found.append(url.rstrip('.,;\')').lower())
    for ip in _IP_RE.findall(text or ''):
        if not _private(ip):
            found.append(ip)
    out = []
    for frag in sorted(dict.fromkeys(found), key=lambda f: (-len(f), f)):
        if frag in exclude or any(frag in kept for kept in out):
            continue
        out.append(frag)
    if not out:
        tokens = [t for t in re.split(r'\s+', text or '') if len(t) >= 4 and t.lower() not in exclude]
        out = sorted(dict.fromkeys(t.lower() for t in tokens), key=lambda t: (-len(t), t))[:2]
    return sorted(out[:limit])


def _basename(path):
    return re.split(r'[\\/]', str(path).strip().strip('"'))[-1]


def _ends(path):
    base = _basename(path)
    return ('\\' + base) if '\\' in str(path) else ('/' + base) if '/' in str(path) else base


def _shape(fields):
    """(cle de forme, logsource, selection) d'un evenement, ou None s'il n'y a rien de distinctif."""
    eid = str(fields.get('EventID') or '').strip()
    image = fields.get('Image')
    if fields.get('ServiceName') and (eid in ('7045', '4697') or fields.get('ImagePath')):
        sel = {'EventID': int(eid) if eid.isdigit() else 7045, 'ServiceName': fields['ServiceName']}
        if fields.get('ImagePath'):
            sel['ImagePath|endswith'] = _ends(fields['ImagePath'])
        return 'service', {'product': 'windows', 'service': 'system'}, sel
    if fields.get('ScriptBlockText'):
        frags = _fragments(fields['ScriptBlockText'])
        return 'ps_script', {'product': 'windows', 'category': 'ps_script'}, {
            'ScriptBlockText|contains|all': frags}
    if fields.get('TargetObject'):
        parts = re.split(r'\\', fields['TargetObject'])
        sel = {'TargetObject|endswith': '\\'.join(parts[-2:]) if len(parts) > 1 else parts[0]}
        if image:
            sel['Image|endswith'] = _ends(image)
        return 'registry', {'product': 'windows', 'category': 'registry_set'}, sel
    if image and (fields.get('CommandLine') or eid in ('4688', '1')):
        sel = {'Image|endswith': _ends(image)}
        cmd = fields.get('CommandLine')
        if cmd:
            frags = _fragments(cmd, exclude=(_basename(image).lower(),))
            if frags:
                sel['CommandLine|contains|all'] = frags
        if fields.get('ParentImage'):
            sel['ParentImage|endswith'] = _ends(fields['ParentImage'])
        return 'process_creation', {'product': 'windows', 'category': 'process_creation'}, sel
    if eid in ('4624', '4625', '4648') and fields.get('IpAddress'):
        sel = {'EventID': int(eid), 'IpAddress': fields['IpAddress']}
        if fields.get('LogonType'):
            sel['LogonType'] = int(fields['LogonType']) if fields['LogonType'].isdigit() else fields['LogonType']
        return f'auth_{eid}', {'product': 'windows', 'service': 'security'}, sel
    if fields.get('dst_ip') or fields.get('DestinationIp'):
        dst = fields.get('dst_ip') or fields.get('DestinationIp')
        key = 'dst_ip' if fields.get('dst_ip') else 'DestinationIp'
        sel = {key: dst}
        port = fields.get('dst_port') or fields.get('DestinationPort')
        if port:
            sel['dst_port' if key == 'dst_ip' else 'DestinationPort'] = int(port) if str(port).isdigit() else port
        return 'network', {'category': 'firewall'} if key == 'dst_ip' else {
            'product': 'windows', 'category': 'network_connection'}, sel
    message = fields.get('message')
    if message:
        m = _SSH_PHRASE.search(message)
        if m:
            frags = [m.group(1)] + ([m.group(3)] if _IP_RE.fullmatch(m.group(3)) else [m.group(2)])
            return 'linux_auth', {'product': 'linux', 'service': 'auth'}, {'message|contains|all': frags}
        frags = _fragments(message)
        if frags:
            return 'generic', {'product': 'generic'}, {'message|contains|all': frags}
    return None


def _q(value):
    """Scalaire YAML entre apostrophes (apostrophe doublee) ; entiers nus."""
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        return str(value)
    text = str(value).replace('\n', ' ').replace('\r', ' ')
    if (re.fullmatch(r'[A-Za-z][A-Za-z0-9_.\-]*', text)
            and text.lower() not in ('true', 'false', 'null', 'yes', 'no', 'on', 'off', 'y', 'n')):
        return text
    return "'" + text.replace("'", "''") + "'"


def _sigma_escape(value):
    if isinstance(value, str):
        return value.replace('*', '\\*').replace('?', '\\?')
    return value


def render_sigma(rule):
    """Regle (dict ordonne) -> YAML Sigma."""
    lines = []

    def emit(key, value, indent=0):
        pad = '  ' * indent
        if isinstance(value, dict):
            lines.append(f'{pad}{key}:')
            for k, v in value.items():
                emit(k, v, indent + 1)
        elif isinstance(value, list):
            if not value:
                lines.append(f'{pad}{key}: []')
            else:
                lines.append(f'{pad}{key}:')
                for item in value:
                    lines.append(f'{pad}  - {_q(item)}')
        else:
            lines.append(f'{pad}{key}: {_q(value)}')

    for key, value in rule.items():
        if key == 'detection':
            lines.append('detection:')
            for name, block in value.items():
                if name == 'condition':
                    lines.append(f'  condition: {block}')
                    continue
                lines.append(f'  {name}:')
                for field, v in block.items():
                    v = [_sigma_escape(x) for x in v] if isinstance(v, list) else _sigma_escape(v)
                    emit(field, v, 2)
        else:
            emit(key, value)
    return '\n'.join(lines) + '\n'


def build_sigma_rules(case_dir, finding, filter_values=None):
    """Regles Sigma (dicts) pour un constat : une par forme d'evenement etaye."""
    events = graph.finding_events(case_dir, finding)
    groups = {}
    for row in events:
        shape = _shape(event_fields(row))
        if not shape:
            continue
        key, logsource, selection = shape
        group = groups.setdefault(json.dumps([key, selection], sort_keys=True, default=str),
                                  {'logsource': logsource, 'selection': selection, 'refs': []})
        ref = {'artifact': row['artifact'], 'kind': row['ref_kind'], 'value': str(row['ref_value'])}
        if row.get('ref_kind') and ref not in group['refs']:
            group['refs'].append(ref)
    techniques = memory.techniques_in(finding.get('mitre'))
    rules = []
    for n, (gkey, group) in enumerate(sorted(groups.items()), 1):
        detection = {'selection': group['selection']}
        if filter_values:
            field = next((f.split('|', 1)[0] for f in group['selection']
                          if f.split('|', 1)[0] in ('CommandLine', 'ScriptBlockText', 'message')),
                         'CommandLine')
            detection['filter'] = {f'{field}|contains': [str(v) for v in filter_values]}
            detection['condition'] = 'selection and not filter'
        else:
            detection['condition'] = 'selection'
        title = f"Phoenix - {finding.get('title') or 'constat'}"[:120]
        rule = {
            'title': title + (f' ({n})' if len(groups) > 1 else ''),
            'id': str(uuid.uuid5(_NAMESPACE, f"{finding.get('title')}|{gkey}|{filter_values}")),
            'status': 'experimental',
            'description': (f"Generated by Phoenix DFIR from finding #{finding['id']} "
                            f"({finding.get('severity')}): {finding.get('title')}")[:400],
            'references': [],
            'author': 'Phoenix DFIR',
            'date': datetime.date.today().isoformat(),
            'tags': [f'attack.{t.lower()}' for t in techniques],
            'logsource': group['logsource'],
            'detection': detection,
            'falsepositives': ['Legitimate administrative activity matching the same fields'],
            'level': _LEVELS.get(finding.get('severity'), 'medium'),
        }
        rules.append((rule, group['refs']))
    return rules


# ============================================================================
# Sigma : lecture (sous-ensemble YAML genere) et evaluation
# ============================================================================

def _scalar(text):
    text = text.strip()
    if text == '[]':
        return []
    if text.startswith("'") and text.endswith("'") and len(text) >= 2:
        return text[1:-1].replace("''", "'")
    if text.startswith('"') and text.endswith('"') and len(text) >= 2:
        return text[1:-1]
    if re.fullmatch(r'-?\d+', text):
        return int(text)
    if text in ('true', 'false'):
        return text == 'true'
    return text


def parse_yaml(text):
    """Analyseur YAML minimal (mappings indentes, listes '- scalaire', scalaires
    apostrophes ou nus) : suffit aux regles Sigma generees ici."""
    lines = [(len(r) - len(r.lstrip(' ')), r.strip()) for r in (text or '').splitlines()
             if r.strip() and not r.lstrip().startswith('#')]
    root = {}
    stack = [(-1, root)]  # (indentation de la cle parente, conteneur)
    current_list = None
    for i, (indent, line) in enumerate(lines):
        if line.startswith('- ') or line == '-':
            if current_list is None:
                raise ValueError(f'liste inattendue : {line}')
            current_list.append(_scalar(line[2:]))
            continue
        current_list = None
        while indent <= stack[-1][0]:
            stack.pop()
        container = stack[-1][1]
        if ':' not in line or not isinstance(container, dict):
            raise ValueError(f'ligne YAML non reconnue : {line}')
        key, _sep, value = line.partition(': ') if ': ' in line else line.partition(':')
        key = key.strip()
        if value.strip():
            container[key] = _scalar(value)
            continue
        nxt = lines[i + 1] if i + 1 < len(lines) else None
        if nxt and nxt[1].startswith('-') and nxt[0] >= indent:
            container[key] = current_list = []
        elif nxt and nxt[0] > indent:
            container[key] = {}
            stack.append((indent, container[key]))
        else:
            container[key] = None
    return root


def _unescape(value):
    return str(value).replace('\\*', '*').replace('\\?', '?')


def _field(event, name):
    if name in event:
        return event[name]
    low = name.lower()
    for k, v in event.items():
        if k.lower() == low:
            return v
    return None


def _match_value(actual, expected, mods):
    a = str(actual).lower()
    e = _unescape(expected).lower()
    if 'contains' in mods:
        return e in a
    if 'startswith' in mods:
        return a.startswith(e)
    if 'endswith' in mods:
        return a.endswith(e)
    return a == e


def _match_block(block, event):
    if isinstance(block, list):
        return any(_match_block(b, event) for b in block)
    if not isinstance(block, dict) or not block:
        return False
    for key, expected in block.items():
        name, *mods = key.split('|')
        unknown = set(mods) - {'contains', 'startswith', 'endswith', 'all'}
        if unknown:
            raise ValueError(f'modificateur Sigma non supporte : {sorted(unknown)}')
        actual = _field(event, name)
        if actual is None:
            return False
        values = expected if isinstance(expected, list) else [expected]
        check = all if 'all' in mods else any
        if not check(_match_value(actual, v, mods) for v in values):
            return False
    return True


def match_rule(rule, event):
    detection = rule.get('detection') or {}
    condition = ' '.join(str(detection.get('condition', '')).split())
    m = re.fullmatch(r'(\w+)(?: and not (\w+))?', condition)
    if not m or m.group(1) not in detection:
        raise ValueError(f'condition Sigma non supportee : {condition!r}')
    if not _match_block(detection[m.group(1)], event):
        return False
    return not (m.group(2) and _match_block(detection.get(m.group(2)), event))


def validate_sigma(rule):
    """Lacunes de structure d'une regle Sigma (liste vide si valide)."""
    gaps = []
    for key in ('title', 'id', 'status', 'description', 'logsource', 'detection', 'level'):
        if not rule.get(key):
            gaps.append(f'champ manquant : {key}')
    try:
        uuid.UUID(str(rule.get('id')))
    except ValueError:
        gaps.append('id doit etre un UUID')
    det = rule.get('detection') or {}
    if 'condition' not in det or 'selection' not in det:
        gaps.append('detection doit contenir selection et condition')
    for tag in rule.get('tags') or []:
        if not re.fullmatch(r'attack\.t\d{4}(?:\.\d{3})?', str(tag)):
            gaps.append(f'tag invalide : {tag}')
    if rule.get('level') not in ('informational', 'low', 'medium', 'high', 'critical'):
        gaps.append('level invalide')
    return gaps


# ============================================================================
# Fichiers de detection et index
# ============================================================================

def detections_dir(case_dir):
    return os.path.join(case_dir, memory.DETECTIONS_DIRNAME)


def _load_index(case_dir):
    try:
        with open(os.path.join(detections_dir(case_dir), INDEX_FILE), 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get('rules'), dict):
            return data
    except (OSError, ValueError):
        pass
    return {'version': 1, 'rules': {}}


def _save_index(case_dir, data):
    os.makedirs(detections_dir(case_dir), exist_ok=True)
    with open(os.path.join(detections_dir(case_dir), INDEX_FILE), 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=1)


def _write_rule(case_dir, name, content, meta):
    os.makedirs(detections_dir(case_dir), exist_ok=True)
    path = os.path.join(detections_dir(case_dir), name)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    data = _load_index(case_dir)
    data['rules'][name] = meta
    _save_index(case_dir, data)
    return path


def _rule_file(case_dir, rule_file):
    """Chemin d'une regle du dossier detections/ du cas (jamais en dehors)."""
    base = os.path.realpath(detections_dir(case_dir))
    path = os.path.realpath(os.path.join(base, os.path.basename(str(rule_file or ''))))
    if not path.startswith(base + os.sep) or not os.path.isfile(path):
        return None
    return path


def _finding(case_dir, finding_id):
    return next((f for f in memory.get_state(case_dir)['findings'] if f.get('id') == finding_id), None)


# ============================================================================
# Tests de regles
# ============================================================================

def test_sigma(case_dir, rule, expected_refs=(), benign_dir=None):
    """Evaluer une regle Sigma (dict) sur le cas et sur un corpus benin."""
    corpus, denied = _resolve_corpus(benign_dir)
    if denied:
        return denied
    case_matches = []
    for row in graph.all_events(case_dir):
        if match_rule(rule, event_fields(row)) and row.get('ref_kind'):
            ref = {'artifact': row['artifact'], 'kind': row['ref_kind'], 'value': str(row['ref_value'])}
            if ref not in case_matches:
                case_matches.append(ref)
    expected = [dict(r, value=str(r.get('value'))) for r in expected_refs or []]
    missed = [r for r in expected if r not in case_matches]
    fps, benign_events, files = [], 0, []
    if corpus:
        events, files = corpus_events(corpus)
        benign_events = len(events)
        for ev in events:
            if match_rule(rule, event_fields(ev)):
                fps.append({'artifact': ev['artifact'], 'kind': ev.get('ref_kind'),
                            'value': ev.get('ref_value'), 'text': (ev.get('text') or '')[:200]})
    ok = bool(expected) and not missed and not fps
    return {'case_matches': case_matches[:200], 'case_match_count': len(case_matches),
            'expected': expected, 'missed': missed, 'malicious_matched': bool(expected) and not missed,
            'benign_corpus': os.path.relpath(corpus, _REPO) if corpus and corpus.startswith(_REPO) else corpus,
            'benign_files': files, 'benign_events': benign_events,
            'false_positives': len(fps), 'false_positive_samples': fps[:10],
            'verdict': 'ok' if ok else ('faux positifs' if fps else 'ne couvre pas le malveillant')}


def generate_sigma(case_dir, finding_id, filter_values=None, benign_dir=None):
    finding = _finding(case_dir, finding_id)
    if finding is None:
        return {'error': f'Constat #{finding_id} introuvable'}
    rules = build_sigma_rules(case_dir, finding, filter_values)
    if not rules:
        return {'error': ("Aucun evenement indexe exploitable derriere ce constat (references a des "
                          "evenements de la super-timeline requises).")}
    out = []
    for n, (rule, refs) in enumerate(rules, 1):
        text = render_sigma(rule)
        test = test_sigma(case_dir, parse_yaml(text), refs, benign_dir)
        if test.get('error'):
            return test
        name = f'{PREFIX}f{finding_id}_{n}.yml'
        meta = {'type': 'sigma', 'finding_id': finding_id, 'title': rule['title'], 'id': rule['id'],
                'refs': refs, 'test': {k: test[k] for k in ('malicious_matched', 'false_positives',
                                                             'case_match_count', 'verdict')}}
        path = _write_rule(case_dir, name, text, meta)
        out.append({'rule_file': os.path.relpath(path, case_dir), 'title': rule['title'],
                    'id': rule['id'], 'yaml': text, 'validation_gaps': validate_sigma(parse_yaml(text)),
                    'test': test})
    return {'finding_id': finding_id, 'rules': out}


def test_rule(case_dir, rule_file, benign_dir=None):
    path = _rule_file(case_dir, rule_file)
    if not path:
        return {'error': f"Regle introuvable dans {memory.DETECTIONS_DIRNAME}/ : {rule_file}"}
    meta = _load_index(case_dir)['rules'].get(os.path.basename(path), {})
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    if path.endswith('.yar'):
        result = test_yara(case_dir, parse_yara(text), benign_dir, meta.get('source'))
    else:
        try:
            rule = parse_yaml(text)
            result = test_sigma(case_dir, rule, meta.get('refs') or [], benign_dir)
        except ValueError as exc:
            return {'error': f'Regle Sigma hors du sous-ensemble evaluable : {exc}'}
        result['validation_gaps'] = validate_sigma(rule)
    result['rule_file'] = os.path.relpath(path, case_dir)
    return result


# ============================================================================
# YARA
# ============================================================================

_ASCII_RE = re.compile(rb'[\x20-\x7e]{6,}')
_WIDE_RE = re.compile(rb'(?<![\x20-\x7e])(?:[\x20-\x7e]\x00){6,}')
_GENERIC = ('this program cannot be run in dos mode', 'kernel32.dll', 'ntdll.dll', 'user32.dll',
            'advapi32.dll', 'msvcrt.dll', 'getprocaddress', 'loadlibrary', 'virtualalloc',
            'microsoft corporation', '.text', '.rdata', '.data', '.reloc', 'rich', 'mscoree.dll',
            'http://www.w3.org', 'xml version', 'copyright', 'getmodulehandle', 'exitprocess')
MAX_YARA_STRINGS = 8
MAX_YARA_FILE = 50 * 1024 * 1024


def _entropy(text):
    counts = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values()) if text else 0.0


def _strings(data):
    found = {}
    for m in _ASCII_RE.finditer(data):
        s = m.group(0).decode('ascii')[:120].strip()
        if len(s) >= 6:
            found.setdefault(s, 'ascii')
    for m in _WIDE_RE.finditer(data):
        s = m.group(0).decode('utf-16-le', errors='ignore')[:120].strip()
        if len(s) >= 6 and s not in found:
            found[s] = 'wide'
    return found


def _score(s):
    low = s.lower()
    score = min(len(s), 60) + 10 * _entropy(s)
    if _URL_RE.search(s) or _IP_RE.search(s):
        score += 40
    if re.search(r'[a-z]:\\|\\\\|/tmp/|/dev/|hk(lm|cu)\\|\.(exe|dll|ps1|bat|vbs|sh)\b', low):
        score += 25
    if any(k in low for k in ('password', 'token', 'cmd', 'powershell', 'invoke', 'payload', 'beacon')):
        score += 10
    if len(set(s)) < 4:
        score -= 50
    return score


def _corpus_blobs(corpus):
    blobs = []
    for root, _dirs, names in os.walk(corpus):
        for name in names:
            if name in _SKIP_CORPUS:
                continue
            path = os.path.join(root, name)
            try:
                if os.path.getsize(path) <= MAX_CORPUS_BYTES:
                    with open(path, 'rb') as f:
                        blobs.append((os.path.relpath(path, corpus), f.read()))
            except OSError:
                continue
    return blobs


def _yara_text(value):
    out = []
    for ch in value:
        if ch in '\\"':
            out.append('\\' + ch)
        elif 32 <= ord(ch) < 127:
            out.append(ch)
        else:
            out.append(f'\\x{ord(ch) & 0xff:02x}')
    return ''.join(out)


def _yara_name(text):
    name = re.sub(r'[^A-Za-z0-9_]', '_', text)
    return ('r_' + name if not name[:1].isalpha() else name)[:100]


def build_yara(file_path, data, benign_blobs, finding=None):
    found = _strings(data)
    benign = b'\n'.join(b for _n, b in benign_blobs).lower()
    candidates = []
    for s, enc in found.items():
        low = s.lower()
        if any(g in low for g in _GENERIC) or s.isdigit():
            continue
        encoded = s.encode('utf-16-le' if enc == 'wide' else 'ascii', errors='ignore').lower()
        if encoded in benign or s.lower().encode('ascii', errors='ignore') in benign:
            continue
        candidates.append((_score(s), s, enc))
    candidates.sort(key=lambda c: (-c[0], c[1]))
    picked = candidates[:MAX_YARA_STRINGS]
    if len(picked) < 2:
        return None
    sha256 = hashlib.sha256(data).hexdigest()
    n_required = max(2, math.ceil(len(picked) / 2))
    header = 'uint16(0) == 0x5A4D and ' if data[:2] == b'MZ' else ''
    strings = [{'id': f'$s{i}', 'value': s, 'modifier': enc} for i, (_sc, s, enc) in enumerate(picked, 1)]
    return {
        'name': _yara_name(f'phoenix_{os.path.splitext(os.path.basename(file_path))[0]}_{sha256[:8]}'),
        'meta': {'description': (f"Generated by Phoenix DFIR from {os.path.basename(file_path)}"
                                 + (f" (finding #{finding['id']})" if finding else '')),
                 'author': 'Phoenix DFIR', 'date': datetime.date.today().isoformat(),
                 'hash': sha256},
        'tags': [t.lower().replace('.', '_') for t in memory.techniques_in((finding or {}).get('mitre'))],
        'strings': strings,
        'mz': bool(header),
        'required': n_required,
    }


def render_yara(rule):
    tags = (' : ' + ' '.join(rule['tags'])) if rule.get('tags') else ''
    lines = [f"rule {rule['name']}{tags}", '{', '    meta:']
    for key, value in rule['meta'].items():
        lines.append(f'        {key} = "{_yara_text(str(value))}"')
    lines.append('    strings:')
    for s in rule['strings']:
        lines.append(f"        {s['id']} = \"{_yara_text(s['value'])}\" {s['modifier']}")
    lines.append('    condition:')
    lines.append('        ' + ('uint16(0) == 0x5A4D and ' if rule['mz'] else '')
                 + f"{rule['required']} of them")
    lines.append('}')
    return '\n'.join(lines) + '\n'


def _yara_unescape(text):
    return re.sub(r'\\x([0-9a-fA-F]{2})|\\(.)',
                  lambda m: chr(int(m.group(1), 16)) if m.group(1) else m.group(2), text)


def parse_yara(text):
    """Lecture du sous-ensemble YARA genere (chaines texte ascii/wide, 'N of them', MZ)."""
    rule = {'strings': [], 'mz': 'uint16(0) == 0x5A4D' in text, 'required': 1}
    name = re.search(r'^rule\s+(\w+)', text, re.MULTILINE)
    rule['name'] = name.group(1) if name else 'rule'
    for m in re.finditer(r'^\s*(\$\w+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*([a-z ]*)$', text, re.MULTILINE):
        mods = m.group(3).split() or ['ascii']
        rule['strings'].append({'id': m.group(1), 'value': _yara_unescape(m.group(2)),
                                'modifier': 'wide' if 'wide' in mods else 'ascii',
                                'nocase': 'nocase' in mods})
    cond = re.search(r'condition:\s*(.+?)\s*\}', text, re.DOTALL)
    cond_text = ' '.join((cond.group(1) if cond else '').split())
    m = re.search(r'(\d+|all|any) of them', cond_text)
    if m:
        rule['required'] = (len(rule['strings']) if m.group(1) == 'all'
                            else 1 if m.group(1) == 'any' else int(m.group(1)))
    return rule


def match_yara(rule, data):
    if rule['mz'] and data[:2] != b'MZ':
        return False
    hits = 0
    low = None
    for s in rule['strings']:
        needle = s['value'].encode('utf-16-le' if s['modifier'] == 'wide' else 'latin-1', errors='ignore')
        if s.get('nocase'):
            low = data.lower() if low is None else low
            hit = needle.lower() in low
        else:
            hit = needle in data
        hits += 1 if hit else 0
    return hits >= rule['required']


def test_yara(case_dir, rule, benign_dir=None, source=None):
    corpus, denied = _resolve_corpus(benign_dir)
    if denied:
        return denied
    det = os.path.realpath(detections_dir(case_dir))
    case_hits = []
    for path in toolkit.case_artifacts(case_dir):
        real = os.path.realpath(path)
        if real.startswith(det + os.sep):
            continue
        try:
            if os.path.getsize(path) > MAX_YARA_FILE:
                continue
            with open(path, 'rb') as f:
                if match_yara(rule, f.read()):
                    case_hits.append(os.path.relpath(path, case_dir))
        except OSError:
            continue
    fps = [name for name, blob in (_corpus_blobs(corpus) if corpus else []) if match_yara(rule, blob)]
    source_hit = None if not source else source in case_hits
    return {'case_matches': case_hits, 'source': source, 'malicious_matched': source_hit,
            'benign_corpus': os.path.relpath(corpus, _REPO) if corpus and corpus.startswith(_REPO) else corpus,
            'false_positives': len(fps), 'false_positive_files': fps[:20],
            'verdict': 'ok' if source_hit is not False and not fps else
                       ('faux positifs' if fps else 'ne couvre pas le fichier source')}


def generate_yara(case_dir, file_path, finding_id=None, benign_dir=None):
    if not os.path.isdir(case_dir):
        return {'error': f"Dossier introuvable: {case_dir}"}
    real = os.path.realpath(file_path)
    case_real = os.path.realpath(case_dir)
    if not real.startswith(case_real + os.sep) or not os.path.isfile(real):
        return {'error': "file_path doit designer un fichier du cas (extrait ou carve)."}
    if os.path.getsize(real) > MAX_YARA_FILE:
        return {'error': 'Fichier trop volumineux pour la generation YARA (50 Mo max).'}
    finding = _finding(case_dir, finding_id) if finding_id is not None else None
    if finding_id is not None and finding is None:
        return {'error': f'Constat #{finding_id} introuvable'}
    corpus, denied = _resolve_corpus(benign_dir)
    if denied:
        return denied
    with open(real, 'rb') as f:
        data = f.read()
    rule = build_yara(real, data, _corpus_blobs(corpus) if corpus else [], finding)
    if rule is None:
        return {'error': "Pas assez de chaines distinctives (absentes du corpus benin) pour une regle."}
    text = render_yara(rule)
    source = os.path.relpath(real, case_real)
    test = test_yara(case_dir, parse_yara(text), benign_dir, source)
    name = f"{PREFIX}{'f' + str(finding_id) + '_' if finding_id is not None else ''}{rule['name'][:60]}.yar"
    meta = {'type': 'yara', 'finding_id': finding_id, 'title': rule['name'], 'source': source,
            'sha256': rule['meta']['hash'],
            'test': {'malicious_matched': test['malicious_matched'],
                     'false_positives': test['false_positives'], 'verdict': test['verdict']}}
    path = _write_rule(case_dir, name, text, meta)
    return {'rule_file': os.path.relpath(path, case_dir), 'rule': text,
            'strings': [s['value'] for s in rule['strings']], 'test': test}


# ============================================================================
# Outils
# ============================================================================

_CASE = {'case_dir': {'type': 'string', 'description': 'Dossier du cas'}}
_BENIGN = {'benign_dir': {'type': 'string',
                          'description': 'Corpus benin (defaut : eval/suite/benign_admin_activity)'}}


@toolkit.tool(
    'detect_generate_sigma',
    "Ingenierie de detection : generer des regles Sigma a partir des evenements qui etayent un "
    "constat (EventID, Image, fragments de CommandLine, ParentImage, ServiceName, TargetObject...), "
    "les ecrire dans detections/ et les tester (correspondance aux evenements malveillants du cas, "
    "faux positifs sur le corpus benin). filter_values ajoute une exclusion (selection and not filter).",
    {'type': 'object', 'properties': dict(_CASE, **_BENIGN, **{
        'finding_id': {'type': 'integer', 'description': 'Constat source'},
        'filter_values': {'type': 'array', 'items': {'type': 'string'},
                          'description': 'Fragments a exclure (faux positifs connus)'},
    }), 'required': ['case_dir', 'finding_id']},
)
def detect_generate_sigma(case_dir, finding_id, filter_values=None, benign_dir=None):
    return generate_sigma(case_dir, finding_id, filter_values, benign_dir)


@toolkit.tool(
    'detect_test_rule',
    "Tester une regle de detections/ (Sigma .yml ou YARA .yar) : correspondances dans le cas (doit "
    "couvrir les evenements / le fichier malveillants) et faux positifs sur un corpus benin.",
    {'type': 'object', 'properties': dict(_CASE, **_BENIGN, **{
        'rule_file': {'type': 'string', 'description': 'Nom du fichier de regle dans detections/'},
    }), 'required': ['case_dir', 'rule_file']},
)
def detect_test_rule(case_dir, rule_file, benign_dir=None):
    return test_rule(case_dir, rule_file, benign_dir)


@toolkit.tool(
    'detect_generate_yara',
    "Generer une regle YARA pour un fichier extrait ou carve du cas : chaines distinctives (ascii / "
    "wide) absentes du corpus benin, condition 'N of them' (+ en-tete MZ si executable), testee sur "
    "les fichiers du cas et le corpus benin. Ecrite dans detections/.",
    {'type': 'object', 'properties': dict(_CASE, **_BENIGN, **{
        'file_path': {'type': 'string', 'description': 'Fichier du cas a caracteriser'},
        'finding_id': {'type': 'integer', 'description': 'Constat associe (optionnel)'},
    }), 'required': ['case_dir', 'file_path']},
)
def detect_generate_yara(case_dir, file_path, finding_id=None, benign_dir=None):
    return generate_yara(case_dir, file_path, finding_id, benign_dir)
