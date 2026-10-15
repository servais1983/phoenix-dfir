"""Boite a outils DFIR : registre unique des outils forensiques.

Chaque outil est declare une seule fois (nom, description, schema JSON des
parametres, fonction Python). Le meme registre alimente :
- le serveur MCP (tools/list, tools/call) pour GitHub Copilot en mode agent ;
- l'enqueteur autonome (function calling via l'API GitHub Models).

Les parsers proviennent du backend Phoenix (backend/parsers.py, mitre.py,
integrations/sigma_connector.py) — aucune logique dupliquee.
"""

import datetime
import hashlib
import json
import os
import re
import sys
import threading

import requests

# Rendre les modules du backend Phoenix importables
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_BACKEND_DIR = os.path.join(_REPO_ROOT, 'backend')
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import mitre  # noqa: E402
import parsers  # noqa: E402
from integrations.sigma_connector import SigmaConnector  # noqa: E402

from . import disk  # noqa: E402
from . import evidence_db  # noqa: E402
from . import exports  # noqa: E402
from . import hayabusa  # noqa: E402
from . import memory  # noqa: E402
from . import pathpolicy  # noqa: E402
from . import volatility  # noqa: E402
from . import zimmermann  # noqa: E402

# ============================================================================
# Registre des outils
# ============================================================================

TOOLS = {}


def tool(name, description, schema):
    """Enregistrer une fonction comme outil DFIR."""
    def decorator(func):
        TOOLS[name] = {
            'name': name,
            'description': description,
            'input_schema': schema,
            'func': func,
        }
        return func
    return decorator


def list_tools():
    """Liste des outils au format MCP (name, description, inputSchema)."""
    return [
        {'name': t['name'], 'description': t['description'], 'inputSchema': t['input_schema']}
        for t in TOOLS.values()
    ]


# Outils de lecture seule (verification) : n'alterent ni la memoire narrative
# ni les fichiers, hormis verify_finding qui statue sur un constat existant.
READONLY_TOOLS = (
    'list_artifacts', 'parse_evtx', 'parse_csv', 'parse_json_file', 'parse_log_file',
    'parse_prefetch', 'parse_lnk', 'parse_browser_history', 'analyze_artifact',
    'extract_iocs', 'sigma_scan', 'mitre_map_events', 'virustotal_lookup',
    'zimmermann_status', 'run_zimmermann', 'get_case_state', 'verify_finding',
    'volatility_status', 'run_volatility', 'hayabusa_status', 'run_hayabusa',
    'search_evidence', 'get_timeline', 'list_sources',
    'disk_status', 'disk_image_info', 'disk_list_files', 'disk_timeline',
)

# Essaim d'agents specialises : chaque outil est rattache a l'agent qui
# l'opere (console enqueteur temps reel et chaine de traçabilite).
AGENTS = {
    'triage': 'Agent Triage & Collecte',
    'disk': 'Agent Disque & EVTX',
    'memory': 'Agent Memoire (Volatility 3)',
    'intel': 'Agent Threat Intel & Correlation',
    'lead': 'Orchestrateur Lead',
}

_TOOL_AGENT = {
    'list_artifacts': 'triage', 'analyze_artifact': 'triage', 'extract_iocs': 'triage',
    'parse_evtx': 'disk', 'parse_csv': 'disk', 'parse_json_file': 'disk',
    'parse_log_file': 'disk', 'parse_prefetch': 'disk', 'parse_lnk': 'disk',
    'parse_browser_history': 'disk', 'sigma_scan': 'disk', 'zimmermann_status': 'disk',
    'run_zimmermann': 'disk', 'hayabusa_status': 'disk', 'run_hayabusa': 'disk',
    'volatility_status': 'memory', 'run_volatility': 'memory',
    'disk_status': 'disk_image', 'disk_image_info': 'disk_image', 'disk_list_files': 'disk_image',
    'disk_timeline': 'disk_image', 'disk_extract_artifacts': 'disk_image',
    'virustotal_lookup': 'intel', 'mitre_map_events': 'intel',
    'search_evidence': 'intel', 'get_timeline': 'intel', 'list_sources': 'intel',
    'prompt_injection_shield': 'shield',
    'audit_tool_coverage': 'quality', 'audit_evidence_coverage': 'quality',
    'challenge_finding': 'quality', 'phase_gate': 'quality',
}
AGENTS['quality'] = 'Controle qualite & contre-analyse'
AGENTS['disk_image'] = 'Agent Images disque (Sleuth Kit)'
AGENTS['shield'] = 'Bouclier Anti-Prompt-Injection'


def agent_for(tool_name):
    """Nom de l'agent specialise operant un outil (Orchestrateur par defaut)."""
    return AGENTS[_TOOL_AGENT.get(tool_name, 'lead')]


def openai_tools(names=None):
    """Liste des outils au format function-calling OpenAI (API GitHub Models).

    `names` (iterable optionnel) restreint aux outils indiques — utilise pour
    la passe de verification (sous-ensemble lecture seule).
    """
    selected = TOOLS.values() if names is None else (TOOLS[n] for n in names if n in TOOLS)
    return [
        {
            'type': 'function',
            'function': {
                'name': t['name'],
                'description': t['description'],
                'parameters': t['input_schema'],
            },
        }
        for t in selected
    ]


# Arguments d'outils portant un chemin de fichier local (soumis a la politique)
_PATH_ARGS = ('file_path', 'case_dir')


# ============================================================================
# Index des preuves observees (sortie structuree stricte)
# ============================================================================
# Chaque identifiant extrait par un outil DETERMINISTE (RecordID EVTX, PID
# Volatility, ligne de log, ligne CSV) est indexe par artefact. Un constat
# (record_finding) doit citer au moins un de ces identifiants : le LLM ne peut
# pas inventer une preuve qu'aucun outil n'a produite.

REF_KINDS = ('record_id', 'pid', 'line', 'row', 'inode')
_REF_KEYS = {
    'record_id': 'record_id', 'RecordID': 'record_id', 'EventRecordID': 'record_id',
    'EventRecordId': 'record_id', 'RecordNumber': 'record_id',
    'pid': 'pid', 'PID': 'pid', 'Pid': 'pid', 'ProcessId': 'pid',
    'line': 'line', 'row': 'row', 'inode': 'inode',
}


def ref_value(kind, value):
    """Valeur de reference normalisee, ou None si invalide pour ce type.
    Un inode peut etre compose (NTFS : 128-128-1), les autres sont numeriques."""
    text = str(value).strip()
    if kind == 'inode':
        return text if re.fullmatch(r'\d+(?:-\d+)*', text) else None
    return str(int(text)) if text.isdigit() else None
_evidence_lock = threading.Lock()
_active = threading.local()

# Outils dont la sortie est indexee dans la super-timeline du cas
INDEXED_TOOLS = (
    'parse_evtx', 'parse_csv', 'parse_json_file', 'parse_log_file', 'parse_prefetch',
    'parse_lnk', 'parse_browser_history', 'analyze_artifact', 'sigma_scan', 'run_hayabusa',
    'run_volatility', 'run_zimmermann', 'extract_iocs',
    'disk_image_info', 'disk_timeline', 'disk_extract_artifacts',
)


def set_active_case(case_dir):
    """Dossier du cas courant (par thread) : cible de l'index de preuves."""
    _active.case_dir = os.path.abspath(case_dir) if case_dir else None


def active_case():
    return getattr(_active, 'case_dir', None)


def _case_for(file_path):
    case = active_case()
    if case and os.path.abspath(file_path).startswith(case + os.sep):
        return case
    return None
_evidence_index = {}   # chemin reel de l'artefact -> {kind: set(valeurs)}
_MAX_REFS_PER_ARTIFACT = 200000


def _harvest(obj, acc, depth=0):
    if depth > 8:
        return
    if isinstance(obj, dict):
        for key, value in obj.items():
            kind = _REF_KEYS.get(key)
            normalized = ref_value(kind, value) if kind and isinstance(value, (int, str)) else None
            if normalized is not None:
                acc.setdefault(kind, set()).add(normalized)
            elif isinstance(value, (dict, list)):
                _harvest(value, acc, depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _harvest(item, acc, depth + 1)


def index_evidence(arguments, result):
    """Indexer les identifiants de preuve d'une sortie d'outil reussie."""
    file_path = (arguments or {}).get('file_path')
    if not isinstance(file_path, str) or not isinstance(result, dict) or result.get('error'):
        return 0
    found = {}
    _harvest(result, found)
    if not found:
        return 0
    key = os.path.realpath(file_path)
    with _evidence_lock:
        bucket = _evidence_index.setdefault(key, {})
        for kind, values in found.items():
            target = bucket.setdefault(kind, set())
            if len(target) < _MAX_REFS_PER_ARTIFACT:
                target.update(values)
    return sum(len(v) for v in found.values())


def reset_evidence_index():
    with _evidence_lock:
        _evidence_index.clear()


def strict_evidence():
    return os.environ.get('PHOENIX_STRICT_EVIDENCE', 'true').strip().lower() not in ('0', 'false', 'no')


def _matching_artifacts(artifact, case_dir):
    candidates = {os.path.realpath(artifact)}
    if case_dir and not os.path.isabs(artifact):
        candidates.add(os.path.realpath(os.path.join(case_dir, artifact)))
    base = os.path.basename(artifact.rstrip('/\\'))
    keys = []
    for key in _evidence_index:
        if (key in candidates or os.path.basename(key) == base
                or any(c.startswith(key + os.sep) for c in candidates)):
            keys.append(key)
    return keys


def validate_refs(refs, case_dir=None):
    """Separer les references de preuve observees (valides) des inventees."""
    valid, invalid = [], []
    case_dir = case_dir or active_case()
    for ref in refs or []:
        if not isinstance(ref, dict):
            invalid.append({'ref': ref, 'reason': 'format attendu {artifact, kind, value}'})
            continue
        artifact = str(ref.get('artifact') or '')
        kind = ref.get('kind')
        raw_value = str(ref.get('value', '')).strip()
        clean = {'artifact': artifact, 'kind': kind, 'value': raw_value}
        value = ref_value(kind, raw_value) if kind in REF_KINDS else None
        if not artifact or value is None:
            invalid.append(dict(clean, reason=f'kind parmi {list(REF_KINDS)} et value valide requis'))
            continue
        clean['value'] = value
        with _evidence_lock:
            ok = any(value in _evidence_index[k].get(kind, ())
                     for k in _matching_artifacts(artifact, case_dir))
        if not ok and case_dir:
            # Index persistant du cas : valide meme apres redemarrage du processus
            ok = evidence_db.has_ref(case_dir, artifact, kind, value)
        (valid if ok else invalid).append(
            clean if ok else dict(clean, reason="identifiant absent des sorties d'outils de cet artefact"))
    return valid, invalid


def _index_run(name, arguments, result):
    """Indexer la sortie d'un outil deterministe dans la super-timeline du cas."""
    if name not in INDEXED_TOOLS:
        return
    file_path = arguments.get('file_path')
    if not isinstance(file_path, str):
        return
    case = _case_for(file_path)
    if not case:
        return
    try:
        count = evidence_db.record_run(case, name, file_path, result)
        if isinstance(result, dict) and count:
            result['indexed_events'] = count
    except Exception:  # l'indexation ne doit jamais faire echouer l'outil
        pass


def run_tool(name, arguments=None):
    """Executer un outil et retourner un resultat JSON-serialisable."""
    if name not in TOOLS:
        return {'error': f"Outil inconnu: {name}. Outils disponibles: {sorted(TOOLS)}"}
    arguments = arguments or {}
    # Sandboxing : refuser tout acces fichier hors des racines autorisees
    for key in _PATH_ARGS:
        value = arguments.get(key)
        if isinstance(value, str) and value:
            denied = pathpolicy.check(value)
            if denied:
                return denied
    try:
        result = TOOLS[name]['func'](**arguments)
        index_evidence(arguments, result)
        _index_run(name, arguments, result)
        if isinstance(result, dict) and 'preview' in result:
            # Volumineux : indexe en totalite, seul l'apercu est renvoye
            result.pop('events', None)
        return result
    except TypeError as e:
        return {'error': f"Arguments invalides pour {name}: {e}"}
    except Exception as e:
        return {'error': f"Erreur durant {name}: {e}"}


def _schema(properties, required=None):
    return {
        'type': 'object',
        'properties': properties,
        'required': required or [],
    }


# ============================================================================
# Inventaire du cas
# ============================================================================

_KNOWN_TYPES = {
    '.evtx': 'Journal Windows EVTX',
    '.csv': 'CSV',
    '.json': 'JSON',
    '.log': 'Log texte',
    '.txt': 'Texte',
    '.xml': 'XML',
    '.pf': 'Prefetch Windows',
    '.lnk': 'Raccourci Windows LNK',
    '.sqlite': 'Base SQLite (historique navigateur ?)',
    '.db': 'Base SQLite (historique navigateur ?)',
    '.ps1': 'Script PowerShell',
    '.bat': 'Script Batch',
    '.sh': 'Script Shell',
    '.pcap': 'Capture reseau PCAP',
    '.mft': 'Master File Table NTFS',
    '.hve': 'Ruche registre Windows',
    '.dat': 'Ruche registre Windows (NTUSER.DAT ?)',
    '.raw': 'Dump memoire (RAW) - Volatility 3',
    '.mem': 'Dump memoire - Volatility 3',
    '.vmem': 'Memoire de VM VMware - Volatility 3',
    '.dmp': 'Crash dump / dump memoire - Volatility 3',
    '.lime': 'Dump memoire Linux (LiME) - Volatility 3',
    '.e01': 'Image disque EnCase (E01) - Sleuth Kit',
    '.ex01': 'Image disque EnCase (Ex01) - Sleuth Kit',
    '.dd': 'Image disque brute (dd) - Sleuth Kit',
    '.img': 'Image disque - Sleuth Kit',
    '.001': 'Image disque segmentee (.001) - Sleuth Kit',
    '.vmdk': 'Disque virtuel VMware - Sleuth Kit',
    '.vhd': 'Disque virtuel Hyper-V - Sleuth Kit',
    '.vhdx': 'Disque virtuel Hyper-V - Sleuth Kit',
}


INTERNAL_FILES = (memory.STATE_FILENAME, evidence_db.DB_NAME, 'PHOENIX.md',
                  'attack_navigator_layer.json', 'iocs.csv')


def is_internal_file(fname):
    """Fichiers produits par Phoenix dans le dossier du cas (pas des preuves)."""
    return (fname in INTERNAL_FILES or fname.startswith('rapport_phoenix_')
            or fname.startswith(evidence_db.DB_NAME) or disk.is_manifest(fname))


def case_artifacts(case_dir):
    """Chemins des artefacts du cas (hors fichiers internes de Phoenix)."""
    paths = []
    for root, _dirs, files in os.walk(case_dir):
        for fname in sorted(files):
            if not is_internal_file(fname):
                paths.append(os.path.join(root, fname))
    return paths


@tool(
    'list_artifacts',
    "Inventorier les artefacts d'un dossier de cas DFIR : liste recursive des fichiers avec "
    "type detecte, taille et empreintes MD5/SHA256. TOUJOURS appeler cet outil en premier "
    "pour decouvrir les preuves disponibles.",
    _schema({'case_dir': {'type': 'string', 'description': 'Chemin du dossier contenant les artefacts du cas'}},
            ['case_dir']),
)
def list_artifacts(case_dir):
    if not os.path.isdir(case_dir):
        return {'error': f"Dossier introuvable: {case_dir}"}
    set_active_case(case_dir)
    artifacts = []
    for root, _dirs, files in os.walk(case_dir):
        for fname in sorted(f for f in files if not is_internal_file(f)):
            path = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            try:
                size = os.path.getsize(path)
                md5, sha256 = hashlib.md5(), hashlib.sha256()
                with open(path, 'rb') as f:
                    for chunk in iter(lambda: f.read(1 << 20), b''):
                        md5.update(chunk)
                        sha256.update(chunk)
                kind = _KNOWN_TYPES.get(ext, f'Inconnu ({ext or "sans extension"})')
                if ext in disk.AMBIGUOUS_EXTENSIONS and disk.looks_like_disk(path):
                    kind = 'Image disque brute (signature MBR/GPT/FS) - Sleuth Kit'
                artifacts.append({
                    'path': path,
                    'name': fname,
                    'type': kind,
                    'size_bytes': size,
                    'md5': md5.hexdigest(),
                    'sha256': sha256.hexdigest(),
                })
            except OSError as e:
                artifacts.append({'path': path, 'name': fname, 'error': str(e)})
    return {'case_dir': case_dir, 'total': len(artifacts), 'artifacts': artifacts}


# ============================================================================
# Parsers natifs Phoenix
# ============================================================================

@tool(
    'parse_evtx',
    "Parser un journal d'evenements Windows EVTX : evenements structures (event_id, timestamp, "
    "provider, donnees), comptage par Event ID, severite, IoCs extraits et mapping MITRE ATT&CK.",
    _schema({
        'file_path': {'type': 'string', 'description': 'Chemin du fichier .evtx'},
        'event_id_filter': {'type': 'string', 'description': "Event IDs a filtrer, separes par des virgules (ex: '4624,4625')"},
        'max_records': {'type': 'integer', 'description': 'Nombre max d\'evenements retournes (defaut 500)'},
    }, ['file_path']),
)
def parse_evtx(file_path, event_id_filter=None, max_records=500):
    result = parsers.parse_evtx(file_path, event_id_filter, max_records)
    event_ids = sorted({e.get('event_id') for e in result.get('events', []) if e.get('event_id')})
    if event_ids:
        result['mitre_attack'] = mitre.get_attack_summary(event_ids)
    return result


@tool(
    'parse_csv',
    "Parser un fichier CSV (exports d'outils forensiques, logs tabulaires) : colonnes, "
    "apercu des lignes, statistiques et IoCs extraits.",
    _schema({
        'file_path': {'type': 'string', 'description': 'Chemin du fichier .csv'},
        'max_rows': {'type': 'integer', 'description': 'Nombre max de lignes analysees (defaut 5000)'},
    }, ['file_path']),
)
def parse_csv(file_path, max_rows=5000):
    return parsers.parse_csv(file_path, max_rows)


@tool(
    'parse_json_file',
    "Parser un fichier JSON (exports SIEM/EDR, resultats d'outils) : structure, apercu et IoCs extraits.",
    _schema({'file_path': {'type': 'string', 'description': 'Chemin du fichier .json'}}, ['file_path']),
)
def parse_json_file(file_path):
    return parsers.parse_json(file_path)


@tool(
    'parse_log_file',
    "Parser un log texte (syslog, applicatif, .log/.txt/.xml/scripts) : lignes suspectes, "
    "severite detectee par heuristique et IoCs extraits.",
    _schema({
        'file_path': {'type': 'string', 'description': 'Chemin du fichier log'},
        'max_lines': {'type': 'integer', 'description': 'Nombre max de lignes analysees (defaut 10000)'},
    }, ['file_path']),
)
def parse_log_file(file_path, max_lines=10000):
    return parsers.parse_log(file_path, max_lines)


@tool(
    'parse_prefetch',
    "Parser un fichier Prefetch Windows (.pf) : executable, nombre d'executions, "
    "derniere execution — preuve d'execution de programme.",
    _schema({'file_path': {'type': 'string', 'description': 'Chemin du fichier .pf'}}, ['file_path']),
)
def parse_prefetch(file_path):
    return parsers.parse_prefetch(file_path)


@tool(
    'parse_lnk',
    "Parser un raccourci Windows (.lnk) : cible, arguments, horodatages — trace d'acces a un fichier.",
    _schema({'file_path': {'type': 'string', 'description': 'Chemin du fichier .lnk'}}, ['file_path']),
)
def parse_lnk(file_path):
    return parsers.parse_lnk(file_path)


@tool(
    'parse_browser_history',
    "Parser un historique de navigateur SQLite (Chromium 'History' ou Firefox 'places.sqlite') : "
    "URLs visitees, horodatages, detection d'URLs suspectes.",
    _schema({
        'file_path': {'type': 'string', 'description': 'Chemin de la base SQLite'},
        'limit': {'type': 'integer', 'description': 'Nombre max d\'entrees (defaut 2000)'},
    }, ['file_path']),
)
def parse_browser_history(file_path, limit=2000):
    return parsers.parse_browser_history(file_path, limit)


@tool(
    'analyze_artifact',
    "Analyser automatiquement un artefact quel que soit son format (dispatch selon l'extension : "
    "EVTX, CSV, JSON, Prefetch, LNK, SQLite navigateur, log texte). Pratique quand le type est inconnu.",
    _schema({
        'file_path': {'type': 'string', 'description': "Chemin de l'artefact"},
        'event_id_filter': {'type': 'string', 'description': 'Pour les EVTX : Event IDs separes par des virgules'},
    }, ['file_path']),
)
def analyze_artifact(file_path, event_id_filter=None):
    return parsers.analyze_file_standalone(file_path, event_id_filter)


# ============================================================================
# IoCs, Sigma, MITRE, VirusTotal
# ============================================================================

@tool(
    'extract_iocs',
    "Extraire les indicateurs de compromission (IPs publiques, domaines, URLs, hashes MD5/SHA1/SHA256, "
    "emails, CVE) d'un texte brut ou d'un fichier.",
    _schema({
        'text': {'type': 'string', 'description': 'Texte a analyser'},
        'file_path': {'type': 'string', 'description': 'Ou chemin d\'un fichier a analyser'},
    }),
)
def extract_iocs(text=None, file_path=None):
    if not text and not file_path:
        return {'error': "Fournir 'text' ou 'file_path'"}
    if file_path:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            text = f.read(5 << 20)
    iocs = parsers.extract_iocs(text)
    return {'total': len(iocs), 'iocs': iocs}


def _sigma_normalize_event(evt):
    """Aplatir un evenement EVTX Phoenix vers les champs attendus par les regles Sigma."""
    data = evt.get('data', {}) or {}

    def get(*names):
        for n in names:
            v = data.get(n)
            if v:
                return v
        return ''

    logon_type = get('LogonType')
    if isinstance(logon_type, str) and logon_type.isdigit():
        logon_type = int(logon_type)
    return {
        'event_id': evt.get('event_id'),
        'record_id': evt.get('record_id'),
        'timestamp': evt.get('timestamp'),
        'image': get('Image', 'NewProcessName', 'ProcessName', 'Application'),
        'command_line': get('CommandLine', 'ProcessCommandLine'),
        'target_object': get('TargetObject'),
        'service_name': get('ServiceName'),
        'object_name': get('ObjectName'),
        'target_image': get('TargetImage'),
        'logon_type': logon_type,
        'ticket_encryption': get('TicketEncryptionType'),
    }


def _sigma_scan_events(events, tactic=None):
    """Appliquer les regles Sigma integrees sur des evenements deja normalises."""
    connector = SigmaConnector()
    kwargs = {'events': events}
    if tactic:
        kwargs['tactic'] = tactic
    return connector.search('', **kwargs)


@tool(
    'sigma_scan',
    "Scanner un journal EVTX avec les 26 regles Sigma integrees (brute force, pass-the-hash, "
    "Kerberoasting, LSASS, log clearing, persistence, PsExec, C2, ransomware...) : alertes avec "
    "niveau, tactique et technique MITRE ATT&CK. A lancer sur CHAQUE fichier EVTX du cas.",
    _schema({
        'file_path': {'type': 'string', 'description': 'Chemin du fichier .evtx'},
        'tactic': {'type': 'string', 'description': "Filtrer par tactique (ex: 'credential_access', 'persistence')"},
    }, ['file_path']),
)
def sigma_scan(file_path, tactic=None):
    parsed = parsers.parse_evtx(file_path, None, max_records=2000)
    if parsed.get('error'):
        return {'error': parsed['error']}
    events = [_sigma_normalize_event(e) for e in parsed.get('events', [])]
    result = _sigma_scan_events(events, tactic)
    # Compacter : l'evenement complet de chaque alerte est volumineux
    for alert in result.get('alerts', []):
        evt = alert.pop('event', {})
        alert['event_id'] = evt.get('event_id')
        alert['record_id'] = evt.get('record_id')
        alert['timestamp'] = evt.get('timestamp')
    result['file'] = file_path
    return result


@tool(
    'mitre_map_events',
    "Mapper une liste d'Event IDs Windows vers les tactiques et techniques MITRE ATT&CK.",
    _schema({'event_ids': {'type': 'array', 'items': {'type': 'integer'},
                           'description': 'Event IDs Windows observes (ex: [4624, 4625, 1102])'}},
            ['event_ids']),
)
def mitre_map_events(event_ids):
    return {'tactics': mitre.get_attack_summary(event_ids)}


@tool(
    'virustotal_lookup',
    "Enrichir un IoC (ip, domain ou hash) via VirusTotal : score de detection, proprietaire, pays. "
    "Necessite la variable d'environnement API_KEY_VT.",
    _schema({
        'ioc_type': {'type': 'string', 'enum': ['ip', 'domain', 'hash'], 'description': "Type d'IoC"},
        'value': {'type': 'string', 'description': "Valeur de l'IoC"},
    }, ['ioc_type', 'value']),
)
def virustotal_lookup(ioc_type, value):
    api_key = os.environ.get('API_KEY_VT', '')
    if not api_key or api_key.startswith('VOTRE_'):
        return {'error': "Cle VirusTotal absente : definissez la variable d'environnement API_KEY_VT"}
    endpoints = {
        'ip': f'https://www.virustotal.com/api/v3/ip_addresses/{value}',
        'domain': f'https://www.virustotal.com/api/v3/domains/{value}',
        'hash': f'https://www.virustotal.com/api/v3/files/{value}',
    }
    url = endpoints.get(ioc_type)
    if not url:
        return {'error': f"Type d'IoC non supporte: {ioc_type}"}
    try:
        resp = requests.get(url, headers={'accept': 'application/json', 'x-apikey': api_key}, timeout=30)
        if resp.status_code == 404:
            return {'ioc': value, 'found': False, 'message': 'Non reference sur VirusTotal'}
        resp.raise_for_status()
        attrs = resp.json().get('data', {}).get('attributes', {})
        stats = attrs.get('last_analysis_stats', {})
        return {
            'ioc': value,
            'found': True,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'owner': attrs.get('as_owner', 'N/A'),
            'country': attrs.get('country', 'N/A'),
            'reputation': attrs.get('reputation', 0),
        }
    except requests.RequestException as e:
        return {'error': f'Erreur VirusTotal: {e}'}


# ============================================================================
# Outils Eric Zimmermann
# ============================================================================

@tool(
    'zimmermann_status',
    "Verifier la disponibilite des outils forensiques Eric Zimmermann (EvtxECmd, PECmd, LECmd, "
    "MFTECmd, AmcacheParser, AppCompatCacheParser, SBECmd, JLECmd, RECmd, SrumECmd...) : "
    "runtime dotnet, chemin d'installation (EZ_TOOLS_PATH) et outils trouves.",
    _schema({}),
)
def zimmermann_status():
    return zimmermann.status()


@tool(
    'run_zimmermann',
    "Executer un outil Eric Zimmermann sur un artefact (sortie CSV parsee) : EvtxECmd (EVTX), "
    "PECmd (Prefetch), LECmd (LNK), JLECmd (JumpLists), MFTECmd ($MFT/$J), AmcacheParser (Amcache.hve), "
    "AppCompatCacheParser (SYSTEM hive/Shimcache), SBECmd (ShellBags), RECmd (registre), "
    "SrumECmd (SRUM), SQLECmd (SQLite). Utiliser zimmermann_status d'abord ; en cas "
    "d'indisponibilite, se rabattre sur les parsers natifs (parse_evtx, parse_prefetch, parse_lnk...).",
    _schema({
        'tool': {'type': 'string', 'enum': sorted(zimmermann.EZ_TOOLS),
                 'description': "Nom de l'outil Zimmermann"},
        'file_path': {'type': 'string', 'description': "Artefact a traiter (fichier, ou dossier pour SBECmd/SQLECmd)"},
        'max_rows': {'type': 'integer', 'description': 'Nombre max de lignes CSV retournees (defaut 200)'},
    }, ['tool', 'file_path']),
)
def run_zimmermann(tool, file_path, max_rows=200):
    return zimmermann.run(tool, file_path, max_rows=max_rows)


# ============================================================================
# Memoire vive (Volatility 3) et timeline EVTX (Hayabusa)
# ============================================================================

@tool(
    'volatility_status',
    "Verifier la disponibilite de Volatility 3 (analyse de dumps memoire) et lister les plugins "
    "autorises.",
    _schema({}),
)
def volatility_status():
    return volatility.status()


@tool(
    'run_volatility',
    "Executer un plugin Volatility 3 sur un dump memoire (.raw/.mem/.vmem/.dmp/.lime) : processus "
    "(windows.pslist/pstree/psscan), lignes de commande (windows.cmdline), injection de code / "
    "process hollowing (windows.malfind), connexions reseau / beacons C2 (windows.netscan), "
    "services (windows.svcscan), DLL, handles, privileges... Filtre --pid optionnel. "
    "Appeler volatility_status d'abord.",
    _schema({
        'file_path': {'type': 'string', 'description': 'Chemin du dump memoire'},
        'plugin': {'type': 'string', 'enum': sorted(volatility.PLUGINS),
                   'description': 'Plugin Volatility 3 (liste blanche, lecture seule)'},
        'pid': {'type': 'integer', 'description': 'Filtrer sur un PID (plugins compatibles)'},
        'max_rows': {'type': 'integer', 'description': 'Nombre max de lignes retournees (defaut 300)'},
    }, ['file_path', 'plugin']),
)
def run_volatility(file_path, plugin, pid=None, max_rows=300):
    return volatility.run(file_path, plugin, pid=pid, max_rows=max_rows)


@tool(
    'hayabusa_status',
    "Verifier la disponibilite de Hayabusa (timeline de detection EVTX, milliers de regles "
    "Sigma/Hayabusa).",
    _schema({}),
)
def hayabusa_status():
    return hayabusa.status()


@tool(
    'run_hayabusa',
    "Executer Hayabusa json-timeline sur un fichier EVTX ou un dossier d'EVTX : alertes Sigma/"
    "Hayabusa triees par severite (regle, Event ID, RecordID, tactiques MITRE, details). Complete "
    "sigma_scan avec une couverture de regles bien plus large. Appeler hayabusa_status d'abord.",
    _schema({
        'file_path': {'type': 'string', 'description': "Fichier .evtx ou dossier d'EVTX"},
        'min_level': {'type': 'string', 'enum': list(hayabusa.MIN_LEVELS),
                      'description': 'Niveau minimal des alertes (defaut medium)'},
        'max_alerts': {'type': 'integer', 'description': "Nombre max d'alertes retournees (defaut 300)"},
    }, ['file_path']),
)
def run_hayabusa(file_path, min_level='medium', max_alerts=300):
    return hayabusa.run(file_path, min_level=min_level, max_alerts=max_alerts)


# ============================================================================
# Memoire d'enquete (plan, findings, hypotheses)
# ============================================================================

@tool(
    'set_investigation_plan',
    "Definir le plan d'investigation : decomposer le cas en 3 a 7 etapes courtes et actionnables "
    "AVANT de commencer la collecte. A appeler tot dans l'enquete pour rester focalise.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'steps': {'type': 'array', 'items': {'type': 'string'},
                  'description': "Liste ordonnee de 3 a 7 etapes d'investigation"},
    }, ['case_dir', 'steps']),
)
def set_investigation_plan(case_dir, steps):
    return memory.set_plan(case_dir, steps)


@tool(
    'complete_plan_step',
    "Marquer une etape du plan comme terminee (avec une note de resultat). Permet de suivre "
    "l'avancement et d'eviter les oublis.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'step_index': {'type': 'integer', 'description': "Numero de l'etape (1 = premiere)"},
        'note': {'type': 'string', 'description': 'Resultat / conclusion de cette etape'},
    }, ['case_dir', 'step_index']),
)
def complete_plan_step(case_dir, step_index, note=''):
    return memory.complete_step(case_dir, step_index, note)


@tool(
    'record_finding',
    "Consigner un constat d'enquete lie a une preuve : chaque anomalie ou element probant "
    "(alerte Sigma, IoC malveillant, execution suspecte, effacement de logs...). A appeler des "
    "qu'un element significatif est etabli, pour construire le rapport au fil de l'eau. "
    "SORTIE STRICTE : evidence_refs doit citer au moins un identifiant EXACT extrait par un outil "
    "(record_id d'un EVTX via parse_evtx/sigma_scan/run_hayabusa, pid via run_volatility, line via "
    "parse_log_file, row via parse_csv, inode via disk_list_files/disk_timeline) ; un constat sans "
    "reference observee est rejete.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'title': {'type': 'string', 'description': 'Constat en une phrase'},
        'severity': {'type': 'string', 'enum': list(memory.SEVERITIES), 'description': 'Severite'},
        'evidence': {'type': 'string', 'description': 'Preuve : fichier, Event ID, horodatage, IoC...'},
        'mitre': {'type': 'string', 'description': "Technique MITRE ATT&CK (ex: T1110)"},
        'confidence': {'type': 'string', 'enum': list(memory.CONFIDENCES), 'description': 'Niveau de confiance'},
        'evidence_refs': {
            'type': 'array',
            'description': "Identifiants exacts extraits par les outils (au moins un)",
            'items': {
                'type': 'object',
                'properties': {
                    'artifact': {'type': 'string', 'description': "Chemin ou nom de l'artefact"},
                    'kind': {'type': 'string', 'enum': list(REF_KINDS)},
                    'value': {'type': ['integer', 'string'],
                              'description': 'RecordID, PID, numero de ligne, inode (ex: 128-128-1)...'},
                },
                'required': ['artifact', 'kind', 'value'],
                'additionalProperties': False,
            },
        },
    }, ['case_dir', 'title', 'evidence_refs']),
)
def record_finding(case_dir, title, severity='info', evidence='', mitre='', confidence='possible',
                   evidence_refs=None):
    valid, invalid = validate_refs(evidence_refs, case_dir)
    if strict_evidence() and not valid:
        return {
            'error': ("Constat rejete (sortie structuree stricte) : evidence_refs doit citer au moins "
                      "un record_id / pid / line / row EXACT present dans la sortie d'un outil "
                      "deterministe sur cet artefact. Relance l'outil adequat puis cite l'identifiant."),
            'invalid_refs': invalid,
        }
    result = memory.record_finding(case_dir, title, severity, evidence, mitre, confidence,
                                   evidence_refs=valid)
    if invalid:
        result['ignored_refs'] = invalid
    return result


@tool(
    'set_hypothesis',
    "Formuler ou mettre a jour une hypothese d'enquete (DFIR = demarche hypothetico-deductive). "
    "Ex: 'Mouvement lateral via PsExec'. Reappeler avec le meme texte et status 'confirmed'/'refuted' "
    "quand les preuves tranchent.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'hypothesis': {'type': 'string', 'description': "Hypothese (identifiant = son texte)"},
        'status': {'type': 'string', 'enum': list(memory.HYPOTHESIS_STATUSES), 'description': 'Statut'},
        'rationale': {'type': 'string', 'description': 'Preuves confirmant / refutant'},
    }, ['case_dir', 'hypothesis']),
)
def set_hypothesis(case_dir, hypothesis, status='open', rationale=''):
    return memory.set_hypothesis(case_dir, hypothesis, status, rationale)


@tool(
    'get_case_state',
    "Restituer l'etat accumule du cas : plan et avancement, tous les constats (findings) et "
    "hypotheses. A consulter pour se resituer sur un gros cas ou avant de rediger le rapport.",
    _schema({'case_dir': {'type': 'string', 'description': 'Dossier du cas'}}, ['case_dir']),
)
def get_case_state(case_dir):
    return memory.get_state(case_dir)


@tool(
    'verify_finding',
    "Consigner le resultat d'une VERIFICATION INDEPENDANTE d'un constat : apres avoir re-examine "
    "la preuve brute a la source, statuer 'verified' (la preuve confirme), 'unverified' "
    "(impossible a reproduire) ou 'refuted' (la preuve contredit). Reduit les faux positifs.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'finding_id': {'type': 'integer', 'description': 'Numero du constat a verifier'},
        'verdict': {'type': 'string', 'enum': list(memory.VERIFICATION_STATUSES),
                    'description': 'Resultat de la verification'},
        'note': {'type': 'string', 'description': 'Preuve re-examinee justifiant le verdict'},
    }, ['case_dir', 'finding_id', 'verdict']),
)
def verify_finding(case_dir, finding_id, verdict, note=''):
    return memory.verify_finding(case_dir, finding_id, verdict, note)


@tool(
    'propose_remediation',
    "Proposer une action de confinement / remediation (isolement d'hote, kill de processus, blocage "
    "d'IP, desactivation de compte...) soumise a VALIDATION HUMAINE (Human-in-the-Loop). L'action "
    "n'est JAMAIS executee automatiquement : un analyste l'approuve ou la rejette depuis la console "
    "enqueteur DFIR. A utiliser quand une compromission active est etablie par des preuves.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'target_host': {'type': 'string', 'description': 'Hote cible (nom ou IP)'},
        'command': {'type': 'string', 'description': "Commande / action de remediation proposee"},
        'reason': {'type': 'string', 'description': 'Justification appuyee sur les preuves'},
        'mitre': {'type': 'string', 'description': 'Technique MITRE ATT&CK concernee'},
        'severity': {'type': 'string', 'enum': list(memory.SEVERITIES), 'description': 'Severite'},
    }, ['case_dir', 'target_host', 'command', 'reason']),
)
def propose_remediation(case_dir, target_host, command, reason, mitre='', severity='high'):
    return memory.propose_remediation(case_dir, target_host, command, reason, mitre, severity)


# ============================================================================
# Images disque (The Sleuth Kit)
# ============================================================================

@tool(
    'disk_status',
    "Verifier la disponibilite de The Sleuth Kit (analyse d'images disque E01/raw/dd/VMDK/VHD) et "
    "les formats d'image supportes.",
    _schema({}),
)
def disk_status():
    return disk.status()


@tool(
    'disk_image_info',
    "Inspecter une image disque SANS la monter : table de partitions (offsets) et systeme de "
    "fichiers de chaque partition (NTFS, FAT, ext4...). Premiere etape sur toute image disque.",
    _schema({'file_path': {'type': 'string', 'description': "Chemin de l'image (.E01, .dd, .raw, .img...)"}},
            ['file_path']),
)
def disk_image_info(file_path):
    return disk.image_info(file_path)


@tool(
    'disk_list_files',
    "Lister l'arborescence d'une image disque (lecture seule), fichiers SUPPRIMES inclus "
    "(deleted=true), avec inode citable. Filtrer par chemin partiel ou deleted_only.",
    _schema({
        'file_path': {'type': 'string', 'description': "Chemin de l'image"},
        'offset': {'type': 'integer', 'description': 'Offset de partition en secteurs (defaut : toutes)'},
        'path_filter': {'type': 'string', 'description': "Filtre sur le chemin (ex: 'Users/jdoe')"},
        'deleted_only': {'type': 'boolean', 'description': 'Seulement les fichiers supprimes'},
        'max_entries': {'type': 'integer', 'description': "Nombre max d'entrees (defaut 500)"},
    }, ['file_path']),
)
def disk_list_files(file_path, offset=None, path_filter=None, deleted_only=False, max_entries=500):
    return disk.list_files(file_path, offset=offset, path_filter=path_filter,
                           deleted_only=deleted_only, max_entries=max_entries)


@tool(
    'disk_timeline',
    "Timeline MACB du systeme de fichiers d'une image disque (modification, acces, changement, "
    "creation de chaque fichier, supprimes inclus). Les evenements sont indexes dans la "
    "super-timeline du cas pour etre correles avec les journaux (get_timeline).",
    _schema({
        'file_path': {'type': 'string', 'description': "Chemin de l'image"},
        'offset': {'type': 'integer', 'description': 'Offset de partition (defaut : toutes)'},
        'path_filter': {'type': 'string', 'description': 'Filtre sur le chemin'},
    }, ['file_path']),
)
def disk_timeline(file_path, offset=None, path_filter=None):
    result = disk.timeline(file_path, offset=offset, path_filter=path_filter)
    if isinstance(result, dict) and isinstance(result.get('events'), list):
        # Tout est indexe ; seul un apercu est renvoye au LLM
        result['preview'] = result['events'][:100]
    return result


@tool(
    'disk_extract_artifacts',
    "Extraire d'une image disque les artefacts forensiques connus (journaux EVTX, ruches de "
    "registre SYSTEM/SOFTWARE/SAM/NTUSER, Amcache, Prefetch, LNK, historiques navigateurs et "
    "PowerShell, taches planifiees, $MFT, logs et crontabs Linux, cles SSH...) vers le dossier du "
    "cas, avec manifeste de provenance (inode, SHA-256). Les fichiers extraits deviennent des "
    "artefacts a analyser avec les parsers. Profils : windows, linux, auto ; ou patterns "
    "personnalises ('Users/*/Documents/**').",
    _schema({
        'file_path': {'type': 'string', 'description': "Chemin de l'image"},
        'case_dir': {'type': 'string', 'description': 'Dossier du cas (destination)'},
        'offset': {'type': 'integer', 'description': 'Offset de partition (defaut : toutes)'},
        'profile': {'type': 'string', 'enum': sorted(disk.PROFILES), 'description': 'Profil (defaut auto)'},
        'patterns': {'type': 'array', 'items': {'type': 'string'},
                     'description': "Motifs de chemins supplementaires ('*' un niveau, '**' recursif)"},
        'include_deleted': {'type': 'boolean', 'description': 'Inclure les fichiers supprimes (defaut oui)'},
    }, ['file_path', 'case_dir']),
)
def disk_extract_artifacts(file_path, case_dir, offset=None, profile='auto', patterns=None,
                           include_deleted=True):
    return disk.extract_artifacts(file_path, case_dir, offset=offset, profile=profile,
                                  patterns=patterns, include_deleted=include_deleted)


# ============================================================================
# Super-timeline : recherche et chronologie sur tous les artefacts indexes
# ============================================================================

@tool(
    'search_evidence',
    "Recherche plein texte (FTS5) dans TOUS les evenements deja extraits du cas (EVTX, logs, CSV, "
    "Sigma, Hayabusa, Volatility...) : comptes, IP, processus, commandes, chemins. Chaque resultat "
    "porte sa reference de preuve citable (ref : artefact, record_id/pid/line/row). Plusieurs mots "
    "= ET ; utiliser OR entre mots pour une alternative, guillemets pour une expression exacte.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'query': {'type': 'string', 'description': "Termes recherches (ex: 'svc_backup 185.220.101.44')"},
        'artifact': {'type': 'string', 'description': "Limiter a un artefact (nom partiel)"},
        'limit': {'type': 'integer', 'description': 'Nombre max de resultats (defaut 50)'},
    }, ['case_dir', 'query']),
)
def search_evidence(case_dir, query, artifact=None, limit=50):
    return evidence_db.search(case_dir, query, artifact=artifact, limit=limit)


@tool(
    'get_timeline',
    "Super-timeline du cas : evenements de TOUS les artefacts indexes, tries par horodatage UTC, "
    "filtrables par fenetre temporelle, hote, utilisateur, artefact ou texte. Indispensable pour "
    "correler entre sources (ex: connexion -> execution -> persistance -> C2).",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'start': {'type': 'string', 'description': 'Debut (ISO 8601, ex: 2026-10-10T03:00:00Z)'},
        'end': {'type': 'string', 'description': 'Fin (ISO 8601)'},
        'host': {'type': 'string', 'description': 'Filtre hote (partiel)'},
        'user': {'type': 'string', 'description': 'Filtre utilisateur (partiel)'},
        'contains': {'type': 'string', 'description': 'Texte contenu dans l\'evenement'},
        'artifact': {'type': 'string', 'description': 'Filtre artefact (partiel)'},
        'limit': {'type': 'integer', 'description': 'Nombre max d\'evenements (defaut 200)'},
    }, ['case_dir']),
)
def get_timeline(case_dir, start=None, end=None, host=None, user=None, contains=None,
                 artifact=None, limit=200):
    return evidence_db.timeline(case_dir, start=start, end=end, host=host, user=user,
                                contains=contains, artifact=artifact, limit=limit)


@tool(
    'list_sources',
    "Lister les sources indexees du cas : quel outil a ete execute sur quel artefact, avec quel "
    "succes et combien d'evenements, plus l'etendue temporelle couverte.",
    _schema({'case_dir': {'type': 'string', 'description': 'Dossier du cas'}}, ['case_dir']),
)
def list_sources(case_dir):
    return evidence_db.sources(case_dir)


# ============================================================================
# Controle qualite : audits de couverture et contre-analyse
# ============================================================================

_MEMORY_EXT = ('.raw', '.mem', '.vmem', '.dmp', '.lime')


def applicable_tools(path):
    """Groupes d'outils applicables a un artefact : chaque groupe doit etre couvert
    par au moins un de ses outils. Les outils indisponibles sur la machine sont
    signales a part (ils ne constituent pas une lacune de l'enqueteur)."""
    ext = os.path.splitext(path)[1].lower()
    groups, unavailable = [], []
    if disk.looks_like_disk(path):
        if disk.tsk_available():
            groups = [('inventaire disque', ('disk_image_info', 'disk_list_files')),
                      ('extraction disque', ('disk_extract_artifacts',)),
                      ('timeline disque', ('disk_timeline',))]
        else:
            unavailable.append('The Sleuth Kit')
    elif ext == '.evtx':
        groups = [('parsing', ('parse_evtx', 'analyze_artifact', 'run_zimmermann')),
                  ('detection', ('sigma_scan', 'run_hayabusa'))]
    elif ext in ('.log', '.txt', '.xml', '.ps1', '.bat', '.sh'):
        groups = [('parsing', ('parse_log_file', 'analyze_artifact'))]
    elif ext == '.csv':
        groups = [('parsing', ('parse_csv', 'analyze_artifact'))]
    elif ext == '.json':
        groups = [('parsing', ('parse_json_file', 'analyze_artifact'))]
    elif ext == '.pf':
        groups = [('parsing', ('parse_prefetch', 'analyze_artifact', 'run_zimmermann'))]
    elif ext == '.lnk':
        groups = [('parsing', ('parse_lnk', 'analyze_artifact', 'run_zimmermann'))]
    elif ext in ('.sqlite', '.db'):
        groups = [('parsing', ('parse_browser_history', 'analyze_artifact', 'run_zimmermann'))]
    elif ext in _MEMORY_EXT:
        if volatility.status()['available']:
            groups = [('memoire', ('run_volatility',))]
        else:
            unavailable.append('Volatility 3')
    elif ext in ('.hve', '.dat', '.mft'):
        if zimmermann.status()['available']:
            groups = [('parsing', ('run_zimmermann',))]
        else:
            unavailable.append('EZ Tools')
    return groups, unavailable


@tool(
    'audit_tool_coverage',
    "Audit de couverture des OUTILS : pour chaque artefact, verifier que les outils applicables "
    "(parsing, detection Sigma/Hayabusa, memoire) ont bien ete executes. Retourne les lacunes a "
    "combler. A appeler en fin d'extraction et pendant la contre-analyse.",
    _schema({'case_dir': {'type': 'string', 'description': 'Dossier du cas'}}, ['case_dir']),
)
def audit_tool_coverage(case_dir):
    if not os.path.isdir(case_dir):
        return {'error': f"Dossier introuvable: {case_dir}"}
    result = compute_tool_coverage(case_dir)
    memory.mark_audit(case_dir, 'tool_coverage', {k: result[k] for k in
                                                  ('artifacts_fully_covered', 'gap_count')})
    return result


def compute_tool_coverage(case_dir):
    """Lacunes de couverture d'outils (sans marquer l'audit comme effectue)."""
    runs = evidence_db.runs_by_artifact(case_dir)
    gaps, unavailable, failed, covered = [], [], [], 0
    for path in case_artifacts(case_dir):
        rel = os.path.relpath(path, case_dir)
        artifact_runs = runs.get(rel, {})
        attempted = set(artifact_runs)
        groups, missing_tools = applicable_tools(path)
        for label in missing_tools:
            unavailable.append({'artifact': rel, 'tool': label})
        # Un outil tente mais en echec (dump corrompu, symboles absents...) couvre
        # l'etape : il est signale a part, sans bloquer indefiniment l'enquete.
        artifact_gaps = [{'artifact': rel, 'step': step, 'run_one_of': list(tools)}
                         for step, tools in groups if not attempted.intersection(tools)]
        for step, tools in groups:
            tried = attempted.intersection(tools)
            if tried and not any(artifact_runs[t] for t in tried):
                failed.append({'artifact': rel, 'step': step, 'failed_tools': sorted(tried)})
        gaps.extend(artifact_gaps)
        if groups and not artifact_gaps:
            covered += 1
    return {'gaps': gaps, 'failed_runs': failed, 'unavailable_tools': unavailable,
            'artifacts_fully_covered': covered, 'gap_count': len(gaps), 'complete': not gaps}


@tool(
    'audit_evidence_coverage',
    "Audit de couverture des PREUVES : artefacts jamais analyses, et artefacts analyses mais jamais "
    "cites dans un constat (pistes potentiellement ignorees). A appeler pendant la contre-analyse.",
    _schema({'case_dir': {'type': 'string', 'description': 'Dossier du cas'}}, ['case_dir']),
)
def audit_evidence_coverage(case_dir):
    if not os.path.isdir(case_dir):
        return {'error': f"Dossier introuvable: {case_dir}"}
    runs = evidence_db.runs_by_artifact(case_dir)
    cited = set()
    for f in memory.get_state(case_dir)['findings']:
        for ref in f.get('evidence_refs') or []:
            cited.add(os.path.basename(str(ref.get('artifact', ''))))
    never_analyzed, analyzed_not_cited, cited_list = [], [], []
    for path in case_artifacts(case_dir):
        rel = os.path.relpath(path, case_dir)
        if not any(runs.get(rel, {}).values()):
            never_analyzed.append(rel)
        elif os.path.basename(rel) in cited:
            cited_list.append(rel)
        else:
            analyzed_not_cited.append(rel)
    summary = {'never_analyzed_count': len(never_analyzed),
               'analyzed_not_cited_count': len(analyzed_not_cited), 'cited_count': len(cited_list)}
    memory.mark_audit(case_dir, 'evidence_coverage', summary)
    return {'never_analyzed': never_analyzed, 'analyzed_not_cited': analyzed_not_cited,
            'cited': cited_list, **summary}


@tool(
    'challenge_finding',
    "CONTRE-ANALYSE d'un constat : formuler l'hypothese alternative la plus plausible (activite "
    "legitime, faux positif d'outil, autre acteur...), chercher les preuves qui la soutiendraient "
    "(search_evidence, get_timeline), puis statuer : 'upheld' (le constat resiste), 'downgraded' "
    "(affaibli, preciser new_severity) ou 'refuted' (l'alternative l'emporte). Obligatoire pour "
    "chaque constat critical/high.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'finding_id': {'type': 'integer', 'description': 'Numero du constat'},
        'alternative': {'type': 'string', 'description': 'Hypothese alternative testee'},
        'verdict': {'type': 'string', 'enum': list(memory.CHALLENGE_VERDICTS)},
        'rationale': {'type': 'string', 'description': 'Preuves pour et contre, avec references'},
        'new_severity': {'type': 'string', 'enum': list(memory.SEVERITIES),
                         'description': 'Nouvelle severite si downgraded'},
    }, ['case_dir', 'finding_id', 'alternative', 'verdict', 'rationale']),
)
def challenge_finding(case_dir, finding_id, alternative, verdict, rationale, new_severity=None):
    return memory.challenge_finding(case_dir, finding_id, alternative, verdict, rationale, new_severity)


@tool(
    'declare_no_incident',
    "Conclure EXPLICITEMENT qu'aucun incident n'est etabli (activite legitime), avec la "
    "justification fondee sur les preuves examinees. Ne jamais inventer de constat pour remplir "
    "une enquete : un cas sain est un resultat valide.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'rationale': {'type': 'string', 'description': 'Pourquoi aucun incident (preuves examinees)'},
    }, ['case_dir', 'rationale']),
)
def declare_no_incident(case_dir, rationale):
    return memory.declare_no_incident(case_dir, rationale)


# ============================================================================
# Rapport
# ============================================================================

ANNEX_MARKER = '\n\n---\n\n# Annexe - Synthese d\'enquete\n\n'


def _with_annex(body, case_dir):
    """Attacher (ou remplacer) l'annexe de synthese memoire au corps du rapport."""
    base = body.split(ANNEX_MARKER, 1)[0].rstrip()
    state_md = memory.render_markdown(case_dir)
    if state_md.strip():
        return base + ANNEX_MARKER + state_md
    return base


def refresh_report_annex(report_path, case_dir):
    """Regenerer l'annexe d'un rapport deja ecrit (apres la verification)."""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        refreshed = _with_annex(content, case_dir)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(refreshed if refreshed.endswith('\n') else refreshed + '\n')
        _write_exports(case_dir, refreshed)
        return True
    except OSError:
        return False


@tool(
    'save_report',
    "Sauvegarder le rapport d'enquete final au format Markdown dans le dossier du cas. "
    "A appeler UNE FOIS en fin d'investigation avec le rapport complet (resume executif, "
    "artefacts analyses, IoCs, timeline, mapping MITRE, conclusions et recommandations).",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'title': {'type': 'string', 'description': 'Titre du rapport'},
        'markdown': {'type': 'string', 'description': 'Contenu Markdown complet du rapport'},
    }, ['case_dir', 'title', 'markdown']),
)
def save_report(case_dir, title, markdown):
    if not os.path.isdir(case_dir):
        return {'error': f"Dossier introuvable: {case_dir}"}
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(case_dir, f'rapport_phoenix_{ts}.md')
    header = (f"# {title}\n\n> Rapport genere par Phoenix DFIR (enqueteur GitHub Copilot) "
              f"le {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    body = markdown if markdown.lstrip().startswith('#') else header + markdown
    # Annexer automatiquement la memoire d'enquete (findings, hypotheses, plan)
    # pour que le rapport soit toujours trace aux preuves accumulees.
    body = _with_annex(body, case_dir)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(body if body.endswith('\n') else body + '\n')
    result = {'saved': True, 'report_path': path, 'size_bytes': os.path.getsize(path)}
    written = _write_exports(case_dir, body)
    if written:
        result['exports'] = written
    return result


def _write_exports(case_dir, report_text):
    """Calque ATT&CK Navigator + CSV d'IoCs a cote du rapport (best-effort)."""
    first = (report_text or '').lstrip().splitlines()[:1]
    title = first[0].lstrip('# ').strip() if first else 'Enquete'
    try:
        return exports.write_exports(case_dir, title, report_text)
    except Exception:
        return None


def to_json(result, limit=None):
    """Serialiser un resultat d'outil en JSON compact, tronque si necessaire."""
    text = json.dumps(result, ensure_ascii=False, default=str)
    if limit and len(text) > limit:
        text = text[:limit] + f'... [tronque, {len(text)} caracteres au total]'
    return text
