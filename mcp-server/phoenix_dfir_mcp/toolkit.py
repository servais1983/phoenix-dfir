"""Boite a outils DFIR : registre unique des outils forensiques.

Chaque outil est declare une seule fois (nom, description, schema JSON des
parametres, fonction Python). Le meme registre alimente :
- le serveur MCP (tools/list, tools/call) pour GitHub Copilot en mode agent ;
- l'enqueteur autonome (function calling via l'API GitHub Models).

Les parsers proviennent du backend Phoenix (backend/parsers.py, mitre.py,
integrations/sigma_connector.py) — aucune logique dupliquee.

This module keeps the registry, the evidence index, run_tool and the
extensions. The core tools live in one module per family (tools_artifacts,
tools_external, tools_case, tools_disk, tools_evidence), imported in order so
the tool list is unchanged, and every name is re-exported here.
"""

import datetime
import hashlib
import json
import os
import re
import threading

import requests

from ._paths import ensure_backend_importable

# Rendre les modules du backend Phoenix importables (point unique : _paths.py)
ensure_backend_importable()

import mitre  # noqa: E402
import parsers  # noqa: E402
from integrations.ioc_validation import InvalidIoC, path_segment, validate_ioc  # noqa: E402
from integrations.sigma_connector import SigmaConnector  # noqa: E402

from . import contracts  # noqa: E402
from . import disk  # noqa: E402
from . import evidence_db  # noqa: E402
from . import exports  # noqa: E402
from . import hayabusa  # noqa: E402
from . import memory  # noqa: E402
from . import pathpolicy  # noqa: E402
from . import sigma_engine  # noqa: E402
from . import verifier  # noqa: E402
from . import workspace  # noqa: E402
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
    """Dossier du cas courant (par thread) : cible de l'index de preuves.

    Pendant un job d'investigation, le dossier du job (pathpolicy.job_scope)
    prime toujours sur cette valeur."""
    _active.case_dir = os.path.abspath(case_dir) if case_dir else None


def active_case():
    job_case = pathpolicy.current_case()
    if job_case:
        return job_case
    return getattr(_active, 'case_dir', None)


def _rel_in_case(path, case_dir):
    """Chemin de l'artefact relatif au cas ('/' comme separateur), '.' pour le
    cas lui-meme, ou None s'il est hors du cas. Un lien symbolique du cas
    (evidence du coffre) reste rattache au cas par son chemin logique."""
    if not path or not case_dir:
        return None
    for candidate, case in ((os.path.abspath(path), os.path.abspath(case_dir)),
                            (os.path.realpath(path), os.path.realpath(case_dir))):
        if os.path.normcase(candidate) == os.path.normcase(case):
            return '.'
        if pathpolicy._contains(candidate, case, strict=True):
            return os.path.relpath(candidate, case).replace(os.sep, '/')
    return None


def _case_for(file_path):
    case = active_case()
    if case and _rel_in_case(file_path, case) not in (None, '.'):
        return case
    return None


# Index des preuves CLOISONNE PAR CAS :
#   portee (dossier reel du cas, ou '' hors cas en mode MCP stdio)
#     -> cle d'artefact (chemin relatif au cas, ou chemin reel hors cas)
#       -> {kind: set(valeurs)}
# Un constat du cas A ne peut donc jamais citer un identifiant observe dans le
# cas B, meme si les deux artefacts portent le meme nom.
_GLOBAL_SCOPE = ''
_evidence_index = {}
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


def _index_slot(file_path):
    """(portee, cle) d'indexation d'un artefact, ou None s'il ne doit pas etre indexe."""
    case = active_case()
    if case:
        rel = _rel_in_case(file_path, case)
        if rel is not None:
            return os.path.realpath(case), rel
        if pathpolicy.current_job() is not None:
            return None  # job actif : rien n'est indexe hors du cas du job
    return _GLOBAL_SCOPE, os.path.realpath(file_path)


def index_evidence(arguments, result):
    """Indexer les identifiants de preuve d'une sortie d'outil reussie."""
    file_path = (arguments or {}).get('file_path')
    if not isinstance(file_path, str) or not isinstance(result, dict) or result.get('error'):
        return 0
    found = {}
    _harvest(result, found)
    if not found:
        return 0
    slot = _index_slot(file_path)
    if slot is None:
        return 0
    scope, key = slot
    with _evidence_lock:
        bucket = _evidence_index.setdefault(scope, {}).setdefault(key, {})
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


def _basename(path):
    return re.split(r'[\\/]', str(path).rstrip('/\\'))[-1]


def _key_matches(key, wanted, sep):
    """Une cle d'index correspond-elle a la reference : meme chemin, meme nom
    de fichier, ou dossier analyse (Hayabusa...) contenant l'artefact cite ?"""
    if key == '.':
        return True  # outil lance sur le dossier du cas entier (Hayabusa...)
    if key == wanted or _basename(key) == _basename(wanted):
        return True
    return bool(wanted) and wanted.startswith(key.rstrip(sep) + sep)


def _matching_buckets(artifact, case_dir):
    """Entrees de l'index consultables pour un artefact cite, limitees au cas."""
    if case_dir:
        scope = os.path.realpath(case_dir)
        if os.path.isabs(artifact):
            rel = _rel_in_case(artifact, case_dir)
            if rel is None:
                return []  # chemin absolu hors du cas : jamais valide pour ce cas
        else:
            rel = os.path.normpath(artifact).replace(os.sep, '/')
        buckets = [bucket for key, bucket in _evidence_index.get(scope, {}).items()
                   if _key_matches(key, rel, '/')]
        # Mode MCP stdio : artefacts indexes sans cas actif mais situes dans ce cas
        wanted = os.path.realpath(os.path.join(case_dir, artifact))
        buckets += [bucket for key, bucket in _evidence_index.get(_GLOBAL_SCOPE, {}).items()
                    if _rel_in_case(key, scope) is not None and _key_matches(key, wanted, os.sep)]
        return buckets
    wanted = os.path.realpath(artifact)
    return [bucket for key, bucket in _evidence_index.get(_GLOBAL_SCOPE, {}).items()
            if _key_matches(key, wanted, os.sep)]


def validate_refs(refs, case_dir=None):
    """Separer les references de preuve observees (valides) des inventees.

    Seul le cas courant est consulte (index memoire cloisonne par cas + base
    de preuves persistante du cas). Pendant un job, le cas du job est impose."""
    valid, invalid = [], []
    case_dir = pathpolicy.current_case() or case_dir or active_case()
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
            ok = any(value in bucket.get(kind, ())
                     for bucket in _matching_buckets(artifact, case_dir))
        outside = bool(case_dir) and os.path.isabs(artifact) and _rel_in_case(artifact, case_dir) is None
        if not ok and case_dir and not outside:
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
    except Exception:  # nosec B110 - l'indexation ne doit jamais faire echouer l'outil
        pass


def _enforce_job_case(name, arguments):
    """Pendant un job, tout argument case_dir est IMPOSE au dossier du job :
    le LLM (potentiellement manipule par une injection) ne choisit jamais le
    cas dans lequel la memoire, le rapport ou l'extraction lisent et ecrivent."""
    job_case = pathpolicy.current_case()
    if not job_case:
        return arguments
    props = (TOOLS[name].get('input_schema') or {}).get('properties') or {}
    if 'case_dir' in props or 'case_dir' in arguments:
        arguments = dict(arguments)
        arguments['case_dir'] = job_case
    return arguments


def run_tool(name, arguments=None):
    """Executer un outil et retourner un resultat JSON-serialisable."""
    if name not in TOOLS:
        return {'error': f"Outil inconnu: {name}. Outils disponibles: {sorted(TOOLS)}"}
    if not isinstance(arguments, dict):
        arguments = {}
    arguments = _enforce_job_case(name, arguments)
    # Sandboxing : refuser tout acces fichier hors des racines autorisees
    for key in _PATH_ARGS:
        value = arguments.get(key)
        if value is not None and not isinstance(value, str):
            return {'error': f"Argument '{key}' invalide : chemin attendu"}
        if value:
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


def to_json(result, limit=None):
    """Serialiser un resultat d'outil en JSON compact, tronque si necessaire."""
    text = json.dumps(result, ensure_ascii=False, default=str)
    if limit and len(text) > limit:
        text = text[:limit] + f'... [tronque, {len(text)} caracteres au total]'
    return text


# ============================================================================
# Tools, by family (one module each, registered in order in TOOLS)
# ============================================================================
# Every name stays reachable as toolkit.<name> (MCP server, engines, tests).

from .tools_artifacts import (  # noqa: E402,F401
    _KNOWN_TYPES, INTERNAL_FILES, EXT_INTERNAL_FILES, EXT_INTERNAL_PREFIXES, EXT_INTERNAL_DIRS,
    LAYOUT_INTERNAL_DIRS, LAYOUT_INTERNAL_FILES, is_internal_file, case_artifacts, list_artifacts, parse_evtx,
    parse_csv, parse_json_file, DEFAULT_MAX_JSON_MB, _max_json_bytes, _json_too_big, parse_log_file,
    parse_prefetch, parse_lnk, parse_browser_history, analyze_artifact, extract_iocs, _sigma_normalize_event,
    _EVENT_ID_KEYS, _RECORD_ID_KEYS, _EXPORT_EXT, _int_or_none, _first_key, _load_event_export,
    is_windows_event_export, _sigma_scan_events, sigma_scan, mitre_map_events, virustotal_lookup,
)
from .tools_external import (  # noqa: E402,F401
    zimmermann_status, run_zimmermann, volatility_status, run_volatility, hayabusa_status, run_hayabusa,
)
from .tools_case import (  # noqa: E402,F401
    set_investigation_plan, complete_plan_step, record_finding, set_hypothesis, get_case_state,
    verify_finding, propose_remediation,
)
from .tools_disk import (  # noqa: E402,F401
    disk_status, disk_image_info, disk_list_files, disk_timeline, disk_extract_artifacts,
)
from .tools_evidence import (  # noqa: E402,F401
    search_evidence, get_timeline, list_sources, _MEMORY_EXT, applicable_tools, audit_tool_coverage,
    compute_tool_coverage, audit_evidence_coverage, challenge_finding, declare_no_incident, ANNEX_MARKER,
    report_quality, _with_annex, refresh_report_annex, save_report, _write_exports,
)


# ============================================================================
# Extensions (phoenix_dfir_mcp/ext) : outils supplementaires auto-declares
# ============================================================================

_EXT_MODULES = []
EXT_PHASE_TOOLS = {}
EXT_PHASE_HINTS = {}
EXT_ERRORS = {}
EXT_TOOLS = set()  # outils enregistres par les extensions
EXT_PASSTHROUGH = set()  # outils de pilotage hors quarantaine double LLM (dualllm.py)


def _load_extensions():
    global READONLY_TOOLS, INDEXED_TOOLS
    import importlib
    from .ext import EXTENSIONS
    for name in EXTENSIONS:
        before = set(TOOLS)
        try:
            module = importlib.import_module(f'.ext.{name}', __package__)
        except Exception as exc:  # une extension cassee ne bloque pas les autres
            EXT_ERRORS[name] = f'{type(exc).__name__}: {exc}'
            continue
        _EXT_MODULES.append(module)
        EXT_TOOLS.update(set(TOOLS) - before)
        agent = getattr(module, 'AGENT', None)
        if agent:
            AGENTS[agent[0]] = agent[1]
        READONLY_TOOLS = READONLY_TOOLS + tuple(getattr(module, 'READONLY', ()))
        INDEXED_TOOLS = INDEXED_TOOLS + tuple(getattr(module, 'INDEXED', ()))
        _KNOWN_TYPES.update(getattr(module, 'KNOWN_TYPES', {}))
        EXT_INTERNAL_FILES.update(getattr(module, 'INTERNAL_FILES', ()))
        EXT_INTERNAL_PREFIXES.update(getattr(module, 'INTERNAL_PREFIXES', ()))
        EXT_INTERNAL_DIRS.update(getattr(module, 'INTERNAL_DIRS', ()))
        EXT_PASSTHROUGH.update(getattr(module, 'PASSTHROUGH', ()))
        for phase, names in getattr(module, 'PHASE_TOOLS', {}).items():
            EXT_PHASE_TOOLS.setdefault(phase, []).extend(names)
        for phase, hint in getattr(module, 'PHASE_HINTS', {}).items():
            EXT_PHASE_HINTS.setdefault(phase, []).append(hint)
        if agent:
            for tool_name in getattr(module, 'TOOL_NAMES', ()) or (set(TOOLS) - before):
                _TOOL_AGENT.setdefault(tool_name, agent[0])


_load_extensions()
