"""Inventory, native parsers, IoCs, Sigma, ATT&CK mapping and VirusTotal tools.

Registered in the single tool registry of ``toolkit``, which re-exports every
name: callers keep using ``toolkit.<name>``.
"""

import hashlib
import os

import requests

from ._paths import ensure_backend_importable

ensure_backend_importable()

import mitre  # noqa: E402
import parsers  # noqa: E402
from integrations.ioc_validation import InvalidIoC, path_segment, validate_ioc  # noqa: E402
from integrations.sigma_connector import SigmaConnector  # noqa: E402

from . import disk, evidence_db, kerberos, logdetect, memory, sigma_engine, workspace  # noqa: E402
from .toolkit import _schema, set_active_case, tool  # noqa: E402

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


# ground_truth.json : corrige d'un cas d'evaluation, jamais une preuve (ne doit
# atteindre ni l'enqueteur ni le triage)
INTERNAL_FILES = (memory.STATE_FILENAME, evidence_db.DB_NAME, 'PHOENIX.md',
                  'attack_navigator_layer.json', 'iocs.csv', 'ground_truth.json')


# Fichiers internes declares par les extensions (graphe, regles generees...)
EXT_INTERNAL_FILES = set()
EXT_INTERNAL_PREFIXES = set()
EXT_INTERNAL_DIRS = set()  # sous-dossiers de premier niveau du cas produits par Phoenix
# Disposition standard (evidence/ present) : rapports, custody et manifeste ne
# sont pas des preuves ; derived/ reste visible (fichiers extraits a analyser)
LAYOUT_INTERNAL_DIRS = {'reports', 'custody'}
LAYOUT_INTERNAL_FILES = {'manifest.sha256', 'manifest.sha256.tmp'}



def is_internal_file(fname):
    """Fichiers produits par Phoenix dans le dossier du cas (pas des preuves)."""
    return (fname in INTERNAL_FILES or fname.startswith('rapport_phoenix_')
            or fname.startswith(evidence_db.DB_NAME) or disk.is_manifest(fname)
            or fname in EXT_INTERNAL_FILES
            or any(fname.startswith(p) for p in EXT_INTERNAL_PREFIXES))


def case_artifacts(case_dir):
    """Chemins des artefacts du cas (hors fichiers internes de Phoenix)."""
    paths = []
    layout = workspace.has_layout(case_dir)
    for root, dirs, files in os.walk(case_dir):
        at_top = os.path.abspath(root) == os.path.abspath(case_dir)
        if at_top:
            skipped = EXT_INTERNAL_DIRS | (LAYOUT_INTERNAL_DIRS if layout else set())
            dirs[:] = [d for d in dirs if d not in skipped]
        for fname in sorted(files):
            if is_internal_file(fname) or (at_top and layout and fname in LAYOUT_INTERNAL_FILES):
                continue
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
    for root, dirs, files in os.walk(case_dir):
        if os.path.abspath(root) == os.path.abspath(case_dir) and EXT_INTERNAL_DIRS:
            dirs[:] = [d for d in dirs if d not in EXT_INTERNAL_DIRS]
        for fname in sorted(f for f in files if not is_internal_file(f)):
            path = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            try:
                size = os.path.getsize(path)
                md5, sha256 = hashlib.md5(usedforsecurity=False), hashlib.sha256()
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
    too_big = _json_too_big(file_path)
    if too_big:
        return too_big
    return parsers.parse_json(file_path)


# Un JSON est charge entierement en memoire : au-dela de ce plafond (Mo,
# PHOENIX_MAX_JSON_MB), l'outil refuse explicitement plutot que de saturer la RAM.
DEFAULT_MAX_JSON_MB = 64


def _max_json_bytes():
    try:
        return max(1, int(os.environ.get('PHOENIX_MAX_JSON_MB', DEFAULT_MAX_JSON_MB))) << 20
    except ValueError:
        return DEFAULT_MAX_JSON_MB << 20


def _json_too_big(file_path):
    try:
        size = os.path.getsize(file_path)
    except OSError:
        return None  # le parser remontera l'erreur de lecture
    limit = _max_json_bytes()
    if size > limit:
        return {'error': (f"Fichier JSON trop volumineux ({size} octets > {limit} octets) : "
                          "chargement refuse. Utiliser parse_log_file (lecture ligne a ligne) "
                          "ou extract_iocs sur ce fichier."),
                'size_bytes': size, 'limit_bytes': limit}
    return None


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
    result = parsers.parse_log(file_path, max_lines)
    if not result.get('error'):
        # Deterministic detections (SSH brute force...), each citing its line
        alerts = logdetect.detect(result.get('events', []))
        if alerts:
            result['alerts'] = alerts
    return result


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
    if os.path.splitext(file_path)[1].lower() == '.json':
        too_big = _json_too_big(file_path)
        if too_big:
            return too_big
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
        'properties': ' '.join(str(get(n)) for n in ('Properties', 'AccessList', 'ObjectType', 'Message', 'message')
                               if get(n)),
        'subject_user': get('SubjectUserName'),
    }


# Exports d'evenements Windows (JSON / JSON Lines / CSV issus d'un SIEM ou d'un
# convertisseur EVTX) : memes regles Sigma que les fichiers .evtx natifs.
_EVENT_ID_KEYS = ('EventID', 'EventId', 'event_id', 'EventCode', 'eventid', 'Id')
_RECORD_ID_KEYS = ('RecordID', 'EventRecordID', 'RecordNumber', 'record_id')
_EXPORT_EXT = ('.json', '.jsonl', '.ndjson', '.csv')


def _int_or_none(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _first_key(data, keys):
    for k in keys:
        if k in data and data[k] not in (None, ''):
            return data[k]
    system = data.get('System') if isinstance(data.get('System'), dict) else None
    if system:
        return _first_key(system, keys)
    return None


def _load_event_export(file_path):
    """Evenements Windows d'un export JSON/CSV au format attendu par la normalisation Sigma."""
    ext = os.path.splitext(file_path)[1].lower()
    parsed = parsers.parse_csv(file_path) if ext == '.csv' else parsers.parse_json(file_path)
    if parsed.get('error'):
        return None, parsed['error']
    events = []
    for evt in parsed.get('events', []):
        data = evt.get('data') if isinstance(evt.get('data'), dict) else {}
        event_id = _int_or_none(_first_key(data, _EVENT_ID_KEYS))
        if event_id is None:
            continue
        events.append({'event_id': event_id,
                       'record_id': _int_or_none(_first_key(data, _RECORD_ID_KEYS)),
                       'timestamp': evt.get('timestamp'), 'row': evt.get('row'), 'data': data})
    return events, None


def is_windows_event_export(file_path, sample=50):
    """Vrai si un fichier JSON/CSV contient des evenements Windows (Event ID)."""
    if os.path.splitext(file_path)[1].lower() not in _EXPORT_EXT:
        return False
    try:
        if os.path.getsize(file_path) > 512 * 1024 * 1024:
            return False
        events, error = _load_event_export(file_path)
    except Exception:
        return False
    return bool(events) and not error


def _sigma_scan_events(events, tactic=None):
    """Appliquer les regles Sigma integrees sur des evenements deja normalises."""
    connector = SigmaConnector()
    kwargs = {'events': events}
    if tactic:
        kwargs['tactic'] = tactic
    return connector.search('', **kwargs)


@tool(
    'sigma_scan',
    "Scanner un journal EVTX, ou un export d'evenements Windows en JSON / JSON Lines / CSV (champ EventID), "
    "avec les 29 regles Sigma integrees (brute force, pass-the-hash, Kerberoasting, DCSync, LSASS, log "
    "clearing, persistence, PsExec, C2, ransomware...) et, si pySigma est installe, les regles SigmaHQ "
    "(sous-ensemble embarque, phoenix rules sync, phoenix rules import) : alertes avec niveau, tactique, "
    "technique MITRE ATT&CK et record_id/row de l'evenement. A lancer sur CHAQUE journal Windows du cas.",
    _schema({
        'file_path': {'type': 'string', 'description': 'Chemin du fichier .evtx ou de l\'export JSON/CSV'},
        'tactic': {'type': 'string', 'description': "Filtrer par tactique (ex: 'credential_access', 'persistence')"},
    }, ['file_path']),
)
def sigma_scan(file_path, tactic=None):
    if os.path.splitext(file_path)[1].lower() in _EXPORT_EXT:
        raw, error = _load_event_export(file_path)
        if error:
            return {'error': error}
        if not raw:
            return {'error': "Aucun evenement Windows (champ EventID) dans ce fichier"}
    else:
        parsed = parsers.parse_evtx(file_path, None, max_records=2000)
        if parsed.get('error'):
            return {'error': parsed['error']}
        raw = parsed.get('events', [])
    events = []
    for e in raw:
        normalized = _sigma_normalize_event(e)
        if e.get('row') is not None:
            normalized['row'] = e['row']
        events.append(normalized)
    result = _sigma_scan_events(events, tactic)
    # Compacter : l'evenement complet de chaque alerte est volumineux
    for alert in result.get('alerts', []):
        evt = alert.pop('event', {})
        alert['engine'] = 'builtin'
        alert['event_id'] = evt.get('event_id')
        alert['record_id'] = evt.get('record_id')
        alert['timestamp'] = evt.get('timestamp')
        if evt.get('row') is not None:
            alert['row'] = evt['row']
    engines = {'builtin': {'rules': result.get('rules_evaluated', 0), 'alerts': len(result.get('alerts', []))}}
    hq = sigma_engine.scan(raw, extra_dirs=[sigma_engine.connector_rules_path()])
    if hq.get('available'):
        hq_alerts = [a for a in hq['alerts'] if not tactic or tactic in a.get('tactics', [])]
        result['alerts'] = result.get('alerts', []) + hq_alerts
        result['total_alerts'] = len(result['alerts'])
        result['message'] = f"{result['total_alerts']} alerte(s) Sigma declenchee(s)"
        engines['pysigma'] = {'rules': hq['rules_loaded'], 'alerts': len(hq_alerts),
                              'rules_skipped_logsource': hq['rules_skipped_logsource'],
                              'rules_invalid': hq['rules_invalid'], 'rules_failed': hq['rules_failed']}
    else:
        engines['pysigma'] = {'status': hq.get('detail', 'not available')}
    # Kerberos correlation: a TGS without TGT is a forged ticket, not Kerberoasting
    kept, forged, reclassified = kerberos.correlate(result.get('alerts', []), raw)
    if forged and (not tactic or tactic == 'credential_access'):
        kept = kept + forged
    if forged or reclassified:
        result['alerts'] = kept
        result['total_alerts'] = len(kept)
        result['message'] = f"{len(kept)} alerte(s) Sigma declenchee(s)"
    engines['correlation'] = {'alerts': len(forged), 'reclassified': reclassified}
    result['engines'] = engines
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
        'ip': 'https://www.virustotal.com/api/v3/ip_addresses/',
        'domain': 'https://www.virustotal.com/api/v3/domains/',
        'hash': 'https://www.virustotal.com/api/v3/files/',
    }
    base = endpoints.get(ioc_type)
    if not base:
        return {'error': f"Type d'IoC non supporte: {ioc_type}"}
    try:
        value = validate_ioc(ioc_type, value)
    except InvalidIoC as e:
        return {'error': str(e)}
    url = base + path_segment(value)
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
