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
import sys

import requests

# Rendre les modules du backend Phoenix importables
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_BACKEND_DIR = os.path.join(_REPO_ROOT, 'backend')
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import mitre  # noqa: E402
import parsers  # noqa: E402
from integrations.sigma_connector import SigmaConnector  # noqa: E402

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


def openai_tools():
    """Liste des outils au format function-calling OpenAI (API GitHub Models)."""
    return [
        {
            'type': 'function',
            'function': {
                'name': t['name'],
                'description': t['description'],
                'parameters': t['input_schema'],
            },
        }
        for t in TOOLS.values()
    ]


def run_tool(name, arguments=None):
    """Executer un outil et retourner un resultat JSON-serialisable."""
    if name not in TOOLS:
        return {'error': f"Outil inconnu: {name}. Outils disponibles: {sorted(TOOLS)}"}
    try:
        return TOOLS[name]['func'](**(arguments or {}))
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
}


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
    artifacts = []
    for root, _dirs, files in os.walk(case_dir):
        for fname in sorted(files):
            path = os.path.join(root, fname)
            ext = os.path.splitext(fname)[1].lower()
            try:
                size = os.path.getsize(path)
                md5, sha256 = hashlib.md5(), hashlib.sha256()
                with open(path, 'rb') as f:
                    for chunk in iter(lambda: f.read(1 << 20), b''):
                        md5.update(chunk)
                        sha256.update(chunk)
                artifacts.append({
                    'path': path,
                    'name': fname,
                    'type': _KNOWN_TYPES.get(ext, f'Inconnu ({ext or "sans extension"})'),
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
# Rapport
# ============================================================================

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
    with open(path, 'w', encoding='utf-8') as f:
        f.write(body if body.endswith('\n') else body + '\n')
    return {'saved': True, 'report_path': path, 'size_bytes': os.path.getsize(path)}


def to_json(result, limit=None):
    """Serialiser un resultat d'outil en JSON compact, tronque si necessaire."""
    text = json.dumps(result, ensure_ascii=False, default=str)
    if limit and len(text) > limit:
        text = text[:limit] + f'... [tronque, {len(text)} caracteres au total]'
    return text
