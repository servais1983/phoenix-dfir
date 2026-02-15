"""
Phoenix DFIR - Standalone File Parsers
Analyse de fichiers sans dependance IA externe
"""

import csv
import json
import re
import io
import os
import xml.etree.ElementTree as ET
from datetime import datetime


# ============================================================================
# IOC EXTRACTION PATTERNS
# ============================================================================

IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|de|uk|fr|info|biz|xyz|top|cc|tk|ml|ga|cf|gq|pw)\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"\']+')
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
CVE_PATTERN = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)

PRIVATE_IP_PREFIXES = ('10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.',
                       '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
                       '172.28.', '172.29.', '172.30.', '172.31.', '192.168.', '127.', '0.')


def extract_iocs(text):
    """Extraire automatiquement les IoCs d'un texte"""
    iocs = []

    for ip in set(IP_PATTERN.findall(text)):
        if not ip.startswith(PRIVATE_IP_PREFIXES):
            iocs.append({'type': 'ip', 'value': ip, 'source': 'auto-extract'})

    for domain in set(DOMAIN_PATTERN.findall(text)):
        if domain.lower() not in ('example.com', 'localhost.com'):
            iocs.append({'type': 'domain', 'value': domain.lower(), 'source': 'auto-extract'})

    for email in set(EMAIL_PATTERN.findall(text)):
        iocs.append({'type': 'email', 'value': email.lower(), 'source': 'auto-extract'})

    for url in set(URL_PATTERN.findall(text)):
        iocs.append({'type': 'url', 'value': url, 'source': 'auto-extract'})

    for sha256 in set(SHA256_PATTERN.findall(text)):
        iocs.append({'type': 'hash_sha256', 'value': sha256.lower(), 'source': 'auto-extract'})

    remaining = SHA256_PATTERN.sub('', text)
    for sha1 in set(SHA1_PATTERN.findall(remaining)):
        iocs.append({'type': 'hash_sha1', 'value': sha1.lower(), 'source': 'auto-extract'})

    remaining2 = SHA1_PATTERN.sub('', remaining)
    for md5 in set(MD5_PATTERN.findall(remaining2)):
        iocs.append({'type': 'hash_md5', 'value': md5.lower(), 'source': 'auto-extract'})

    for cve in set(CVE_PATTERN.findall(text)):
        iocs.append({'type': 'cve', 'value': cve.upper(), 'source': 'auto-extract'})

    return iocs


# ============================================================================
# EVTX PARSER
# ============================================================================

def parse_evtx(filepath, event_id_filter=None, max_records=500):
    """Parser EVTX natif sans dependance IA"""
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
    except ImportError:
        return {
            'error': 'Module python-evtx requis: pip install python-evtx',
            'events': [],
            'summary': 'Parser EVTX non disponible',
            'iocs': []
        }

    events = []
    event_counts = {}
    raw_text = []
    filter_ids = None

    if event_id_filter:
        filter_ids = set()
        for eid in str(event_id_filter).replace(' ', '').split(','):
            try:
                filter_ids.add(int(eid))
            except ValueError:
                pass

    try:
        with evtx.Evtx(filepath) as log:
            for i, record in enumerate(log.records()):
                if i >= max_records * 5:
                    break
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)
                    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}

                    system = root.find('ns:System', ns)
                    if system is None:
                        continue

                    event_id_elem = system.find('ns:EventID', ns)
                    event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0

                    if filter_ids and event_id not in filter_ids:
                        continue

                    time_created = system.find('ns:TimeCreated', ns)
                    timestamp = time_created.get('SystemTime', '') if time_created is not None else ''

                    provider = system.find('ns:Provider', ns)
                    provider_name = provider.get('Name', '') if provider is not None else ''

                    computer = system.find('ns:Computer', ns)
                    computer_name = computer.text if computer is not None else ''

                    level_elem = system.find('ns:Level', ns)
                    level = int(level_elem.text) if level_elem is not None and level_elem.text else 4

                    level_map = {1: 'critical', 2: 'high', 3: 'medium', 4: 'info', 5: 'low'}
                    severity = level_map.get(level, 'info')

                    # Event data
                    event_data = {}
                    data_elem = root.find('ns:EventData', ns)
                    if data_elem is not None:
                        for data in data_elem.findall('ns:Data', ns):
                            name = data.get('Name', '')
                            value = data.text or ''
                            if name:
                                event_data[name] = value

                    event_counts[event_id] = event_counts.get(event_id, 0) + 1

                    if len(events) < max_records:
                        evt = {
                            'event_id': event_id,
                            'timestamp': timestamp,
                            'provider': provider_name,
                            'computer': computer_name,
                            'severity': severity,
                            'data': event_data
                        }
                        events.append(evt)
                        raw_text.append(xml_str)

                except Exception:
                    continue

    except Exception as e:
        return {
            'error': f'Erreur lecture EVTX: {str(e)}',
            'events': [],
            'summary': '',
            'iocs': []
        }

    # Security event descriptions
    sec_events = {
        4624: 'Connexion reussie',
        4625: 'Echec de connexion',
        4634: 'Deconnexion',
        4648: 'Connexion avec identifiants explicites',
        4672: 'Privileges speciaux attribues',
        4688: 'Nouveau processus cree',
        4689: 'Processus termine',
        4697: 'Service installe',
        4698: 'Tache planifiee creee',
        4720: 'Compte utilisateur cree',
        4722: 'Compte utilisateur active',
        4724: 'Mot de passe reinitialise',
        4728: 'Membre ajoute a un groupe global',
        4732: 'Membre ajoute a un groupe local',
        4756: 'Membre ajoute a un groupe universel',
        7045: 'Service installe',
        1: 'Processus cree (Sysmon)',
        3: 'Connexion reseau (Sysmon)',
        11: 'Fichier cree (Sysmon)',
        13: 'Modification registre (Sysmon)',
    }

    top_events = sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    summary_lines = [
        f"=== Analyse EVTX: {os.path.basename(filepath)} ===",
        f"Total evenements traites: {sum(event_counts.values())}",
        f"Types d'evenements uniques: {len(event_counts)}",
        "",
        "--- Top Event IDs ---"
    ]
    for eid, count in top_events:
        desc = sec_events.get(eid, '')
        summary_lines.append(f"  Event ID {eid}: {count} occurrence(s) {f'- {desc}' if desc else ''}")

    # Suspicious events
    suspicious_ids = {4625, 4648, 4672, 4697, 4698, 4720, 7045, 1, 3}
    found_suspicious = [(eid, c) for eid, c in event_counts.items() if eid in suspicious_ids]
    if found_suspicious:
        summary_lines.append("")
        summary_lines.append("--- Evenements Suspects ---")
        for eid, count in sorted(found_suspicious, key=lambda x: x[1], reverse=True):
            summary_lines.append(f"  [!] Event ID {eid} ({sec_events.get(eid, 'inconnu')}): {count}x")

    full_text = '\n'.join(raw_text)
    iocs = extract_iocs(full_text)

    return {
        'events': events,
        'event_counts': event_counts,
        'summary': '\n'.join(summary_lines),
        'iocs': iocs,
        'total_parsed': sum(event_counts.values())
    }


# ============================================================================
# CSV PARSER
# ============================================================================

def parse_csv(filepath, max_rows=5000):
    """Parser CSV generique"""
    events = []
    raw_text = []

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            sample = f.read(8192)
            f.seek(0)
            dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
            has_header = csv.Sniffer().has_header(sample)
            f.seek(0)

            reader = csv.reader(f, dialect)
            headers = next(reader) if has_header else None

            if headers:
                # Find timestamp-like columns
                time_cols = [i for i, h in enumerate(headers) if any(k in h.lower() for k in ('time', 'date', 'timestamp', 'when', 'heure'))]
                # Find severity-like columns
                sev_cols = [i for i, h in enumerate(headers) if any(k in h.lower() for k in ('severity', 'level', 'priority', 'sev', 'criticite'))]

            row_count = 0
            for row in reader:
                if row_count >= max_rows:
                    break
                row_count += 1
                raw_text.append(','.join(row))

                if headers:
                    event = {headers[i]: row[i] for i in range(min(len(headers), len(row)))}
                    timestamp = row[time_cols[0]] if time_cols and time_cols[0] < len(row) else ''
                    severity = row[sev_cols[0]].lower() if sev_cols and sev_cols[0] < len(row) else 'info'
                else:
                    event = {f'col_{i}': v for i, v in enumerate(row)}
                    timestamp = row[0] if row else ''
                    severity = 'info'

                sev_map = {'critical': 'critical', 'crit': 'critical', 'high': 'high', 'warning': 'medium',
                           'warn': 'medium', 'medium': 'medium', 'low': 'low', 'info': 'info', 'notice': 'info'}
                severity = sev_map.get(severity, 'info')

                events.append({
                    'timestamp': timestamp,
                    'severity': severity,
                    'data': event,
                    'event': ', '.join(f'{k}={v}' for k, v in list(event.items())[:5])
                })

    except Exception as e:
        return {
            'error': f'Erreur lecture CSV: {str(e)}',
            'events': [], 'summary': '', 'iocs': []
        }

    summary_lines = [
        f"=== Analyse CSV: {os.path.basename(filepath)} ===",
        f"Lignes analysees: {len(events)}",
        f"Colonnes: {', '.join(headers) if headers else 'N/A'}",
    ]

    full_text = '\n'.join(raw_text)
    iocs = extract_iocs(full_text)

    if iocs:
        summary_lines.append(f"\nIoCs detectes: {len(iocs)}")
        for ioc in iocs[:10]:
            summary_lines.append(f"  [{ioc['type']}] {ioc['value']}")

    return {
        'events': events[:500],
        'headers': headers,
        'summary': '\n'.join(summary_lines),
        'iocs': iocs,
        'total_rows': len(events)
    }


# ============================================================================
# JSON PARSER
# ============================================================================

def parse_json(filepath):
    """Parser JSON generique"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    except Exception as e:
        return {
            'error': f'Erreur lecture JSON: {str(e)}',
            'events': [], 'summary': '', 'iocs': []
        }

    raw_text = json.dumps(data, default=str)
    iocs = extract_iocs(raw_text)

    events = []
    if isinstance(data, list):
        for item in data[:1000]:
            if isinstance(item, dict):
                timestamp = ''
                for k in ('timestamp', 'time', 'date', 'created', '@timestamp', 'datetime'):
                    if k in item:
                        timestamp = str(item[k])
                        break
                events.append({
                    'timestamp': timestamp,
                    'severity': item.get('severity', item.get('level', 'info')),
                    'data': item,
                    'event': str(item.get('message', item.get('event', item.get('description', json.dumps(item)[:200]))))
                })
            else:
                events.append({'timestamp': '', 'severity': 'info', 'event': str(item), 'data': item})

    def count_structure(obj, depth=0):
        if depth > 5:
            return "..."
        if isinstance(obj, dict):
            return {k: count_structure(v, depth + 1) for k, v in list(obj.items())[:20]}
        elif isinstance(obj, list):
            return f"[{len(obj)} elements]"
        else:
            return type(obj).__name__

    structure = count_structure(data)
    summary_lines = [
        f"=== Analyse JSON: {os.path.basename(filepath)} ===",
        f"Type racine: {'Array' if isinstance(data, list) else 'Object'}",
        f"Taille: {len(data) if isinstance(data, (list, dict)) else 'scalaire'}",
        f"Structure: {json.dumps(structure, indent=2, default=str)[:500]}",
    ]

    if iocs:
        summary_lines.append(f"\nIoCs detectes: {len(iocs)}")
        for ioc in iocs[:10]:
            summary_lines.append(f"  [{ioc['type']}] {ioc['value']}")

    return {
        'events': events,
        'summary': '\n'.join(summary_lines),
        'iocs': iocs,
        'structure': structure
    }


# ============================================================================
# LOG/TXT PARSER
# ============================================================================

SYSLOG_PATTERN = re.compile(
    r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)',
    re.MULTILINE
)
TIMESTAMP_PATTERNS = [
    re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'),
    re.compile(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'),
    re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
    re.compile(r'(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})'),
]

SEVERITY_KEYWORDS = {
    'critical': ['critical', 'crit', 'fatal', 'emergency', 'emerg', 'panic'],
    'high': ['error', 'err', 'alert', 'failure', 'failed', 'denied'],
    'medium': ['warning', 'warn', 'caution'],
    'low': ['notice', 'info', 'information'],
}


def detect_severity(line):
    """Detecter la severite d'une ligne de log"""
    lower = line.lower()
    for sev, keywords in SEVERITY_KEYWORDS.items():
        for kw in keywords:
            if kw in lower:
                return sev
    return 'info'


def parse_log(filepath, max_lines=10000):
    """Parser de fichiers LOG/TXT generique"""
    events = []
    raw_text = []
    severity_counts = {}

    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                line = line.strip()
                if not line:
                    continue

                raw_text.append(line)
                timestamp = ''
                for pattern in TIMESTAMP_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        timestamp = match.group(1)
                        break

                severity = detect_severity(line)
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

                syslog = SYSLOG_PATTERN.match(line)
                if syslog:
                    events.append({
                        'timestamp': syslog.group(1),
                        'host': syslog.group(2),
                        'process': syslog.group(3),
                        'pid': syslog.group(4),
                        'message': syslog.group(5),
                        'severity': severity,
                        'event': syslog.group(5)[:200]
                    })
                else:
                    events.append({
                        'timestamp': timestamp,
                        'severity': severity,
                        'event': line[:200],
                        'data': {'raw': line}
                    })

    except Exception as e:
        return {
            'error': f'Erreur lecture LOG: {str(e)}',
            'events': [], 'summary': '', 'iocs': []
        }

    full_text = '\n'.join(raw_text)
    iocs = extract_iocs(full_text)

    summary_lines = [
        f"=== Analyse LOG: {os.path.basename(filepath)} ===",
        f"Lignes analysees: {len(events)}",
        "",
        "--- Repartition par severite ---",
    ]
    for sev in ['critical', 'high', 'medium', 'low', 'info']:
        count = severity_counts.get(sev, 0)
        if count > 0:
            summary_lines.append(f"  {sev.upper()}: {count}")

    if iocs:
        summary_lines.append(f"\nIoCs detectes: {len(iocs)}")
        for ioc in iocs[:15]:
            summary_lines.append(f"  [{ioc['type']}] {ioc['value']}")

    return {
        'events': events[:500],
        'summary': '\n'.join(summary_lines),
        'iocs': iocs,
        'severity_counts': severity_counts,
        'total_lines': len(events)
    }


# ============================================================================
# MAIN DISPATCHER
# ============================================================================

def analyze_file_standalone(filepath, event_id_filter=None):
    """Analyser un fichier avec le parser adapte"""
    ext = os.path.splitext(filepath)[1].lower()

    if ext == '.evtx':
        return parse_evtx(filepath, event_id_filter)
    elif ext == '.csv':
        return parse_csv(filepath)
    elif ext == '.json':
        return parse_json(filepath)
    else:
        return parse_log(filepath)
