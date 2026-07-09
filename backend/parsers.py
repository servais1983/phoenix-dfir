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

def _evtx_engine():
    """Moteur EVTX disponible : 'rust' (pyevtx-rs, wheels precompiles fiables),
    'python' (python-evtx historique) ou None."""
    try:
        import evtx  # noqa: F401 - pyevtx-rs
        return 'rust'
    except ImportError:
        pass
    try:
        import Evtx.Evtx  # noqa: F401 - python-evtx
        return 'python'
    except ImportError:
        return None


def _iter_evtx_xml(filepath):
    """Iterer les enregistrements EVTX en XML, quel que soit le moteur installe."""
    if _evtx_engine() == 'rust':
        from evtx import PyEvtxParser
        for record in PyEvtxParser(filepath).records():
            yield record['data']
        return
    import Evtx.Evtx as evtx
    with evtx.Evtx(filepath) as log:
        for record in log.records():
            yield record.xml()


def parse_evtx(filepath, event_id_filter=None, max_records=500):
    """Parser EVTX natif sans dependance IA"""
    if _evtx_engine() is None:
        return {
            'error': "Parser EVTX requis : pip install evtx (recommande, wheels precompiles) ou python-evtx",
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
        for i, xml_str in enumerate(_iter_evtx_xml(filepath)):
                if i >= max_records * 5:
                    break
                try:
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
# WINDOWS PREFETCH PARSER (.pf)
# ============================================================================

def parse_prefetch(filepath):
    """Parser un fichier Prefetch Windows (.pf).

    Lit le format SCCA versions 17 (XP), 23 (Vista/7), 26 (Win8), 30/31 (Win10/11).
    Les fichiers Win10/11 sont compresses MAM/XPRESS - signature 'MAM\\x04' decompressee
    via la lib python-libscca si dispo, sinon best-effort sur l'en-tete brut.
    """
    if not os.path.isfile(filepath):
        return {'error': 'Fichier introuvable', 'events': [], 'summary': '', 'iocs': []}

    try:
        with open(filepath, 'rb') as f:
            head = f.read(4096)
    except OSError as e:
        return {'error': f'Erreur lecture: {e}', 'events': [], 'summary': '', 'iocs': []}

    # Detecter compression Win10+ (MAM signature)
    if head[:3] == b'MAM':
        try:
            import ctypes
            # Win10+ utilise MS-XPRESS. Sans lib dediee, on tente python-libscca si dispo.
            try:
                import pyscca
                scca = pyscca.file()
                scca.open(filepath)
                exec_name = scca.executable_filename or ''
                run_count = scca.run_count or 0
                last_run = scca.get_last_run_time(0).isoformat() if scca.run_count else None
                hash_str = f'{scca.prefetch_hash:08X}' if scca.prefetch_hash else ''
                strings = [scca.get_filename(i) for i in range(scca.number_of_filenames)]
                scca.close()
                return _format_prefetch_result(filepath, exec_name, hash_str, run_count, last_run, strings)
            except ImportError:
                pass

            return {
                'error': 'Prefetch Win10+ compresse: installer pyscca pour decompresser',
                'events': [], 'summary': 'Format MAM/XPRESS non decompresse', 'iocs': [],
                'compressed': True,
            }
        except Exception as e:
            return {'error': f'Erreur decompression Prefetch: {e}', 'events': [], 'summary': '', 'iocs': []}

    # Format non compresse (Win7/8) : version a offset 0, signature 'SCCA' a offset 4
    if head[4:8] != b'SCCA':
        return {'error': 'Signature Prefetch invalide', 'events': [], 'summary': '', 'iocs': []}

    try:
        version = int.from_bytes(head[0:4], 'little')
        # Executable name a offset 0x10, 60 chars UTF-16LE
        exec_name = head[0x10:0x10 + 60].decode('utf-16le', errors='ignore').rstrip('\x00')
        prefetch_hash = int.from_bytes(head[0x4C:0x50], 'little')
        # Run count: offset depend de la version (Vista/7: 0x98, Win8: 0xD0)
        run_count_offset = 0x98 if version <= 23 else 0xD0
        run_count = int.from_bytes(head[run_count_offset:run_count_offset + 4], 'little')
    except Exception as e:
        return {'error': f'Erreur parsing Prefetch: {e}', 'events': [], 'summary': '', 'iocs': []}

    return _format_prefetch_result(filepath, exec_name, f'{prefetch_hash:08X}', run_count, None, [])


def _format_prefetch_result(filepath, exec_name, hash_str, run_count, last_run, strings):
    base = os.path.basename(filepath)
    events = [{
        'timestamp': last_run or '',
        'event_id': 'PF',
        'description': f'Prefetch: {exec_name} execute {run_count} fois',
        'severity': 'info',
        'source': 'prefetch',
    }]
    summary_lines = [
        f'=== Analyse Prefetch: {base} ===',
        f'Executable: {exec_name}',
        f'Hash prefetch: {hash_str}',
        f'Nombre d\'executions: {run_count}',
    ]
    if last_run:
        summary_lines.append(f'Derniere execution: {last_run}')
    if strings:
        summary_lines.append(f'Fichiers references: {len(strings)}')
        for s in strings[:20]:
            summary_lines.append(f'  {s}')

    text_blob = '\n'.join(strings + [exec_name])
    iocs = extract_iocs(text_blob)

    return {
        'events': events,
        'summary': '\n'.join(summary_lines),
        'iocs': iocs,
        'executable': exec_name,
        'run_count': run_count,
        'last_run': last_run,
        'referenced_files': strings,
    }


# ============================================================================
# BROWSER HISTORY PARSER (Chrome/Edge/Firefox SQLite)
# ============================================================================

def parse_browser_history(filepath, limit=2000):
    """Parser un fichier d'historique navigateur SQLite (Chrome/Edge/Firefox).

    Chrome/Edge: table 'urls' (url, title, visit_count, last_visit_time WebKit epoch).
    Firefox places.sqlite: table 'moz_places' (url, title, visit_count, last_visit_date PRRTime).
    """
    if not os.path.isfile(filepath):
        return {'error': 'Fichier introuvable', 'events': [], 'summary': '', 'iocs': []}

    import sqlite3 as _sql
    import shutil
    import tempfile

    # Le navigateur peut tenir un lock sur la DB : on copie
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.sqlite')
    tmp.close()
    try:
        shutil.copyfile(filepath, tmp.name)
        conn = _sql.connect(tmp.name)
        conn.row_factory = _sql.Row
        cur = conn.cursor()

        tables = {r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        rows = []
        browser = 'unknown'

        if 'urls' in tables:
            browser = 'chromium'
            # WebKit time: microseconds since 1601-01-01 UTC
            cur.execute(
                "SELECT url, title, visit_count, last_visit_time FROM urls "
                "ORDER BY last_visit_time DESC LIMIT ?",
                (limit,)
            )
            for r in cur.fetchall():
                wk = r['last_visit_time'] or 0
                # Convert WebKit -> ISO
                if wk:
                    ts = datetime.fromtimestamp(wk / 1_000_000 - 11644473600).isoformat()
                else:
                    ts = ''
                rows.append({
                    'timestamp': ts,
                    'event_id': 'BR',
                    'url': r['url'] or '',
                    'title': (r['title'] or '')[:200],
                    'visit_count': r['visit_count'] or 0,
                    'severity': 'info',
                    'source': 'browser_history',
                })
        elif 'moz_places' in tables:
            browser = 'firefox'
            cur.execute(
                "SELECT url, title, visit_count, last_visit_date FROM moz_places "
                "ORDER BY last_visit_date DESC LIMIT ?",
                (limit,)
            )
            for r in cur.fetchall():
                lvd = r['last_visit_date'] or 0
                ts = datetime.fromtimestamp(lvd / 1_000_000).isoformat() if lvd else ''
                rows.append({
                    'timestamp': ts,
                    'event_id': 'BR',
                    'url': r['url'] or '',
                    'title': (r['title'] or '')[:200],
                    'visit_count': r['visit_count'] or 0,
                    'severity': 'info',
                    'source': 'browser_history',
                })
        else:
            conn.close()
            return {'error': 'Schema non reconnu (ni Chromium ni Firefox)',
                    'events': [], 'summary': '', 'iocs': []}

        conn.close()
    except _sql.DatabaseError as e:
        return {'error': f'SQLite invalide: {e}', 'events': [], 'summary': '', 'iocs': []}
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

    # Extraire IoCs depuis URLs + titres
    text_blob = '\n'.join(f"{r['url']} {r['title']}" for r in rows)
    iocs = extract_iocs(text_blob)

    summary_lines = [
        f'=== Historique navigateur: {os.path.basename(filepath)} ===',
        f'Navigateur detecte: {browser}',
        f'Visites analysees: {len(rows)}',
    ]
    if rows:
        # Top domaines
        from collections import Counter
        domain_counter = Counter()
        for r in rows:
            url = r['url']
            try:
                from urllib.parse import urlparse
                host = urlparse(url).hostname
                if host:
                    domain_counter[host] += 1
            except Exception:
                pass
        summary_lines.append('\nTop 10 domaines visites:')
        for host, count in domain_counter.most_common(10):
            summary_lines.append(f'  {host}: {count} visite(s)')

    if iocs:
        summary_lines.append(f'\nIoCs detectes: {len(iocs)}')

    return {
        'events': rows[:500],
        'summary': '\n'.join(summary_lines),
        'iocs': iocs,
        'browser': browser,
        'total_visits': len(rows),
    }


# ============================================================================
# LNK PARSER (Windows shortcuts)
# ============================================================================

def parse_lnk(filepath):
    """Parser un fichier raccourci Windows (.lnk).

    Format MS-SHLLINK. On extrait : target path, working dir, arguments,
    icon location, machine ID, drive serial.
    Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/
    """
    if not os.path.isfile(filepath):
        return {'error': 'Fichier introuvable', 'events': [], 'summary': '', 'iocs': []}

    try:
        with open(filepath, 'rb') as f:
            data = f.read()
    except OSError as e:
        return {'error': f'Erreur lecture: {e}', 'events': [], 'summary': '', 'iocs': []}

    if len(data) < 0x4C:
        return {'error': 'Fichier trop court', 'events': [], 'summary': '', 'iocs': []}

    # Header LNK : ShellLinkHeader
    header_size = int.from_bytes(data[0:4], 'little')
    if header_size != 0x4C:
        return {'error': 'Pas un fichier LNK valide', 'events': [], 'summary': '', 'iocs': []}

    link_clsid = data[4:20]
    if link_clsid != b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46':
        return {'error': 'CLSID LNK incorrect', 'events': [], 'summary': '', 'iocs': []}

    link_flags = int.from_bytes(data[20:24], 'little')
    file_attrs = int.from_bytes(data[24:28], 'little')
    # Timestamps FILETIME (100ns since 1601-01-01)
    def _filetime_to_iso(raw):
        ft = int.from_bytes(raw, 'little')
        if ft == 0:
            return ''
        try:
            return datetime.fromtimestamp(ft / 10_000_000 - 11644473600).isoformat()
        except (ValueError, OSError, OverflowError):
            return ''
    creation = _filetime_to_iso(data[28:36])
    access = _filetime_to_iso(data[36:44])
    write = _filetime_to_iso(data[44:52])
    file_size = int.from_bytes(data[52:56], 'little')

    offset = 0x4C

    # LinkTargetIDList (si flag HasLinkTargetIDList=0x1)
    if link_flags & 0x1:
        if offset + 2 > len(data):
            return {'error': 'LNK corrompu (TargetIDList)', 'events': [], 'summary': '', 'iocs': []}
        idlist_size = int.from_bytes(data[offset:offset + 2], 'little')
        offset += 2 + idlist_size

    target_path = ''
    working_dir = ''
    arguments = ''
    icon_location = ''

    # LinkInfo (si HasLinkInfo=0x2)
    if link_flags & 0x2 and offset + 4 <= len(data):
        linkinfo_size = int.from_bytes(data[offset:offset + 4], 'little')
        linkinfo = data[offset:offset + linkinfo_size]
        if len(linkinfo) >= 0x20:
            local_base_offset = int.from_bytes(linkinfo[0x10:0x14], 'little')
            if 0 < local_base_offset < len(linkinfo):
                # ANSI null-terminated
                end = linkinfo.find(b'\x00', local_base_offset)
                target_path = linkinfo[local_base_offset:end].decode('latin-1', errors='replace')
        offset += linkinfo_size

    # StringData section
    def _read_string(buf, off, is_unicode):
        if off + 2 > len(buf):
            return '', off
        count = int.from_bytes(buf[off:off + 2], 'little')
        off += 2
        if is_unicode:
            byte_count = count * 2
            s = buf[off:off + byte_count].decode('utf-16le', errors='replace')
            off += byte_count
        else:
            s = buf[off:off + count].decode('latin-1', errors='replace')
            off += count
        return s, off

    is_unicode = bool(link_flags & 0x80)

    string_flags = [
        ('HasName', 0x4, 'name'),
        ('HasRelativePath', 0x8, 'relative_path'),
        ('HasWorkingDir', 0x10, 'working_dir'),
        ('HasArguments', 0x20, 'arguments'),
        ('HasIconLocation', 0x40, 'icon_location'),
    ]
    strings = {}
    for _, flag, field in string_flags:
        if link_flags & flag:
            try:
                s, offset = _read_string(data, offset, is_unicode)
                strings[field] = s
            except Exception:
                break

    working_dir = strings.get('working_dir', '')
    arguments = strings.get('arguments', '')
    icon_location = strings.get('icon_location', '')
    if not target_path:
        target_path = strings.get('relative_path', '')

    summary_lines = [
        f'=== Analyse LNK: {os.path.basename(filepath)} ===',
        f'Cible: {target_path or "(inconnue)"}',
    ]
    if working_dir:
        summary_lines.append(f'Working dir: {working_dir}')
    if arguments:
        summary_lines.append(f'Arguments: {arguments}')
    if icon_location:
        summary_lines.append(f'Icon: {icon_location}')
    if creation:
        summary_lines.append(f'Creation cible: {creation}')
    if write:
        summary_lines.append(f'Modification cible: {write}')
    summary_lines.append(f'Taille cible: {file_size} octets')
    summary_lines.append(f'Flags: 0x{link_flags:08X}')

    text_blob = ' '.join([target_path, working_dir, arguments, icon_location])
    iocs = extract_iocs(text_blob)

    # Severite : eleve si arguments suspects ou cible dans %TEMP%/AppData
    severity = 'low'
    suspicious_strings = ('powershell', 'cmd.exe /c', 'rundll32', 'mshta',
                          'wscript', 'cscript', '\\temp\\', '\\appdata\\')
    blob_lower = text_blob.lower()
    if any(s in blob_lower for s in suspicious_strings):
        severity = 'high'

    events = [{
        'timestamp': write or creation or '',
        'event_id': 'LNK',
        'description': f'Raccourci vers {target_path}',
        'severity': severity,
        'source': 'lnk',
    }]

    return {
        'events': events,
        'summary': '\n'.join(summary_lines),
        'iocs': iocs,
        'target_path': target_path,
        'working_dir': working_dir,
        'arguments': arguments,
        'icon_location': icon_location,
        'creation_time': creation,
        'last_access_time': access,
        'last_write_time': write,
        'file_size': file_size,
        'flags': link_flags,
        'file_attributes': file_attrs,
        'severity': severity,
    }


# ============================================================================
# MAIN DISPATCHER
# ============================================================================

def analyze_file_standalone(filepath, event_id_filter=None):
    """Analyser un fichier avec le parser adapte"""
    ext = os.path.splitext(filepath)[1].lower()
    fname = os.path.basename(filepath).lower()

    if ext == '.evtx':
        return parse_evtx(filepath, event_id_filter)
    elif ext == '.csv':
        return parse_csv(filepath)
    elif ext == '.json':
        return parse_json(filepath)
    elif ext == '.pf':
        return parse_prefetch(filepath)
    elif ext == '.lnk':
        return parse_lnk(filepath)
    elif ext in ('.sqlite', '.db') or fname in ('history', 'places.sqlite'):
        return parse_browser_history(filepath)
    else:
        return parse_log(filepath)
