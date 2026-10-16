"""Analyse de captures reseau (PCAP / PCAPNG) en Python pur.

Outils : net_pcap_summary, net_dns, net_http, net_tls, net_detect.

Toutes les sorties sont indexees dans la super-timeline du cas et citables :
la reference de preuve est 'row' = NUMERO DE PAQUET dans la capture (1 = premier
paquet, identique a frame.number de Wireshark). Un flux est cite par le numero
de son premier paquet, une transaction HTTP par le paquet portant sa ligne de
requete, une poignee de main TLS par le paquet du ClientHello.

Aucun contenu n'est jamais execute : les corps HTTP extraits (carving) sont
ecrits tels quels avec un manifeste SHA-256. tshark est optionnel (hierarchie
des protocoles si present sur le PATH), jamais requis.
"""

import datetime
import hashlib
import ipaddress
import json
import os
import re
import shutil
import statistics
import subprocess  # nosec B404 - tshark optionnel, arguments en liste, sans shell
import threading

from .. import toolkit
from . import _net_pcap as net_pcap, _net_proto as net_proto

AGENT = ('network', 'Agent Reseau & Desobfuscation')
TOOL_NAMES = ('net_pcap_summary', 'net_dns', 'net_http', 'net_tls', 'net_detect')
READONLY = ('net_pcap_summary', 'net_dns', 'net_tls', 'net_detect')
INDEXED = TOOL_NAMES
KNOWN_TYPES = {
    '.pcap': 'Capture reseau PCAP',
    '.pcapng': 'Capture reseau PCAPNG',
    '.cap': 'Capture reseau (pcap)',
}
PHASE_TOOLS = {
    'extraction': TOOL_NAMES,
    'correlation': TOOL_NAMES,
    'contre_analyse': ('net_pcap_summary', 'net_dns', 'net_tls', 'net_detect'),
}
PHASE_HINTS = {
    'extraction': (
        "- CAPTURES RESEAU (.pcap/.pcapng/.cap) : net_pcap_summary (flux, top talkers), net_dns, "
        "net_http (carve=true extrait les fichiers transferes vers extracted/pcap/ avec manifeste "
        "SHA-256), net_tls (SNI, JA3, JA4, certificats) PUIS net_detect. Reference citable : "
        "row = numero de paquet de la capture."),
    'correlation': (
        "- Reseau : net_detect signale beaconing, exfiltration, tunnel DNS, DGA, identifiants en "
        "clair, User-Agent et ports suspects avec techniques ATT&CK et row (numero de paquet) a "
        "citer ; correler avec les journaux (IP, horodatage UTC) via get_timeline."),
}

_PCAP_EXT = tuple(KNOWN_TYPES)
EVENT_CAP = 50000
PREVIEW = 100
DEFAULT_MAX_CARVE_MB = 25
MAX_CARVED_FILES = 500
CARVE_DIR = ('extracted', 'pcap')

_PATH = {'type': 'string', 'description': 'Chemin de la capture (.pcap, .pcapng, .cap)'}
_CAPS = {
    'max_packets': {'type': 'integer', 'description': 'Plafond de paquets lus (defaut 1000000, '
                                                      'PHOENIX_PCAP_MAX_PACKETS)'},
    'max_stream_bytes': {'type': 'integer', 'description': 'Plafond d\'octets reassembles par sens '
                                                           'TCP (defaut 4 Mo, PHOENIX_PCAP_MAX_STREAM_BYTES)'},
}


def applicable(path):
    """Groupes d'outils pour l'audit de couverture d'une capture reseau."""
    ext = os.path.splitext(path)[1].lower()
    if ext in _PCAP_EXT or (ext not in ('.evtx', '.json', '.csv', '.log', '.txt')
                            and net_pcap.sniff(path)):
        return [('reseau', ('net_pcap_summary', 'net_dns', 'net_http', 'net_tls')),
                ('detection reseau', ('net_detect',))]
    return None


# ============================================================================
# Analyse commune (mise en cache par fichier et plafonds)
# ============================================================================

_cache = {}
_cache_lock = threading.Lock()
_CACHE_SIZE = 2


def iso(ts):
    if ts is None:
        return None
    try:
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
            '%Y-%m-%dT%H:%M:%S.%fZ')
    except (OverflowError, OSError, ValueError):
        return None


def is_internal(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
            or addr.is_reserved or addr.is_unspecified or ip == '255.255.255.255')


_PORT_APPS = {22: 'SSH', 23: 'Telnet', 25: 'SMTP', 88: 'Kerberos', 110: 'POP3', 135: 'MSRPC',
              139: 'NetBIOS', 143: 'IMAP', 389: 'LDAP', 445: 'SMB', 587: 'SMTP', 636: 'LDAPS',
              1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM'}
_UDP_APPS = {53: 'DNS', 67: 'DHCP', 68: 'DHCP', 123: 'NTP', 137: 'NBNS', 161: 'SNMP', 443: 'QUIC',
             514: 'Syslog', 1900: 'SSDP', 5353: 'mDNS', 5355: 'LLMNR'}


class Analysis:
    def __init__(self, cap):
        self.cap = cap
        self.dns = []
        self.http = []
        self.tls = []
        self.ftp = []
        self._run()

    def _run(self):
        for frame, ts, src, sport, dst, dport, payload in self.cap.udp_packets:
            self._dns(net_proto.parse_dns(payload), frame, ts, src, sport, dst, dport, 'udp')
        self.cap.udp_packets = []
        limit = self.cap.limits['max_stream_bytes']
        for flow in self.cap.flows:
            if flow.proto == 'UDP':
                flow.app = _UDP_APPS.get(flow.sport) or _UDP_APPS.get(flow.cport) or 'UDP'
                continue
            c, s = flow.c2s.data, flow.s2c.data
            if net_proto.looks_tls(c):
                flow.app = 'TLS'
                info = net_proto.parse_tls(bytes(c[:1 << 16]), bytes(s[:1 << 16]))
                if info:
                    info.update({'flow': flow, 'frame': flow.c2s.frame_at(0),
                                 'ts': flow.c2s.time_at(0)})
                    self.tls.append(info)
            elif bytes(c[:10]).startswith(net_pcap.HTTP_METHODS):
                flow.app = 'HTTP'
                for tx in net_proto.parse_http(flow.c2s, flow.s2c, limit):
                    tx['flow'] = flow
                    self.http.append(tx)
            elif flow.sport == 21 or (bytes(s[:4]) == b'220 ' and bytes(c[:5]).upper() == b'USER '):
                flow.app = 'FTP'
                for off, cmd, arg in net_proto.parse_ftp(flow.c2s):
                    self.ftp.append({'flow': flow, 'frame': flow.c2s.frame_at(off),
                                     'ts': flow.c2s.time_at(off), 'cmd': cmd, 'arg': arg})
            elif flow.sport == 53:
                flow.app = 'DNS'
                for stream, src, sport, dst, dport in ((flow.c2s, flow.client, flow.cport, flow.server, flow.sport),
                                                       (flow.s2c, flow.server, flow.sport, flow.client, flow.cport)):
                    data, pos = bytes(stream.data), 0
                    while pos + 2 <= len(data):
                        ln = int.from_bytes(data[pos:pos + 2], 'big')
                        self._dns(net_proto.parse_dns(data[pos + 2:pos + 2 + ln]), stream.frame_at(pos),
                                  stream.time_at(pos), src, sport, dst, dport, 'tcp')
                        pos += 2 + ln
            elif bytes(s[:4]) == b'SSH-' or bytes(c[:4]) == b'SSH-':
                flow.app = 'SSH'
            elif bytes(s[:5]).startswith(b'HTTP/'):
                flow.app = 'HTTP'
            else:
                flow.app = _PORT_APPS.get(flow.sport, 'TCP')
            if flow.app not in ('HTTP',):
                # Seul HTTP a besoin des flux complets apres analyse : liberer la memoire
                flow.c2s.data = bytearray(flow.c2s.data[:4096])
                flow.s2c.data = bytearray(flow.s2c.data[:4096])

    def _dns(self, msg, frame, ts, src, sport, dst, dport, transport):
        if not msg or not msg['questions']:
            return
        q = msg['questions'][0]
        self.dns.append({'frame': frame, 'ts': ts, 'src': src, 'sport': sport, 'dst': dst,
                         'dport': dport, 'id': msg['id'], 'qr': msg['qr'], 'rcode': msg['rcode'],
                         'qname': q['name'].lower(), 'qtype': q['type'], 'answers': msg['answers'],
                         'transport': transport, 'client': dst if msg['qr'] else src})


def analyze(file_path, max_packets=None, max_stream_bytes=None):
    """Lire et dissequer une capture (resultat mis en cache par fichier + plafonds)."""
    st = os.stat(file_path)
    limits = net_pcap.caps(max_packets, max_stream_bytes)
    key = (os.path.realpath(file_path), st.st_size, st.st_mtime_ns, tuple(sorted(limits.items())))
    with _cache_lock:
        hit = _cache.get(key)
        if hit is not None:
            return hit
    result = Analysis(net_pcap.read_capture(file_path, max_packets, max_stream_bytes))
    with _cache_lock:
        _cache[key] = result
        while len(_cache) > _CACHE_SIZE:
            _cache.pop(next(iter(_cache)))
    return result


def clear_cache():
    with _cache_lock:
        _cache.clear()


def _guard(file_path):
    if not os.path.isfile(file_path):
        return {'error': f'Fichier introuvable: {file_path}'}
    if not net_pcap.sniff(file_path):
        return {'error': 'Fichier non reconnu comme capture pcap / pcapng (octets magiques)'}
    return None


def _with_events(result, events):
    events = events[:EVENT_CAP]
    result['events'] = events
    result['events_total'] = len(events)
    if len(events) > 2 * PREVIEW:
        # Tout est indexe ; seul un apercu est renvoye au LLM
        result['preview'] = events[:PREVIEW]
    return result


def _run_safely(func):
    def wrapper(file_path, *args, **kwargs):
        denied = _guard(file_path)
        if denied:
            return denied
        try:
            return func(file_path, *args, **kwargs)
        except net_pcap.CaptureError as e:
            return {'error': f'Capture illisible : {e}'}
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper


def _flow_dict(flow):
    return {
        'row': flow.first_frame, 'flow': flow.id, 'proto': flow.proto, 'app': flow.app,
        'client': flow.client, 'client_port': flow.cport, 'server': flow.server,
        'server_port': flow.sport, 'packets': sum(flow.pkts), 'bytes': sum(flow.bytes),
        'bytes_c2s': flow.bytes[0], 'bytes_s2c': flow.bytes[1],
        'payload_c2s': flow.payload[0], 'payload_s2c': flow.payload[1],
        'start': iso(flow.first_ts), 'end': iso(flow.last_ts), 'duration_s': round(flow.duration, 3),
    }


# ============================================================================
# net_pcap_summary
# ============================================================================

_LINKTYPES = {0: 'NULL', 1: 'Ethernet', 101: 'IP brut', 108: 'LOOP', 113: 'Linux SLL',
              228: 'IPv4', 229: 'IPv6', 276: 'Linux SLL2'}


def _tshark_hierarchy(file_path):
    exe = shutil.which('tshark')
    if not exe:
        return {'available': False}
    try:
        proc = subprocess.run([exe, '-n', '-r', file_path, '-q', '-z', 'io,phs'],  # nosec B603
                              capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        return {'available': True, 'error': str(e)}
    return {'available': True, 'protocol_hierarchy': (proc.stdout or '')[:8000]}


@toolkit.tool(
    'net_pcap_summary',
    "Synthese d'une capture reseau PCAP/PCAPNG (Python pur, hors ligne) : metadonnees (format, "
    "liaison, periode, paquets), protocoles, top talkers, conversations (flux 5-tuple avec octets, "
    "paquets, duree). Chaque flux est indexe et citable par row = numero de son premier paquet.",
    toolkit._schema(dict({'file_path': _PATH,
                          'top': {'type': 'integer', 'description': 'Taille des classements (defaut 20)'},
                          'use_tshark': {'type': 'boolean', 'description': 'Ajouter la hierarchie de '
                                         'protocoles tshark si installe (optionnel)'}}, **_CAPS),
                    ['file_path']),
)
@_run_safely
def net_pcap_summary(file_path, top=20, use_tshark=False, max_packets=None, max_stream_bytes=None):
    a = analyze(file_path, max_packets, max_stream_bytes)
    cap = a.cap
    top = max(1, min(int(top or 20), 200))
    apps = {}
    for flow in cap.flows:
        entry = apps.setdefault(flow.app or flow.proto, {'flows': 0, 'packets': 0, 'bytes': 0})
        entry['flows'] += 1
        entry['packets'] += sum(flow.pkts)
        entry['bytes'] += sum(flow.bytes)
    talkers = sorted(cap.hosts.items(), key=lambda kv: -(kv[1][1] + kv[1][3]))[:top]
    flows_by_bytes = sorted(cap.flows, key=lambda fl: -sum(fl.bytes))
    meta = cap.meta
    result = {
        'file': os.path.basename(file_path),
        'capture': {
            'format': meta.get('format'), 'endianness': meta.get('endianness'),
            'ts_resolution': meta.get('ts_resolution'), 'snaplen': meta.get('snaplen'),
            'link_types': sorted(_LINKTYPES.get(lt, str(lt)) for lt in meta['linktypes']),
            'packets': cap.packets, 'bytes': cap.bytes,
            'first_packet': iso(cap.first_ts), 'last_packet': iso(cap.last_ts),
            'duration_s': round(cap.last_ts - cap.first_ts, 3) if cap.first_ts is not None else 0,
            'truncated': cap.truncated, 'flows': len(cap.flows), 'flows_capped': cap.flows_capped,
            'errors': meta['errors'][:20], 'limits': cap.limits,
        },
        'protocols': {'network': cap.l3, 'transport': cap.l4,
                      'applications': dict(sorted(apps.items(), key=lambda kv: -kv[1]['bytes']))},
        'top_talkers': [{'ip': ip, 'internal': is_internal(ip), 'packets_sent': v[0], 'bytes_sent': v[1],
                         'packets_received': v[2], 'bytes_received': v[3]} for ip, v in talkers],
        'external_hosts': sorted({fl.server for fl in cap.flows if not is_internal(fl.server)})[:top * 5],
        'conversations': [_flow_dict(fl) for fl in flows_by_bytes[:top]],
    }
    if use_tshark:
        result['tshark'] = _tshark_hierarchy(file_path)
    events = []
    for flow in cap.flows:
        d = _flow_dict(flow)
        events.append(dict(d, timestamp=d['start'], host=flow.client, event=(
            f"Flux {flow.proto} {flow.client}:{flow.cport} -> {flow.server}:{flow.sport} "
            f"({flow.app}) {d['packets']} paquets, {d['bytes']} octets "
            f"(sortant {flow.payload[0]} / entrant {flow.payload[1]} octets utiles), {d['duration_s']} s")))
    return _with_events(result, events)


# ============================================================================
# net_dns
# ============================================================================

DNS_TUNNEL_MIN_NAMES = 15
DNS_TUNNEL_MIN_LEN = 25
DNS_TUNNEL_MIN_ENTROPY = 3.6
DNS_LONG_LABEL = 40
DGA_THRESHOLD = 0.6


def _sub_part(qname, base):
    return qname[:-len(base)].rstrip('.') if qname.endswith(base) and qname != base else ''


def dns_stats(a):
    queries = [d for d in a.dns if not d['qr']]
    responses = [d for d in a.dns if d['qr']]
    rcodes, by_client, per_base, names = {}, {}, {}, {}
    for r in responses:
        rcodes[r['rcode']] = rcodes.get(r['rcode'], 0) + 1
        entry = by_client.setdefault(r['client'], [0, 0])
        entry[0] += 1
        entry[1] += r['rcode'] == 'NXDOMAIN'
    for q in queries:
        names[q['qname']] = names.get(q['qname'], 0) + 1
        base = net_proto.base_domain(q['qname'])
        b = per_base.setdefault(base, {'domain': base, 'queries': 0, 'subs': set(), 'txt': 0,
                                       'clients': set(), 'frames': [], 'first': q['ts'], 'chars': 0})
        b['queries'] += 1
        b['clients'].add(q['src'])
        sub = _sub_part(q['qname'], base)
        if sub and len(b['subs']) < 5000:
            b['subs'].add(sub)
        b['chars'] += len(sub)
        b['txt'] += q['qtype'] in ('TXT', 'NULL', 'CNAME', 'MX')
        if len(b['frames']) < 2000:
            b['frames'].append((q['frame'], q['ts']))
    nx_names = {r['qname'] for r in responses if r['rcode'] == 'NXDOMAIN'}
    bases = []
    for b in per_base.values():
        subs = b.pop('subs')
        lens = [len(s) for s in subs]
        labels = [lab for s in subs for lab in s.split('.')]
        b.update({
            'unique_subdomains': len(subs),
            'avg_subdomain_len': round(sum(lens) / len(lens), 1) if lens else 0,
            'max_label_len': max((len(x) for x in labels), default=0),
            'avg_entropy': round(sum(net_proto.entropy(s) for s in subs) / len(subs), 2) if subs else 0,
            'txt_ratio': round(b['txt'] / b['queries'], 2) if b['queries'] else 0,
            'clients': sorted(b['clients']),
        })
        bases.append(b)
    return queries, responses, rcodes, by_client, names, bases, nx_names


def tunnel_candidates(bases, min_names=DNS_TUNNEL_MIN_NAMES):
    out = []
    for b in bases:
        if b['unique_subdomains'] < min_names:
            continue
        if (b['avg_subdomain_len'] >= DNS_TUNNEL_MIN_LEN or b['avg_entropy'] >= DNS_TUNNEL_MIN_ENTROPY
                or b['max_label_len'] >= DNS_LONG_LABEL or b['txt_ratio'] >= 0.5):
            out.append(b)
    return out


def _dns_public(b):
    return {k: v for k, v in b.items() if k not in ('frames', 'first', 'txt')}


@toolkit.tool(
    'net_dns',
    "Analyse DNS d'une capture : requetes et reponses (nom, type, code retour, reponses), taux "
    "NXDOMAIN par client, sous-domaines longs ou a forte entropie (heuristique de tunnel DNS), noms "
    "de type DGA. Chaque message est indexe et citable par row = numero de paquet.",
    toolkit._schema(dict({'file_path': _PATH,
                          'top': {'type': 'integer', 'description': 'Taille des classements (defaut 20)'}},
                         **_CAPS), ['file_path']),
)
@_run_safely
def net_dns(file_path, top=20, max_packets=None, max_stream_bytes=None):
    a = analyze(file_path, max_packets, max_stream_bytes)
    top = max(1, min(int(top or 20), 200))
    queries, responses, rcodes, by_client, names, bases, nx_names = dns_stats(a)
    long_names = sorted({q['qname'] for q in queries
                         if max((len(x) for x in q['qname'].split('.')), default=0) >= DNS_LONG_LABEL
                         or net_proto.entropy(_sub_part(q['qname'], net_proto.base_domain(q['qname']))) >= 4.0})
    dga = sorted({(q['qname'], net_proto.dga_score(q['qname'])) for q in queries
                  if net_proto.dga_score(q['qname']) >= DGA_THRESHOLD}, key=lambda x: -x[1])
    result = {
        'file': os.path.basename(file_path),
        'total_queries': len(queries), 'total_responses': len(responses),
        'unique_names': len(names), 'rcodes': rcodes,
        'nxdomain_rate': round(rcodes.get('NXDOMAIN', 0) / len(responses), 3) if responses else 0.0,
        'nxdomain_by_client': sorted(({'client': c, 'responses': v[0], 'nxdomain': v[1],
                                       'rate': round(v[1] / v[0], 3)} for c, v in by_client.items()),
                                     key=lambda x: -x['nxdomain'])[:top],
        'top_queried': sorted(({'name': n, 'count': c} for n, c in names.items()),
                              key=lambda x: -x['count'])[:top],
        'base_domains': [_dns_public(b) for b in sorted(bases, key=lambda b: -b['unique_subdomains'])[:top]],
        'suspicious': {
            'tunneling': [_dns_public(b) for b in tunnel_candidates(bases)],
            'long_or_high_entropy': long_names[:top * 5],
            'dga_like': [{'name': n, 'score': s, 'nxdomain': n in nx_names} for n, s in dga[:top * 5]],
        },
    }
    events = []
    for d in a.dns:
        answers = ', '.join(f"{x['type']} {x['data']}" for x in d['answers'][:8])
        if d['qr']:
            text = f"DNS reponse {d['rcode']} {d['qname']} ({d['qtype']})" + (f' -> {answers}' if answers else '')
        else:
            text = f"DNS requete {d['qtype']} {d['qname']} de {d['src']} vers {d['dst']}"
        events.append({'row': d['frame'], 'timestamp': iso(d['ts']), 'host': d['client'],
                       'src': d['src'], 'dst': d['dst'], 'qname': d['qname'], 'qtype': d['qtype'],
                       'rcode': d['rcode'] if d['qr'] else None, 'answers': answers or None,
                       'event': text})
    return _with_events(result, events)


# ============================================================================
# net_http (+ carving)
# ============================================================================

_SAFE = re.compile(r'[^A-Za-z0-9._-]+')
_FILE_TYPES = ('application/', 'image/', 'audio/', 'video/', 'font/')
_TEXTUAL = ('application/json', 'application/javascript', 'application/x-www-form-urlencoded',
            'application/xml', 'application/ocsp')


def _url(tx):
    host = tx.get('host') or tx['flow'].server
    port = tx['flow'].sport
    if ':' not in host and port != 80:
        host = f'{host}:{port}'
    uri = tx['uri']
    return uri if uri.startswith('http://') else f'http://{host}{uri}'


def _uri_name(uri):
    path = uri.split('?', 1)[0].rstrip('/')
    return path.rsplit('/', 1)[-1] if '/' in path else path


def _safe_name(name, fallback='body'):
    name = _SAFE.sub('_', (name or '').replace('\\', '/').rsplit('/', 1)[-1]).strip('._')
    return (name or fallback)[:80]


def _tx_summary(tx):
    flow = tx['flow']
    return {
        'row': tx['frame'], 'timestamp': iso(tx['ts']), 'client': flow.client, 'server': flow.server,
        'server_port': flow.sport, 'method': tx['method'], 'http_host': tx['host'], 'uri': tx['uri'][:2000],
        'url': _url(tx)[:2000], 'user_agent': tx.get('user_agent'), 'content_type': tx.get('content_type'),
        'request_body_len': tx.get('request_body_len', 0), 'status': tx.get('status'),
        'response_content_type': tx.get('response_content_type'),
        'response_body_len': tx.get('response_body_len'), 'response_row': tx.get('response_frame'),
    }


def _uploads(tx):
    """Fichiers televerses d'une requete : [(nom, contenu, type)]."""
    body = tx.get('request_body') or b''
    if tx['method'] not in ('POST', 'PUT', 'PATCH') or not body:
        return []
    ctype = tx.get('content_type') or ''
    if 'multipart/form-data' in ctype.lower():
        files = [(fname or name or 'part', content, pct)
                 for name, fname, content, pct in net_proto.multipart_parts(body, ctype) if fname]
        if files:
            return files
    name = net_proto._filename_from(tx['request_headers']) or _uri_name(tx['uri']) or 'upload'
    return [(name, body, ctype)]


def _carve_targets(tx, carve_all):
    out = []
    for name, content, ctype in _uploads(tx):
        out.append(('upload', name, content, ctype, tx['frame']))
    body = tx.get('response_body') or b''
    if body:
        rtype = (tx.get('response_content_type') or '').lower()
        attach = net_proto._filename_from(tx.get('response_headers') or {})
        filelike = (attach or net_proto.magic(body)
                    or (rtype.startswith(_FILE_TYPES) and not rtype.startswith(_TEXTUAL)))
        if carve_all or filelike:
            out.append(('download', attach or _uri_name(tx['uri']) or 'index', body, rtype,
                        tx.get('response_frame') or tx['frame']))
    return out


def _default_case(file_path):
    case = toolkit._case_for(file_path)
    return case or os.path.dirname(os.path.abspath(file_path))


def carve(a, file_path, case_dir=None, carve_all=False, max_carve_mb=None):
    """Ecrire les corps HTTP (televersements et telechargements de fichiers) dans
    <cas>/extracted/pcap/<capture>/ avec un manifeste SHA-256. Rien n'est execute."""
    case_dir = os.path.abspath(case_dir or _default_case(file_path))
    if not os.path.isdir(case_dir):
        return {'error': f'Dossier du cas introuvable: {case_dir}'}
    limit = (int(max_carve_mb) if max_carve_mb and int(max_carve_mb) > 0
             else net_pcap.env_int('PHOENIX_PCAP_MAX_CARVE_MB', DEFAULT_MAX_CARVE_MB)) << 20
    tag = _safe_name(os.path.basename(file_path), 'capture').replace('.', '_')
    dest = os.path.join(case_dir, *CARVE_DIR, tag)
    real_case = os.path.realpath(case_dir)
    if not os.path.realpath(dest).startswith(real_case.rstrip(os.sep) + os.sep):
        return {'error': 'Destination de carving hors du dossier du cas'}
    os.makedirs(dest, exist_ok=True)
    manifest_path = os.path.join(dest, 'extraction_manifest.json')
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        manifest = {}
    with open(file_path, 'rb') as f:
        src_hash = hashlib.sha256()
        for chunk in iter(lambda: f.read(1 << 20), b''):
            src_hash.update(chunk)
    entries = {e['file']: e for e in manifest.get('files', []) if isinstance(e, dict) and 'file' in e}
    carved, skipped = [], 0
    for tx in a.http:
        for direction, name, content, ctype, frame in _carve_targets(tx, carve_all):
            if len(entries) >= MAX_CARVED_FILES:
                skipped += 1
                continue
            truncated = len(content) > limit or not (tx.get('request_complete', True) if direction == 'upload'
                                                       else tx.get('response_complete', True))
            data = bytes(content[:limit])
            fname = f'{frame or 0:06d}_{direction}_{_safe_name(name)}'
            path = os.path.join(dest, fname)
            if not os.path.realpath(path).startswith(os.path.realpath(dest) + os.sep):
                continue
            with open(path, 'wb') as out:
                out.write(data)
            entry = {
                'file': fname, 'path': os.path.relpath(path, case_dir).replace(os.sep, '/'),
                'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'row': frame,
                'direction': direction, 'original_name': name, 'method': tx['method'],
                'url': _url(tx)[:2000], 'client': tx['flow'].client, 'server': tx['flow'].server,
                'server_port': tx['flow'].sport, 'content_type': ctype or None,
                'magic': net_proto.magic(data), 'truncated': truncated, 'timestamp': iso(tx['ts']),
            }
            entries[fname] = entry
            carved.append(entry)
    manifest = {
        'tool': 'net_http', 'source': os.path.basename(file_path),
        'source_sha256': src_hash.hexdigest(),
        'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'note': 'Contenu extrait tel quel, jamais execute.',
        'files': sorted(entries.values(), key=lambda e: e['file']),
    }
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    return {'carved': carved, 'carved_count': len(carved), 'skipped_over_limit': skipped,
            'destination': os.path.relpath(dest, case_dir).replace(os.sep, '/'),
            'manifest': os.path.relpath(manifest_path, case_dir).replace(os.sep, '/'),
            'max_file_bytes': limit}


@toolkit.tool(
    'net_http',
    "Analyse HTTP/1.x d'une capture (flux TCP reassembles) : requetes (methode, hote, URI, "
    "User-Agent), reponses (statut, type, tailles), televersements POST/PUT. carve=true extrait les "
    "fichiers transferes (televersements, telechargements de fichiers) vers "
    "<cas>/extracted/pcap/<capture>/ avec manifeste SHA-256 (jamais executes). Chaque transaction "
    "est citable par row = numero du paquet de la requete.",
    toolkit._schema(dict({
        'file_path': _PATH,
        'carve': {'type': 'boolean', 'description': 'Extraire les corps (defaut non)'},
        'carve_all': {'type': 'boolean', 'description': 'Extraire aussi les pages et textes (defaut non)'},
        'case_dir': {'type': 'string', 'description': 'Dossier du cas (destination du carving)'},
        'max_carve_mb': {'type': 'integer', 'description': 'Taille max par fichier extrait '
                                                         '(defaut 25 Mo, PHOENIX_PCAP_MAX_CARVE_MB)'},
        'max_transactions': {'type': 'integer', 'description': 'Transactions detaillees renvoyees (defaut 300)'},
    }, **_CAPS), ['file_path']),
)
@_run_safely
def net_http(file_path, carve=False, carve_all=False, case_dir=None, max_carve_mb=None,
             max_transactions=300, max_packets=None, max_stream_bytes=None):
    a = analyze(file_path, max_packets, max_stream_bytes)
    txs = [_tx_summary(tx) for tx in a.http]
    uploads = []
    for tx in a.http:
        for name, content, ctype in _uploads(tx):
            uploads.append(dict(_tx_summary(tx), filename=name, size=len(content), upload_content_type=ctype,
                                magic=net_proto.magic(content), sha256=hashlib.sha256(content).hexdigest()))
    uas, hosts = {}, {}
    for t in txs:
        uas[t['user_agent'] or '(aucun)'] = uas.get(t['user_agent'] or '(aucun)', 0) + 1
        hosts[t['http_host'] or t['server']] = hosts.get(t['http_host'] or t['server'], 0) + 1
    limit = max(1, min(int(max_transactions or 300), 5000))
    result = {
        'file': os.path.basename(file_path), 'transactions': len(txs),
        'requests': txs[:limit], 'uploads': uploads[:limit],
        'user_agents': dict(sorted(uas.items(), key=lambda kv: -kv[1])),
        'hosts': dict(sorted(hosts.items(), key=lambda kv: -kv[1])[:50]),
        'methods': {m: sum(1 for t in txs if t['method'] == m) for m in sorted({t['method'] for t in txs})},
    }
    if carve:
        result['carving'] = globals()['carve'](a, file_path, case_dir=case_dir, carve_all=carve_all,
                                               max_carve_mb=max_carve_mb)
    events = []
    for t in txs:
        text = (f"HTTP {t['method']} {t['url']} de {t['client']} -> {t['status'] or '-'} "
                f"(UA: {t['user_agent'] or '-'}, envoye {t['request_body_len']} o, "
                f"recu {t['response_body_len'] or 0} o)")
        events.append(dict(t, host=t['client'], event=text[:1500]))
    return _with_events(result, events)


# ============================================================================
# net_tls
# ============================================================================

def _tls_summary(info):
    flow = info['flow']
    sh = info.get('server_hello') or {}
    return {
        'row': info['frame'], 'timestamp': iso(info['ts']), 'client': flow.client, 'server': flow.server,
        'server_port': flow.sport, 'sni': info.get('sni'), 'alpn': info.get('alpn') or [],
        'client_version': info.get('client_version'), 'ja3': info.get('ja3'),
        'ja3_hash': info.get('ja3_hash'), 'ja4': info.get('ja4'), 'ja4_raw': info.get('ja4_raw'),
        'server_version': sh.get('version'), 'cipher': sh.get('cipher_name'),
        'ja3s': sh.get('ja3s'), 'ja3s_hash': sh.get('ja3s_hash'),
        'certificates': [{k: c.get(k) for k in ('subject', 'issuer', 'not_before', 'not_after',
                                                'self_signed', 'sha256', 'serial')}
                         for c in info.get('certificates') or []],
    }


@toolkit.tool(
    'net_tls',
    "Analyse TLS d'une capture : ClientHello (SNI, ALPN, empreintes JA3 / hash JA3 et JA4), "
    "ServerHello (version, suite chiffree, JA3S), certificats visibles (sujet, emetteur, validite, "
    "auto-signe). Chaque poignee de main est citable par row = numero du paquet du ClientHello.",
    toolkit._schema(dict({'file_path': _PATH}, **_CAPS), ['file_path']),
)
@_run_safely
def net_tls(file_path, max_packets=None, max_stream_bytes=None):
    a = analyze(file_path, max_packets, max_stream_bytes)
    hs = [_tls_summary(i) for i in a.tls]

    def count(key):
        acc = {}
        for h in hs:
            if h.get(key):
                e = acc.setdefault(h[key], {key: h[key], 'count': 0, 'servers': set(), 'snis': set()})
                e['count'] += 1
                e['servers'].add(h['server'])
                if h['sni']:
                    e['snis'].add(h['sni'])
        return [dict(e, servers=sorted(e['servers'])[:20], snis=sorted(e['snis'])[:20])
                for e in sorted(acc.values(), key=lambda e: -e['count'])][:50]
    result = {
        'file': os.path.basename(file_path), 'handshakes': len(hs), 'tls': hs[:1000],
        'ja3': count('ja3_hash'), 'ja4': count('ja4'), 'sni': count('sni'),
    }
    events = []
    for h in hs:
        certs = '; '.join(f"{c['subject']} (emetteur {c['issuer']})" for c in h['certificates'][:2])
        text = (f"TLS {h['client']} -> {h['server']}:{h['server_port']} SNI={h['sni'] or '-'} "
                f"JA3={h['ja3_hash']} JA4={h['ja4']} {h['server_version'] or ''} {h['cipher'] or ''}"
                + (f' cert: {certs}' if certs else ''))
        ev = {k: v for k, v in h.items() if k != 'certificates'}
        events.append(dict(ev, host=h['client'], event=text[:1500]))
    return _with_events(result, events)


# ============================================================================
# net_detect : heuristiques de detection
# ============================================================================

_SUSPICIOUS_UA = (
    (re.compile(r'powershell', re.I), 'PowerShell'),
    (re.compile(r'python-requests|python-urllib|aiohttp', re.I), 'Python'),
    (re.compile(r'^curl/|^wget/', re.I), 'curl/wget'),
    (re.compile(r'go-http-client', re.I), 'Go http client'),
    (re.compile(r'Microsoft-CryptoAPI|CertUtil', re.I), 'certutil'),
    (re.compile(r'Microsoft BITS', re.I), 'BITS'),
    (re.compile(r'nmap|sqlmap|nikto|masscan|zgrab|gobuster|dirbuster|hydra', re.I), 'scanner'),
    (re.compile(r'MSIE [2-6]\.0', re.I), 'navigateur obsolete (MSIE <= 6)'),
    (re.compile(r'WinHttp|WinInet', re.I), 'WinHTTP brut'),
)
_STD_PORTS = {20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 8080, 8443}
_HTTP_PORTS = {80, 8080, 8000, 8008, 8888, 3128}
_TLS_PORTS = {443, 8443, 465, 993, 995, 636, 853, 5986, 3269, 9443}
_EXEC_EXT = ('.exe', '.dll', '.ps1', '.hta', '.vbs', '.js', '.bat', '.scr', '.msi', '.jar', '.sh', '.elf')
_ARCHIVE_EXT = ('.zip', '.rar', '.7z', '.tar', '.gz', '.tgz')
_PASS_FIELD = re.compile(r'(?:^|&)(pass|passwd|password|pwd|motdepasse)=([^&]*)', re.I)


def _mask(secret):
    secret = secret or ''
    return (secret[:1] + '*' * max(0, len(secret) - 1)) if secret else ''


def _cv(values):
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean else 0.0


class _Findings:
    def __init__(self):
        self.items = []

    def add(self, kind, title, severity, mitre, description, row, ts, src=None, dst=None, **details):
        self.items.append({
            'id': f'NET-{len(self.items) + 1:03d}', 'type': kind, 'title': title, 'severity': severity,
            'mitre': list(mitre), 'description': description, 'row': row, 'timestamp': iso(ts),
            'src': src, 'dst': dst, **details,
        })


def _beacons(a, f, min_conn, max_jitter, seen):
    groups = {}
    for flow in a.cap.flows:
        if flow.proto != 'TCP' or flow.first_ts is None:
            continue
        groups.setdefault((flow.client, flow.server, flow.sport), []).append(flow)
    tls_by_flow = {i['flow'].id: i for i in a.tls}
    for (client, server, port), flows in groups.items():
        if len(flows) < min_conn:
            continue
        flows.sort(key=lambda fl: fl.first_ts)
        starts = [fl.first_ts for fl in flows]
        intervals = [b - a_ for a_, b in zip(starts, starts[1:])]
        mean = statistics.fmean(intervals)
        if mean < 1.0:
            continue
        jitter = _cv(intervals)
        sizes = [sum(fl.bytes) for fl in flows]
        size_cv = _cv(sizes)
        if jitter > max_jitter or size_cv > 0.25:
            continue
        external = not is_internal(server)
        app = flows[0].app
        web = app in ('HTTP', 'TLS') or port in _HTTP_PORTS | _TLS_PORTS
        mitre = ['T1071.001'] if web else ['T1071']
        if app == 'TLS':
            mitre.append('T1573.002')
        tls = tls_by_flow.get(flows[0].id) or {}
        seen.add(server)
        f.add('beaconing', f'Beaconing vers {server}:{port}', 'high' if external else 'medium', mitre,
              (f'{len(flows)} connexions de {client} vers {server}:{port} ({app}) toutes les '
               f'{mean:.1f} s (gigue {jitter:.1%}), volume quasi constant ({statistics.fmean(sizes):.0f} '
               f'octets, variation {size_cv:.1%}). Signature d\'un implant C2 qui rappelle son serveur.'),
              flows[0].first_frame, flows[0].first_ts, client, server, dst_port=port,
              interval_s=round(mean, 2), jitter=round(jitter, 4), size_cv=round(size_cv, 4),
              connections_count=len(flows), sni=tls.get('sni'), ja3_hash=tls.get('ja3_hash'),
              ja4=tls.get('ja4'), external=external,
              connections=[{'row': fl.first_frame, 'timestamp': iso(fl.first_ts), 'bytes': sum(fl.bytes)}
                           for fl in flows[:200]])


def _exfil(a, f, min_bytes, beacon_dsts):
    clients_per_server, agg = {}, {}
    for flow in a.cap.flows:
        clients_per_server.setdefault(flow.server, set()).add(flow.client)
        if is_internal(flow.server) or not is_internal(flow.client):
            continue
        e = agg.setdefault((flow.client, flow.server), {'out': 0, 'in': 0, 'flows': [], 'apps': set(),
                                                        'ports': set()})
        e['out'] += flow.payload[0]
        e['in'] += flow.payload[1]
        e['flows'].append(flow)
        e['apps'].add(flow.app)
        e['ports'].add(flow.sport)
    uploads = {}
    for tx in a.http:
        for name, content, _ctype in _uploads(tx):
            uploads.setdefault((tx['flow'].client, tx['flow'].server), []).append((tx, name, len(content)))
    for (client, server), e in agg.items():
        rare = len(clients_per_server.get(server, ())) == 1
        if e['out'] < min_bytes or e['out'] < 3 * (e['in'] + 1) or not rare:
            continue
        ups = uploads.get((client, server), [])
        cleartext = bool(e['apps'] & {'HTTP', 'FTP', 'TCP'})
        mitre = ['T1041'] if server in beacon_dsts else ['T1048.003' if cleartext else 'T1048']
        first = min(e['flows'], key=lambda fl: fl.first_frame)
        f.add('exfiltration', f'Volume sortant anormal vers {server}', 'high', mitre,
              (f"{e['out']} octets envoyes par {client} vers {server} (port(s) "
               f"{', '.join(str(p) for p in sorted(e['ports']))}, {', '.join(sorted(a_ or '?' for a_ in e['apps']))}) "
               f"contre {e['in']} recus ; destination externe contactee par ce seul poste."
               + (f" Televersement(s) : {', '.join(n for _t, n, _s in ups[:5])}." if ups else '')),
              ups[0][0]['frame'] if ups else first.first_frame,
              ups[0][0]['ts'] if ups else first.first_ts, client, server,
              bytes_out=e['out'], bytes_in=e['in'], ratio=round(e['out'] / (e['in'] + 1), 1),
              uploads=[{'row': t['frame'], 'filename': n, 'size': s, 'url': _url(t)} for t, n, s in ups[:20]],
              flows=[{'row': fl.first_frame, 'timestamp': iso(fl.first_ts), 'bytes_out': fl.payload[0]}
                     for fl in e['flows'][:100]])
    for (client, server), ups in uploads.items():
        for tx, name, size in ups:
            if (name.lower().endswith(_ARCHIVE_EXT) or net_proto.magic(tx.get('request_body') or b'')
                    in ('zip', '7z', 'rar', 'gzip')) and not is_internal(server):
                f.add('archive_upload', f'Archive televersee vers {server} : {name}', 'high',
                      ['T1048.003', 'T1560'],
                      (f"{client} envoie l'archive {name} ({size} octets) par HTTP {tx['method']} vers "
                       f"{_url(tx)} : collecte archivee puis exfiltree en clair."),
                      tx['frame'], tx['ts'], client, server, filename=name, size=size, url=_url(tx))


def _dns_findings(a, f):
    queries, responses, _rc, by_client, _names, bases, nx_names = dns_stats(a)
    for b in tunnel_candidates(bases):
        mitre = ['T1071.004', 'T1572']
        if b['chars'] >= 1000:
            mitre.append('T1048')
        frame, ts = b['frames'][0]
        f.add('dns_tunneling', f"Tunnel DNS probable via {b['domain']}", 'high', mitre,
              (f"{b['queries']} requetes, {b['unique_subdomains']} sous-domaines uniques sous "
               f"{b['domain']} (longueur moyenne {b['avg_subdomain_len']}, label max "
               f"{b['max_label_len']}, entropie {b['avg_entropy']}, part TXT/NULL {b['txt_ratio']}) : "
               f"donnees encodees dans les noms ({b['chars']} caracteres)."),
              frame, ts, ', '.join(b['clients'][:5]), b['domain'], domain=b['domain'],
              queries=b['queries'], unique_subdomains=b['unique_subdomains'], encoded_chars=b['chars'],
              samples=[{'row': fr, 'timestamp': iso(t)} for fr, t in b['frames'][:50]])
    dga = {}
    for q in queries:
        if q['qname'] in nx_names and net_proto.dga_score(q['qname']) >= DGA_THRESHOLD:
            dga.setdefault(q['src'], {}).setdefault(q['qname'], (q['frame'], q['ts']))
    for client, names in dga.items():
        if len(names) >= 5:
            first = min(names.values())
            f.add('dga', f'Noms de domaine generes (DGA) depuis {client}', 'medium', ['T1568.002'],
                  (f'{len(names)} noms aleatoires en NXDOMAIN (ex: {", ".join(sorted(names)[:5])}) : '
                   'algorithme de generation de domaines d\'un malware cherchant son C2.'),
                  first[0], first[1], client, None, names=sorted(names)[:50],
                  samples=[{'row': fr, 'timestamp': iso(t)} for fr, t in sorted(names.values())[:50]])
    for client, (total, nx) in by_client.items():
        if total >= 20 and nx / total >= 0.5 and client not in dga:
            f.add('nxdomain', f'Taux NXDOMAIN eleve pour {client}', 'low', ['T1568'],
                  f'{nx}/{total} reponses NXDOMAIN ({nx / total:.0%}).', None, None, client, None,
                  nxdomain=nx, responses=total)


def _cred_findings(a, f):
    for tx in a.http:
        creds = net_proto.basic_auth(tx['request_headers'])
        if creds:
            f.add('cleartext_credentials', f"Identifiants HTTP Basic en clair ({creds[0]})", 'medium',
                  ['T1552'], (f"Authentification Basic de {tx['flow'].client} vers {_url(tx)} : "
                              f"utilisateur {creds[0]}, mot de passe {_mask(creds[1])} (masque)."),
                  tx['frame'], tx['ts'], tx['flow'].client, tx['flow'].server, user=creds[0],
                  protocol='HTTP Basic', password_masked=_mask(creds[1]))
        body = tx.get('request_body') or b''
        if tx['method'] == 'POST' and 'urlencoded' in (tx.get('content_type') or '').lower():
            m = _PASS_FIELD.search(body[:65536].decode('latin-1'))
            if m:
                f.add('cleartext_credentials', 'Mot de passe en clair dans un formulaire HTTP', 'medium',
                      ['T1552'], f"Champ {m.group(1)} envoye en clair a {_url(tx)}.",
                      tx['frame'], tx['ts'], tx['flow'].client, tx['flow'].server, protocol='HTTP POST',
                      password_masked=_mask(m.group(2)))
    users = {}
    for c in a.ftp:
        if c['cmd'] == 'USER':
            users[c['flow'].id] = c
        elif c['cmd'] == 'PASS':
            u = users.get(c['flow'].id)
            user = u['arg'] if u else '?'
            f.add('cleartext_credentials', f'Identifiants FTP en clair ({user})', 'medium', ['T1552'],
                  (f"USER {user} / PASS {_mask(c['arg'])} (masque) de {c['flow'].client} vers "
                   f"{c['flow'].server}:{c['flow'].sport}."),
                  (u or c)['frame'], (u or c)['ts'], c['flow'].client, c['flow'].server, user=user,
                  protocol='FTP', password_masked=_mask(c['arg']))


def _ua_findings(a, f):
    seen = {}
    for tx in a.http:
        ua = tx.get('user_agent')
        label = '(aucun User-Agent)' if not ua else next((lab for rx, lab in _SUSPICIOUS_UA if rx.search(ua)), None)
        if label:
            seen.setdefault((tx['flow'].client, ua or '', label), []).append(tx)
    for (client, ua, label), txs in seen.items():
        tx = txs[0]
        f.add('suspicious_user_agent', f'User-Agent suspect ({label}) depuis {client}', 'medium',
              ['T1071.001'], (f"{len(txs)} requete(s) avec User-Agent '{ua or '-'}' vers "
                              f"{', '.join(sorted({_url(t) for t in txs})[:3])}."),
              tx['frame'], tx['ts'], client, tx['flow'].server, user_agent=ua or None,
              requests=[{'row': t['frame'], 'timestamp': iso(t['ts']), 'url': _url(t)} for t in txs[:50]])
    for tx in a.http:
        body = tx.get('response_body') or b''
        name = _uri_name(tx['uri']).lower()
        if tx.get('status') == 200 and (net_proto.magic(body) in ('pe', 'elf') or name.endswith(_EXEC_EXT)):
            f.add('tool_transfer', f'Telechargement d\'executable ou de script : {_url(tx)}', 'high',
                  ['T1105'], (f"{tx['flow'].client} telecharge {name or _url(tx)} ({len(body)} octets, "
                              f"type {net_proto.magic(body) or tx.get('response_content_type') or '?'})."),
                  tx['frame'], tx['ts'], tx['flow'].client, tx['flow'].server, url=_url(tx),
                  sha256=hashlib.sha256(body).hexdigest() if body else None)


def _port_findings(a, f):
    groups = {}
    for flow in a.cap.flows:
        if flow.proto != 'TCP' or is_internal(flow.server) or not (flow.payload[0] or flow.payload[1]):
            continue
        mismatch = ((flow.app == 'HTTP' and flow.sport not in _HTTP_PORTS)
                    or (flow.app == 'TLS' and flow.sport not in _TLS_PORTS))
        if flow.sport in _STD_PORTS and not mismatch:
            continue
        groups.setdefault((flow.server, flow.sport, flow.app, mismatch), []).append(flow)
    for (server, port, app, mismatch), flows in groups.items():
        first = flows[0]
        title = (f'{app} sur port non standard {server}:{port}' if mismatch
                 else f'Connexion vers port non standard {server}:{port}')
        f.add('non_standard_port', title, 'medium' if mismatch else 'low', ['T1571'],
              (f"{len(flows)} connexion(s) de {first.client} vers {server}:{port} ({app}), "
               f"{sum(fl.payload[0] for fl in flows)} octets envoyes."),
              first.first_frame, first.first_ts, first.client, server, dst_port=port, app=app,
              flows=[{'row': fl.first_frame, 'timestamp': iso(fl.first_ts)} for fl in flows[:50]])


def _tls_findings(a, f):
    groups = {}
    for info in a.tls:
        flow = info['flow']
        if is_internal(flow.server):
            continue
        cert = next((c for c in info.get('certificates') or [] if c.get('self_signed')), None)
        if cert:
            groups.setdefault((flow.server, cert.get('sha256')), []).append((info, cert))
    for (server, _sha), items in groups.items():
        info, cert = items[0]
        f.add('self_signed_certificate', f'Certificat auto-signe presente par {server}', 'low', ['T1573.002'],
              (f"Sujet = emetteur = {cert.get('subject')} (SNI {info.get('sni') or '-'}), "
               f"{len(items)} poignee(s) de main."),
              info['frame'], info['ts'], info['flow'].client, server, sni=info.get('sni'),
              ja3_hash=info.get('ja3_hash'), cert_sha256=cert.get('sha256'),
              handshakes=[{'row': i['frame'], 'timestamp': iso(i['ts'])} for i, _c in items[:100]])


@toolkit.tool(
    'net_detect',
    "Detections reseau sur une capture : beaconing (intervalle regulier, faible gigue, taille "
    "constante), exfiltration (volume sortant vers IP externe rare, archive televersee), tunnel DNS, "
    "DGA, identifiants en clair (HTTP Basic, FTP USER/PASS, formulaires), User-Agent suspects, "
    "telechargement d'executables, ports non standard, certificats auto-signes. Chaque constat porte "
    "ses techniques ATT&CK et les row (numeros de paquets) a citer.",
    toolkit._schema(dict({
        'file_path': _PATH,
        'beacon_min_connections': {'type': 'integer', 'description': 'Connexions min. pour un beacon (defaut 6)'},
        'beacon_max_jitter': {'type': 'number', 'description': 'Gigue max (ecart-type/moyenne, defaut 0.2)'},
        'exfil_min_bytes': {'type': 'integer', 'description': 'Octets sortants min. pour l\'exfiltration '
                                                             '(defaut 50000)'},
    }, **_CAPS), ['file_path']),
)
@_run_safely
def net_detect(file_path, beacon_min_connections=6, beacon_max_jitter=0.2, exfil_min_bytes=50000,
               max_packets=None, max_stream_bytes=None):
    a = analyze(file_path, max_packets, max_stream_bytes)
    f = _Findings()
    beacon_dsts = set()
    _beacons(a, f, max(3, int(beacon_min_connections or 6)), float(beacon_max_jitter or 0.2), beacon_dsts)
    _exfil(a, f, max(1, int(exfil_min_bytes or 50000)), beacon_dsts)
    _dns_findings(a, f)
    _cred_findings(a, f)
    _ua_findings(a, f)
    _port_findings(a, f)
    _tls_findings(a, f)
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    findings = sorted(f.items, key=lambda x: (order.get(x['severity'], 5), x['id']))
    techniques = sorted({t for x in findings for t in x['mitre']})
    result = {
        'file': os.path.basename(file_path), 'total_findings': len(findings),
        'by_type': {k: sum(1 for x in findings if x['type'] == k) for k in sorted({x['type'] for x in findings})},
        'mitre_techniques': techniques, 'findings': findings,
        'note': ('Heuristiques : confirmer chaque constat (hypothese alternative, autres sources). '
                 'row = numero de paquet dans la capture.'),
    }
    events = []
    for x in findings:
        if x['row'] is None:
            continue
        events.append({'row': x['row'], 'timestamp': x['timestamp'], 'host': x['src'],
                       'severity': x['severity'], 'mitre': ', '.join(x['mitre']), 'dst': x['dst'],
                       'event': f"[{x['id']}] {x['title']} ({', '.join(x['mitre'])}) : {x['description']}"[:1900]})
    return _with_events(result, events)
