"""Lecture de captures reseau en Python pur (aucune dependance externe).

- PCAP classique (micro et nano-secondes, petit et grand boutiste) ;
- PCAPNG (SHB, IDB avec if_tsresol, EPB, SPB, OPB obsolete) ;
- couches liaison : Ethernet (VLAN 802.1Q/QinQ), Linux SLL / SLL2, IP brut,
  boucle locale BSD (NULL/LOOP) ;
- IPv4 / IPv6 (en-tetes d'extension), TCP / UDP / ICMP ;
- reassemblage des flux TCP a memoire bornee (octets par sens, total, segments
  hors ordre) avec correspondance offset -> numero de paquet.

Reference de preuve : le numero de paquet (1 = premier paquet du fichier,
identique a frame.number de Wireshark) est publie sous la cle 'row'.

Module de support des extensions reseau : il n'enregistre aucun outil.
"""

import bisect
import os
import struct


PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1e-6), b'\xa1\xb2\xc3\xd4': ('>', 1e-6),
    b'\x4d\x3c\xb2\xa1': ('<', 1e-9), b'\xa1\xb2\x3c\x4d': ('>', 1e-9),
}
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'

DEFAULT_MAX_PACKETS = 1_000_000
DEFAULT_MAX_STREAM_BYTES = 4 << 20
DEFAULT_MAX_TOTAL_STREAM_BYTES = 256 << 20
DEFAULT_MAX_FLOWS = 200_000
# Flux non HTTP (TLS, FTP, inconnu) : seul le debut est utile (poignee de main, commandes)
NON_HTTP_STREAM_BYTES = 256 << 10
MAX_PENDING_SEGMENTS = 4096
_MASK32 = 0xFFFFFFFF

HTTP_METHODS = (b'GET', b'POST', b'PUT', b'HEAD', b'OPTIONS', b'DELETE', b'PATCH', b'CONNECT',
                b'TRACE', b'PROPFIND')

ETHERTYPES = {0x0806: 'ARP', 0x88cc: 'LLDP', 0x8035: 'RARP', 0x888e: 'EAPOL', 0x8847: 'MPLS'}
IP_PROTOS = {1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 50: 'ESP', 58: 'ICMPv6',
             89: 'OSPF', 132: 'SCTP'}


def env_int(name, default):
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def caps(max_packets=None, max_stream_bytes=None):
    """Plafonds effectifs (parametres d'outil, sinon variables d'environnement)."""
    return {
        'max_packets': int(max_packets) if max_packets and int(max_packets) > 0
        else env_int('PHOENIX_PCAP_MAX_PACKETS', DEFAULT_MAX_PACKETS),
        'max_stream_bytes': int(max_stream_bytes) if max_stream_bytes and int(max_stream_bytes) > 0
        else env_int('PHOENIX_PCAP_MAX_STREAM_BYTES', DEFAULT_MAX_STREAM_BYTES),
        'max_total_stream_bytes': env_int('PHOENIX_PCAP_MAX_TOTAL_STREAM_BYTES',
                                          DEFAULT_MAX_TOTAL_STREAM_BYTES),
        'max_flows': env_int('PHOENIX_PCAP_MAX_FLOWS', DEFAULT_MAX_FLOWS),
    }


def sniff(path):
    """'pcap', 'pcapng' ou None selon les octets magiques."""
    try:
        with open(path, 'rb') as f:
            head = f.read(12)
    except OSError:
        return None
    if head[:4] in PCAP_MAGICS and len(head) >= 4:
        return 'pcap'
    if head[:4] == PCAPNG_MAGIC and len(head) >= 12 and head[8:12] in (b'\x4d\x3c\x2b\x1a',
                                                                       b'\x1a\x2b\x3c\x4d'):
        return 'pcapng'
    return None


class CaptureError(Exception):
    pass


# ============================================================================
# Lecture des enregistrements (format de fichier)
# ============================================================================

def iter_records(f, meta):
    """Generer (ts, linktype, data, orig_len) ; renseigne meta (format, linktypes...)."""
    head = f.read(4)
    f.seek(0)
    if head in PCAP_MAGICS:
        yield from _iter_pcap(f, meta)
    elif head == PCAPNG_MAGIC:
        yield from _iter_pcapng(f, meta)
    else:
        raise CaptureError('Format non reconnu (ni pcap ni pcapng)')


def _iter_pcap(f, meta):
    hdr = f.read(24)
    if len(hdr) < 24:
        raise CaptureError('En-tete pcap tronque')
    endian, res = PCAP_MAGICS[hdr[:4]]
    vmaj, vmin, _zone, _sig, snaplen, network = struct.unpack(endian + 'HHiIII', hdr[4:])
    linktype = network & 0x0FFFFFFF
    meta.update({'format': 'pcap', 'version': f'{vmaj}.{vmin}', 'snaplen': snaplen,
                 'endianness': 'little' if endian == '<' else 'big',
                 'ts_resolution': 'ns' if res == 1e-9 else 'us'})
    meta['linktypes'].add(linktype)
    rec = struct.Struct(endian + 'IIII')
    while True:
        h = f.read(16)
        if len(h) < 16:
            if h:
                meta['errors'].append('Enregistrement pcap tronque en fin de fichier')
            return
        sec, frac, incl, orig = rec.unpack(h)
        if incl > max(snaplen, 262144) * 4 or incl > 64 << 20:
            meta['errors'].append(f'Longueur de paquet aberrante ({incl}) : lecture arretee')
            return
        data = f.read(incl)
        if len(data) < incl:
            meta['errors'].append('Paquet tronque en fin de fichier')
            return
        yield sec + frac * res, linktype, data, orig


def _tsresol(opts, endian):
    """Option if_tsresol (code 9) d'un IDB -> facteur en secondes (defaut micro)."""
    pos = 0
    while pos + 4 <= len(opts):
        code, length = struct.unpack(endian + 'HH', opts[pos:pos + 4])
        if code == 0:
            break
        value = opts[pos + 4:pos + 4 + length]
        if code == 9 and value:
            v = value[0]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        pos += 4 + length + (-length % 4)
    return 1e-6


def _iter_pcapng(f, meta):
    meta.update({'format': 'pcapng'})
    endian = '<'
    interfaces = []
    while True:
        h = f.read(8)
        if len(h) < 8:
            if h:
                meta['errors'].append('Bloc pcapng tronque en fin de fichier')
            return
        btype_raw = h[:4]
        if btype_raw == PCAPNG_MAGIC:
            bom = f.read(4)
            if bom == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif bom == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            else:
                raise CaptureError('Section pcapng invalide (byte-order magic)')
            meta['endianness'] = 'little' if endian == '<' else 'big'
            total = struct.unpack(endian + 'I', h[4:8])[0]
            if total < 28 or total > 64 << 20:
                raise CaptureError('Longueur de SHB invalide')
            f.read(total - 12)
            interfaces = []  # nouvelle section : nouvelles interfaces
            meta['sections'] = meta.get('sections', 0) + 1
            continue
        btype, total = struct.unpack(endian + 'II', h)
        if total < 12 or total % 4 or total > 64 << 20:
            meta['errors'].append(f'Longueur de bloc pcapng invalide ({total}) : lecture arretee')
            return
        body = f.read(total - 8)
        if len(body) < total - 8:
            meta['errors'].append('Bloc pcapng tronque en fin de fichier')
            return
        body = body[:-4]
        if btype == 1 and len(body) >= 8:  # IDB
            linktype, _res, snaplen = struct.unpack(endian + 'HHI', body[:8])
            interfaces.append((linktype, _tsresol(body[8:], endian), snaplen))
            meta['linktypes'].add(linktype)
            meta['snaplen'] = max(meta.get('snaplen') or 0, snaplen)
        elif btype == 6 and len(body) >= 20:  # EPB
            ifid, hi, lo, cap, orig = struct.unpack(endian + 'IIIII', body[:20])
            if ifid >= len(interfaces):
                meta['errors'].append('EPB referencant une interface inconnue')
                continue
            linktype, res, _snap = interfaces[ifid]
            yield ((hi << 32) | lo) * res, linktype, body[20:20 + cap], orig
        elif btype == 3 and len(body) >= 4 and interfaces:  # SPB : interface 0, pas d'horodatage
            orig = struct.unpack(endian + 'I', body[:4])[0]
            linktype, _res, snaplen = interfaces[0]
            cap = min(orig, snaplen or orig, len(body) - 4)
            yield None, linktype, body[4:4 + cap], orig
        elif btype == 2 and len(body) >= 20:  # OPB (obsolete)
            ifid, _drops, hi, lo, cap, orig = struct.unpack(endian + 'HHIIII', body[:20])
            if ifid < len(interfaces):
                linktype, res, _snap = interfaces[ifid]
                yield ((hi << 32) | lo) * res, linktype, body[20:20 + cap], orig


# ============================================================================
# Decodage des couches
# ============================================================================

class Packet:
    __slots__ = ('frame', 'ts', 'length', 'l3', 'src', 'dst', 'proto', 'sport', 'dport',
                 'flags', 'seq', 'ack', 'payload', 'ip_version', 'ttl')

    def __init__(self, frame, ts, length):
        self.frame = frame
        self.ts = ts
        self.length = length
        self.l3 = None
        self.src = self.dst = None
        self.proto = None
        self.sport = self.dport = None
        self.flags = 0
        self.seq = self.ack = 0
        self.payload = b''
        self.ip_version = None
        self.ttl = None


def _ip4(b):
    return '.'.join(str(x) for x in b)


def _ip6(b):
    words = struct.unpack('>8H', b)
    # compression '::' de la plus longue suite de zeros (RFC 5952)
    best, best_len, cur, cur_len = -1, 0, -1, 0
    for i, w in enumerate(words):
        if w == 0:
            if cur < 0:
                cur, cur_len = i, 1
            else:
                cur_len += 1
            if cur_len > best_len:
                best, best_len = cur, cur_len
        else:
            cur, cur_len = -1, 0
    parts = [format(w, 'x') for w in words]
    if best_len >= 2:
        parts = parts[:best] + [''] + parts[best + best_len:]
        if best == 0:
            parts = [''] + parts
        if best + best_len == 8:
            parts = parts + ['']
    return ':'.join(parts)


def _l2(linktype, data):
    """(ethertype ou famille, offset de la couche 3) ; ethertype 0 = inconnu."""
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return 0, 0
        etype = struct.unpack('>H', data[12:14])[0]
        off = 14
        while etype in (0x8100, 0x88a8, 0x9100) and len(data) >= off + 4:
            etype = struct.unpack('>H', data[off + 2:off + 4])[0]
            off += 4
        return etype, off
    if linktype == 113:  # Linux SLL
        if len(data) < 16:
            return 0, 0
        return struct.unpack('>H', data[14:16])[0], 16
    if linktype == 276:  # Linux SLL2
        if len(data) < 20:
            return 0, 0
        return struct.unpack('>H', data[0:2])[0], 20
    if linktype in (101, 12, 14):  # IP brut
        if not data:
            return 0, 0
        return (0x0800 if data[0] >> 4 == 4 else 0x86DD if data[0] >> 4 == 6 else 0), 0
    if linktype == 228:
        return 0x0800, 0
    if linktype == 229:
        return 0x86DD, 0
    if linktype in (0, 108):  # NULL / LOOP : famille d'adresses sur 4 octets
        if len(data) < 4:
            return 0, 0
        fam = struct.unpack('<I', data[:4])[0]
        if fam > 0xFFFF:
            fam = struct.unpack('>I', data[:4])[0]
        if fam == 2:
            return 0x0800, 4
        if fam in (10, 24, 28, 30):
            return 0x86DD, 4
        return 0, 0
    return 0, 0


def decode(frame, ts, linktype, data, orig_len):
    """Decoder un paquet jusqu'a la couche transport (jamais d'exception)."""
    pkt = Packet(frame, ts, orig_len)
    try:
        etype, off = _l2(linktype, data)
        if etype == 0x0800 and len(data) >= off + 20:
            v_ihl = data[off]
            ihl = (v_ihl & 0x0F) * 4
            if v_ihl >> 4 != 4 or ihl < 20:
                pkt.l3 = 'IPv4?'
                return pkt
            total = struct.unpack('>H', data[off + 2:off + 4])[0]
            frag = struct.unpack('>H', data[off + 6:off + 8])[0]
            pkt.ttl = data[off + 8]
            proto = data[off + 9]
            pkt.src, pkt.dst = _ip4(data[off + 12:off + 16]), _ip4(data[off + 16:off + 20])
            pkt.ip_version, pkt.l3 = 4, 'IPv4'
            end = off + total if total >= ihl else len(data)
            l4 = data[off + ihl:min(end, len(data))]
            if frag & 0x1FFF:  # fragment non initial : pas d'en-tete transport
                pkt.proto = IP_PROTOS.get(proto, f'IP/{proto}') + '-fragment'
                return pkt
            _l4(pkt, proto, l4)
        elif etype == 0x86DD and len(data) >= off + 40:
            plen = struct.unpack('>H', data[off + 4:off + 6])[0]
            nxt = data[off + 6]
            pkt.ttl = data[off + 7]
            pkt.src, pkt.dst = _ip6(data[off + 8:off + 24]), _ip6(data[off + 24:off + 40])
            pkt.ip_version, pkt.l3 = 6, 'IPv6'
            pos = off + 40
            end = min(len(data), pos + plen) if plen else len(data)
            for _ in range(8):  # en-tetes d'extension
                if nxt in (0, 43, 60) and pos + 2 <= end:
                    nxt, pos = data[pos], pos + (data[pos + 1] + 1) * 8
                elif nxt == 51 and pos + 2 <= end:
                    nxt, pos = data[pos], pos + (data[pos + 1] + 2) * 4
                elif nxt == 44 and pos + 8 <= end:
                    fragoff = struct.unpack('>H', data[pos + 2:pos + 4])[0] >> 3
                    nxt, pos = data[pos], pos + 8
                    if fragoff:
                        pkt.proto = IP_PROTOS.get(nxt, f'IP/{nxt}') + '-fragment'
                        return pkt
                else:
                    break
            _l4(pkt, nxt, data[pos:end])
        else:
            pkt.l3 = ETHERTYPES.get(etype, f'ethertype 0x{etype:04x}' if etype else 'inconnu')
    except (struct.error, IndexError):
        pkt.proto = pkt.proto or 'malforme'
    return pkt


def _l4(pkt, proto, seg):
    if proto == 6 and len(seg) >= 20:
        pkt.proto = 'TCP'
        pkt.sport, pkt.dport, pkt.seq, pkt.ack, off_flags = struct.unpack('>HHIIH', seg[:14])
        doff = (off_flags >> 12) * 4
        pkt.flags = off_flags & 0x1FF
        pkt.payload = seg[doff:] if doff >= 20 else b''
    elif proto == 17 and len(seg) >= 8:
        pkt.proto = 'UDP'
        pkt.sport, pkt.dport, ulen = struct.unpack('>HHH', seg[:6])
        pkt.payload = seg[8:ulen] if 8 <= ulen <= len(seg) else seg[8:]
    else:
        pkt.proto = IP_PROTOS.get(proto, f'IP/{proto}')
        pkt.payload = seg


# ============================================================================
# Reassemblage TCP
# ============================================================================

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


class Budget:
    """Budget memoire global du reassemblage (octets bufferises)."""

    def __init__(self, total):
        self.total = total
        self.used = 0
        self.exhausted = False


class TcpStream:
    """Un sens d'une connexion TCP, reassemble dans l'ordre des numeros de sequence."""

    __slots__ = ('base', 'data', 'pending', 'pending_bytes', 'offsets', 'frames', 'times', 'cap',
                 'budget', 'truncated', 'stopped', 'classified', 'max_cap')

    def __init__(self, cap, budget):
        self.base = None
        self.data = bytearray()
        self.pending = {}
        self.pending_bytes = 0
        self.offsets, self.frames, self.times = [], [], []
        self.cap = cap
        self.max_cap = cap
        self.budget = budget
        self.truncated = False
        self.stopped = False
        self.classified = False

    def syn(self, seq):
        if self.base is None or not self.data:
            self.base = (seq + 1) & _MASK32

    def add(self, seq, payload, frame, ts):
        if not payload or self.stopped:
            if payload and self.stopped:
                self.truncated = True
            return
        if self.base is None:
            self.base = seq
        off = (seq - self.base) & _MASK32
        if off >= 1 << 31:  # avant le debut connu (retransmission ancienne)
            back = (1 << 32) - off
            if back >= len(payload):
                return
            payload, off = payload[back:], 0
        length = len(self.data)
        if off <= length:
            if off + len(payload) > length:
                self._append(payload[length - off:], frame, ts)
                self._drain()
        elif off - length <= self.cap and len(self.pending) < MAX_PENDING_SEGMENTS:
            if off not in self.pending:
                self.pending[off] = (bytes(payload), frame, ts)
                self.pending_bytes += len(payload)
                if self.pending_bytes > self.cap:
                    self.truncated = True
                    self.stopped = True

    def _append(self, chunk, frame, ts):
        if not chunk:
            return
        if not self.classified and len(self.data) + len(chunk) >= 8:
            self.classified = True
            head = bytes(self.data[:16]) + bytes(chunk[:16])
            if not (head.startswith(HTTP_METHODS) or head.startswith(b'HTTP/')):
                self.cap = min(self.cap, NON_HTTP_STREAM_BYTES)
        room = min(self.cap - len(self.data), self.budget.total - self.budget.used)
        if room <= 0:
            self.truncated = self.stopped = True
            if self.budget.used >= self.budget.total:
                self.budget.exhausted = True
            return
        if len(chunk) > room:
            chunk = chunk[:room]
            self.truncated = True
            self.stopped = True
        self.offsets.append(len(self.data))
        self.frames.append(frame)
        self.times.append(ts)
        self.data += chunk
        self.budget.used += len(chunk)

    def _drain(self):
        while self.pending and not self.stopped:
            length = len(self.data)
            ready = [k for k in self.pending if k <= length]
            if not ready:
                return
            k = min(ready)
            seg, frame, ts = self.pending.pop(k)
            self.pending_bytes -= len(seg)
            if k + len(seg) > length:
                self._append(seg[length - k:], frame, ts)

    @property
    def gaps(self):
        return bool(self.pending)

    def frame_at(self, offset):
        """Numero du paquet portant l'octet `offset` du flux (None si inconnu)."""
        if not self.offsets:
            return None
        i = bisect.bisect_right(self.offsets, offset) - 1
        return self.frames[max(i, 0)]

    def time_at(self, offset):
        if not self.offsets:
            return None
        i = bisect.bisect_right(self.offsets, offset) - 1
        return self.times[max(i, 0)]


class Flow:
    __slots__ = ('id', 'proto', 'client', 'cport', 'server', 'sport', 'first_frame', 'first_ts',
                 'last_ts', 'pkts', 'bytes', 'payload', 'syn', 'synack', 'fin', 'rst', 'app',
                 'c2s', 's2c', 'frames')

    def __init__(self, fid, proto, client, cport, server, sport, frame, ts):
        self.id = fid
        self.proto = proto
        self.client, self.cport, self.server, self.sport = client, cport, server, sport
        self.first_frame = frame
        self.first_ts = self.last_ts = ts
        self.pkts = [0, 0]
        self.bytes = [0, 0]
        self.payload = [0, 0]
        self.syn = self.synack = self.fin = self.rst = False
        self.app = None
        self.c2s = self.s2c = None
        self.frames = []

    @property
    def duration(self):
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)


_WELL_KNOWN = {20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 135, 137, 138, 139, 143, 161,
               389, 443, 445, 465, 514, 587, 636, 853, 993, 995, 1433, 1521, 3268, 3306, 3389,
               5060, 5353, 5355, 5432, 5985, 5986, 8080, 8443}


def _server_side(pkt):
    """Le destinataire du paquet est-il le serveur ? (heuristique hors SYN)."""
    if pkt.dport in _WELL_KNOWN and pkt.sport not in _WELL_KNOWN:
        return True
    if pkt.sport in _WELL_KNOWN and pkt.dport not in _WELL_KNOWN:
        return False
    return pkt.dport < pkt.sport if pkt.dport < 1024 or pkt.sport < 1024 else True


class Capture:
    """Resultat de lecture d'une capture : metadonnees, paquets agreges, flux."""

    def __init__(self, path, limits):
        self.path = path
        self.limits = limits
        self.meta = {'format': None, 'linktypes': set(), 'errors': [], 'snaplen': None}
        self.packets = 0
        self.bytes = 0
        self.first_ts = self.last_ts = None
        self.truncated = False
        self.flows = []
        self.l3 = {}
        self.l4 = {}
        self.udp_packets = []  # (frame, ts, src, sport, dst, dport, payload) pour DNS
        self.budget = Budget(limits['max_total_stream_bytes'])
        self.flows_capped = False
        self.hosts = {}  # ip -> [paquets emis, octets emis, paquets recus, octets recus]
        self._index = {}

    def _host(self, ip, sent, length):
        entry = self.hosts.get(ip)
        if entry is None:
            if len(self.hosts) >= self.limits['max_flows']:
                return
            entry = self.hosts[ip] = [0, 0, 0, 0]
        i = 0 if sent else 2
        entry[i] += 1
        entry[i + 1] += length

    def _flow_for(self, pkt):
        a, b = (pkt.src, pkt.sport), (pkt.dst, pkt.dport)
        key = (pkt.proto,) + (a + b if a <= b else b + a)
        flow = self._index.get(key)
        is_syn = pkt.proto == 'TCP' and pkt.flags & SYN and not pkt.flags & ACK
        if flow is not None and is_syn and (flow.fin or flow.rst or flow.payload[0] or flow.payload[1]):
            flow = None  # reutilisation du 5-tuple : nouvelle connexion
        if flow is None:
            if len(self.flows) >= self.limits['max_flows']:
                self.flows_capped = True
                return None, 0
            if pkt.proto == 'TCP':
                if is_syn:
                    to_server = True
                elif pkt.flags & SYN and pkt.flags & ACK:
                    to_server = False
                else:
                    to_server = _server_side(pkt)
            else:
                to_server = _server_side(pkt)
            if to_server:
                flow = Flow(len(self.flows), pkt.proto, pkt.src, pkt.sport, pkt.dst, pkt.dport,
                            pkt.frame, pkt.ts)
            else:
                flow = Flow(len(self.flows), pkt.proto, pkt.dst, pkt.dport, pkt.src, pkt.sport,
                            pkt.frame, pkt.ts)
            if pkt.proto == 'TCP':
                cap = self.limits['max_stream_bytes']
                flow.c2s, flow.s2c = TcpStream(cap, self.budget), TcpStream(cap, self.budget)
            self.flows.append(flow)
            self._index[key] = flow
        direction = 0 if (pkt.src, pkt.sport) == (flow.client, flow.cport) else 1
        return flow, direction

    def add(self, pkt):
        self.packets += 1
        self.bytes += pkt.length
        if pkt.ts is not None:
            if self.first_ts is None or pkt.ts < self.first_ts:
                self.first_ts = pkt.ts
            if self.last_ts is None or pkt.ts > self.last_ts:
                self.last_ts = pkt.ts
        self.l3[pkt.l3 or 'inconnu'] = self.l3.get(pkt.l3 or 'inconnu', 0) + 1
        if pkt.proto:
            self.l4[pkt.proto] = self.l4.get(pkt.proto, 0) + 1
        if pkt.src is not None:
            self._host(pkt.src, True, pkt.length)
            self._host(pkt.dst, False, pkt.length)
        if pkt.proto not in ('TCP', 'UDP') or pkt.sport is None:
            return
        flow, d = self._flow_for(pkt)
        if flow is None:
            return
        flow.pkts[d] += 1
        flow.bytes[d] += pkt.length
        flow.payload[d] += len(pkt.payload)
        if pkt.ts is not None:
            if flow.first_ts is None:
                flow.first_ts = pkt.ts
            flow.last_ts = pkt.ts
        if len(flow.frames) < 64:
            flow.frames.append(pkt.frame)
        if pkt.proto == 'UDP':
            if pkt.payload and (53 in (pkt.sport, pkt.dport)):
                self.udp_packets.append((pkt.frame, pkt.ts, pkt.src, pkt.sport, pkt.dst, pkt.dport,
                                         bytes(pkt.payload[:4096])))
            return
        stream = flow.c2s if d == 0 else flow.s2c
        if pkt.flags & SYN:
            flow.syn = flow.syn or not pkt.flags & ACK
            flow.synack = flow.synack or bool(pkt.flags & ACK)
            stream.syn(pkt.seq)
        if pkt.flags & FIN:
            flow.fin = True
        if pkt.flags & RST:
            flow.rst = True
        if pkt.payload:
            stream.add(pkt.seq, pkt.payload, pkt.frame, pkt.ts)


def read_capture(path, max_packets=None, max_stream_bytes=None):
    """Lire et agreger une capture (bornee par les plafonds)."""
    limits = caps(max_packets, max_stream_bytes)
    cap = Capture(path, limits)
    with open(path, 'rb') as f:
        frame = 0
        for ts, linktype, data, orig in iter_records(f, cap.meta):
            frame += 1
            if frame > limits['max_packets']:
                cap.truncated = True
                cap.meta['errors'].append(f"Plafond de paquets atteint ({limits['max_packets']}) : "
                                          'suite de la capture ignoree')
                break
            cap.add(decode(frame, ts, linktype, data, orig))
    if cap.budget.exhausted:
        cap.meta['errors'].append('Budget memoire de reassemblage TCP epuise : flux tronques')
    return cap
