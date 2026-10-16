"""Dissecteurs applicatifs en Python pur : DNS, HTTP/1.x, TLS (JA3, JA3S, JA4,
certificats), FTP. Aucune execution de contenu : lecture d'octets uniquement.

Module de support des extensions reseau : il n'enregistre aucun outil.
"""

import base64
import hashlib
import math
import re
import struct
import zlib


# ============================================================================
# Utilitaires
# ============================================================================


def entropy(text):
    """Entropie de Shannon (bits par caractere)."""
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_SECOND_LEVEL = {'co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'gouv', 'ne', 'or', 'go'}


def base_domain(name):
    """Domaine enregistre approximatif (sans liste publique de suffixes)."""
    labels = [x for x in name.lower().rstrip('.').split('.') if x]
    if len(labels) <= 2:
        return '.'.join(labels)
    if labels[-2] in _SECOND_LEVEL and len(labels[-1]) == 2:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def safe_decompress(data, encoding, limit):
    """Decompresser (gzip / deflate / zlib) sans depasser `limit` octets ; None si echec."""
    modes = {'gzip': (31,), 'x-gzip': (31,), 'deflate': (15, -15), 'zlib': (15,)}.get(encoding)
    if not modes:
        return None
    for wbits in modes:
        try:
            d = zlib.decompressobj(wbits)
            out = d.decompress(bytes(data), limit)
            return out
        except zlib.error:
            continue
    return None


MAGIC = ((b'MZ', 'pe'), (b'\x7fELF', 'elf'), (b'PK\x03\x04', 'zip'), (b'%PDF', 'pdf'),
         (b'\x1f\x8b', 'gzip'), (b'7z\xbc\xaf\x27\x1c', '7z'), (b'Rar!', 'rar'),
         (b'\xd0\xcf\x11\xe0', 'ole'), (b'\x89PNG', 'png'), (b'\xff\xd8\xff', 'jpeg'),
         (b'GIF8', 'gif'), (b'\xca\xfe\xba\xbe', 'macho'), (b'BZh', 'bzip2'))


def magic(data):
    for sig, name in MAGIC:
        if data[:len(sig)] == sig:
            return name
    return None


# ============================================================================
# DNS
# ============================================================================

QTYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 10: 'NULL', 12: 'PTR', 15: 'MX', 16: 'TXT',
          28: 'AAAA', 33: 'SRV', 41: 'OPT', 65: 'HTTPS', 255: 'ANY'}
RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}


def _dns_name(msg, pos):
    labels, jumps, end = [], 0, None
    while True:
        if pos >= len(msg):
            raise ValueError('nom DNS tronque')
        length = msg[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                raise ValueError('pointeur tronque')
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            jumps += 1
            if jumps > 32:
                raise ValueError('boucle de compression')
            continue
        if length == 0:
            pos += 1
            break
        labels.append(msg[pos + 1:pos + 1 + length].decode('ascii', 'replace'))
        pos += 1 + length
        if len(labels) > 128:
            raise ValueError('nom trop long')
    return '.'.join(labels), (end if end is not None else pos)


def parse_dns(msg):
    """Message DNS -> dict (id, qr, rcode, questions, answers) ou None."""
    if len(msg) < 12:
        return None
    try:
        tid, flags, qd, an, ns, ar = struct.unpack('>HHHHHH', msg[:12])
        if qd > 64 or an > 512:
            return None
        pos = 12
        questions = []
        for _ in range(qd):
            name, pos = _dns_name(msg, pos)
            qtype, _qclass = struct.unpack('>HH', msg[pos:pos + 4])
            pos += 4
            questions.append({'name': name, 'type': QTYPES.get(qtype, str(qtype))})
        answers = []
        for _ in range(an):
            name, pos = _dns_name(msg, pos)
            rtype, _rclass, ttl, rdlen = struct.unpack('>HHIH', msg[pos:pos + 10])
            pos += 10
            rdata = msg[pos:pos + rdlen]
            value = None
            if rtype == 1 and rdlen == 4:
                value = '.'.join(str(x) for x in rdata)
            elif rtype == 28 and rdlen == 16:
                from ._net_pcap import _ip6
                value = _ip6(rdata)
            elif rtype in (2, 5, 12):
                value = _dns_name(msg, pos)[0]
            elif rtype == 15 and rdlen > 2:
                value = _dns_name(msg, pos + 2)[0]
            elif rtype == 16:
                parts, p = [], 0
                while p < len(rdata):
                    ln = rdata[p]
                    parts.append(rdata[p + 1:p + 1 + ln].decode('utf-8', 'replace'))
                    p += 1 + ln
                value = ''.join(parts)[:512]
            else:
                value = rdata[:64].hex()
            answers.append({'name': name, 'type': QTYPES.get(rtype, str(rtype)), 'ttl': ttl,
                            'data': value})
            pos += rdlen
        return {'id': tid, 'qr': bool(flags & 0x8000), 'rcode': RCODES.get(flags & 0xF, str(flags & 0xF)),
                'questions': questions, 'answers': answers}
    except (ValueError, struct.error, IndexError):
        return None


_VOWELS = set('aeiouy')


def dga_score(name):
    """Score 0..1 de nom genere algorithmiquement (sur le label enregistre)."""
    label = base_domain(name).split('.')[0]
    if len(label) < 8:
        return 0.0
    ent = entropy(label)
    vowels = sum(1 for c in label if c in _VOWELS) / len(label)
    digits = sum(1 for c in label if c.isdigit()) / len(label)
    run, longest = 0, 0
    for c in label:
        run = run + 1 if c.isalpha() and c not in _VOWELS else 0
        longest = max(longest, run)
    score = 0.0
    score += min(1.0, max(0.0, (ent - 2.8) / 1.2)) * 0.4
    score += (0.25 if vowels < 0.25 else 0.1 if vowels < 0.32 else 0.0)
    score += 0.15 if longest >= 5 else 0.0
    score += 0.1 if 0.1 <= digits <= 0.6 else 0.0
    score += 0.1 if len(label) >= 12 else 0.0
    return round(min(score, 1.0), 2)


# ============================================================================
# HTTP/1.x
# ============================================================================

_METHODS = ('GET', 'POST', 'PUT', 'HEAD', 'OPTIONS', 'DELETE', 'PATCH', 'CONNECT', 'TRACE',
            'PROPFIND')
MAX_HEADER = 64 << 10
MAX_MESSAGES = 10000


def _headers(block):
    lines = block.decode('latin-1').split('\r\n')
    first, headers = lines[0], {}
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            k = k.strip().lower()
            headers[k] = (headers[k] + ', ' + v.strip()) if k in headers else v.strip()
    return first, headers


def _dechunk(data, pos, limit):
    """Corps 'chunked' a partir de pos -> (corps, position de fin, complet)."""
    out = bytearray()
    while pos < len(data):
        eol = data.find(b'\r\n', pos, pos + 1024)
        if eol < 0:
            return bytes(out), len(data), False
        try:
            size = int(bytes(data[pos:eol]).split(b';')[0].strip() or b'0', 16)
        except ValueError:
            return bytes(out), len(data), False
        pos = eol + 2
        if size == 0:
            end = data.find(b'\r\n\r\n', pos - 2, pos + 8192)
            return bytes(out), (end + 4 if end >= 0 else pos + 2), True
        if len(out) < limit:
            out += data[pos:pos + min(size, limit - len(out))]
        pos += size + 2
    return bytes(out), len(data), False


def _messages(data, is_request, limit, no_body_for=None):
    """Decouper un flux HTTP en messages : [(offset, ligne, en-tetes, corps, complet)]."""
    out, pos, n = [], 0, 0
    no_body_for = list(no_body_for or [])
    while pos < len(data) and n < MAX_MESSAGES:
        end = data.find(b'\r\n\r\n', pos, pos + MAX_HEADER)
        if end < 0:
            break
        first, headers = _headers(bytes(data[pos:end]))
        token = first.split(' ', 1)[0]
        if is_request and token not in _METHODS:
            break
        if not is_request and not token.startswith('HTTP/'):
            break
        body_start = end + 4
        body, complete = b'', True
        status = None
        if not is_request:
            try:
                status = int(first.split(' ')[1])
            except (IndexError, ValueError):
                status = 0
        no_body = (not is_request and (100 <= (status or 0) < 200 or status in (204, 304)))
        if not is_request and status and status >= 200 and no_body_for:
            head_request = no_body_for.pop(0) == 'HEAD'
            no_body = no_body or head_request
        if no_body:
            nxt = body_start
        elif 'chunked' in headers.get('transfer-encoding', '').lower():
            body, nxt, complete = _dechunk(data, body_start, limit)
        elif 'content-length' in headers:
            try:
                cl = max(0, int(headers['content-length'].split(',')[0]))
            except ValueError:
                cl = 0
            body = bytes(data[body_start:body_start + min(cl, limit)])
            complete = len(data) - body_start >= cl
            nxt = body_start + cl
        elif is_request:
            nxt = body_start
        else:  # reponse sans longueur : jusqu'a la fermeture
            body = bytes(data[body_start:body_start + limit])
            nxt = len(data)
        out.append((pos, first, headers, body, complete, status))
        pos, n = nxt, n + 1
    return out


def _filename_from(headers):
    cd = headers.get('content-disposition', '')
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd, re.IGNORECASE)
    return m.group(1).strip() if m else None


def multipart_parts(body, content_type):
    """Parties d'un corps multipart/form-data : [(nom de champ, nom de fichier, contenu)]."""
    m = re.search(r'boundary="?([^";]+)"?', content_type or '', re.IGNORECASE)
    if not m:
        return []
    boundary = b'--' + m.group(1).encode('latin-1')
    parts = []
    for chunk in body.split(boundary)[1:]:
        if chunk.startswith(b'--'):
            break
        chunk = chunk[2:] if chunk.startswith(b'\r\n') else chunk
        end = chunk.find(b'\r\n\r\n')
        if end < 0:
            continue
        _first, headers = _headers(b'X\r\n' + chunk[:end])
        content = chunk[end + 4:]
        if content.endswith(b'\r\n'):
            content = content[:-2]
        cd = headers.get('content-disposition', '')
        name = re.search(r'\bname="([^"]*)"', cd)
        parts.append((name.group(1) if name else None, _filename_from(headers), content,
                      headers.get('content-type')))
    return parts


def parse_http(client, server, limit):
    """Transactions HTTP d'une connexion (flux reassembles client et serveur)."""
    requests_ = _messages(client.data, True, limit) if client is not None else []
    methods = [r[1].split(' ', 1)[0] for r in requests_]
    responses = [r for r in (_messages(server.data, False, limit, methods) if server is not None else [])
                 if not (r[5] and 100 <= r[5] < 200)]
    out = []
    for i, (off, first, headers, body, complete, _st) in enumerate(requests_):
        parts = first.split(' ')
        method = parts[0]
        uri = parts[1] if len(parts) > 1 else ''
        tx = {
            'offset': off, 'frame': client.frame_at(off), 'ts': client.time_at(off),
            'method': method, 'uri': uri, 'version': parts[2] if len(parts) > 2 else '',
            'host': headers.get('host', ''), 'user_agent': headers.get('user-agent'),
            'referer': headers.get('referer'), 'content_type': headers.get('content-type'),
            'request_headers': headers, 'request_body': body, 'request_complete': complete,
            'request_body_len': int(headers.get('content-length', '0').split(',')[0] or 0)
            if headers.get('content-length', '').split(',')[0].strip().isdigit() else len(body),
        }
        if i < len(responses):
            roff, rfirst, rheaders, rbody, rcomplete, status = responses[i]
            encoding = rheaders.get('content-encoding', '').lower().strip()
            decoded = safe_decompress(rbody, encoding, limit) if encoding else None
            tx.update({
                'response_frame': server.frame_at(roff), 'status': status,
                'reason': rfirst.split(' ', 2)[2] if rfirst.count(' ') >= 2 else '',
                'response_content_type': rheaders.get('content-type'),
                'response_headers': rheaders, 'response_body': decoded if decoded is not None else rbody,
                'response_encoding': encoding or None, 'response_complete': rcomplete,
                'response_body_len': len(rbody), 'server': rheaders.get('server'),
            })
        out.append(tx)
    return out


def basic_auth(headers):
    """Identifiants HTTP Basic (utilisateur, mot de passe) ou None."""
    value = headers.get('authorization', '')
    if not value.lower().startswith('basic '):
        return None
    try:
        raw = base64.b64decode(value[6:].strip(), validate=False).decode('utf-8', 'replace')
    except (ValueError, TypeError):
        return None
    user, _, password = raw.partition(':')
    return user, password


# ============================================================================
# TLS : ClientHello / ServerHello / Certificate, JA3, JA3S, JA4
# ============================================================================

TLS_VERSIONS = {0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2',
                0x0304: 'TLS 1.3', 0x0002: 'SSL 2.0'}
_JA4_VERSIONS = {0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3',
                 0x0002: 's2', 0xfeff: 'd1', 0xfefd: 'd2', 0xfefc: 'd3'}
CIPHER_NAMES = {
    0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384',
    0x1303: 'TLS_CHACHA20_POLY1305_SHA256', 0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA', 0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384', 0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    0x0005: 'TLS_RSA_WITH_RC4_128_SHA', 0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
}


def is_grease(v):
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def tls_handshakes(data, limit=1 << 16):
    """Messages de poignee de main d'un sens TLS : [(type, corps)] (bornes)."""
    hs, pos = bytearray(), 0
    while pos + 5 <= len(data) and len(hs) < limit:
        ctype, _ver, length = data[pos], data[pos + 1:pos + 3], struct.unpack('>H', data[pos + 3:pos + 5])[0]
        if ctype not in (20, 21, 22, 23) or _ver[0] != 3:
            break
        if ctype == 22:
            hs += data[pos + 5:pos + 5 + length]
        elif ctype in (20, 23):
            break
        pos += 5 + length
    msgs, p = [], 0
    while p + 4 <= len(hs):
        htype = hs[p]
        hlen = int.from_bytes(hs[p + 1:p + 4], 'big')
        if p + 4 + hlen > len(hs):
            msgs.append((htype, bytes(hs[p + 4:])))  # message tronque
            break
        msgs.append((htype, bytes(hs[p + 4:p + 4 + hlen])))
        p += 4 + hlen
    return msgs


def _u16list(b):
    return [struct.unpack('>H', b[i:i + 2])[0] for i in range(0, len(b) - 1, 2)]


def _extensions(body, pos):
    exts = []
    if pos + 2 > len(body):
        return exts
    total = struct.unpack('>H', body[pos:pos + 2])[0]
    pos += 2
    end = min(len(body), pos + total)
    while pos + 4 <= end:
        etype, elen = struct.unpack('>HH', body[pos:pos + 4])
        exts.append((etype, body[pos + 4:pos + 4 + elen]))
        pos += 4 + elen
    return exts


def parse_client_hello(body):
    version = struct.unpack('>H', body[0:2])[0]
    pos = 34
    sid = body[pos]
    pos += 1 + sid
    clen = struct.unpack('>H', body[pos:pos + 2])[0]
    ciphers = _u16list(body[pos + 2:pos + 2 + clen])
    pos += 2 + clen
    comp = body[pos]
    pos += 1 + comp
    exts = _extensions(body, pos)
    hello = {'legacy_version': version, 'ciphers': ciphers, 'extensions': [e for e, _ in exts],
             'sni': None, 'alpn': [], 'groups': [], 'point_formats': [], 'sig_algs': [],
             'supported_versions': []}
    for etype, data in exts:
        try:
            if etype == 0 and len(data) >= 5:
                ln = struct.unpack('>H', data[3:5])[0]
                hello['sni'] = data[5:5 + ln].decode('ascii', 'replace')
            elif etype == 16 and len(data) >= 2:
                p = 2
                while p < len(data):
                    ln = data[p]
                    hello['alpn'].append(data[p + 1:p + 1 + ln].decode('ascii', 'replace'))
                    p += 1 + ln
            elif etype == 10 and len(data) >= 2:
                hello['groups'] = _u16list(data[2:2 + struct.unpack('>H', data[:2])[0]])
            elif etype == 11 and data:
                hello['point_formats'] = list(data[1:1 + data[0]])
            elif etype == 13 and len(data) >= 2:
                hello['sig_algs'] = _u16list(data[2:2 + struct.unpack('>H', data[:2])[0]])
            elif etype == 43 and data:
                hello['supported_versions'] = _u16list(data[1:1 + data[0]])
        except (IndexError, struct.error):
            continue
    return hello


def ja3(hello):
    def j(values):
        return '-'.join(str(v) for v in values if not is_grease(v))
    text = ','.join([str(hello['legacy_version']), j(hello['ciphers']), j(hello['extensions']),
                     j(hello['groups']), j(hello['point_formats'])])
    return text, hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


def _ja4_alpn(alpn):
    if not alpn or not alpn[0]:
        return '00'
    value = alpn[0]
    first, last = value[0], value[-1]
    if first.isascii() and first.isalnum() and last.isascii() and last.isalnum():
        return first + last
    hexed = value.encode('latin-1', 'replace').hex()
    return hexed[0] + hexed[-1]


def ja4(hello, transport='t'):
    """Empreinte JA4 (specification publique FoxIO : JA4_a _ JA4_b _ JA4_c)."""
    versions = [v for v in hello['supported_versions'] if not is_grease(v)]
    version = max(versions) if versions else hello['legacy_version']
    ciphers = [c for c in hello['ciphers'] if not is_grease(c)]
    exts = [e for e in hello['extensions'] if not is_grease(e)]
    part_a = (transport + _JA4_VERSIONS.get(version, '00') + ('d' if hello['sni'] else 'i')
              + f'{min(len(ciphers), 99):02d}' + f'{min(len(exts), 99):02d}' + _ja4_alpn(hello['alpn']))

    def h12(text):
        return hashlib.sha256(text.encode()).hexdigest()[:12]
    part_b = h12(','.join(f'{c:04x}' for c in sorted(ciphers))) if ciphers else '000000000000'
    ext_sorted = sorted(e for e in exts if e not in (0x0000, 0x0010))
    c_text = ','.join(f'{e:04x}' for e in ext_sorted)
    sig = [s for s in hello['sig_algs'] if not is_grease(s)]
    if sig:
        c_text += '_' + ','.join(f'{s:04x}' for s in sig)
    part_c = h12(c_text) if ext_sorted or sig else '000000000000'
    raw = f"{part_a}_{','.join(f'{c:04x}' for c in sorted(ciphers))}_{c_text}"
    return f'{part_a}_{part_b}_{part_c}', raw


def parse_server_hello(body):
    version = struct.unpack('>H', body[0:2])[0]
    pos = 34
    sid = body[pos]
    pos += 1 + sid
    cipher = struct.unpack('>H', body[pos:pos + 2])[0]
    pos += 3
    exts = _extensions(body, pos)
    selected = version
    alpn = None
    for etype, data in exts:
        if etype == 43 and len(data) >= 2:
            selected = struct.unpack('>H', data[:2])[0]
        elif etype == 16 and len(data) >= 3:
            alpn = data[3:3 + data[2]].decode('ascii', 'replace')
    ext_ids = [e for e, _ in exts]
    text = f"{version},{cipher},{'-'.join(str(e) for e in ext_ids if not is_grease(e))}"
    return {'legacy_version': version, 'version': TLS_VERSIONS.get(selected, hex(selected)),
            'cipher': cipher, 'cipher_name': CIPHER_NAMES.get(cipher, f'0x{cipher:04x}'),
            'extensions': ext_ids, 'alpn': alpn, 'ja3s': text,
            'ja3s_hash': hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()}


# --- DER minimal pour les sujets / emetteurs de certificats -----------------

_OIDS = {'2.5.4.3': 'CN', '2.5.4.6': 'C', '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.10': 'O',
         '2.5.4.11': 'OU', '1.2.840.113549.1.9.1': 'emailAddress'}


def _der(data, pos):
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise ValueError('longueur DER non supportee')
        length = int.from_bytes(data[pos:pos + n], 'big')
        pos += n
    if pos + length > len(data):
        raise ValueError('DER tronque')
    return tag, pos, pos + length


def _children(data, start, end):
    out, pos = [], start
    while pos < end:
        tag, s, e = _der(data, pos)
        out.append((tag, s, e))
        pos = e
    return out


def _oid(b):
    first = b[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for x in b[1:]:
        val = (val << 7) | (x & 0x7F)
        if not x & 0x80:
            parts.append(str(val))
            val = 0
    return '.'.join(parts)


def _name(data, start, end):
    parts = []
    for _t, s, e in _children(data, start, end):  # SET
        for _t2, s2, e2 in _children(data, s, e):  # SEQUENCE {oid, valeur}
            kids = _children(data, s2, e2)
            if len(kids) >= 2:
                oid = _oid(data[kids[0][1]:kids[0][2]])
                value = data[kids[1][1]:kids[1][2]].decode('utf-8', 'replace')
                parts.append(f'{_OIDS.get(oid, oid)}={value}')
    return ', '.join(parts)


def _time(data, tag, s, e):
    text = data[s:e].decode('ascii', 'replace')
    if tag == 0x17 and len(text) >= 12:  # UTCTime AAMMJJhhmmssZ
        year = int(text[:2])
        year += 2000 if year < 50 else 1900
        return f'{year}-{text[2:4]}-{text[4:6]}T{text[6:8]}:{text[8:10]}:{text[10:12]}Z'
    if tag == 0x18 and len(text) >= 14:
        return f'{text[:4]}-{text[4:6]}-{text[6:8]}T{text[8:10]}:{text[10:12]}:{text[12:14]}Z'
    return text


def parse_certificate(der):
    """Sujet, emetteur, validite et empreinte SHA-256 d'un certificat X.509 DER."""
    info = {'sha256': hashlib.sha256(der).hexdigest(), 'size': len(der)}
    try:
        _t, s, e = _der(der, 0)
        _t, ts, te = _der(der, s)  # tbsCertificate
        kids = _children(der, ts, te)
        idx = 1 if kids and kids[0][0] == 0xA0 else 0
        serial = kids[idx]
        issuer, validity, subject = kids[idx + 2], kids[idx + 3], kids[idx + 4]
        info['serial'] = der[serial[1]:serial[2]].hex()
        info['issuer'] = _name(der, issuer[1], issuer[2])
        info['subject'] = _name(der, subject[1], subject[2])
        times = _children(der, validity[1], validity[2])
        if len(times) == 2:
            info['not_before'] = _time(der, *times[0])
            info['not_after'] = _time(der, *times[1])
        info['self_signed'] = bool(info['subject']) and info['subject'] == info['issuer']
    except (ValueError, IndexError):
        info['error'] = 'certificat non decodable'
    return info


def parse_certificates(body):
    certs = []
    try:
        total = int.from_bytes(body[0:3], 'big')
        pos, end = 3, min(len(body), 3 + total)
        while pos + 3 <= end and len(certs) < 10:
            ln = int.from_bytes(body[pos:pos + 3], 'big')
            certs.append(parse_certificate(body[pos + 3:pos + 3 + ln]))
            pos += 3 + ln
    except (IndexError, ValueError):
        pass
    return certs


def parse_tls(client_data, server_data):
    """Poignee de main TLS d'une connexion -> dict (ou None si pas TLS)."""
    out = {}
    for htype, body in tls_handshakes(client_data):
        if htype == 1 and 'client_hello' not in out:
            try:
                hello = parse_client_hello(body)
            except (IndexError, struct.error):
                continue
            text, digest = ja3(hello)
            j4, j4raw = ja4(hello)
            out['client_hello'] = hello
            out.update({'sni': hello['sni'], 'alpn': hello['alpn'], 'ja3': text, 'ja3_hash': digest,
                        'ja4': j4, 'ja4_raw': j4raw,
                        'client_version': TLS_VERSIONS.get(hello['legacy_version'],
                                                           hex(hello['legacy_version']))})
    if server_data:
        for htype, body in tls_handshakes(server_data):
            try:
                if htype == 2 and 'server_hello' not in out:
                    out['server_hello'] = parse_server_hello(body)
                elif htype == 11 and 'certificates' not in out:
                    out['certificates'] = parse_certificates(body)
            except (IndexError, struct.error):
                continue
    return out or None


def looks_tls(data):
    return len(data) >= 6 and data[0] == 0x16 and data[1] == 3 and data[2] <= 4 and data[5] in (1, 2)


# ============================================================================
# FTP
# ============================================================================

def parse_ftp(client):
    """Commandes FTP du client : [(offset, commande, argument)]."""
    out, pos = [], 0
    data = bytes(client.data[:1 << 16])
    for raw in data.split(b'\r\n'):
        line = raw.decode('latin-1').strip()
        if line:
            cmd, _, arg = line.partition(' ')
            if cmd.isalpha() and len(cmd) <= 5:
                out.append((pos, cmd.upper(), arg))
        pos += len(raw) + 2
        if len(out) > 2000:
            break
    return out
