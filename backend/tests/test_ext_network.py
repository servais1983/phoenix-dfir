"""Extension reseau (ext/network.py) : lecture pcap / pcapng, reassemblage TCP,
dissecteurs DNS / HTTP / TLS, detections, carving et references citables."""

import base64
import hashlib
import json
import os
import struct
import time

import pytest


from phoenix_dfir_mcp import evidence_db, pathpolicy, toolkit  # noqa: E402
from phoenix_dfir_mcp.ext import _net_pcap as net_pcap  # noqa: E402
from phoenix_dfir_mcp.ext import _net_proto as net_proto  # noqa: E402
from phoenix_dfir_mcp.ext import network  # noqa: E402

import build_network_ad_cases as B  # noqa: E402

T0 = 1760256000.0  # 2025-10-12T08:00:00Z


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    network.clear_cache()
    for name in network.INDEXED:  # robustesse si le mecanisme d'extensions n'a pas fusionne
        if name not in toolkit.INDEXED_TOOLS:
            monkeypatch.setattr(toolkit, 'INDEXED_TOOLS', toolkit.INDEXED_TOOLS + (name,))
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


def _write(path, writer):
    writer.write(str(path))
    return str(path)


def _dns_pkt(name='www.example.org', src='10.0.0.5', dst='10.0.0.1'):
    return B.udp(src, dst, 5354, 53, B.dns_query(1, name))


# ============================================================================
# Formats de capture
# ============================================================================

@pytest.mark.parametrize('endian,nano', [('<', False), ('>', False), ('<', True), ('>', True)])
def test_pcap_classique_endianness_et_resolution(tmp_path, endian, nano):
    frame = B.ether(_dns_pkt())
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    frac = 123456789 if nano else 123456
    data = struct.pack(endian + 'IHHiIII', magic, 2, 4, 0, 0, 65535, 1)
    data += struct.pack(endian + 'IIII', int(T0), frac, len(frame), len(frame)) + frame
    path = tmp_path / 'c.pcap'
    path.write_bytes(data)
    assert net_pcap.sniff(str(path)) == 'pcap'
    cap = net_pcap.read_capture(str(path))
    assert cap.packets == 1 and cap.meta['format'] == 'pcap'
    assert abs(cap.first_ts - (T0 + (0.123456789 if nano else 0.123456))) < 1e-6
    assert cap.meta['ts_resolution'] == ('ns' if nano else 'us')
    a = network.Analysis(cap)
    assert a.dns and a.dns[0]['qname'] == 'www.example.org'


def _block(btype, body, endian='<'):
    body += b'\x00' * (-len(body) % 4)
    total = 12 + len(body)
    return struct.pack(endian + 'II', btype, total) + body + struct.pack(endian + 'I', total)


@pytest.mark.parametrize('endian', ['<', '>'])
def test_pcapng_shb_idb_epb_spb(tmp_path, endian):
    frame = B.ether(_dns_pkt('pcapng.example.org'))
    shb = struct.pack(endian + 'IHHq', 0x1A2B3C4D, 1, 0, -1)
    shb_block = b'\x0a\x0d\x0d\x0a' + struct.pack(endian + 'I', 28) + shb + struct.pack(endian + 'I', 28)
    opts = struct.pack(endian + 'HH', 9, 1) + b'\x09\x00\x00\x00' + struct.pack(endian + 'HH', 0, 0)
    idb = _block(1, struct.pack(endian + 'HHI', 1, 0, 65535) + opts, endian)
    ts = int(T0 * 1e9)
    epb = _block(6, struct.pack(endian + 'IIIII', 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame, endian)
    spb = _block(3, struct.pack(endian + 'I', len(frame)) + frame, endian)
    path = tmp_path / 'c.pcapng'
    path.write_bytes(shb_block + idb + epb + spb)
    assert net_pcap.sniff(str(path)) == 'pcapng'
    cap = net_pcap.read_capture(str(path))
    assert cap.packets == 2 and cap.meta['format'] == 'pcapng'
    assert abs(cap.first_ts - T0) < 1e-3
    a = network.Analysis(cap)
    assert [d['qname'] for d in a.dns] == ['pcapng.example.org'] * 2


def test_liaisons_sll_ip_brut_et_ipv6(tmp_path):
    ip_pkt = _dns_pkt('sll.example.org')
    sll = struct.pack('>HHH8sH', 0, 1, 6, b'\x02' * 8, 0x0800) + ip_pkt
    for linktype, data in ((113, sll), (101, ip_pkt)):
        pkt = net_pcap.decode(1, T0, linktype, data, len(data))
        assert pkt.proto == 'UDP' and pkt.dport == 53 and pkt.src == '10.0.0.5'
    # IPv6 + TCP
    tcp_seg = struct.pack('>HHIIBBHHH', 50000, 443, 1, 0, 5 << 4, 0x02, 1024, 0, 0)
    ip6 = (struct.pack('>IHBB', 6 << 28, len(tcp_seg), 6, 64) + bytes.fromhex('20010db8' + '0' * 23 + '1')
           + bytes.fromhex('2a00' + '0' * 27 + '2') + tcp_seg)
    pkt = net_pcap.decode(1, T0, 1, b'\x00' * 12 + b'\x86\xdd' + ip6, 54 + len(tcp_seg))
    assert pkt.l3 == 'IPv6' and pkt.proto == 'TCP' and pkt.src == '2001:db8::1' and pkt.dport == 443


def test_fichier_non_capture_refuse(tmp_path):
    p = tmp_path / 'x.pcap'
    p.write_text('pas une capture')
    assert 'error' in toolkit.run_tool('net_pcap_summary', {'file_path': str(p)})


# ============================================================================
# Reassemblage TCP et plafonds
# ============================================================================

def test_reassemblage_hors_ordre_et_retransmission(tmp_path):
    req = B.http_request('GET', 'site.example.org', '/a/b?c=1', B.BROWSER_UA)
    c, s = '10.0.0.5', '93.184.216.34'
    w = B.PcapWriter()
    w.add(T0, B.ether(B.tcp(c, s, 40000, 80, 100, 0, B.SYN)))
    w.add(T0 + .01, B.ether(B.tcp(s, c, 80, 40000, 900, 101, B.SYN | B.ACK)))
    parts = [req[:20], req[20:50], req[50:]]
    offs = [0, 20, 50]
    # ordre : 2e segment, 3e, 1er, puis retransmission du 2e
    for t, i in ((.02, 1), (.03, 2), (.04, 0), (.05, 1)):
        w.add(T0 + t, B.ether(B.tcp(c, s, 40000, 80, 101 + offs[i], 901, B.PSH | B.ACK, parts[i])))
    resp = B.http_response(200, b'hello', 'text/plain')
    w.add(T0 + .06, B.ether(B.tcp(s, c, 80, 40000, 901, 101 + len(req), B.PSH | B.ACK, resp)))
    path = _write(tmp_path / 'r.pcap', w)
    a = network.analyze(path)
    flow = a.cap.flows[0]
    assert bytes(flow.c2s.data[:len(req)]) == req
    assert len(a.http) == 1 and a.http[0]['uri'] == '/a/b?c=1' and a.http[0]['status'] == 200
    assert a.http[0]['frame'] == 5  # le paquet portant l'octet 0 de la requete


def test_plafonds_paquets_et_flux(tmp_path, monkeypatch):
    big = b'POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 400000\r\n\r\n' + b'A' * 400000
    w = B.PcapWriter()
    B.tcp_session(w, T0, '10.0.0.5', 40001, '45.1.2.3', 80, [(big, b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')])
    path = _write(tmp_path / 'big.pcap', w)
    cap = net_pcap.read_capture(path, max_stream_bytes=10000)
    assert len(cap.flows[0].c2s.data) == 10000 and cap.flows[0].c2s.truncated
    cap = net_pcap.read_capture(path, max_packets=10)
    assert cap.packets == 10 and cap.truncated
    monkeypatch.setenv('PHOENIX_PCAP_MAX_PACKETS', '7')
    assert net_pcap.read_capture(path).packets == 7


def test_capture_volumineuse_sans_blocage(tmp_path):
    w = B.PcapWriter()
    frame = B.ether(B.udp('10.0.0.5', '10.0.0.9', 1000, 2000, b'x' * 50))
    for i in range(20000):
        w.add(T0 + i * 0.001, frame)
    path = _write(tmp_path / 'many.pcap', w)
    start = time.time()
    r = toolkit.run_tool('net_pcap_summary', {'file_path': path, 'max_packets': 5000})
    assert time.time() - start < 20
    assert r['capture']['packets'] == 5000 and r['capture']['truncated']


# ============================================================================
# TLS : JA3 (vecteur de reference), JA4, certificats
# ============================================================================

def _hello_body(record):
    return net_proto.tls_handshakes(record)[0][1]


def test_ja3_vecteur_de_reference():
    rec = B.client_hello(sni='example.com', ciphers=(47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4),
                         groups=(23, 24, 25), point_formats=(0,), alpn=None, sig_algs=None, version=0x0301)
    hello = net_proto.parse_client_hello(_hello_body(rec))
    text, digest = net_proto.ja3(hello)
    assert text == '769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0'
    assert digest == 'ada70206e40642a3e4461f35503241d5'


def test_ja4_et_grease():
    rec = B.client_hello(sni=None, ciphers=(0x0a0a, 0x1301, 0x1302, 0xc02b), groups=(0x1a1a, 29, 23),
                         alpn=('h2',), sig_algs=(0x0403, 0x0804), versions=(0x2a2a, 0x0304, 0x0303),
                         extra_exts=(0x3a3a, 23))
    hello = net_proto.parse_client_hello(_hello_body(rec))
    ja4, raw = net_proto.ja4(hello)
    # 3 suites (GREASE exclu), 7 extensions (GREASE exclu) : 23, 10, 11, 13, 16, 43 ... sans SNI
    exts = [e for e in hello['extensions'] if not net_proto.is_grease(e)]
    assert ja4.startswith(f't13i03{len(exts):02d}h2_')
    assert ja4.split('_')[1] == hashlib.sha256(b'1301,1302,c02b').hexdigest()[:12]
    c_text = ','.join(f'{e:04x}' for e in sorted(e for e in exts if e not in (0, 16))) + '_0403,0804'
    assert ja4.split('_')[2] == hashlib.sha256(c_text.encode()).hexdigest()[:12]
    assert raw.endswith(c_text)
    assert '2a2a' not in raw and '0a0a' not in raw


def test_certificat_et_serverhello(tmp_path):
    w = B.PcapWriter()
    cert = B.fake_certificate('evil.example.net', 'evil.example.net')
    B.tls_session(w, T0, '10.0.0.5', 41000, '91.200.1.1', 'evil.example.net', cert, b'a' * 50, b'b' * 50)
    r = toolkit.run_tool('net_tls', {'file_path': _write(tmp_path / 't.pcap', w)})
    hs = r['tls'][0]
    assert hs['sni'] == 'evil.example.net' and hs['cipher'] == 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
    assert hs['certificates'][0]['subject'] == 'CN=evil.example.net' and hs['certificates'][0]['self_signed']
    assert hs['ja3_hash'] and hs['ja4'].startswith('t12d') and hs['ja3s_hash'] and hs['row'] == 4


# ============================================================================
# Detections : positifs et negatif benin
# ============================================================================

def _benign(w, rnd_seed=3):
    import random
    rnd = random.Random(rnd_seed)
    t = T0
    for i in range(10):
        B.dns_exchange(w, t, '10.0.0.5', '10.0.0.1', 10 + i, 'www.wikipedia.org', answers=('185.15.59.224',),
                       sport=30000 + i)
        B.tcp_session(w, t + .1, '10.0.0.5', 33000 + i, '185.15.59.224', 80,
                      [(B.http_request('GET', 'www.wikipedia.org', f'/wiki/Page{i}', B.BROWSER_UA),
                        B.http_response(200, b'<html>' + b'x' * rnd.randrange(500, 5000) + b'</html>'))],
                      isn=(rnd.randrange(1 << 30), rnd.randrange(1 << 30)))
        t += rnd.choice((7, 30, 95, 180, 3, 400))


def test_negatif_benin_aucune_detection(tmp_path):
    w = B.PcapWriter()
    _benign(w)
    r = toolkit.run_tool('net_detect', {'file_path': _write(tmp_path / 'ok.pcap', w)})
    assert r['total_findings'] == 0, r['findings']


def test_beaconing_et_ja3(tmp_path):
    path = B.build_c2_beacon(str(tmp_path))
    r = toolkit.run_tool('net_detect', {'file_path': path})
    beacon = [f for f in r['findings'] if f['type'] == 'beaconing']
    assert len(beacon) == 1
    b = beacon[0]
    assert b['dst'] == B.C2_IP and 'T1071.001' in b['mitre'] and abs(b['interval_s'] - 60) < 1
    assert b['ja3_hash'] == B._beacon_ja3() and b['sni'] == B.C2_DOMAIN
    assert len(b['connections']) == 24
    assert not [f for f in r['findings'] if f['type'] in ('exfiltration', 'dns_tunneling')]


def test_tunnel_dns(tmp_path):
    path = B.build_dns_tunnel(str(tmp_path))
    r = toolkit.run_tool('net_detect', {'file_path': path})
    tun = [f for f in r['findings'] if f['type'] == 'dns_tunneling']
    assert len(tun) == 1 and tun[0]['domain'] == B.TUNNEL_DOMAIN
    assert {'T1071.004', 'T1572', 'T1048'} <= set(tun[0]['mitre'])
    d = toolkit.run_tool('net_dns', {'file_path': path})
    assert d['rcodes']['NXDOMAIN'] == 1 and d['suspicious']['tunneling'][0]['domain'] == B.TUNNEL_DOMAIN
    assert d['suspicious']['long_or_high_entropy']


def test_dga(tmp_path):
    w = B.PcapWriter()
    for i, name in enumerate(['xkqzvbtrpwml.com', 'qzhvxkrtpbnw.net', 'vbnqzxtkrwpl.org', 'tkzqxvrbpnml.info',
                              'pqxzvkrtbwnl.biz', 'zxqvkbtrpmwl.com']):
        B.dns_exchange(w, T0 + i, '10.0.0.7', '10.0.0.1', 50 + i, name, rcode=3, sport=31000 + i)
    r = toolkit.run_tool('net_detect', {'file_path': _write(tmp_path / 'dga.pcap', w)})
    assert [f['mitre'] for f in r['findings'] if f['type'] == 'dga'] == [['T1568.002']]


def test_exfiltration_archive_et_carving(tmp_path):
    case = tmp_path / 'cas'
    case.mkdir()
    path, sha = B.build_http_exfil(str(case))
    toolkit.set_active_case(str(case))
    r = toolkit.run_tool('net_detect', {'file_path': path})
    types = {f['type']: f for f in r['findings']}
    assert types['archive_upload']['filename'] == B.EXFIL_NAME and 'T1048.003' in types['archive_upload']['mitre']
    assert types['exfiltration']['dst'] == B.EXFIL_IP and types['exfiltration']['bytes_out'] > 60000
    assert 'PowerShell' in types['suspicious_user_agent']['title']
    h = toolkit.run_tool('net_http', {'file_path': path, 'carve': True})
    carving = h['carving']
    assert carving['carved_count'] == 1
    entry = carving['carved'][0]
    assert entry['original_name'] == B.EXFIL_NAME and entry['sha256'] == sha and entry['magic'] == 'zip'
    carved = case / entry['path']
    assert hashlib.sha256(carved.read_bytes()).hexdigest() == sha
    manifest = json.loads((case / carving['manifest']).read_text())
    assert manifest['files'][0]['sha256'] == sha and manifest['source_sha256']
    # Le manifeste n'est pas un artefact ; l'archive extraite en est un
    arts = [os.path.relpath(p, case) for p in toolkit.case_artifacts(str(case))]
    assert any(a.endswith(B.EXFIL_NAME) for a in arts) and not any('manifest' in a for a in arts)
    # Plafond de taille
    h2 = toolkit.run_tool('net_http', {'file_path': path, 'carve': True, 'max_carve_mb': 1})
    assert h2['carving']['carved'][0]['truncated'] is False


def test_carving_tronque_au_plafond(tmp_path):
    case = tmp_path / 'cas'
    case.mkdir()
    w = B.PcapWriter()
    body = b'Z' * (1200 << 10)
    B.tcp_session(w, T0, '10.0.0.5', 40300, '91.1.1.1', 80,
                  [(B.http_request('PUT', 'up.example.net', '/files/dump.bin', 'curl/8.4.0', body,
                                   'application/octet-stream'), B.http_response(201))])
    path = _write(case / 'put.pcap', w)
    r = network.carve(network.analyze(path), path, case_dir=str(case), max_carve_mb=1)
    entry = r['carved'][0]
    assert entry['size'] == 1 << 20 and entry['truncated'] and entry['original_name'] == 'dump.bin'


def test_identifiants_en_clair_http_et_ftp(tmp_path):
    w = B.PcapWriter()
    auth = base64.b64encode(b'admin:S3cret!').decode()
    B.tcp_session(w, T0, '10.0.0.5', 40100, '10.0.0.80', 80,
                  [(B.http_request('GET', 'nas.local', '/admin', B.BROWSER_UA, extra=[f'Authorization: Basic {auth}']),
                    B.http_response(200, b'ok'))])
    B.tcp_session(w, T0 + 5, '10.0.0.5', 40101, '10.0.0.21', 21,
                  [(b'', b'220 FTP pret\r\n'), (b'USER backup\r\n', b'331 ok\r\n'), (b'PASS Hunter2\r\n', b'230 ok\r\n')])
    r = toolkit.run_tool('net_detect', {'file_path': _write(tmp_path / 'creds.pcap', w)})
    creds = [f for f in r['findings'] if f['type'] == 'cleartext_credentials']
    assert {c['protocol'] for c in creds} == {'HTTP Basic', 'FTP'}
    assert {c['user'] for c in creds} == {'admin', 'backup'}
    assert all('T1552' in c['mitre'] for c in creds)
    assert 'S3cret' not in json.dumps(r) and 'Hunter2' not in json.dumps(r)


def test_port_non_standard_et_executable(tmp_path):
    w = B.PcapWriter()
    B.tcp_session(w, T0, '10.0.0.5', 40200, '91.10.20.30', 4444, [(b'\x00\x01hello', b'\x00\x02world')])
    B.tcp_session(w, T0 + 3, '10.0.0.5', 40201, '91.10.20.31', 80,
                  [(B.http_request('GET', 'dl.example.net', '/tools/run.exe', 'curl/8.4.0'),
                    B.http_response(200, b'MZ' + b'\x90' * 300, 'application/octet-stream'))])
    r = toolkit.run_tool('net_detect', {'file_path': _write(tmp_path / 'ports.pcap', w)})
    by = {f['type']: f for f in r['findings']}
    assert by['non_standard_port']['dst_port'] == 4444 and by['non_standard_port']['mitre'] == ['T1571']
    assert by['tool_transfer']['mitre'] == ['T1105']
    assert 'curl' in by['suspicious_user_agent']['title']


# ============================================================================
# Indexation et references citables
# ============================================================================

def test_sorties_indexees_et_references_valides(tmp_path):
    case = tmp_path / 'cas'
    case.mkdir()
    path = B.build_c2_beacon(str(case))
    toolkit.set_active_case(str(case))
    for name in network.TOOL_NAMES:
        r = toolkit.run_tool(name, {'file_path': path})
        assert not r.get('error'), (name, r)
        assert r.get('indexed_events', 0) >= (0 if name == 'net_http' else 1), name
    det = toolkit.run_tool('net_detect', {'file_path': path})
    beacon = next(f for f in det['findings'] if f['type'] == 'beaconing')
    refs = [{'artifact': os.path.basename(path), 'kind': 'row', 'value': c['row']} for c in beacon['connections'][:3]]
    ok, bad = toolkit.validate_refs(refs, str(case))
    assert len(ok) == 3 and not bad
    _ok, bad = toolkit.validate_refs([{'artifact': os.path.basename(path), 'kind': 'row', 'value': 999999}], str(case))
    assert bad
    hits = evidence_db.search(str(case), B.C2_DOMAIN)
    assert hits['total_matches'] >= 1 and hits['events'][0]['ref']['kind'] == 'row'
    tl = evidence_db.timeline(str(case), contains='Beaconing')
    assert tl['events'] and tl['events'][0]['ts'].startswith('2026-10-12')
    assert toolkit.compute_tool_coverage(str(case))['gaps'] == []


def test_declarations_extension():
    assert network.AGENT == ('network', 'Agent Reseau & Desobfuscation')
    assert set(network.INDEXED) == set(network.TOOL_NAMES)
    assert 'net_http' not in network.READONLY
    assert {'.pcap', '.pcapng', '.cap'} <= set(network.KNOWN_TYPES)
    assert network.applicable('x.pcapng')[1] == ('detection reseau', ('net_detect',))
    assert network.applicable('x.evtx') is None
    for name in network.TOOL_NAMES:
        assert name in toolkit.TOOLS


def test_detection_par_octets_magiques(tmp_path):
    w = B.PcapWriter()
    w.add(T0, B.ether(_dns_pkt()))
    p = _write(tmp_path / 'capture_sans_extension', w)
    assert network.applicable(p) is not None
    (tmp_path / 'notes.bin').write_bytes(b'texte quelconque')
    assert network.applicable(str(tmp_path / 'notes.bin')) is None
