"""Desobfuscation statique multi-couches (scripts PowerShell, JS, VBA, batch...).

Decodage automatique, couche par couche, avec trace de recette (chaque
operation appliquee, dans l'ordre) : base64 (dont UTF-16LE de PowerShell
-EncodedCommand), hexadecimal, URL / pourcent, entites HTML, gzip / deflate /
zlib (motifs IO.Compression), codes de caracteres ([char]0x41,
String.fromCharCode, chr()), inversion de chaine, concatenation et operateur
de format ('a'+'b', "{1}{0}" -f), suppression des backticks, XOR mono-octet
(force brute avec score ASCII / anglais) et ROT13.

STATIQUE UNIQUEMENT : rien n'est jamais execute ni emule. Les entrees, la
profondeur et les sorties sont plafonnees ; toutes les expressions regulieres
sont bornees (pas de retour arriere catastrophique).
"""

import base64
import binascii
import codecs
import csv
import hashlib
import html
import io
import os
import re
import time
import urllib.parse
import zlib

from .. import toolkit

AGENT = ('network', 'Agent Reseau & Desobfuscation')
TOOL_NAMES = ('deobfuscate_text', 'deobfuscate_artifact')
READONLY = TOOL_NAMES
INDEXED = ('deobfuscate_artifact',)
KNOWN_TYPES = {'.vbs': 'Script VBScript', '.js': 'Script JavaScript', '.hta': 'Application HTML (HTA)',
               '.psm1': 'Module PowerShell', '.cmd': 'Script Batch'}
PHASE_TOOLS = {
    'extraction': TOOL_NAMES,
    'correlation': TOOL_NAMES,
    'contre_analyse': TOOL_NAMES,
}
PHASE_HINTS = {
    'extraction': (
        "- Commandes ou scripts encodes / obfusques (powershell -enc, FromBase64String, [char], "
        "concatenations, -f, XOR...) : deobfuscate_artifact (fichier : lignes suspectes, row/line "
        "citables) ou deobfuscate_text (chaine) revelent la charge, la recette de decodage, les IoCs "
        "(URL de C2...) et les indicateurs (download cradle, contournement AMSI, chargement "
        "reflectif). Analyse statique : rien n'est execute."),
    'correlation': (
        "- Une charge desobfusquee est une preuve : citer la ligne/row de l'artefact source et "
        "rapporter l'URL ou l'IP revelee (IoC) avec ses techniques (T1027, T1059.001, T1620...)."),
}

DEFAULT_MAX_BYTES = 1 << 20
DEFAULT_MAX_DEPTH = 20
MAX_OUTPUT = 20000
TIME_BUDGET_S = 10.0
_SCRIPT_EXT = ('.ps1', '.psm1', '.vbs', '.js', '.jse', '.hta', '.bat', '.cmd', '.wsf')


def _max_bytes():
    try:
        value = int(os.environ.get('PHOENIX_DEOBF_MAX_BYTES', DEFAULT_MAX_BYTES))
    except ValueError:
        return DEFAULT_MAX_BYTES
    return value if value > 0 else DEFAULT_MAX_BYTES


# ============================================================================
# Scores et utilitaires
# ============================================================================

_KEYWORDS = ('http', 'powershell', 'invoke', 'iex', 'new-object', 'webclient', 'download',
             'function', 'cmd.exe', 'system.', 'frombase64', 'eval(', 'wscript', 'createobject',
             'shell', 'exec', '.exe', 'reflection', 'amsi', 'string', 'object', 'return',
             'document', 'write', 'the ', ' and ', 'var ', '$env', 'start-process')
_STRONG = ('http', 'powershell', 'invoke', 'iex', 'new-object', 'webclient', 'downloadstring',
           'frombase64string', 'cmd.exe', '.exe', 'function', 'wscript', 'createobject', 'eval(')


def _hits(text, words=_KEYWORDS):
    low = text.lower()
    return sum(1 for w in words if w in low)


def _printable(data):
    if not data:
        return 0.0
    ok = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return ok / len(data)


def _bytes_to_text(data):
    """Octets -> texte lisible (UTF-16LE de PowerShell ou UTF-8), sinon None."""
    if len(data) >= 4 and len(data) % 2 == 0:
        odd = data[1::2]
        if sum(1 for b in odd if b == 0) >= 0.8 * len(odd):
            try:
                text = data.decode('utf-16-le')
            except UnicodeDecodeError:
                text = None
            if text and _printable(text.encode('latin-1', 'replace')) >= 0.9:
                return text, 'utf-16le'
    if _printable(data) >= 0.9:
        return data.decode('utf-8', 'replace'), 'utf-8'
    return None


def _xor_score(data):
    p = _printable(data)
    if p < 0.95:
        return p
    spaces = data.count(b' ') / max(1, len(data))
    text = data.decode('latin-1')
    return p + min(spaces, 0.2) + 0.3 * min(_hits(text), 5)


def _xor_bruteforce(data, hinted=None):
    """XOR mono-octet : (cle, clair) du meilleur candidat lisible, ou None."""
    sample = data[:4096]
    keys = ([hinted] if hinted else []) + [k for k in range(1, 256) if k != hinted]
    best = None
    for key in keys:
        score = _xor_score(bytes(b ^ key for b in sample))
        if best is None or score > best[0]:
            best = (score, key)
        if key == hinted and score >= 1.0:
            break
    if best and best[0] >= 1.1:
        key = best[1]
        return key, bytes(b ^ key for b in data)
    return None


_MAGIC = ((b'MZ', 'pe'), (b'\x7fELF', 'elf'), (b'PK\x03\x04', 'zip'), (b'%PDF', 'pdf'),
          (b'\xd0\xcf\x11\xe0', 'ole'))


def _magic(data):
    return next((name for sig, name in _MAGIC if data[:len(sig)] == sig), None)


def _quote(text):
    if "'" not in text:
        return "'" + text + "'"
    if '"' not in text:
        return '"' + text + '"'
    return "'" + text.replace("'", "''") + "'"


# ============================================================================
# Moteur
# ============================================================================

class _Engine:
    def __init__(self, max_depth, cap):
        self.max_depth = max_depth
        self.cap = cap
        self.recipe = []
        self.artifacts = []
        self.layers = []
        self.done = set()
        self.deadline = time.monotonic() + TIME_BUDGET_S

    # --- decodage d'octets (decompression, texte, XOR) ---------------------
    def decode_bytes(self, data, ctx, ops, depth=0):
        if depth > 4 or not data:
            return None
        if data[:2] == b'\x1f\x8b':
            out = self._inflate(data, 31)
            if out is not None:
                ops.append(('gzip', f'{len(data)} -> {len(out)} octets'))
                return self.decode_bytes(out, ctx, ops, depth + 1)
        if len(data) > 2 and data[0] == 0x78 and ((data[0] << 8) | data[1]) % 31 == 0:
            out = self._inflate(data, 15)
            if out is not None:
                ops.append(('zlib', f'{len(data)} -> {len(out)} octets'))
                return self.decode_bytes(out, ctx, ops, depth + 1)
        text = _bytes_to_text(data)
        if text:
            if text[1] == 'utf-16le':
                ops.append(('utf-16le', 'texte UTF-16LE (PowerShell -EncodedCommand)'))
            return text[0]
        if 'deflate' in ctx.lower():
            out = self._inflate(data, -15)
            if out is not None and out:
                ops.append(('deflate', f'{len(data)} -> {len(out)} octets (DeflateStream)'))
                return self.decode_bytes(out, ctx, ops, depth + 1)
        kind = _magic(data)
        if kind:
            self._artifact(data, kind)
            return None
        m = re.search(r'-bxor\s*(0x[0-9a-fA-F]{1,2}|\d{1,3})\b', ctx)
        hinted = int(m.group(1), 0) if m else None
        if hinted is not None and not 0 < hinted < 256:
            hinted = None
        xor = _xor_bruteforce(data, hinted) if len(data) >= 8 else None
        if xor:
            ops.append(('xor', f'cle mono-octet 0x{xor[0]:02x}' + (' (indiquee par -bxor)' if xor[0] == hinted else '')))
            return self.decode_bytes(xor[1], '', ops, depth + 1)
        self._artifact(data, 'binaire')
        return None

    def _inflate(self, data, wbits):
        try:
            return zlib.decompressobj(wbits).decompress(data, self.cap)
        except zlib.error:
            return None

    def _artifact(self, data, kind):
        digest = hashlib.sha256(data).hexdigest()
        if digest not in {a['sha256'] for a in self.artifacts} and len(self.artifacts) < 50:
            self.artifacts.append({'type': kind, 'size': len(data), 'sha256': digest,
                                   'head_hex': data[:16].hex()})

    # --- transformations textuelles ---------------------------------------
    def run(self, text):
        current = text
        self.layers.append(current)
        steps = 0
        while steps < self.max_depth and time.monotonic() < self.deadline:
            for name, func in _TRANSFORMS:
                out = func(self, current)
                if out is None:
                    continue
                new, entries = out
                if new == current or not entries:
                    continue
                new = new[:self.cap]
                for op, detail in entries:
                    steps += 1
                    self.recipe.append({'step': len(self.recipe) + 1, 'operation': op, 'detail': detail,
                                        'transform': name})
                self.recipe[-1]['output_preview'] = new[:300]
                self.recipe[-1]['output_length'] = len(new)
                current = new
                self.layers.append(current)
                break
            else:
                break
        return current


_LIT = r"'[^'\n]{0,4096}'|\"[^\"\n]{0,4096}\""
_CHAIN_RE = re.compile(rf"(?:{_LIT})(?:\s*[+&]\s*(?:{_LIT}))+")
_PAREN_LIT_RE = re.compile(rf"(?<=[=(,+\s])\(\s*({_LIT})\s*\)")
_FORMAT_RE = re.compile(rf"\(\s*({_LIT})\s*-f\s*((?:{_LIT})(?:\s*,\s*(?:{_LIT})){{0,200}})\s*\)"
                        rf"|({_LIT})\s*-f\s*((?:{_LIT})(?:\s*,\s*(?:{_LIT})){{0,200}})", re.I)
_LIT_ONLY = re.compile(_LIT)
_BACKTICK_RE = re.compile(r'(?<=\w)`(?=[\w-])')
_CHAR_RE = re.compile(r'\[char\]\s*\(?\s*(0x[0-9a-fA-F]{1,6}|\d{1,7})\s*\)?', re.I)
_CHAR_ARRAY_RE = re.compile(r'(?:-join\s*)?\[char\[\]\]\s*@?\(\s*((?:(?:0x[0-9a-fA-F]{1,6}|\d{1,7})\s*,\s*){0,100000}'
                            r'(?:0x[0-9a-fA-F]{1,6}|\d{1,7}))\s*\)(?:\s*-join\s*(?:\'\'|""))?', re.I)
_FROMCC_RE = re.compile(r'String\.fromCharCode\(\s*((?:(?:0x[0-9a-fA-F]{1,6}|\d{1,7})\s*,\s*){0,100000}'
                        r'(?:0x[0-9a-fA-F]{1,6}|\d{1,7}))\s*\)', re.I)
_CHR_RE = re.compile(r'\bchrw?\$?\s*\(\s*(\d{1,7})\s*\)', re.I)
_B64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
_HEX_ESC_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}')
_HEX_LIST_RE = re.compile(r'(?:0x[0-9a-fA-F]{2}\s*,\s*){3,}0x[0-9a-fA-F]{2}')
_HEX_RE = re.compile(r'\b(?:[0-9a-fA-F]{2}){8,}\b')
_PCT_RE = re.compile(r'%(?:[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})')
_ENTITY_RE = re.compile(r'&(?:#x?[0-9a-fA-F]{1,6}|lt|gt|amp|quot|apos);')


def _strip(lit):
    inner = lit[1:-1]
    return inner.replace("''", "'") if lit[0] == "'" else inner


def _t_html(eng, text):
    if len(_ENTITY_RE.findall(text[:200000])) < 2:
        return None
    return html.unescape(text), [('html_entities', 'entites HTML decodees')]


def _t_url(eng, text):
    n = len(_PCT_RE.findall(text[:200000]))
    if n < 3:
        return None
    out = re.sub(r'%u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)
    return urllib.parse.unquote(out), [('url_decode', f'{n} sequences %XX decodees')]


def _t_backtick(eng, text):
    n = len(_BACKTICK_RE.findall(text))
    if not n:
        return None
    return _BACKTICK_RE.sub('', text), [('backtick_removal', f'{n} backticks PowerShell retires')]


def _codes(group):
    out = []
    for tok in re.split(r'\s*,\s*', group.strip()):
        value = int(tok, 0) if tok.lower().startswith('0x') else int(tok)
        if not 0 <= value < 0x110000:
            raise ValueError
        out.append(chr(value))
    return ''.join(out)


def _t_charcode(eng, text):
    count = [0]

    def sub(rx, quote=True):
        def repl(m):
            try:
                value = _codes(m.group(1))
            except ValueError:
                return m.group(0)
            count[0] += 1
            return _quote(value) if quote else value
        return rx.sub(repl, text)
    for rx in (_CHAR_ARRAY_RE, _FROMCC_RE, _CHAR_RE, _CHR_RE):
        text = sub(rx)
    if not count[0]:
        return None
    return text, [('char_codes', f'{count[0]} expression(s) de codes de caracteres resolues')]


def _t_format(eng, text):
    count = [0]

    def repl(m):
        fmt_lit, args_text = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), m.group(4))
        fmt = _strip(fmt_lit)
        if not re.search(r'\{\d+', fmt):
            return m.group(0)
        args = [_strip(a) for a in _LIT_ONLY.findall(args_text)]

        def field(f):
            i = int(f.group(1))
            return args[i] if i < len(args) else f.group(0)
        count[0] += 1
        return _quote(re.sub(r'\{(\d+)(?:[,:][^}]{0,20})?\}', field, fmt))
    out = _FORMAT_RE.sub(repl, text)
    if not count[0]:
        return None
    return out, [('format_operator', f"{count[0]} operateur(s) -f reconstitue(s)")]


def _t_concat(eng, text):
    count = [0]

    def repl(m):
        count[0] += 1
        return _quote(''.join(_strip(x) for x in _LIT_ONLY.findall(m.group(0))))
    out = _CHAIN_RE.sub(repl, text)
    out2 = _PAREN_LIT_RE.sub(lambda m: m.group(1), out)
    if not count[0] and out2 == text:
        return None
    return out2, [('concatenation', f'{count[0]} concatenation(s) de chaines fusionnee(s)')]


def _t_reverse(eng, text):
    count = [0]

    def repl(m):
        lit = m.group(0)
        inner = _strip(lit)
        if len(inner) >= 8 and _hits(inner[::-1], _STRONG) > _hits(inner, _STRONG):
            count[0] += 1
            return _quote(inner[::-1])
        return lit
    out = _LIT_ONLY.sub(repl, text)
    if count[0]:
        return out, [('reverse', f'{count[0]} chaine(s) inversee(s)')]
    if len(text) >= 12 and _hits(text[::-1], _STRONG) >= _hits(text, _STRONG) + 2:
        return text[::-1], [('reverse', 'texte entier inverse')]
    return None


def _t_rot13(eng, text):
    rot = codecs.decode(text, 'rot13')
    if _hits(rot, _STRONG) >= _hits(text, _STRONG) + 2:
        return rot, [('rot13', 'ROT13')]
    return None


def _replace_blob(text, start, end, decoded):
    if end - start >= 0.6 * len(text.strip()):
        return decoded
    return text[:start] + _quote(decoded) + text[end:]


def _t_base64(eng, text):
    cands = sorted(_B64_RE.finditer(text[:eng.cap]), key=lambda m: -len(m.group(0)))[:30]
    for m in cands:
        tok = m.group(0)
        if tok in eng.done or re.fullmatch(r'[0-9a-fA-F]+', tok):
            continue
        eng.done.add(tok)
        body = tok.rstrip('=')
        if len(body) % 4 == 1:
            continue
        try:
            raw = base64.b64decode(body + '=' * (-len(body) % 4))
        except (binascii.Error, ValueError):
            continue
        ops = [('base64', f'{len(tok)} caracteres -> {len(raw)} octets')]
        decoded = eng.decode_bytes(raw, text, ops)
        if decoded is None or len(decoded.strip()) < 4:
            continue
        return _replace_blob(text, m.start(), m.end(), decoded), ops
    return None


def _t_hex(eng, text):
    for rx, clean in ((_HEX_ESC_RE, lambda s: s.replace('\\x', '')),
                      (_HEX_LIST_RE, lambda s: re.sub(r'0x|[\s,]', '', s)),
                      (_HEX_RE, lambda s: s)):
        for m in sorted(rx.finditer(text[:eng.cap]), key=lambda m: -len(m.group(0)))[:20]:
            tok = m.group(0)
            if tok in eng.done:
                continue
            eng.done.add(tok)
            try:
                raw = bytes.fromhex(clean(tok))
            except ValueError:
                continue
            ops = [('hex', f'{len(tok)} caracteres -> {len(raw)} octets')]
            decoded = eng.decode_bytes(raw, text, ops)
            if decoded is None or len(decoded.strip()) < 4:
                continue
            return _replace_blob(text, m.start(), m.end(), decoded), ops
    return None


_TRANSFORMS = (('html', _t_html), ('url', _t_url), ('backtick', _t_backtick),
               ('charcode', _t_charcode), ('format', _t_format), ('concat', _t_concat),
               ('reverse', _t_reverse), ('base64', _t_base64), ('hex', _t_hex), ('rot13', _t_rot13))


# ============================================================================
# Indicateurs et IoCs
# ============================================================================

INDICATORS = (
    ('download_cradle', 'Telechargement (download cradle)', ('T1105',),
     r'DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\birm\b'
     r'|Start-BitsTransfer|Net\.WebClient|bitsadmin\s{1,5}/transfer|certutil.{0,40}-urlcache'
     r'|XMLHTTP|WinHttpRequest'),
    ('dynamic_execution', 'Execution dynamique (IEX / Invoke-Expression)', ('T1059.001',),
     r'\bIEX\b|Invoke-Expression|\biex\s{0,3}\('),
    ('amsi_bypass', 'Contournement AMSI', ('T1562.001',),
     r'AmsiUtils|amsiInitFailed|AmsiScanBuffer|amsi\.dll|AmsiContext'),
    ('etw_bypass', 'Neutralisation ETW', ('T1562.006',), r'EtwEventWrite|PSEtwLogProvider'),
    ('reflective_loading', 'Chargement reflectif en memoire', ('T1620',),
     r'Reflection\.Assembly\]::Load|Assembly\]::Load\s{0,3}\(|\.EntryPoint\.Invoke|VirtualAlloc'
     r'|CreateThread|GetDelegateForFunctionPointer|Marshal\]::Copy|Invoke-ReflectivePEInjection'
     r'|DefineDynamicAssembly'),
    ('hidden_window', 'Fenetre masquee', ('T1564.003',), r'-w(?:indowstyle)?\s{1,5}h(?:idden)?\b'),
    ('policy_bypass', 'Contournement de la politique d\'execution', ('T1059.001',),
     r'-ep\s{1,5}bypass|-ExecutionPolicy\s{1,5}Bypass|-exec\s{1,5}bypass'),
    ('encoded_command', 'Commande PowerShell encodee', ('T1027', 'T1059.001'),
     r'\s-e(?:nc|ncodedcommand|c)?\s{1,5}[A-Za-z0-9+/=]{20,}'),
    ('in_memory_decompression', 'Decompression en memoire (IO.Compression)', ('T1027',),
     r'IO\.Compression|GzipStream|DeflateStream'),
    ('credential_theft', 'Vol d\'identifiants (Mimikatz)', ('T1003.001',),
     r'sekurlsa|Invoke-Mimikatz|lsadump::'),
)
_INDICATOR_RX = [(k, n, m, re.compile(rx, re.I)) for k, n, m, rx in INDICATORS]
_URL_RE = re.compile(r'\b(?:https?|ftp)://[^\s\'"<>()`;,]{3,2000}', re.I)
_IP_PORT_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b')


def _indicators(layers):
    found = {}
    for idx, layer in enumerate(layers):
        for key, name, mitre, rx in _INDICATOR_RX:
            if key in found:
                continue
            m = rx.search(layer)
            if m:
                s = max(0, m.start() - 40)
                found[key] = {'indicator': key, 'name': name, 'mitre': list(mitre), 'layer': idx,
                              'match': layer[s:m.end() + 60].replace('\n', ' ')[:200]}
    return list(found.values())


def _iocs(layers):
    text = '\n'.join(layers)[:4 << 20]
    iocs, seen = [], set()
    try:
        extracted = toolkit.parsers.extract_iocs(text)
    except Exception:  # repli sur les expressions regulieres locales
        extracted = []
    for url in _URL_RE.findall(text):
        extracted.append({'type': 'url', 'value': url.rstrip('.)\'"')})
    for ipp in _IP_PORT_RE.findall(text):
        extracted.append({'type': 'ip_port', 'value': ipp})
    for ioc in extracted:
        value = ioc['value'].rstrip(').;,\'"') if ioc['type'] == 'url' else ioc['value']
        key = (ioc['type'], value)
        if key not in seen:
            seen.add(key)
            iocs.append({'type': ioc['type'], 'value': value})
    return iocs[:500]


def deobfuscate(text, max_depth=None, max_bytes=None):
    """Desobfusquer un texte ; retourne la recette, le texte final, IoCs et indicateurs."""
    cap = int(max_bytes) if max_bytes and int(max_bytes) > 0 else _max_bytes()
    depth = max(1, min(int(max_depth or DEFAULT_MAX_DEPTH), 100))
    text = text if isinstance(text, str) else str(text)
    truncated = len(text) > cap
    eng = _Engine(depth, cap)
    final = eng.run(text[:cap])
    indicators = _indicators(eng.layers)
    mitre = {t for i in indicators for t in i['mitre']}
    if eng.recipe:
        mitre.update(('T1027', 'T1140'))
    return {
        'input_length': len(text), 'truncated_input': truncated, 'layers': len(eng.recipe),
        'recipe': eng.recipe, 'operations': [r['operation'] for r in eng.recipe],
        'decoded': final[:MAX_OUTPUT], 'decoded_truncated': len(final) > MAX_OUTPUT,
        'iocs': _iocs(eng.layers[1:] if len(eng.layers) > 1 else eng.layers),
        'indicators': indicators, 'embedded_binaries': eng.artifacts,
        'mitre_techniques': sorted(mitre),
        'note': 'Analyse statique : aucun code n\'a ete execute ni emule.',
    }


@toolkit.tool(
    'deobfuscate_text',
    "Desobfusquer STATIQUEMENT une chaine (commande ou script) : decodage multi-couches automatique "
    "(base64 dont PowerShell -EncodedCommand UTF-16LE, hex, URL, entites HTML, gzip/deflate/zlib, "
    "codes de caracteres, inversion, concatenations et -f, backticks, XOR mono-octet, ROT13) avec "
    "trace de recette, IoCs extraits (URL de C2...) et indicateurs (download cradle, contournement "
    "AMSI, chargement reflectif). Rien n'est jamais execute.",
    toolkit._schema({
        'text': {'type': 'string', 'description': 'Texte obfusque'},
        'max_depth': {'type': 'integer', 'description': 'Operations de decodage max (defaut 20)'},
    }, ['text']),
)
def deobfuscate_text(text, max_depth=None):
    if not isinstance(text, str) or not text:
        return {'error': "Fournir 'text' (chaine non vide)"}
    return deobfuscate(text, max_depth)


# ============================================================================
# deobfuscate_artifact : plage d'un fichier ou lignes suspectes
# ============================================================================

_SUSPECT_RE = re.compile(
    r'[A-Za-z0-9+/]{40,}={0,2}|\s-e(?:nc|ncodedcommand|c)?\s{1,5}[A-Za-z0-9+/=]{20,}|FromBase64String'
    r'|\[char\]|fromCharCode|\bchrw?\(|-bxor|[\'"]\s*-f\s*[\'"]|[\'"]\s*\+\s*[\'"]'
    r'|(?:%[0-9a-fA-F]{2}){3}|(?:&#x?[0-9a-fA-F]{1,6};){3}|(?:\\x[0-9a-fA-F]{2}){4}'
    r'|\w`\w|\[array\]::Reverse|StrReverse', re.I)
_ENCODED_COMMAND_RE = re.compile(
    r'\s-e(?:nc|ncodedcommand|c)?\s{1,5}[A-Za-z0-9+/=]{40,}|FromBase64String\s*\(', re.I)
_TIME_COLS = ('timestamp', 'time', 'date', 'createtime', 'utctime', 'timecreated', 'when')


def looks_obfuscated(text):
    return bool(_SUSPECT_RE.search(text or ''))


_EXPORT_PARSERS = {'.csv': 'parse_csv', '.json': 'parse_json_file', '.jsonl': 'parse_json_file',
                   '.log': 'parse_log_file', '.txt': 'parse_log_file'}


def applicable(path):
    """Scripts (.ps1, .js, .vbs, .hta, .bat...) and exports (CSV, JSON, logs: command lines
    of a memory dump, EDR...) visibly obfuscated: parsing + deobfuscation."""
    ext = os.path.splitext(path)[1].lower()
    if ext not in _SCRIPT_EXT and ext not in _EXPORT_PARSERS:
        return None
    try:
        with open(path, 'rb') as f:
            head = f.read(256 << 10)
    except OSError:
        return None
    text = _decode_file_bytes(head)
    if ext in _EXPORT_PARSERS:
        # An export is claimed only for an encoded command, not for any long token
        if not _ENCODED_COMMAND_RE.search(text):
            return None
        groups = [('parsing', (_EXPORT_PARSERS[ext], 'analyze_artifact'))]
        if ext in ('.csv', '.json', '.jsonl') and toolkit.is_windows_event_export(path):
            groups.append(('detection', ('sigma_scan',)))
        return groups + [('desobfuscation', ('deobfuscate_artifact',))]
    if not looks_obfuscated(text):
        return None
    return [('parsing', ('parse_log_file', 'analyze_artifact')),
            ('desobfuscation', ('deobfuscate_artifact',))]


def _decode_file_bytes(data):
    if data[:2] in (b'\xff\xfe', b'\xfe\xff'):
        return data.decode('utf-16', 'replace')
    if len(data) >= 4 and data[1:2] == b'\x00' and data[3:4] == b'\x00':
        return data.decode('utf-16-le', 'replace')
    return data.decode('utf-8-sig', 'replace')


def _best_cell(values):
    cells = [v for v in values if isinstance(v, str) and looks_obfuscated(v)]
    return max(cells, key=len) if cells else None


def _summary(res):
    return {k: res[k] for k in ('layers', 'operations', 'iocs', 'indicators', 'mitre_techniques',
                                'embedded_binaries')}


def _event(res, line, row=None, data=None, ts=None):
    preview = res['decoded'][:600].replace('\n', ' ')
    urls = [i['value'] for i in res['iocs'] if i['type'] == 'url'][:5]
    ev = {'line': line, 'timestamp': ts, 'severity': 'high' if res['indicators'] else 'medium',
          'event': (f"Desobfuscation ({' > '.join(res['operations']) or 'aucune couche'}) "
                    + (f"URL: {', '.join(urls)} " if urls else '')
                    + (f"indicateurs: {', '.join(i['indicator'] for i in res['indicators'])} " if res['indicators'] else '')
                    + f"| {preview}")[:1900],
          'mitre': ', '.join(res['mitre_techniques'])}
    if row is not None:
        ev['row'] = row
    if data:
        ev['data'] = {k: v for k, v in data.items() if isinstance(v, str) and len(v) < 300}
    return ev


def _alert(res, line, row=None, ts=None):
    """A decoded payload with behaviour indicators, citing its line (and row for a CSV)."""
    names = ', '.join(i['name'] for i in res['indicators'])
    alert = {'type': 'deobfuscated_payload', 'severity': 'high', 'techniques': res['mitre_techniques'],
             'title': f"Charge desobfusquee ({' > '.join(res['operations']) or 'texte clair'}) : {names}",
             'description': res['decoded'][:300].replace('\n', ' '), 'line': line, 'timestamp': ts}
    if row is not None:
        alert['row'] = row
    return alert


@toolkit.tool(
    'deobfuscate_artifact',
    "Desobfusquer STATIQUEMENT un fichier (script, log, export CSV de lignes de commande...) : soit "
    "une plage (offset/length octets) ou une ligne precise, soit, par defaut, chaque ligne suspecte "
    "(base64, -enc, [char], concatenations...). Pour chaque ligne : recette de decodage, texte final, "
    "IoCs et indicateurs. Resultats indexes et citables (line ; row pour un CSV). Rien n'est execute.",
    toolkit._schema({
        'file_path': {'type': 'string', 'description': 'Chemin du fichier'},
        'offset': {'type': 'integer', 'description': 'Debut de la plage (octets)'},
        'length': {'type': 'integer', 'description': 'Longueur de la plage (octets, defaut 1 Mo max)'},
        'line': {'type': 'integer', 'description': 'Ligne precise a desobfusquer (1 = premiere)'},
        'max_lines': {'type': 'integer', 'description': 'Lignes suspectes traitees au plus (defaut 200)'},
        'max_depth': {'type': 'integer', 'description': 'Operations de decodage max par texte (defaut 20)'},
    }, ['file_path']),
)
def deobfuscate_artifact(file_path, offset=None, length=None, line=None, max_lines=200, max_depth=None):
    if not os.path.isfile(file_path):
        return {'error': f'Fichier introuvable: {file_path}'}
    cap = _max_bytes()
    size = os.path.getsize(file_path)
    if offset is not None or length is not None:
        start = max(0, int(offset or 0))
        span = min(int(length) if length else cap, cap)
        with open(file_path, 'rb') as f:
            line_no = 1
            pos = 0
            while pos < start:
                chunk = f.read(min(1 << 20, start - pos))
                if not chunk:
                    break
                line_no += chunk.count(b'\n')
                pos += len(chunk)
            data = f.read(span)
        res = deobfuscate(_decode_file_bytes(data), max_depth)
        res.update({'file': os.path.basename(file_path), 'offset': start, 'length': len(data),
                    'line': line_no})
        res['events'] = [_event(res, line_no)]
        return res
    max_lines = max(1, min(int(max_lines or 200), 5000))
    results, scanned, truncated = [], 0, False
    is_csv = os.path.splitext(file_path)[1].lower() == '.csv'
    with open(file_path, 'rb') as f:
        raw = f.read(64 << 20)
        truncated = size > len(raw)
    text = _decode_file_bytes(raw)
    if is_csv:
        rows = _csv_rows(text)
    else:
        rows = ((i + 1, None, ln, None) for i, ln in enumerate(text.splitlines()))
    for line_no, row_no, content, data in rows:
        scanned += 1
        if line is not None and line_no != int(line):
            continue
        target = _best_cell(data.values()) if data else content
        if line is None and (not target or not looks_obfuscated(target)):
            continue
        res = deobfuscate((target or content)[:cap], max_depth)
        if not res['layers'] and not res['indicators'] and line is None:
            continue
        ts = None
        if data:
            ts = next((v for k, v in data.items() if k and k.strip().lower() in _TIME_COLS and v), None)
        results.append((line_no, row_no, data, ts, res))
        if len(results) >= max_lines or line is not None:
            break
    events = [_event(res, ln, rn, data, ts) for ln, rn, data, ts, res in results]
    iocs, seen = [], set()
    for *_x, res in results:
        for i in res['iocs']:
            if (i['type'], i['value']) not in seen:
                seen.add((i['type'], i['value']))
                iocs.append(i)
    alerts = [_alert(res, ln, rn, ts) for ln, rn, _d, ts, res in results if res['indicators']]
    return {
        'file': os.path.basename(file_path), 'lines_scanned': scanned, 'file_truncated': truncated,
        'decoded_count': len(results),
        **({'alerts': alerts} if alerts else {}),
        'decoded': [dict(_summary(res), line=ln, row=rn, timestamp=ts, decoded=res['decoded'][:4000],
                         recipe=res['recipe'])
                    for ln, rn, _d, ts, res in results],
        'iocs': iocs[:500],
        'mitre_techniques': sorted({t for *_x, res in results for t in res['mitre_techniques']}),
        'events': events,
        'note': 'Analyse statique : aucun code n\'a ete execute ni emule. line = ligne physique, '
                'row = ligne de donnees CSV (comme parse_csv).',
    }


def _csv_rows(text):
    """(ligne physique, row comme parse_csv, cellule brute, dict) pour chaque enregistrement."""
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=',;\t|')
        has_header = csv.Sniffer().has_header(sample)
    except csv.Error:
        dialect, has_header = csv.excel, False
    reader = csv.reader(io.StringIO(text), dialect)
    headers = None
    row_no = 0
    start_line = 1
    for rec in reader:
        line_no = start_line
        start_line = reader.line_num + 1
        if headers is None and has_header:
            headers = rec
            continue
        row_no += 1
        data = ({headers[i]: rec[i] for i in range(min(len(headers), len(rec)))} if headers
                else {f'col_{i}': v for i, v in enumerate(rec)})
        yield line_no, row_no, ','.join(rec), data
