"""Memoire episodique inter-enquetes : retrouver les cas passes similaires.

Index local des cas passes (JSON, hors des dossiers de cas). Pour chaque cas :
techniques ATT&CK, IoCs (IP, domaines, URL, empreintes), outils offensifs
nommes et termes saillants des constats, extraits de case_state.json (et du
iocs.csv exporte).

Similarite (pure Python) :
    score = 0.35 * Jaccard(IoCs) + 0.30 * Jaccard(techniques, parents inclus)
          + 0.10 * Jaccard(outils) + 0.25 * cosinus TF-IDF(texte des constats)

ISOLATION : seuls les dossiers situes sous les racines configurees
(PHOENIX_CASES_ROOT, separateur os.pathsep ; a defaut backend/uploads/cases et
backend/uploads/inbox s'ils existent) sont indexes et lus, chemins reels
(liens symboliques resolus). Sans racine, seul un dossier explicitement fourni
et autorise par la politique de chemins est indexe. Les donnees d'autres cas
renvoyees au LLM sont des metadonnees (pas de preuve brute), passees au
bouclier anti-injection.
"""

import csv
import datetime
import json
import math
import os
import re
import threading

from .. import memory, pathpolicy, shield, toolkit

AGENT = ('casemem', 'Memoire inter-enquetes')
READONLY = ('casemem_similar_cases',)
PHASE_TOOLS = {
    'correlation': ('casemem_similar_cases',),
    'rapport': ('casemem_index_case',),
}

INDEX_VERSION = 1
WEIGHTS = {'iocs': 0.35, 'techniques': 0.30, 'tools': 0.10, 'text': 0.25}
MAX_CASES_SCANNED = 2000
TOP_TERMS = 25
_lock = threading.Lock()

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_DEFAULT_ROOTS = (os.path.join(_REPO, 'backend', 'uploads', 'cases'),
                  os.path.join(_REPO, 'backend', 'uploads', 'inbox'))

_IP_RE = re.compile(r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b')
_HASH_RE = re.compile(r'\b(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32})\b')
_URL_RE = re.compile(r'https?://[^\s\'"<>()]+', re.IGNORECASE)
_DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b', re.IGNORECASE)
_NOT_TLD = {'exe', 'dll', 'ps1', 'bat', 'cmd', 'vbs', 'js', 'zip', 'txt', 'log', 'sys', 'docx',
            'xlsx', 'pdf', 'lnk', 'msi', 'tmp', 'dat', 'ini', 'json', 'xml', 'csv', 'evtx', 'md',
            'py', 'sh', 'local', 'internal', 'lan', 'corp', 'img', 'raw', 'mem'}
_TOOLS = ('mimikatz', 'psexec', 'cobalt strike', 'cobaltstrike', 'beacon', 'rclone', 'anydesk',
          'teamviewer', 'procdump', 'certutil', 'bitsadmin', 'wmic', 'rundll32', 'regsvr32', 'mshta',
          'adfind', 'bloodhound', 'sharphound', 'ngrok', 'plink', 'winscp', 'impacket', 'secretsdump',
          'wmiexec', 'lazagne', 'rubeus', 'kerbrute', 'hydra', 'metasploit', 'meterpreter', 'sliver',
          'chisel', 'powershell', 'vssadmin', 'ntdsutil', 'nltest', 'net.exe', 'schtasks', 'curl',
          'wget', 'nmap', 'masscan', 'tor', 'megasync', 'filezilla', '7z', 'winrar')
_STOP = set('''a an and are as at be by de des du en est et for from has in is it la le les of on or
par pas pour que qui sur the to un une with was were via dans au aux ce cette ces sont ont plus
suspect suspecte constat finding event events evenement depuis vers apres avant'''.split())
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_.\-]{2,40}")


# ----------------------------------------------------------------------------
# Racines et isolation
# ----------------------------------------------------------------------------

def roots():
    """Racines des cas (chemins reels). PHOENIX_CASES_ROOT prime ; sinon les
    dossiers de cas de la plateforme s'ils existent."""
    raw = os.environ.get('PHOENIX_CASES_ROOT', '')
    if raw.strip():
        candidates = [p for p in raw.split(os.pathsep) if p.strip()]
    else:
        candidates = [p for p in _DEFAULT_ROOTS if os.path.isdir(p)]
    return [os.path.realpath(os.path.expanduser(p)) for p in candidates if os.path.isdir(p)]


def _under(path, root):
    return pathpolicy.within(path, root)


def allowed_case(case_dir, explicit=False):
    """Le dossier peut-il etre lu/indexe ? Sous une racine configuree ; sans racine,
    seulement un dossier explicitement fourni et autorise par la politique."""
    if not case_dir or not os.path.isdir(case_dir):
        return False
    real = os.path.realpath(case_dir)
    configured = roots()
    if configured:
        return any(_under(real, r) and real != r for r in configured)
    return bool(explicit) and pathpolicy.is_allowed(case_dir)


def index_path():
    custom = os.environ.get('PHOENIX_CASEMEM_INDEX', '').strip()
    if custom:
        return os.path.abspath(os.path.expanduser(custom))
    configured = roots()
    if configured:
        return os.path.join(configured[0], '.phoenix_casemem_index.json')
    return os.path.join(os.path.expanduser('~'), '.phoenix_dfir', 'casemem_index.json')


# ----------------------------------------------------------------------------
# Profil d'un cas
# ----------------------------------------------------------------------------

def _tokens(text):
    return [t.strip('.-_') for t in _TOKEN_RE.findall(text.lower())
            if t.strip('.-_') not in _STOP and not t.isdigit() and len(t.strip('.-_')) > 2]


def _iocs(text):
    found = set()
    for ip in _IP_RE.findall(text):
        if not ip.startswith(('127.', '0.')) and ip != '255.255.255.255':
            found.add(f'ip:{ip}')
    for h in _HASH_RE.findall(text):
        found.add(f'hash:{h.lower()}')
    for url in _URL_RE.findall(text):
        found.add(f"url:{url.rstrip('.,;').lower()}")
    for dom in _DOMAIN_RE.findall(text):
        d = dom.lower()
        if d.rsplit('.', 1)[-1] not in _NOT_TLD and not _IP_RE.fullmatch(d):
            found.add(f'domain:{d}')
    return found


def _techniques(text):
    techs = set()
    for t in memory.techniques_in(text):
        techs.add(t)
        techs.add(t.split('.', 1)[0])
    return techs


def profile(case_dir):
    """Profil d'un cas a partir de sa memoire (case_state.json) et de son iocs.csv."""
    state = memory.load_state(case_dir)
    parts = []
    findings = [f for f in state.get('findings') or []
                if (f.get('challenge') or {}).get('verdict') != 'refuted'
                and f.get('verification') != 'refuted']
    for f in findings:
        parts.extend([str(f.get('title') or ''), str(f.get('evidence') or ''), str(f.get('mitre') or '')])
    for h in state.get('hypotheses') or []:
        if h.get('status') in memory.SUPPORTED_STATUSES:
            parts.extend([h.get('statement') or '', ' '.join(h.get('techniques') or [])])
    text = '\n'.join(parts)
    iocs = _iocs(text)
    csv_path = os.path.join(case_dir, 'iocs.csv')
    if os.path.isfile(csv_path):
        try:
            with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
                for row in list(csv.DictReader(f))[:2000]:
                    iocs |= _iocs(str(row.get('value') or ''))
        except (OSError, csv.Error):
            pass
    low = text.lower()
    tools = {t for t in _TOOLS if re.search(rf'(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])', low)}
    counts = {}
    for tok in _tokens(text):
        counts[tok] = counts.get(tok, 0) + 1
    terms = dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:200])
    return {
        'case_id': os.path.basename(os.path.realpath(case_dir).rstrip(os.sep)),
        'path': os.path.realpath(case_dir),
        'techniques': sorted(_techniques(text + ' ' + ' '.join(
            ' '.join(h.get('techniques') or []) for h in state.get('hypotheses') or []
            if h.get('status') in memory.SUPPORTED_STATUSES))),
        'iocs': sorted(iocs),
        'tools': sorted(tools),
        'terms': terms,
        'top_terms': list(terms)[:TOP_TERMS],
        'findings': [str(f.get('title') or '')[:200] for f in findings][:30],
        'indexed_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    }


# ----------------------------------------------------------------------------
# Index
# ----------------------------------------------------------------------------

def load_index():
    try:
        with open(index_path(), 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get('version') == INDEX_VERSION:
            data.setdefault('cases', {})
            return data
    except (OSError, ValueError):
        pass
    return {'version': INDEX_VERSION, 'cases': {}}


def _save_index(data):
    path = index_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def _state_mtime(case_dir):
    try:
        return os.path.getmtime(os.path.join(case_dir, memory.STATE_FILENAME))
    except OSError:
        return None


def index_case(case_dir, explicit=True):
    if not allowed_case(case_dir, explicit=explicit):
        return {'error': ("Dossier hors des racines de cas autorisees (PHOENIX_CASES_ROOT) : "
                          "non indexe.")}
    prof = profile(case_dir)
    prof['state_mtime'] = _state_mtime(case_dir)
    with _lock:
        data = load_index()
        data['cases'][prof['path']] = prof
        _save_index(data)
    return {'indexed': prof['case_id'], 'techniques': prof['techniques'], 'iocs': len(prof['iocs']),
            'tools': prof['tools'], 'index_size': len(data['cases'])}


def refresh_index():
    """Indexer les cas des racines configurees (case_state.json modifie depuis)."""
    configured = roots()
    if not configured:
        return load_index()
    with _lock:
        data = load_index()
        # Entrees d'un cas disparu ou hors racines : retirees (jamais relues)
        for path in list(data['cases']):
            if not any(_under(path, r) for r in configured) or not os.path.isdir(path):
                data['cases'].pop(path)
        scanned = 0
        for root in configured:
            try:
                entries = sorted(os.scandir(root), key=lambda e: e.name)
            except OSError:
                continue
            for entry in entries:
                if scanned >= MAX_CASES_SCANNED:
                    break
                if not entry.is_dir(follow_symlinks=False):
                    continue
                real = os.path.realpath(entry.path)
                if not _under(real, root):
                    continue
                mtime = _state_mtime(real)
                if mtime is None:
                    continue
                scanned += 1
                known = data['cases'].get(real)
                if known and known.get('state_mtime') == mtime:
                    continue
                prof = profile(real)
                prof['state_mtime'] = mtime
                data['cases'][real] = prof
        _save_index(data)
        return data


# ----------------------------------------------------------------------------
# Similarite
# ----------------------------------------------------------------------------

def jaccard(a, b):
    a, b = set(a), set(b)
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def _tfidf(terms, df, n_docs):
    vec = {}
    for term, tf in terms.items():
        idf = math.log((1 + n_docs) / (1 + df.get(term, 0))) + 1.0
        vec[term] = (1 + math.log(tf)) * idf
    return vec


def cosine(a, b):
    dot = sum(v * b.get(k, 0.0) for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def similarity(query, other, df, n_docs):
    parts = {
        'iocs': jaccard(query['iocs'], other['iocs']),
        'techniques': jaccard(query['techniques'], other['techniques']),
        'tools': jaccard(query['tools'], other['tools']),
        'text': cosine(_tfidf(query['terms'], df, n_docs), _tfidf(other['terms'], df, n_docs)),
    }
    score = sum(WEIGHTS[k] * v for k, v in parts.items())
    return round(score, 4), {k: round(v, 4) for k, v in parts.items()}


def similar_cases(case_dir, top_k=5, extra_dirs=None):
    if not case_dir or not os.path.isdir(case_dir):
        return {'error': f"Dossier introuvable: {case_dir}"}
    query = profile(case_dir)
    data = refresh_index()
    candidates = {}
    for path, prof in data['cases'].items():
        if any(_under(path, r) for r in roots()) or not roots():
            candidates[path] = prof
    for d in extra_dirs or []:
        if allowed_case(d, explicit=True):
            prof = profile(d)
            candidates[prof['path']] = prof
    candidates.pop(query['path'], None)
    docs = list(candidates.values()) + [query]
    df = {}
    for doc in docs:
        for term in doc['terms']:
            df[term] = df.get(term, 0) + 1
    matches = []
    for prof in candidates.values():
        score, parts = similarity(query, prof, df, len(docs))
        if score <= 0:
            continue
        shared_iocs = sorted(set(query['iocs']) & set(prof['iocs']))
        shared_tech = sorted(set(query['techniques']) & set(prof['techniques']))
        shared_tools = sorted(set(query['tools']) & set(prof['tools']))
        shared_terms = [t for t in query['top_terms'] if t in prof['terms']][:10]
        why = []
        if shared_iocs:
            why.append(f"{len(shared_iocs)} IoC(s) commun(s) : {', '.join(shared_iocs[:5])}")
        if shared_tech:
            why.append(f"techniques communes : {', '.join(shared_tech[:8])}")
        if shared_tools:
            why.append(f"outils communs : {', '.join(shared_tools)}")
        if shared_terms:
            why.append(f"termes communs des constats : {', '.join(shared_terms[:6])}")
        matches.append({'case_id': prof['case_id'], 'score': score, 'components': parts,
                        'shared_iocs': shared_iocs[:50], 'shared_techniques': shared_tech,
                        'shared_tools': shared_tools, 'shared_terms': shared_terms,
                        'past_findings': prof.get('findings', [])[:10], 'why': '; '.join(why)})
    matches.sort(key=lambda m: (-m['score'], m['case_id']))
    top_k = max(1, min(int(top_k or 5), 50))
    result = {'case': query['case_id'], 'roots': len(roots()), 'indexed_cases': len(candidates),
              'weights': WEIGHTS, 'matches': matches[:top_k]}
    clean, _hits = shield.sanitize(result)
    return clean


@toolkit.tool(
    'casemem_similar_cases',
    "Memoire inter-enquetes : retrouver les cas passes les plus similaires au cas courant (IoCs et "
    "techniques ATT&CK communs, outils, termes des constats ; Jaccard pondere + cosinus TF-IDF), avec "
    "les elements partages et la raison. A utiliser comme piste, jamais comme preuve.",
    {'type': 'object', 'properties': {
        'case_dir': {'type': 'string', 'description': 'Dossier du cas courant'},
        'top_k': {'type': 'integer', 'description': 'Nombre de cas renvoyes (defaut 5)'},
    }, 'required': ['case_dir']},
)
def casemem_similar_cases(case_dir, top_k=5):
    return similar_cases(case_dir, top_k)


@toolkit.tool(
    'casemem_index_case',
    "Ajouter le cas courant (apres le rapport) a l'index de memoire inter-enquetes : techniques, "
    "IoCs, outils et termes des constats retenus. Refuse hors des racines de cas configurees.",
    {'type': 'object', 'properties': {
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
    }, 'required': ['case_dir']},
)
def casemem_index_case(case_dir):
    return index_case(case_dir, explicit=True)
