"""Graphe d'entites du cas : pivots, patient zero et rayon d'impact.

Construit a partir de la super-timeline du cas (evidence_db) et des constats
(memoire du cas) :

- NOEUDS : user, host, process (pid/ppid), file, ip, domain, url, account
  (principal cloud), registry (cle de registre), service ;
- ARETES : authenticated_to, failed_auth_to, executed, parent_of,
  connected_to, resolved, wrote, created_service, accessed, hosted_on, chacune
  portant ses references de preuve (artefact + record_id / line / row / pid)
  et ses horodatages first/last.

Extraction CONSERVATRICE : champs normalises des evenements (hote,
utilisateur, processus, Event ID), paires cle=valeur connues du texte indexe,
et quelques motifs stricts (sshd Accepted/Failed, sudo, URL). Un champ absent
ne cree rien : le graphe ne devine pas.

Une entite est MALVEILLANTE si elle apparait dans un evenement cite par un
constat retenu (non refute) ; elle herite alors des techniques ATT&CK et des
numeros de constats. Le graphe est ecrit dans <case_dir>/entity_graph.json
(contrat JSON version 1, consomme par l'interface).
"""

import datetime
import heapq
import ipaddress
import json
import os
import re
import sqlite3

from . import evidence_db, memory

GRAPH_FILE = memory.GRAPH_FILENAME
GRAPH_VERSION = 1
MAX_EVENTS = 200000
MAX_REFS_PER_EDGE = 25
MAX_PATH = 20
DEFAULT_BLAST_DEPTH = 6

NODE_TYPES = ('host', 'user', 'account', 'process', 'file', 'ip', 'domain', 'url', 'registry',
              'service')
# Priorite du patient zero a horodatage egal : hote compromis d'abord.
_PZ_PRIORITY = {'host': 0, 'account': 1, 'user': 1, 'process': 2, 'service': 3, 'file': 4,
                'registry': 5, 'url': 6, 'domain': 7, 'ip': 8}
_IMPACT_TYPES = ('host', 'user', 'account')

# ----------------------------------------------------------------------------
# Extraction des champs
# ----------------------------------------------------------------------------

_KEY_RE = re.compile(r'(?:(?<=\s)|^)([A-Za-z_][A-Za-z0-9_.]{0,63})=')


def parse_kv(text):
    """Paires cle=valeur d'un texte d'evenement indexe ('k=v k2=v2 ...').
    La premiere occurrence d'une cle l'emporte."""
    text = text or ''
    out = {}
    matches = list(_KEY_RE.finditer(text))
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        value = text[m.end():end].strip().rstrip(',;').strip()
        if value and m.group(1) not in out:
            out[m.group(1)] = value
    return out


_FIELDS = {
    'host': ('Computer', 'computer', 'host', 'Hostname', 'hostname', 'src_host', 'WorkstationName',
             'DeviceName'),
    'user': ('TargetUserName', 'user', 'User', 'SubjectUserName', 'username', 'UserName'),
    # Pas la colonne 'process' (demon syslog : sshd, CRON...) : seulement des champs d'image
    'image': ('Image', 'NewProcessName', 'ProcessName', 'ImageFileName', 'executable', 'exe'),
    'pid': ('ProcessId', 'NewProcessId', 'pid', 'PID', 'Pid'),
    'ppid': ('ParentProcessId', 'PPID', 'ppid', 'CreatorProcessId'),
    'parent': ('ParentImage', 'ParentProcessName'),
    'cmd': ('CommandLine', 'ProcessCommandLine', 'cmdline', 'command', 'proctitle'),
    'src_ip': ('IpAddress', 'SourceIp', 'src_ip', 'SourceAddress', 'ClientIP', 'sourceIPAddress',
               'ipAddress', 'source_ip', 'client_ip', 'callerIp', 'addr'),
    'dst_ip': ('DestinationIp', 'dst_ip', 'DestAddress', 'RemoteAddress', 'ForeignAddr'),
    'domain': ('QueryName', 'DestinationHostname', 'dns_query'),
    'file': ('TargetFilename', 'ServiceFileName'),
    'service_image': ('ImagePath',),
    'registry': ('TargetObject',),
    'service': ('ServiceName',),
    'account': ('UserPrincipalName', 'userPrincipalName', 'userIdentity.arn', 'arn', 'principalId'),
    'event_id': ('EventID', 'event_id', 'EventId'),
    'logon_type': ('LogonType',),
}
_NON_USERS = {'-', '', 'n/a', 'system', 'local service', 'network service', 'anonymous logon',
              'localsystem', 'nt authority\\system', 'null', 'none'}
_IPV4 = r'(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}'
_IPV4_RE = re.compile(rf'^{_IPV4}$')
_IPV6_RE = re.compile(r'^[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}$')
_DOMAIN_RE = re.compile(r'^(?=.{4,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+'
                        r'[A-Za-z]{2,24}$')
_URL_RE = re.compile(r'https?://[^\s\'"<>()\[\]{}|\\^`]+', re.IGNORECASE)
_ARN_RE = re.compile(r'arn:aws:(?:iam|sts)::\d{12}:[A-Za-z-]+/[\w+=,.@/-]+')
_SSH_RE = re.compile(r'\b(Accepted|Failed) (?:password|publickey|keyboard-interactive/pam|none|'
                     r'hostbased) for (?:invalid user )?(\S+) from (\S+) port \d+')
_SUDO_RE = re.compile(r'^(\S+) : .*?\bUSER=(\S+) ; COMMAND=(\S+)')
_LOGLINE_HOST_RE = re.compile(r'(?:^|\s)(?:raw|event|message)=\d{4}-\d{2}-\d{2}T\S+\s+([A-Za-z0-9][A-Za-z0-9_.-]{0,62})\s+\S+\s+EventID=')
_SUCCESS_AUTH = {'4624', '4648', '4768', '4769', '4776'}
_FAILED_AUTH = {'4625', '4771'}
_SERVICE_EVENTS = {'7045', '4697'}
_FILE_EXT = ('.exe', '.dll', '.ps1', '.bat', '.cmd', '.vbs', '.js', '.zip', '.txt', '.log', '.sys',
             '.docx', '.xlsx', '.pdf', '.lnk', '.msi', '.tmp', '.dat', '.ini', '.json', '.xml', '.csv')
_TECH_RE = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)


def _pick(fields, name, row=None):
    if row is not None:
        col = {'host': 'host', 'event_id': 'event_id'}.get(name)
        if col and row.get(col):
            return str(row[col]).strip()
    for key in _FIELDS[name]:
        value = fields.get(key)
        if value not in (None, ''):
            return str(value).strip()
    return None


def _basename(path):
    return re.split(r'[\\/]', str(path).strip().strip('"').rstrip('\\/'))[-1]


def _clean_user(value):
    if not value:
        return None
    name = str(value).strip().strip('"')
    if '\\' in name:
        name = name.rsplit('\\', 1)[1]
    if name.lower() in _NON_USERS or name.endswith('$') or len(name) > 128 or ' ' in name:
        return None
    return name


def _ip_kind(value):
    text = str(value or '').strip().strip('[]')
    if text.startswith('::ffff:'):
        text = text[7:]
    if _IPV4_RE.match(text) and not _non_routable(text):
        return text
    if ':' in text and _IPV6_RE.match(text) and text not in ('::', '::1'):
        return text.lower()
    return None


def _non_routable(text):
    """Adresse non significative pour le graphe (non specifiee, boucle locale, diffusion)."""
    addr = ipaddress.ip_address(text)
    return addr.is_unspecified or addr.is_loopback or text == '255.255.255.255'


def _domain(value):
    text = str(value or '').strip().strip('.').lower()
    if not _DOMAIN_RE.match(text) or text.endswith(_FILE_EXT):
        return None
    return text


def _pid(value):
    text = str(value or '').strip()
    if text.lower().startswith('0x'):
        try:
            return str(int(text, 16))
        except ValueError:
            return None
    return text if text.isdigit() else None


def event_fields(row):
    """Champs utiles d'un evenement indexe (colonnes + cle=valeur + motifs stricts)."""
    kv = parse_kv(row.get('text') or '')
    raw = kv.get('raw') or kv.get('message') or kv.get('event') or ''
    out = {'kv': kv, 'raw': raw}
    out['event_id'] = _pick(kv, 'event_id', row)
    host = _pick(kv, 'host', row)
    if not host:
        m = _LOGLINE_HOST_RE.search(row.get('text') or '')
        host = m.group(1) if m else None
    out['host'] = host
    out['user'] = next((u for u in (_clean_user(v) for v in
                                    [row.get('user')] + [kv.get(k) for k in _FIELDS['user']]) if u),
                       None)
    image = _pick(kv, 'image', row)
    if not image:
        # La colonne 'process' n'est une image que si c'est un chemin (pas un nom de demon syslog)
        proc = kv.get('process') or row.get('process')
        if proc and re.search(r'[\\/]|\.exe$', str(proc), re.I):
            image = str(proc).strip()
    out['image'] = image
    if kv.get('NewProcessId'):
        # 4688 : NewProcessId = processus cree, ProcessId = createur (parent)
        out['pid'] = _pid(kv['NewProcessId'])
        out['ppid'] = _pid(kv.get('ParentProcessId') or kv.get('ProcessId'))
    else:
        out['pid'] = _pid(_pick(kv, 'pid'))
        out['ppid'] = _pid(_pick(kv, 'ppid'))
    out['parent'] = _pick(kv, 'parent')
    out['cmd'] = _pick(kv, 'cmd')
    out['src_ip'] = _ip_kind(_pick(kv, 'src_ip'))
    out['dst_ip'] = _ip_kind(_pick(kv, 'dst_ip'))
    out['domain'] = _domain(_pick(kv, 'domain'))
    out['file'] = _pick(kv, 'file')
    out['service'] = _pick(kv, 'service')
    out['service_image'] = _pick(kv, 'service_image')
    out['registry'] = _pick(kv, 'registry')
    account = _pick(kv, 'account')
    if not account:
        m = _ARN_RE.search(row.get('text') or '')
        account = m.group(0) if m else None
    out['account'] = account
    out['auth'] = None
    m = _SSH_RE.search(raw)
    if m:
        out['auth'] = 'success' if m.group(1) == 'Accepted' else 'failure'
        out['user'] = _clean_user(m.group(2)) or out['user']
        out['src_ip'] = _ip_kind(m.group(3)) or out['src_ip']
    elif out['event_id'] in _SUCCESS_AUTH or (kv.get('LogonType') and out['event_id'] != '4625'):
        out['auth'] = 'success'
    elif out['event_id'] in _FAILED_AUTH:
        out['auth'] = 'failure'
    m = _SUDO_RE.match(raw)
    if m:
        out['user'] = _clean_user(m.group(1)) or out['user']
        out['image'] = m.group(3)
        out['cmd'] = raw.split('COMMAND=', 1)[1].strip()
    texts = ' '.join(v for v in (out['cmd'], kv.get('ScriptBlockText'), raw) if v)
    out['urls'] = list(dict.fromkeys(u.rstrip('.,;') for u in _URL_RE.findall(texts)))[:10]
    return out


# ----------------------------------------------------------------------------
# Construction
# ----------------------------------------------------------------------------

def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _min_ts(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _max_ts(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


class _Builder:
    def __init__(self):
        self.nodes = {}
        self.aliases = {}
        self.edges = {}
        self.touched = {}  # event id -> (node ids, edge keys)

    def node(self, ntype, label, ts, key=None):
        label = str(label).strip()[:300]
        if not label:
            return None
        alias = f"{ntype}:{(key or label).lower()}"
        node_id = self.aliases.get(alias)
        if node_id is None:
            node_id = f"{ntype}:{key or label}"
            self.aliases[alias] = node_id
            self.nodes[node_id] = {'id': node_id, 'type': ntype, 'label': label, 'first_seen': ts,
                                   'last_seen': ts, 'malicious': False, 'technique_ids': [],
                                   'finding_ids': [], '_mal_ts': None}
        else:
            n = self.nodes[node_id]
            n['first_seen'] = _min_ts(n['first_seen'], ts)
            n['last_seen'] = _max_ts(n['last_seen'], ts)
        self._current[0].add(node_id)
        return node_id

    def edge(self, source, target, etype, ts, ref):
        if not source or not target or source == target:
            return
        key = (source, target, etype)
        e = self.edges.get(key)
        if e is None:
            e = self.edges[key] = {'source': source, 'target': target, 'type': etype,
                                   'first_seen': ts, 'last_seen': ts, 'refs': [],
                                   'technique_ids': [], 'finding_ids': [], '_mal_ts': None}
        else:
            e['first_seen'] = _min_ts(e['first_seen'], ts)
            e['last_seen'] = _max_ts(e['last_seen'], ts)
        if ref and ref not in e['refs'] and len(e['refs']) < MAX_REFS_PER_EDGE:
            e['refs'].append(ref)
        self._current[1].add(key)

    def add_event(self, row):
        self._current = (set(), set())
        self.touched[row['id']] = self._current
        f = event_fields(row)
        ts = row.get('ts')
        ref = ({'artifact': row['artifact'], 'kind': row['ref_kind'], 'value': str(row['ref_value'])}
               if row.get('ref_kind') else None)
        host = self.node('host', f['host'], ts) if f['host'] else None
        user = self.node('user', f['user'], ts, key=f['user'].lower()) if f['user'] else None
        account = self.node('account', f['account'], ts) if f['account'] else None
        src_ip = self.node('ip', f['src_ip'], ts) if f['src_ip'] else None
        dst_ip = self.node('ip', f['dst_ip'], ts) if f['dst_ip'] else None
        actor = None
        if f['auth'] and (user or account) and host:
            etype = 'authenticated_to' if f['auth'] == 'success' else 'failed_auth_to'
            self.edge(user or account, host, etype, ts, ref)
        if src_ip and host:
            self.edge(src_ip, host, 'connected_to', ts, ref)
        if src_ip and account and not host:
            self.edge(src_ip, account, 'connected_to', ts, ref)
        if f['image'] and not f['auth']:
            exe = _basename(f['image'])
            scope = f['host'] or '?'
            key = f"{scope}/{exe.lower()}" + (f"/{f['pid']}" if f['pid'] else '')
            label = exe + (f" (pid {f['pid']})" if f['pid'] else '')
            actor = self.node('process', label, ts, key=key)
            node = self.nodes[actor]
            if f['pid']:
                node['pid'] = int(f['pid'])
            if f['ppid']:
                node['ppid'] = int(f['ppid'])
            if host:
                self.edge(host, actor, 'executed', ts, ref)
            if user:
                self.edge(user, actor, 'executed', ts, ref)
            if f['parent'] or f['ppid']:
                pexe = _basename(f['parent']) if f['parent'] else None
                pkey = f"{scope}/{(pexe or '').lower()}" + (f"/{f['ppid']}" if f['ppid'] else '')
                if pexe or f['ppid']:
                    plabel = (pexe or 'pid') + (f" (pid {f['ppid']})" if f['ppid'] else '')
                    parent = self.node('process', plabel, ts, key=pkey)
                    if f['ppid']:
                        self.nodes[parent]['pid'] = int(f['ppid'])
                    self.edge(parent, actor, 'parent_of', ts, ref)
        source = actor or host
        if dst_ip and source:
            self.edge(source, dst_ip, 'connected_to', ts, ref)
        if f['domain'] and source:
            dom = self.node('domain', f['domain'], ts)
            self.edge(source, dom, 'resolved', ts, ref)
            if dst_ip:
                self.edge(dom, dst_ip, 'resolved', ts, ref)
        if f['file'] and source:
            self.edge(source, self.node('file', f['file'], ts, key=f['file'].lower()), 'wrote', ts, ref)
        if f['registry'] and source:
            self.edge(source, self.node('registry', f['registry'], ts, key=f['registry'].lower()),
                      'wrote', ts, ref)
        if f['service'] and (host or f['event_id'] in _SERVICE_EVENTS):
            svc = self.node('service', f['service'], ts,
                            key=f"{(f['host'] or '?')}/{f['service'].lower()}")
            if host:
                self.edge(host, svc, 'created_service', ts, ref)
            if f['service_image']:
                path = f['service_image'].strip().strip('"')
                self.edge(svc, self.node('file', path, ts, key=path.lower()), 'executed', ts, ref)
        origin = source or user
        for url in f['urls']:
            unode = self.node('url', url, ts)
            if origin:
                self.edge(origin, unode, 'accessed', ts, ref)
            netloc = url.split('://', 1)[1].split('/', 1)[0].rsplit('@', 1)[-1].split(':', 1)[0]
            ip = _ip_kind(netloc)
            dom = None if ip else _domain(netloc)
            if ip:
                self.edge(unode, self.node('ip', ip, ts), 'hosted_on', ts, ref)
            elif dom:
                self.edge(unode, self.node('domain', dom, ts), 'hosted_on', ts, ref)


def _events(case_dir):
    if not evidence_db.exists(case_dir):
        return []
    conn = sqlite3.connect(evidence_db.db_path(case_dir), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        try:
            rows = conn.execute(
                'SELECT id, artifact, ts, host, user, process, event_id, ref_kind, ref_value, text '
                'FROM events ORDER BY ts IS NULL, ts, id LIMIT ?', (MAX_EVENTS,)).fetchall()
        except sqlite3.DatabaseError:
            return []
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _events_for_ref(conn, case_dir, ref):
    artifact = str(ref.get('artifact') or '')
    base = os.path.basename(artifact.replace('\\', '/').rstrip('/'))
    rel = os.path.relpath(artifact, case_dir) if os.path.isabs(artifact) else artifact
    rows = conn.execute(
        'SELECT DISTINCT event_id FROM event_refs WHERE kind=? AND value=? '
        'AND (artifact=? OR artifact=? OR artifact LIKE ?)',
        (ref.get('kind'), str(ref.get('value')), rel.replace(os.sep, '/'), base, f'%/{base}'))
    return [r[0] for r in rows.fetchall()]


def all_events(case_dir):
    """Evenements indexes du cas (lignes de la table events, ordre chronologique)."""
    return _events(case_dir)


def finding_events(case_dir, finding):
    """Evenements indexes cites par les evidence_refs d'un constat (sans doublon)."""
    if not evidence_db.exists(case_dir):
        return []
    conn = sqlite3.connect(evidence_db.db_path(case_dir), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        ids = []
        for ref in finding.get('evidence_refs') or []:
            if isinstance(ref, dict):
                ids.extend(i for i in _events_for_ref(conn, case_dir, ref) if i not in ids)
        if not ids:
            return []
        marks = ','.join('?' for _ in ids)
        rows = conn.execute(
            'SELECT id, artifact, ts, host, user, process, event_id, ref_kind, ref_value, text '
            f'FROM events WHERE id IN ({marks}) ORDER BY ts, id', ids).fetchall()  # nosec B608 - placeholders
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _retained_findings(case_dir):
    out = []
    for f in memory.get_state(case_dir)['findings']:
        if f.get('verification') == 'refuted' or (f.get('challenge') or {}).get('verdict') == 'refuted':
            continue
        if 'injection de prompt' in (f.get('title') or '').lower():
            continue
        out.append(f)
    return out


def _mark(item, finding, ts):
    item['malicious'] = True
    if finding['id'] not in item['finding_ids']:
        item['finding_ids'].append(finding['id'])
    for tech in memory.techniques_in(finding.get('mitre')):
        if tech not in item['technique_ids']:
            item['technique_ids'].append(tech)
    item['_mal_ts'] = _min_ts(item['_mal_ts'], ts)


def _link_findings(builder, case_dir, events_by_id):
    findings = _retained_findings(case_dir)
    if not findings or not evidence_db.exists(case_dir):
        return
    conn = sqlite3.connect(evidence_db.db_path(case_dir), timeout=30)
    try:
        for finding in findings:
            for ref in finding.get('evidence_refs') or []:
                if not isinstance(ref, dict):
                    continue
                try:
                    ids = _events_for_ref(conn, case_dir, ref)
                except sqlite3.DatabaseError:
                    ids = []
                for event_id in ids:
                    touched = builder.touched.get(event_id)
                    if not touched:
                        continue
                    ts = (events_by_id.get(event_id) or {}).get('ts')
                    node_ids, edge_keys = touched
                    for node_id in node_ids:
                        _mark(builder.nodes[node_id], finding, ts)
                    for key in edge_keys:
                        builder.edges[key]['malicious'] = True
                        _mark(builder.edges[key], finding, ts)
    finally:
        conn.close()


def build(case_dir):
    """Construire le graphe (dict au format du contrat, avec champs internes '_')."""
    builder = _Builder()
    events = _events(case_dir)
    for row in events:
        builder.add_event(row)
    _link_findings(builder, case_dir, {r['id']: r for r in events})
    return _assemble(builder)


def _assemble(builder):
    nodes = sorted(builder.nodes.values(), key=lambda n: n['id'])
    edges = []
    for i, e in enumerate(builder.edges.values(), 1):
        edge = dict(e)
        edge['id'] = f'e{i}'
        edge.pop('malicious', None)
        edges.append(edge)
    graph = {'version': GRAPH_VERSION, 'generated_at': _now_iso(), 'nodes': nodes, 'edges': edges,
             'patient_zero': {'node': None, 'timestamp': None, 'path': []},
             'blast_radius': {'seed': None, 'nodes': []}}
    pz = patient_zero(graph)
    graph['patient_zero'] = {'node': pz['node'], 'timestamp': pz['timestamp'], 'path': pz['path']}
    if pz['node']:
        br = blast_radius(graph, pz['node'])
        graph['blast_radius'] = {'seed': br['seed'], 'nodes': [n['id'] for n in br['nodes']]}
    return graph


_NODE_KEYS = ('id', 'type', 'label', 'first_seen', 'last_seen', 'malicious', 'technique_ids',
              'finding_ids')
_EDGE_KEYS = ('id', 'source', 'target', 'type', 'first_seen', 'last_seen', 'refs',
              'technique_ids', 'finding_ids')


def to_contract(graph):
    """Graphe au format exact du fichier entity_graph.json (version 1)."""
    nodes = []
    for n in graph['nodes']:
        node = {k: n.get(k) for k in _NODE_KEYS}
        node['malicious'] = bool(node['malicious'])
        node['technique_ids'] = list(node['technique_ids'] or [])
        node['finding_ids'] = list(node['finding_ids'] or [])
        nodes.append(node)
    edges = []
    for e in graph['edges']:
        edge = {k: e.get(k) for k in _EDGE_KEYS}
        edge['refs'] = [{'artifact': r.get('artifact'), 'kind': r.get('kind'),
                         'value': str(r.get('value'))} for r in edge['refs'] or []]
        edge['technique_ids'] = list(edge['technique_ids'] or [])
        edge['finding_ids'] = list(edge['finding_ids'] or [])
        edges.append(edge)
    pz = graph.get('patient_zero') or {}
    br = graph.get('blast_radius') or {}
    return {'version': GRAPH_VERSION, 'generated_at': graph.get('generated_at') or _now_iso(),
            'nodes': nodes, 'edges': edges,
            'patient_zero': {'node': pz.get('node'), 'timestamp': pz.get('timestamp'),
                             'path': list(pz.get('path') or [])},
            'blast_radius': {'seed': br.get('seed'), 'nodes': list(br.get('nodes') or [])}}


def graph_path(case_dir):
    return os.path.join(case_dir, GRAPH_FILE)


def build_and_save(case_dir):
    """Construire le graphe et l'ecrire dans <case_dir>/entity_graph.json."""
    graph = build(case_dir)
    contract = to_contract(graph)
    tmp = graph_path(case_dir) + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(contract, f, ensure_ascii=False, indent=1)
    os.replace(tmp, graph_path(case_dir))
    return graph


def load(case_dir, rebuild=False):
    """Graphe du cas (reconstruit s'il est absent, illisible ou si rebuild)."""
    if not rebuild:
        try:
            with open(graph_path(case_dir), 'r', encoding='utf-8') as f:
                graph = json.load(f)
            if isinstance(graph, dict) and graph.get('version') == GRAPH_VERSION:
                return graph
        except (OSError, ValueError):
            pass
    return build_and_save(case_dir)


# ----------------------------------------------------------------------------
# Requetes : voisins, patient zero, rayon d'impact
# ----------------------------------------------------------------------------

def _index(graph):
    nodes = {n['id']: n for n in graph['nodes']}
    adj = {}
    for e in graph['edges']:
        adj.setdefault(e['source'], []).append((e, e['target']))
        adj.setdefault(e['target'], []).append((e, e['source']))
    return nodes, adj


def resolve(graph, entity):
    """Identifiant de noeud a partir d'un id exact, d'un libelle ou d'une valeur."""
    if not entity:
        return None
    text = str(entity).strip()
    nodes = graph['nodes']
    for n in nodes:
        if n['id'] == text:
            return n['id']
    low = text.lower()
    for n in nodes:
        if n['id'].lower() == low:
            return n['id']
    matches = [n for n in nodes if (n.get('label') or '').lower() == low
               or n['id'].split(':', 1)[-1].lower() == low]
    if matches:
        return sorted(matches, key=lambda n: (_PZ_PRIORITY.get(n['type'], 9), n['id']))[0]['id']
    return None


def neighbors(graph, entity, depth=1, limit=200):
    """Voisinage d'une entite jusqu'a `depth` sauts (aretes dans les deux sens)."""
    start = resolve(graph, entity)
    if start is None:
        return {'error': f"Entite introuvable dans le graphe : {entity}"}
    depth = max(1, min(int(depth or 1), 4))
    nodes, adj = _index(graph)
    seen = {start: 0}
    frontier = [start]
    edges = []
    edge_ids = set()
    for hop in range(1, depth + 1):
        nxt = []
        for node_id in frontier:
            for e, other in adj.get(node_id, ()):
                if e['id'] not in edge_ids:
                    edge_ids.add(e['id'])
                    edges.append(e)
                if other not in seen:
                    seen[other] = hop
                    nxt.append(other)
        frontier = nxt
        if len(seen) > limit:
            break
    out_nodes = [dict(_public(nodes[i]), hops=h)
                 for i, h in sorted(seen.items(), key=lambda x: (x[1], x[0]))
                 if i in nodes][:limit]
    keep = {n['id'] for n in out_nodes}
    return {'entity': start, 'depth': depth, 'nodes': out_nodes,
            'edges': [_public(e) for e in edges
                      if e['source'] in keep and e['target'] in keep][:limit * 2]}


def _public(item):
    return {k: v for k, v in item.items() if not k.startswith('_')}


def _mal_ts(item):
    return item.get('_mal_ts') or (item.get('first_seen') if item.get('malicious') else None)


def patient_zero(graph):
    """Entite malveillante la plus ancienne (horodatage du premier evenement cite par
    un constat), avec le chemin de raisonnement."""
    nodes, adj = _index(graph)
    candidates = [n for n in graph['nodes'] if n.get('malicious')]
    if not candidates:
        return {'node': None, 'timestamp': None, 'path': [],
                'reasoning': ["Aucune entite rattachee a un constat retenu : patient zero indetermine."]}
    _far = '9999-12-31T23:59:59Z'
    candidates.sort(key=lambda n: (_mal_ts(n) or _far, _PZ_PRIORITY.get(n['type'], 9), n['id']))
    pz = candidates[0]
    t0 = _mal_ts(pz)
    reasoning = [f"Premier evenement malveillant : {t0 or 'horodatage inconnu'} "
                 f"(constat(s) #{', #'.join(str(i) for i in pz['finding_ids'])})."]
    same = [n['id'] for n in candidates if _mal_ts(n) == t0 and n['id'] != pz['id']]
    if same:
        reasoning.append(f"Entites du meme evenement : {', '.join(same[:10])} ; {pz['id']} retenu "
                         "(priorite hote > compte > processus > reseau).")
    # Origine : entite externe malveillante reliee au patient zero, au plus tard a t0
    origin = None
    for e, other in adj.get(pz['id'], ()):
        o = nodes.get(other)
        if (o and o.get('malicious') and o['type'] in ('ip', 'domain', 'url')
                and e.get('finding_ids') and (_mal_ts(e) or _far) <= (t0 or _far)):
            origin = other
            break
    path = ([origin] if origin else []) + [pz['id']]
    if origin:
        reasoning.append(f"Origine : {origin} relie a {pz['id']} par une relation malveillante.")
    # Chemin chronologique : relations malveillantes successives depuis le patient zero
    current, t_cur = pz['id'], t0
    visited = set(path)
    while len(path) < MAX_PATH:
        options = []
        for e, other in adj.get(current, ()):
            if other in visited or not e.get('finding_ids'):
                continue
            ts = _mal_ts(e) or e.get('first_seen')
            if t_cur and ts and ts < t_cur:
                continue
            options.append((ts or _far, other, e))
        if not options:
            break
        options.sort(key=lambda x: (x[0], x[1]))
        ts, other, e = options[0]
        reasoning.append(f"{ts if ts != _far else '?'} : {current} -[{e['type']}]-> {other}")
        path.append(other)
        visited.add(other)
        current, t_cur = other, (ts if ts != _far else t_cur)
    return {'node': pz['id'], 'timestamp': t0, 'path': path, 'reasoning': reasoning,
            'type': pz['type'], 'label': pz.get('label'), 'finding_ids': pz['finding_ids'],
            'technique_ids': pz['technique_ids']}


def blast_radius(graph, seed=None, depth=DEFAULT_BLAST_DEPTH):
    """Hotes et comptes atteignables depuis `seed` APRES son premier evenement
    malveillant, par des relations actives ensuite (ordre chronologique d'atteinte)."""
    nodes, adj = _index(graph)
    if seed is None:
        seed = patient_zero(graph)['node']
    start = resolve(graph, seed) if seed else None
    if start is None:
        return {'seed': None, 'nodes': [], 'error': f"Entite de depart introuvable : {seed}"}
    t0 = _mal_ts(nodes[start]) or nodes[start].get('first_seen')
    depth = max(1, min(int(depth or DEFAULT_BLAST_DEPTH), 10))
    _null = ''
    best = {start: (t0 or _null, 0, None, None)}
    heap = [(t0 or _null, 0, start)]
    while heap:
        t_cur, hops, node_id = heapq.heappop(heap)
        if best.get(node_id, (None,))[0] != t_cur or hops >= depth:
            continue
        for e, other in adj.get(node_id, ()):
            last = e.get('last_seen')
            if t_cur and last and last < t_cur:
                continue  # relation inactive apres la compromission du noeud courant
            arrival = max(t_cur or _null, e.get('first_seen') or _null)
            if other not in best or arrival < best[other][0]:
                best[other] = (arrival, hops + 1, node_id, e)
                heapq.heappush(heap, (arrival, hops + 1, other))
    reached = []
    for node_id, (arrival, hops, via, e) in best.items():
        node = nodes.get(node_id)
        if node_id == start or not node or node['type'] not in _IMPACT_TYPES:
            continue
        reached.append({'id': node_id, 'type': node['type'], 'label': node.get('label'),
                        'reached_at': arrival or None, 'hops': hops, 'via': via,
                        'relation': e['type'] if e else None, 'malicious': node.get('malicious')})
    reached.sort(key=lambda r: (r['reached_at'] or '9999', r['hops'], r['id']))
    return {'seed': start, 'since': t0, 'nodes': reached}


def summary(graph):
    types = {}
    for n in graph['nodes']:
        types[n['type']] = types.get(n['type'], 0) + 1
    etypes = {}
    for e in graph['edges']:
        etypes[e['type']] = etypes.get(e['type'], 0) + 1
    return {'nodes': len(graph['nodes']), 'edges': len(graph['edges']), 'node_types': types,
            'edge_types': etypes,
            'malicious_nodes': [n['id'] for n in graph['nodes'] if n.get('malicious')][:50]}
