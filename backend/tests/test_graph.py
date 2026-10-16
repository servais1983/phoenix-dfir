#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Graphe d'entites : construction depuis une super-timeline synthetique,
contrat JSON entity_graph.json, pivots, patient zero et rayon d'impact."""

import json
import os
import sys

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
_MCP_DIR = os.path.join(_ROOT, 'mcp-server')
if _MCP_DIR not in sys.path:
    sys.path.insert(0, _MCP_DIR)

from phoenix_dfir_mcp import evidence_db, graph, memory, pathpolicy, toolkit  # noqa: E402


@pytest.fixture(autouse=True)
def _isolation():
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


def _evt(rid, ts, computer, event_id, **data):
    return {'record_id': rid, 'timestamp': ts, 'computer': computer, 'event_id': event_id,
            'data': data}


@pytest.fixture
def case(tmp_path):
    """Super-timeline synthetique : acces de jdoe a WS-01 depuis Internet, PowerShell,
    C2, rebond vers SRV-01 ; bob (avant l'attaque) et admin/SRV-02 (sans lien) hors impact."""
    d = tmp_path / 'case'
    d.mkdir()
    for name in ('WS-01_Security.evtx', 'SRV-01_Security.evtx', 'WS-01_Sysmon.evtx'):
        (d / name).write_bytes(b'ElfFile\x00')
    ws = [
        _evt(99, '2026-10-01T07:00:00Z', 'WS-01', 4624, TargetUserName='bob', LogonType='2'),
        _evt(100, '2026-10-01T08:00:00Z', 'WS-01', 4624, TargetUserName='jdoe', LogonType='10',
             IpAddress='203.0.113.5'),
        _evt(101, '2026-10-01T08:05:00Z', 'WS-01', 4688, SubjectUserName='jdoe',
             TargetUserName='-', NewProcessName='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
             NewProcessId='4242', ProcessId='1000', ParentProcessName='C:\\Windows\\explorer.exe',
             CommandLine='powershell.exe -nop -w hidden -enc SQBFAFgA'),
    ]
    srv = [
        _evt(200, '2026-10-01T08:20:00Z', 'SRV-01', 4624, TargetUserName='jdoe', LogonType='3',
             IpAddress='10.0.0.5'),
        _evt(201, '2026-10-01T08:30:00Z', 'SRV-02', 4624, TargetUserName='admin', LogonType='3'),
        _evt(202, '2026-10-01T09:00:00Z', 'SRV-01', 4624, TargetUserName='carol', LogonType='2'),
        _evt(203, '2026-10-01T09:05:00Z', 'SRV-01', 7045, ServiceName='UpdSvc',
             ImagePath='C:\\Windows\\Temp\\upd.exe', AccountName='LocalSystem'),
    ]
    sysmon = [
        _evt(300, '2026-10-01T08:10:00Z', 'WS-01', 3, Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
             ProcessId='4242', DestinationIp='198.51.100.7', DestinationHostname='c2.evil-domain.net'),
        _evt(301, '2026-10-01T08:11:00Z', 'WS-01', 11, Image='C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
             ProcessId='4242', TargetFilename='C:\\Users\\jdoe\\AppData\\Roaming\\loot.zip'),
        _evt(302, '2026-10-01T08:12:00Z', 'WS-01', 13, Image='C:\\Windows\\System32\\reg.exe',
             ProcessId='5000', TargetObject='HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\upd'),
    ]
    evidence_db.record_run(str(d), 'parse_evtx', str(d / 'WS-01_Security.evtx'), {'events': ws})
    evidence_db.record_run(str(d), 'parse_evtx', str(d / 'SRV-01_Security.evtx'), {'events': srv})
    evidence_db.record_run(str(d), 'parse_evtx', str(d / 'WS-01_Sysmon.evtx'), {'events': sysmon})
    memory.record_finding(str(d), 'RDP depuis Internet avec jdoe', severity='high', mitre='T1078',
                          evidence_refs=[{'artifact': 'WS-01_Security.evtx', 'kind': 'record_id',
                                          'value': '100'}])
    memory.record_finding(str(d), 'PowerShell encode', severity='high', mitre='T1059.001',
                          evidence_refs=[{'artifact': 'WS-01_Security.evtx', 'kind': 'record_id',
                                          'value': '101'},
                                         {'artifact': 'WS-01_Sysmon.evtx', 'kind': 'record_id',
                                          'value': '300'}])
    memory.record_finding(str(d), 'Faux positif ecarte', severity='high', mitre='T1021',
                          evidence_refs=[{'artifact': 'SRV-01_Security.evtx', 'kind': 'record_id',
                                          'value': '201'}])
    memory.challenge_finding(str(d), 3, 'admin', 'refuted', 'maintenance planifiee')
    return str(d)


def _by_id(g):
    return {n['id']: n for n in g['nodes']}


def test_contrat_json_entity_graph(case):
    toolkit.set_active_case(case)
    result = toolkit.run_tool('graph_build', {'case_dir': case})
    assert result['graph_file'].endswith('entity_graph.json')
    with open(os.path.join(case, 'entity_graph.json'), encoding='utf-8') as f:
        g = json.load(f)
    assert set(g) == {'version', 'generated_at', 'nodes', 'edges', 'patient_zero', 'blast_radius'}
    assert g['version'] == 1 and g['generated_at'].endswith('Z')
    for n in g['nodes']:
        assert set(n) == {'id', 'type', 'label', 'first_seen', 'last_seen', 'malicious',
                          'technique_ids', 'finding_ids'}
        assert n['id'].startswith(n['type'] + ':') and n['type'] in graph.NODE_TYPES
        assert isinstance(n['malicious'], bool)
    for e in g['edges']:
        assert set(e) == {'id', 'source', 'target', 'type', 'first_seen', 'last_seen', 'refs',
                          'technique_ids', 'finding_ids'}
        assert e['id'].startswith('e')
        for r in e['refs']:
            assert set(r) == {'artifact', 'kind', 'value'} and isinstance(r['value'], str)
    assert set(g['patient_zero']) == {'node', 'timestamp', 'path'}
    assert set(g['blast_radius']) == {'seed', 'nodes'}
    ids = {n['id'] for n in g['nodes']}
    assert all(e['source'] in ids and e['target'] in ids for e in g['edges'])
    # Le graphe n'est pas un artefact du cas
    names = [a['name'] for a in toolkit.run_tool('list_artifacts', {'case_dir': case})['artifacts']]
    assert 'entity_graph.json' not in names


def test_entites_et_relations(case):
    g = graph.build(case)
    nodes = _by_id(g)
    edges = {(e['source'], e['type'], e['target']): e for e in g['edges']}
    ps = 'process:WS-01/powershell.exe/4242'
    assert nodes[ps]['pid'] == 4242 and nodes[ps]['ppid'] == 1000
    assert ('process:WS-01/explorer.exe/1000', 'parent_of', ps) in edges
    assert ('user:jdoe', 'authenticated_to', 'host:WS-01') in edges
    assert ('ip:203.0.113.5', 'connected_to', 'host:WS-01') in edges
    assert ('user:jdoe', 'executed', ps) in edges and ('host:WS-01', 'executed', ps) in edges
    assert (ps, 'connected_to', 'ip:198.51.100.7') in edges
    assert (ps, 'resolved', 'domain:c2.evil-domain.net') in edges
    assert (ps, 'wrote', 'file:c:\\users\\jdoe\\appdata\\roaming\\loot.zip') in edges
    assert any(t == 'wrote' and dst.startswith('registry:') for _s, t, dst in edges)
    assert ('host:SRV-01', 'created_service', 'service:SRV-01/updsvc') in edges
    # References de preuve et horodatages sur les aretes
    auth = edges[('user:jdoe', 'authenticated_to', 'host:WS-01')]
    assert auth['refs'] == [{'artifact': 'WS-01_Security.evtx', 'kind': 'record_id', 'value': '100'}]
    assert auth['first_seen'] == '2026-10-01T08:00:00Z' and auth['finding_ids'] == [1]
    # Comptes systeme et '-' ignores ; constat refute non propage
    assert 'user:-' not in nodes and 'user:localsystem' not in nodes
    assert not nodes['user:admin']['malicious'] and not nodes['host:SRV-02']['malicious']
    assert nodes[ps]['technique_ids'] == ['T1059.001'] and nodes[ps]['finding_ids'] == [2]
    assert set(nodes['host:WS-01']['finding_ids']) == {1, 2}


def test_patient_zero_et_chemin(case):
    pz = graph.patient_zero(graph.build(case))
    assert pz['node'] == 'host:WS-01' and pz['timestamp'] == '2026-10-01T08:00:00Z'
    assert pz['path'][:2] == ['ip:203.0.113.5', 'host:WS-01']
    assert pz['reasoning'] and 'constat' in pz['reasoning'][0]
    # Chemin chronologique : horodatages croissants des relations suivies
    stamps = [line.split(' : ', 1)[0] for line in pz['reasoning'] if ' -[' in line]
    assert stamps == sorted(stamps)


def test_rayon_d_impact_chronologique(case):
    g = graph.build(case)
    br = graph.blast_radius(g, 'host:WS-01')
    order = [n['id'] for n in br['nodes']]
    # jdoe compromis a 08:00 -> SRV-01 a 08:20 -> carol a 09:00 ; bob (07:00) et admin/SRV-02 exclus
    assert order == ['user:jdoe', 'host:SRV-01', 'user:carol']
    assert [n['reached_at'] for n in br['nodes']] == sorted(n['reached_at'] for n in br['nodes'])
    assert 'user:bob' not in order and 'host:SRV-02' not in order
    assert graph.build(case)['blast_radius'] == {'seed': 'host:WS-01', 'nodes': order}
    assert 'error' in graph.blast_radius(g, 'host:INCONNU')


def test_voisins_et_resolution(case):
    toolkit.set_active_case(case)
    r = toolkit.run_tool('graph_neighbors', {'case_dir': case, 'entity': 'jdoe', 'depth': 1})
    ids = {n['id'] for n in r['nodes']}
    assert r['entity'] == 'user:jdoe'
    assert {'host:WS-01', 'host:SRV-01', 'process:WS-01/powershell.exe/4242'} <= ids
    assert all(not k.startswith('_') for n in r['nodes'] for k in n)
    deeper = toolkit.run_tool('graph_neighbors', {'case_dir': case, 'entity': 'user:jdoe', 'depth': 2})
    assert 'user:carol' in {n['id'] for n in deeper['nodes']}
    assert 'error' in toolkit.run_tool('graph_neighbors', {'case_dir': case, 'entity': 'zzz'})
    pz = toolkit.run_tool('graph_patient_zero', {'case_dir': case})
    assert pz['node'] == 'host:WS-01'


def test_extraction_conservatrice_de_texte():
    kv = graph.parse_kv("line=2 raw=2026-10-11T09:02:10Z SRV-AD-01 Security EventID=4688 "
                        "User=CORP\\svc CommandLine=powershell -c \"a b\" event=x")
    assert kv['EventID'] == '4688' and kv['User'] == 'CORP\\svc'
    assert kv['CommandLine'] == 'powershell -c "a b"'
    f = graph.event_fields({'text': 'line=37 host=srv-web-01 process=sshd pid=4188 message=Accepted '
                                    'password for svc_backup from 185.220.101.44 port 41877 ssh2'})
    assert f['auth'] == 'success' and f['user'] == 'svc_backup' and f['src_ip'] == '185.220.101.44'
    assert f['image'] is None  # un demon syslog ne cree pas de noeud processus
    f = graph.event_fields({'text': 'message=Failed password for invalid user oracle from 1.2.3.4 port 1'})
    assert f['auth'] == 'failure' and f['user'] == 'oracle'
    # Rien de devine : texte libre sans champ connu
    f = graph.event_fields({'text': 'note=le serveur 10.0.0.1 semble lent'})
    assert not any(f[k] for k in ('host', 'user', 'src_ip', 'dst_ip', 'image', 'domain'))


def test_graphe_vide_sans_index(tmp_path):
    g = graph.build_and_save(str(tmp_path))
    assert g['nodes'] == [] and g['patient_zero']['node'] is None
    data = json.load(open(tmp_path / 'entity_graph.json', encoding='utf-8'))
    assert data['blast_radius'] == {'seed': None, 'nodes': []}
