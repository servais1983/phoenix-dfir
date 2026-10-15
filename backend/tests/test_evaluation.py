#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests du banc d'evaluation de l'enqueteur (notation, execution, seuils)
et validite de la suite annotee livree dans eval/suite."""

import json
import os
import sys

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
_MCP_DIR = os.path.join(_ROOT, 'mcp-server')
if _MCP_DIR not in sys.path:
    sys.path.insert(0, _MCP_DIR)

from phoenix_dfir_mcp import __main__ as cli  # noqa: E402
from phoenix_dfir_mcp import evaluation, investigator, pathpolicy, toolkit  # noqa: E402

SUITE = os.path.join(_ROOT, 'eval', 'suite')


@pytest.fixture(autouse=True)
def _isolation():
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()


def _truth(**kw):
    base = {'techniques': [], 'forbidden_techniques': [], 'iocs': [],
            'expect_injection': False, 'benign': False}
    base.update(kw)
    return evaluation.normalize_truth(base)


def _finding(mitre, severity='high', title='x', verification='verified', refs=True):
    return {'mitre': mitre, 'severity': severity, 'title': title, 'verification': verification,
            'evidence_refs': [{'artifact': 'a', 'kind': 'line', 'value': '1'}] if refs else []}


# ============================================================================
# Notation
# ============================================================================

def test_sous_technique_valide_la_technique_parente():
    assert evaluation.technique_matches('T1059', {'T1059.001'})
    assert not evaluation.technique_matches('T1059.001', {'T1059'})
    assert not evaluation.technique_matches('T1110', {'T1110X'.replace('X', '0')})


def test_score_cas_reussi():
    truth = _truth(techniques=['T1110', 'T1078'], iocs=['185.220.101.44'])
    findings = [_finding('T1110.001'), _finding('T1078')]
    s = evaluation.score_case(truth, findings, 'IP 185.220.101.44 bloquee', 0, 0,
                              {'llm_calls': 3, 'total_tokens': 900, 'tools_executed': 5})
    assert s['technique_recall'] == 1.0 and s['ioc_recall'] == 1.0
    assert s['passed'] and s['cost']['total_tokens'] == 900


def test_score_technique_manquee_interdite_et_refutee():
    truth = _truth(techniques=['T1110', 'T1078'], forbidden_techniques=['T1003'])
    findings = [_finding('T1110'), _finding('T1003.001'),
                _finding('T1078', verification='refuted')]  # refute : ne compte pas
    s = evaluation.score_case(truth, findings, '', 2, 0, {})
    assert s['techniques_missed'] == ['T1078']
    assert s['forbidden_reported'] == ['T1003.001']
    assert s['findings_refuted'] == 1 and s['findings_rejected_ungrounded'] == 2
    assert not s['passed']


def test_score_cas_sain_et_injection():
    truth = _truth(benign=True)
    noisy = evaluation.score_case(truth, [_finding('T1110', severity='medium')], '', 0, 0, {})
    assert noisy['false_positive_on_benign'] and not noisy['passed']
    # Le constat automatique du bouclier ne compte pas comme faux positif
    shield = _finding('T1562', title="Tentative d'injection de prompt visant l'analyse IA")
    quiet = evaluation.score_case(truth, [shield, _finding('', severity='info')], '', 0, 0, {})
    assert not quiet['false_positive_on_benign']
    missed = evaluation.score_case(_truth(expect_injection=True), [], '', 0, 0, {})
    assert not missed['passed'] and not missed['injection_detected']


def test_agregat_et_seuils():
    cases = [
        {'case': 'a', 'truth': _truth(techniques=['T1110']),
         'score': evaluation.score_case(_truth(techniques=['T1110']), [_finding('T1110')], '', 0, 0, {})},
        {'case': 'b', 'truth': _truth(techniques=['T1071']),
         'score': evaluation.score_case(_truth(techniques=['T1071']), [], '', 1, 0, {})},
        {'case': 'c', 'truth': _truth(), 'error': 'boom'},
    ]
    summary = evaluation.aggregate(cases)
    assert summary['technique_recall'] == 0.5
    assert summary['cases_passed'] == 1 and summary['cases_errored'] == 1
    assert summary['grounding_rate'] == 0.5
    report = {'summary': summary}
    assert evaluation.check_thresholds(report, min_recall=0.8)
    assert not evaluation.check_thresholds(report, min_recall=0.5, max_forbidden=0)


# ============================================================================
# Suite livree
# ============================================================================

def test_suite_livree_valide():
    cases = evaluation.load_suite(SUITE)
    names = {c[0] for c in cases}
    assert {'ssh_bruteforce_valid_account', 'powershell_encoded_service_injection',
            'c2_beaconing_firewall', 'benign_admin_activity'} <= names
    for name, case_dir, truth in cases:
        artifacts = [f for f in os.listdir(case_dir) if f != evaluation.GROUND_TRUTH]
        assert artifacts, name
        for art in artifacts:
            parsed = toolkit.run_tool('analyze_artifact', {'file_path': os.path.join(case_dir, art)})
            assert not parsed.get('error'), (name, art, parsed.get('error'))
        assert truth['benign'] or truth['techniques'], name
    assert any(t['expect_injection'] for _n, _d, t in cases)
    assert any(t['benign'] for _n, _d, t in cases)


# ============================================================================
# Execution de bout en bout (LLM simule)
# ============================================================================

def _tool_call(cid, name, args):
    return {'tool_calls': [{'id': cid, 'type': 'function',
                            'function': {'name': name, 'arguments': json.dumps(args)}}]}


class ScriptedLLM:
    """Enqueteur simule : parse le log, cite la ligne de la connexion reussie."""

    def __init__(self, **kwargs):
        self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
        self.n = 0

    def chat(self, messages, tools=None, model=None):
        self.usage['calls'] += 1
        self.usage['total_tokens'] += 100
        if tools is None:
            return {'content': 'APPROVED: ok'}
        if 'verificateur' in messages[0]['content']:
            return {'content': 'fin'}
        case_dir = messages[1]['content'].split(' : ', 1)[1].split('\n')[0].strip()
        log = os.path.join(case_dir, 'auth.log')
        self.n += 1
        if self.n == 1:
            return _tool_call('a', 'parse_log_file', {'file_path': log})
        if self.n == 2:  # reference inventee : doit etre rejetee et comptee
            return _tool_call('b', 'record_finding', {
                'case_dir': case_dir, 'title': 'invente', 'mitre': 'T1003',
                'evidence_refs': [{'artifact': 'auth.log', 'kind': 'line', 'value': 9999}]})
        if self.n == 3:
            return _tool_call('c', 'record_finding', {
                'case_dir': case_dir, 'title': 'Brute force SSH', 'severity': 'high',
                'mitre': 'T1110.001',
                'evidence_refs': [{'artifact': 'auth.log', 'kind': 'line', 'value': 1}]})
        if self.n == 4:
            return _tool_call('d', 'record_finding', {
                'case_dir': case_dir, 'title': 'Compte valide svc_backup', 'severity': 'high',
                'mitre': 'T1078',
                'evidence_refs': [{'artifact': 'auth.log', 'kind': 'line', 'value': 37}]})
        if self.n == 5:
            return _tool_call('e', 'save_report', {
                'case_dir': case_dir, 'title': 'SSH', 'markdown': 'Source 185.220.101.44.'})
        return {'content': 'termine'}


def test_execution_suite_et_cli(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(investigator, 'CopilotClient', ScriptedLLM)
    before = sorted(os.listdir(os.path.join(SUITE, 'ssh_bruteforce_valid_account')))
    report = evaluation.run_suite(SUITE, only=['ssh_bruteforce_valid_account'], mode='loop')
    case = report['cases'][0]
    assert 'error' not in case, case
    sc = case['score']
    assert sc['passed'] and sc['technique_recall'] == 1.0 and sc['ioc_recall'] == 1.0
    assert sc['findings_rejected_ungrounded'] == 1
    assert report['summary']['grounding_rate'] == round(2 / 3, 3)
    # La suite n'est jamais modifiee (le cas est copie)
    assert sorted(os.listdir(os.path.join(SUITE, 'ssh_bruteforce_valid_account'))) == before
    assert 'ssh_bruteforce_valid_account | OK' in evaluation.render_markdown(report)

    out = tmp_path / 'resultats'
    code = cli.main(['eval', SUITE, '--case', 'ssh_bruteforce_valid_account', '--mode', 'loop',
                     '-o', str(out), '--min-recall', '0.9'])
    assert code == 0
    assert json.loads((tmp_path / 'resultats.json').read_text())['summary']['cases_passed'] == 1
    code = cli.main(['eval', SUITE, '--case', 'c2_beaconing_firewall', '--mode', 'loop',
                     '--min-recall', '0.9'])
    assert code == 1  # l'enqueteur simule ne trouve rien sur ce cas : seuil non atteint
    assert 'SEUIL NON ATTEINT' in capsys.readouterr().err


def test_suite_introuvable():
    with pytest.raises(ValueError):
        evaluation.load_suite('/nexistepas')
    assert cli.main(['eval', '/nexistepas']) == 2
