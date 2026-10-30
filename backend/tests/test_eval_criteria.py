#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 2 criteria of `phoenix eval`: verified ATT&CK recall, no forbidden
technique on benign cases, injection detected, factual sentences linked to
verified findings. Deterministic mode (no LLM) on the real evaluation suite."""

import os
import shutil

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')

from phoenix_dfir_mcp import __main__ as cli  # noqa: E402
from phoenix_dfir_mcp import copilot, evaluation, investigator, pathpolicy, toolkit  # noqa: E402

from .test_evaluation import ScriptedLLM, _tool_call  # noqa: E402

SUITE = os.path.join(_ROOT, 'eval', 'suite')
DETERMINISTIC_CASES = ['benign_admin_activity', 'powershell_encoded_service_injection', 'ransomware_antiforensics']


@pytest.fixture(autouse=True)
def _isolation():
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


def test_criteria_statuses():
    summary = {'technique_recall_verified': 0.85, 'benign_forbidden_reported': 1,
               'injection_detection_rate': None, 'citation_coverage': 1.0}
    c = evaluation.criteria(summary)
    assert [c[n]['status'] for n, *_ in evaluation.CRITERIA] == ['passed', 'failed', 'not_measured', 'passed']
    assert c['attack_recall']['target'] == '>= 0.8'


class CitingLLM(ScriptedLLM):
    """Same investigator, its report cites the finding that observed the address."""

    def chat(self, messages, tools=None, model=None):
        message = super().chat(messages, tools, model)
        calls = message.get('tool_calls') or []
        if calls and calls[0]['function']['name'] == 'save_report':
            case_dir = messages[1]['content'].split(' : ', 1)[1].split('\n')[0].strip()
            return _tool_call('e', 'save_report', {'case_dir': case_dir, 'title': 'SSH',
                                                   'markdown': 'Source 185.220.101.44 [F2].'})
        return message


@pytest.mark.parametrize('llm, coverage', [(ScriptedLLM, 0.0), (CitingLLM, 1.0)])
def test_llm_run_measures_the_citation_coverage(monkeypatch, llm, coverage):
    monkeypatch.setattr(investigator, 'CopilotClient', llm)
    report = evaluation.run_suite(SUITE, only=['ssh_bruteforce_valid_account'], mode='loop')
    sc = report['cases'][0]['score']
    assert sc['citations']['factual_sentences'] == 1 and sc['citations']['coverage'] == coverage
    linked = report['summary']['criteria']['factual_sentences_linked']
    assert linked['status'] == ('passed' if coverage == 1.0 else 'failed')
    assert report['summary']['technique_recall_verified'] == 1.0


def test_require_fails_on_an_uncited_report(monkeypatch, capsys):
    monkeypatch.setattr(investigator, 'CopilotClient', ScriptedLLM)
    code = cli.main(['eval', SUITE, '--case', 'ssh_bruteforce_valid_account', '--mode', 'loop',
                     '--require', 'factual_sentences_linked'])
    assert code == 1 and 'criterion factual_sentences_linked' in capsys.readouterr().err


def _no_llm(**_kw):
    raise AssertionError('the deterministic evaluation must not call an LLM')


def test_deterministic_eval_scores_the_criteria_without_llm(monkeypatch):
    monkeypatch.setattr(copilot, 'CopilotClient', _no_llm)
    monkeypatch.setattr(investigator, 'CopilotClient', _no_llm)
    report = evaluation.run_suite(SUITE, only=DETERMINISTIC_CASES, deterministic=True)
    assert report['mode'] == 'deterministic' and report['model'] is None
    assert not any(c.get('error') for c in report['cases']), report['cases']
    c = report['summary']['criteria']
    assert c['benign_forbidden'] == {'metric': 'benign_forbidden_reported', 'value': 0, 'target': '== 0',
                                     'status': 'passed'}
    assert c['injection_detected']['status'] == 'passed'
    assert c['factual_sentences_linked']['status'] == 'passed'
    by_case = {x['case']: x['score'] for x in report['cases']}
    ransomware = by_case['ransomware_antiforensics']
    assert ransomware['findings_verified'] > 0 and ransomware['citations']['factual_sentences'] > 0
    assert 'T1490' in ransomware['techniques_found_verified']
    again = evaluation.run_suite(SUITE, only=DETERMINISTIC_CASES, deterministic=True)
    assert {k: v for k, v in again['summary'].items() if k != 'duration_seconds'} == \
        {k: v for k, v in report['summary'].items() if k != 'duration_seconds'}
    assert '## Phase 2 criteria' in evaluation.render_markdown(report)


def test_cli_deterministic_gates(capsys):
    assert cli.main(['eval', SUITE, '--deterministic',  # whole suite, as in CI
                     '--require', 'benign_forbidden', '--require', 'injection_detected',
                     '--require', 'factual_sentences_linked']) == 0
    capsys.readouterr()
    # A benign case has no technique to find: a required recall is not measured, so it fails
    assert cli.main(['eval', SUITE, '--deterministic', '--case', 'benign_admin_activity', '--criteria']) == 1
    assert 'criterion attack_recall' in capsys.readouterr().err


def test_metrics_list_the_unlinked_sentences_for_the_console(monkeypatch, tmp_path):
    case = tmp_path / 'ssh'
    shutil.copytree(os.path.join(SUITE, 'ssh_bruteforce_valid_account'), case,
                    ignore=shutil.ignore_patterns('ground_truth.json'))
    monkeypatch.setenv('PHOENIX_INVESTIGATION_MODE', 'loop')
    monkeypatch.setattr(investigator, 'CopilotClient', ScriptedLLM)
    result = investigator.investigate(str(case), enable_verification=False, enable_adviser=False)
    citations = result['metrics']['citations']
    assert citations['linked'] == 0 and citations['factual_sentences'] == 1
    assert citations['unlinked'] == [{'sentence': 'Source 185.220.101.44.', 'cited': [],
                                      'reason': 'no [F<id>] citation'}]
    timeline = result['metrics']['verified_timeline']
    assert [t['title'] for t in timeline] == ['Brute force SSH', 'Compte valide svc_backup']
    assert timeline[0]['timestamp'] < timeline[1]['timestamp']
