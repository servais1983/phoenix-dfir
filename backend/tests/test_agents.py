#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Specialized agents: team per phase, tool owners, token budget, CLI."""

import json
import os
import shutil

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')

from phoenix_dfir_mcp import __main__ as cli  # noqa: E402
from phoenix_dfir_mcp import agents, contracts, investigator, pathpolicy, phases, toolkit  # noqa: E402

from .test_phases import PhasedLLM, _call  # noqa: E402

SUITE = os.path.join(_ROOT, 'eval', 'suite')


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    monkeypatch.delenv('PHOENIX_INVESTIGATION_MODE', raising=False)
    monkeypatch.delenv('PHOENIX_STRICT_EVIDENCE', raising=False)
    monkeypatch.delenv('PHOENIX_AGENT_MAX_TOKENS', raising=False)
    monkeypatch.delenv('PHOENIX_EXTRACTION_WORKERS', raising=False)
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


@pytest.fixture
def ssh_case(tmp_path):
    case = tmp_path / 'ssh'
    shutil.copytree(os.path.join(SUITE, 'ssh_bruteforce_valid_account'), case,
                    ignore=shutil.ignore_patterns('ground_truth.json'))
    return str(case)


# ============================================================================
# Specialized agents wired to the phases
# ============================================================================

def test_every_phase_tool_belongs_to_an_agent_of_its_team():
    for phase in phases.PHASES:
        assert phase.tools == phase.declared_tools, phase.key
        assert phase.team[0] is agents.lead(phase.key)
    assert [agents.lead(p.key).name for p in phases.PHASES] == [
        'triage', 'triage', 'attack', 'verifier', 'writer']


def test_tool_owners():
    assert agents.owner('extraction', 'net_tls') == 'network'
    assert agents.owner('extraction', 'sigma_scan') == 'logs'
    assert agents.owner('extraction', 'cloud_parse_log') == 'cloud'
    assert agents.owner('correlation', 'record_finding') == 'attack'
    assert agents.owner('rapport', 'save_report') == 'writer'
    assert agents.owner('rapport', 'parse_evtx') is None
    assert not agents.AGENTS['writer'].allows('record_finding')


def test_phased_run_reports_agents_tokens_and_phase_contracts(monkeypatch, ssh_case):
    llm = PhasedLLM()
    monkeypatch.setattr(phases, 'CopilotClient', llm)
    result = investigator.investigate(ssh_case, enable_verification=False)
    m = result['metrics']
    assert m['gates_passed'] == 5
    for row in m['phases']:
        contracts.PhaseOutput.model_validate(row)
    assert [r['agent'] for r in m['phases']] == ['triage', 'triage', 'attack', 'verifier', 'writer']
    usage = m['agents']['usage']
    assert set(usage) == {'triage', 'attack', 'verifier', 'writer'}
    assert sum(r['tokens'] for r in m['phases']) == sum(u['total_tokens'] for u in usage.values())
    calls = m['agents']['tool_calls']
    assert calls['logs'] >= 1 and calls['attack'] >= 1 and calls['writer'] >= 1


class BudgetLLM:
    """Calls list_artifacts forever, 600 tokens per answer."""

    def __init__(self):
        self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
        self.sessions = []  # LLM calls of each phase session

    def __call__(self, **_kw):
        return self

    def chat(self, messages, tools=None, model=None, **_kw):
        self.usage['calls'] += 1
        self.usage['total_tokens'] += 600
        if tools is None:
            return {'content': 'fin'}
        if len(messages) == 2:  # system + phase prompt: a new session
            self.sessions.append(0)
        self.sessions[-1] += 1
        case = messages[1]['content'].split('Dossier du cas : ', 1)[1].split('\n', 1)[0].strip()
        return _call('list_artifacts', {'case_dir': case})


def test_agent_token_budget_stops_a_session(monkeypatch, ssh_case):
    monkeypatch.setenv('PHOENIX_AGENT_MAX_TOKENS', '1000')
    llm = BudgetLLM()
    monkeypatch.setattr(phases, 'CopilotClient', llm)
    result = investigator.investigate(ssh_case, enable_verification=False, enable_adviser=False)
    assert len(llm.sessions) >= 5 and set(llm.sessions) == {2}  # 600 + 600 >= 1000: stop
    assert all(r['tokens'] <= 1200 * r['attempts'] for r in result['metrics']['phases'])


# ============================================================================
# CLI
# ============================================================================

def test_cli_agents_and_schemas(capsys, tmp_path):
    assert cli.main(['agents', '--json']) == 0
    rows = {r['name']: r for r in json.loads(capsys.readouterr().out)}
    assert set(rows) == set(agents.AGENTS) and 'net_tls' in rows['network']['tools_available']
    assert cli.main(['schemas', '-o', str(tmp_path / 's')]) == 0
    assert sorted(os.listdir(tmp_path / 's')) == sorted(f'{n}.schema.json' for n in contracts.CONTRACTS)
