#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent contracts (Pydantic v2) and validated LLM answers (at most 2 retries)."""

import json
import os
import shutil

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')

from phoenix_dfir_mcp import contracts, dualllm, pathpolicy, toolkit  # noqa: E402


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


REF37 = {'artifact': 'auth.log', 'kind': 'line', 'value': 37}


# ============================================================================
# Contracts
# ============================================================================

def test_finding_contract():
    ok, problems = contracts.validate('finding', {'title': 'SSH access from 185.220.101.44', 'severity': 'high',
                                                  'mitre': 'T1110.001', 'evidence_refs': [REF37]})
    assert problems is None and ok.evidence_refs[0].kind == 'line'
    for bad, field in ((dict(severity='urgent'), 'severity'),
                       (dict(mitre='brute force'), 'mitre'),
                       (dict(evidence_refs=[{'artifact': 'auth.log', 'kind': 'offset', 'value': 3}]), 'kind'),
                       (dict(evidence_refs=[{'artifact': 'auth.log', 'kind': 'line', 'value': 'ten'}]), 'value'),
                       (dict(extra='x'), 'extra')):
        _model, problems = contracts.validate('finding', {'title': 'x', **bad})
        assert problems and field in problems, (bad, problems)


def test_hypothesis_contract_normalizes_techniques():
    ok, _ = contracts.validate('hypothesis', {'question': 'initial access', 'statement': 'SSH brute force',
                                              'techniques': ['t1110.001'], 'prior': 0.4})
    assert ok.techniques == ['T1110.001']
    assert contracts.validate('hypothesis', {'question': 'q', 'statement': 's', 'techniques': ['phishing']})[1]
    assert contracts.validate('hypothesis', {'question': 'q', 'statement': 's', 'prior': 1.5})[1]


def test_contracts_ref_kinds_match_the_toolkit():
    assert contracts.REF_KINDS == toolkit.REF_KINDS


def test_json_schemas_are_exported():
    schemas = contracts.json_schemas()
    assert set(schemas) == set(contracts.CONTRACTS)
    for name, schema in schemas.items():
        json.dumps(schema)
        assert schema['type'] == 'object' and schema.get('additionalProperties') is False, name
    assert schemas['finding']['required'] == ['title']


def test_extraction_contract_matches_the_extractor_schema():
    required = set(dualllm.OUTPUT_SCHEMA['required'])
    assert set(contracts.json_schema('extraction')['required']) == required
    sample = {'summary': {'events_total': 41, 'by_category': [{'category': 'authentication', 'count': 41}]},
              'entities': [{'type': 'ip', 'value': '185.220.101.44',
                            'ref': {'artifact': 'auth.log', 'kind': 'line', 'value': '37'}}],
              'detections': [], 'errors': []}
    assert contracts.validate('extraction', sample)[1] is None


# ============================================================================
# Validated LLM answers: at most 2 retries, tokens per agent
# ============================================================================

class ScriptedClient:
    model = 'scripted'

    def __init__(self, answers):
        self.answers = list(answers)
        self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
        self.requests = []

    def chat(self, messages, tools=None, temperature=None, response_format=None, model=None):
        self.requests.append({'messages': list(messages), 'temperature': temperature,
                              'response_format': response_format})
        self.usage['calls'] += 1
        self.usage['prompt_tokens'] += 20
        self.usage['completion_tokens'] += 5
        self.usage['total_tokens'] += 25
        answer = self.answers.pop(0) if self.answers else 'still not json'
        return {'content': answer if isinstance(answer, str) else json.dumps(answer)}


VERDICT = {'finding_id': 1, 'verdict': 'verified', 'note': 'line 37 shows the login'}


def test_ask_json_retries_with_the_validation_errors():
    client = ScriptedClient(['not json', {'finding_id': 0, 'verdict': 'maybe'}, VERDICT])
    log = contracts.UsageLog()
    model, info = contracts.ask_json(client, [{'role': 'user', 'content': 'verify finding 1'}], 'verdict',
                                     agent='verifier', usage_log=log)
    assert model.verdict == 'verified' and info['attempts'] == 3
    third = client.requests[2]['messages']
    assert 'finding_id' in third[-1]['content'] and 'verdict' in third[-1]['content']
    assert all(r['temperature'] == 0 for r in client.requests)
    assert client.requests[0]['response_format']['json_schema']['schema'] == contracts.json_schema('verdict')
    assert log.snapshot()['verifier'] == {'calls': 3, 'prompt_tokens': 60, 'completion_tokens': 15,
                                          'total_tokens': 75, 'retries': 2, 'failures': 0}


def test_ask_json_stops_after_two_retries():
    client = ScriptedClient(['no'] * 10)
    log = contracts.UsageLog()
    model, info = contracts.ask_json(client, [{'role': 'user', 'content': 'x'}], 'verdict', agent='v',
                                     usage_log=log, retries=5)
    assert model is None and info['attempts'] == 3 and len(client.requests) == 3
    assert log.snapshot()['v']['failures'] == 1 and 'not valid JSON' in info['error']


def test_extractor_retries_garbage_then_falls_back_to_deterministic_fields(monkeypatch, ssh_case):
    client = ScriptedClient(['garbage'] * 5)
    monkeypatch.setattr(dualllm, 'CopilotClient', lambda **_kw: client)
    q = dualllm.Quarantine(ssh_case)
    extracted, _dropped, error = q.extract('parse_log_file', 'Accepted password', dualllm.GroundTruth({}, {}, None))
    assert extracted is None and error.startswith('extraction impossible')
    assert len(client.requests) == 3 and q.stats['contract_retries'] == 2
    assert q.metrics({})['agents']['extractor']['calls'] == 3


# ============================================================================
# Tool arguments follow the contracts
# ============================================================================

def test_record_finding_tool_rejects_an_off_contract_finding(ssh_case):
    toolkit.set_active_case(ssh_case)
    toolkit.run_tool('parse_log_file', {'file_path': os.path.join(ssh_case, 'auth.log')})
    bad = toolkit.run_tool('record_finding', {'case_dir': ssh_case, 'title': 'SSH login', 'severity': 'high',
                                              'mitre': 'brute force', 'evidence_refs': [REF37]})
    assert "contrat 'finding'" in bad['error'] and 'mitre' in bad['error']
    good = toolkit.run_tool('record_finding', {'case_dir': ssh_case, 'title': 'SSH login', 'severity': 'high',
                                               'mitre': 'T1110.001', 'evidence_refs': [REF37]})
    assert good['recorded']['id'] == 1


def test_add_hypothesis_tool_rejects_unknown_techniques(tmp_path):
    bad = toolkit.run_tool('add_hypothesis', {'case_dir': str(tmp_path), 'question': 'initial access',
                                              'statement': 'Phishing', 'techniques': ['phishing']})
    assert "contrat 'hypothesis'" in bad['error']
