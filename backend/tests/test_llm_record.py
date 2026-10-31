#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Record the answers of a local LLM server once, replay them with no model.

The recording goes through the real HTTP path (tests/local_llm_server.py, an
LM Studio style server); the replay runs with no server at all, on another
copy of the case, and must give the same investigation."""

import json
import shutil

import pytest

from phoenix_dfir_mcp import __main__ as cli
from phoenix_dfir_mcp import evaluation, investigator, llm_record

from .test_local_llm_e2e import MODELS, SUITE, investigation_script, local_env  # noqa: F401
from tests.local_llm_server import LocalLLMServer

CASE = 'benign_admin_activity'


def _copy(tmp_path, name):
    target = tmp_path / name / CASE
    shutil.copytree(SUITE / CASE, target, ignore=shutil.ignore_patterns('ground_truth.json'))
    return target


def _summary(result):
    m = result['metrics']
    return {'gates': m['gates_passed'], 'phases': [(p['phase'], p['passed'], p['attempts']) for p in m['phases']],
            'tools': [c['tool'] for c in result['tool_calls']], 'findings': m['findings'],
            'citations': m['citations']['coverage']}


def test_replay_reproduces_a_recorded_investigation(local_env, tmp_path):  # noqa: F811
    recording = tmp_path / 'answers.jsonl'
    first = _copy(tmp_path, 'run1')
    llm_record.start_recording(str(recording))
    with LocalLLMServer(MODELS, investigation_script(first)) as server:
        local_env.setenv('PHOENIX_LMSTUDIO_URL', server.url)
        with llm_record.scope(CASE, str(first), record_path=str(recording)):
            recorded = investigator.investigate(str(first), mode='phased')
        calls = len(server.chats())
    lines = recording.read_text(encoding='utf-8').splitlines()
    assert len(lines) == calls + 1  # header + one line per chat
    assert str(first) not in recording.read_text(encoding='utf-8')  # the case path is a token
    assert llm_record.CASE_TOKEN in recording.read_text(encoding='utf-8')

    # No server any more: the replay must not reach a model
    local_env.setenv('PHOENIX_LMSTUDIO_URL', 'http://127.0.0.1:9/v1')
    second = _copy(tmp_path, 'run2')
    with llm_record.scope(CASE, str(second), replay=llm_record.load(str(recording))):
        replayed = investigator.investigate(str(second), mode='phased')
    assert _summary(replayed) == _summary(recorded)
    assert all(str(second) in json.dumps(c['arguments']) for c in replayed['tool_calls']
               if 'case_dir' in c['arguments'])


def test_a_diverging_replay_stops_instead_of_making_an_answer_up(tmp_path):
    case = _copy(tmp_path, 'run')
    with llm_record.scope(CASE, str(case), replay={}):
        with pytest.raises(llm_record.ReplayError):
            investigator.investigate(str(case), mode='phased')


def test_eval_cli_records_then_replays(local_env, tmp_path, capsys):  # noqa: F811
    import os
    import tempfile
    recording = tmp_path / 'answers.jsonl'
    work = str(tmp_path / 'eval_work')
    os.makedirs(work)
    real_mkdtemp = tempfile.mkdtemp
    # The eval copies the case to a temporary folder; the scripted server answers with that folder
    local_env.setattr(evaluation.tempfile, 'mkdtemp', lambda prefix='': work)
    with LocalLLMServer(MODELS, investigation_script(os.path.join(work, CASE))) as server:
        local_env.setenv('PHOENIX_LMSTUDIO_URL', server.url)
        assert cli.main(['eval', str(SUITE), '--case', CASE, '--record', str(recording)]) == 0
    recorded = capsys.readouterr().out
    local_env.setattr(evaluation.tempfile, 'mkdtemp', real_mkdtemp)
    local_env.setenv('PHOENIX_LMSTUDIO_URL', 'http://127.0.0.1:9/v1')  # no model
    assert cli.main(['eval', str(SUITE), '--case', CASE, '--replay', str(recording)]) == 0
    replayed = capsys.readouterr().out
    row = [ln for ln in recorded.splitlines() if ln.startswith('| ' + CASE)]
    assert row and row == [ln for ln in replayed.splitlines() if ln.startswith('| ' + CASE)]


def test_case_path_is_tokenised_inside_tool_call_arguments(tmp_path):
    # Tool call arguments are a JSON string: a Windows path is escaped twice in the message
    case_dir = str(tmp_path / 'C:\\Users\\runner\\case')
    rec = llm_record._Scope(CASE, case_dir)
    message = {'role': 'assistant', 'content': f'Reading {rec.case_dir}',
               'tool_calls': [{'function': {'name': 'list_evidence',
                                            'arguments': json.dumps({'case_dir': rec.case_dir})}}]}
    stored = rec._to_token(message)
    assert rec.case_dir not in json.dumps(stored) and rec.case_dir not in str(stored)
    assert stored['content'] == 'Reading ' + llm_record.CASE_TOKEN
    assert json.loads(stored['tool_calls'][0]['function']['arguments']) == {'case_dir': llm_record.CASE_TOKEN}
    assert rec._from_token(stored) == message
