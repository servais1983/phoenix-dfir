"""Every LLM driven process against a local server speaking the LM Studio / Jan API.

The server (tests/local_llm_server.py) runs on 127.0.0.1 and answers from a
fixed script, so these tests go through the real HTTP path: model discovery,
role based model choice, tool calls, quarantine extraction, legacy analysis
and the web API. A live check against a real local server is in
test_local_llm_live.py.
"""

import json
import re
import shutil
from pathlib import Path

import pytest

from phoenix_dfir_mcp import copilot, dualllm, investigator, models
from tests.local_llm_server import LocalLLMServer, tool_call

SUITE = Path(__file__).resolve().parents[2] / 'eval' / 'suite'
MODELS = ['openai/gpt-oss-20b', 'qwen/qwen3-14b', 'text-embedding-nomic-embed-text-v1.5']
INVESTIGATOR = 'openai/gpt-oss-20b'   # best tool calling model listed
EXTRACTOR = 'qwen/qwen3-14b'          # fast mid-sized model for the quarantine
PHASE_SCRIPT = {
    1: ['list_artifacts', 'set_investigation_plan'],
    2: ['parse_log_file'],
    3: ['declare_no_incident'],
    4: ['audit_tool_coverage', 'audit_evidence_coverage'],
    5: ['save_report'],
}


@pytest.fixture
def local_env(monkeypatch):
    for var in ('PHOENIX_LMSTUDIO_MODEL', 'PHOENIX_EXTRACTOR_MODEL', 'PHOENIX_DUAL_LLM',
                'PHOENIX_ALLOW_CLOUD_LLM', 'PHOENIX_INVESTIGATION_MODE', 'PHOENIX_LLM_MAX_PARAMS_B') + tuple(
            f'PHOENIX_LLM_MODEL_{r.upper()}' for r in models.ROLES):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'lmstudio')
    monkeypatch.setenv('PHOENIX_LLM_RETRY_BACKOFF', '0')
    models._cache.clear()
    copilot._probe_cache.clear()
    yield monkeypatch
    models._cache.clear()
    copilot._probe_cache.clear()


@pytest.fixture
def case(tmp_path):
    target = tmp_path / 'benign_admin_activity'
    shutil.copytree(SUITE / 'benign_admin_activity', target)
    (target / 'ground_truth.json').unlink()
    return target


def _called(messages):
    return [c['function']['name'] for m in messages if m.get('role') == 'assistant'
            for c in (m.get('tool_calls') or [])]


def investigation_script(case_dir):
    case = str(case_dir)
    args = {
        'list_artifacts': {'case_dir': case},
        'set_investigation_plan': {'case_dir': case, 'steps': ['Inventory', 'Parse auth.log', 'Conclude']},
        'parse_log_file': {'file_path': str(Path(case) / 'auth.log')},
        'declare_no_incident': {'case_dir': case,
                                'rationale': 'Only routine administration in auth.log (cron, key login, sudo).'},
        'audit_tool_coverage': {'case_dir': case},
        'audit_evidence_coverage': {'case_dir': case},
        'save_report': {'case_dir': case, 'title': 'Benign administration', 'markdown': (
            '# Benign administration\n\n## Resume executif\nNo incident.\n\n'
            '## Chronologie\nSee auth.log lines.\n\n## Recommandations\nNone.\n')},
    }

    def script(payload):
        messages = payload['messages']
        if not payload.get('tools'):
            return {'role': 'assistant', 'content': 'APPROVED: report complete and supported.'}
        prompt = ' '.join(str(m.get('content') or '') for m in messages[:2])
        match = re.search(r'PHASE (\d)/5', prompt)
        todo = PHASE_SCRIPT[int(match.group(1))] if match else [
            'list_artifacts', 'parse_log_file', 'declare_no_incident', 'save_report']
        done = _called(messages)
        for name in todo:
            if name not in done:
                return tool_call(f'call_{len(done) + 1}', name, args[name])
        return {'role': 'assistant', 'content': 'Phase complete.'}

    return script


def test_phased_investigation_runs_on_the_local_server(local_env, case):
    with LocalLLMServer(MODELS, investigation_script(case)) as server:
        local_env.setenv('PHOENIX_LMSTUDIO_URL', server.url)
        result = investigator.investigate(str(case), mode='phased')
    chats = server.chats()
    assert chats, 'no request reached the local server'
    assert {c['model'] for c in chats} == {INVESTIGATOR}
    assert all(c['temperature'] == 0 and c['seed'] == copilot.DEFAULT_SEED for c in chats)
    assert ('/v1/models', None) in server.requests
    assert result['metrics']['gates_passed'] == 5, result['metrics']['phases']
    assert result['report_path'] and Path(result['report_path']).is_file()


def test_loop_investigation_uses_the_reviewer_role_for_the_adviser(local_env, case):
    local_env.setenv('PHOENIX_LLM_MODEL_REVIEWER', EXTRACTOR)
    with LocalLLMServer(MODELS, investigation_script(case)) as server:
        local_env.setenv('PHOENIX_LMSTUDIO_URL', server.url)
        result = investigator.investigate(str(case), mode='loop')
    with_tools = [c for c in server.chats() if c.get('tools')]
    review = [c for c in server.chats() if not c.get('tools')]
    assert with_tools and {c['model'] for c in with_tools} == {INVESTIGATOR}
    assert review and {c['model'] for c in review} == {EXTRACTOR}
    assert 'APPROVED' in (result['metrics']['adviser_verdict'] or '')
    assert [t['tool'] for t in result['tool_calls']][:2] == ['list_artifacts', 'parse_log_file']


def test_quarantine_extractor_gets_its_own_model(local_env, case):
    local_env.setenv('PHOENIX_DUAL_LLM', 'true')

    def script(payload):
        return {'role': 'assistant', 'content': json.dumps({'entities': [], 'detections': []})}

    with LocalLLMServer(MODELS, script) as server:
        local_env.setenv('PHOENIX_LMSTUDIO_URL', server.url)
        quarantine = dualllm.from_env(str(case))
        assert quarantine.client.model == EXTRACTOR and quarantine.client.role == 'extractor'
        quarantine.client.chat([{'role': 'user', 'content': 'extract'}],
                               response_format=dualllm.Quarantine._response_format())
    assert server.chats()[-1]['model'] == EXTRACTOR
    assert 'response_format' in server.chats()[-1]


def test_legacy_analysis_uses_the_analyst_role(local_env, case):
    pytest.importorskip('typer')
    pytest.importorskip('pandas')
    import importlib
    import phoenix
    phoenix = importlib.reload(phoenix)

    with LocalLLMServer(MODELS, lambda payload: {'role': 'assistant', 'content': 'auth.log: routine.'}) as server:
        local_env.setenv('PHOENIX_LMSTUDIO_URL', server.url)
        answer = phoenix.handle_generic_text(str(case / 'auth.log'), 'summary', {})
    assert answer == 'auth.log: routine.'
    chat = server.chats()[-1]
    assert chat['model'] == models.select('lmstudio', 'analyst') == INVESTIGATOR
    assert '<donnees_outil' in chat['messages'][-1]['content']


def test_web_api_reports_the_role_plan(local_env, tmp_path):
    import database
    local_env.setattr(database, 'DB_PATH', str(tmp_path / 'web.db'))
    database.init_db()
    from app import app
    from tests.auth_helpers import bootstrap_admin
    client = app.test_client()
    token = bootstrap_admin(client, 'llm_admin', 'Phx-Llm-Admin-2026!', 'LLM Admin')['token']
    headers = {'Authorization': f'Bearer {token}'}
    with LocalLLMServer(MODELS, lambda payload: {'role': 'assistant', 'content': 'ok'}) as server:
        local_env.setenv('PHOENIX_LMSTUDIO_URL', server.url)
        plan = client.get('/api/llm/models', headers=headers).get_json()
        status = client.get('/api/autonomous/status', headers=headers).get_json()
    assert plan['provider'] == 'lmstudio' and plan['available'] == sorted(MODELS)
    assert plan['roles']['investigator']['model'] == INVESTIGATOR
    assert plan['roles']['extractor']['model'] == EXTRACTOR
    assert {s['provider']: s['reachable'] for s in plan['servers']}['lmstudio'] is True
    assert status['llm_provider'] == 'lmstudio' and status['model'] == INVESTIGATOR
    assert status['llm_roles']['extractor'] == EXTRACTOR
    assert client.get('/api/llm/models').status_code == 401


def test_models_command_checks_tool_calling(local_env, capsys):
    from phoenix_dfir_mcp import __main__ as cli

    def script(payload):
        if payload.get('tools'):
            return tool_call('probe', 'record_check', {'status': 'ok'})
        return {'role': 'assistant', 'content': 'no tools'}

    with LocalLLMServer(MODELS, script) as server:
        local_env.setenv('PHOENIX_LMSTUDIO_URL', server.url)
        assert cli.main(['models', '--check', '--json']) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan['roles']['investigator']['tool_calling']['ok'] is True
    assert plan['roles']['extractor']['tool_calling']['ok'] is True
    assert 'text-embedding-nomic-embed-text-v1.5' in plan['available']
