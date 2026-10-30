"""Role based model selection (models.py) on realistic local model lists."""

import pytest

from phoenix_dfir_mcp import copilot, models

LMSTUDIO = ['openai/gpt-oss-20b', 'qwen/qwen3-14b', 'meta-llama-3.1-8b-instruct',
            'deepseek-r1-distill-qwen-14b', 'google/gemma-3-12b',
            'text-embedding-nomic-embed-text-v1.5']
OLLAMA = ['qwen2.5-coder:14b', 'llama3.1:8b', 'nomic-embed-text:latest', 'qwen3:30b-a3b', 'llava:7b']
JAN = ['llama3-8b-instruct', 'mistral-small-24b-instruct', 'qwen2.5-7b-instruct']

ROLE_VARS = tuple(f'PHOENIX_LLM_MODEL_{r.upper()}' for r in models.ROLES) + (
    'PHOENIX_EXTRACTOR_MODEL', 'PHOENIX_LLM_MAX_PARAMS_B', 'PHOENIX_OLLAMA_MODEL', 'PHOENIX_LMSTUDIO_MODEL',
    'PHOENIX_JAN_MODEL', 'PHOENIX_LLM_PROVIDER')


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for var in ROLE_VARS:
        monkeypatch.delenv(var, raising=False)
    models._cache.clear()
    yield
    models._cache.clear()


def best(names, role):
    return models.rank(names, role)[0][0]


def test_lmstudio_catalogue():
    assert best(LMSTUDIO, 'investigator') == 'openai/gpt-oss-20b'
    assert best(LMSTUDIO, 'reviewer') == 'openai/gpt-oss-20b'
    assert best(LMSTUDIO, 'extractor') == 'qwen/qwen3-14b'
    assert 'text-embedding-nomic-embed-text-v1.5' not in [n for n, _ in models.rank(LMSTUDIO, 'analyst')]


def test_ollama_catalogue_prefers_moe_and_skips_embeddings_and_vision():
    assert best(OLLAMA, 'investigator') == 'qwen3:30b-a3b'
    assert best(OLLAMA, 'extractor') == 'qwen3:30b-a3b'  # 3B active parameters: fast
    usable = [n for n, _ in models.rank(OLLAMA, 'investigator')]
    assert 'nomic-embed-text:latest' not in usable and 'llava:7b' not in usable


def test_jan_catalogue():
    assert best(JAN, 'investigator') == 'mistral-small-24b-instruct'
    assert best(JAN, 'extractor') == 'qwen2.5-7b-instruct'


def test_reasoning_model_is_kept_out_of_tool_calling():
    names = ['deepseek-r1-distill-qwen-14b', 'meta-llama-3.1-8b-instruct']
    assert best(names, 'investigator') == 'meta-llama-3.1-8b-instruct'
    assert best(names, 'extractor') == 'meta-llama-3.1-8b-instruct'


def test_size_cap_ranks_big_models_down(monkeypatch):
    names = ['llama-3.3-70b-instruct', 'qwen3-14b']
    assert best(names, 'investigator') == 'qwen3-14b'
    monkeypatch.setenv('PHOENIX_LLM_MAX_PARAMS_B', '80')
    assert best(names, 'investigator') == 'llama-3.3-70b-instruct'


def test_ranking_is_deterministic():
    assert models.rank(LMSTUDIO, 'investigator') == models.rank(list(reversed(LMSTUDIO)), 'investigator')


def test_unusable_models_score_none():
    assert models.score('nomic-embed-text:latest', 'investigator') is None
    assert models.score('qwen2.5-7b-base', 'investigator') is None
    assert models.score('qwen2.5-7b-instruct', 'unknown-role') is None


@pytest.mark.parametrize('role', models.ROLES)
def test_explicit_variables_win(monkeypatch, role):
    assert models.choose('lmstudio', role, LMSTUDIO)[1] == 'auto'
    monkeypatch.setenv('PHOENIX_LMSTUDIO_MODEL', 'my/provider-model')
    assert models.choose('lmstudio', role, LMSTUDIO) == ('my/provider-model', 'provider-env')
    monkeypatch.setenv(f'PHOENIX_LLM_MODEL_{role.upper()}', 'my/role-model')
    assert models.choose('lmstudio', role, LMSTUDIO) == ('my/role-model', 'role-env')


def test_legacy_extractor_variable(monkeypatch):
    monkeypatch.setenv('PHOENIX_EXTRACTOR_MODEL', 'small')
    assert models.choose('jan', 'extractor', JAN) == ('small', 'role-env')


def test_no_listed_model_falls_back_to_the_provider_default():
    assert models.choose('ollama', 'investigator', []) == (copilot.DEFAULT_OLLAMA_MODEL, 'default')
    assert models.choose('jan', 'reviewer', []) == (copilot.DEFAULT_DESKTOP_MODEL, 'default')


def test_cloud_providers_never_list_models(monkeypatch):
    calls = []
    monkeypatch.setattr(models.requests, 'get', lambda *a, **k: calls.append(a))
    assert models.list_models('openai') == [] and models.list_models('github') == []
    assert calls == []


def test_discovery_only_contacts_local_hosts(monkeypatch):
    calls = []
    monkeypatch.setattr(models.requests, 'get', lambda *a, **k: calls.append(a))
    monkeypatch.setenv('PHOENIX_LMSTUDIO_URL', 'https://models.example.com/v1')
    assert models.list_models('lmstudio') == [] and calls == []


def test_plan_covers_every_role(monkeypatch):
    monkeypatch.setattr(models, 'list_models', lambda provider, **kw: list(LMSTUDIO))
    plan = models.plan('lmstudio')
    assert set(plan['roles']) == set(models.ROLES)
    assert plan['roles']['extractor']['model'] == 'qwen/qwen3-14b'
    assert plan['roles']['investigator']['candidates'][0]['model'] == 'openai/gpt-oss-20b'
    assert plan['label'] == 'LM Studio (local LLM)'
