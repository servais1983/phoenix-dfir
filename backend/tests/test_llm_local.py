"""Local-first LLM client: local providers by default, cloud only on explicit opt-in."""

import os
from urllib.parse import urlsplit

import pytest
import requests

import custody
import database
from phoenix_dfir_mcp import copilot, pathpolicy

LLM_VARS = ('PHOENIX_LLM_PROVIDER', 'PHOENIX_ALLOW_CLOUD_LLM', 'OPENAI_API_KEY', 'OPENAI_BASE_URL',
            'GITHUB_TOKEN', 'PHOENIX_GITHUB_TOKEN', 'OLLAMA_BASE_URL', 'PHOENIX_OLLAMA_MODEL',
            'PHOENIX_LLAMACPP_URL', 'PHOENIX_LLAMACPP_MODEL', 'PHOENIX_LLM_SEED',
            'PHOENIX_LLM_LOCAL_HOSTS', 'PHOENIX_GITHUB_MODELS_URL')


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in LLM_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv('PHOENIX_LLM_RETRY_BACKOFF', '0')
    copilot._probe_cache.clear()
    yield
    copilot._probe_cache.clear()


class Resp:
    def __init__(self, status=200, content='ok'):
        self.status_code = status
        self.content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f'{self.status_code} error', response=self)

    def json(self):
        return {'choices': [{'message': {'content': self.content}}], 'usage': {'total_tokens': 3}}


@pytest.fixture
def network(monkeypatch):
    """Record every outgoing request instead of sending it."""
    calls = []

    def fake_post(url, headers=None, json=None, timeout=None):
        calls.append(('POST', url, json))
        return Resp()

    def fake_get(url, timeout=None, **kwargs):
        calls.append(('GET', url, None))
        raise requests.ConnectionError('offline')

    monkeypatch.setattr(copilot.requests, 'post', fake_post)
    monkeypatch.setattr(copilot.requests, 'get', fake_get)
    return calls


@pytest.fixture
def ledger(monkeypatch, tmp_path):
    monkeypatch.setattr(database, 'DB_PATH', str(tmp_path / 'ledger.db'))
    custody.init_schema()
    return custody


def _is_local(url):
    return copilot.is_local_url(url)


# ---------------------------------------------------------------------------
# Provider selection
# ---------------------------------------------------------------------------

def test_default_provider_is_ollama():
    assert copilot.requested_provider() == 'ollama'
    assert copilot.provider_name() == 'ollama'
    assert copilot.CopilotClient().url == 'http://localhost:11434/v1/chat/completions'


def test_unknown_provider_falls_back_to_ollama(monkeypatch):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'something-else')
    assert copilot.provider_name() == 'ollama'


def test_auto_never_selects_a_cloud_provider(monkeypatch):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'auto')
    monkeypatch.setenv('PHOENIX_ALLOW_CLOUD_LLM', '1')
    monkeypatch.setenv('OPENAI_API_KEY', 'placeholder')
    monkeypatch.setenv('GITHUB_TOKEN', 'placeholder')
    monkeypatch.setattr(copilot, 'ollama_reachable', lambda timeout=1.5: False)
    monkeypatch.setattr(copilot, 'llamacpp_reachable', lambda timeout=1.5: False)
    assert copilot.provider_name() == 'ollama'
    monkeypatch.setattr(copilot, 'llamacpp_reachable', lambda timeout=1.5: True)
    assert copilot.provider_name() == 'llamacpp'
    monkeypatch.setattr(copilot, 'ollama_reachable', lambda timeout=1.5: True)
    assert copilot.provider_name() == 'ollama'


def test_llamacpp_provider_defaults(monkeypatch, network):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'llamacpp')
    client = copilot.CopilotClient()
    assert client.url == 'http://127.0.0.1:8080/v1/chat/completions'
    assert client.model == copilot.DEFAULT_LLAMACPP_MODEL
    assert copilot.is_configured() and copilot.provider_label() == 'llama.cpp (local LLM)'
    assert client.chat([{'role': 'user', 'content': 'hi'}])['content'] == 'ok'
    assert network[-1][1] == 'http://127.0.0.1:8080/v1/chat/completions'
    monkeypatch.setenv('PHOENIX_LLAMACPP_URL', 'http://127.0.0.1:9090/v1/')
    assert copilot.CopilotClient().url == 'http://127.0.0.1:9090/v1/chat/completions'


# ---------------------------------------------------------------------------
# No leak without opt-in
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('provider,env', [
    ('openai', {'OPENAI_API_KEY': 'placeholder'}),
    ('github', {'GITHUB_TOKEN': 'placeholder'}),
])
def test_cloud_provider_refused_without_opt_in(monkeypatch, network, provider, env):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', provider)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert not copilot.is_configured()
    with pytest.raises(copilot.CopilotError, match='PHOENIX_ALLOW_CLOUD_LLM'):
        copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    assert network == []


@pytest.mark.parametrize('base', [
    'http://203.0.113.10:11434',
    'https://llm.example.com',
    'http://8.8.8.8:11434',
])
def test_local_provider_on_public_host_is_refused_without_opt_in(monkeypatch, network, base):
    monkeypatch.setenv('OLLAMA_BASE_URL', base)
    with pytest.raises(copilot.CopilotError, match='PHOENIX_ALLOW_CLOUD_LLM'):
        copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    assert network == []


@pytest.mark.parametrize('base', [
    'http://localhost:11434', 'http://127.0.0.1:11434', 'http://[::1]:11434',
    'http://192.168.1.20:11434', 'http://10.0.0.5:11434', 'http://host.docker.internal:11434',
    'http://ollama:11434',
])
def test_local_provider_on_local_host_is_allowed(monkeypatch, network, base):
    monkeypatch.setenv('OLLAMA_BASE_URL', base)
    assert copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])['content'] == 'ok'
    assert len(network) == 1


def test_extra_local_hosts_are_configurable(monkeypatch, network):
    monkeypatch.setenv('OLLAMA_BASE_URL', 'http://gpu.lab.example:11434')
    with pytest.raises(copilot.CopilotError):
        copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    monkeypatch.setenv('PHOENIX_LLM_LOCAL_HOSTS', 'gpu.lab.example')
    copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    assert len(network) == 1


def test_no_non_loopback_request_without_opt_in(monkeypatch, network):
    """Whatever the configuration, nothing leaves the host without the opt-in."""
    monkeypatch.setenv('OPENAI_API_KEY', 'placeholder')
    monkeypatch.setenv('GITHUB_TOKEN', 'placeholder')
    for provider in ('auto', 'ollama', 'llamacpp', 'openai', 'github', 'bogus'):
        monkeypatch.setenv('PHOENIX_LLM_PROVIDER', provider)
        copilot._probe_cache.clear()
        try:
            copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
        except copilot.CopilotError:
            pass
    assert network, 'local providers must have been called'
    for _method, url, _payload in network:
        assert urlsplit(url).hostname in ('localhost', '127.0.0.1'), url


# ---------------------------------------------------------------------------
# Cloud opt-in and consent ledger
# ---------------------------------------------------------------------------

def test_cloud_provider_with_opt_in_records_consent(monkeypatch, network, ledger, tmp_path):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'openai')
    monkeypatch.setenv('OPENAI_API_KEY', 'placeholder')
    monkeypatch.setenv('PHOENIX_ALLOW_CLOUD_LLM', '1')
    assert copilot.is_configured()
    case = tmp_path / 'case'
    case.mkdir()
    client = copilot.CopilotClient()
    with pathpolicy.job_scope(str(case)):
        client.chat([{'role': 'user', 'content': 'x'}])
        client.chat([{'role': 'user', 'content': 'y'}])
    assert [c[1] for c in network] == ['https://api.openai.com/v1/chat/completions'] * 2
    consents = [e for e in ledger.list_entries() if e['action'] == 'llm_cloud_consent']
    assert len(consents) == 1, 'one consent per client'
    entry = consents[0]
    assert entry['details']['provider'] == 'openai'
    assert entry['details']['host'] == 'api.openai.com'
    assert entry['details']['model'] == copilot.DEFAULT_OPENAI_MODEL
    assert os.path.normcase(entry['artifact_ref']) == pathpolicy._normalize(str(case))
    assert 'placeholder' not in str(entry)
    assert ledger.verify_chain()['valid']


def test_cloud_call_refused_when_consent_cannot_be_recorded(monkeypatch, network):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'github')
    monkeypatch.setenv('GITHUB_TOKEN', 'placeholder')
    monkeypatch.setenv('PHOENIX_ALLOW_CLOUD_LLM', '1')

    def broken(*args, **kwargs):
        raise RuntimeError('ledger offline')

    monkeypatch.setattr(custody, 'record', broken)
    with pytest.raises(copilot.CopilotError, match='consent'):
        copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    assert network == []


# ---------------------------------------------------------------------------
# Determinism and retries
# ---------------------------------------------------------------------------

def test_payload_is_deterministic(monkeypatch, network):
    copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    payload = network[-1][2]
    assert payload['temperature'] == 0 and payload['seed'] == copilot.DEFAULT_SEED
    monkeypatch.setenv('PHOENIX_LLM_SEED', '7')
    copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}], temperature=0.3)
    payload = network[-1][2]
    assert payload['temperature'] == 0.3 and payload['seed'] == 7


def test_invalid_seed_falls_back_to_default(monkeypatch):
    monkeypatch.setenv('PHOENIX_LLM_SEED', 'abc')
    assert copilot.llm_seed() == copilot.DEFAULT_SEED


def test_transient_errors_are_retried_with_a_bound(monkeypatch):
    attempts = []

    def flaky(url, headers=None, json=None, timeout=None):
        attempts.append(url)
        if len(attempts) < 3:
            raise requests.ConnectionError('reset')
        return Resp()

    monkeypatch.setattr(copilot.requests, 'post', flaky)
    assert copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])['content'] == 'ok'
    assert len(attempts) == 3

    attempts.clear()

    def down(url, headers=None, json=None, timeout=None):
        attempts.append(url)
        return Resp(status=503)

    monkeypatch.setattr(copilot.requests, 'post', down)
    with pytest.raises(copilot.CopilotError):
        copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    assert len(attempts) == copilot.MAX_ATTEMPTS == 3


def test_client_errors_are_not_retried(monkeypatch):
    attempts = []

    def bad(url, headers=None, json=None, timeout=None):
        attempts.append(url)
        return Resp(status=400)

    monkeypatch.setattr(copilot.requests, 'post', bad)
    with pytest.raises(copilot.CopilotError):
        copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    assert len(attempts) == 1


def test_llm_reachable_probes_local_servers_only(monkeypatch, network):
    assert copilot.llm_reachable() is False
    assert network and all(_is_local(url) for _m, url, _p in network)
    monkeypatch.setattr(copilot, 'llamacpp_reachable', lambda timeout=1.5: True)
    assert copilot.llm_reachable('llamacpp') is True
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'openai')
    monkeypatch.setenv('OPENAI_API_KEY', 'placeholder')
    assert copilot.llm_reachable() is False
    monkeypatch.setenv('PHOENIX_ALLOW_CLOUD_LLM', '1')
    assert copilot.llm_reachable() is True


# ---------------------------------------------------------------------------
# Desktop local servers: LM Studio and Jan
# ---------------------------------------------------------------------------

DESKTOP_VARS = ('PHOENIX_LMSTUDIO_URL', 'PHOENIX_LMSTUDIO_MODEL', 'PHOENIX_JAN_URL', 'PHOENIX_JAN_MODEL',
                'PHOENIX_JAN_API_KEY')


class ModelsResp:
    status_code = 200

    def __init__(self, ids):
        self.ids = ids

    def json(self):
        return {'object': 'list', 'data': [{'id': i, 'object': 'model'} for i in self.ids]}


@pytest.fixture
def desktop_env(monkeypatch):
    for var in DESKTOP_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize('provider,url,label', [
    ('lmstudio', 'http://localhost:1234/v1/chat/completions', 'LM Studio (local LLM)'),
    ('jan', 'http://localhost:1337/v1/chat/completions', 'Jan (local LLM)'),
])
def test_desktop_server_defaults(monkeypatch, network, desktop_env, provider, url, label):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', provider)
    client = copilot.CopilotClient()
    assert client.url == url and client.label == label
    assert copilot.is_configured() and not copilot.is_cloud()
    assert client.model == copilot.DEFAULT_DESKTOP_MODEL  # no server listed a model
    assert client.chat([{'role': 'user', 'content': 'hi'}])['content'] == 'ok'
    method, posted, payload = network[-1]
    assert (method, posted) == ('POST', url) and payload['temperature'] == 0


def test_desktop_model_is_the_first_listed_model(monkeypatch, desktop_env):
    seen = []

    def fake_get(url, headers=None, timeout=None):
        seen.append((url, headers))
        return ModelsResp(['qwen2.5-7b-instruct', 'llama3-8b-instruct'])

    monkeypatch.setattr(copilot.requests, 'get', fake_get)
    assert copilot.desktop_model('jan') == 'llama3-8b-instruct'
    assert seen == [('http://localhost:1337/v1/models', {})]
    monkeypatch.setenv('PHOENIX_JAN_MODEL', 'mistral-7b')
    assert copilot.desktop_model('jan') == 'mistral-7b'


def test_jan_api_key_is_sent_when_configured(monkeypatch, network, desktop_env):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'jan')
    monkeypatch.setenv('PHOENIX_JAN_API_KEY', 'placeholder')
    monkeypatch.setenv('PHOENIX_JAN_MODEL', 'llama3-8b-instruct')
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured.update(headers=headers, payload=json)
        return Resp()

    monkeypatch.setattr(copilot.requests, 'post', fake_post)
    copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    assert captured['headers']['Authorization'] == 'Bearer placeholder'
    assert captured['payload']['model'] == 'llama3-8b-instruct'


def test_lmstudio_sends_no_authorization(monkeypatch, network, desktop_env):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'lmstudio')
    monkeypatch.setenv('PHOENIX_JAN_API_KEY', 'placeholder')
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured.update(headers=headers)
        return Resp()

    monkeypatch.setattr(copilot.requests, 'post', fake_post)
    copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    assert 'Authorization' not in captured['headers']


def test_auto_falls_through_to_desktop_servers(monkeypatch, desktop_env):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'auto')
    monkeypatch.setattr(copilot, 'ollama_reachable', lambda timeout=1.5: False)
    monkeypatch.setattr(copilot, 'llamacpp_reachable', lambda timeout=1.5: False)
    up = set()
    monkeypatch.setattr(copilot, 'desktop_reachable', lambda name, timeout=1.5: name in up)
    assert copilot.provider_name() == 'ollama'
    up.add('jan')
    assert copilot.provider_name() == 'jan'
    up.add('lmstudio')
    assert copilot.provider_name() == 'lmstudio'
    assert copilot.llm_reachable('jan') is True


def test_desktop_server_on_public_host_is_refused(monkeypatch, network, desktop_env):
    monkeypatch.setenv('PHOENIX_LLM_PROVIDER', 'lmstudio')
    monkeypatch.setenv('PHOENIX_LMSTUDIO_URL', 'https://lmstudio.example.com/v1')
    monkeypatch.setenv('PHOENIX_LMSTUDIO_MODEL', 'm')
    with pytest.raises(copilot.CopilotError, match='PHOENIX_ALLOW_CLOUD_LLM'):
        copilot.CopilotClient().chat([{'role': 'user', 'content': 'x'}])
    assert network == []


def test_desktop_model_discovery_never_leaves_the_host(monkeypatch, desktop_env):
    calls = []
    monkeypatch.setattr(copilot.requests, 'get', lambda *a, **k: calls.append(a) or ModelsResp(['x']))
    monkeypatch.setenv('PHOENIX_JAN_URL', 'https://jan.example.com/v1')
    assert copilot.desktop_model('jan') == copilot.DEFAULT_DESKTOP_MODEL
    assert calls == []
