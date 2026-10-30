"""LLM client for the investigator: chat completions with function calling.

Local first. Every provider speaks the OpenAI chat completions format:

- 'ollama' (default): local Ollama server (OLLAMA_BASE_URL, default
  http://localhost:11434; PHOENIX_OLLAMA_MODEL).
- 'llamacpp': local llama.cpp server (PHOENIX_LLAMACPP_URL, default
  http://127.0.0.1:8080/v1; PHOENIX_LLAMACPP_MODEL).
- 'auto': the first reachable local server (Ollama, then llama.cpp). It never
  selects a cloud provider.
- 'openai' and 'github' (GitHub Models): cloud providers. They are refused
  unless PHOENIX_ALLOW_CLOUD_LLM=1, and the first call of each client records
  a consent entry in the custody ledger. There is never an automatic cloud
  fallback.

A local provider pointed at a public host is treated like a cloud provider:
only loopback, private and link-local addresses, single-label host names
(container services), host.docker.internal and the hosts listed in
PHOENIX_LLM_LOCAL_HOSTS are considered local.

Calls are deterministic by default (temperature 0, PHOENIX_LLM_SEED) and
transient failures are retried at most twice with exponential backoff.

Selection: PHOENIX_LLM_PROVIDER=ollama|llamacpp|auto|openai|github.
"""

import ipaddress
import os
import threading
import time
from urllib.parse import urlsplit

import requests

DEFAULT_MODEL = 'openai/gpt-4o-mini'
DEFAULT_URL = 'https://models.github.ai/inference/chat/completions'

DEFAULT_OLLAMA_URL = 'http://localhost:11434'
DEFAULT_OLLAMA_MODEL = 'qwen2.5-coder:14b'

DEFAULT_LLAMACPP_URL = 'http://127.0.0.1:8080/v1'
DEFAULT_LLAMACPP_MODEL = 'local'

DEFAULT_OPENAI_URL = 'https://api.openai.com/v1'
DEFAULT_OPENAI_MODEL = 'gpt-4o-mini'

LOCAL_PROVIDERS = ('ollama', 'llamacpp')
CLOUD_PROVIDERS = ('openai', 'github')
PROVIDERS = LOCAL_PROVIDERS + CLOUD_PROVIDERS
DEFAULT_PROVIDER = 'ollama'

DEFAULT_SEED = 42
MAX_ATTEMPTS = 3  # one call plus at most two retries
_RETRY_STATUS = (408, 425, 429, 500, 502, 503, 504)
_LOCAL_SUFFIXES = ('.local', '.internal', '.lan', '.home.arpa', '.localhost')
# Private ranges only (RFC 1918 and IPv6 ULA): ipaddress.is_private also
# accepts documentation and reserved ranges, which are not the local network.
_PRIVATE_NETS = tuple(ipaddress.ip_network(n) for n in
                      ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7'))

_PROBE_TTL = 60
_probe_lock = threading.Lock()
_probe_cache = {}  # url -> (timestamp, reachable)


def _probe(url, timeout):
    now = time.monotonic()
    with _probe_lock:
        cached = _probe_cache.get(url)
        if cached and now - cached[0] < _PROBE_TTL:
            return cached[1]
    ok = False
    if is_local_url(url):
        try:
            ok = requests.get(url, timeout=timeout).status_code == 200
        except requests.RequestException:
            ok = False
    with _probe_lock:
        _probe_cache[url] = (now, ok)
    return ok


def ollama_reachable(timeout=1.5):
    """Does the Ollama server answer? (cached for 60 s)"""
    return _probe(f'{ollama_base_url()}/api/tags', timeout)


def llamacpp_reachable(timeout=1.5):
    """Does the llama.cpp server answer? (cached for 60 s)"""
    return _probe(f'{llamacpp_base_url()}/models', timeout)


def _github_token():
    return os.environ.get('PHOENIX_GITHUB_TOKEN') or os.environ.get('GITHUB_TOKEN', '')


def cloud_allowed():
    """Has the operator explicitly allowed cloud LLM providers?"""
    return os.environ.get('PHOENIX_ALLOW_CLOUD_LLM', '').strip() == '1'


def _extra_local_hosts():
    raw = os.environ.get('PHOENIX_LLM_LOCAL_HOSTS', '')
    return {h.strip().lower() for h in raw.split(',') if h.strip()}


def is_local_url(url):
    """Is the URL served from this host or the investigation network?"""
    host = (urlsplit(url).hostname or '').lower().rstrip('.')
    if not host:
        return False
    if host in _extra_local_hosts() or host in ('localhost', 'host.docker.internal'):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return '.' not in host or host.endswith(_LOCAL_SUFFIXES)
    if getattr(addr, 'ipv4_mapped', None):
        addr = addr.ipv4_mapped
    return (addr.is_loopback or addr.is_link_local
            or any(addr.version == net.version and addr in net for net in _PRIVATE_NETS))


def requested_provider():
    provider = os.environ.get('PHOENIX_LLM_PROVIDER', DEFAULT_PROVIDER).strip().lower()
    return provider if provider in PROVIDERS + ('auto',) else DEFAULT_PROVIDER


def provider_name():
    """Effective provider. 'auto' resolves to a reachable local server only."""
    provider = requested_provider()
    if provider != 'auto':
        return provider
    if ollama_reachable():
        return 'ollama'
    if llamacpp_reachable():
        return 'llamacpp'
    return DEFAULT_PROVIDER


def llm_reachable(provider=None):
    """Can a call be attempted now? Local: the server answers. Cloud: opted in and configured."""
    provider = provider or provider_name()
    if provider == 'ollama':
        return ollama_reachable()
    if provider == 'llamacpp':
        return llamacpp_reachable()
    return is_configured(provider)


def is_cloud(provider=None):
    return (provider or provider_name()) in CLOUD_PROVIDERS


def default_model(provider=None):
    provider = provider or provider_name()
    if provider == 'ollama':
        return os.environ.get('PHOENIX_OLLAMA_MODEL', DEFAULT_OLLAMA_MODEL)
    if provider == 'llamacpp':
        return os.environ.get('PHOENIX_LLAMACPP_MODEL', DEFAULT_LLAMACPP_MODEL)
    if provider == 'openai':
        return os.environ.get('PHOENIX_OPENAI_MODEL', DEFAULT_OPENAI_MODEL)
    return os.environ.get('PHOENIX_GITHUB_MODEL', DEFAULT_MODEL)


def ollama_base_url():
    return os.environ.get('OLLAMA_BASE_URL', DEFAULT_OLLAMA_URL).rstrip('/')


def llamacpp_base_url():
    return os.environ.get('PHOENIX_LLAMACPP_URL', DEFAULT_LLAMACPP_URL).rstrip('/')


def llm_seed():
    try:
        return int(os.environ.get('PHOENIX_LLM_SEED', DEFAULT_SEED))
    except ValueError:
        return DEFAULT_SEED


def _retry_backoff():
    try:
        return max(0.0, float(os.environ.get('PHOENIX_LLM_RETRY_BACKOFF', '1')))
    except ValueError:
        return 1.0


def is_configured(provider=None):
    """Can the provider be used right now?

    Local providers need no secret, only a URL (always set by default).
    Cloud providers need PHOENIX_ALLOW_CLOUD_LLM=1 and their key.
    """
    provider = provider or provider_name()
    if provider == 'ollama':
        return bool(ollama_base_url())
    if provider == 'llamacpp':
        return bool(llamacpp_base_url())
    if not cloud_allowed():
        return False
    if provider == 'openai':
        return bool(os.environ.get('OPENAI_API_KEY'))
    return bool(_github_token())


def provider_label(provider=None):
    return {'ollama': 'Ollama (local LLM)', 'llamacpp': 'llama.cpp (local LLM)',
            'openai': 'OpenAI (cloud)'}.get(provider or provider_name(), 'GitHub Models (cloud)')


def _record_cloud_consent(client):
    """Record the cloud LLM consent in the custody ledger (fail closed)."""
    try:
        from . import ledger, pathpolicy
        ledger.record(
            'llm_cloud_consent', 'phoenix-llm', agent='copilot',
            artifact_ref=pathpolicy.current_case() or '',
            summary=f'Cloud LLM {client.label} enabled by PHOENIX_ALLOW_CLOUD_LLM=1 (model {client.model})',
            details={'provider': client.provider, 'model': client.model,
                     'host': urlsplit(client.url).hostname or '', 'opt_in': 'PHOENIX_ALLOW_CLOUD_LLM'})
    except Exception as e:
        raise CopilotError(f'Cloud LLM refused: the consent could not be recorded in the ledger ({e}).') from e


class CopilotError(RuntimeError):
    """LLM call error (configuration or network)."""


class CopilotClient:
    """Minimal chat completions client (Ollama, llama.cpp, or opted-in cloud)."""

    def __init__(self, model=None, token=None, url=None, timeout=None, provider=None):
        self.provider = provider or provider_name()
        if self.provider == 'ollama':
            self.token = token or ''
            self.url = url or f'{ollama_base_url()}/v1/chat/completions'
            # Local models are slower: more generous timeout
            self.timeout = timeout or 600
        elif self.provider == 'llamacpp':
            self.token = token or ''
            self.url = url or f'{llamacpp_base_url()}/chat/completions'
            self.timeout = timeout or 600
        elif self.provider == 'openai':
            self.token = token or os.environ.get('OPENAI_API_KEY', '')
            base = os.environ.get('OPENAI_BASE_URL', DEFAULT_OPENAI_URL).rstrip('/')
            self.url = url or f'{base}/chat/completions'
            self.timeout = timeout or 180
        else:
            self.token = token or _github_token()
            self.url = url or os.environ.get('PHOENIX_GITHUB_MODELS_URL', DEFAULT_URL)
            self.timeout = timeout or 180
        self.model = model or default_model(self.provider)
        self._consent_recorded = False
        # Observability: cumulated token usage, to trace the cost of an investigation.
        self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}

    @property
    def label(self):
        return provider_label(self.provider)

    def chat(self, messages, tools=None, model=None, temperature=None, response_format=None):
        """Send a conversation and return the assistant message (dict).

        The message may hold 'content' and/or 'tool_calls' (OpenAI function
        calling format). An explicit `model` selects a stronger model for one
        pass (for example the adviser review). `temperature` defaults to 0;
        `response_format` constrains the output to a JSON schema (dualllm.py).
        """
        self._check_allowed()
        payload = {'model': model or self.model, 'messages': messages,
                   'temperature': 0 if temperature is None else temperature, 'seed': llm_seed()}
        if tools:
            payload['tools'] = tools
        if response_format:
            payload['response_format'] = response_format
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        data = self._post(headers, payload)
        try:
            message = data['choices'][0]['message']
        except (KeyError, IndexError, TypeError) as e:
            raise CopilotError(f'Unexpected {self.label} response: {e}') from e
        self._track_usage(data.get('usage'))
        return message

    def _check_allowed(self):
        """Refuse any call that would leave the investigation network without opt-in."""
        remote = self.provider in CLOUD_PROVIDERS or not is_local_url(self.url)
        if remote and not cloud_allowed():
            raise CopilotError(
                f'{self.label} refused: {urlsplit(self.url).hostname or self.url} is not a local host. '
                'Cloud LLMs require PHOENIX_ALLOW_CLOUD_LLM=1 and a recorded consent; '
                'the default is a local LLM (PHOENIX_LLM_PROVIDER=ollama or llamacpp).')
        if self.provider == 'github' and not self.token:
            raise CopilotError(
                'GitHub Models is not configured: set GITHUB_TOKEN or PHOENIX_GITHUB_TOKEN '
                '(fine-grained PAT with the Models: read permission), '
                'or use a local LLM with PHOENIX_LLM_PROVIDER=ollama.')
        if self.provider == 'openai' and not self.token:
            raise CopilotError('OpenAI is not configured: set OPENAI_API_KEY.')
        if remote and not self._consent_recorded:
            _record_cloud_consent(self)
            self._consent_recorded = True

    def _post(self, headers, payload):
        """POST with at most two retries on transient failures (backoff 1 s, 2 s)."""
        backoff = _retry_backoff()
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                resp = requests.post(self.url, headers=headers, json=payload, timeout=self.timeout)
                resp.raise_for_status()
                return resp.json()
            except requests.HTTPError as e:
                status = getattr(e.response, 'status_code', None)
                if status not in _RETRY_STATUS or attempt == MAX_ATTEMPTS:
                    raise CopilotError(f'{self.label} call failed: {e}') from e
            except (requests.ConnectionError, requests.Timeout) as e:
                if attempt == MAX_ATTEMPTS:
                    raise CopilotError(f'{self.label} call failed: {e}') from e
            except requests.RequestException as e:
                raise CopilotError(f'{self.label} call failed: {e}') from e
            except ValueError as e:
                raise CopilotError(f'Unexpected {self.label} response: {e}') from e
            time.sleep(backoff * (2 ** (attempt - 1)))
        raise CopilotError(f'{self.label} call failed')  # pragma: no cover

    def _track_usage(self, usage):
        self.usage['calls'] += 1
        if isinstance(usage, dict):
            for key in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
                self.usage[key] += int(usage.get(key) or 0)
