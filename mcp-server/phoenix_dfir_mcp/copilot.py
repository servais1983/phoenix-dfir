"""Client LLM de l'enqueteur : chat completions avec function calling.

Deux fournisseurs, meme format (OpenAI chat completions) :

- 'github' (defaut) : GitHub Copilot via l'API GitHub Models
  (https://docs.github.com/en/github-models), la meme integration que le
  reste de Phoenix : un jeton GitHub avec la permission "Models: read"
  suffit (GITHUB_TOKEN ou PHOENIX_GITHUB_TOKEN).
- 'ollama' : LLM local / air-gapped via l'API compatible OpenAI d'Ollama
  (https://ollama.com). Aucune donnee ne quitte le reseau d'investigation.
  OLLAMA_BASE_URL (defaut http://localhost:11434 ; en Docker Desktop :
  http://host.docker.internal:11434) et PHOENIX_OLLAMA_MODEL.

- 'openai' : API OpenAI (OPENAI_API_KEY, OPENAI_BASE_URL, PHOENIX_OPENAI_MODEL).
- 'auto' : HYBRIDE, confidentialite d'abord — Ollama s'il repond (local,
  air-gapped), sinon OpenAI si une cle est configuree, sinon GitHub Copilot.

Selection : PHOENIX_LLM_PROVIDER=github|ollama|openai|auto.
"""

import os
import threading
import time

import requests

DEFAULT_MODEL = 'openai/gpt-4o-mini'
DEFAULT_URL = 'https://models.github.ai/inference/chat/completions'

DEFAULT_OLLAMA_URL = 'http://localhost:11434'
DEFAULT_OLLAMA_MODEL = 'qwen2.5-coder:14b'

DEFAULT_OPENAI_URL = 'https://api.openai.com/v1'
DEFAULT_OPENAI_MODEL = 'gpt-4o-mini'

PROVIDERS = ('github', 'ollama', 'openai')
_PROBE_TTL = 60
_probe_lock = threading.Lock()
_probe_cache = {}  # url -> (horodatage, joignable)


def ollama_reachable(timeout=1.5):
    """Ollama repond-il ? (resultat mis en cache 60 s)"""
    url = ollama_base_url()
    now = time.monotonic()
    with _probe_lock:
        cached = _probe_cache.get(url)
        if cached and now - cached[0] < _PROBE_TTL:
            return cached[1]
    try:
        ok = requests.get(f'{url}/api/tags', timeout=timeout).status_code == 200
    except requests.RequestException:
        ok = False
    with _probe_lock:
        _probe_cache[url] = (now, ok)
    return ok


def _github_token():
    return os.environ.get('PHOENIX_GITHUB_TOKEN') or os.environ.get('GITHUB_TOKEN', '')


def requested_provider():
    provider = os.environ.get('PHOENIX_LLM_PROVIDER', 'github').strip().lower()
    return provider if provider in PROVIDERS + ('auto',) else 'github'


def provider_name():
    """Fournisseur LLM effectif ('auto' resolu : Ollama > OpenAI > GitHub)."""
    provider = requested_provider()
    if provider != 'auto':
        return provider
    if ollama_reachable():
        return 'ollama'
    if os.environ.get('OPENAI_API_KEY'):
        return 'openai'
    return 'github'


def default_model(provider=None):
    provider = provider or provider_name()
    if provider == 'ollama':
        return os.environ.get('PHOENIX_OLLAMA_MODEL', DEFAULT_OLLAMA_MODEL)
    if provider == 'openai':
        return os.environ.get('PHOENIX_OPENAI_MODEL', DEFAULT_OPENAI_MODEL)
    return os.environ.get('PHOENIX_GITHUB_MODEL', DEFAULT_MODEL)


def ollama_base_url():
    return os.environ.get('OLLAMA_BASE_URL', DEFAULT_OLLAMA_URL).rstrip('/')


def is_configured(provider=None):
    """Le fournisseur LLM est-il utilisable ?

    GitHub : un jeton est requis. Ollama : aucun secret, seule l'URL compte
    (toujours definie, avec une valeur par defaut).
    """
    provider = provider or provider_name()
    if provider == 'ollama':
        return bool(ollama_base_url())
    if provider == 'openai':
        return bool(os.environ.get('OPENAI_API_KEY'))
    return bool(_github_token())


def provider_label(provider=None):
    return {'ollama': 'Ollama (LLM local)', 'openai': 'OpenAI'}.get(
        provider or provider_name(), 'GitHub Copilot')


class CopilotError(RuntimeError):
    """Erreur d'appel au LLM (configuration ou reseau)."""


class CopilotClient:
    """Client minimal chat completions (GitHub Models ou Ollama)."""

    def __init__(self, model=None, token=None, url=None, timeout=None, provider=None):
        self.provider = provider or provider_name()
        if self.provider == 'ollama':
            self.token = token or ''
            self.url = url or f'{ollama_base_url()}/v1/chat/completions'
            # Les modeles locaux sont plus lents : delai plus genereux
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
        # Observabilite : consommation cumulee de tokens - permet de tracer le
        # cout d'une investigation.
        self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}

    @property
    def label(self):
        return provider_label(self.provider)

    def chat(self, messages, tools=None, model=None):
        """Envoyer une conversation, retourner le message assistant (dict).

        Le message retourne peut contenir 'content' et/ou 'tool_calls'
        (format OpenAI function calling). Un `model` explicite permet d'utiliser
        un modele plus puissant pour une passe donnee (ex: revue adviser).
        """
        if self.provider == 'github' and not self.token:
            raise CopilotError(
                "GitHub Copilot non configure : definissez un jeton GitHub via GITHUB_TOKEN "
                "ou PHOENIX_GITHUB_TOKEN (fine-grained PAT avec la permission Models: read), "
                "ou utilisez un LLM local avec PHOENIX_LLM_PROVIDER=ollama."
            )
        if self.provider == 'openai' and not self.token:
            raise CopilotError("OpenAI non configure : definissez OPENAI_API_KEY.")
        payload = {'model': model or self.model, 'messages': messages}
        if tools:
            payload['tools'] = tools
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        try:
            resp = requests.post(self.url, headers=headers, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
            self._track_usage(data.get('usage'))
            return data['choices'][0]['message']
        except requests.RequestException as e:
            raise CopilotError(f'Appel {self.label} echoue: {e}') from e
        except (KeyError, IndexError, ValueError) as e:
            raise CopilotError(f'Reponse {self.label} inattendue: {e}') from e

    def _track_usage(self, usage):
        self.usage['calls'] += 1
        if isinstance(usage, dict):
            for key in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
                self.usage[key] += int(usage.get(key) or 0)
