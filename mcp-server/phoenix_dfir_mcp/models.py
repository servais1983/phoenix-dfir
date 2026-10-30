"""Pick the best local model for each role of the investigation.

Phoenix asks the LLM for four kinds of work:

- ``investigator``: drives the tools (five phases or loop, independent
  verification). Needs reliable tool calling and a large context.
- ``reviewer``: the adviser review of the final report. No tools; benefits from
  the strongest reasoning model available.
- ``extractor``: the quarantined dual-LLM extractor. Short JSON outputs, called
  once per tool result: a fast mid-sized model is enough.
- ``analyst``: the file analysis of the web console. Plain text answers.

The local server (Ollama, llama.cpp, LM Studio or Jan) is asked which models it
has, and each one is scored for each role from its name: model family (known
tool calling quality), parameter count, and kind (embedding, vision, reasoning,
coder). The ranking is deterministic: same list, same choice. An explicit
variable always wins:

- ``PHOENIX_LLM_MODEL_<ROLE>`` for one role (``PHOENIX_EXTRACTOR_MODEL`` also
  works for the extractor);
- the provider variable (``PHOENIX_OLLAMA_MODEL``, ``PHOENIX_LMSTUDIO_MODEL``...)
  for every role.

``PHOENIX_LLM_MAX_PARAMS_B`` (default 32) caps the size considered comfortable
on the machine: bigger models are ranked down, never excluded.

Model discovery only talks to local hosts (``copilot.is_local_url``). Nothing
is ever downloaded.
"""

import os
import re
import threading
import time

import requests

from . import copilot

ROLES = ('investigator', 'reviewer', 'extractor', 'analyst')
DEFAULT_MAX_PARAMS_B = 32.0

# Families ranked by tool calling and instruction following quality on DFIR
# style work (structured arguments, long tool outputs, JSON).
FAMILIES = (
    ('gpt-oss', 95), ('qwen3', 93), ('qwen2.5', 88), ('qwen2', 74), ('llama-3.3', 87), ('llama3.3', 87),
    ('llama-3.1', 84), ('llama3.1', 84), ('mistral-small', 85), ('devstral', 83), ('mistral-nemo', 80),
    ('hermes-3', 82), ('hermes3', 82), ('command-r', 78), ('granite-3', 76), ('granite3', 76),
    ('llama-3.2', 70), ('llama3.2', 70), ('phi-4', 66), ('phi4', 66), ('gemma-3', 62), ('gemma3', 62),
    ('deepseek-r1', 58), ('qwq', 60), ('mistral', 70), ('llama-3', 68), ('llama3', 68),
)
UNKNOWN_FAMILY = 45
EXCLUDED = ('embed', 'embedding', 'bge-', 'e5-', 'nomic', 'rerank', 'whisper', 'tts', 'clip', 'minilm')
VISION = ('llava', 'vision', '-vl', 'moondream', 'bakllava')
REASONING = ('deepseek-r1', 'qwq', 'gpt-oss', 'thinking', 'reasoning', '-r1')
_PARAMS = re.compile(r'(?<![\d.])(\d+(?:\.\d+)?)\s*[bB](?![a-zA-Z])')
_MOE_ACTIVE = re.compile(r'-a(\d+(?:\.\d+)?)b', re.I)

_cache_lock = threading.Lock()
_cache = {}  # url -> (timestamp, [model ids])
_CACHE_TTL = 60


def max_params():
    try:
        return max(1.0, float(os.environ.get('PHOENIX_LLM_MAX_PARAMS_B', DEFAULT_MAX_PARAMS_B)))
    except ValueError:
        return DEFAULT_MAX_PARAMS_B


def profile(name):
    """What the model name tells: family score, size in billions, kind flags."""
    low = name.lower()
    family, family_score = None, UNKNOWN_FAMILY
    for key, score in FAMILIES:
        if key in low:
            family, family_score = key, score
            break
    sizes = [float(x) for x in _PARAMS.findall(low.replace('_', '-'))]
    active = _MOE_ACTIVE.search(low)
    total = max(sizes) if sizes else None
    return {
        'name': name,
        'family': family,
        'family_score': family_score,
        'params_b': total,
        'active_params_b': float(active.group(1)) if active else None,
        'excluded': any(k in low for k in EXCLUDED),
        'vision_only': any(k in low for k in VISION) and 'instruct' not in low,
        'reasoning': any(k in low for k in REASONING),
        'coder': 'coder' in low or 'devstral' in low,
        'base': bool(re.search(r'(^|[-_:/])base($|[-_:.])', low)) and 'instruct' not in low,
    }


def score(name, role):
    """Suitability of a model for a role (higher is better, None = unusable)."""
    p = profile(name)
    if p['excluded'] or p['vision_only'] or p['base'] or role not in ROLES:
        return None
    s = float(p['family_score'])
    cap = max_params()
    size = p['params_b']
    # Mixture of experts runs at the speed of its active parameters
    speed_size = p['active_params_b'] or size
    if role in ('investigator', 'analyst', 'reviewer'):
        if size is not None:
            s += 20.0 * min(size, cap) / cap
            if size > cap:
                s -= 30.0
        if role == 'investigator' and p['reasoning'] and p['family'] in ('deepseek-r1', 'qwq'):
            s -= 15.0  # long hidden reasoning, weak tool calling
        if role == 'reviewer' and p['reasoning']:
            s += 10.0
        if role == 'analyst' and p['coder']:
            s -= 3.0
    elif role == 'extractor':
        if p['reasoning'] and p['family'] in ('deepseek-r1', 'qwq'):
            s -= 20.0
        if speed_size is not None:
            # Sweet spot 3 to 14 billion parameters: fast, still reliable JSON
            if speed_size < 3:
                s -= 10.0
            elif speed_size <= 14:
                s += 10.0
            elif speed_size > 20:
                s -= 10.0
        if size is not None and size > cap:
            s -= 30.0
    return round(s, 2)


def rank(names, role):
    """Usable models for a role, best first (ties broken by name)."""
    scored = [(score(n, role), n) for n in names]
    return [(n, s) for s, n in sorted((x for x in scored if x[0] is not None), key=lambda x: (-x[0], x[1]))]


def _list_url(provider):
    if provider == 'ollama':
        return f'{copilot.ollama_base_url()}/api/tags'
    if provider == 'llamacpp':
        return f'{copilot.llamacpp_base_url()}/models'
    if provider in copilot.DESKTOP_SERVERS:
        return f'{copilot.desktop_base_url(provider)}/models'
    return None


def list_models(provider, timeout=2.0, refresh=False):
    """Model names the local server reports ([] if unreachable or not local)."""
    url = _list_url(provider)
    if not url or not copilot.is_local_url(url):
        return []
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(url)
        if hit and not refresh and now - hit[0] < _CACHE_TTL:
            return list(hit[1])
    headers = {}
    if provider in copilot.DESKTOP_SERVERS:
        token = copilot._desktop_token(provider)
        if token:
            headers['Authorization'] = f'Bearer {token}'
    names = []
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            if provider == 'ollama':
                names = [m.get('name') or m.get('model') for m in data.get('models', []) if isinstance(m, dict)]
            else:
                names = [m.get('id') for m in data.get('data', []) if isinstance(m, dict)]
    except (requests.RequestException, ValueError, AttributeError, TypeError):
        names = []
    names = sorted({n for n in names if isinstance(n, str) and n.strip()})
    with _cache_lock:
        _cache[url] = (now, names)
    return list(names)


def _role_env(role):
    value = os.environ.get(f'PHOENIX_LLM_MODEL_{role.upper()}', '').strip()
    if not value and role == 'extractor':
        value = os.environ.get('PHOENIX_EXTRACTOR_MODEL', '').strip()
    return value


def _provider_env(provider):
    var = {'ollama': 'PHOENIX_OLLAMA_MODEL', 'llamacpp': 'PHOENIX_LLAMACPP_MODEL',
           'openai': 'PHOENIX_OPENAI_MODEL', 'github': 'PHOENIX_GITHUB_MODEL'}.get(provider)
    if provider in copilot.DESKTOP_SERVERS:
        var = copilot.DESKTOP_SERVERS[provider]['model_env']
    return os.environ.get(var, '').strip() if var else ''


def choose(provider, role, available=None):
    """(model, source) for a role. source: role-env, provider-env, auto or default."""
    explicit = _role_env(role)
    if explicit:
        return explicit, 'role-env'
    explicit = _provider_env(provider)
    if explicit:
        return explicit, 'provider-env'
    if provider in copilot.LOCAL_PROVIDERS:
        names = list_models(provider) if available is None else available
        ranked = rank(names, role)
        if ranked:
            return ranked[0][0], 'auto'
    return copilot.static_default_model(provider), 'default'


def select(provider=None, role='investigator'):
    """The model name to use for a role."""
    return choose(provider or copilot.provider_name(), role)[0]


def plan(provider=None):
    """Model chosen for every role, with the top candidates (doctor, API, CLI)."""
    provider = provider or copilot.provider_name()
    available = list_models(provider) if provider in copilot.LOCAL_PROVIDERS else []
    roles = {}
    for role in ROLES:
        model, source = choose(provider, role, available)
        roles[role] = {'model': model, 'source': source, 'score': score(model, role),
                       'candidates': [{'model': n, 'score': s} for n, s in rank(available, role)[:3]]}
    return {'provider': provider, 'label': copilot.provider_label(provider), 'available': available,
            'max_params_b': max_params(), 'roles': roles}


PROBE_TOOL = {'type': 'function', 'function': {
    'name': 'record_check', 'description': 'Record the check result.',
    'parameters': {'type': 'object', 'properties': {'status': {'type': 'string', 'enum': ['ok']}},
                   'required': ['status']}}}


def probe_tool_calling(provider, model, timeout=120):
    """Ask the model for one tool call. Returns {'ok': bool, 'detail': str, 'seconds': float}."""
    started = time.monotonic()
    try:
        client = copilot.CopilotClient(provider=provider, model=model, timeout=timeout)
        msg = client.chat([{'role': 'system', 'content': 'You call tools when asked.'},
                           {'role': 'user', 'content': 'Call record_check with status "ok". No prose.'}],
                          tools=[PROBE_TOOL])
    except copilot.CopilotError as e:
        return {'ok': False, 'detail': str(e)[:300], 'seconds': round(time.monotonic() - started, 2)}
    calls = msg.get('tool_calls') or []
    ok = any(((c.get('function') or {}).get('name') == 'record_check') for c in calls if isinstance(c, dict))
    detail = 'tool call returned' if ok else f"no tool call (answer: {str(msg.get('content') or '')[:120]!r})"
    return {'ok': ok, 'detail': detail, 'seconds': round(time.monotonic() - started, 2)}
