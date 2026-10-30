"""Contracts of the agents: what an LLM may hand back, as Pydantic v2 models.

Every structured output of an LLM is validated against one of these models
before Phoenix uses it. The models are exported as JSON Schema
(``json_schemas``, ``phoenix schemas``), so a local server can also constrain
its output with them.

``ask_json`` is the only way an agent gets a structured answer: ``temperature``
0, the configured seed, the JSON Schema of the contract as response format, and
at most ``MAX_RETRIES`` (2) new attempts, each told the exact validation errors
of the previous answer. Token usage is logged per agent (``UsageLog``).
"""

import json
import re
import threading
from typing import Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

MAX_RETRIES = 2
REF_KINDS = ('record_id', 'pid', 'line', 'row', 'inode')
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
CONFIDENCES = ('confirmed', 'likely', 'possible')
VERDICTS = ('verified', 'unverified', 'refuted')
_TECHNIQUE = re.compile(r'^T\d{4}(?:\.\d{3})?$')
_TECHNIQUES_IN_TEXT = re.compile(r'T\d{4}(?:\.\d{3})?')


class _Contract(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class EvidenceRef(_Contract):
    """An identifier a tool extracted from an artifact."""
    artifact: str = Field(min_length=1, max_length=500, description='Path or name of the artifact')
    kind: Literal['record_id', 'pid', 'line', 'row', 'inode']
    value: Union[int, str] = Field(description='RecordID, PID, line or row number, inode (128-128-1)')

    @field_validator('value')
    @classmethod
    def _value(cls, v):
        text = str(v).strip()
        if not re.fullmatch(r'\d+(?:-\d+)*', text):
            raise ValueError('a reference value is a number (an NTFS inode may be 128-128-1)')
        return v


class Finding(_Contract):
    """A finding as an agent records it (``record_finding``)."""
    title: str = Field(min_length=1, max_length=300)
    severity: Literal['critical', 'high', 'medium', 'low', 'info'] = 'info'
    evidence: str = Field(default='', max_length=1000)
    mitre: str = Field(default='', max_length=120, description='ATT&CK technique(s), e.g. T1110.001')
    confidence: Literal['confirmed', 'likely', 'possible'] = 'possible'
    evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_length=20)

    @field_validator('mitre')
    @classmethod
    def _mitre(cls, v):
        text = (v or '').strip()
        if text and not _TECHNIQUES_IN_TEXT.search(text.upper()):
            raise ValueError("mitre must name an ATT&CK technique such as 'T1110.001'")
        return text


class Hypothesis(_Contract):
    """A competing hypothesis for one investigation question."""
    question: str = Field(min_length=1, max_length=200)
    statement: str = Field(min_length=1, max_length=500)
    techniques: list[str] = Field(default_factory=list, max_length=20)
    prior: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    rationale: str = Field(default='', max_length=1000)

    @field_validator('techniques')
    @classmethod
    def _techniques(cls, v):
        bad = [t for t in v if not _TECHNIQUE.match(str(t).strip().upper())]
        if bad:
            raise ValueError(f'not ATT&CK techniques: {bad[:5]}')
        return [str(t).strip().upper() for t in v]


class Verdict(_Contract):
    """Answer of the independent verification of one finding."""
    finding_id: int = Field(ge=1)
    verdict: Literal['verified', 'unverified', 'refuted']
    note: str = Field(default='', max_length=600)


class PhaseOutput(_Contract):
    """What a phase leaves behind (computed by Phoenix, never written by the LLM)."""
    phase: str
    agent: str
    passed: bool
    attempts: int = Field(ge=1)
    gaps: list[str] = Field(default_factory=list)
    findings: list[int] = Field(default_factory=list, description='Ids of the findings recorded so far')
    tokens: int = Field(default=0, ge=0)


# Quarantined extraction (dual LLM): same shape as dualllm.OUTPUT_SCHEMA
class _Ref(_Contract):
    artifact: str
    kind: Literal['record_id', 'pid', 'line', 'row', 'inode']
    value: str


class _Category(_Contract):
    category: Literal['authentication', 'process', 'network', 'file', 'registry', 'persistence',
                      'service', 'script', 'account', 'detection', 'other']
    count: int


class _Summary(_Contract):
    events_total: int
    by_category: list[_Category]


class _Entity(_Contract):
    type: Literal['ip', 'domain', 'user', 'host', 'process', 'file', 'hash']
    value: str
    ref: _Ref


class _Detection(_Contract):
    title: str
    technique: str
    severity: Literal['informational', 'low', 'medium', 'high', 'critical']
    ref: _Ref


class Extraction(_Contract):
    """Facts the quarantined extractor reads in one tool output."""
    summary: _Summary
    entities: list[_Entity]
    detections: list[_Detection]
    errors: list[str]


CONTRACTS = {
    'evidence_ref': EvidenceRef,
    'finding': Finding,
    'hypothesis': Hypothesis,
    'verdict': Verdict,
    'phase_output': PhaseOutput,
    'extraction': Extraction,
}


def json_schema(name):
    return CONTRACTS[name].model_json_schema()


def json_schemas():
    """Every contract as a JSON Schema (stable order)."""
    return {name: json_schema(name) for name in sorted(CONTRACTS)}


def errors_text(exc, limit=8):
    """Validation errors in a few lines the LLM can act on."""
    out = []
    for err in exc.errors()[:limit]:
        where = '.'.join(str(p) for p in err.get('loc', ())) or '(root)'
        out.append(f"- {where}: {err.get('msg')}")
    return '\n'.join(out)


def validate(name, data):
    """(model, None) or (None, errors text)."""
    try:
        return CONTRACTS[name].model_validate(data), None
    except ValidationError as e:
        return None, errors_text(e)


# ----------------------------------------------------------------------------
# Token usage per agent
# ----------------------------------------------------------------------------

class UsageLog:
    """Calls, retries, failures and tokens of each agent (thread safe)."""

    KEYS = ('calls', 'prompt_tokens', 'completion_tokens', 'total_tokens', 'retries', 'failures')

    def __init__(self):
        self._lock = threading.Lock()
        self._agents = {}

    def add(self, agent, before, after, retries=0, failed=False):
        before, after = before or {}, after or {}
        with self._lock:
            row = self._agents.setdefault(agent, dict.fromkeys(self.KEYS, 0))
            for key in ('calls', 'prompt_tokens', 'completion_tokens', 'total_tokens'):
                row[key] += max(0, int(after.get(key) or 0) - int(before.get(key) or 0))
            row['retries'] += retries
            row['failures'] += int(bool(failed))

    def snapshot(self):
        with self._lock:
            return {name: dict(row) for name, row in sorted(self._agents.items())}


def _parse(text):
    text = (text or '').strip()
    if text.startswith('```'):
        text = re.sub(r'^```(?:json)?\s*|\s*```$', '', text)
    return json.loads(text)


def response_format(name):
    return {'type': 'json_schema',
            'json_schema': {'name': f'phoenix_{name}', 'strict': True, 'schema': json_schema(name)}}


def ask_json(client, messages, contract, agent='agent', usage_log=None, retries=MAX_RETRIES,
             response_format_override=False, salvage=None, **chat_kwargs):
    """Ask ``client`` for a JSON answer that satisfies ``contract``.

    Returns ``(model or None, info)``: ``info`` has ``attempts``, ``errors``
    (one text per rejected answer) and ``error`` when every attempt failed.
    ``response_format_override`` False sends the contract JSON Schema; any
    other value (None included) is passed as the response format as is.
    ``salvage(data)`` True accepts an answer off contract without a new
    attempt: the caller then checks it field by field (``info['salvaged']``)."""
    retries = max(0, min(int(retries), MAX_RETRIES))
    fmt = response_format(contract) if response_format_override is False else response_format_override
    convo = list(messages)
    errors = []
    before = dict(getattr(client, 'usage', {}) or {})
    model, last_data = None, None
    for attempt in range(1, retries + 2):
        try:
            message = client.chat(convo, tools=None, temperature=0, response_format=fmt, **chat_kwargs) or {}
        except Exception as e:  # transport failure: not retried here, the caller degrades
            errors.append(f'{type(e).__name__}: {str(e)[:200]}')
            break
        content = message.get('content') or ''
        try:
            data = _parse(content)
        except (ValueError, TypeError) as e:
            problem = f'- (root): not valid JSON ({type(e).__name__})'
        else:
            last_data = data
            model, problem = validate(contract, data)
            if model is not None:
                break
            if salvage is not None and salvage(data):
                errors.append(problem)
                break
        errors.append(problem)
        if attempt <= retries:
            convo = convo + [{'role': 'assistant', 'content': content[:4000]},
                             {'role': 'user', 'content': (
                                 'Your answer does not follow the JSON contract. Errors:\n' + problem
                                 + '\nAnswer again with the corrected JSON object only.')}]
    info = {'attempts': len(errors) + (1 if model is not None else 0), 'errors': errors,
            'salvaged': model is None and salvage is not None and last_data is not None and salvage(last_data)}
    if model is None:
        info['error'] = errors[-1] if errors else 'no answer'
        info['last_data'] = last_data  # last parsed answer, for a caller that can salvage parts
    if usage_log is not None:
        usage_log.add(agent, before, dict(getattr(client, 'usage', {}) or {}),
                      retries=max(0, info['attempts'] - 1), failed=model is None)
    return model, info
