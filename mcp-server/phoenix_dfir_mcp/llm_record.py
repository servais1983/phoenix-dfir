"""Record the answers of a local LLM once, replay them without any model.

``phoenix eval --record answers.jsonl`` runs the investigator on a real local
model (Ollama, llama.cpp, LM Studio, Jan) and writes every chat answer to a
JSON Lines file. ``phoenix eval --replay answers.jsonl`` runs the same
investigation again with no model: each chat call gets the recorded answer
of the same case, role and rank. The tools still run for real on the case, so
the verifier, the gates and the criteria are measured on the actual evidence.

The case is copied to a different temporary folder at each run: its path is
stored as ``{{CASE_DIR}}`` and restored on replay. A call with no recorded
answer, or of another role than the recording, stops with an error: a replay
never makes an answer up.
"""

import contextlib
import contextvars
import datetime
import hashlib
import json
import os
import threading

from . import __version__

CASE_TOKEN = '{{CASE_DIR}}'
_scope = contextvars.ContextVar('phoenix_llm_record_scope', default=None)
_lock = threading.Lock()


class ReplayError(RuntimeError):
    """No recorded answer for this call: the replay diverged from the recording."""


def _escaped(path):
    return json.dumps(str(path))[1:-1]


def _key(case, role, index):
    return f'{case}\x1f{role}\x1f{index}'


class _Scope:
    def __init__(self, case, case_dir, record_path=None, replay=None):
        self.case = case
        self.case_dir = os.path.abspath(case_dir) if case_dir else None
        self.record_path = record_path
        self.replay = replay
        self.counters = {}

    def next_index(self, role):
        with _lock:
            self.counters[role] = self.counters.get(role, 0) + 1
            return self.counters[role]

    def _to_token(self, text):
        if not self.case_dir:
            return text
        for path in sorted({os.path.realpath(self.case_dir), self.case_dir}, key=len, reverse=True):
            text = text.replace(_escaped(path), CASE_TOKEN)
        return text

    def _from_token(self, text):
        return text.replace(CASE_TOKEN, _escaped(self.case_dir)) if self.case_dir else text

    def write(self, role, index, model, messages, message, usage):
        line = {'case': self.case, 'role': role, 'index': index, 'model': model,
                'request_sha256': hashlib.sha256(self._to_token(json.dumps(messages, sort_keys=True,
                                                                           default=str)).encode()).hexdigest(),
                'message': json.loads(self._to_token(json.dumps(message, default=str))),
                'usage': usage or {}}
        with _lock, open(self.record_path, 'a', encoding='utf-8', newline='\n') as f:
            f.write(json.dumps(line, ensure_ascii=False, sort_keys=True) + '\n')

    def read(self, role, index):
        entry = self.replay.get(_key(self.case, role, index))
        if entry is None:
            raise ReplayError(f'no recorded answer for case {self.case!r}, role {role!r}, call {index}: '
                              'the replay diverged from the recording')
        message = json.loads(self._from_token(json.dumps(entry['message'])))
        return message, entry.get('usage') or {}, entry.get('model')


def load(path):
    """Recorded answers by (case, role, index)."""
    answers = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if 'message' in entry:
                answers[_key(entry.get('case', ''), entry['role'], entry['index'])] = entry
    return answers


def start_recording(path, **header):
    """Create the recording file with a header line (version, time, provider...)."""
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(json.dumps({'phoenix': __version__, 'recorded_at': datetime.datetime.now(
            datetime.timezone.utc).isoformat(timespec='seconds'), **header}, sort_keys=True) + '\n')


@contextlib.contextmanager
def scope(case, case_dir, record_path=None, replay=None):
    """Record (``record_path``) or replay (``replay``: dict from ``load``) the chats of one case."""
    token = _scope.set(_Scope(case, case_dir, record_path, replay))
    try:
        yield
    finally:
        _scope.reset(token)


def active():
    return _scope.get()
