"""Where tools write derived data (extracted files, carved payloads).

Tools never choose this location themselves: they ask ``derived_root``.

- inside ``derived_scope(path)`` (used by the deterministic triage), derived
  data goes to that folder, outside the case;
- for a case with the standard layout (an ``evidence`` sub folder), it goes
  to ``<case>/derived``;
- otherwise (flat legacy case folder), it goes to the case folder itself, as
  before.
"""

import contextlib
import contextvars
import os

EVIDENCE_DIR = 'evidence'
DERIVED_DIR = 'derived'

_override = contextvars.ContextVar('phoenix_derived_root', default=None)


def has_layout(case_dir):
    """Does the case use the standard layout (evidence/ sub folder)?"""
    return bool(case_dir) and os.path.isdir(os.path.join(case_dir, EVIDENCE_DIR))


def derived_root(case_dir):
    """Absolute folder that receives the derived data of this case."""
    override = _override.get()
    if override:
        return override
    case_dir = os.path.abspath(case_dir)
    if has_layout(case_dir):
        return os.path.join(case_dir, DERIVED_DIR)
    return case_dir


@contextlib.contextmanager
def derived_scope(path):
    """Send derived data to `path` for the duration of the block."""
    path = os.path.abspath(path)
    os.makedirs(path, exist_ok=True)
    token = _override.set(path)
    try:
        yield path
    finally:
        _override.reset(token)


def rel(path, case_dir):
    """Path of a derived file as reported to the investigator (posix style).

    Relative to the case when it lives inside it, else relative to the
    derived root.
    """
    path = os.path.abspath(path)
    case_dir = os.path.abspath(case_dir)
    try:
        inside = os.path.commonpath([os.path.normcase(path), os.path.normcase(case_dir)]) == os.path.normcase(case_dir)
    except ValueError:  # different drives on Windows
        inside = False
    base = case_dir if inside else derived_root(case_dir)
    return os.path.relpath(path, base).replace(os.sep, '/')
