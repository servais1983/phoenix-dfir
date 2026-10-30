"""Locate the Phoenix backend modules used by the toolkit.

The toolkit reuses the backend parsers, MITRE mapping, Sigma engine and
custody ledger. They are flat modules (``import parsers``), so their folder
must be importable. It is resolved in this order:

1. ``PHOENIX_BACKEND_DIR`` when set;
2. the ``backend`` folder of a source checkout (or an editable install);
3. the ``phoenix_dfir_backend`` folder shipped in the installed wheel.

This is the only place that extends ``sys.path`` for the backend.
"""

import importlib.util
import os
import sys
from pathlib import Path


def _is_backend(path):
    return path is not None and (path / 'parsers.py').is_file() and (path / 'custody.py').is_file()


def backend_dir():
    """Return the backend folder as a resolved Path, or None if not found."""
    env = os.environ.get('PHOENIX_BACKEND_DIR', '').strip()
    if env and _is_backend(Path(env).resolve()):
        return Path(env).resolve()
    checkout = Path(__file__).resolve().parents[2] / 'backend'
    if _is_backend(checkout):
        return checkout
    spec = importlib.util.find_spec('phoenix_dfir_backend')
    if spec is not None and spec.submodule_search_locations:
        for location in spec.submodule_search_locations:
            if _is_backend(Path(location).resolve()):
                return Path(location).resolve()
    return None


def ensure_backend_importable():
    """Make the backend modules importable. Raise ImportError if missing."""
    path = backend_dir()
    if path is None:
        raise ImportError('Phoenix backend modules not found: set PHOENIX_BACKEND_DIR '
                          'or install the phoenix-dfir package.')
    entry = str(path)
    if not any(os.path.normcase(p) == os.path.normcase(entry) for p in sys.path):
        sys.path.insert(0, entry)
    return path
