"""Where Phoenix keeps its own data (database, evidence vault) on each OS.

- An explicit variable always wins (PHOENIX_DB_PATH, PHOENIX_EVIDENCE_VAULT,
  PHOENIX_DATA_DIR).
- A source checkout (pyproject.toml next to backend/) keeps its historical
  locations inside the repository.
- An installed package uses the per-user data folder of the OS (platformdirs):
  %LOCALAPPDATA%\\phoenix-dfir on Windows, ~/Library/Application Support/phoenix-dfir
  on macOS, ~/.local/share/phoenix-dfir on Linux.
"""

import os
from pathlib import Path

APP_NAME = 'phoenix-dfir'
BACKEND_DIR = Path(__file__).resolve().parent
REPO_ROOT = BACKEND_DIR.parent


def is_source_checkout():
    return (REPO_ROOT / 'pyproject.toml').is_file() and (REPO_ROOT / 'backend').is_dir()


def data_dir():
    """Per-user data folder (created on demand)."""
    explicit = os.environ.get('PHOENIX_DATA_DIR', '').strip()
    if explicit:
        path = Path(explicit)
    else:
        try:
            import platformdirs
            path = Path(platformdirs.user_data_dir(APP_NAME, appauthor=False))
        except ImportError:  # pragma: no cover - platformdirs is a core dependency
            path = Path.home() / f'.{APP_NAME}'
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_db_path():
    explicit = os.environ.get('PHOENIX_DB_PATH', '').strip()
    if explicit:
        return explicit
    if is_source_checkout():
        return str(BACKEND_DIR / 'phoenix.db')
    return str(data_dir() / 'phoenix.db')


def default_vault_dir():
    explicit = os.environ.get('PHOENIX_EVIDENCE_VAULT', '').strip()
    if explicit:
        return explicit
    if is_source_checkout():
        return str(REPO_ROOT / 'evidence_vault')
    return str(data_dir() / 'evidence_vault')
