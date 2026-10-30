"""Per-OS data locations (datadirs.py): no hardcoded Unix path."""

from pathlib import Path

import datadirs
import evidence_vault


def test_source_checkout_keeps_repository_locations(monkeypatch):
    for var in ('PHOENIX_DB_PATH', 'PHOENIX_EVIDENCE_VAULT', 'PHOENIX_DATA_DIR'):
        monkeypatch.delenv(var, raising=False)
    assert datadirs.is_source_checkout()
    assert Path(datadirs.default_db_path()) == datadirs.BACKEND_DIR / 'phoenix.db'
    assert Path(evidence_vault.vault_dir()) == datadirs.REPO_ROOT / 'evidence_vault'


def test_installed_package_uses_the_user_data_folder(monkeypatch, tmp_path):
    for var in ('PHOENIX_DB_PATH', 'PHOENIX_EVIDENCE_VAULT'):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(datadirs, 'REPO_ROOT', tmp_path / 'site-packages')
    monkeypatch.setenv('PHOENIX_DATA_DIR', str(tmp_path / 'data'))
    assert not datadirs.is_source_checkout()
    assert Path(datadirs.default_db_path()) == tmp_path / 'data' / 'phoenix.db'
    assert Path(evidence_vault.vault_dir()) == tmp_path / 'data' / 'evidence_vault'
    assert (tmp_path / 'data').is_dir()


def test_platformdirs_default(monkeypatch, tmp_path):
    import platformdirs
    monkeypatch.delenv('PHOENIX_DATA_DIR', raising=False)
    monkeypatch.setattr(platformdirs, 'user_data_dir', lambda app, appauthor=None: str(tmp_path / app))
    assert datadirs.data_dir() == tmp_path / 'phoenix-dfir'


def test_explicit_variables_win(monkeypatch, tmp_path):
    monkeypatch.setenv('PHOENIX_DB_PATH', str(tmp_path / 'x.db'))
    monkeypatch.setenv('PHOENIX_EVIDENCE_VAULT', str(tmp_path / 'vault'))
    assert datadirs.default_db_path() == str(tmp_path / 'x.db')
    assert evidence_vault.vault_dir() == str(tmp_path / 'vault')


def test_no_hardcoded_unix_mount_in_backend():
    source = (datadirs.BACKEND_DIR / 'evidence_vault.py').read_text(encoding='utf-8')
    assert "'/mnt" not in source and '"/mnt' not in source


def test_runtime_folders_leave_the_installed_package(monkeypatch, tmp_path):
    monkeypatch.setattr(datadirs, 'REPO_ROOT', tmp_path / 'site-packages')
    monkeypatch.setenv('PHOENIX_DATA_DIR', str(tmp_path / 'data'))
    for name in ('uploads', 'reports', 'sessions', 'evidence_inbox'):
        assert Path(datadirs.runtime_dir(name)) == tmp_path / 'data' / name
    assert Path(datadirs.secret_key_file()) == tmp_path / 'data' / '.secret_key'


def test_runtime_folders_stay_in_a_checkout():
    assert Path(datadirs.runtime_dir('uploads')) == datadirs.BACKEND_DIR / 'uploads'
    assert Path(datadirs.secret_key_file()) == datadirs.BACKEND_DIR / '.secret_key'
