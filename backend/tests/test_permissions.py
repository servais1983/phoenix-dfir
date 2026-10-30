"""Best-effort owner-only permissions (auth.restrict_permissions)."""

import logging
import os
import stat
import sys

import pytest

import auth


@pytest.mark.skipif(sys.platform == 'win32', reason='POSIX permission bits')
def test_posix_permissions_are_restricted(tmp_path):
    key = tmp_path / '.secret_key'
    key.write_text('x', encoding='utf-8')
    os.chmod(key, 0o644)
    assert auth.restrict_permissions(str(key)) is True
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600


def test_windows_warns_instead_of_pretending(monkeypatch, tmp_path, caplog):
    key = tmp_path / '.secret_key'
    key.write_text('x', encoding='utf-8')
    monkeypatch.setattr(sys, 'platform', 'win32')
    with caplog.at_level(logging.WARNING, logger='phoenix'):
        assert auth.restrict_permissions(str(key)) is False
    assert 'not enforced on Windows' in caplog.text


def test_chmod_failure_is_reported(monkeypatch, tmp_path, caplog):
    def refuse(path, mode):
        raise PermissionError('read-only file system')

    monkeypatch.setattr(sys, 'platform', 'linux')
    monkeypatch.setattr(auth.os, 'chmod', refuse)
    with caplog.at_level(logging.WARNING, logger='phoenix'):
        assert auth.restrict_permissions(str(tmp_path / 'k')) is False
    assert 'could not restrict permissions' in caplog.text
