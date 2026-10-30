"""Path containment (pathpolicy.within) and strict mode, POSIX and Windows rules."""

import ntpath
import os
import posixpath
import sys

import pytest

from phoenix_dfir_mcp import __main__ as cli
from phoenix_dfir_mcp import pathpolicy, server


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv('PHOENIX_TOOL_ROOTS', raising=False)
    pathpolicy.reset()
    yield
    pathpolicy.reset()


@pytest.mark.parametrize('target,root,expected', [
    (r'C:\Cases\A\evidence\file.evtx', r'c:\cases\a', True),
    (r'C:\Cases\A', r'C:\Cases\A', True),
    (r'C:\Cases\AB\file.evtx', r'C:\Cases\A', False),
    (r'D:\Cases\A\file.evtx', r'C:\Cases\A', False),
    (r'\\SERVER\Share\Case\f.log', r'\\server\share\case', True),
    (r'\\server\share\other\f.log', r'\\server\share\case', False),
])
def test_windows_rules(target, root, expected):
    assert pathpolicy._contains(target, root, pathmod=ntpath) is expected


@pytest.mark.parametrize('target,root,expected', [
    ('/cases/a/file', '/cases/a', True),
    ('/cases/ab/file', '/cases/a', False),
    ('/cases/A/file', '/cases/a', False),  # POSIX is case sensitive
    ('/cases', '/cases/a', False),
])
def test_posix_rules(target, root, expected):
    assert pathpolicy._contains(target, root, pathmod=posixpath) is expected


def test_strict_excludes_the_root_itself():
    assert pathpolicy._contains('/cases/a', '/cases/a', pathmod=posixpath, strict=True) is False


def test_within_resolves_traversal_and_sibling_prefix(tmp_path):
    case = tmp_path / 'case'
    sibling = tmp_path / 'case_backup'
    case.mkdir()
    sibling.mkdir()
    assert pathpolicy.within(case / 'x.log', case)
    assert not pathpolicy.within(sibling / 'x.log', case)
    assert not pathpolicy.within(case / '..' / 'case_backup' / 'x.log', case)


@pytest.mark.skipif(sys.platform == 'win32', reason='symlink creation needs privileges on Windows')
def test_within_follows_symlinks_out_of_the_root(tmp_path):
    case, outside = tmp_path / 'case', tmp_path / 'outside'
    case.mkdir()
    outside.mkdir()
    (case / 'link').symlink_to(outside, target_is_directory=True)
    assert not pathpolicy.within(case / 'link' / 'secret', case)


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows only: case-insensitive paths')
def test_within_is_case_insensitive_on_windows(tmp_path):
    assert pathpolicy.within(str(tmp_path / 'x.log').upper(), str(tmp_path).lower())


def test_strict_mode_denies_everything_without_roots(tmp_path):
    target = tmp_path / 'f.log'
    assert pathpolicy.is_allowed(target)
    pathpolicy.set_strict(True)
    assert not pathpolicy.is_allowed(target)
    assert 'PHOENIX_TOOL_ROOTS' in pathpolicy.check(target)['error']
    pathpolicy.add_root(tmp_path)
    assert pathpolicy.is_allowed(target) and pathpolicy.check(target) is None


def test_strict_mode_honors_env_roots(monkeypatch, tmp_path):
    other = tmp_path / 'other'
    other.mkdir()
    monkeypatch.setenv('PHOENIX_TOOL_ROOTS', os.pathsep.join([str(tmp_path / 'case'), str(other)]))
    pathpolicy.set_strict(True)
    assert pathpolicy.is_allowed(other / 'a.evtx')
    assert not pathpolicy.is_allowed(tmp_path / 'elsewhere' / 'a.evtx')


def test_serve_mcp_command_enables_strict_mode(monkeypatch, capsys):
    monkeypatch.setattr(server, 'serve', lambda: None)
    assert cli.main(['serve-mcp']) == 0
    assert pathpolicy.is_strict()
    assert 'PHOENIX_TOOL_ROOTS' in capsys.readouterr().err
