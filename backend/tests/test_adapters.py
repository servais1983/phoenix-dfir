"""External tool adapters, exercised with fake executables (version banners only)."""

import os
import stat
import sys

import pytest

from phoenix_dfir_mcp import adapters, disk, hayabusa, volatility
from phoenix_dfir_mcp.adapters import base

BANNERS = {
    'volatility': 'Volatility 3 Framework 2.7.0',
    'hayabusa': 'Hayabusa v3.1.1 - Dev Build',
    'tsk': 'The Sleuth Kit ver 4.12.1',
    'tshark': 'TShark (Wireshark) 4.2.2 (Git v4.2.2 packaged as 4.2.2-1)',
}
TOOL_ENV = ('PHOENIX_VOLATILITY_CMD', 'PHOENIX_HAYABUSA_CMD', 'PHOENIX_TSK_CMD', 'PHOENIX_TSHARK_CMD',
            'PHOENIX_EZTOOLS_CMD', 'EZ_TOOLS_PATH')


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    for var in TOOL_ENV:
        monkeypatch.delenv(var, raising=False)
    empty = tmp_path / 'empty_path'
    empty.mkdir()
    monkeypatch.setenv('PATH', str(empty))
    monkeypatch.setattr(adapters.Volatility, 'detect_extra', lambda self: None)


def _script(tmp_path, name, banner):
    script = tmp_path / f'{name}_fake.py'
    script.write_text(f'print({banner!r})\n', encoding='utf-8')
    return f'"{sys.executable}" "{script}"'


def _on_path(folder, name, banner):
    """A fake executable found through the PATH, on every OS."""
    folder.mkdir(exist_ok=True)
    if os.name == 'nt':
        path = folder / f'{name}.bat'
        path.write_text(f'@echo {banner}\r\n', encoding='utf-8')
    else:
        path = folder / name
        path.write_text(f'#!/bin/sh\necho "{banner}"\n', encoding='utf-8')
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_every_tool_reports_not_available_without_installation():
    for status in adapters.statuses():
        assert status['available'] is False and status['status'] == 'not available', status
        assert status['help'] and status['version'] is None


def test_missing_tool_cannot_run():
    with pytest.raises(adapters.ToolNotAvailable, match='not available'):
        adapters.get('tshark').run(['-v'])


@pytest.mark.parametrize('name,env', [('volatility', 'PHOENIX_VOLATILITY_CMD'), ('tshark', 'PHOENIX_TSHARK_CMD')])
def test_explicit_command_is_detected_with_its_version(monkeypatch, tmp_path, name, env):
    monkeypatch.setenv(env, _script(tmp_path, name, BANNERS[name]))
    adapter = adapters.get(name)
    assert adapter.detect() == [sys.executable, str(tmp_path / f'{name}_fake.py')]
    status = adapter.status()
    assert status['available'] and status['version'] == {'volatility': '2.7.0', 'tshark': '4.2.2'}[name]


def test_explicit_command_that_does_not_exist_is_not_available(monkeypatch, tmp_path):
    monkeypatch.setenv('PHOENIX_TSHARK_CMD', str(tmp_path / 'nope' / 'tshark'))
    assert adapters.get('tshark').detect() is None


def test_tool_found_on_the_path(monkeypatch, tmp_path):
    folder = tmp_path / 'bin'
    _on_path(folder, 'tshark', BANNERS['tshark'])
    monkeypatch.setenv('PATH', str(folder))
    status = adapters.get('tshark').status()
    assert status['available'] and status['version'] == '4.2.2'


def test_sleuthkit_needs_every_binary(monkeypatch, tmp_path):
    folder = tmp_path / 'tsk'
    for name in ('mmls', 'fsstat', 'fls'):
        _on_path(folder, name, BANNERS['tsk'])
    monkeypatch.setenv('PATH', str(folder))
    assert not disk.tsk_available()
    _on_path(folder, 'icat', BANNERS['tsk'])
    assert disk.tsk_available()
    assert adapters.get('tsk').version() == '4.12.1'
    monkeypatch.setenv('PATH', str(tmp_path / 'empty_path'))
    monkeypatch.setenv('PHOENIX_TSK_CMD', str(folder))
    assert disk.tsk_available()


def test_hayabusa_module_uses_the_adapter(monkeypatch, tmp_path):
    binary = _on_path(tmp_path / 'hb', 'hayabusa', BANNERS['hayabusa'])
    monkeypatch.setenv('PHOENIX_HAYABUSA_CMD', str(binary))
    assert hayabusa._find_binary() == str(binary)
    assert adapters.get('hayabusa').version() == '3.1.1'


def test_volatility_module_uses_the_adapter(monkeypatch, tmp_path):
    monkeypatch.setenv('PHOENIX_VOLATILITY_CMD', _script(tmp_path, 'vol', BANNERS['volatility']))
    assert volatility._find_command()[0] == sys.executable
    assert 'windows.pslist' in adapters.get('volatility').capabilities()['plugins']


def test_eztools_lists_missing_tools():
    status = adapters.get('eztools').status()
    assert status['available'] is False
    assert 'PECmd' in status['capabilities']['missing']


@pytest.mark.parametrize('value,expected', [
    ('', None),
    ('vol', ['vol']),
    ('python -m volatility3', ['python', '-m', 'volatility3']),
])
def test_parse_command(value, expected):
    assert base.parse_command(value) == expected


def test_parse_command_keeps_an_existing_path_with_spaces(tmp_path):
    exe = tmp_path / 'My Tools' / 'tshark'
    exe.parent.mkdir()
    exe.write_text('', encoding='utf-8')
    assert base.parse_command(str(exe)) == [str(exe)]
