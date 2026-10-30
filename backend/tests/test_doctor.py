"""`phoenix doctor`: JSON and text diagnostic, no network beyond local probes."""

import json

import pytest

from phoenix_dfir_mcp import __main__ as cli
from phoenix_dfir_mcp import __version__, adapters, copilot, doctor


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    empty = tmp_path / 'bin'
    empty.mkdir()
    monkeypatch.setenv('PATH', str(empty))
    for var in ('PHOENIX_VOLATILITY_CMD', 'PHOENIX_HAYABUSA_CMD', 'PHOENIX_TSK_CMD', 'PHOENIX_TSHARK_CMD',
                'EZ_TOOLS_PATH', 'PHOENIX_EZTOOLS_CMD', 'PHOENIX_LLM_PROVIDER', 'PHOENIX_ALLOW_CLOUD_LLM'):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(adapters.Volatility, 'detect_extra', lambda self: None)
    probed = []
    monkeypatch.setattr(copilot, '_probe', lambda url, timeout: probed.append(url) or False)
    return probed


def test_json_report(capsys, offline):
    assert cli.main(['doctor', '--json']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['phoenix'] == __version__
    assert report['llm']['provider'] == 'ollama' and report['llm']['reachable'] is False
    assert report['llm']['cloud_allowed'] is False and report['llm']['deterministic_triage'] is True
    assert sorted(report['summary']['tools_not_available']) == ['eztools', 'hayabusa', 'tsk', 'tshark',
                                                                'volatility']
    assert {t['status'] for t in report['tools']} == {'not available'}
    assert all(copilot.is_local_url(url) for url in offline)


def test_text_report(capsys):
    assert cli.main(['doctor']) == 0
    out = capsys.readouterr().out
    assert f'Phoenix DFIR {__version__}' in out
    assert 'TShark: not available' in out and 'Fallback: built-in pure Python PCAP parser' in out
    assert 'falls back to phoenix triage' in out


def test_available_tool_is_listed_with_version(monkeypatch, tmp_path):
    import sys
    script = tmp_path / 'tshark_fake.py'
    script.write_text("print('TShark (Wireshark) 4.2.2')\n", encoding='utf-8')
    monkeypatch.setenv('PHOENIX_TSHARK_CMD', f'"{sys.executable}" "{script}"')
    report = doctor.collect()
    tshark = next(t for t in report['tools'] if t['name'] == 'tshark')
    assert tshark['available'] and tshark['version'] == '4.2.2'
    assert 'tshark' in report['summary']['tools_available']
    assert '[ok]   TShark 4.2.2' in doctor.render_text(report)
