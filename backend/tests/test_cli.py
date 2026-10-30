"""`phoenix` command line: triage and the investigate fallback."""

import json
from pathlib import Path

import pytest

from phoenix_dfir_mcp import __main__ as cli
from phoenix_dfir_mcp import __version__, copilot

SUITE = Path(__file__).resolve().parents[2] / 'eval' / 'suite'


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(['--version'])
    assert exc.value.code == 0 and __version__ in capsys.readouterr().out


def test_triage_json(capsys, tmp_path):
    assert cli.main(['triage', str(SUITE / 'ad_kerberoasting_dcsync'), '--format', 'json',
                     '-o', str(tmp_path)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['deterministic'] is True and report['llm'] is None
    assert 'T1558.003' in report['summary']['techniques']
    assert json.loads((tmp_path / 'triage.json').read_text(encoding='utf-8')) == report


def test_triage_missing_case(capsys, tmp_path):
    assert cli.main(['triage', str(tmp_path / 'absent')]) == 2


def test_investigate_falls_back_to_triage_without_llm(capsys, monkeypatch):
    monkeypatch.setattr(copilot, 'llm_reachable', lambda provider=None: False)
    assert cli.main(['investigate', str(SUITE / 'net_c2_beacon_pcap')]) == 0
    out = capsys.readouterr()
    assert 'running the deterministic triage instead' in out.err
    assert 'Beaconing' in out.out and 'row=18' in out.out


def test_investigate_without_fallback_fails_on_llm_error(capsys, monkeypatch):
    from phoenix_dfir_mcp import investigator

    def no_llm(*args, **kwargs):
        raise copilot.CopilotError('Ollama (local LLM) call failed: connection refused')

    monkeypatch.setattr(investigator, 'investigate', no_llm)
    assert cli.main(['investigate', '--no-triage-fallback', str(SUITE / 'net_c2_beacon_pcap')]) == 1
    assert 'connection refused' in capsys.readouterr().err
