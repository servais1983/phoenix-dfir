"""Case layout, evidence manifest, read-only evidence and phoenix verify."""

import os
import stat
import sys
from pathlib import Path

import pytest

from phoenix_dfir_mcp import __main__ as cli
from phoenix_dfir_mcp import casefile, toolkit, triage, workspace

SUITE = Path(__file__).resolve().parents[2] / 'eval' / 'suite'


@pytest.fixture(autouse=True)
def ledger_db(monkeypatch, tmp_path):
    import database
    monkeypatch.setattr(database, 'DB_PATH', str(tmp_path / 'ledger.db'))


def _actions():
    import custody
    return [e['action'] for e in custody.list_entries()]


def _make_writable(case):
    for p in (case / 'evidence').rglob('*'):
        if p.is_file():
            os.chmod(p, stat.S_IREAD | stat.S_IWRITE)


@pytest.fixture
def case(tmp_path):
    case = tmp_path / 'case'
    casefile.ingest(case, [SUITE / 'net_c2_beacon_pcap' / 'ws-fin-02_capture.pcap',
                           SUITE / 'benign_admin_activity' / 'auth.log'])
    yield case
    _make_writable(case)


def test_ingest_creates_the_layout_and_manifest(case):
    assert all((case / name).is_dir() for name in casefile.LAYOUT)
    manifest = casefile.read_manifest(case)
    assert sorted(manifest) == ['evidence/auth.log', 'evidence/ws-fin-02_capture.pcap']
    source = SUITE / 'benign_admin_activity' / 'auth.log'
    assert manifest['evidence/auth.log'] == casefile.sha256_file(source)
    line = (case / casefile.MANIFEST).read_text(encoding='utf-8').splitlines()[0]
    assert line == f"{manifest['evidence/auth.log']}  evidence/auth.log"  # sha256sum format
    assert _actions().count('evidence_ingested') == 2


def test_ingested_evidence_is_read_only(case):
    mode = os.stat(case / 'evidence' / 'auth.log').st_mode
    assert not mode & stat.S_IWUSR
    if sys.platform != 'win32' and os.geteuid() != 0:
        with pytest.raises(PermissionError):
            open(case / 'evidence' / 'auth.log', 'a').close()


def test_ingest_refuses_to_overwrite(case):
    with pytest.raises(casefile.CaseError, match='overwrite refused'):
        casefile.ingest(case, [SUITE / 'benign_admin_activity' / 'auth.log'])


def test_ingest_missing_source(tmp_path):
    with pytest.raises(casefile.CaseError, match='not found'):
        casefile.ingest(tmp_path / 'c', [tmp_path / 'absent.evtx'])


def test_ingest_folder_keeps_the_tree(tmp_path):
    case = tmp_path / 'case'
    result = casefile.ingest(case, [SUITE / 'ad_kerberoasting_dcsync'])
    assert 'evidence/ad_kerberoasting_dcsync/dc01_security.json' in [a['path'] for a in result['added']]
    _make_writable(case)


def test_verify_valid_case_is_recorded(case):
    result = casefile.verify(case)
    assert result['valid'] and result['checked'] == result['ok'] == 2
    assert _actions()[-1] == 'evidence_verified'
    assert Path(result['record']).parent == case / 'custody'


def test_verify_detects_modified_missing_and_unlisted_evidence(case):
    target = case / 'evidence' / 'auth.log'
    os.chmod(target, stat.S_IREAD | stat.S_IWRITE)
    target.write_bytes(target.read_bytes() + b'tampered\n')
    os.chmod(case / 'evidence' / 'ws-fin-02_capture.pcap', stat.S_IREAD | stat.S_IWRITE)
    (case / 'evidence' / 'ws-fin-02_capture.pcap').unlink()
    (case / 'evidence' / 'dropped.txt').write_text('not ingested', encoding='utf-8')
    result = casefile.verify(case)
    assert not result['valid']
    assert [m['path'] for m in result['mismatched']] == ['evidence/auth.log']
    assert result['missing'] == ['evidence/ws-fin-02_capture.pcap']
    assert result['unlisted'] == ['evidence/dropped.txt']
    import custody
    last = custody.list_entries()[-1]
    assert last['action'] == 'evidence_verified' and last['severity'] == 'high'
    assert custody.verify_chain()['valid']


def test_verify_without_manifest(tmp_path):
    casefile.init_case(tmp_path / 'c')
    with pytest.raises(casefile.CaseError, match='ingest'):
        casefile.verify(tmp_path / 'c')


def test_layout_internals_are_not_artifacts(case):
    casefile.verify(case)
    rels = sorted(Path(p).relative_to(case).as_posix() for p in toolkit.case_artifacts(str(case)))
    assert rels == ['evidence/auth.log', 'evidence/ws-fin-02_capture.pcap']
    assert workspace.derived_root(str(case)) == str(case / 'derived')


def test_triage_on_a_layout_case(case):
    report = triage.run_triage(case)
    assert sorted(a['path'] for a in report['artifacts']) == ['evidence/auth.log', 'evidence/ws-fin-02_capture.pcap']
    assert any(f['entities'].get('dst') == '185.225.73.90' for f in report['findings'])


def test_cli_ingest_verify_and_triage(tmp_path, capsys):
    case = tmp_path / 'cli_case'
    assert cli.main(['ingest', str(case), str(SUITE / 'ad_kerberoasting_dcsync' / 'dc01_security.json')]) == 0
    assert 'evidence/dc01_security.json' in capsys.readouterr().out
    assert cli.main(['verify', str(case)]) == 0
    assert 'VALID: 1/1' in capsys.readouterr().out
    assert cli.main(['triage', str(case)]) == 0
    assert (case / 'reports' / 'triage.json').is_file() and (case / 'reports' / 'triage.md').is_file()
    assert cli.main(['verify', str(case)]) == 0, 'triage must leave the evidence untouched'
    _make_writable(case)
    (case / 'evidence' / 'dc01_security.json').write_text('{}', encoding='utf-8')
    assert cli.main(['verify', str(case)]) == 1
    assert 'INTEGRITY FAILURE' in capsys.readouterr().out
