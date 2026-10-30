#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sigma engine: pySigma rules on real Windows events of the evaluation suite."""

import io
import json
import os
import sqlite3
import zipfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]

from phoenix_dfir_mcp import __main__ as cli  # noqa: E402
from phoenix_dfir_mcp import doctor, sigma_engine, toolkit, verifier  # noqa: E402

SUITE = _ROOT / 'eval' / 'suite'
RANSOMWARE = SUITE / 'ransomware_antiforensics' / 'srv-fichiers-01_events.json'
KERBEROAST = SUITE / 'ad_kerberoasting_dcsync' / 'dc01_security.json'
GOLDEN = SUITE / 'ad_golden_ticket' / 'dc01_security.json'
WINDOWS_EXPORTS = (RANSOMWARE, KERBEROAST, GOLDEN)
needs_pysigma = pytest.mark.skipif(not sigma_engine.available(), reason='pySigma is not installed')


@pytest.fixture(autouse=True)
def _isolated_store(monkeypatch, tmp_path):
    monkeypatch.setenv('PHOENIX_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('PHOENIX_DB_PATH', str(tmp_path / 'absent.db'))
    monkeypatch.delenv('PHOENIX_SIGMA_RULES', raising=False)
    monkeypatch.delenv('PHOENIX_SIGMAHQ_SHA256', raising=False)


def _events(path):
    events, error = toolkit._load_event_export(str(path))
    assert error is None and events
    return events


def _bundled_zip(root='sigma-r2026-07-01'):
    """Zip of the bundled SigmaHQ files, laid out like the SigmaHQ release archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for path in sorted(sigma_engine.BUNDLED_DIR.rglob('*')):
            if path.is_file():
                z.write(path, f'{root}/{path.relative_to(sigma_engine.BUNDLED_DIR).as_posix()}')
    return buf.getvalue()


# ----------------------------------------------------------------------------
# Built in rules as Sigma YAML
# ----------------------------------------------------------------------------

def test_builtin_yaml_files_match_the_builtin_rules(tmp_path):
    written = sigma_engine.export_builtin(tmp_path / 'out')
    assert len(written) == len(sigma_engine.builtin_rules()) == 29
    for path in written:
        shipped = sigma_engine.BUILTIN_DIR / path.name
        assert shipped.read_text(encoding='utf-8') == path.read_text(encoding='utf-8'), path.name


@needs_pysigma
@pytest.mark.parametrize('export', WINDOWS_EXPORTS, ids=lambda p: p.parent.name)
def test_builtin_yaml_gives_the_same_alerts_as_the_builtin_engine(export):
    rules, errors = [], []
    for path in sorted(sigma_engine.BUILTIN_DIR.glob('*.yml')):
        compiled = sigma_engine._compile(path)
        (errors if 'error' in compiled else rules).append(compiled)
    assert not errors and len(rules) == 29
    builtin = toolkit.sigma_scan(str(export))
    expected = sorted((a['rule_id'], a['record_id']) for a in builtin['alerts'] if a['engine'] == 'builtin')
    got = sorted((a['rule_id'], a['record_id']) for a in sigma_engine.scan(_events(export), rules=rules)['alerts'])
    assert expected and got == expected


# ----------------------------------------------------------------------------
# SigmaHQ rules
# ----------------------------------------------------------------------------

@needs_pysigma
def test_bundled_sigmahq_rules_all_load():
    rules, errors = sigma_engine.load_rules()
    assert errors == [] and len(rules) == 25
    assert all(r['author'] and r['url'].startswith(sigma_engine.SIGMAHQ_BLOB) for r in rules)


@needs_pysigma
def test_sigmahq_rules_on_the_ransomware_case_cite_record_ids():
    result = sigma_engine.scan(_events(RANSOMWARE))
    by_file = {}
    for alert in result['alerts']:
        by_file.setdefault(alert['rule_file'], set()).add(alert['record_id'])
    assert by_file['win_security_audit_log_cleared.yml'] == {552122}
    assert 'proc_creation_win_susp_shadow_copies_deletion.yml' in by_file
    assert 'proc_creation_win_bcdedit_boot_conf_tamper.yml' in by_file
    raw = {e['record_id']: e for e in _events(RANSOMWARE)}
    for alert in result['alerts']:
        assert alert['record_id'] in raw  # every alert points to an observed event
        assert alert['rule_author'] and alert['rule_url']  # DRL 1.1 attribution
    assert result['rules_failed'] == []


@needs_pysigma
def test_sigmahq_dcsync_rule_skips_domain_controllers():
    alerts = sigma_engine.scan(_events(KERBEROAST))['alerts']
    dcsync = {a['record_id'] for a in alerts if a['rule_file'] == 'win_security_dcsync.yml'}
    events = {e['record_id']: e for e in _events(KERBEROAST)}
    assert dcsync
    for record_id in dcsync:
        assert not str(events[record_id]['data'].get('SubjectUserName', '')).endswith('$')


@needs_pysigma
def test_sigma_scan_merges_both_engines_and_indexes_the_refs(tmp_path):
    case = tmp_path / 'case'
    case.mkdir()
    export = case / RANSOMWARE.name
    export.write_bytes(RANSOMWARE.read_bytes())
    toolkit.set_active_case(str(case))
    try:
        result = toolkit.run_tool('sigma_scan', {'file_path': str(export)})
        engines = {a['engine'] for a in result['alerts']}
        assert engines == {'builtin', 'pysigma'}
        assert result['engines']['pysigma']['rules'] == 25
        assert result['total_alerts'] == len(result['alerts'])
        finding = {'title': 'Security log cleared by adm.legrand',
                   'evidence_refs': [{'artifact': export.name, 'kind': 'record_id', 'value': 552122}]}
        assert verifier.verify_finding(str(case), finding)['status'] == verifier.VERIFIED
    finally:
        toolkit.set_active_case(None)
        toolkit.reset_evidence_index()


def test_sigma_scan_without_pysigma_keeps_the_builtin_rules(monkeypatch):
    monkeypatch.setattr(sigma_engine, 'available', lambda: False)
    result = toolkit.sigma_scan(str(RANSOMWARE))
    assert result['alerts'] and {a['engine'] for a in result['alerts']} == {'builtin'}
    assert 'not available' in result['engines']['pysigma']['status']


# ----------------------------------------------------------------------------
# Engine safety
# ----------------------------------------------------------------------------

def test_event_table_is_read_only_while_rules_run():
    table = sigma_engine._EventTable(_events(RANSOMWARE))
    try:
        with pytest.raises(sqlite3.DatabaseError):
            table.conn.execute('DELETE FROM logs')
        assert table.match('SELECT * FROM logs WHERE EventID=1102') == [21]
        # A field no event has is an empty column, not an error
        assert table.match("SELECT * FROM logs WHERE NoSuchField='x'") == []
    finally:
        table.close()


def test_flatten_maps_export_fields_to_sigma_names():
    event = next(e for e in _events(RANSOMWARE) if e['event_id'] == 4688)
    fields = sigma_engine.flatten(event)
    assert fields['Image'] == event['data']['NewProcessName']
    assert fields['EventID'] == 4688 and fields['Channel'] == 'Security'


def test_unsupported_logsource_is_skipped():
    assert sigma_engine.supported_logsource({'product': 'windows', 'category': 'process_creation'})
    assert not sigma_engine.supported_logsource({'product': 'linux', 'category': 'process_creation'})
    assert not sigma_engine.supported_logsource({'product': 'windows', 'service': 'unknown-channel'})


# ----------------------------------------------------------------------------
# Rule store: import, sync, connector rules_path
# ----------------------------------------------------------------------------

def test_import_keeps_only_rules_and_never_escapes_the_store(tmp_path):
    rule = (sigma_engine.BUNDLED_DIR / 'rules' / 'windows' / 'builtin' / 'security'
            / 'win_security_audit_log_cleared.yml').read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('pack/rules/a.yml', rule)
        z.writestr('../escape.yml', rule)
        z.writestr('/abs/escape.yml', rule)
        z.writestr('C:/drive/escape.yml', rule)
        z.writestr('pack/tool.exe', b'MZ')
    archive = tmp_path / 'pack.zip'
    archive.write_bytes(buf.getvalue())
    result = sigma_engine.import_archive(str(archive))
    target = Path(result['target'])
    assert result['rules'] == 2 and result['skipped'] == 3  # '/abs/...' is made relative
    assert sorted(p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_file()) == [
        'abs/escape.yml', 'pack/rules/a.yml']
    assert not (tmp_path / 'escape.yml').exists()
    assert target.parent == sigma_engine.store_dir() / 'imported'


@needs_pysigma
def test_imported_rules_are_loaded_once(tmp_path):
    archive = tmp_path / 'hq.zip'
    archive.write_bytes(_bundled_zip())
    sigma_engine.import_archive(str(archive))
    rules, errors = sigma_engine.load_rules()
    assert len(rules) == 25 and not errors  # same rule ids as the bundled ones: not duplicated


def test_sync_refuses_an_archive_with_another_digest(monkeypatch):
    data = _bundled_zip()

    class Resp:
        content = data

        def raise_for_status(self):
            return None

    import requests
    monkeypatch.setattr(requests, 'get', lambda url, timeout: Resp())
    with pytest.raises(ValueError):
        sigma_engine.sync(expected_sha256='0' * 64)
    assert not (sigma_engine.store_dir() / sigma_engine.SIGMAHQ_TAG).exists()
    import hashlib
    result = sigma_engine.sync(expected_sha256=hashlib.sha256(data).hexdigest())
    source = json.loads((Path(result['target']) / 'SOURCE.json').read_text(encoding='utf-8'))
    assert source['tag'] == sigma_engine.SIGMAHQ_TAG and source['rules'] == 25
    assert (Path(result['target']) / 'rules' / 'windows').is_dir()
    assert Path(result['target']) / 'rules' in sigma_engine.rule_dirs()


def test_connector_rules_path_is_read_from_the_console_database(monkeypatch, tmp_path):
    db = tmp_path / 'phoenix.db'
    conn = sqlite3.connect(db)
    conn.execute('CREATE TABLE integration_configs (connector_id TEXT, config TEXT)')
    conn.execute('INSERT INTO integration_configs VALUES (?, ?)',
                 ('sigma', json.dumps({'rules_path': str(sigma_engine.BUILTIN_DIR)})))
    conn.commit()
    conn.close()
    monkeypatch.setenv('PHOENIX_DB_PATH', str(db))
    assert sigma_engine.connector_rules_path() == str(sigma_engine.BUILTIN_DIR)
    assert sigma_engine.BUILTIN_DIR in sigma_engine.rule_dirs([sigma_engine.connector_rules_path()])


@needs_pysigma
def test_connector_test_connection_counts_runnable_rules():
    from integrations.sigma_connector import SigmaConnector
    result = SigmaConnector({'rules_path': str(sigma_engine.BUILTIN_DIR)}).test_connection()
    assert result['custom_rules'] == 29 and result['custom_rules_usable'] == 29


# ----------------------------------------------------------------------------
# CLI and doctor
# ----------------------------------------------------------------------------

def test_cli_rules_list_json(capsys):
    assert cli.main(['rules', 'list', '--json']) == 0
    report = json.loads(capsys.readouterr().out)
    assert report['builtin_rules'] == 29
    if sigma_engine.available():
        assert report['rules'] == 25 and report['invalid'] == 0


def test_doctor_reports_the_sigma_engine():
    info = doctor.collect()['sigma']
    assert info['builtin_rules'] == 29
    assert info['available'] == sigma_engine.available()
    assert 'Sigma rules' in doctor.render_text(doctor.collect())


@needs_pysigma
def test_triage_keeps_the_sigmahq_rule_author():
    from phoenix_dfir_mcp import triage
    report = triage.run_triage(RANSOMWARE.parent)
    hq = [f for f in report['findings'] if f.get('rule')]
    assert hq and all(f['rule']['author'] and f['rule']['url'] for f in hq)
    assert 'author: ' in triage.render_markdown(report)
