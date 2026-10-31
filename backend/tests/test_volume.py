#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Volume: 100 000 Windows events (eval/build_volume_events.py) scanned in full,
with the planted detections found at their record ids, and an explicit warning
when a cap leaves the end of a file unread."""

import time

from phoenix_dfir_mcp import toolkit

import build_volume_events  # noqa: E402  (eval/ is on the pytest pythonpath)

COUNT = 100_000


def _records(result, rule_id):
    return sorted(a['record_id'] for a in result['alerts'] if a['rule_id'] == rule_id)


def test_large_export_is_scanned_to_the_end(tmp_path):
    path = build_volume_events.write(str(tmp_path / 'security.json'), COUNT)
    started = time.monotonic()
    result = toolkit.sigma_scan(path)
    elapsed = time.monotonic() - started
    first = build_volume_events.FIRST_RECORD
    planted = build_volume_events.planted(COUNT)
    cleared = sorted(first + pos for pos, kind in planted.items() if kind == 'log_cleared')
    encoded = [first + pos for pos, kind in planted.items() if kind == 'encoded_powershell']
    assert result['events_scanned'] == COUNT and result['truncated'] is False
    assert _records(result, 'phoenix-log-clearing') == cleared  # including the last ten events
    assert _records(result, 'phoenix-powershell-encoded') == encoded
    assert elapsed < 120, f'{COUNT} events took {elapsed:.0f} s'


def test_a_cap_is_never_silent(tmp_path, monkeypatch):
    path = build_volume_events.write(str(tmp_path / 'security.json'), 20_000)
    monkeypatch.setenv('PHOENIX_SIGMA_MAX_EVENTS', '15000')
    result = toolkit.sigma_scan(path)
    assert result['events_scanned'] == 15000 and result['truncated'] is True
    assert 'PHOENIX_SIGMA_MAX_EVENTS' in result['warning']
    assert _records(result, 'phoenix-log-clearing') == [build_volume_events.FIRST_RECORD + 1000]


def test_builder_is_deterministic(tmp_path):
    a = build_volume_events.write(str(tmp_path / 'a.json'), 2000)
    b = build_volume_events.write(str(tmp_path / 'b.json'), 2000)
    with open(a, 'rb') as fa, open(b, 'rb') as fb:
        assert fa.read() == fb.read()


def _case(tmp_path, name, builder, **kw):
    from phoenix_dfir_mcp import toolkit as tk
    case = tmp_path / 'case'
    case.mkdir(exist_ok=True)
    path = builder(str(case / name), **kw)
    tk.set_active_case(str(case))
    return str(case), path


def test_text_log_detections_see_past_the_preview(tmp_path):
    _case_dir, path = _case(tmp_path, 'auth.log', build_volume_events.write_auth_log)
    try:
        result = toolkit.run_tool('parse_log_file', {'file_path': path})
        assert result['truncated'] is False and result['lines_read'] == 12_037
        assert 'events' not in result and len(result['preview']) == 500  # the LLM gets a preview
        assert result['indexed_events'] == 12_037  # the index gets everything
        brute = next(a for a in result['alerts'] if a['type'] == 'ssh_bruteforce')
        assert brute['line'] == 12_001 and brute['failures'] == 36
    finally:
        toolkit.set_active_case(None)


def test_csv_detections_see_past_the_preview(tmp_path):
    _case_dir, path = _case(tmp_path, 'firewall.csv', build_volume_events.write_flow_csv)
    try:
        result = toolkit.run_tool('parse_csv', {'file_path': path})
        assert result['truncated'] is False and result['total_rows'] == 6_030
        [beacon] = result['alerts']
        assert beacon['dst'] == '91.215.85.14' and beacon['row'] == 6_001
        assert result['indexed_events'] == 6_030
    finally:
        toolkit.set_active_case(None)


def test_json_export_is_indexed_in_full(tmp_path):
    _case_dir, path = _case(tmp_path, 'security.json', build_volume_events.write, count=3000)
    try:
        result = toolkit.run_tool('parse_json_file', {'file_path': path})
        assert result['truncated'] is False and result['indexed_events'] == 3000
        assert len(result['preview']) == 500
    finally:
        toolkit.set_active_case(None)


def test_parse_cap_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv('PHOENIX_PARSE_MAX_RECORDS', '1000')
    path = build_volume_events.write_auth_log(str(tmp_path / 'auth.log'))
    result = toolkit.parse_log_file(path)
    assert result['truncated'] is True and result['lines_read'] == 1000
    assert 'PHOENIX_PARSE_MAX_RECORDS' in result['warning']


def test_index_cap_is_reported(tmp_path, monkeypatch):
    monkeypatch.setenv('PHOENIX_INDEX_MAX_EVENTS', '100')
    _case_dir, path = _case(tmp_path, 'auth.log', build_volume_events.write_auth_log, noise_lines=500)
    try:
        result = toolkit.run_tool('parse_log_file', {'file_path': path})
        assert result['indexed_events'] == 100
        assert result['index_truncated'] == {'indexed': 100, 'total': 537}
        assert 'PHOENIX_INDEX_MAX_EVENTS' in result['warning']
    finally:
        toolkit.set_active_case(None)


def test_graph_build_reports_the_events_it_left_out(tmp_path, monkeypatch):
    from phoenix_dfir_mcp import graph
    _case_dir, path = _case(tmp_path, 'auth.log', build_volume_events.write_auth_log, noise_lines=50)
    try:
        toolkit.run_tool('parse_log_file', {'file_path': path})
        monkeypatch.setattr(graph, 'MAX_EVENTS', 20)
        result = toolkit.run_tool('graph_build', {'case_dir': _case_dir})
        assert result['events'] == {'used': 20, 'total': 87, 'truncated': True}
        assert 'evenements' in result['warning']
        monkeypatch.setattr(graph, 'MAX_EVENTS', 200000)
        assert toolkit.run_tool('graph_build', {'case_dir': _case_dir})['events']['truncated'] is False
    finally:
        toolkit.set_active_case(None)


def test_batched_index_keeps_ids_unique_across_runs(tmp_path):
    from phoenix_dfir_mcp import evidence_db, verifier
    case_dir, path = _case(tmp_path, 'auth.log', build_volume_events.write_auth_log, noise_lines=12_000)
    try:
        first = toolkit.run_tool('parse_log_file', {'file_path': path})
        second = toolkit.run_tool('parse_csv', {'file_path': build_volume_events.write_flow_csv(
            str(tmp_path / 'case' / 'firewall.csv'))})
        assert first['indexed_events'] == 12_037 and second['indexed_events'] == 6_030
        conn = evidence_db._connect(case_dir)
        try:
            assert tuple(conn.execute('SELECT COUNT(*), COUNT(DISTINCT id) FROM events').fetchone()) == (18_067, 18_067)
            assert conn.execute('SELECT COUNT(*) FROM events_fts').fetchone()[0] == 18_067
        finally:
            conn.close()
        ref = {'artifact': 'firewall.csv', 'kind': 'row', 'value': 6_030}
        assert verifier.verify_finding(case_dir, {'title': 'Beacon to 91.215.85.14',
                                                  'evidence_refs': [ref]})['status'] == verifier.VERIFIED
    finally:
        toolkit.set_active_case(None)
