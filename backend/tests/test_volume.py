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
