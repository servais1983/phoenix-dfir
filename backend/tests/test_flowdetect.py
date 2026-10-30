#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Beaconing on flow exports, on the real cases of the evaluation suite."""

import os

from phoenix_dfir_mcp import flowdetect, toolkit, triage

SUITE = os.path.join(os.path.dirname(__file__), '..', '..', 'eval', 'suite')
FIREWALL = os.path.join(SUITE, 'c2_beaconing_firewall', 'firewall_export.csv')


def test_firewall_beacon_cites_its_rows():
    result = toolkit.parse_csv(FIREWALL)
    [alert] = result['alerts']
    assert alert['dst'] == '91.215.85.14' and alert['dst_port'] == 443 and alert['technique'] == 'T1071.001'
    assert alert['host'] == 'PC-COMPTA-07' and alert['row'] == 1
    assert 55 <= alert['interval_s'] <= 65
    events = {e['row']: e for e in result['events']}
    assert all(events[r]['data']['dst_ip'] == '91.215.85.14' for r in alert['rows'])


def test_irregular_or_internal_flows_are_not_beacons():
    rows = [{'row': i + 1, 'data': {'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.9', 'dst_port': '443',
                                    'timestamp': f'2026-10-12T14:{i:02d}:00Z', 'bytes_out': '600'}}
            for i in range(10)]
    assert flowdetect.beacon_alerts(rows) == []  # internal destination
    irregular = [dict(r, data=dict(r['data'], dst_ip='91.215.85.14',
                                   timestamp=f'2026-10-12T14:{(i * i) % 60:02d}:00Z'))
                 for i, r in enumerate(rows)]
    assert flowdetect.beacon_alerts(irregular) == []


def test_benign_csv_cases_raise_no_beacon():
    for case in ('identity_benign_admin',):
        report = triage.run_triage(os.path.join(SUITE, case))
        assert not [f for f in report['findings'] if 'Beaconing' in f['title']]


def test_triage_finds_the_firewall_beacon():
    techniques = triage.run_triage(os.path.join(SUITE, 'c2_beaconing_firewall'))['summary']['techniques']
    assert 'T1071.001' in techniques
