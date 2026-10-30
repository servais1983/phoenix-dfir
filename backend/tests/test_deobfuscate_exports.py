#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Obfuscated command lines in exports (memory cmdline CSV): decoded statically,
reported as alerts that cite their row. Real fileless case of the suite."""

import os

from phoenix_dfir_mcp import toolkit, triage

SUITE = os.path.join(os.path.dirname(__file__), '..', '..', 'eval', 'suite')
CMDLINE = os.path.join(SUITE, 'fileless_powershell_memory', 'ws-compta-03_cmdline.csv')


def test_cmdline_export_is_offered_to_the_deobfuscator_and_keeps_parsing():
    groups, _missing = toolkit.applicable_tools(CMDLINE)
    tools = {t for _g, names in groups for t in names}
    assert 'deobfuscate_artifact' in tools and 'parse_csv' in tools


def test_decoded_payload_alert_cites_the_row():
    result = toolkit.run_tool('deobfuscate_artifact', {'file_path': CMDLINE})
    [alert] = result['alerts']
    assert alert['row'] == 8 and alert['severity'] == 'high'
    assert {'T1027', 'T1059.001', 'T1105', 'T1562.001', 'T1620'} <= set(alert['techniques'])
    assert any('194.58.112.77' in i['value'] for i in result['iocs'])


def test_triage_fileless_case_techniques():
    techniques = set(triage.run_triage(os.path.join(SUITE, 'fileless_powershell_memory'))['summary']['techniques'])
    assert {'T1027', 'T1059.001', 'T1105', 'T1562.001', 'T1620'} <= techniques


def test_plain_exports_are_not_claimed():
    for case, name in (('c2_beaconing_firewall', 'firewall_export.csv'),
                       ('identity_benign_admin', 'entra_audit_logs.json')):
        groups, _m = toolkit.applicable_tools(os.path.join(SUITE, case, name))
        assert 'deobfuscate_artifact' not in {t for _g, names in groups for t in names}
