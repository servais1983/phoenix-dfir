#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""File system detections on tabular exports, on the real ransomware case."""

import os

from phoenix_dfir_mcp import filedetect, toolkit, triage

SUITE = os.path.join(os.path.dirname(__file__), '..', '..', 'eval', 'suite')
CASE = os.path.join(SUITE, 'ransomware_antiforensics')


def test_mass_encryption_cites_the_renames():
    result = toolkit.parse_csv(os.path.join(CASE, 'file_activity.csv'))
    [alert] = [a for a in result['alerts'] if a['type'] == 'mass_encryption']
    assert alert['technique'] == 'T1486' and alert['extension'] == '.crypt7'
    assert alert['process'] == 'C:\\ProgramData\\svchostupd.exe' and alert['user'] == 'adm.legrand'
    rows = {e['row']: e['data'] for e in result['events']}
    assert all(rows[r]['target_path'].endswith('.crypt7') for r in alert['rows'])
    assert alert['files'] >= filedetect.MIN_ENCRYPTED_FILES


def test_timestomping_on_the_mft_export():
    alerts = toolkit.parse_csv(os.path.join(CASE, 'mft_export.csv'))['alerts']
    assert [(a['technique'], a['file'], a['row']) for a in alerts] == [('T1070.006', 'svchostupd.exe', 1)]


def test_ordinary_writes_and_backup_renames_are_not_encryption():
    rows = [{'row': i, 'data': {'operation': 'rename', 'process': 'robocopy.exe',
                                'source_path': f'D:\\a\\f{i}.docx', 'target_path': f'D:\\a\\f{i}.docx.bak'}}
            for i in range(1, 30)]
    assert filedetect.encryption_alerts(rows) == []
    writes = [{'row': r['row'], 'data': dict(r['data'], operation='write')} for r in rows]
    assert filedetect.encryption_alerts(writes) == []


def test_triage_ransomware_techniques():
    techniques = triage.run_triage(CASE)['summary']['techniques']
    assert {'T1486', 'T1070.006', 'T1490', 'T1070.001'} <= set(techniques)
