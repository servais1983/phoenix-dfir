#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic text log detections, on the real cases of the evaluation suite."""

import os

from phoenix_dfir_mcp import logdetect, sigma_engine, toolkit, triage

SUITE = os.path.join(os.path.dirname(__file__), '..', '..', 'eval', 'suite')
SSH_LOG = os.path.join(SUITE, 'ssh_bruteforce_valid_account', 'auth.log')
BENIGN_LOG = os.path.join(SUITE, 'benign_admin_activity', 'auth.log')


def test_ssh_brute_force_then_login_cites_the_lines():
    alerts = toolkit.parse_log_file(SSH_LOG)['alerts']
    by_type = {a['type']: a for a in alerts}
    brute = by_type['ssh_bruteforce']
    assert brute['technique'] == 'T1110' and brute['src'] == '185.220.101.44'
    assert brute['failures'] == 36 and brute['line'] == 1
    login = by_type['ssh_login_after_bruteforce']
    assert login['technique'] == 'T1078' and login['user'] == 'svc_backup' and login['line'] == 37
    with open(SSH_LOG, encoding='utf-8') as f:
        lines = f.read().splitlines()
    assert 'Accepted password for svc_backup from 185.220.101.44' in lines[login['line'] - 1]
    assert all('Failed password' in lines[n - 1] for n in brute['lines'])


def test_benign_log_raises_no_alert():
    assert 'alerts' not in toolkit.parse_log_file(BENIGN_LOG)


def test_few_failures_are_not_a_brute_force():
    events = [{'line': n, 'process': 'sshd', 'message': f'Failed password for root from 198.51.100.7 port {n} ssh2'}
              for n in range(1, logdetect.BRUTE_FORCE_MIN_FAILURES)]
    assert logdetect.ssh_alerts(events) == []


def test_triage_reports_both_ssh_techniques():
    report = triage.run_triage(os.path.join(SUITE, 'ssh_bruteforce_valid_account'))
    techniques = report['summary']['techniques']
    assert 'T1110' in techniques and 'T1078' in techniques
    assert triage.run_triage(os.path.join(SUITE, 'benign_admin_activity'))['findings'] == []


POWERSHELL_LOG = os.path.join(SUITE, 'powershell_encoded_service_injection', 'srv-ad-01_events.log')


def test_windows_events_written_as_text_go_through_the_sigma_rules():
    alerts = toolkit.parse_log_file(POWERSHELL_LOG)['alerts']
    by_technique = {}
    for a in alerts:
        by_technique.setdefault(a['technique'], set()).add(a['line'])
    assert by_technique['T1105'] == {1}  # IEX (New-Object Net.WebClient).DownloadString(...)
    assert by_technique['T1543.003'] == {3}  # service WinDefendHealthSvc
    if sigma_engine.available():
        assert 2 in by_technique['T1059.001']  # powershell.exe -nop -w hidden -enc
    with open(POWERSHELL_LOG, encoding='utf-8') as f:
        lines = f.read().splitlines()
    assert 'DownloadString' in lines[0] and 'EventID=7045' in lines[2]


def test_windows_text_lines_keep_the_full_command_line():
    events = toolkit.parsers.parse_log(POWERSHELL_LOG)['events']
    [encoded] = [e for e in logdetect.windows_events(events) if e['line'] == 2]
    assert encoded['data']['CommandLine'].endswith('IABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA')
    assert encoded['event_id'] == 4688 and encoded['channel'] == 'Security'
