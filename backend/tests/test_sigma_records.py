#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SigmaHQ rules on cloud and Linux records (pySigma), on the real cases of the suite."""

import os

import pytest

from phoenix_dfir_mcp import sigma_engine, toolkit, triage

SUITE = os.path.join(os.path.dirname(__file__), '..', '..', 'eval', 'suite')
CLOUDTRAIL = os.path.join(SUITE, 'cloud_aws_key_compromise', '418295730216_CloudTrail_eu-west-3_20261013.json.gz')
AUDIT = os.path.join(SUITE, 'linux_auditd_persistence', 'audit.log')
needs_pysigma = pytest.mark.skipif(not sigma_engine.available(), reason='pySigma is not installed')


def test_flatten_record_uses_dotted_field_names():
    flat = sigma_engine.flatten_record({'userIdentity': {'type': 'IAMUser', 'sessionContext': {'mfa': 'false'}},
                                        'eventName': 'StopLogging', 'resources': [{'x': 1}], 'tags': ['a', 'b']})
    assert {name: value for name, value in flat.values()} == {
        'userIdentity.type': 'IAMUser', 'userIdentity.sessionContext.mfa': 'false', 'eventName': 'StopLogging',
        'tags': 'a b'}


@needs_pysigma
def test_cloudtrail_rules_cite_the_record_rows():
    result = toolkit.TOOLS['cloud_parse_log']['func'](file_path=CLOUDTRAIL)
    events = {e['row']: e for e in result['events']}
    by_file = {a['rule_file']: a for a in result['alerts']}
    assert events[by_file['aws_cloudtrail_disable_logging.yml']['row']]['operation'] == 'StopLogging'
    assert events[by_file['aws_iam_backdoor_users_keys.yml']['row']]['operation'] == 'CreateAccessKey'
    assert all(a['rule_author'] and a['rule_url'] for a in result['alerts'])


@needs_pysigma
def test_auditd_rules_cite_the_line_of_their_event():
    result = toolkit.TOOLS['linux_parse_auditd']['func'](file_path=AUDIT)
    event_lines = {e['line'] for e in result['events']}
    by_file = {a['rule_file']: a for a in result['alerts']}
    assert {'lnx_auditd_create_account.yml', 'lnx_auditd_susp_exe_folders.yml'} <= set(by_file)
    assert all(a['line'] in event_lines for a in result['alerts'])  # verifiable refs
    with open(AUDIT, encoding='utf-8') as f:
        lines = f.read().splitlines()
    assert 'useradd' in lines[by_file['lnx_auditd_create_account.yml']['record_line'] - 1]
    assert '/tmp/.x/kworker' in ' '.join(lines[121:126])


@needs_pysigma
def test_record_rules_raise_nothing_on_benign_cloud_and_identity_cases():
    for case in ('identity_benign_admin', 'macos_benign_admin'):
        report = triage.run_triage(os.path.join(SUITE, case))
        assert not [f for f in report['findings'] if f['severity'] in ('critical', 'high', 'medium')]


def test_without_pysigma_the_cloud_parser_is_unchanged(monkeypatch):
    monkeypatch.setattr(sigma_engine, 'available', lambda: False)
    assert 'alerts' not in toolkit.TOOLS['cloud_parse_log']['func'](file_path=CLOUDTRAIL)
