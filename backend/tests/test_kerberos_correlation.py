#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kerberos correlation: a service ticket without any TGT for its account is a
forged ticket (T1558.001), not Kerberoasting. Real cases of the evaluation suite."""

import os

from phoenix_dfir_mcp import kerberos, toolkit, triage

SUITE = os.path.join(os.path.dirname(__file__), '..', '..', 'eval', 'suite')
GOLDEN = os.path.join(SUITE, 'ad_golden_ticket', 'dc01_security.json')
KERBEROAST = os.path.join(SUITE, 'ad_kerberoasting_dcsync', 'dc01_security.json')


def _techniques(result):
    return {t for a in result['alerts'] for t in (a.get('techniques') or [a.get('technique')]) if t}


def test_golden_ticket_service_tickets_without_tgt():
    result = toolkit.sigma_scan(GOLDEN)
    forged = [a for a in result['alerts'] if a.get('technique') == 'T1558.001']
    assert sorted(a['record_id'] for a in forged) == [1203361, 1203362, 1203363, 1203364]
    assert all(a['user'] == 'svc_admin_backup' and a['engine'] == 'phoenix-correlation' for a in forged)
    assert 'T1558.003' not in _techniques(result)  # no Kerberoasting on a forged ticket
    assert result['engines']['correlation']['reclassified'] >= 1


def test_kerberoasting_stays_kerberoasting():
    result = toolkit.sigma_scan(KERBEROAST)
    assert 'T1558.003' in _techniques(result)
    assert 'T1558.001' not in _techniques(result)
    assert result['engines']['correlation']['reclassified'] == 0


def test_no_tgt_coverage_means_no_forged_ticket():
    # A log without any 4768 cannot tell a forged ticket from a missing log
    events = [{'event_id': 4769, 'record_id': 7, 'timestamp': '2026-10-12T08:00:00Z',
               'data': {'TargetUserName': 'x@corp', 'ServiceName': 'svc', 'TicketEncryptionType': '0x17'}}]
    assert kerberos.forged_ticket_alerts(events) == []


def test_triage_golden_ticket_has_no_forbidden_technique():
    techniques = triage.run_triage(os.path.join(SUITE, 'ad_golden_ticket'))['summary']['techniques']
    assert 'T1558.001' in techniques and 'T1558.003' not in techniques
