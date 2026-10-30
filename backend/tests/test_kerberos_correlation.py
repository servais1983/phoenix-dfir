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


TRUNCATED = os.path.join(SUITE, 'benign_kerberos_truncated', 'dc02_security.json')


def test_truncated_log_is_not_a_forged_ticket():
    # The log starts after the TGT of svc_report and its tickets are AES like every TGT: inconclusive
    result = toolkit.sigma_scan(TRUNCATED)
    assert 'T1558.001' not in _techniques(result)
    notes = [a for a in result['alerts'] if a.get('engine') == 'phoenix-correlation']
    assert len(notes) == 3  # the three service tickets of svc_report
    for note in notes:
        assert note['level'] == 'low' and note['user'] == 'svc_report' and not note.get('technique')
        assert 'non concluant' in note['rule_title']


def test_forged_ticket_needs_coverage_or_rc4():
    def ev(sec, eid, user, enc='0x12'):
        return {'event_id': eid, 'record_id': sec, 'timestamp': f'2026-10-12T{sec // 3600:02d}:{sec % 3600 // 60:02d}:00Z',
                'data': {'TargetUserName': user, 'ServiceName': 'FS01$', 'TicketEncryptionType': enc}}
    short = [ev(60, 4768, 'a'), ev(120, 4769, 'x')]
    long = [ev(60, 4768, 'a'), ev(11 * 3600, 4769, 'x')]
    rc4 = [ev(60, 4768, 'a'), ev(120, 4769, 'x', '0x17')]
    assert kerberos.forged_ticket_alerts(short)[0]['level'] == 'low'
    assert kerberos.forged_ticket_alerts(long)[0]['technique'] == 'T1558.001'
    assert kerberos.forged_ticket_alerts(rc4)[0]['technique'] == 'T1558.001'
