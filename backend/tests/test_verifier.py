#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic verifier: a finding is kept only when the case evidence backs it.

Every case used here is a real case of the evaluation suite (eval/suite/)."""

import os
import shutil

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')

from phoenix_dfir_mcp import memory, pathpolicy, phases, toolkit, verifier  # noqa: E402

SUITE = os.path.join(_ROOT, 'eval', 'suite')
PCAP = 'ws-fin-02_capture.pcap'


@pytest.fixture(autouse=True)
def _isolation():
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


def _case(tmp_path, name):
    case = tmp_path / name
    shutil.copytree(os.path.join(SUITE, name), case, ignore=shutil.ignore_patterns('ground_truth.json'))
    toolkit.set_active_case(str(case))
    return str(case)


@pytest.fixture
def beacon_case(tmp_path):
    d = _case(tmp_path, 'net_c2_beacon_pcap')
    for tool in ('net_detect', 'net_tls'):
        toolkit.run_tool(tool, {'file_path': os.path.join(d, PCAP)})
    return d


def _ref(row):
    return {'artifact': PCAP, 'kind': 'row', 'value': row}


def test_entities_keep_private_ips_and_skip_file_names():
    ents = dict(verifier.entities('Beacon 10.20.30.15 -> 185.225.73.90 (cdn-telemetry-sync.net), see auth.log'))
    assert ents.get('domain') == 'cdn-telemetry-sync.net'
    found = verifier.entities('10.20.30.15 185.225.73.90 auth.log')
    assert ('ip', '10.20.30.15') in found and ('ip', '185.225.73.90') in found
    assert not any(v == 'auth.log' for _k, v in found)


def test_real_beacon_with_the_right_rows_is_verified(beacon_case):
    finding = {'title': 'C2 beacon to 185.225.73.90 (SNI cdn-telemetry-sync.net)',
               'evidence_refs': [_ref(18), _ref(21)]}
    v = verifier.verify_finding(beacon_case, finding)
    assert v['status'] == verifier.VERIFIED, v
    assert v['refs_found'] == 2 and v['missing'] == []


def test_entity_absent_from_the_referenced_event_is_unverified(beacon_case):
    # www.wikipedia.org is in the capture (TLS row 6) but not in the beaconing row 18:
    # citing row 18 does not prove it
    v = verifier.verify_finding(beacon_case, {'title': 'Beacon to www.wikipedia.org',
                                              'evidence_refs': [_ref(18)]})
    assert v['status'] == verifier.UNVERIFIED
    assert ['domain', 'www.wikipedia.org'] in v['missing']
    assert verifier.verify_finding(beacon_case, {'title': 'TLS to www.wikipedia.org',
                                                 'evidence_refs': [_ref(6)]})['status'] == verifier.VERIFIED


def test_fabricated_ip_is_rejected(beacon_case):
    v = verifier.verify_finding(beacon_case, {'title': 'Exfiltration to 8.8.4.4',
                                              'evidence_refs': [_ref(18)]})
    assert v['status'] == verifier.UNVERIFIED and 'not in the referenced events' in v['reason']


def test_reference_never_produced_by_a_tool_is_rejected(beacon_case):
    v = verifier.verify_finding(beacon_case, {'title': 'Beacon', 'evidence_refs': [_ref(999999)]})
    assert v['status'] == verifier.UNVERIFIED and 'absent' in v['reason']


def test_finding_without_reference_is_unverified(beacon_case):
    v = verifier.verify_finding(beacon_case, {'title': 'Beacon to 185.225.73.90'})
    assert v['status'] == verifier.UNVERIFIED and v['reason'] == 'no evidence reference'


def test_verify_case_stores_verdicts_and_keeps_llm_refutation(beacon_case):
    memory.record_finding(beacon_case, 'C2 beacon to 185.225.73.90', severity='high', mitre='T1071.001',
                          evidence_refs=[_ref(18)])
    memory.record_finding(beacon_case, 'Exfiltration to 8.8.4.4', severity='high', mitre='T1048',
                          evidence_refs=[_ref(18)])
    memory.record_finding(beacon_case, 'C2 beacon refuted by review 185.225.73.90', severity='low',
                          evidence_refs=[_ref(18)])
    memory.verify_finding(beacon_case, 3, 'refuted', 'independent check')
    summary = verifier.verify_case(beacon_case)
    assert summary['verified_ids'] == [1]
    assert (summary['verified'], summary['unverified'], summary['refuted']) == (1, 1, 1)
    state = memory.get_state(beacon_case)
    by_id = {f['id']: f for f in state['findings']}
    assert by_id[2]['verification'] == 'unverified'
    assert by_id[2]['verification_note'].startswith('[deterministic]')
    assert by_id[3]['verification'] == 'refuted'  # the LLM can only remove a finding
    assert by_id[3]['deterministic']['status'] == 'verified'
    # Same case, same verdicts
    assert verifier.verify_case(beacon_case) == summary


def test_rendered_report_separates_unverified_findings(beacon_case):
    memory.record_finding(beacon_case, 'C2 beacon to 185.225.73.90', severity='high', mitre='T1071.001',
                          evidence_refs=[_ref(18)])
    memory.record_finding(beacon_case, 'Exfiltration to 8.8.4.4', severity='high', evidence_refs=[_ref(18)])
    verifier.verify_case(beacon_case)
    md = memory.render_markdown(beacon_case)
    verified, excluded = md.split('## Constats non verifies', 1)
    assert '185.225.73.90' in verified and '8.8.4.4' not in verified
    assert '8.8.4.4' in excluded


def test_citation_coverage():
    report = ('# Report\n## Summary\nBeacon to 185.225.73.90 every 60 s [F1].\n'
              'Domain cdn-telemetry-sync.net [F2].\nTechnique T1071.001.\nContain the host.\n'
              '```\n185.225.73.90 in a code block is ignored\n```\n')
    c = verifier.check_citations(report, {1})
    assert c['factual_sentences'] == 3 and c['linked'] == 1
    reasons = {u['sentence']: u['reason'] for u in c['unlinked']}
    assert reasons['Domain cdn-telemetry-sync.net [F2].'] == 'cites a non verified finding'
    assert reasons['Technique T1071.001.'] == 'no [F<id>] citation'
    assert verifier.check_citations('# Title\nNo fact here.\n', set())['coverage'] == 1.0


def test_report_gate_rejects_uncited_facts(beacon_case):
    memory.record_finding(beacon_case, 'C2 beacon to 185.225.73.90', severity='high', mitre='T1071.001',
                          evidence_refs=[_ref(18)])
    verifier.verify_case(beacon_case)
    body = ('# R\n## Resume executif\nBeacon to 185.225.73.90.\n## Chronologie\n- x\n'
            '## Recommandations\nIsolate.\n')

    class Ctx:
        report_path = os.path.join(beacon_case, 'report.md')
    with open(Ctx.report_path, 'w', encoding='utf-8') as f:
        f.write(body)
    gaps = phases.gate_rapport(beacon_case, Ctx)
    assert any('[F<id>]' in g for g in gaps), gaps
    with open(Ctx.report_path, 'w', encoding='utf-8') as f:
        f.write(body.replace('185.225.73.90.', '185.225.73.90 [F1].'))
    assert not any('[F<id>]' in g for g in phases.gate_rapport(beacon_case, Ctx))


def test_deterministic_report_only_cites_verified_findings(beacon_case):
    memory.record_finding(beacon_case, 'C2 beacon to 185.225.73.90', severity='high', mitre='T1071.001',
                          evidence_refs=[_ref(18)])
    memory.record_finding(beacon_case, 'Exfiltration to 8.8.4.4', severity='high', evidence_refs=[_ref(18)])
    verifier.verify_case(beacon_case)
    md = phases.deterministic_report(beacon_case)
    assert '185.225.73.90' in md and '8.8.4.4' not in md and '[F1]' in md
    assert verifier.check_citations(md, verifier.verified_ids(beacon_case))['coverage'] == 1.0


def test_shield_finding_is_replayed_on_the_artifact(tmp_path):
    d = _case(tmp_path, 'powershell_encoded_service_injection')
    log = 'srv-ad-01_events.log'
    detector = {'name': 'shield', 'artifact': log, 'tool': 'parse_log_file'}
    v = verifier.verify_finding(d, {'title': 'Prompt injection in the evidence', 'detector': detector})
    assert v['status'] == verifier.VERIFIED and 'hit' in v['reason']
    missing = dict(detector, artifact='absent.log')
    v = verifier.verify_finding(d, {'title': 'Prompt injection', 'detector': missing})
    assert v['status'] == verifier.UNVERIFIED and v['reason'] == 'artifact not found in the case'


def test_shield_replay_on_a_clean_artifact_is_unverified(tmp_path):
    d = _case(tmp_path, 'net_c2_beacon_pcap')
    v = verifier.verify_finding(d, {'title': 'Injection', 'detector': {'name': 'shield', 'artifact': PCAP}})
    assert v['status'] == verifier.UNVERIFIED and v['reason'] == 'shield replay: 0 hit(s)'


def test_ip_at_the_end_of_a_sentence_is_an_entity():
    assert ('ip', '185.225.73.90') in verifier.entities('Beacon to 185.225.73.90.')
    assert verifier.entities('version 1.2.3.4.5') == []


def test_report_metadata_written_by_phoenix_is_not_a_claim():
    report = ('# R\n\n> Report generated by Phoenix DFIR (autonomous investigator) le 2026-10-30 15:41:57\n\n'
              'Beacon to 185.225.73.90 [F1].\n')
    c = verifier.check_citations(report, {1})
    assert c['factual_sentences'] == 1 and c['coverage'] == 1.0


def test_a_citation_does_not_prove_an_entity_the_finding_never_observed(tmp_path):
    case = tmp_path / 'ssh'
    shutil.copytree(os.path.join(SUITE, 'ssh_bruteforce_valid_account'), case,
                    ignore=shutil.ignore_patterns('ground_truth.json'))
    toolkit.set_active_case(str(case))
    toolkit.run_tool('parse_log_file', {'file_path': str(case / 'auth.log')})
    memory.record_finding(str(case), 'Valid account login', severity='high', mitre='T1078',
                          evidence_refs=[{'artifact': 'auth.log', 'kind': 'line', 'value': 37}])
    verified = set(verifier.verify_case(str(case))['verified_ids'])
    report = 'Login from 185.220.101.44 [F1].\nExfiltration to 8.8.4.4 [F1].\n'
    c = verifier.check_citations(report, verified, str(case))
    assert c['factual_sentences'] == 2 and c['linked'] == 1
    assert '8.8.4.4' in c['unlinked'][0]['reason']
    assert verifier.check_citations(report, verified)['linked'] == 2  # without the case: ids only


def test_written_references_are_not_email_entities():
    sentence = 'Cluster admin binding (T1098.006; line=169@kube-apiserver-audit.log, row=3@QuarantineEventsV2) [F1]'
    assert verifier.entities(sentence) == []
    assert ('email', 'a.martin@nordbridge.fr') in verifier.entities('Mail forwarded by a.martin@nordbridge.fr')


def test_beacon_detection_alone_verifies_its_tls_fingerprints(beacon_case):
    finding = {'title': 'C2 beacon to 185.225.73.90 (SNI cdn-telemetry-sync.net, '
                        'JA3 f4d2d3a6181a89560a58f2e52107b0c6)', 'evidence_refs': [_ref(18)]}
    assert verifier.verify_finding(beacon_case, finding)['status'] == verifier.VERIFIED
