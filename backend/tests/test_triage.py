"""Deterministic triage (no LLM) on the versioned evaluation cases."""

import os
import shutil
from pathlib import Path

import pytest

from phoenix_dfir_mcp import triage

SUITE = Path(__file__).resolve().parents[2] / 'eval' / 'suite'
SEVERE = ('critical', 'high', 'medium')


def _snapshot(folder):
    return {p.relative_to(folder).as_posix(): (p.stat().st_size, p.stat().st_mtime_ns)
            for p in Path(folder).rglob('*')}


@pytest.fixture(scope='module')
def reports():
    return {case: triage.run_triage(SUITE / case)
            for case in ('net_c2_beacon_pcap', 'ad_kerberoasting_dcsync', 'benign_admin_activity')}


def test_beaconing_to_c2_is_found_with_row(reports):
    report = reports['net_c2_beacon_pcap']
    beacons = [f for f in report['findings']
               if f['entities'].get('dst') == '185.225.73.90' and 'T1071.001' in f['techniques']]
    assert beacons, report['findings']
    beacon = beacons[0]
    assert beacon['severity'] == 'high' and beacon['tool'] == 'net_detect'
    assert all('row' in ref for ref in beacon['refs'])


def test_kerberoasting_is_found_with_record_id(reports):
    report = reports['ad_kerberoasting_dcsync']
    kerberoast = [f for f in report['findings'] if 'T1558.003' in f['techniques']]
    assert kerberoast, report['findings']
    assert kerberoast[0]['tool'] == 'sigma_scan'
    assert kerberoast[0]['refs'] and all('record_id' in ref for ref in kerberoast[0]['refs'])
    assert kerberoast[0]['count'] == len(kerberoast[0]['refs'])


def test_benign_activity_has_no_finding_medium_or_above(reports):
    report = reports['benign_admin_activity']
    assert [f for f in report['findings'] if f['severity'] in SEVERE] == []
    assert report['summary']['tool_errors'] == 0


def test_ground_truth_is_never_an_artifact(reports):
    for report in reports.values():
        assert 'ground_truth.json' not in [a['path'] for a in report['artifacts']]


def test_artifacts_are_hashed(reports):
    import hashlib
    for case, report in reports.items():
        for artifact in report['artifacts']:
            data = (SUITE / case / artifact['path']).read_bytes()
            assert artifact['sha256'] == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize('case', sorted(p.name for p in SUITE.iterdir() if p.is_dir()))
def test_every_finding_cites_an_observed_reference(case):
    report = triage.run_triage(SUITE / case)
    for finding in report['findings']:
        assert finding['refs'], finding
        for ref in finding['refs']:
            assert set(ref) <= set(triage.REF_KEYS), ref
    assert report['summary']['tool_errors'] == 0, [a['errors'] for a in report['artifacts'] if a['errors']]


def test_triage_is_deterministic_and_read_only(tmp_path):
    case = tmp_path / 'net_c2_beacon_pcap'
    shutil.copytree(SUITE / 'net_c2_beacon_pcap', case)
    before = _snapshot(case)
    first = triage.to_json(triage.run_triage(case))
    second = triage.to_json(triage.run_triage(case))
    assert first == second
    assert _snapshot(case) == before, 'triage must not write into the case folder'


def test_report_files_are_written_only_where_asked(tmp_path, reports):
    out = tmp_path / 'reports'
    json_path, md_path = triage.write_report(reports['net_c2_beacon_pcap'], out)
    assert sorted(os.listdir(out)) == ['triage.json', 'triage.md']
    markdown = Path(md_path).read_text(encoding='utf-8')
    assert '185.225.73.90' in markdown and 'row=18' in markdown
    assert Path(json_path).read_text(encoding='utf-8') == triage.to_json(reports['net_c2_beacon_pcap'])


def test_missing_case_is_an_error(tmp_path):
    with pytest.raises(ValueError):
        triage.run_triage(tmp_path / 'absent')


@pytest.mark.skipif(not shutil.which('fls') or not shutil.which('icat'),
                    reason='The Sleuth Kit (fls, icat) is not installed')
def test_disk_image_derived_files_are_triaged_outside_the_case(tmp_path):
    case = tmp_path / 'disk_image_data_exfiltration'
    shutil.copytree(SUITE / 'disk_image_data_exfiltration', case)
    before = _snapshot(case)
    report = triage.run_triage(case)
    assert _snapshot(case) == before
    derived = [a['path'] for a in report['artifacts'] if a['path'].startswith('derived/')]
    assert 'derived/extracted/poste_jdoe.img/p0/var/log/auth.log' in derived
    kept = tmp_path / 'derived'
    report = triage.run_triage(case, derived_dir=kept)
    assert (kept / 'extracted' / 'poste_jdoe.img' / 'p0' / 'var' / 'log' / 'auth.log').is_file()
    assert _snapshot(case) == before
