#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bounded parallel extraction in the deterministic triage."""

import os

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')

from phoenix_dfir_mcp import pathpolicy, toolkit, triage  # noqa: E402


SUITE = os.path.join(_ROOT, 'eval', 'suite')


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    monkeypatch.delenv('PHOENIX_INVESTIGATION_MODE', raising=False)
    monkeypatch.delenv('PHOENIX_STRICT_EVIDENCE', raising=False)
    monkeypatch.delenv('PHOENIX_AGENT_MAX_TOKENS', raising=False)
    monkeypatch.delenv('PHOENIX_EXTRACTION_WORKERS', raising=False)
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


# ============================================================================
# Bounded parallel extraction (deterministic)
# ============================================================================

@pytest.mark.parametrize('case', ['ransomware_antiforensics', 'net_c2_beacon_pcap', 'cloud_m365_bec_oauth'])
def test_parallel_triage_is_byte_identical(case):
    path = os.path.join(SUITE, case)
    one = triage.to_json(triage.run_triage(path, workers=1))
    assert triage.to_json(triage.run_triage(path, workers=4)) == one
    assert triage.to_json(triage.run_triage(path, workers=16)) == one


def test_parallel_triage_keeps_the_derived_scope(tmp_path):
    derived = tmp_path / 'derived'
    path = os.path.join(SUITE, 'disk_image_data_exfiltration')
    serial = triage.run_triage(path, derived_dir=str(tmp_path / 'serial'), workers=1)
    parallel = triage.run_triage(path, derived_dir=str(derived), workers=4)
    assert triage.to_json(parallel) == triage.to_json(serial)
    assert not os.path.exists(os.path.join(path, 'derived'))


def test_extraction_workers_env(monkeypatch):
    monkeypatch.setenv('PHOENIX_EXTRACTION_WORKERS', '3')
    assert triage.extraction_workers() == 3
    monkeypatch.setenv('PHOENIX_EXTRACTION_WORKERS', '999')
    assert triage.extraction_workers() == triage.MAX_WORKERS
    monkeypatch.setenv('PHOENIX_EXTRACTION_WORKERS', 'many')
    assert triage.extraction_workers() == 1
