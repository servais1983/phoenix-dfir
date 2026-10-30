#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Benign counter-examples (eval/build_benign_cases.py): legitimate activity that
looks like what each deterministic detector looks for must raise nothing."""

import json
import os

import pytest

from phoenix_dfir_mcp import triage

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
SUITE = os.path.join(_ROOT, 'eval', 'suite')

import build_benign_cases  # noqa: E402  (eval/ is on the pytest pythonpath)

CASES = sorted(build_benign_cases.CASES)


@pytest.mark.parametrize('case', CASES)
def test_benign_case_raises_no_finding(case):
    report = triage.run_triage(os.path.join(SUITE, case))
    with open(os.path.join(SUITE, case, 'ground_truth.json'), encoding='utf-8') as f:
        truth = json.load(f)
    assert truth['benign'] is True
    significant = [(f['severity'], f['title']) for f in report['findings']
                   if f['severity'] in ('critical', 'high', 'medium')]
    assert significant == []
    techniques = report['summary']['techniques']
    assert not [t for t in techniques if any(t == x or t.startswith(x + '.') for x in truth['forbidden_techniques'])]


def test_builder_is_deterministic(tmp_path):
    build_benign_cases.build_all(str(tmp_path))
    for case in CASES:
        for name in os.listdir(tmp_path / case):
            with open(tmp_path / case / name, 'rb') as a, open(os.path.join(SUITE, case, name), 'rb') as b:
                assert a.read() == b.read(), (case, name)
