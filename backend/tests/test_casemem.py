#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Memoire episodique inter-enquetes : profils de cas, similarite (Jaccard
pondere + TF-IDF) et isolation par racines de cas."""

import json
import os
import sys

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
_MCP_DIR = os.path.join(_ROOT, 'mcp-server')
if _MCP_DIR not in sys.path:
    sys.path.insert(0, _MCP_DIR)

from phoenix_dfir_mcp import memory, pathpolicy, toolkit  # noqa: E402
from phoenix_dfir_mcp.ext import casemem  # noqa: E402


@pytest.fixture(autouse=True)
def _isolation(monkeypatch, tmp_path):
    monkeypatch.delenv('PHOENIX_CASES_ROOT', raising=False)
    monkeypatch.setenv('PHOENIX_CASEMEM_INDEX', str(tmp_path / 'index.json'))
    pathpolicy.reset()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()


def _case(path, findings):
    path.mkdir(parents=True)
    for title, mitre, evidence in findings:
        memory.record_finding(str(path), title, severity='high', mitre=mitre, evidence=evidence)
    return str(path)


@pytest.fixture
def root(tmp_path, monkeypatch):
    r = tmp_path / 'cases'
    _case(r / 'past_powershell', [
        ('PowerShell encode telecharge un script', 'T1059.001',
         'IEX DownloadString http://45.137.21.9/a.ps1 via powershell -enc'),
        ('Service de persistance cree', 'T1543.003', 'ImagePath C:\\ProgramData\\updater.exe')])
    _case(r / 'past_ssh', [
        ('Brute force SSH puis connexion', 'T1110.001', 'hydra depuis 185.220.101.44 sur svc_backup')])
    _case(r / 'past_c2', [
        ('Beaconing HTTPS regulier', 'T1071.001', 'PC-COMPTA-07 vers 91.215.85.14:443 toutes les 60s')])
    monkeypatch.setenv('PHOENIX_CASES_ROOT', str(r))
    return r


def test_profil_extrait_iocs_techniques_outils_termes(tmp_path):
    d = _case(tmp_path / 'c', [('Mimikatz sur DC', 'T1003.001',
                                'sekurlsa via mimikatz, hash 0123456789abcdef0123456789abcdef, '
                                'exfil vers files.evil-cdn.com et 8.8.4.4, fichier dump.zip')])
    p = casemem.profile(d)
    assert {'T1003.001', 'T1003'} <= set(p['techniques'])
    assert {'ip:8.8.4.4', 'hash:0123456789abcdef0123456789abcdef', 'domain:files.evil-cdn.com'} <= set(p['iocs'])
    assert 'domain:dump.zip' not in p['iocs']
    assert 'mimikatz' in p['tools'] and 'mimikatz' in p['top_terms']


def test_classement_par_similarite(root, tmp_path):
    current = _case(root / 'current', [
        ('PowerShell encode et telechargement', 'T1059.001',
         'powershell -nop -enc puis DownloadString depuis 45.137.21.9'),
        ('Service WinDefendHealthSvc', 'T1543.003', 'service de persistance')])
    toolkit.set_active_case(current)
    r = toolkit.run_tool('casemem_similar_cases', {'case_dir': current, 'top_k': 3})
    ids = [m['case_id'] for m in r['matches']]
    assert ids[0] == 'past_powershell' and 'current' not in ids
    top = r['matches'][0]
    assert top['shared_iocs'] == ['ip:45.137.21.9']
    assert {'T1059.001', 'T1543.003'} <= set(top['shared_techniques'])
    assert 'IoC' in top['why'] and 'techniques' in top['why']
    assert all(a['score'] >= b['score'] for a, b in zip(r['matches'], r['matches'][1:]))
    # scores bornes, composantes exposees
    assert 0 < top['score'] <= 1 and set(top['components']) == set(casemem.WEIGHTS)


def test_similarite_jaccard_et_cosinus():
    assert casemem.jaccard({'a', 'b'}, {'b', 'c'}) == pytest.approx(1 / 3)
    assert casemem.jaccard(set(), set()) == 0
    assert casemem.cosine({'x': 1.0}, {'x': 2.0}) == pytest.approx(1.0)
    assert casemem.cosine({'x': 1.0}, {'y': 1.0}) == 0


def test_isolation_racines(root, tmp_path):
    outside = _case(tmp_path / 'ailleurs' / 'secret_case', [
        ('PowerShell encode', 'T1059.001', '45.137.21.9 powershell')])
    # Lien symbolique sous la racine vers un cas exterieur : jamais lu
    os.symlink(outside, root / 'lien_vers_secret')
    current = _case(root / 'current', [('PowerShell', 'T1059.001', '45.137.21.9')])
    r = casemem.similar_cases(current, top_k=10)
    assert 'secret_case' not in [m['case_id'] for m in r['matches']]
    assert 'lien_vers_secret' not in [m['case_id'] for m in r['matches']]
    refused = casemem.index_case(outside)
    assert 'error' in refused
    index = json.load(open(tmp_path / 'index.json', encoding='utf-8'))
    assert all(p.startswith(os.path.realpath(root)) for p in index['cases'])
    # la racine elle-meme n'est pas un cas
    assert not casemem.allowed_case(str(root))


def test_sans_racine_seul_le_dossier_explicite(tmp_path, monkeypatch):
    monkeypatch.delenv('PHOENIX_CASES_ROOT', raising=False)
    monkeypatch.setattr(casemem, '_DEFAULT_ROOTS', ())
    a = _case(tmp_path / 'a', [('C2', 'T1071.001', '91.215.85.14')])
    b = _case(tmp_path / 'b', [('C2 encore', 'T1071.001', '91.215.85.14')])
    assert casemem.roots() == []
    assert casemem.index_case(a)['indexed'] == 'a'
    # pas de balayage implicite : b n'est connu que s'il est indexe explicitement
    assert [m['case_id'] for m in casemem.similar_cases(b)['matches']] == ['a']
    # dans un job, un dossier hors du cas du job est refuse
    with pathpolicy.job_scope(b):
        assert 'error' in casemem.index_case(a)
        assert 'error' not in casemem.index_case(b)
