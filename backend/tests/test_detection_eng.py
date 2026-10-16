#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ingenierie de detection : generation Sigma (structure valide), evaluation
du sous-ensemble Sigma, correspondance au malveillant sans faux positif sur le
corpus benin, generation et test YARA."""

import os
import shutil
import sys

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
_MCP_DIR = os.path.join(_ROOT, 'mcp-server')
if _MCP_DIR not in sys.path:
    sys.path.insert(0, _MCP_DIR)

from phoenix_dfir_mcp import memory, pathpolicy, toolkit  # noqa: E402
from phoenix_dfir_mcp.ext import detect_engineering as de  # noqa: E402

SUITE = os.path.join(_ROOT, 'eval', 'suite')


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    monkeypatch.delenv('PHOENIX_STRICT_EVIDENCE', raising=False)
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


def _copy(tmp_path, name):
    case = tmp_path / name
    shutil.copytree(os.path.join(SUITE, name), case, ignore=shutil.ignore_patterns('ground_truth.json'))
    toolkit.set_active_case(str(case))
    return str(case)


@pytest.fixture
def ps_case(tmp_path):
    d = _copy(tmp_path, 'powershell_encoded_service_injection')
    toolkit.run_tool('parse_log_file', {'file_path': os.path.join(d, 'srv-ad-01_events.log')})
    for line, title, mitre in ((2, 'PowerShell encode', 'T1059.001'),
                               (3, 'Service de persistance', 'T1543.003')):
        r = toolkit.run_tool('record_finding', {
            'case_dir': d, 'title': title, 'severity': 'high', 'mitre': mitre,
            'evidence_refs': [{'artifact': 'srv-ad-01_events.log', 'kind': 'line', 'value': line}]})
        assert 'recorded' in r
    return d


def test_sigma_genere_valide_et_teste(ps_case):
    r = toolkit.run_tool('detect_generate_sigma', {'case_dir': ps_case, 'finding_id': 1})
    rule = r['rules'][0]
    assert rule['rule_file'] == os.path.join('detections', 'phoenix_detection_f1_1.yml')
    assert rule['validation_gaps'] == []
    parsed = de.parse_yaml(rule['yaml'])
    assert parsed['status'] == 'experimental' and parsed['references'] == []
    assert parsed['tags'] == ['attack.t1059.001'] and parsed['level'] == 'high'
    assert parsed['logsource'] == {'product': 'windows', 'category': 'process_creation'}
    sel = parsed['detection']['selection']
    assert sel['Image|endswith'] == '\\powershell.exe'
    assert set(sel['CommandLine|contains|all']) == {'-enc', '-nop', '-w hidden'}
    assert parsed['detection']['condition'] == 'selection'
    yaml = pytest.importorskip('yaml')
    assert yaml.safe_load(rule['yaml']) == parsed  # YAML standard, meme lecture
    test = rule['test']
    assert test['malicious_matched'] and test['missed'] == []
    assert test['case_matches'] == [{'artifact': 'srv-ad-01_events.log', 'kind': 'line', 'value': '2'}]
    assert test['benign_events'] > 0 and test['false_positives'] == 0 and test['verdict'] == 'ok'
    # id deterministe (uuid5) : regenerer donne le meme id
    again = toolkit.run_tool('detect_generate_sigma', {'case_dir': ps_case, 'finding_id': 1})
    assert again['rules'][0]['id'] == rule['id']


def test_sigma_service_et_retest(ps_case):
    r = toolkit.run_tool('detect_generate_sigma', {'case_dir': ps_case, 'finding_id': 2})
    parsed = de.parse_yaml(r['rules'][0]['yaml'])
    assert parsed['detection']['selection'] == {'EventID': 7045, 'ServiceName': 'WinDefendHealthSvc',
                                                'ImagePath|endswith': '\\updater.exe'}
    assert parsed['logsource'] == {'product': 'windows', 'service': 'system'}
    t = toolkit.run_tool('detect_test_rule', {'case_dir': ps_case, 'rule_file': 'phoenix_detection_f2_1.yml'})
    assert t['malicious_matched'] and t['false_positives'] == 0
    assert 'error' in toolkit.run_tool('detect_test_rule', {'case_dir': ps_case,
                                                            'rule_file': '../case_state.json'})
    # regles listees dans l'annexe du rapport, jamais comme artefacts
    assert 'phoenix_detection_f2_1.yml' in memory.render_markdown(ps_case)
    names = [a['name'] for a in toolkit.run_tool('list_artifacts', {'case_dir': ps_case})['artifacts']]
    assert names == ['srv-ad-01_events.log']
    assert 'error' in toolkit.run_tool('detect_generate_sigma', {'case_dir': ps_case, 'finding_id': 9})


def test_sigma_ssh_linux_sans_faux_positif(tmp_path):
    d = _copy(tmp_path, 'ssh_bruteforce_valid_account')
    toolkit.run_tool('parse_log_file', {'file_path': os.path.join(d, 'auth.log')})
    toolkit.run_tool('record_finding', {
        'case_dir': d, 'title': 'Connexion svc_backup apres brute force', 'severity': 'critical',
        'mitre': 'T1110.001', 'evidence_refs': [{'artifact': 'auth.log', 'kind': 'line', 'value': 37}]})
    rule = toolkit.run_tool('detect_generate_sigma', {'case_dir': d, 'finding_id': 1})['rules'][0]
    parsed = de.parse_yaml(rule['yaml'])
    assert parsed['logsource'] == {'product': 'linux', 'service': 'auth'}
    assert parsed['detection']['selection'] == {
        'message|contains|all': ['Accepted password for', '185.220.101.44']}
    assert parsed['level'] == 'critical'
    assert rule['test']['malicious_matched'] and rule['test']['false_positives'] == 0


def test_faux_positifs_mesures_et_filtre(tmp_path):
    """Une regle trop large touche le corpus benin ; le filtre l'en exclut."""
    d = str(tmp_path / 'vide')
    os.makedirs(d)
    broad = {'title': 'x', 'detection': {'selection': {'message|contains': ['Accepted publickey']},
                                         'condition': 'selection'}}
    t = de.test_sigma(d, broad)
    assert t['false_positives'] == 1 and 'deploy' in t['false_positive_samples'][0]['text']
    filtered = {'title': 'x', 'detection': {
        'selection': {'message|contains': ['Accepted publickey']},
        'filter': {'message|contains': ['10.10.1.20']},
        'condition': 'selection and not filter'}}
    assert de.test_sigma(d, filtered)['false_positives'] == 0


def test_evaluateur_sous_ensemble_sigma():
    ev = {'Image': 'C:\\Windows\\System32\\cmd.exe', 'CommandLine': 'cmd /c whoami /all',
          'EventID': '4688'}

    def rule(sel, cond='selection', **extra):
        return {'detection': dict(selection=sel, condition=cond, **extra)}
    assert de.match_rule(rule({'Image|endswith': '\\CMD.EXE'}), ev)  # insensible a la casse
    assert de.match_rule(rule({'Image|startswith': 'c:\\windows'}), ev)
    assert de.match_rule(rule({'EventID': 4688}), ev)
    assert not de.match_rule(rule({'EventID': 4624}), ev)
    assert de.match_rule(rule({'CommandLine|contains': ['nope', 'whoami']}), ev)  # liste = OU
    assert not de.match_rule(rule({'CommandLine|contains|all': ['nope', 'whoami']}), ev)
    assert not de.match_rule(rule({'CommandLine|contains': 'whoami', 'Image|endswith': 'ps.exe'}), ev)
    assert not de.match_rule(rule({'User': 'x'}), ev)  # champ absent
    assert not de.match_rule(rule({'Image|endswith': 'cmd.exe'}, 'selection and not filter',
                                  filter={'CommandLine|contains': '/all'}), ev)
    assert de.match_rule(rule({'CommandLine|contains': 'who\\*'}), {'CommandLine': 'who*'})
    with pytest.raises(ValueError):
        de.match_rule(rule({'Image|re': '.*'}), ev)
    with pytest.raises(ValueError):
        de.match_rule(rule({'Image': 'x'}, '1 of selection*'), ev)


def test_yaml_minimal_echappement():
    text = de.render_sigma({'title': "L'attaque: test", 'detection': {
        'selection': {'CommandLine|contains': ["it's", 'a*b']}, 'condition': 'selection'}})
    parsed = de.parse_yaml(text)
    assert parsed['title'] == "L'attaque: test"
    assert parsed['detection']['selection']['CommandLine|contains'] == ["it's", 'a\\*b']
    assert de.match_rule(parsed, {'CommandLine': 'xx a*b'}) and not de.match_rule(parsed, {'CommandLine': 'axxb'})
    assert de.validate_sigma(parsed)  # champs obligatoires manquants detectes


def test_yara_chaines_distinctives_et_tests(tmp_path):
    d = tmp_path / 'cas'
    (d / 'extracted').mkdir(parents=True)
    payload = (b'MZ\x90\x00' + b'\x00' * 60 + b'This program cannot be run in DOS mode\x00'
               b'kernel32.dll\x00GetProcAddress\x00'
               b'http://45.137.21.9/stage2.bin\x00'
               b'C:\\ProgramData\\updater.exe\x00'
               b'svc_backup_beacon_key=Zx81Q\x00'
               b'/usr/bin/systemctl restart nginx\x00'  # present dans le corpus benin
               + 'WinDefendHealthSvc'.encode('utf-16-le') + b'\x00\x00'
               + b'\x00\x01\x02' * 50)
    target = d / 'extracted' / 'dropper.bin'
    target.write_bytes(payload)
    (d / 'notes.txt').write_text('rien de special ici\n')
    toolkit.set_active_case(str(d))
    r = toolkit.run_tool('detect_generate_yara', {'case_dir': str(d), 'file_path': str(target)})
    assert 'error' not in r, r
    strings = r['strings']
    assert 'http://45.137.21.9/stage2.bin' in strings and 'C:\\ProgramData\\updater.exe' in strings
    assert 'WinDefendHealthSvc' in strings
    assert not any('kernel32' in s.lower() or 'dos mode' in s.lower() for s in strings)
    assert not any('systemctl restart nginx' in s for s in strings)  # vu dans le corpus benin
    assert 'uint16(0) == 0x5A4D and' in r['rule'] and 'of them' in r['rule']
    assert '"WinDefendHealthSvc" wide' in r['rule'] and 'C:\\\\ProgramData' in r['rule']
    test = r['test']
    assert test['case_matches'] == ['extracted/dropper.bin'] and test['malicious_matched']
    assert test['false_positives'] == 0 and test['verdict'] == 'ok'
    parsed = de.parse_yara(r['rule'])
    assert {s['value'] for s in parsed['strings']} == set(strings) and parsed['mz']
    assert not de.match_yara(parsed, payload[2:])  # sans en-tete MZ
    name = os.path.basename(r['rule_file'])
    assert name.startswith('phoenix_detection_') and name.endswith('.yar')
    retest = toolkit.run_tool('detect_test_rule', {'case_dir': str(d), 'rule_file': name})
    assert retest['malicious_matched'] and retest['false_positives'] == 0
    # fichier hors du cas refuse
    outside = tmp_path / 'autre.bin'
    outside.write_bytes(payload)
    assert 'error' in de.generate_yara(str(d), str(outside))
