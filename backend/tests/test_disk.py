#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de l'analyse d'images disque (The Sleuth Kit) et du corrige factuel
du banc d'evaluation."""

import hashlib
import os
import shutil

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')

from phoenix_dfir_mcp import disk, evaluation, evidence_db, pathpolicy, phases, toolkit  # noqa: E402

IMAGE = os.path.join(_ROOT, 'eval', 'suite', 'disk_image_data_exfiltration', 'poste_jdoe.img')
needs_tsk = pytest.mark.skipif(not disk.tsk_available(), reason='The Sleuth Kit non installe')


@pytest.fixture(autouse=True)
def _isolation():
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


@pytest.fixture
def case(tmp_path):
    case_dir = tmp_path / 'cas'
    case_dir.mkdir()
    shutil.copy(IMAGE, case_dir / 'poste_jdoe.img')
    toolkit.set_active_case(str(case_dir))
    return str(case_dir)


# ============================================================================
# Unitaires (sans Sleuth Kit)
# ============================================================================

def test_detection_disque_ou_memoire(tmp_path):
    mbr = tmp_path / 'disque.raw'
    data = bytearray(4096)
    data[510:512] = b'\x55\xaa'
    mbr.write_bytes(bytes(data))
    memory_dump = tmp_path / 'memoire.raw'
    memory_dump.write_bytes(b'\x00' * 4096)
    ext = tmp_path / 'fs.raw'
    raw = bytearray(4096)
    raw[1080:1082] = b'\x53\xef'
    ext.write_bytes(bytes(raw))
    assert disk.looks_like_disk(str(mbr))
    assert disk.looks_like_disk(str(ext))
    assert not disk.looks_like_disk(str(memory_dump))
    assert disk.looks_like_disk(str(tmp_path / 'image.E01'))
    assert not disk.looks_like_disk(str(tmp_path / 'notes.txt'))


def test_motifs_de_chemins():
    assert disk._match('Windows/System32/winevt/Logs/Security.evtx', 'windows/system32/winevt/logs/*.evtx')
    assert disk._match('Users/jdoe/NTUSER.DAT', 'Users/*/NTUSER.DAT')
    assert not disk._match('Users/jdoe/sub/NTUSER.DAT', 'Users/*/NTUSER.DAT')
    assert disk._match('Windows/System32/Tasks/Microsoft/Update', 'Windows/System32/Tasks/**')
    assert disk._match('var/log/auth.log.1', 'var/log/auth.log*')


def test_extraction_confinee_au_dossier(tmp_path):
    base = str(tmp_path / 'extracted')
    assert disk._safe_target(base, 'img', 0, '../../etc/passwd').startswith(os.path.realpath(base))
    assert disk._safe_target(base, 'img', 0, 'Users/jdoe/x').endswith(os.path.join('Users', 'jdoe', 'x'))


def test_lignes_fls_et_bodyfile():
    m = disk._FLS_LINE.match('r/r * 128-128-1(realloc):\tUsers/jdoe/secret.docx')
    assert m.group('inode') == '128-128-1' and m.group('deleted')
    assert not disk._FLS_LINE.match('r/r 35:\tvar/log/auth.log').group('deleted')
    events = disk._parse_bodyfile(
        '0|/Users/a.txt (deleted)|26|r/rrw-r--r--|0|0|12|1760000000|1760000100|1760000200|0', 0)
    assert [e['macb'] for e in events] == ['m', 'a', 'c']  # creation = 0 ignoree
    assert events[0]['deleted'] and events[0]['inode'] == '26'


def test_reference_inode_ntfs():
    assert toolkit.ref_value('inode', '128-128-1') == '128-128-1'
    assert toolkit.ref_value('inode', '26') == '26'
    assert toolkit.ref_value('inode', '../etc') is None
    assert toolkit.ref_value('line', '007') == '7'


def test_outils_absents_message_explicite(monkeypatch, tmp_path):
    monkeypatch.setattr(disk, 'tsk_available', lambda: False)
    img = tmp_path / 'x.E01'
    img.write_bytes(b'EVF')
    r = disk.image_info(str(img))
    assert 'Sleuth Kit' in r['error'] and 'help' in r
    groups, unavailable = toolkit.applicable_tools(str(img))
    assert groups == [] and unavailable == ['The Sleuth Kit']


def test_corrige_factuel():
    facts = evaluation._normalize_facts([
        {'id': 'Q1', 'question': 'Fichier ?', 'answer': 'plan_strategique_2027.docx', 'related': ['Orion']},
        {'id': 'Q2', 'question': 'IP ?', 'answer': ['45.137.21.9:8080'], 'related': ['45.137.21.9']},
        {'id': 'Q3', 'question': 'Compte ?', 'answer': ['jdoe']},
    ])
    res = evaluation.score_facts(facts, "Le fichier PLAN_STRATEGIQUE_2027.docx a ete supprime ; "
                                        "envoi vers 45.137.21.9 en HTTP.")
    assert [(r['exact'], r['detected']) for r in res] == [(True, True), (False, True), (False, False)]
    truth = evaluation.normalize_truth({'facts': [{'answer': 'x'}]})
    assert truth['facts'][0]['id'] == 'F1'


# ============================================================================
# Integration (Sleuth Kit reel, image de la suite d'evaluation)
# ============================================================================

@needs_tsk
def test_inventaire_image(case):
    info = toolkit.run_tool('disk_image_info', {'file_path': os.path.join(case, 'poste_jdoe.img')})
    assert info['filesystems'][0]['fs_type'] == 'Ext4'
    assert info['filesystems'][0]['offset'] == 0


@needs_tsk
def test_fichiers_supprimes(case):
    r = toolkit.run_tool('disk_list_files', {'file_path': os.path.join(case, 'poste_jdoe.img'),
                                             'deleted_only': True})
    paths = {e['path'] for e in r['entries']}
    assert 'Users/jdoe/Documents/Projet_Orion/plan_strategique_2027.docx' in paths
    assert 'Users/Public/maj_q3.zip' in paths and r['deleted'] == 2


@needs_tsk
def test_extraction_avec_provenance_et_couverture(case):
    img = os.path.join(case, 'poste_jdoe.img')
    r = toolkit.run_tool('disk_extract_artifacts', {'file_path': img, 'case_dir': case})
    extracted = {e['source_path']: e for e in r['extracted']}
    hist = 'Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt'
    assert hist in extracted and 'var/log/auth.log' in extracted
    out = os.path.join(case, extracted[hist]['extracted_to'])
    data = open(out, 'rb').read()
    assert b'45.137.21.9' in data
    assert extracted[hist]['sha256'] == hashlib.sha256(data).hexdigest()
    assert os.path.isfile(os.path.join(case, r['manifest']))
    # Le manifeste n'est pas un artefact ; les fichiers extraits en sont
    names = [a['name'] for a in toolkit.run_tool('list_artifacts', {'case_dir': case})['artifacts']]
    assert disk.MANIFEST not in names and 'ConsoleHost_history.txt' in names
    # La porte d'extraction exige desormais l'analyse des fichiers extraits
    gaps = phases.gate_extraction(case, None)
    assert any('ConsoleHost_history.txt' in g for g in gaps)
    toolkit.run_tool('disk_timeline', {'file_path': img})
    toolkit.run_tool('disk_image_info', {'file_path': img})
    for rel in ('ConsoleHost_history.txt', 'auth.log'):
        path = next(os.path.join(case, e['extracted_to']) for e in r['extracted']
                    if e['source_path'].endswith(rel))
        toolkit.run_tool('parse_log_file', {'file_path': path})
    assert phases.gate_extraction(case, None) == []


@needs_tsk
def test_timeline_disque_indexee_et_citable(case):
    img = os.path.join(case, 'poste_jdoe.img')
    tl = toolkit.run_tool('disk_timeline', {'file_path': img})
    assert tl['total_events'] > 10 and 'events' not in tl and tl['preview']
    hits = toolkit.run_tool('search_evidence', {'case_dir': case, 'query': 'maj_q3.zip'})
    assert hits['total_matches'] >= 1
    ref = hits['events'][0]['ref']
    assert ref['kind'] == 'inode'
    ok, bad = toolkit.validate_refs([dict(ref, artifact='poste_jdoe.img')], case)
    assert ok and not bad
    assert evidence_db.sources(case)['sources'][0]['tool'] == 'disk_timeline'


# ============================================================================
# Bout en bout : enquete a phases + notation sur le cas image disque
# ============================================================================

import json  # noqa: E402

from phoenix_dfir_mcp import memory  # noqa: E402

SUITE = os.path.join(_ROOT, 'eval', 'suite')
HIST = 'Users/jdoe/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt'

REPORT = """# Exfiltration depuis le poste de jdoe
## Resume executif
Le compte jdoe a compresse Projet_Orion dans maj_q3.zip puis l'a envoye vers
http://45.137.21.9:8080/upload, avant de supprimer plan_strategique_2027.docx.
## Chronologie
- Compress-Archive puis Invoke-WebRequest -Method Put (ConsoleHost_history.txt lignes 2-3).
## Indicateurs de compromission (IoC)
- 45.137.21.9:8080
## Mapping MITRE ATT&CK
T1560.001, T1070.004
## Conclusions
Exfiltration de donnees confidentielles par un utilisateur interne.
## Recommandations
Bloquer 45.137.21.9, preserver le poste, auditer les acces a Projet_Orion.
"""


def _call(name, args):
    return {'tool_calls': [{'id': name, 'type': 'function',
                            'function': {'name': name, 'arguments': json.dumps(args)}}]}


class DiskCaseLLM:
    def __init__(self, **kwargs):
        self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
        self.step = {}

    def chat(self, messages, tools=None, model=None):
        self.usage['calls'] += 1
        if tools is None or 'verificateur' in messages[0]['content']:
            return {'content': 'fin'}
        prompt = messages[1]['content']
        phase = int(prompt.split('PHASE ', 1)[1][0])
        case = prompt.split('Dossier du cas : ', 1)[1].split('\n', 1)[0].strip()
        n = self.step.get(phase, 0)
        self.step[phase] = n + 1
        img = os.path.join(case, 'poste_jdoe.img')
        extracted = os.path.join(case, 'extracted', 'poste_jdoe.img', 'p0')
        script = {
            1: [_call('list_artifacts', {'case_dir': case}),
                _call('set_investigation_plan', {'case_dir': case, 'steps': ['Image', 'Correlation']}),
                _call('disk_image_info', {'file_path': img})],
            2: [_call('disk_extract_artifacts', {'file_path': img, 'case_dir': case}),
                _call('disk_timeline', {'file_path': img}),
                _call('disk_list_files', {'file_path': img, 'deleted_only': True}),
                _call('parse_log_file', {'file_path': os.path.join(extracted, HIST)}),
                _call('parse_log_file', {'file_path': os.path.join(extracted, 'var/log/auth.log')})],
            3: [_call('search_evidence', {'case_dir': case, 'query': 'Invoke-WebRequest'}),
                _call('record_finding', {
                    'case_dir': case, 'title': 'Archive maj_q3.zip exfiltree vers 45.137.21.9',
                    'severity': 'critical', 'mitre': 'T1560.001', 'evidence': 'ConsoleHost_history',
                    'evidence_refs': [{'artifact': 'ConsoleHost_history.txt', 'kind': 'line', 'value': 3}]}),
                _call('record_finding', {
                    'case_dir': case, 'title': 'Suppression de plan_strategique_2027.docx',
                    'severity': 'high', 'mitre': 'T1070.004', 'evidence': 'fichier supprime',
                    'evidence_refs': [{'artifact': 'ConsoleHost_history.txt', 'kind': 'line', 'value': 5}]})],
            4: [_call('challenge_finding', {'case_dir': case, 'finding_id': 1, 'verdict': 'upheld',
                                            'alternative': 'Sauvegarde legitime',
                                            'rationale': 'Destination externe non referencee.'}),
                _call('challenge_finding', {'case_dir': case, 'finding_id': 2, 'verdict': 'upheld',
                                            'alternative': 'Menage de routine',
                                            'rationale': 'Supprime juste apres envoi.'}),
                _call('audit_tool_coverage', {'case_dir': case}),
                _call('audit_evidence_coverage', {'case_dir': case})],
            5: [_call('save_report', {'case_dir': case, 'title': 'Exfiltration', 'markdown': REPORT})],
        }[phase]
        return script[n] if n < len(script) else {'content': 'phase terminee'}


@needs_tsk
def test_benchmark_image_disque_bout_en_bout(monkeypatch):
    monkeypatch.setattr(phases, 'CopilotClient', DiskCaseLLM)
    monkeypatch.delenv('PHOENIX_INVESTIGATION_MODE', raising=False)
    report = evaluation.run_suite(SUITE, only=['disk_image_data_exfiltration'], mode='phased')
    case = report['cases'][0]
    assert 'error' not in case, case
    sc = case['score']
    assert sc['fact_exact'] == 1.0 and sc['fact_detection'] == 1.0, sc['facts']
    assert sc['technique_recall'] == 1.0 and sc['ioc_recall'] == 1.0
    assert sc['passed']
    assert report['summary']['fact_exact'] == 1.0
    assert 'Corrige factuel' in evaluation.render_markdown(report)
    # Memoire du cas : pas de pollution de la suite d'origine
    assert not os.path.exists(os.path.join(SUITE, 'disk_image_data_exfiltration', memory.STATE_FILENAME))
