#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hypotheses concurrentes (mise a jour bayesienne), retro-compatibilite de
case_state.json, portes qualite associees et enquete cinq phases de bout en
bout (enqueteur simule) exercant hypotheses, graphe, detection et memoire
inter-enquetes."""

import json
import math
import os
import re
import shutil

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')

from phoenix_dfir_mcp import investigator, memory, pathpolicy, phases, toolkit  # noqa: E402

SUITE = os.path.join(_ROOT, 'eval', 'suite')


@pytest.fixture(autouse=True)
def _isolation(monkeypatch, tmp_path):
    monkeypatch.delenv('PHOENIX_INVESTIGATION_MODE', raising=False)
    monkeypatch.delenv('PHOENIX_STRICT_EVIDENCE', raising=False)
    monkeypatch.delenv('PHOENIX_CASES_ROOT', raising=False)
    monkeypatch.setenv('PHOENIX_CASEMEM_INDEX', str(tmp_path / 'casemem_index.json'))
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


def _odds(p):
    return p / (1 - p)


# ============================================================================
# Mise a jour bayesienne
# ============================================================================

def test_echelle_et_log_cote():
    assert memory.likelihood_ratio('weak') == 2 and memory.likelihood_ratio('moderate') == 5
    assert memory.likelihood_ratio('strong') == 20 and memory.likelihood_ratio('neutral') == 1
    assert memory.likelihood_ratio(7) == 7 and memory.likelihood_ratio('7.5') == 7.5
    for bad in (0.5, 0, 101, 'enorme', None, True, float('nan')):
        assert memory.likelihood_ratio(bad) is None
    # prior 0.5, preuve forte pour : cote 1 * 20
    p = memory.posterior_from(0.5, [{'direction': 'supports', 'weight': 20}])
    assert p == pytest.approx(20 / 21, abs=1e-4)
    # + preuve faible contre : cote 20 / 2 = 10
    p = memory.posterior_from(0.5, [{'direction': 'supports', 'weight': 20},
                                    {'direction': 'refutes', 'weight': 2}])
    assert p == pytest.approx(10 / 11, abs=1e-4)
    # prior 0.2, modere pour : cote 0.25 * 5 = 1.25
    assert memory.posterior_from(0.2, [{'direction': 'supports', 'weight': 5}]) == pytest.approx(
        1.25 / 2.25, abs=1e-4)
    # additivite en log-cote : l'ordre des preuves est indifferent
    ev = [{'direction': 'refutes', 'weight': 5}, {'direction': 'supports', 'weight': 20},
          {'direction': 'supports', 'weight': 2}]
    expected = 1 / (1 + math.exp(-(math.log(20) + math.log(2) - math.log(5))))
    assert memory.posterior_from(0.5, ev) == pytest.approx(expected, abs=1e-4)
    assert memory.posterior_from(0.5, list(reversed(ev))) == memory.posterior_from(0.5, ev)
    # prior borne : jamais 0 ni 1
    assert memory.clamp_prior(0) == 0.01 and memory.clamp_prior(1) == 0.99


def test_hypotheses_concurrentes_ponderation_et_classement(tmp_path):
    d = str(tmp_path)
    memory.record_finding(d, 'Piece jointe macro ouverte', severity='high', mitre='T1566.001')
    memory.record_finding(d, 'Connexion RDP externe', severity='medium', mitre='T1133')
    a = memory.add_hypothesis(d, 'Acces initial', 'Hameconnage', techniques=['T1566.001'])['created']
    b = memory.add_hypothesis(d, 'acces  INITIAL', 'RDP expose', techniques='T1133', prior=0.3)['created']
    assert a['posterior'] == 0.5 and b['prior'] == 0.3 and b['techniques'] == ['T1133']
    assert 'error' in memory.add_hypothesis(d, 'acces initial', 'Hameconnage')  # doublon
    assert 'error' in memory.add_hypothesis(d, 'acces initial', 'X', prior=1.5)
    # preuve obligatoire : constat existant
    assert 'error' in memory.weigh_evidence(d, a['id'], 'supports', 'strong', finding_id=99)
    assert 'error' in memory.weigh_evidence(d, a['id'], 'supports', 'strong')
    assert 'error' in memory.weigh_evidence(d, a['id'], 'peut-etre', 'strong', finding_id=1)
    assert 'error' in memory.weigh_evidence(d, 42, 'supports', 'strong', finding_id=1)
    r = memory.weigh_evidence(d, a['id'], 'supports', 'strong', finding_id=1)
    assert r['weighed']['posterior'] == pytest.approx(20 / 21, abs=1e-4)
    assert r['weighed']['status'] == 'supported'
    # re-ponderer la meme preuve remplace son poids (pas de double comptage)
    r = memory.weigh_evidence(d, a['id'], 'supports', 'moderate', finding_id=1)
    assert r['weighed']['posterior'] == pytest.approx(5 / 6, abs=1e-4)
    assert len(memory.get_state(d)['hypotheses'][0]['evidence']) == 1
    memory.weigh_evidence(d, b['id'], 'refutes', 'strong', finding_id=2)
    ranking = memory.rank_hypotheses(d)['questions'][0]
    assert [h['id'] for h in ranking['ranking']] == [a['id'], b['id']]
    assert ranking['leader'] == a['id'] and not ranking['inconclusive']
    statuses = {h['id']: h['status'] for h in memory.get_state(d)['hypotheses']}
    assert statuses == {a['id']: 'supported', b['id']: 'refuted'}
    # la tentative de refutation du leader est tracee
    memory.weigh_evidence(d, a['id'], 'refutes', 'neutral', finding_id=2, note='rien trouve')
    h = memory.get_state(d)['hypotheses'][0]
    assert h['refutation_attempted'] and h['posterior'] == pytest.approx(5 / 6, abs=1e-4)


def test_question_non_tranchee(tmp_path):
    d = str(tmp_path)
    memory.record_finding(d, 'Execution', severity='high', mitre='T1059')
    a = memory.add_hypothesis(d, 'execution', 'Script malveillant')['created']['id']
    b = memory.add_hypothesis(d, 'execution', 'Script admin')['created']['id']
    memory.weigh_evidence(d, a, 'supports', 'weak', finding_id=1)
    memory.weigh_evidence(d, b, 'supports', 'weak', finding_id=1)
    q = memory.rank_hypotheses(d, 'Execution')['questions'][0]
    assert q['inconclusive'] and q['margin'] == 0
    assert {h['status'] for h in memory.get_state(d)['hypotheses']} == {'inconclusive'}
    # une preuve forte departage
    memory.weigh_evidence(d, a, 'supports', 'strong', finding_id=1)
    assert not memory.rank_hypotheses(d)['questions'][0]['inconclusive']
    annex = memory.render_markdown(d)
    assert 'Question : execution' in annex and 'Posterior' in annex


def test_outil_weigh_evidence_valide_les_references(tmp_path):
    case = tmp_path / 'ps'
    shutil.copytree(os.path.join(SUITE, 'powershell_encoded_service_injection'), case,
                    ignore=shutil.ignore_patterns('ground_truth.json'))
    d = str(case)
    toolkit.set_active_case(d)
    toolkit.run_tool('parse_log_file', {'file_path': os.path.join(d, 'srv-ad-01_events.log')})
    hid = toolkit.run_tool('add_hypothesis', {'case_dir': d, 'question': 'execution',
                                              'statement': 'PowerShell malveillant'})['created']['id']
    bad = toolkit.run_tool('weigh_evidence', {'case_dir': d, 'hypothesis_id': hid, 'direction': 'supports',
                                              'weight': 'strong',
                                              'ref': {'artifact': 'srv-ad-01_events.log', 'kind': 'line',
                                                      'value': 999}})
    assert 'error' in bad and bad['invalid_refs']
    ok = toolkit.run_tool('weigh_evidence', {'case_dir': d, 'hypothesis_id': hid, 'direction': 'supports',
                                             'weight': 5,
                                             'ref': {'artifact': 'srv-ad-01_events.log', 'kind': 'line',
                                                     'value': 2}})
    assert ok['weighed']['posterior'] == pytest.approx(5 / 6, abs=1e-4)
    assert memory.get_state(d)['hypotheses'][0]['evidence'][0]['ref']['value'] == '2'
    ranked = toolkit.run_tool('rank_hypotheses', {'case_dir': d})
    assert ranked['questions'][0]['leader'] == hid and ranked['scale']['likelihood_ratios']['strong'] == 20


# ============================================================================
# Retro-compatibilite
# ============================================================================

def test_ancien_case_state_et_set_hypothesis_historique(tmp_path):
    d = str(tmp_path)
    old = {'plan': [], 'findings': [], 'remediations': [],
           'hypotheses': [{'id': 1, 'hypothesis': 'Vol de creds', 'status': 'confirmed',
                           'rationale': 'Mimikatz', 'ts': '2025-01-01T00:00:00'},
                          {'id': 2, 'hypothesis': 'Exfiltration', 'status': 'open', 'rationale': '',
                           'ts': '2025-01-01T00:00:00'}]}
    with open(os.path.join(d, memory.STATE_FILENAME), 'w', encoding='utf-8') as f:
        json.dump(old, f)
    state = memory.get_state(d)
    h = state['hypotheses'][0]
    assert h['hypothesis'] == h['statement'] == 'Vol de creds'
    assert h['status'] == 'confirmed' and h['prior'] == 0.5 and h['posterior'] == 0.5
    assert h['evidence'] == [] and h['question'] is None
    assert state['summary']['hypotheses_confirmed'] == 1
    # outil historique : meme signature, meme comportement
    r = toolkit.run_tool('set_hypothesis', {'case_dir': d, 'hypothesis': 'Exfiltration',
                                            'status': 'refuted', 'rationale': 'pas de flux'})
    assert r['updated']['status'] == 'refuted' and r['updated']['id'] == 2
    r = toolkit.run_tool('set_hypothesis', {'case_dir': d, 'hypothesis': 'Persistance'})
    assert r['created']['id'] == 3 and r['created']['status'] == 'open'
    # champs optionnels
    r = toolkit.run_tool('set_hypothesis', {'case_dir': d, 'hypothesis': 'Persistance',
                                            'question': 'persistance', 'techniques': ['T1543.003'],
                                            'prior': 0.7})
    assert r['updated']['question'] == 'persistance' and r['updated']['prior'] == 0.7
    assert 'Vol de creds' in memory.render_markdown(d)
    schema = toolkit.TOOLS['set_hypothesis']['input_schema']
    assert schema['required'] == ['case_dir', 'hypothesis']
    assert 'supported' in schema['properties']['status']['enum']
    assert 'confirmed' in schema['properties']['status']['enum']


def test_case_state_corrompu_ou_partiel(tmp_path):
    d = str(tmp_path)
    with open(os.path.join(d, memory.STATE_FILENAME), 'w', encoding='utf-8') as f:
        json.dump({'findings': []}, f)
    assert memory.get_state(d)['hypotheses'] == []
    with open(os.path.join(d, memory.STATE_FILENAME), 'w', encoding='utf-8') as f:
        f.write('{pas du json')
    assert memory.get_state(d)['plan'] == []


# ============================================================================
# Portes
# ============================================================================

def test_porte_correlation_exige_des_hypotheses_concurrentes(tmp_path):
    d = str(tmp_path)
    memory.record_finding(d, 'PowerShell encode', severity='high', mitre='T1059.001')
    gaps = phases.gate_correlation(d, None)
    assert any('hypotheses concurrentes' in g for g in gaps)
    memory.add_hypothesis(d, 'execution', 'Attaquant')
    assert any('hypotheses concurrentes' in g for g in phases.gate_correlation(d, None))
    memory.add_hypothesis(d, 'execution', 'Administrateur')
    assert phases.gate_correlation(d, None) == []


def test_porte_correlation_cas_sain_sans_hypotheses(tmp_path):
    d = str(tmp_path)
    memory.declare_no_incident(d, 'activite legitime')
    memory.record_finding(d, 'Note', severity='low')
    assert phases.gate_correlation(d, None) == []


def _audited(d):
    memory.mark_audit(d, 'tool_coverage', {})
    memory.mark_audit(d, 'evidence_coverage', {})


def test_porte_contre_analyse_hypotheses(tmp_path):
    d = str(tmp_path)
    _audited(d)
    memory.record_finding(d, 'PowerShell encode', severity='high', mitre='T1059.001')
    memory.challenge_finding(d, 1, 'admin', 'upheld', 'non')
    memory.record_finding(d, 'Service cree', severity='critical', mitre='T1543.003')
    memory.challenge_finding(d, 2, 'installeur', 'upheld', 'non')
    a = memory.add_hypothesis(d, 'execution', 'Attaquant', techniques=['T1059'])['created']['id']
    b = memory.add_hypothesis(d, 'execution', 'Admin')['created']['id']
    gaps = phases.gate_contre_analyse(d, None)
    # constat 1 rattache par technique parente mais groupe jamais pondere ; constat 2 orphelin
    assert any('Constat #1' in g and 'jamais ete pondere' in g for g in gaps)
    assert any('Constat #2' in g and 'aucun groupe' in g for g in gaps)
    memory.weigh_evidence(d, a, 'supports', 'strong', finding_id=1)
    memory.weigh_evidence(d, a, 'supports', 'moderate', finding_id=2)
    gaps = phases.gate_contre_analyse(d, None)
    assert len(gaps) == 1 and "n'a pas ete confrontee" in gaps[0] and f'#{a}' in gaps[0]
    # refuter le leader : ici sans effet (neutral), la porte passe
    memory.weigh_evidence(d, a, 'refutes', 'neutral', finding_id=1)
    assert phases.gate_contre_analyse(d, None) == []
    # une hypothese 'supported' sans preuve a l'appui est signalee
    memory.set_hypothesis(d, 'Admin', status='supported')
    gaps = phases.gate_contre_analyse(d, None)
    assert any(f'Hypothese #{b}' in g and 'sans aucune preuve' in g for g in gaps)
    # determinisme : meme etat, memes lacunes
    assert phases.gate_contre_analyse(d, None) == gaps


def test_nouveau_leader_doit_aussi_etre_confronte(tmp_path):
    d = str(tmp_path)
    _audited(d)
    memory.record_finding(d, 'Exfiltration', severity='high', mitre='T1048')
    memory.challenge_finding(d, 1, 'sauvegarde', 'upheld', 'non')
    a = memory.add_hypothesis(d, 'exfiltration', 'Vol de donnees')['created']['id']
    b = memory.add_hypothesis(d, 'exfiltration', 'Sauvegarde cloud')['created']['id']
    memory.weigh_evidence(d, a, 'supports', 'weak', finding_id=1)
    memory.weigh_evidence(d, a, 'refutes', 'strong', finding_id=1)  # A s'effondre
    memory.weigh_evidence(d, b, 'supports', 'moderate', finding_id=1)
    gaps = phases.gate_contre_analyse(d, None)
    assert any(f'#{b}' in g and 'confrontee' in g for g in gaps)


# ============================================================================
# Bout en bout : cinq phases, enqueteur simule
# ============================================================================

def _call(name, args, cid='c'):
    return {'tool_calls': [{'id': cid, 'type': 'function',
                            'function': {'name': name, 'arguments': json.dumps(args)}}]}


REPORT = """# Compromission de SRV-AD-01
## Resume executif
PowerShell encode puis service de persistance (srv-ad-01_events.log lignes 2 et 3).
## Chronologie
- 2026-10-11T09:02:10Z PowerShell -enc (line 2) ; 09:03:40Z service WinDefendHealthSvc (line 3).
## Indicateurs de compromission (IoC)
- 45.137.21.9, C:\\ProgramData\\updater.exe
## Mapping MITRE ATT&CK
T1059.001, T1543.003
## Conclusions
Hypothese retenue : compte svc_backup compromis.
## Recommandations
Supprimer le service, reinitialiser svc_backup.
"""


class ReasoningLLM:
    """Enqueteur simule : la premiere tentative des phases 3 et 4 oublie les hypotheses
    (porte en echec), la relance les pose, les pondere et tente de refuter le leader."""

    def __init__(self, **kwargs):
        self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
        self.step = {}
        self.prompts = {}
        self.tools_seen = {}

    def __call__(self, **kwargs):
        return self

    def chat(self, messages, tools=None, model=None):
        self.usage['calls'] += 1
        if tools is None or 'verificateur' in messages[0]['content']:
            return {'content': 'fin'}
        prompt = messages[1]['content']
        phase = int(re.search(r'PHASE (\d)/5', prompt).group(1))
        retry = 'CONTROLE QUALITE ECHOUE' in prompt
        case = prompt.split('Dossier du cas : ', 1)[1].split('\n', 1)[0].strip()
        key = (phase, retry)
        n = self.step.get(key, 0)
        if n == 0:
            self.prompts[key] = prompt
            self.tools_seen[phase] = {t['function']['name'] for t in tools}
        self.step[key] = n + 1
        script = self._script(phase, retry, case)
        return script[n] if n < len(script) else {'content': 'phase terminee'}

    def _script(self, phase, retry, case):
        log = os.path.join(case, 'srv-ad-01_events.log')
        if phase == 1:
            return [_call('list_artifacts', {'case_dir': case}),
                    _call('set_investigation_plan', {'case_dir': case, 'steps': ['Parser', 'Correler']})]
        if phase == 2:
            return [_call('parse_log_file', {'file_path': log}),
                    _call('audit_tool_coverage', {'case_dir': case})]
        if phase == 3 and not retry:
            return [_call('record_finding', {
                        'case_dir': case, 'title': 'PowerShell encode -nop -w hidden -enc',
                        'severity': 'high', 'mitre': 'T1059.001', 'evidence': '45.137.21.9',
                        'evidence_refs': [{'artifact': 'srv-ad-01_events.log', 'kind': 'line', 'value': 2}]}),
                    _call('record_finding', {
                        'case_dir': case, 'title': 'Service de persistance WinDefendHealthSvc',
                        'severity': 'critical', 'mitre': 'T1543.003',
                        'evidence_refs': [{'artifact': 'srv-ad-01_events.log', 'kind': 'line', 'value': 3}]})]
        if phase == 3:
            return [_call('add_hypothesis', {'case_dir': case, 'question': 'origine de la compromission',
                                             'statement': 'Compte svc_backup compromis par un attaquant',
                                             'techniques': ['T1059.001', 'T1543.003', 'T1078']}),
                    _call('add_hypothesis', {'case_dir': case, 'question': 'origine de la compromission',
                                             'statement': "Script d'administration legitime",
                                             'prior': 0.4}),
                    _call('weigh_evidence', {'case_dir': case, 'hypothesis_id': 1, 'finding_id': 2,
                                             'direction': 'supports', 'weight': 'strong'}),
                    _call('weigh_evidence', {'case_dir': case, 'hypothesis_id': 1, 'finding_id': 3,
                                             'direction': 'supports', 'weight': 'moderate'}),
                    _call('weigh_evidence', {'case_dir': case, 'hypothesis_id': 2, 'finding_id': 3,
                                             'direction': 'refutes', 'weight': 'strong',
                                             'note': 'Service deguise en composant Defender'}),
                    _call('graph_build', {'case_dir': case}),
                    _call('graph_patient_zero', {'case_dir': case})]
        if phase == 4 and not retry:
            return [_call('challenge_finding', {'case_dir': case, 'finding_id': 2, 'verdict': 'upheld',
                                                'alternative': 'Script admin', 'rationale': 'Encode + cache'}),
                    _call('challenge_finding', {'case_dir': case, 'finding_id': 3, 'verdict': 'upheld',
                                                'alternative': 'Installeur', 'rationale': 'Nom trompeur'}),
                    _call('audit_tool_coverage', {'case_dir': case}),
                    _call('audit_evidence_coverage', {'case_dir': case})]
        if phase == 4:
            return [_call('rank_hypotheses', {'case_dir': case}),
                    _call('weigh_evidence', {'case_dir': case, 'hypothesis_id': 1, 'finding_id': 2,
                                             'direction': 'refutes', 'weight': 'neutral',
                                             'note': "Aucune trace d'une tache d'administration planifiee"}),
                    _call('detect_generate_sigma', {'case_dir': case, 'finding_id': 2}),
                    _call('detect_test_rule', {'case_dir': case, 'rule_file': 'phoenix_detection_f2_1.yml'})]
        if phase == 5:
            return [_call('save_report', {'case_dir': case, 'title': 'Rapport', 'markdown': REPORT}),
                    _call('casemem_index_case', {'case_dir': case})]
        return []


def test_enquete_cinq_phases_avec_hypotheses_graphe_et_detection(monkeypatch, tmp_path):
    root = tmp_path / 'cases'
    case = root / 'ps-incident'
    shutil.copytree(os.path.join(SUITE, 'powershell_encoded_service_injection'), case,
                    ignore=shutil.ignore_patterns('ground_truth.json'))
    monkeypatch.setenv('PHOENIX_CASES_ROOT', str(root))
    llm = ReasoningLLM()
    monkeypatch.setattr(phases, 'CopilotClient', llm)
    notified = []
    result = investigator.investigate(str(case), enable_verification=False,
                                      on_tool=lambda s, n, a, r: notified.append((n, a, r)))
    by_phase = {p['phase']: p for p in result['metrics']['phases']}
    assert result['metrics']['gates_passed'] == 5, result['metrics']['phases']
    assert by_phase['correlation']['attempts'] == 2
    assert by_phase['contre_analyse']['attempts'] == 2
    assert 'hypotheses concurrentes' in llm.prompts[(3, True)]
    assert "n'a pas ete confrontee" in llm.prompts[(4, True)]
    assert {'add_hypothesis', 'weigh_evidence', 'graph_build'} <= llm.tools_seen[3]
    assert {'weigh_evidence', 'detect_generate_sigma'} <= llm.tools_seen[4]
    # Hypotheses : leader etaye, alternative refutee, refutation du leader tentee
    hyps = {h['id']: h for h in memory.get_state(str(case))['hypotheses']}
    assert hyps[1]['status'] == 'supported' and hyps[1]['refutation_attempted']
    assert hyps[1]['posterior'] == pytest.approx(100 / 101, abs=1e-4)
    assert hyps[2]['status'] == 'refuted'
    # Graphe reconstruit automatiquement (fin de correlation et de contre-analyse)
    assert sum(1 for n, a, r in notified if n == 'graph_build') >= 3
    g = json.load(open(case / 'entity_graph.json', encoding='utf-8'))
    assert g['version'] == 1 and g['patient_zero']['node'] == 'host:SRV-AD-01'
    assert any(n['id'] == 'service:SRV-AD-01/windefendhealthsvc' and n['malicious'] for n in g['nodes'])
    # Regle Sigma ecrite et testee
    rule_path = case / 'detections' / 'phoenix_detection_f2_1.yml'
    assert rule_path.is_file()
    tested = [r for n, a, r in notified if n == 'detect_test_rule'][0]
    assert tested['malicious_matched'] and tested['false_positives'] == 0
    # Rapport : annexe hypotheses (posterior), patient zero / rayon d'impact, detections
    report = open(result['report_path'], encoding='utf-8').read()
    assert 'Hypotheses (concurrentes, probabilite a posteriori)' in report
    assert 'Patient zero : host:SRV-AD-01' in report and "Rayon d'impact" in report
    assert 'detections/phoenix_detection_f2_1.yml' in report
    # Produits du raisonnement : jamais des artefacts a analyser
    names = [a['name'] for a in toolkit.run_tool('list_artifacts', {'case_dir': str(case)})['artifacts']]
    assert names == ['srv-ad-01_events.log']
    # Memoire inter-enquetes : cas indexe sous la racine configuree
    index = json.load(open(tmp_path / 'casemem_index.json', encoding='utf-8'))
    prof = index['cases'][os.path.realpath(case)]
    assert 'T1059.001' in prof['techniques'] and 'ip:45.137.21.9' in prof['iocs']
