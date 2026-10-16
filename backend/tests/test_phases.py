#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests du moteur d'enquete en cinq phases a portes qualite, de la
super-timeline (evidence_db), des audits de couverture, de la contre-analyse
et des exports ATT&CK Navigator / IoC."""

import csv
import json
import os
import re
import shutil
import sys

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
_MCP_DIR = os.path.join(_ROOT, 'mcp-server')
if _MCP_DIR not in sys.path:
    sys.path.insert(0, _MCP_DIR)

from phoenix_dfir_mcp import evidence_db, exports, investigator, memory, pathpolicy, phases, toolkit  # noqa: E402

SUITE = os.path.join(_ROOT, 'eval', 'suite')


@pytest.fixture(autouse=True)
def _isolation(monkeypatch):
    monkeypatch.delenv('PHOENIX_INVESTIGATION_MODE', raising=False)
    monkeypatch.delenv('PHOENIX_STRICT_EVIDENCE', raising=False)
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


@pytest.fixture
def ssh_case(tmp_path):
    case = tmp_path / 'ssh'
    shutil.copytree(os.path.join(SUITE, 'ssh_bruteforce_valid_account'), case,
                    ignore=shutil.ignore_patterns('ground_truth.json'))
    return str(case)


def _call(name, args, cid='c'):
    return {'tool_calls': [{'id': cid, 'type': 'function',
                            'function': {'name': name, 'arguments': json.dumps(args)}}]}


REPORT = """# Compromission SSH de srv-web-01
## Resume executif
Brute force puis connexion de svc_backup depuis 185.220.101.44.
## Chronologie
- 2026-10-10T03:12Z premiers echecs (auth.log line 1) ; 03:19:02Z connexion (line 37).
## Indicateurs de compromission (IoC)
- 185.220.101.44
## Mapping MITRE ATT&CK
T1110.001, T1078
## Conclusions
Compte de service compromis.
## Recommandations
Reinitialiser svc_backup, bloquer l'IP, MFA sur SSH.
"""


class PhasedLLM:
    """Enqueteur simule qui suit les consignes de chaque phase.

    `skip_first` : phases dont la premiere tentative ne fait rien (porte en echec)."""

    def __init__(self, skip_first=(), benign=False, never_report=False):
        self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
        self.skip_first = set(skip_first)
        self.benign = benign
        self.never_report = never_report
        self.step = {}
        self.prompts = []
        self.tools_seen = {}

    def __call__(self, **kwargs):  # remplace la classe CopilotClient
        return self

    def chat(self, messages, tools=None, model=None):
        self.usage['calls'] += 1
        self.usage['total_tokens'] += 10
        if tools is None or 'verificateur' in messages[0]['content']:
            return {'content': 'fin'}
        prompt = messages[1]['content']
        phase = int(re.search(r'PHASE (\d)/5', prompt).group(1))
        retry = 'CONTROLE QUALITE ECHOUE' in prompt
        case = prompt.split('Dossier du cas : ', 1)[1].split('\n', 1)[0].strip()
        key = (phase, retry)
        if key not in self.step:
            self.prompts.append(prompt)
            self.tools_seen[phase] = {t['function']['name'] for t in tools}
        n = self.step.get(key, 0)
        self.step[key] = n + 1
        if phase in self.skip_first and not retry:
            return {'content': 'rien a faire'}
        script = self._script(phase, case)
        return script[n] if n < len(script) else {'content': 'phase terminee'}

    def _script(self, phase, case):
        log = os.path.join(case, 'auth.log')
        if phase == 1:
            return [_call('list_artifacts', {'case_dir': case}),
                    _call('set_investigation_plan', {'case_dir': case,
                                                     'steps': ['Parser auth.log', 'Correler', 'Rapport']})]
        if phase == 2:
            return [_call('save_report', {'case_dir': case, 'title': 'x', 'markdown': 'trop tot'}),
                    _call('parse_log_file', {'file_path': log}),
                    _call('audit_tool_coverage', {'case_dir': case})]
        if phase == 3:
            if self.benign:
                return [_call('declare_no_incident', {'case_dir': case,
                                                      'rationale': 'Connexions internes legitimes.'})]
            return [_call('search_evidence', {'case_dir': case, 'query': 'Accepted svc_backup'}),
                    _call('record_finding', {
                        'case_dir': case, 'title': 'Brute force SSH puis acces svc_backup',
                        'severity': 'high', 'mitre': 'T1110.001', 'evidence': '185.220.101.44',
                        'evidence_refs': [{'artifact': 'auth.log', 'kind': 'line', 'value': 37}]}),
                    _call('add_hypothesis', {'case_dir': case, 'question': 'acces initial',
                                             'statement': 'Brute force SSH depuis Internet',
                                             'techniques': ['T1110.001']}),
                    _call('add_hypothesis', {'case_dir': case, 'question': 'acces initial',
                                             'statement': 'Connexion legitime du compte de service',
                                             'techniques': ['T1078']}),
                    _call('weigh_evidence', {'case_dir': case, 'hypothesis_id': 1, 'finding_id': 1,
                                             'direction': 'supports', 'weight': 'strong',
                                             'note': '36 echecs puis succes depuis la meme IP'})]
        if phase == 4:
            steps = [] if self.benign else [_call('challenge_finding', {
                'case_dir': case, 'finding_id': 1, 'verdict': 'upheld',
                'alternative': "Faute de frappe d'un administrateur",
                'rationale': '36 echecs sur 6 comptes depuis un noeud Tor : pas une faute de frappe.'}),
                _call('weigh_evidence', {'case_dir': case, 'hypothesis_id': 1, 'finding_id': 1,
                                         'direction': 'refutes', 'weight': 'neutral',
                                         'note': 'Aucune preuve de connexion legitime anterieure'}),
                _call('weigh_evidence', {'case_dir': case, 'hypothesis_id': 2, 'finding_id': 1,
                                         'direction': 'refutes', 'weight': 'moderate',
                                         'note': 'Comptes inexistants testes avant le succes'})]
            return steps + [_call('audit_tool_coverage', {'case_dir': case}),
                            _call('audit_evidence_coverage', {'case_dir': case})]
        if phase == 5:
            if self.never_report:
                return [{'content': 'je ne fais pas de rapport'}]
            body = ("# Revue\n## Resume executif\nAucun incident.\n## Chronologie\n- RAS\n"
                    "## Recommandations\nAucune.\n") if self.benign else REPORT
            return [_call('save_report', {'case_dir': case, 'title': 'Rapport', 'markdown': body})]
        return []


def _run(monkeypatch, case, llm, **kw):
    monkeypatch.setattr(phases, 'CopilotClient', llm)
    notified = []
    result = investigator.investigate(case, on_tool=lambda s, n, a, r: notified.append((n, a, r)),
                                      enable_verification=False, **kw)
    return result, notified


# ============================================================================
# Moteur a phases
# ============================================================================

def test_enquete_complete_cinq_portes(monkeypatch, ssh_case):
    llm = PhasedLLM()
    result, notified = _run(monkeypatch, ssh_case, llm)
    m = result['metrics']
    assert m['mode'] == 'phased' and m['gates_passed'] == 5, m['phases']
    assert all(p['attempts'] == 1 for p in m['phases'])
    # Chaque porte est remontee (chaine de preuve / console)
    gates = [r for n, a, r in notified if n == 'phase_gate']
    assert len(gates) == 5 and all(g['passed'] for g in gates)
    # Liste blanche : save_report refuse en phase d'extraction
    assert 'save_report' not in llm.tools_seen[2] and 'challenge_finding' in llm.tools_seen[4]
    assert not any(n == 'save_report' for n, a, r in notified
                   if a.get('markdown') == 'trop tot')
    # Contre-analyse et exports
    state = memory.get_state(ssh_case)
    assert state['findings'][0]['challenge']['verdict'] == 'upheld'
    layer = json.load(open(os.path.join(ssh_case, exports.NAVIGATOR_FILE)))
    assert [t['techniqueID'] for t in layer['techniques']] == ['T1110.001']
    with open(os.path.join(ssh_case, exports.IOCS_FILE)) as f:
        assert '185.220.101.44' in {row['value'] for row in csv.DictReader(f)}
    report = open(result['report_path'], encoding='utf-8').read()
    assert 'Contre-analyse' in report and 'MAINTENU' in report


def test_porte_en_echec_relance_avec_les_lacunes(monkeypatch, ssh_case):
    llm = PhasedLLM(skip_first={3, 4})
    result, _ = _run(monkeypatch, ssh_case, llm)
    by_phase = {p['phase']: p for p in result['metrics']['phases']}
    assert by_phase['correlation']['attempts'] == 2 and by_phase['correlation']['passed']
    assert by_phase['contre_analyse']['attempts'] == 2 and by_phase['contre_analyse']['passed']
    retry_prompts = [p for p in llm.prompts if 'CONTROLE QUALITE ECHOUE' in p]
    assert any('declare_no_incident' in p for p in retry_prompts)
    assert any('challenge_finding' in p for p in retry_prompts)
    assert result['metrics']['gates_passed'] == 5


def test_cas_sain_conclusion_explicite_sans_constat_invente(monkeypatch, tmp_path):
    case = tmp_path / 'benign'
    shutil.copytree(os.path.join(SUITE, 'benign_admin_activity'), case,
                    ignore=shutil.ignore_patterns('ground_truth.json'))
    result, _ = _run(monkeypatch, str(case), PhasedLLM(benign=True))
    assert result['metrics']['gates_passed'] == 5
    state = memory.get_state(str(case))
    assert state['findings'] == [] and state['conclusion']['no_incident']
    assert 'aucun incident' in open(result['report_path'], encoding='utf-8').read().lower()


def test_rapport_de_secours_si_l_enqueteur_n_en_produit_pas(monkeypatch, ssh_case):
    result, _ = _run(monkeypatch, ssh_case, PhasedLLM(never_report=True), max_phase_retries=0)
    assert result['report_path'] and os.path.isfile(result['report_path'])
    assert 'genere automatiquement' in open(result['report_path'], encoding='utf-8').read()
    assert result['metrics']['gates_passed'] == 4
    assert 'echec : rapport' in result['metrics']['adviser_verdict']


def test_briefing_injecte_et_exclu_des_artefacts(monkeypatch, ssh_case):
    with open(os.path.join(ssh_case, 'PHOENIX.md'), 'w') as f:
        f.write("## Ce qu'on sait\n- Compte suspect : svc_backup\n")
    llm = PhasedLLM()
    _run(monkeypatch, ssh_case, llm)
    assert all('Compte suspect : svc_backup' in p for p in llm.prompts)
    names = [a['name'] for a in toolkit.run_tool('list_artifacts', {'case_dir': ssh_case})['artifacts']]
    assert 'PHOENIX.md' not in names and 'auth.log' in names
    assert evidence_db.DB_NAME not in names


def test_budget_global_respecte(monkeypatch, ssh_case):
    result, _ = _run(monkeypatch, ssh_case, PhasedLLM(), max_steps=3)
    assert result['steps'] <= 3
    assert result['metrics']['gates_passed'] < 5


def test_mode_loop_toujours_disponible(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(investigator, '_investigate_loop', lambda *a, **k: called.setdefault('loop', k))
    investigator.investigate(str(tmp_path), mode='loop')
    assert 'loop' in called


# ============================================================================
# Portes unitaires
# ============================================================================

def test_porte_correlation_contradiction_et_mitre(tmp_path):
    d = str(tmp_path)
    memory.record_finding(d, 'Execution suspecte', severity='critical', mitre='')
    gaps = phases.gate_correlation(d, None)
    assert any('sans technique MITRE' in g for g in gaps)
    memory.declare_no_incident(d, 'rien')
    assert any('Contradiction' in g for g in phases.gate_correlation(d, None))


def test_porte_rapport_sections_obligatoires(tmp_path):
    d = str(tmp_path)

    class Ctx:
        report_path = os.path.join(d, 'r.md')
    with open(Ctx.report_path, 'w') as f:
        f.write('# R\n## Resume executif\nx\n## Recommandations\ny\n')
    gaps = phases.gate_rapport(d, Ctx)
    assert any('chronologie' in g for g in gaps) and any('MITRE' in g for g in gaps)
    memory.declare_no_incident(d, 'cas sain')
    with open(Ctx.report_path, 'a') as f:
        f.write('## Chronologie\n- RAS\n')
    assert phases.gate_rapport(d, Ctx) == []


def test_porte_extraction_lacunes_de_couverture(ssh_case):
    toolkit.set_active_case(ssh_case)
    gaps = phases.gate_extraction(ssh_case, None)
    assert gaps and any('auth.log' in g or 'analyse' in g for g in gaps)
    toolkit.run_tool('parse_log_file', {'file_path': os.path.join(ssh_case, 'auth.log')})
    assert phases.gate_extraction(ssh_case, None) == []


# ============================================================================
# Super-timeline, audits, contre-analyse, exports
# ============================================================================

@pytest.mark.parametrize('raw,expected', [
    ('2026-10-11T09:02:13Z', '2026-10-11T09:02:13Z'),
    ('2026-10-11 09:02:13.1234567', '2026-10-11T09:02:13Z'),
    ('2026-10-11T11:02:13+02:00', '2026-10-11T09:02:13Z'),
    (1760000000, '2025-10-09T08:53:20Z'),
    ('pas une date', None),
])
def test_normalisation_horodatages(raw, expected):
    assert evidence_db.normalize_ts(raw) == expected


def test_horodatage_syslog_sans_annee():
    assert evidence_db.normalize_ts('Oct 10 03:19:02 srv', default_year=2026) == '2026-10-10T03:19:02Z'


def test_recherche_fts_robuste_aux_caracteres_speciaux(ssh_case):
    toolkit.set_active_case(ssh_case)
    toolkit.run_tool('parse_log_file', {'file_path': os.path.join(ssh_case, 'auth.log')})
    r = toolkit.run_tool('search_evidence', {'case_dir': ssh_case, 'query': '185.220.101.44 Accepted'})
    assert r['total_matches'] == 1 and r['events'][0]['ref'] == {
        'artifact': 'auth.log', 'kind': 'line', 'value': '37'}
    assert 'error' not in toolkit.run_tool('search_evidence', {
        'case_dir': ssh_case, 'query': 'sudo: "COMMAND=/usr/bin/id" ) ( * NEAR'})
    either = toolkit.run_tool('search_evidence', {'case_dir': ssh_case, 'query': 'oracle OR ubuntu'})
    assert either['total_matches'] == 12
    tl = toolkit.run_tool('get_timeline', {'case_dir': ssh_case, 'user': None, 'contains': 'sudo'})
    assert tl['returned'] == 1


def test_reference_validee_par_l_index_apres_redemarrage(ssh_case):
    toolkit.set_active_case(ssh_case)
    toolkit.run_tool('parse_log_file', {'file_path': os.path.join(ssh_case, 'auth.log')})
    toolkit.reset_evidence_index()  # simule un redemarrage du processus
    ok, bad = toolkit.validate_refs([{'artifact': 'auth.log', 'kind': 'line', 'value': 37},
                                     {'artifact': 'auth.log', 'kind': 'line', 'value': 999}], ssh_case)
    assert len(ok) == 1 and len(bad) == 1


def test_contre_analyse_affaiblit_ou_ecarte(tmp_path):
    d = str(tmp_path)
    memory.record_finding(d, 'A', severity='critical', confidence='confirmed', mitre='T1059')
    memory.record_finding(d, 'B', severity='high', mitre='T1110')
    r = memory.challenge_finding(d, 1, 'script admin', 'downgraded', 'signe par le SI', 'medium')
    assert r['challenged']['severity'] == 'medium' and r['challenged']['confidence'] == 'likely'
    memory.challenge_finding(d, 2, 'scanner interne', 'refuted', 'IP du scanner Nessus')
    layer = exports.navigator_layer(d, 'test')
    assert [t['techniqueID'] for t in layer['techniques']] == ['T1059']  # B ecarte
    assert 'error' in memory.challenge_finding(d, 1, 'x', 'peut-etre', 'y')


def test_audit_couverture_preuves(ssh_case):
    toolkit.set_active_case(ssh_case)
    r = toolkit.run_tool('audit_evidence_coverage', {'case_dir': ssh_case})
    assert r['never_analyzed'] == ['auth.log']
    toolkit.run_tool('parse_log_file', {'file_path': os.path.join(ssh_case, 'auth.log')})
    r = toolkit.run_tool('audit_evidence_coverage', {'case_dir': ssh_case})
    assert r['analyzed_not_cited'] == ['auth.log'] and r['never_analyzed'] == []
    assert 'evidence_coverage' in memory.get_state(ssh_case)['audits']


def test_outil_tente_en_echec_ne_bloque_pas_la_porte(ssh_case, monkeypatch):
    toolkit.set_active_case(ssh_case)
    dump = os.path.join(ssh_case, 'memdump.raw')
    with open(dump, 'wb') as f:
        f.write(b'\x00' * 32)
    monkeypatch.setattr(toolkit.volatility, 'status', lambda: {'available': True})
    toolkit.run_tool('parse_log_file', {'file_path': os.path.join(ssh_case, 'auth.log')})
    assert any('memdump.raw' in g for g in phases.gate_extraction(ssh_case, None))
    monkeypatch.setattr(toolkit.volatility, 'run', lambda *a, **k: {'error': 'symboles absents'})
    toolkit.run_tool('run_volatility', {'file_path': dump, 'plugin': 'windows.pslist'})
    assert phases.gate_extraction(ssh_case, None) == []
    cov = toolkit.compute_tool_coverage(ssh_case)
    assert cov['failed_runs'] == [{'artifact': 'memdump.raw', 'step': 'memoire',
                                   'failed_tools': ['run_volatility']}]
