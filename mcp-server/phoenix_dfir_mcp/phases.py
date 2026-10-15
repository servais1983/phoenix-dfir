"""Enquete en cinq phases a portes qualite deterministes.

    1. INVENTAIRE      — artefacts inventories, plan d'enquete pose
    2. EXTRACTION      — chaque artefact passe par ses outils applicables,
                         sorties indexees dans la super-timeline (evidence_db)
    3. CORRELATION     — constats cites (RecordID / PID / ligne), mappes ATT&CK,
                         ou conclusion explicite d'absence d'incident
    4. CONTRE-ANALYSE  — chaque constat critique/haut confronte a une hypothese
                         alternative, audits de couverture outils et preuves
    5. RAPPORT         — rapport complet (sections obligatoires) + exports

Chaque phase est une session LLM bornee, avec un prompt dedie et une liste
blanche d'outils (l'enqueteur ne voit que les outils utiles a la phase). A la
fin de chaque phase, une PORTE QUALITE verifie l'etat du cas par des regles
deterministes (memoire du cas, index des preuves, rapport) — jamais par un
LLM. Une porte en echec relance la phase avec la liste exacte des lacunes
(au plus `max_phase_retries` fois), puis l'enquete continue avec des
resultats partiels signales. La memoire du cas et l'index des preuves
servent d'etat entre phases : chaque phase repart d'un contexte compact.

Un fichier PHOENIX.md dans le dossier du cas (briefing de l'enqueteur : ce
qu'on sait, ce qu'on cherche) est injecte dans chaque phase.
"""

import json
import os
import re
import unicodedata

from . import evidence_db, memory, pathpolicy, shield, toolkit
from .copilot import CopilotClient
from .investigator import (ERROR_THRESHOLD, LOOP_THRESHOLD, _notify_tool, _result, _ShieldGuard,
                           _tool_signature)

BRIEFING_FILE = 'PHOENIX.md'
BRIEFING_MAX_CHARS = 4000
DEFAULT_MAX_PHASE_RETRIES = 2

_MEMORY_TOOLS = ('get_case_state', 'complete_plan_step')
_READ_TOOLS = ('list_artifacts', 'parse_evtx', 'parse_csv', 'parse_json_file', 'parse_log_file',
               'parse_prefetch', 'parse_lnk', 'parse_browser_history', 'analyze_artifact',
               'extract_iocs', 'sigma_scan', 'run_hayabusa', 'run_volatility', 'run_zimmermann')
_QUERY_TOOLS = ('search_evidence', 'get_timeline', 'list_sources')


class Phase:
    def __init__(self, key, title, instructions, tools, max_turns):
        self.key = key
        self.title = title
        self.instructions = instructions
        self.tools = tuple(dict.fromkeys(tools))
        self.max_turns = max_turns


PHASES = [
    Phase('inventaire', 'Inventaire', """PHASE 1/5 - INVENTAIRE.
- Appelle list_artifacts sur le dossier du cas.
- Verifie la disponibilite des outils lourds : zimmermann_status, hayabusa_status, volatility_status.
- Appelle set_investigation_plan (3-7 etapes) adapte aux artefacts et au briefing.
Termine sans autre message quand le plan est pose.""",
          ('list_artifacts', 'set_investigation_plan', 'zimmermann_status', 'hayabusa_status',
           'volatility_status', 'get_case_state'), 8),
    Phase('extraction', 'Extraction', """PHASE 2/5 - EXTRACTION.
Execute sur CHAQUE artefact ses outils applicables ; leurs sorties sont indexees automatiquement
dans la super-timeline du cas :
- EVTX : parse_evtx (ou run_zimmermann EvtxECmd) ET sigma_scan (+ run_hayabusa si disponible) ;
- logs/scripts : parse_log_file ; CSV : parse_csv ; JSON : parse_json_file ;
- Prefetch/LNK/SQLite navigateur : parse_prefetch / parse_lnk / parse_browser_history ;
- dumps memoire : run_volatility (windows.pslist, windows.cmdline, windows.malfind, windows.netscan,
  windows.svcscan) si Volatility est disponible.
Puis appelle audit_tool_coverage : s'il reste des lacunes, comble-les. Ne formule pas encore de
constat : cette phase collecte. Marque les etapes du plan avec complete_plan_step.""",
          _READ_TOOLS + _MEMORY_TOOLS + ('audit_tool_coverage', 'list_sources',
                                         'zimmermann_status', 'hayabusa_status',
                                         'volatility_status'), 30),
    Phase('correlation', 'Correlation', """PHASE 3/5 - CORRELATION ET CONSTATS.
- Interroge la super-timeline : get_timeline (fenetres temporelles, hote, utilisateur) et
  search_evidence (comptes, IP, processus, commandes) pour CORRELER entre artefacts et reconstituer
  la chaine d'attaque (acces initial -> execution -> persistance -> mouvement lateral -> C2 ->
  exfiltration).
- Enrichis les IoCs critiques (virustotal_lookup), mappe les Event IDs (mitre_map_events).
- Consigne chaque element probant avec record_finding : technique MITRE ATT&CK OBLIGATOIRE pour les
  constats critical/high, evidence_refs = identifiants EXACTS (record_id, pid, line, row) lus dans
  les resultats d'outils ou de search_evidence/get_timeline (champ 'ref').
- Formule et tranche tes hypotheses (set_hypothesis).
- Compromission ACTIVE etablie -> propose_remediation (validation humaine, jamais executee par toi).
- Si les preuves montrent une activite legitime SANS incident, appelle declare_no_incident avec la
  justification : n'invente jamais de constat.""",
          _READ_TOOLS + _QUERY_TOOLS + _MEMORY_TOOLS + (
              'record_finding', 'set_hypothesis', 'propose_remediation', 'virustotal_lookup',
              'mitre_map_events', 'declare_no_incident'), 25),
    Phase('contre_analyse', 'Contre-analyse', """PHASE 4/5 - CONTRE-ANALYSE (avocat du diable).
- Relis tous les constats (get_case_state). Evalue d'abord la chaine d'attaque d'ensemble : des
  constats coherents qui se corroborent sur plusieurs phases ATT&CK sont plus credibles qu'un
  constat isole.
- Pour CHAQUE constat critical/high : formule l'hypothese alternative la plus plausible (activite
  d'administration legitime, faux positif d'outil, outil de collecte IR, autre explication),
  cherche les preuves qui la soutiendraient (search_evidence, get_timeline), puis appelle
  challenge_finding (upheld / downgraded / refuted) avec la justification.
- Resous les contradictions entre constats. Une detection d'un seul outil ne suffit pas a une
  attribution forte.
- Appelle audit_tool_coverage ET audit_evidence_coverage : comble les lacunes (outil oublie,
  artefact jamais analyse ou jamais cite) en analysant et, si besoin, en ajoutant des constats.""",
          _READ_TOOLS + _QUERY_TOOLS + _MEMORY_TOOLS + (
              'challenge_finding', 'record_finding', 'set_hypothesis', 'audit_tool_coverage',
              'audit_evidence_coverage', 'declare_no_incident'), 20),
    Phase('rapport', 'Rapport', """PHASE 5/5 - RAPPORT.
Consulte get_case_state (et get_timeline pour la chronologie), puis appelle save_report UNE fois avec
un rapport Markdown contenant OBLIGATOIREMENT les sections :
## Resume executif, ## Chronologie (timeline horodatee UTC), ## Indicateurs de compromission (IoC),
## Mapping MITRE ATT&CK, ## Conclusions, ## Recommandations.
Chaque affirmation cite sa preuve (artefact + record_id / pid / ligne). Mentionne les constats
affaiblis ou ecartes par la contre-analyse. Constats, contre-analyse et hypotheses sont annexes
automatiquement ; un calque ATT&CK Navigator et un CSV d'IoCs sont generes a cote du rapport.""",
          ('get_case_state', 'get_timeline', 'search_evidence', 'list_sources', 'save_report'), 8),
]

PHASE_SYSTEM = """Tu es un enqueteur DFIR (Digital Forensics & Incident Response) senior et autonome.
L'enquete se deroule en cinq phases successives ; tu es dans l'une d'elles. A la fin de chaque
phase, un controle qualite deterministe verifie l'etat du cas : s'il echoue, la phase est relancee
avec la liste exacte des lacunes.

REGLES PERMANENTES :
- Agis sans demander de permission ; n'utilise que les outils fournis pour cette phase.
- Appuie chaque conclusion sur une preuve observee. N'invente jamais d'identifiant : record_finding
  exige des evidence_refs (record_id / pid / line / row) produites par un outil, sinon il est rejete.
- Ne repete pas le meme appel en boucle ; si un outil echoue, change d'approche.
- Quand la phase est terminee, reponds par un court message sans appel d'outil.

""" + shield.SYSTEM_RULE


# ============================================================================
# Portes qualite (deterministes)
# ============================================================================

def _fold(text):
    return ''.join(c for c in unicodedata.normalize('NFKD', text or '')
                   if not unicodedata.combining(c)).lower()


def _retained(findings):
    return [f for f in findings if f.get('verification') != 'refuted'
            and (f.get('challenge') or {}).get('verdict') != 'refuted']


def _is_shield_finding(f):
    return 'injection de prompt' in (f.get('title') or '').lower()


def gate_inventaire(case_dir, ctx):
    gaps = []
    if 'list_artifacts' not in ctx.tools_ok:
        gaps.append("list_artifacts n'a pas ete appele avec succes sur le dossier du cas.")
    if not memory.get_state(case_dir)['plan']:
        gaps.append("Aucun plan : appeler set_investigation_plan (3-7 etapes).")
    return gaps


def gate_extraction(case_dir, ctx):
    gaps = []
    artifacts = toolkit.case_artifacts(case_dir)
    if artifacts and not evidence_db.sources(case_dir)['sources']:
        gaps.append("Aucun artefact n'a ete analyse : lancer les parsers adaptes.")
    for gap in toolkit.compute_tool_coverage(case_dir)['gaps'][:15]:
        gaps.append(f"{gap['artifact']} : etape '{gap['step']}' non couverte "
                    f"(executer l'un de : {', '.join(gap['run_one_of'])}).")
    return gaps


def gate_correlation(case_dir, ctx):
    state = memory.get_state(case_dir)
    findings = [f for f in _retained(state['findings']) if not _is_shield_finding(f)]
    no_incident = bool((state.get('conclusion') or {}).get('no_incident'))
    gaps = []
    if not findings and not no_incident:
        gaps.append("Aucun constat et aucune conclusion : consigner les constats (record_finding) "
                    "ou conclure explicitement avec declare_no_incident.")
    for f in findings:
        if f['severity'] in ('critical', 'high') and not _has_technique(f.get('mitre')):
            gaps.append(f"Constat #{f['id']} ({f['severity']}) sans technique MITRE ATT&CK : "
                        "le reconsigner avec la technique (ex: T1059.001).")
    serious = [f for f in findings if f['severity'] in ('critical', 'high')]
    if no_incident and serious:
        gaps.append(f"Contradiction : declare_no_incident alors que {len(serious)} constat(s) "
                    "critical/high sont retenus. Trancher (contre-analyse ou nouvelle conclusion).")
    return gaps


def _has_technique(text):
    return re.search(r'T\d{4}', text or '', re.IGNORECASE) is not None


def gate_contre_analyse(case_dir, ctx):
    state = memory.get_state(case_dir)
    gaps = []
    for f in _retained(state['findings']):
        if f['severity'] in ('critical', 'high') and not f.get('challenge') and not _is_shield_finding(f):
            gaps.append(f"Constat #{f['id']} ({f['severity']}) non confronte a une hypothese "
                        "alternative : appeler challenge_finding.")
    audits = state.get('audits') or {}
    for name, tool in (('tool_coverage', 'audit_tool_coverage'),
                       ('evidence_coverage', 'audit_evidence_coverage')):
        if name not in audits:
            gaps.append(f"Audit non realise : appeler {tool}.")
    return gaps


_REQUIRED_SECTIONS = (
    ('resume', 'un resume executif'),
    ('chronologie|timeline', 'une chronologie horodatee'),
    ('recommandation', 'des recommandations'),
)
_INCIDENT_SECTIONS = (
    ('mitre|att&ck', 'le mapping MITRE ATT&CK'),
    ('ioc|indicateur', 'les indicateurs de compromission'),
)


def gate_rapport(case_dir, ctx):
    if not ctx.report_path or not os.path.isfile(ctx.report_path):
        return ["Aucun rapport : appeler save_report avec le rapport complet."]
    with open(ctx.report_path, 'r', encoding='utf-8') as f:
        body = _fold(f.read().split(toolkit.ANNEX_MARKER, 1)[0])
    state = memory.get_state(case_dir)
    required = list(_REQUIRED_SECTIONS)
    if not (state.get('conclusion') or {}).get('no_incident'):
        required += list(_INCIDENT_SECTIONS)
    return [f"Le rapport ne contient pas {label} : le completer et rappeler save_report."
            for keys, label in required if not any(k in body for k in keys.split('|'))]


GATES = {
    'inventaire': gate_inventaire,
    'extraction': gate_extraction,
    'correlation': gate_correlation,
    'contre_analyse': gate_contre_analyse,
    'rapport': gate_rapport,
}


# ============================================================================
# Execution
# ============================================================================

class _Context:
    def __init__(self, case_dir, client, guard, on_tool, log, turn_budget):
        self.case_dir = case_dir
        self.client = client
        self.guard = guard
        self.on_tool = on_tool
        self.log = log
        self.turns_left = turn_budget
        self.turns_used = 0
        self.executed = []
        self.tools_ok = set()
        self.report_path = None
        self.call_counts = {}
        self.error_count = 0


def load_briefing(case_dir):
    path = os.path.join(case_dir, BRIEFING_FILE)
    if not os.path.isfile(path):
        return ''
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        text, _hits = shield.scan_text(f.read(BRIEFING_MAX_CHARS))
    return text.strip()


def state_digest(case_dir):
    """Etat compact du cas transmis a chaque phase (memoire persistante)."""
    state = memory.get_state(case_dir)
    srcs = evidence_db.sources(case_dir)
    digest = {
        'artifacts': [os.path.relpath(p, case_dir) for p in toolkit.case_artifacts(case_dir)][:200],
        'plan': [f"{'[x]' if s['status'] == 'done' else '[ ]'} {s['step']}" for s in state['plan']],
        'sources_indexed': [f"{s['artifact']} <- {s['tool']} ({s['events']} evt{'' if s['ok'] else ', ECHEC'})"
                            for s in srcs['sources']][:80],
        'timeline_span': srcs.get('time_span'),
        'findings': [{'id': f['id'], 'severity': f['severity'], 'title': f['title'],
                      'mitre': f['mitre'], 'refs': f.get('evidence_refs', [])[:3],
                      'challenge': (f.get('challenge') or {}).get('verdict')}
                     for f in state['findings']],
        'hypotheses': [f"[{h['status']}] {h['hypothesis']}" for h in state['hypotheses']],
        'conclusion': state.get('conclusion'),
        'audits': list((state.get('audits') or {}).keys()),
    }
    clean, _hits = shield.sanitize(digest)
    return clean


def _run_session(ctx, phase, user_prompt, phase_index):
    """Session LLM bornee d'une phase : boucle d'appels d'outils jusqu'a reponse finale."""
    tools = toolkit.openai_tools(names=phase.tools)
    allowed = set(phase.tools)
    messages = [{'role': 'system', 'content': PHASE_SYSTEM},
                {'role': 'user', 'content': user_prompt}]
    for _turn in range(phase.max_turns):
        if ctx.turns_left <= 0:
            ctx.log(f"[{phase.title}] budget global de tours epuise")
            return
        ctx.turns_left -= 1
        ctx.turns_used += 1
        message = ctx.client.chat(messages, tools=tools)
        tool_calls = message.get('tool_calls') or []
        if not tool_calls:
            return
        messages.append({'role': 'assistant', 'content': message.get('content'),
                         'tool_calls': tool_calls})
        step = f'{phase_index}.{ctx.turns_used}'
        for call in tool_calls:
            func = call.get('function', {})
            name = func.get('name', '')
            try:
                arguments = json.loads(func.get('arguments') or '{}')
            except json.JSONDecodeError:
                arguments = {}
            if name not in allowed:
                result = {'error': f"Outil '{name}' non disponible en phase {phase.title}. "
                                   f"Outils autorises : {sorted(allowed)}"}
            else:
                ctx.log(f"[{phase.title}] {name}({toolkit.to_json(arguments, 300)})")
                result = toolkit.run_tool(name, arguments)
                ctx.executed.append({'step': step, 'phase': phase.key, 'tool': name,
                                     'arguments': arguments})
                _notify_tool(ctx.on_tool, step, name, arguments, result)
                if not (isinstance(result, dict) and result.get('error')):
                    ctx.tools_ok.add(name)
                if name == 'save_report' and isinstance(result, dict) and result.get('report_path'):
                    ctx.report_path = result['report_path']
            messages.append({'role': 'tool', 'tool_call_id': call.get('id', ''),
                             'content': ctx.guard.view(step, name, arguments, result)})
            if isinstance(result, dict) and result.get('error'):
                ctx.error_count += 1
                if ctx.error_count % ERROR_THRESHOLD == 0:
                    messages.append({'role': 'user', 'content': (
                        "Plusieurs outils ont echoue. Verifie les chemins (list_sources, "
                        "get_case_state), change d'outil et poursuis avec ce qui fonctionne.")})
            sig = _tool_signature(call)
            ctx.call_counts[sig] = ctx.call_counts.get(sig, 0) + 1
            if ctx.call_counts[sig] == LOOP_THRESHOLD:
                messages.append({'role': 'user', 'content': (
                    f"Tu as deja lance '{name}' avec les memes arguments {LOOP_THRESHOLD} fois. "
                    "Change d'approche ou termine la phase.")})


def _phase_prompt(case_dir, phase, question, briefing, gaps):
    parts = [f"Dossier du cas : {case_dir}"]
    if briefing:
        parts.append("BRIEFING DE L'ENQUETEUR (PHOENIX.md) :\n" + briefing)
    if question:
        parts.append(f"Question / contexte de l'enqueteur principal : {question}")
    parts.append(phase.instructions)
    parts.append("ETAT ACTUEL DU CAS (memoire persistante) :\n"
                 + toolkit.to_json(state_digest(case_dir), 12000))
    if gaps:
        parts.append("CONTROLE QUALITE ECHOUE - combler exactement ces lacunes avant de terminer :\n- "
                     + '\n- '.join(gaps))
    return '\n\n'.join(parts)


def _fallback_report(case_dir, ctx):
    """Rapport minimal deterministe si l'enqueteur n'a pas produit de rapport."""
    result = toolkit.run_tool('save_report', {
        'case_dir': case_dir,
        'title': 'Rapport Phoenix DFIR (genere automatiquement)',
        'markdown': ("# Rapport Phoenix DFIR (genere automatiquement)\n\n"
                     "> L'enqueteur n'a pas produit de rapport valide : synthese generee a partir "
                     "de la memoire du cas. A relire par l'analyste.\n"),
    })
    if isinstance(result, dict) and result.get('report_path'):
        ctx.report_path = result['report_path']
        _notify_tool(ctx.on_tool, 'fallback', 'save_report', {'case_dir': case_dir}, result)


def investigate_phased(case_dir, question=None, model=None, max_steps=None, on_step=None,
                       enable_verification=True, on_tool=None,
                       max_phase_retries=DEFAULT_MAX_PHASE_RETRIES):
    def log(msg):
        if on_step:
            on_step(msg)

    pathpolicy.add_root(case_dir)
    toolkit.set_active_case(case_dir)
    client = CopilotClient(model=model)
    guard = _ShieldGuard(case_dir, on_tool, log)
    budget = max_steps or sum(p.max_turns * (1 + max_phase_retries) for p in PHASES)
    ctx = _Context(case_dir, client, guard, on_tool, log, budget)
    briefing = load_briefing(case_dir)
    if briefing:
        log('[briefing] PHOENIX.md charge et injecte dans chaque phase')

    phase_results = []
    for index, phase in enumerate(PHASES, 1):
        gaps = []
        attempts = 0
        passed = False
        while attempts <= max_phase_retries and ctx.turns_left > 0:
            attempts += 1
            log(f"[phase {index}/5] {phase.title}" + (f" (relance {attempts - 1})" if attempts > 1 else ''))
            _run_session(ctx, phase, _phase_prompt(case_dir, phase, question, briefing, gaps), index)
            gaps = GATES[phase.key](case_dir, ctx)
            passed = not gaps
            _notify_tool(on_tool, f'{index}.gate', 'phase_gate',
                         {'phase': phase.key, 'attempt': attempts},
                         {'passed': passed, 'gaps': gaps,
                          'message': (f"Porte '{phase.title}' franchie" if passed else
                                      f"Porte '{phase.title}' en echec ({len(gaps)} lacune(s)) : "
                                      + ' | '.join(gaps[:3]))[:500]})
            log(f"[porte {phase.title}] " + ('OK' if passed else 'ECHEC - ' + ' | '.join(gaps[:3])))
            if passed:
                break
        phase_results.append({'phase': phase.key, 'passed': passed, 'attempts': attempts,
                              'gaps': gaps})

    if not ctx.report_path:
        _fallback_report(case_dir, ctx)

    passed_count = sum(1 for r in phase_results if r['passed'])
    verdict = f"PORTES: {passed_count}/{len(PHASES)} franchies"
    if passed_count < len(PHASES):
        failed = [r['phase'] for r in phase_results if not r['passed']]
        verdict += f" (echec : {', '.join(failed)})"
    result = _result(verdict, ctx.report_path, ctx.turns_used, ctx.executed, client, case_dir,
                     verdict, log, enable_verification, on_tool, guard)
    result['metrics']['mode'] = 'phased'
    result['metrics']['phases'] = phase_results
    result['metrics']['gates_passed'] = passed_count
    return result
