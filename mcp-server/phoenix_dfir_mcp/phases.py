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
import sys
import unicodedata

from . import agents, contracts, dualllm, evidence_db, graph, memory, pathpolicy, shield, toolkit, verifier
from .copilot import CopilotClient
from .investigator import (ERROR_THRESHOLD, LOOP_THRESHOLD, _notify_tool, _result, _ShieldGuard,
                           _tool_signature)

BRIEFING_FILE = 'PHOENIX.md'
BRIEFING_MAX_CHARS = 4000
DEFAULT_MAX_PHASE_RETRIES = 2

_MEMORY_TOOLS = ('get_case_state', 'complete_plan_step')
_READ_TOOLS = ('list_artifacts', 'parse_evtx', 'parse_csv', 'parse_json_file', 'parse_log_file',
               'parse_prefetch', 'parse_lnk', 'parse_browser_history', 'analyze_artifact',
               'extract_iocs', 'sigma_scan', 'run_hayabusa', 'run_volatility', 'run_zimmermann',
               'disk_image_info', 'disk_list_files', 'disk_timeline')
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
- Verifie la disponibilite des outils lourds : zimmermann_status, hayabusa_status, volatility_status,
  disk_status (images disque).
- Pour chaque image disque (.E01, .dd, .img, .vmdk, .raw a signature disque), appelle
  disk_image_info : partitions et systemes de fichiers.
- Appelle set_investigation_plan (3-7 etapes) adapte aux artefacts et au briefing.
Termine sans autre message quand le plan est pose.""",
          ('list_artifacts', 'set_investigation_plan', 'zimmermann_status', 'hayabusa_status',
           'volatility_status', 'disk_status', 'disk_image_info', 'get_case_state'), 10),
    Phase('extraction', 'Extraction', """PHASE 2/5 - EXTRACTION.
Execute sur CHAQUE artefact ses outils applicables ; leurs sorties sont indexees automatiquement
dans la super-timeline du cas :
- IMAGES DISQUE d'abord : disk_extract_artifacts (profil auto) extrait EVTX, registre, Prefetch, LNK,
  historiques navigateurs/PowerShell, logs Linux... qui deviennent des artefacts du cas a analyser
  ci-dessous ; disk_timeline indexe les horodatages MACB du systeme de fichiers ; disk_list_files
  (deleted_only) revele les fichiers supprimes ;
- EVTX : parse_evtx (ou run_zimmermann EvtxECmd) ET sigma_scan (+ run_hayabusa si disponible) ;
- logs/scripts : parse_log_file ; CSV : parse_csv ; JSON : parse_json_file ;
- Prefetch/LNK/SQLite navigateur : parse_prefetch / parse_lnk / parse_browser_history ;
- dumps memoire : run_volatility (windows.pslist, windows.cmdline, windows.malfind, windows.netscan,
  windows.svcscan) si Volatility est disponible.
Puis appelle audit_tool_coverage : s'il reste des lacunes, comble-les. Ne formule pas encore de
constat : cette phase collecte. Marque les etapes du plan avec complete_plan_step.""",
          _READ_TOOLS + _MEMORY_TOOLS + ('audit_tool_coverage', 'list_sources',
                                         'zimmermann_status', 'hayabusa_status',
                                         'volatility_status', 'disk_status',
                                         'disk_extract_artifacts'), 40),
    Phase('correlation', 'Correlation', """PHASE 3/5 - CORRELATION ET CONSTATS.
- Interroge la super-timeline : get_timeline (fenetres temporelles, hote, utilisateur) et
  search_evidence (comptes, IP, processus, commandes) pour CORRELER entre artefacts et reconstituer
  la chaine d'attaque (acces initial -> execution -> persistance -> mouvement lateral -> C2 ->
  exfiltration).
- Enrichis les IoCs critiques (virustotal_lookup), mappe les Event IDs (mitre_map_events).
- Consigne chaque element probant avec record_finding : technique MITRE ATT&CK OBLIGATOIRE pour les
  constats critical/high, evidence_refs = identifiants EXACTS (record_id, pid, line, row, inode) lus dans
  les resultats d'outils ou de search_evidence/get_timeline (champ 'ref').
- HYPOTHESES CONCURRENTES : pour la question principale (ex. 'acces initial', 'persistance',
  'exfiltration'), pose AU MOINS DEUX hypotheses exclusives avec add_hypothesis (meme question ;
  ex. A hameconnage T1566.001, B RDP expose T1133), puis rattache chaque constat critical/high a
  son groupe avec weigh_evidence (finding_id, direction supports/refutes, poids : faible 2,
  modere 5, fort 20 ; refutation = 1/x). rank_hypotheses donne le classement par probabilite a
  posteriori et signale les questions non tranchees.
- Pivote sur les entites (graph_build, graph_neighbors) : comptes, hotes, processus, IP communs ;
  graph_patient_zero et graph_blast_radius situent la premiere entite compromise et l'impact.
- casemem_similar_cases signale les cas passes similaires (pistes, jamais preuves).
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
  artefact jamais analyse ou jamais cite) en analysant et, si besoin, en ajoutant des constats.
- REFUTATION : pour chaque question, tente de REFUTER l'hypothese en tete (rank_hypotheses) avec
  weigh_evidence direction 'refutes' (poids 'neutral' si aucune preuve contraire n'est trouvee,
  en citant le constat examine). Chaque constat critical/high doit appartenir a un groupe
  d'hypotheses pondere ; une hypothese 'supported' doit avoir au moins une preuve a l'appui.
- Detection : pour les constats retenus, detect_generate_sigma (et detect_generate_yara pour un
  fichier malveillant extrait) ; verifie avec detect_test_rule (malveillant couvert, zero faux
  positif sur le corpus benin).""",
          _READ_TOOLS + _QUERY_TOOLS + _MEMORY_TOOLS + (
              'challenge_finding', 'record_finding', 'set_hypothesis', 'audit_tool_coverage',
              'audit_evidence_coverage', 'declare_no_incident', 'disk_extract_artifacts'), 24),
    Phase('rapport', 'Rapport', """PHASE 5/5 - RAPPORT.
Consulte get_case_state (et get_timeline pour la chronologie), puis appelle save_report UNE fois avec
un rapport Markdown contenant OBLIGATOIREMENT les sections :
## Resume executif, ## Chronologie (timeline horodatee UTC), ## Indicateurs de compromission (IoC),
## Mapping MITRE ATT&CK, ## Conclusions, ## Recommandations.
Chaque affirmation cite sa preuve (artefact + record_id / pid / ligne). CITATIONS : chaque phrase factuelle du rapport (IoC, technique ATT&CK, horodatage, reference) se termine par l'identifiant du constat VERIFIE qui la prouve, au format [F<id>] (ex. [F3]). get_case_state indique la verification deterministe de chaque constat : un constat 'unverified' ne peut pas etre cite ; corrige-le (references dont les evenements contiennent les entites citees) ou retire-le des conclusions.
Mentionne les constats
affaiblis ou ecartes par la contre-analyse. Constats, contre-analyse et hypotheses sont annexes
automatiquement ; un calque ATT&CK Navigator et un CSV d'IoCs sont generes a cote du rapport.
L'annexe liste aussi les hypotheses concurrentes avec leur probabilite a posteriori, le patient
zero et le rayon d'impact (graphe d'entites) et les regles de detection generees : resume-les dans
## Conclusions (hypothese retenue, questions non tranchees). Apres save_report, appelle
casemem_index_case pour verser le cas dans la memoire inter-enquetes.""",
          ('get_case_state', 'get_timeline', 'search_evidence', 'list_sources', 'save_report'), 12),
]


# Outils et consignes des extensions (phoenix_dfir_mcp/ext)
for _phase in PHASES:
    _phase.tools = tuple(dict.fromkeys(_phase.tools + tuple(toolkit.EXT_PHASE_TOOLS.get(_phase.key, ()))))
    for _hint in toolkit.EXT_PHASE_HINTS.get(_phase.key, ()):
        _phase.instructions = _phase.instructions.rstrip() + '\n' + _hint.strip()
    # Only the tools of the phase's agent team (agents.PHASE_TEAMS) are offered
    _phase.declared_tools = _phase.tools
    _phase.tools = agents.team_allowlist(_phase.key, _phase.tools)
    _phase.team = agents.team(_phase.key)

PHASE_SYSTEM = """Tu es un enqueteur DFIR (Digital Forensics & Incident Response) senior et autonome.
L'enquete se deroule en cinq phases successives ; tu es dans l'une d'elles. A la fin de chaque
phase, un controle qualite deterministe verifie l'etat du cas : s'il echoue, la phase est relancee
avec la liste exacte des lacunes.

REGLES PERMANENTES :
- Agis sans demander de permission ; n'utilise que les outils fournis pour cette phase.
- Appuie chaque conclusion sur une preuve observee. N'invente jamais d'identifiant : record_finding
  exige des evidence_refs (record_id / pid / line / row / inode) produites par un outil, sinon il est
  rejete.
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


def _verification_gaps(state):
    gaps = []
    for f in _retained(state['findings']):
        det = f.get('deterministic') or {}
        if f['severity'] in ('critical', 'high') and f.get('verification') != 'verified' and det:
            gaps.append(f"Constat #{f['id']} ({f['severity']}) non verifie : {det.get('reason')}. Citer les "
                        "references (record_id/row/line/pid/inode) dont les evenements contiennent les "
                        "entites citees, ou reconsigner le constat sans entite non prouvee.")
    return gaps


def gate_correlation(case_dir, ctx):
    verifier.verify_case(case_dir)
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
    if serious and not no_incident and _hypotheses_enabled():
        groups = memory.group_hypotheses(state['hypotheses'])
        if not any(len(g) >= 2 for g in groups.values()):
            gaps.append("Incident etabli sans hypotheses concurrentes : appeler add_hypothesis au "
                        "moins deux fois pour la question principale (meme 'question', alternatives "
                        "exclusives, ex. 'acces initial' : A hameconnage, B RDP expose).")
    gaps.extend(_verification_gaps(state))
    return gaps


def _has_technique(text):
    return re.search(r'T\d{4}', text or '', re.IGNORECASE) is not None


# ----------------------------------------------------------------------------
# Hypotheses concurrentes (portes deterministes)
# ----------------------------------------------------------------------------

def _hypotheses_enabled():
    """Regles d'hypotheses actives seulement si les outils sont charges (extension)."""
    return all(name in toolkit.TOOLS for name in ('add_hypothesis', 'weigh_evidence'))


def _parents(techniques):
    return {t.split('.', 1)[0] for t in techniques}


def finding_groups(finding, groups):
    """Groupes d'hypotheses rattaches a un constat : preuve citant le constat, ou
    technique ATT&CK commune (technique parente incluse)."""
    techs = _parents(memory.techniques_in(finding.get('mitre')))
    linked = []
    for key, group in groups.items():
        cited = any(e.get('finding_id') == finding['id'] for h in group for e in h['evidence'])
        shared = techs and any(techs & _parents(h['techniques']) for h in group)
        if cited or shared:
            linked.append(key)
    return linked


def hypothesis_gaps(state):
    """Lacunes de la contre-analyse sur les hypotheses concurrentes."""
    gaps = []
    groups = memory.group_hypotheses(state['hypotheses'])
    serious = [f for f in _retained(state['findings'])
               if f['severity'] in ('critical', 'high') and not _is_shield_finding(f)]
    no_incident = bool((state.get('conclusion') or {}).get('no_incident'))
    to_refute = []
    if serious and not no_incident:
        for f in serious:
            linked = finding_groups(f, groups)
            if not linked:
                gaps.append(f"Constat #{f['id']} ({f['severity']}) rattache a aucun groupe "
                            "d'hypotheses : weigh_evidence avec finding_id="
                            f"{f['id']} sur l'hypothese concernee.")
                continue
            if not any(h['evidence'] for key in linked for h in groups[key]):
                gaps.append(f"Constat #{f['id']} : le groupe d'hypotheses "
                            f"'{groups[linked[0]][0]['question']}' n'a jamais ete pondere "
                            "(weigh_evidence).")
            to_refute.extend(k for k in linked if k not in to_refute)
    for key in to_refute:
        top = memory.leader(groups[key])
        if top and not any(e.get('direction') == 'refutes' for e in top['evidence']):
            gaps.append(f"Question '{top['question']}' : l'hypothese en tete #{top['id']} "
                        f"({top['statement'][:80]}) n'a pas ete confrontee : weigh_evidence "
                        "direction 'refutes' (poids 'neutral' si aucune preuve contraire).")
    for h in state['hypotheses']:
        if h.get('status') in memory.SUPPORTED_STATUSES and not memory.support_count(h):
            gaps.append(f"Hypothese #{h['id']} marquee '{h['status']}' sans aucune preuve a l'appui : "
                        "weigh_evidence (supports) ou revoir son statut.")
    return gaps


def gate_contre_analyse(case_dir, ctx):
    verifier.verify_case(case_dir)
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
    if _hypotheses_enabled():
        gaps.extend(hypothesis_gaps(state))
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
        raw_body = f.read().split(toolkit.ANNEX_MARKER, 1)[0]
    body = _fold(raw_body)
    state = memory.get_state(case_dir)
    required = list(_REQUIRED_SECTIONS)
    if not (state.get('conclusion') or {}).get('no_incident'):
        required += list(_INCIDENT_SECTIONS)
    gaps = [f"Le rapport ne contient pas {label} : le completer et rappeler save_report."
            for keys, label in required if not any(k in body for k in keys.split('|'))]
    citations = verifier.check_citations(raw_body, verifier.verified_ids(case_dir))
    for bad in citations['unlinked'][:5]:
        gaps.append(f"Phrase factuelle non liee a un constat verifie ({bad['reason']}) : "
                    f"\"{bad['sentence'][:140]}\". Ajouter [F<id>] d'un constat verifie ou retirer la phrase.")
    return gaps


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
        self.usage_log = contracts.UsageLog()
        self.tool_calls_by_agent = {}
        self.session_tokens = 0


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
        'hypotheses': [{'id': h['id'], 'question': h.get('question'), 'status': h['status'],
                        'statement': h['hypothesis'], 'posterior': h['posterior'],
                        'supports': memory.support_count(h), 'refutes': memory.refute_count(h)}
                       for h in state['hypotheses']],
        'conclusion': state.get('conclusion'),
        'audits': list((state.get('audits') or {}).keys()),
    }
    clean, _hits = shield.sanitize(digest)
    return clean


def _run_session(ctx, phase, user_prompt, phase_index):
    """Session LLM bornee d'une phase : boucle d'appels d'outils jusqu'a reponse finale."""
    lead = phase.team[0]
    before = dict(getattr(ctx.client, 'usage', {}) or {})
    budget = agents.Budget(lead, before)
    try:
        _session_turns(ctx, phase, user_prompt, phase_index, budget)
    finally:
        after = dict(getattr(ctx.client, 'usage', {}) or {})
        ctx.usage_log.add(lead.name, before, after)
        ctx.session_tokens = budget.charge(after)


def _session_turns(ctx, phase, user_prompt, phase_index, budget):
    tools = toolkit.openai_tools(names=phase.tools)
    allowed = set(phase.tools)
    messages = [{'role': 'system', 'content': PHASE_SYSTEM},
                {'role': 'user', 'content': user_prompt}]
    for _turn in range(phase.max_turns):
        if ctx.turns_left <= 0:
            ctx.log(f"[{phase.title}] budget global de tours epuise")
            return
        if budget.exhausted:
            ctx.log(f"[{phase.title}] budget de tokens de l'agent {budget.agent.name} epuise "
                    f"({budget.used}/{budget.agent.max_tokens})")
            return
        ctx.turns_left -= 1
        ctx.turns_used += 1
        message = ctx.client.chat(messages, tools=tools)
        budget.charge(getattr(ctx.client, 'usage', None))
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
                agent = agents.owner(phase.key, name)
                ctx.tool_calls_by_agent[agent] = ctx.tool_calls_by_agent.get(agent, 0) + 1
                ctx.executed.append({'step': step, 'phase': phase.key, 'tool': name,
                                     'arguments': arguments, 'agent': agent})
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
    lead, members = phase.team[0], phase.team[1:]
    parts.append(f"AGENT DE LA PHASE : {lead.title} ({lead.mission}) Specialistes dont les outils sont "
                 f"disponibles : {', '.join(a.title for a in members)}.")
    parts.append("ETAT ACTUEL DU CAS (memoire persistante) :\n"
                 + toolkit.to_json(state_digest(case_dir), 12000))
    if gaps:
        parts.append("CONTROLE QUALITE ECHOUE - combler exactement ces lacunes avant de terminer :\n- "
                     + '\n- '.join(gaps))
    return '\n\n'.join(parts)


def deterministic_report(case_dir):
    """Rapport sans LLM : uniquement les constats verifies, chacun cite par [F<id>]."""
    verifier.verify_case(case_dir)
    state = memory.get_state(case_dir)
    verified = [f for f in state['findings'] if f.get('verification') == 'verified']
    lines = ["# Rapport Phoenix DFIR (genere automatiquement)", "",
             "> L'enqueteur n'a pas produit de rapport valide : synthese deterministe des constats "
             "verifies. A relire par l'analyste.", "", "## Resume executif", ""]
    if verified:
        lines.append(f"{len(verified)} constat(s) verifie(s) par les preuves du cas.")
    elif (state.get('conclusion') or {}).get('no_incident'):
        lines.append("Aucun incident etabli (voir la conclusion en annexe).")
    else:
        lines.append("Aucun constat verifie.")
    lines += ["", "## Chronologie et constats", ""]
    for f in verified:
        refs = ', '.join(f"{r['kind']}={r['value']}@{os.path.basename(str(r['artifact']))}"
                         for r in f.get('evidence_refs') or [])
        lines.append(f"- {f['severity'].upper()} {f['title']} ({f['mitre'] or 'sans technique'}; {refs}) "
                     f"[F{f['id']}]")
    lines += ["", "## Recommandations", "", "Revue humaine des constats verifies et des constats exclus "
              "en annexe.", ""]
    return '\n'.join(lines)


def _fallback_report(case_dir, ctx):
    """Rapport minimal deterministe si l'enqueteur n'a pas produit de rapport."""
    result = toolkit.run_tool('save_report', {
        'case_dir': case_dir,
        'title': 'Rapport Phoenix DFIR (genere automatiquement)',
        'markdown': deterministic_report(case_dir),
    })
    if isinstance(result, dict) and result.get('report_path'):
        ctx.report_path = result['report_path']
        _notify_tool(ctx.on_tool, 'fallback', 'save_report', {'case_dir': case_dir}, result)


def _rebuild_graph(case_dir, ctx, index):
    """Graphe d'entites reconstruit en fin de correlation / contre-analyse (best-effort :
    n'influence jamais une porte)."""
    try:
        g = graph.build_and_save(case_dir)
    except Exception as exc:  # le graphe ne doit jamais faire echouer l'enquete
        ctx.log(f"[graphe] reconstruction impossible : {exc}")
        return
    pz = g.get('patient_zero') or {}
    _notify_tool(ctx.on_tool, f'{index}.graph', 'graph_build', {'case_dir': case_dir},
                 {'nodes': len(g['nodes']), 'edges': len(g['edges']),
                  'patient_zero': pz.get('node'), 'blast_radius': len((g.get('blast_radius') or {})
                                                                      .get('nodes') or [])})
    ctx.log(f"[graphe] {len(g['nodes'])} entites, {len(g['edges'])} relations, patient zero : "
            f"{pz.get('node') or 'indetermine'}")


def _index_case_memory(case_dir, ctx):
    """Verser le cas dans la memoire inter-enquetes s'il est sous une racine de cas
    configuree (best-effort)."""
    module = sys.modules.get(f'{__package__}.ext.casemem')
    if module is None:
        return
    try:
        if module.roots() and module.allowed_case(case_dir):
            module.index_case(case_dir, explicit=False)
            ctx.log('[memoire inter-enquetes] cas indexe')
    except Exception as exc:  # l'indexation ne doit jamais faire echouer l'enquete
        ctx.log(f"[memoire inter-enquetes] indexation impossible : {exc}")


def investigate_phased(case_dir, question=None, model=None, max_steps=None, on_step=None,
                       enable_verification=True, on_tool=None,
                       max_phase_retries=DEFAULT_MAX_PHASE_RETRIES):
    # Sandboxing PAR JOB : outils confines au cas, case_dir impose aux outils,
    # index de preuves cloisonne (variable de contexte, reinitialisee en sortie).
    with pathpolicy.job_scope(case_dir):
        return _investigate_phased_scoped(case_dir, question, model, max_steps, on_step,
                                          enable_verification, on_tool, max_phase_retries)


def _investigate_phased_scoped(case_dir, question, model, max_steps, on_step,
                               enable_verification, on_tool, max_phase_retries):
    def log(msg):
        if on_step:
            on_step(msg)

    client = CopilotClient(model=model)
    # Double LLM (PHOENIX_DUAL_LLM) : sorties d'outils lues en quarantaine
    guard = _ShieldGuard(case_dir, on_tool, log, dual=dualllm.from_env(case_dir, model))
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
        phase_tokens = 0
        while attempts <= max_phase_retries and ctx.turns_left > 0:
            attempts += 1
            log(f"[phase {index}/5] {phase.title}" + (f" (relance {attempts - 1})" if attempts > 1 else ''))
            _run_session(ctx, phase, _phase_prompt(case_dir, phase, question, briefing, gaps), index)
            phase_tokens += ctx.session_tokens
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
        findings = [f['id'] for f in memory.get_state(case_dir)['findings']]
        output = contracts.PhaseOutput(phase=phase.key, agent=phase.team[0].name, passed=passed,
                                       attempts=max(1, attempts), gaps=gaps, findings=findings,
                                       tokens=phase_tokens)
        phase_results.append(output.model_dump())
        if phase.key in ('correlation', 'contre_analyse'):
            _rebuild_graph(case_dir, ctx, index)

    if not ctx.report_path:
        _fallback_report(case_dir, ctx)
    _index_case_memory(case_dir, ctx)

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
    result['metrics']['agents'] = {'usage': ctx.usage_log.snapshot(),
                                   'tool_calls': dict(sorted((k or 'none', v)
                                                             for k, v in ctx.tool_calls_by_agent.items()))}
    return result
