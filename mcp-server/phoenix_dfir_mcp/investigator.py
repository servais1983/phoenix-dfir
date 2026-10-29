"""Enqueteur DFIR autonome pilote par GitHub Copilot.

Boucle agentique DFIR structuree :

- PLANIFICATION : l'enqueteur decompose d'abord le cas en 3-7 etapes
  (set_investigation_plan), puis les suit (complete_plan_step).
- MEMOIRE STRUCTUREE : constats (record_finding) et hypotheses
  (set_hypothesis) accumules dans le cas, restituables (get_case_state) —
  l'enquete tient sur de gros cas sans saturer le contexte.
- MONITORING D'EXECUTION : detection des boucles (meme outil rejoue) et des
  erreurs repetees, avec injection de conseils correctifs (mentor).
- REVUE ADVISER : une passe critique finale verifie que l'enquete est
  complete et etayee avant de clore (une relance au plus si des lacunes).
- OBSERVABILITE : tokens consommes, outils executes, findings/hypotheses.
- BOUCLIER ANTI-INJECTION : chaque sortie d'outil est nettoyee, les injections
  de prompt cachees dans les artefacts sont neutralisees (et consignees comme
  constat d'anti-forensique) puis encapsulees comme donnees non fiables.
- SORTIE STRUCTUREE STRICTE : un constat doit citer un RecordID / PID / ligne
  reellement extrait par un outil deterministe (toolkit.validate_refs).
- DOUBLE LLM (opt-in, PHOENIX_DUAL_LLM) : le planificateur ne voit jamais la
  sortie brute des outils lisant des artefacts, seulement des faits structures
  extraits en quarantaine et valides de facon deterministe (dualllm.py).
- TRAÇABILITE : chaque appel d'outil est remonte a l'appelant (on_tool) qui
  le scelle dans la chaine de preuve (Chain of Custody SHA-256 de la plateforme).
"""

import json

import os

from . import dualllm, memory, pathpolicy, shield, toolkit
from .copilot import CopilotClient

MAX_STEPS = 45
TOOL_RESULT_MAX_CHARS = 20000
LOOP_THRESHOLD = 3          # meme appel (outil+args) repete => nudge anti-boucle
ERROR_THRESHOLD = 3         # erreurs d'outil cumulees => nudge de reflexion
MAX_ADVISER_RUNS = 2        # revues adviser (borne pour eviter les boucles)
MAX_VERIFY_STEPS = 14       # tours max de la passe de verification

VERIFIER_PROMPT = """Tu es un verificateur DFIR independant. On te remet la liste des constats
(findings) etablis par un enqueteur, avec le dossier du cas. Ta mission : re-examiner la PREUVE
BRUTE a la source pour chaque constat (via les outils de lecture : parsers, sigma_scan,
extract_iocs, get_case_state...) et statuer objectivement.

Pour CHAQUE constat, appelle verify_finding avec :
- 'verified' si la preuve re-examinee confirme sans ambiguite le constat ;
- 'unverified' si tu ne peux pas le reproduire a partir des artefacts ;
- 'refuted' si la preuve contredit le constat.
Sois sceptique : ne valide que ce que la preuve etablit reellement. Quand tous les constats sont
statues, termine (sans autre message).

""" + shield.SYSTEM_RULE

SYSTEM_PROMPT = """Tu es un enqueteur DFIR (Digital Forensics & Incident Response) senior et autonome.
Tu disposes d'une boite a outils forensique complete (parsers EVTX/CSV/JSON/logs/Prefetch/LNK/
navigateurs, extraction d'IoCs, regles Sigma, mapping MITRE ATT&CK, VirusTotal, outils Eric
Zimmermann, Hayabusa, Volatility 3) ET d'une memoire d'enquete (plan, constats, hypotheses).

Ta mission : resoudre le cas SEUL, methodiquement et rapidement.

METHODOLOGIE OBLIGATOIRE :
1. PLAN — commence par list_artifacts, puis set_investigation_plan (3-7 etapes). Marque chaque
   etape terminee avec complete_plan_step.
2. COLLECTE — analyse CHAQUE artefact pertinent avec l'outil adapte a son format. Verifie
   zimmermann_status ; prefere les EZ Tools s'ils sont dispo, sinon les parsers natifs.
3. DETECTION — lance sigma_scan sur chaque EVTX ; si hayabusa_status est disponible, complete
   avec run_hayabusa (couverture de regles bien plus large).
   MEMOIRE VIVE — pour chaque dump memoire (.raw/.mem/.vmem/.dmp), verifie volatility_status puis
   run_volatility : windows.pslist/pstree, windows.cmdline, windows.malfind (injection, process
   hollowing), windows.netscan (beacons C2), windows.svcscan (persistance).
4. MEMOIRE — des qu'un element probant est etabli, appelle record_finding (severite, preuve,
   technique MITRE, confiance). Formule des hypotheses CONCURRENTES par question avec
   add_hypothesis (au moins deux alternatives), pondere-les avec weigh_evidence (preuves pour /
   contre, poids faible 2 / modere 5 / fort 20) et classe-les avec rank_hypotheses ; tente de
   refuter l'hypothese en tete. C'est une demarche hypothetico-deductive.
5. CORRELATION — extract_iocs, croise entre artefacts, enrichis les IoCs critiques via
   virustotal_lookup. Reconstitue la timeline. Mappe les Event IDs via mitre_map_events.
6. CONFINEMENT — si une compromission ACTIVE est etablie par des preuves (beacon C2, compte
   compromis...), propose l'action avec propose_remediation. Elle sera validee ou rejetee par un
   analyste humain : tu n'executes jamais rien toi-meme et tu ne l'attends pas pour continuer.
7. RAPPORT — termine par save_report. Le rapport DOIT contenir : resume executif, deroule de
   l'attaque, timeline, IoCs, mapping MITRE ATT&CK, conclusions et recommandations de remediation.
   Les constats et hypotheses enregistres sont annexes automatiquement.

REGLES :
- Agis sans demander de permission ; tu es seul sur ce cas.
- Appuie chaque conclusion sur une preuve observee (fichier, Event ID, horodatage, IoC).
- Si un outil echoue, change d'approche (ex: parser natif si EZ Tools absents). Ne repete pas
  le meme appel en boucle.
- Ne clos pas avant d'avoir appele save_report.
- SORTIE STRUCTUREE STRICTE : chaque record_finding cite dans evidence_refs au moins un identifiant
  EXACT lu dans la sortie d'un outil (record_id EVTX, pid Volatility, line d'un log, row d'un CSV).
  N'invente jamais d'identifiant : un constat sans reference observee est rejete.

""" + shield.SYSTEM_RULE

ADVISER_PROMPT = """Tu es un reviewer DFIR senior. On te soumet le rapport d'enquete et la synthese
(constats + hypotheses) produits par un enqueteur autonome. Verifie que :
- chaque conclusion majeure est etayee par une preuve concrete ;
- les hypotheses ouvertes ont ete tranchees ou justifiees ;
- la timeline, les IoCs et le mapping MITRE sont presents ;
- des recommandations de remediation sont fournies.

Reponds STRICTEMENT par :
- "APPROVED: <une phrase>" si l'enquete est complete et etayee ;
- "GAPS: <liste des lacunes precises a combler>" s'il manque des elements importants."""


def _tool_signature(call):
    func = call.get('function', {})
    return f"{func.get('name', '')}:{func.get('arguments', '')}"


class _ShieldGuard:
    """Passe chaque sortie d'outil au bouclier avant de la remettre au LLM ;
    une injection detectee devient un constat (une fois par artefact/extrait)."""

    def __init__(self, case_dir, on_tool, log, dual=None):
        self.case_dir = case_dir
        self.on_tool = on_tool
        self.log = log
        self.dual = dual  # dualllm.Quarantine si PHOENIX_DUAL_LLM
        self.seen = set()
        self.flagged = set()
        self.detections = 0

    def view(self, step, name, arguments, result, record=True):
        clean, hits = shield.sanitize(result)
        text = shield.wrap(name, toolkit.to_json(clean, TOOL_RESULT_MAX_CHARS))
        if hits:
            self._handle(step, name, arguments or {}, hits, record)
        if self.dual is not None and self.dual.quarantined(name):
            # Double LLM : le planificateur ne recoit que la vue structuree validee
            return self.dual.planner_view(name, arguments or {}, result, text)
        return text

    def _handle(self, step, name, arguments, hits, record):
        source = arguments.get('file_path') or arguments.get('case_dir') or name
        fresh = [h for h in hits if (source, h['excerpt']) not in self.seen]
        if not fresh:
            return
        self.seen.update((source, h['excerpt']) for h in fresh)
        self.detections += len(fresh)
        excerpts = '; '.join(h['excerpt'] for h in fresh[:3])
        self.log(f"[bouclier] {len(fresh)} injection(s) de prompt neutralisee(s) dans {source}")
        if record and source not in self.flagged:
            self.flagged.add(source)
            memory.record_finding(
                self.case_dir,
                f"Tentative d'injection de prompt visant l'analyse IA dans {os.path.basename(str(source))}",
                severity='high', confidence='likely', mitre='T1562',
                evidence=f"Sortie de {name} : {excerpts}"[:1000],
                verification='verified',
                verification_note='Detection deterministe du bouclier anti-injection (texte neutralise).')
        _notify_tool(self.on_tool, step, 'prompt_injection_shield',
                     {'tool': name, 'file_path': arguments.get('file_path') or ''},
                     {'message': f"{len(fresh)} injection(s) neutralisee(s) : {excerpts}"[:500],
                      'detections': fresh[:20]})


def _notify_tool(on_tool, step, name, arguments, result):
    """Remonter un appel d'outil a l'appelant (chaine de preuve) sans jamais
    interrompre l'enquete si le callback echoue."""
    if not on_tool:
        return
    try:
        on_tool(step, name, arguments, result)
    except Exception:
        pass


def investigate(case_dir, question=None, model=None, max_steps=None, on_step=None,
                enable_adviser=True, enable_verification=True, on_tool=None, mode=None,
                max_phase_retries=None):
    """Mener une investigation autonome complete sur un dossier de cas.

    mode='phased' (defaut, PHOENIX_INVESTIGATION_MODE) : cinq phases a portes
    qualite deterministes (voir phases.py). mode='loop' : boucle agentique
    unique historique (plan + revue adviser).
    """
    mode = (mode or os.environ.get('PHOENIX_INVESTIGATION_MODE', 'phased')).strip().lower()
    if mode == 'loop':
        return _investigate_loop(case_dir, question=question, model=model,
                                 max_steps=max_steps or MAX_STEPS, on_step=on_step,
                                 enable_adviser=enable_adviser,
                                 enable_verification=enable_verification, on_tool=on_tool)
    from . import phases
    kwargs = {}
    if max_phase_retries is not None:
        kwargs['max_phase_retries'] = max_phase_retries
    return phases.investigate_phased(case_dir, question=question, model=model, max_steps=max_steps,
                                     on_step=on_step, enable_verification=enable_verification,
                                     on_tool=on_tool, **kwargs)


def _investigate_loop(case_dir, question=None, model=None, max_steps=MAX_STEPS, on_step=None,
                      enable_adviser=True, enable_verification=True, on_tool=None):
    """Boucle agentique unique (mode 'loop'), confinee au perimetre du cas."""
    # Sandboxing PAR JOB : les outils ne voient que l'arborescence de CE cas
    # (variable de contexte : isole des autres enquetes concurrentes).
    with pathpolicy.job_scope(case_dir):
        return _investigate_loop_scoped(case_dir, question=question, model=model,
                                        max_steps=max_steps, on_step=on_step,
                                        enable_adviser=enable_adviser,
                                        enable_verification=enable_verification, on_tool=on_tool)


def _investigate_loop_scoped(case_dir, question=None, model=None, max_steps=MAX_STEPS, on_step=None,
                             enable_adviser=True, enable_verification=True, on_tool=None):
    """Boucle agentique unique (mode 'loop').

    `on_tool(step, name, arguments, result)` est appele apres chaque outil
    execute (y compris en verification) : la plateforme s'en sert pour sceller
    la chaine de preuve et alimenter la console enqueteur DFIR temps reel.

    Retourne {'summary', 'report_path', 'steps', 'tool_calls', 'metrics'}.
    """
    def log(msg):
        if on_step:
            on_step(msg)

    client = CopilotClient(model=model)
    guard = _ShieldGuard(case_dir, on_tool, log, dual=dualllm.from_env(case_dir, model))
    user_prompt = f"Dossier du cas a investiguer : {case_dir}"
    if question:
        user_prompt += f"\nQuestion / contexte de l'enqueteur principal : {question}"

    messages = [
        {'role': 'system', 'content': SYSTEM_PROMPT},
        {'role': 'user', 'content': user_prompt},
    ]
    tools = toolkit.openai_tools()
    report_path = None
    executed = []
    call_counts = {}
    error_count = 0
    adviser_runs = 0
    adviser_verdict = None

    step = 0
    while step < max_steps:
        step += 1
        message = client.chat(messages, tools=tools)
        tool_calls = message.get('tool_calls') or []

        if not tool_calls:
            # L'enqueteur estime avoir termine : passe de revue adviser (bornee)
            if enable_adviser and adviser_runs < MAX_ADVISER_RUNS and report_path:
                adviser_runs += 1
                verdict = _run_adviser(client, case_dir, report_path, log, guard)
                adviser_verdict = verdict
                if verdict.startswith('GAPS') and step < max_steps:
                    messages.append({'role': 'assistant', 'content': message.get('content')})
                    messages.append({'role': 'user', 'content': (
                        "Revue qualite DFIR - lacunes a combler avant de clore :\n" + verdict +
                        "\nComplete l'analyse puis reappelle save_report avec le rapport mis a jour.")})
                    continue
            summary = message.get('content') or ''
            log(f"[{step}] Rapport final rendu.")
            return _result(summary, report_path, step, executed, client, case_dir,
                           adviser_verdict, log, enable_verification, on_tool, guard)

        messages.append({
            'role': 'assistant',
            'content': message.get('content'),
            'tool_calls': tool_calls,
        })

        for call in tool_calls:
            func = call.get('function', {})
            name = func.get('name', '')
            try:
                arguments = json.loads(func.get('arguments') or '{}')
            except json.JSONDecodeError:
                arguments = {}
            log(f"[{step}] Copilot -> {name}({toolkit.to_json(arguments, 300)})")
            result = toolkit.run_tool(name, arguments)
            executed.append({'step': step, 'tool': name, 'arguments': arguments})
            _notify_tool(on_tool, step, name, arguments, result)
            if name == 'save_report' and isinstance(result, dict) and result.get('report_path'):
                report_path = result['report_path']

            messages.append({
                'role': 'tool',
                'tool_call_id': call.get('id', ''),
                'content': guard.view(step, name, arguments, result),
            })

            # Monitoring d'execution : erreurs repetees -> reflexion
            if isinstance(result, dict) and result.get('error'):
                error_count += 1
                if error_count % ERROR_THRESHOLD == 0:
                    messages.append({'role': 'user', 'content': (
                        "Plusieurs outils ont echoue. Prends du recul : verifie les chemins via "
                        "list_artifacts, change d'outil (parsers natifs si EZ Tools indisponibles) "
                        "et poursuis avec ce qui fonctionne.")})

            # Monitoring d'execution : boucle detectee -> nudge
            sig = _tool_signature(call)
            call_counts[sig] = call_counts.get(sig, 0) + 1
            if call_counts[sig] == LOOP_THRESHOLD:
                messages.append({'role': 'user', 'content': (
                    f"Tu as deja lance '{name}' avec les memes arguments {LOOP_THRESHOLD} fois. "
                    "Change d'approche : consulte get_case_state, passe a un autre artefact ou "
                    "conclus si tu as assez d'elements.")})

    # Budget epuise : demander une conclusion sans outils
    messages.append({'role': 'user', 'content': (
        "Budget d'actions epuise. Si ce n'est pas deja fait, appelle save_report avec ton rapport, "
        "sinon rends ton resume executif final.")})
    message = client.chat(messages, tools=tools)
    for call in (message.get('tool_calls') or []):
        func = call.get('function', {})
        if func.get('name') == 'save_report':
            try:
                args = json.loads(func.get('arguments') or '{}')
                res = toolkit.run_tool('save_report', args)
                _notify_tool(on_tool, max_steps, 'save_report', args, res)
                if isinstance(res, dict) and res.get('report_path'):
                    report_path = res['report_path']
            except json.JSONDecodeError:
                pass
    return _result(message.get('content') or '', report_path, max_steps, executed, client,
                   case_dir, adviser_verdict, log, enable_verification, on_tool, guard)


def _run_verification(client, case_dir, log, max_steps=MAX_VERIFY_STEPS, on_tool=None, guard=None):
    """Passe de verification independante : re-controle chaque constat contre
    la preuve brute et statue verified/unverified/refuted (reduit les faux positifs)."""
    state = memory.get_state(case_dir)
    pending = [f for f in state['findings'] if f.get('verification', 'pending') == 'pending']
    if not pending:
        return
    log(f"[verif] Verification independante de {len(pending)} constat(s)...")
    tools = toolkit.openai_tools(names=toolkit.READONLY_TOOLS)
    guard = guard or _ShieldGuard(case_dir, on_tool, log)
    findings_brief = [{'id': f['id'], 'title': f['title'], 'severity': f['severity'],
                       'evidence': f['evidence'], 'mitre': f['mitre'],
                       'evidence_refs': f.get('evidence_refs') or []} for f in state['findings']]
    # Les constats citent des extraits d'artefacts : eux aussi passent au bouclier
    findings_brief, _hits = shield.sanitize(findings_brief)
    messages = [
        {'role': 'system', 'content': VERIFIER_PROMPT},
        {'role': 'user', 'content': (
            f"Dossier du cas : {case_dir}\nConstats a verifier :\n"
            f"{toolkit.to_json(findings_brief, 8000)}")},
    ]
    for _ in range(max_steps):
        message = client.chat(messages, tools=tools)
        tool_calls = message.get('tool_calls') or []
        if not tool_calls:
            break
        messages.append({'role': 'assistant', 'content': message.get('content'),
                         'tool_calls': tool_calls})
        for call in tool_calls:
            func = call.get('function', {})
            name = func.get('name', '')
            try:
                arguments = json.loads(func.get('arguments') or '{}')
            except json.JSONDecodeError:
                arguments = {}
            # Securite : la passe de verification est strictement lecture seule
            if name not in toolkit.READONLY_TOOLS:
                result = {'error': f"Outil '{name}' non autorise en phase de verification"}
            else:
                result = toolkit.run_tool(name, arguments)
                _notify_tool(on_tool, 'verif', name, arguments, result)
            if name == 'verify_finding' and isinstance(result, dict) and result.get('verified'):
                v = result['verified']
                log(f"[verif] Constat #{v['id']} : {v['verification']}")
            messages.append({'role': 'tool', 'tool_call_id': call.get('id', ''),
                             'content': guard.view('verif', name, arguments, result, record=False)})
    # Les constats non statues restent 'unverified' (prudence)
    remaining = memory.get_state(case_dir)['findings']
    for f in remaining:
        if f.get('verification', 'pending') == 'pending':
            memory.verify_finding(case_dir, f['id'], 'unverified',
                                  'Non reproduit durant la passe de verification.')


def _run_adviser(client, case_dir, report_path, log, guard=None):
    """Passe de revue critique du rapport (verifie completude et etayage)."""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report = f.read()
    except OSError:
        return 'APPROVED: rapport enregistre.'
    state = memory.get_state(case_dir)
    log('[adviser] Revue qualite du rapport...')
    clean_report, _h1 = shield.scan_text(report[:12000])
    clean_state, _h2 = shield.sanitize(state)
    verdict = client.chat([
        {'role': 'system', 'content': ADVISER_PROMPT + '\n\n' + shield.SYSTEM_RULE},
        {'role': 'user', 'content': (
            shield.wrap('rapport', clean_report) + '\n\n'
            + shield.wrap('synthese', toolkit.to_json(clean_state, 4000)))},
    ]) or {}
    text = (verdict.get('content') or 'APPROVED: revue par defaut.').strip()
    log(f"[adviser] {text[:200]}")
    return text


def _result(summary, report_path, steps, executed, client, case_dir, adviser_verdict,
            log=None, enable_verification=True, on_tool=None, guard=None):
    # Verification independante des constats avant de finaliser
    if enable_verification:
        try:
            _run_verification(client, case_dir, log or (lambda _m: None), on_tool=on_tool,
                              guard=guard)
            # Rafraichir l'annexe du rapport pour refleter les statuts de verification
            if report_path:
                toolkit.refresh_report_annex(report_path, case_dir)
        except Exception:
            pass
    state = memory.get_state(case_dir)
    result = {
        'summary': summary,
        'report_path': report_path,
        'steps': steps,
        'tool_calls': executed,
        'metrics': {
            'tools_executed': len(executed),
            'llm_calls': client.usage['calls'],
            'total_tokens': client.usage['total_tokens'],
            'prompt_tokens': client.usage['prompt_tokens'],
            'completion_tokens': client.usage['completion_tokens'],
            'findings': state['summary']['findings'],
            'findings_critical_or_high': state['summary']['critical_or_high'],
            'findings_verified': state['summary']['findings_verified'],
            'findings_unverified': state['summary']['findings_unverified'],
            'hypotheses_confirmed': state['summary']['hypotheses_confirmed'],
            'remediations_pending': state['summary']['remediations_pending'],
            'llm_provider': getattr(client, 'provider', 'github'),
            'prompt_injections_neutralized': guard.detections if guard else 0,
            'adviser_verdict': adviser_verdict,
        },
    }
    dual = getattr(guard, 'dual', None) if guard else None
    if dual is not None:
        # Cout des deux LLM : total = planificateur + extracteur en quarantaine
        dual_metrics = dual.metrics(client.usage)
        result['metrics']['dual_llm'] = dual_metrics
        result['metrics']['total_tokens'] = (dual_metrics['planner_tokens']
                                             + dual_metrics['extractor_tokens'])
    return result
