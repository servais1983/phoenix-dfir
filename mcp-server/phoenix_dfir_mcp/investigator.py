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
"""

import json

from . import memory, pathpolicy, toolkit
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
statues, termine (sans autre message)."""

SYSTEM_PROMPT = """Tu es un enqueteur DFIR (Digital Forensics & Incident Response) senior et autonome.
Tu disposes d'une boite a outils forensique complete (parsers EVTX/CSV/JSON/logs/Prefetch/LNK/
navigateurs, extraction d'IoCs, regles Sigma, mapping MITRE ATT&CK, VirusTotal, outils Eric
Zimmermann) ET d'une memoire d'enquete (plan, constats, hypotheses).

Ta mission : resoudre le cas SEUL, methodiquement et rapidement.

METHODOLOGIE OBLIGATOIRE :
1. PLAN — commence par list_artifacts, puis set_investigation_plan (3-7 etapes). Marque chaque
   etape terminee avec complete_plan_step.
2. COLLECTE — analyse CHAQUE artefact pertinent avec l'outil adapte a son format. Verifie
   zimmermann_status ; prefere les EZ Tools s'ils sont dispo, sinon les parsers natifs.
3. DETECTION — lance sigma_scan sur chaque EVTX.
4. MEMOIRE — des qu'un element probant est etabli, appelle record_finding (severite, preuve,
   technique MITRE, confiance). Formule tes pistes avec set_hypothesis et mets-les a jour
   (confirmed/refuted) quand les preuves tranchent. C'est une demarche hypothetico-deductive.
5. CORRELATION — extract_iocs, croise entre artefacts, enrichis les IoCs critiques via
   virustotal_lookup. Reconstitue la timeline. Mappe les Event IDs via mitre_map_events.
6. RAPPORT — termine par save_report. Le rapport DOIT contenir : resume executif, deroule de
   l'attaque, timeline, IoCs, mapping MITRE ATT&CK, conclusions et recommandations de remediation.
   Les constats et hypotheses enregistres sont annexes automatiquement.

REGLES :
- Agis sans demander de permission ; tu es seul sur ce cas.
- Appuie chaque conclusion sur une preuve observee (fichier, Event ID, horodatage, IoC).
- Si un outil echoue, change d'approche (ex: parser natif si EZ Tools absents). Ne repete pas
  le meme appel en boucle.
- Ne clos pas avant d'avoir appele save_report."""

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


def investigate(case_dir, question=None, model=None, max_steps=MAX_STEPS, on_step=None,
                enable_adviser=True, enable_verification=True):
    """Mener une investigation autonome complete sur un dossier de cas.

    Retourne {'summary', 'report_path', 'steps', 'tool_calls', 'metrics'}.
    """
    def log(msg):
        if on_step:
            on_step(msg)

    # Sandboxing : confiner les outils a l'arborescence du cas
    pathpolicy.add_root(case_dir)

    client = CopilotClient(model=model)
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
                verdict = _run_adviser(client, case_dir, report_path, log)
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
                           adviser_verdict, log, enable_verification)

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
            if name == 'save_report' and isinstance(result, dict) and result.get('report_path'):
                report_path = result['report_path']

            messages.append({
                'role': 'tool',
                'tool_call_id': call.get('id', ''),
                'content': toolkit.to_json(result, TOOL_RESULT_MAX_CHARS),
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
                res = toolkit.run_tool('save_report', json.loads(func.get('arguments') or '{}'))
                if isinstance(res, dict) and res.get('report_path'):
                    report_path = res['report_path']
            except json.JSONDecodeError:
                pass
    return _result(message.get('content') or '', report_path, max_steps, executed, client,
                   case_dir, adviser_verdict, log, enable_verification)


def _run_verification(client, case_dir, log, max_steps=MAX_VERIFY_STEPS):
    """Passe de verification independante : re-controle chaque constat contre
    la preuve brute et statue verified/unverified/refuted (reduit les faux positifs)."""
    state = memory.get_state(case_dir)
    pending = [f for f in state['findings'] if f.get('verification', 'pending') == 'pending']
    if not pending:
        return
    log(f"[verif] Verification independante de {len(pending)} constat(s)...")
    tools = toolkit.openai_tools(names=toolkit.READONLY_TOOLS)
    findings_brief = [{'id': f['id'], 'title': f['title'], 'severity': f['severity'],
                       'evidence': f['evidence'], 'mitre': f['mitre']} for f in state['findings']]
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
            if name == 'verify_finding' and isinstance(result, dict) and result.get('verified'):
                v = result['verified']
                log(f"[verif] Constat #{v['id']} : {v['verification']}")
            messages.append({'role': 'tool', 'tool_call_id': call.get('id', ''),
                             'content': toolkit.to_json(result, TOOL_RESULT_MAX_CHARS)})
    # Les constats non statues restent 'unverified' (prudence)
    remaining = memory.get_state(case_dir)['findings']
    for f in remaining:
        if f.get('verification', 'pending') == 'pending':
            memory.verify_finding(case_dir, f['id'], 'unverified',
                                  'Non reproduit durant la passe de verification.')


def _run_adviser(client, case_dir, report_path, log):
    """Passe de revue critique du rapport (verifie completude et etayage)."""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report = f.read()
    except OSError:
        return 'APPROVED: rapport enregistre.'
    state = memory.get_state(case_dir)
    log('[adviser] Revue qualite du rapport...')
    verdict = client.chat([
        {'role': 'system', 'content': ADVISER_PROMPT},
        {'role': 'user', 'content': (
            f"RAPPORT :\n{report[:12000]}\n\nSYNTHESE :\n{toolkit.to_json(state, 4000)}")},
    ]) or {}
    text = (verdict.get('content') or 'APPROVED: revue par defaut.').strip()
    log(f"[adviser] {text[:200]}")
    return text


def _result(summary, report_path, steps, executed, client, case_dir, adviser_verdict,
            log=None, enable_verification=True):
    # Verification independante des constats avant de finaliser
    if enable_verification:
        try:
            _run_verification(client, case_dir, log or (lambda _m: None))
            # Rafraichir l'annexe du rapport pour refleter les statuts de verification
            if report_path:
                toolkit.refresh_report_annex(report_path, case_dir)
        except Exception:
            pass
    state = memory.get_state(case_dir)
    return {
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
            'adviser_verdict': adviser_verdict,
        },
    }
