"""Enqueteur DFIR autonome pilote par GitHub Copilot.

Boucle agentique : GitHub Copilot (API GitHub Models) recoit la boite a
outils DFIR complete en function calling, choisit lui-meme les outils a
executer (inventaire, parsing, Sigma, IoCs, enrichissement, Zimmermann...),
correle les resultats et termine en redigeant le rapport d'enquete.
"""

import json

from . import toolkit
from .copilot import CopilotClient

MAX_STEPS = 40
TOOL_RESULT_MAX_CHARS = 20000

SYSTEM_PROMPT = """Tu es un enqueteur DFIR (Digital Forensics & Incident Response) senior et autonome.
Tu disposes d'une boite a outils forensique complete (parsers EVTX/CSV/JSON/logs/Prefetch/LNK/navigateurs,
extraction d'IoCs, regles Sigma, mapping MITRE ATT&CK, VirusTotal, outils Eric Zimmermann).

Ta mission : resoudre le cas SEUL, methodiquement et rapidement.

METHODOLOGIE OBLIGATOIRE :
1. INVENTAIRE — commence TOUJOURS par list_artifacts sur le dossier du cas.
2. COLLECTE — analyse CHAQUE artefact pertinent avec l'outil adapte a son format
   (peu importe le format : EVTX, CSV, JSON, logs, Prefetch, LNK, SQLite...).
   Verifie zimmermann_status ; si les EZ Tools sont disponibles, prefere-les pour les
   formats qu'ils couvrent, sinon utilise les parsers natifs.
3. DETECTION — lance sigma_scan sur chaque EVTX ; note chaque alerte (niveau, tactique, technique).
4. CORRELATION — extrais les IoCs (extract_iocs), croise-les entre artefacts,
   enrichis les plus critiques via virustotal_lookup (si configure).
5. CHRONOLOGIE — reconstruis la timeline de l'attaque a partir des horodatages.
6. QUALIFICATION — mappe les evenements sur MITRE ATT&CK (mitre_map_events),
   qualifie le type d'attaque et son etendue.
7. RAPPORT — termine OBLIGATOIREMENT par save_report avec un rapport Markdown complet :
   resume executif, artefacts analyses, alertes Sigma, IoCs (tableau), timeline detaillee,
   mapping MITRE ATT&CK, conclusions et recommandations de remediation.

REGLES :
- Agis sans demander de permission ; tu es seul sur ce cas.
- Appuie chaque conclusion sur des preuves observees (fichier, event ID, horodatage).
- Si un outil echoue, utilise une alternative (ex: parser natif si EZ Tools absents).
- Ne t'arrete pas avant d'avoir sauvegarde le rapport via save_report.
- Apres save_report, rends un resume executif concis en francais."""


def investigate(case_dir, question=None, model=None, max_steps=MAX_STEPS, on_step=None):
    """Mener une investigation autonome complete sur un dossier de cas.

    Retourne {'summary', 'report_path', 'steps', 'tool_calls'}.
    """
    def log(msg):
        if on_step:
            on_step(msg)

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

    for step in range(1, max_steps + 1):
        message = client.chat(messages, tools=tools)
        tool_calls = message.get('tool_calls') or []

        if not tool_calls:
            summary = message.get('content') or ''
            log(f"[{step}] Rapport final rendu.")
            return {
                'summary': summary,
                'report_path': report_path,
                'steps': step,
                'tool_calls': executed,
            }

        # Rejouer le message assistant tel quel puis executer chaque outil demande
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

    # Budget epuise : demander une conclusion sans outils
    messages.append({
        'role': 'user',
        'content': ("Budget d'actions epuise. Rends immediatement ton resume executif final "
                    "a partir des elements deja collectes."),
    })
    message = client.chat(messages)
    return {
        'summary': message.get('content') or '',
        'report_path': report_path,
        'steps': max_steps,
        'tool_calls': executed,
    }
