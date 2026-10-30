"""Investigation memory tools: plan, findings, hypotheses, verification, remediation.

Registered in the single tool registry of ``toolkit``, which re-exports every
name: callers keep using ``toolkit.<name>``.
"""

from . import contracts, memory  # noqa: E402
from .toolkit import REF_KINDS, _schema, strict_evidence, tool, validate_refs  # noqa: E402

# ============================================================================
# Memoire d'enquete (plan, findings, hypotheses)
# ============================================================================

@tool(
    'set_investigation_plan',
    "Definir le plan d'investigation : decomposer le cas en 3 a 7 etapes courtes et actionnables "
    "AVANT de commencer la collecte. A appeler tot dans l'enquete pour rester focalise.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'steps': {'type': 'array', 'items': {'type': 'string'},
                  'description': "Liste ordonnee de 3 a 7 etapes d'investigation"},
    }, ['case_dir', 'steps']),
)
def set_investigation_plan(case_dir, steps):
    return memory.set_plan(case_dir, steps)


@tool(
    'complete_plan_step',
    "Marquer une etape du plan comme terminee (avec une note de resultat). Permet de suivre "
    "l'avancement et d'eviter les oublis.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'step_index': {'type': 'integer', 'description': "Numero de l'etape (1 = premiere)"},
        'note': {'type': 'string', 'description': 'Resultat / conclusion de cette etape'},
    }, ['case_dir', 'step_index']),
)
def complete_plan_step(case_dir, step_index, note=''):
    return memory.complete_step(case_dir, step_index, note)


@tool(
    'record_finding',
    "Consigner un constat d'enquete lie a une preuve : chaque anomalie ou element probant "
    "(alerte Sigma, IoC malveillant, execution suspecte, effacement de logs...). A appeler des "
    "qu'un element significatif est etabli, pour construire le rapport au fil de l'eau. "
    "SORTIE STRICTE : evidence_refs doit citer au moins un identifiant EXACT extrait par un outil "
    "(record_id d'un EVTX via parse_evtx/sigma_scan/run_hayabusa, pid via run_volatility, line via "
    "parse_log_file, row via parse_csv, inode via disk_list_files/disk_timeline) ; un constat sans "
    "reference observee est rejete.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'title': {'type': 'string', 'description': 'Constat en une phrase'},
        'severity': {'type': 'string', 'enum': list(memory.SEVERITIES), 'description': 'Severite'},
        'evidence': {'type': 'string', 'description': 'Preuve : fichier, Event ID, horodatage, IoC...'},
        'mitre': {'type': 'string', 'description': "Technique MITRE ATT&CK (ex: T1110)"},
        'confidence': {'type': 'string', 'enum': list(memory.CONFIDENCES), 'description': 'Niveau de confiance'},
        'evidence_refs': {
            'type': 'array',
            'description': "Identifiants exacts extraits par les outils (au moins un)",
            'items': {
                'type': 'object',
                'properties': {
                    'artifact': {'type': 'string', 'description': "Chemin ou nom de l'artefact"},
                    'kind': {'type': 'string', 'enum': list(REF_KINDS)},
                    'value': {'type': ['integer', 'string'],
                              'description': 'RecordID, PID, numero de ligne, inode (ex: 128-128-1)...'},
                },
                'required': ['artifact', 'kind', 'value'],
                'additionalProperties': False,
            },
        },
    }, ['case_dir', 'title', 'evidence_refs']),
)
def record_finding(case_dir, title, severity='info', evidence='', mitre='', confidence='possible',
                   evidence_refs=None):
    # Contract 'finding' (contracts.Finding): the LLM gets the exact errors to fix
    _model, problems = contracts.validate('finding', {
        'title': title, 'severity': severity, 'evidence': evidence or '', 'mitre': mitre or '',
        'confidence': confidence, 'evidence_refs': list(evidence_refs or [])})
    if problems:
        return {'error': "Constat rejete (contrat 'finding') : corriger puis rappeler record_finding.\n"
                         + problems}
    valid, invalid = validate_refs(evidence_refs, case_dir)
    if strict_evidence() and not valid:
        return {
            'error': ("Constat rejete (sortie structuree stricte) : evidence_refs doit citer au moins "
                      "un record_id / pid / line / row EXACT present dans la sortie d'un outil "
                      "deterministe sur cet artefact. Relance l'outil adequat puis cite l'identifiant."),
            'invalid_refs': invalid,
        }
    result = memory.record_finding(case_dir, title, severity, evidence, mitre, confidence,
                                   evidence_refs=valid)
    if invalid:
        result['ignored_refs'] = invalid
    return result


@tool(
    'set_hypothesis',
    "Formuler ou mettre a jour une hypothese d'enquete (DFIR = demarche hypothetico-deductive). "
    "Ex: 'Mouvement lateral via PsExec'. Reappeler avec le meme texte et status 'confirmed'/'refuted' "
    "quand les preuves tranchent.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'hypothesis': {'type': 'string', 'description': "Hypothese (identifiant = son texte)"},
        'status': {'type': 'string', 'enum': list(memory.HYPOTHESIS_STATUSES), 'description': 'Statut'},
        'rationale': {'type': 'string', 'description': 'Preuves confirmant / refutant'},
    }, ['case_dir', 'hypothesis']),
)
def set_hypothesis(case_dir, hypothesis, status='open', rationale=''):
    return memory.set_hypothesis(case_dir, hypothesis, status, rationale)


@tool(
    'get_case_state',
    "Restituer l'etat accumule du cas : plan et avancement, tous les constats (findings) et "
    "hypotheses. A consulter pour se resituer sur un gros cas ou avant de rediger le rapport.",
    _schema({'case_dir': {'type': 'string', 'description': 'Dossier du cas'}}, ['case_dir']),
)
def get_case_state(case_dir):
    return memory.get_state(case_dir)


@tool(
    'verify_finding',
    "Consigner le resultat d'une VERIFICATION INDEPENDANTE d'un constat : apres avoir re-examine "
    "la preuve brute a la source, statuer 'verified' (la preuve confirme), 'unverified' "
    "(impossible a reproduire) ou 'refuted' (la preuve contredit). Reduit les faux positifs.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'finding_id': {'type': 'integer', 'description': 'Numero du constat a verifier'},
        'verdict': {'type': 'string', 'enum': list(memory.VERIFICATION_STATUSES),
                    'description': 'Resultat de la verification'},
        'note': {'type': 'string', 'description': 'Preuve re-examinee justifiant le verdict'},
    }, ['case_dir', 'finding_id', 'verdict']),
)
def verify_finding(case_dir, finding_id, verdict, note=''):
    return memory.verify_finding(case_dir, finding_id, verdict, note)


@tool(
    'propose_remediation',
    "Proposer une action de confinement / remediation (isolement d'hote, kill de processus, blocage "
    "d'IP, desactivation de compte...) soumise a VALIDATION HUMAINE (Human-in-the-Loop). L'action "
    "n'est JAMAIS executee automatiquement : un analyste l'approuve ou la rejette depuis la console "
    "enqueteur DFIR. A utiliser quand une compromission active est etablie par des preuves.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'target_host': {'type': 'string', 'description': 'Hote cible (nom ou IP)'},
        'command': {'type': 'string', 'description': "Commande / action de remediation proposee"},
        'reason': {'type': 'string', 'description': 'Justification appuyee sur les preuves'},
        'mitre': {'type': 'string', 'description': 'Technique MITRE ATT&CK concernee'},
        'severity': {'type': 'string', 'enum': list(memory.SEVERITIES), 'description': 'Severite'},
    }, ['case_dir', 'target_host', 'command', 'reason']),
)
def propose_remediation(case_dir, target_host, command, reason, mitre='', severity='high'):
    return memory.propose_remediation(case_dir, target_host, command, reason, mitre, severity)
