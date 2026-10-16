"""Hypotheses concurrentes a confiance ponderee par les preuves.

Outils : add_hypothesis (alternatives regroupees par question), weigh_evidence
(preuve pour / contre, rapport de vraisemblance), rank_hypotheses (classement
par probabilite a posteriori, questions non tranchees signalees). L'outil
historique set_hypothesis est etendu (question, techniques, prior optionnels)
sans changer son comportement par defaut. Le calcul (log-cote) est dans
memory.py.
"""

from .. import memory, toolkit

AGENT = ('reasoning', 'Agent Raisonnement & hypotheses concurrentes')
READONLY = ('rank_hypotheses',)
PHASE_TOOLS = {
    'correlation': ('add_hypothesis', 'weigh_evidence', 'rank_hypotheses'),
    'contre_analyse': ('add_hypothesis', 'weigh_evidence', 'rank_hypotheses'),
    'rapport': ('rank_hypotheses',),
}

_WEIGHT_DOC = ("Poids = rapport de vraisemblance : 'neutral' 1 (examinee, non discriminante), "
               "'weak' 2, 'moderate' 5, 'strong' 20, ou un nombre dans [1, 100]. "
               "Une preuve 'refutes' divise la cote par ce rapport (1/x).")

_REF_SCHEMA = {
    'type': 'object',
    'description': "Reference de preuve produite par un outil (validee contre l'index du cas)",
    'properties': {
        'artifact': {'type': 'string'},
        'kind': {'type': 'string', 'enum': list(toolkit.REF_KINDS)},
        'value': {'type': ['integer', 'string']},
    },
    'required': ['artifact', 'kind', 'value'],
}


@toolkit.tool(
    'set_hypothesis',
    "Formuler ou mettre a jour une hypothese d'enquete (DFIR = demarche hypothetico-deductive). "
    "Ex: 'Mouvement lateral via PsExec'. Reappeler avec le meme texte et status 'confirmed'/'refuted' "
    "quand les preuves tranchent. Pour des hypotheses CONCURRENTES ponderees par les preuves, "
    "preferer add_hypothesis + weigh_evidence.",
    {'type': 'object', 'properties': {
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'hypothesis': {'type': 'string', 'description': "Hypothese (identifiant = son texte)"},
        'status': {'type': 'string', 'enum': list(memory.HYPOTHESIS_STATUSES), 'description': 'Statut'},
        'rationale': {'type': 'string', 'description': 'Preuves confirmant / refutant'},
        'question': {'type': 'string', 'description': "Optionnel : question a laquelle l'hypothese repond"},
        'techniques': {'type': 'array', 'items': {'type': 'string'},
                       'description': 'Optionnel : techniques ATT&CK (ex: T1566.001)'},
        'prior': {'type': 'number', 'description': 'Optionnel : probabilite a priori dans ]0, 1['},
    }, 'required': ['case_dir', 'hypothesis']},
)
def set_hypothesis(case_dir, hypothesis, status='open', rationale='', question=None,
                   techniques=None, prior=None):
    return memory.set_hypothesis(case_dir, hypothesis, status, rationale, question=question,
                                 techniques=techniques, prior=prior)


@toolkit.tool(
    'add_hypothesis',
    "Poser une hypothese CONCURRENTE pour une question d'enquete. Appeler au moins deux fois par "
    "question avec des alternatives exclusives (ex: question 'acces initial' : 'Hameconnage avec "
    "piece jointe' T1566.001, puis 'RDP expose sur Internet' T1133). Le statut est ensuite calcule "
    "par weigh_evidence.",
    {'type': 'object', 'properties': {
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'question': {'type': 'string', 'description': "Question (ex: 'acces initial', 'persistance')"},
        'statement': {'type': 'string', 'description': "Enonce de l'hypothese"},
        'techniques': {'type': 'array', 'items': {'type': 'string'},
                       'description': 'Techniques ATT&CK associees'},
        'prior': {'type': 'number', 'description': 'Probabilite a priori dans ]0, 1[ (defaut 0.5)'},
        'rationale': {'type': 'string', 'description': 'Pourquoi cette hypothese est plausible'},
    }, 'required': ['case_dir', 'question', 'statement']},
)
def add_hypothesis(case_dir, question, statement, techniques=None, prior=None, rationale=''):
    return memory.add_hypothesis(case_dir, question, statement, techniques=techniques, prior=prior,
                                 rationale=rationale)


@toolkit.tool(
    'weigh_evidence',
    "Rattacher une preuve a une hypothese, dans un sens ('supports' ou 'refutes'), avec un poids. "
    "La preuve cite un constat EXISTANT (finding_id) ou une reference produite par un outil (ref : "
    "artefact + record_id/pid/line/row/inode, validee). " + _WEIGHT_DOC +
    " Le posterior est mis a jour en log-cote et le classement de la question est renvoye. En "
    "contre-analyse, tenter de REFUTER l'hypothese en tete (direction 'refutes' ; 'neutral' si "
    "aucune preuve contraire n'est trouvee).",
    {'type': 'object', 'properties': {
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'hypothesis_id': {'type': 'integer', 'description': "Numero de l'hypothese"},
        'direction': {'type': 'string', 'enum': list(memory.EVIDENCE_DIRECTIONS)},
        'weight': {'type': ['string', 'number'],
                   'description': "neutral / weak / moderate / strong, ou rapport numerique"},
        'finding_id': {'type': 'integer', 'description': 'Constat existant cite comme preuve'},
        'ref': _REF_SCHEMA,
        'note': {'type': 'string', 'description': 'Pourquoi cette preuve pese dans ce sens'},
    }, 'required': ['case_dir', 'hypothesis_id', 'direction', 'weight']},
)
def weigh_evidence(case_dir, hypothesis_id, direction, weight, finding_id=None, ref=None, note=''):
    clean_ref = None
    if ref:
        valid, invalid = toolkit.validate_refs([ref], case_dir)
        if not valid:
            return {'error': ("Reference rejetee : elle doit citer un identifiant EXACT produit par un "
                              "outil sur cet artefact (ou citer finding_id)."), 'invalid_refs': invalid}
        clean_ref = valid[0]
    return memory.weigh_evidence(case_dir, hypothesis_id, direction, weight, finding_id=finding_id,
                                 ref=clean_ref, note=note)


@toolkit.tool(
    'rank_hypotheses',
    "Classer les hypotheses concurrentes de chaque question par probabilite a posteriori. Une "
    "question est signalee NON TRANCHEE (inconclusive) si les deux premieres hypotheses sont a moins "
    "de la marge (defaut 0.1).",
    {'type': 'object', 'properties': {
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'question': {'type': 'string', 'description': 'Limiter a une question'},
        'margin': {'type': 'number', 'description': 'Marge de departage (defaut 0.1)'},
    }, 'required': ['case_dir']},
)
def rank_hypotheses(case_dir, question=None, margin=memory.HYPOTHESIS_MARGIN):
    return memory.rank_hypotheses(case_dir, question=question, margin=margin)
