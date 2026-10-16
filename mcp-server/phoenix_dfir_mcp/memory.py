"""Memoire d'enquete structuree.

Chaque cas possede un fichier `case_state.json` dans son dossier, qui
accumule au fil de l'investigation :
- le PLAN (working memory) : les etapes decomposees et leur avancement ;
- les FINDINGS (episodic memory) : constats horodates, lies a des preuves,
  avec severite / confiance / technique MITRE ;
- les HYPOTHESES : pistes formees, confirmees ou refutees avec justification ;
  hypotheses CONCURRENTES regroupees par question (ex. 'acces initial' :
  A hameconnage, B RDP expose), chacune avec une probabilite a priori et une
  probabilite a posteriori mise a jour par les preuves (voir plus bas) ;
- les REMEDIATIONS proposees : actions de confinement soumises a validation
  humaine (Human-in-the-Loop) — jamais executees par l'enqueteur.

Cette memoire permet a l'enqueteur de traiter de gros cas multi-artefacts
sans perdre le fil quand la fenetre de contexte se remplit, et de produire
un rapport riche et trace aux preuves. Le stockage fichier (JSON) est simple,
sans dependance, et testable — un seul job ecrit un cas a la fois.
"""

import datetime
import json
import math
import os
import re

STATE_FILENAME = 'case_state.json'
# Produits du raisonnement ecrits dans le dossier du cas (annexes au rapport)
GRAPH_FILENAME = 'entity_graph.json'
DETECTIONS_DIRNAME = 'detections'
DETECTIONS_INDEX = 'phoenix_detection_index.json'

SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
CONFIDENCES = ('confirmed', 'likely', 'possible')
# 'confirmed' : statut historique (equivalent de 'supported'), conserve pour
# les case_state.json existants et l'outil set_hypothesis.
HYPOTHESIS_STATUSES = ('open', 'supported', 'refuted', 'inconclusive', 'confirmed')
SUPPORTED_STATUSES = ('supported', 'confirmed')
VERIFICATION_STATUSES = ('verified', 'unverified', 'refuted')
REMEDIATION_STATUSES = ('pending_approval', 'approved', 'rejected')
CHALLENGE_VERDICTS = ('upheld', 'downgraded', 'refuted')


def _state_path(case_dir):
    return os.path.join(case_dir, STATE_FILENAME)


def load_state(case_dir):
    path = _state_path(case_dir)
    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                state = json.load(f)
        except (json.JSONDecodeError, OSError):
            state = None
        if isinstance(state, dict):
            for key in ('plan', 'findings', 'hypotheses', 'remediations'):
                state.setdefault(key, [])
            state['hypotheses'] = [_normalize_hypothesis(h) for h in state['hypotheses']
                                   if isinstance(h, dict)]
            return state
    return {'plan': [], 'findings': [], 'hypotheses': [], 'remediations': []}


def save_state(case_dir, state):
    with open(_state_path(case_dir), 'w', encoding='utf-8') as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    return state


def _now():
    return datetime.datetime.now().isoformat(timespec='seconds')


def set_plan(case_dir, steps):
    """Enregistrer le plan d'investigation (liste d'etapes courtes)."""
    if not isinstance(steps, list) or not steps:
        return {'error': "steps doit etre une liste non vide d'etapes"}
    state = load_state(case_dir)
    state['plan'] = [{'step': str(s), 'status': 'pending', 'note': ''} for s in steps]
    save_state(case_dir, state)
    return {'plan': state['plan'], 'total_steps': len(state['plan'])}


def complete_step(case_dir, step_index, note=''):
    """Marquer une etape du plan comme terminee (index base 1)."""
    state = load_state(case_dir)
    plan = state.get('plan', [])
    if not plan:
        return {'error': "Aucun plan defini : appelez set_investigation_plan d'abord."}
    if not isinstance(step_index, int) or step_index < 1 or step_index > len(plan):
        return {'error': f"step_index invalide (1..{len(plan)})"}
    plan[step_index - 1]['status'] = 'done'
    plan[step_index - 1]['note'] = str(note)[:500]
    save_state(case_dir, state)
    remaining = sum(1 for s in plan if s['status'] != 'done')
    return {'plan': plan, 'remaining_steps': remaining}


def record_finding(case_dir, title, severity='info', evidence='', mitre='', confidence='possible',
                   evidence_refs=None, verification='pending', verification_note=''):
    """Enregistrer un constat d'enquete lie a une preuve."""
    if not title:
        return {'error': 'title requis'}
    severity = severity if severity in SEVERITIES else 'info'
    confidence = confidence if confidence in CONFIDENCES else 'possible'
    state = load_state(case_dir)
    finding = {
        'id': len(state['findings']) + 1,
        'title': str(title)[:300],
        'severity': severity,
        'confidence': confidence,
        'evidence': str(evidence)[:1000],
        'mitre': str(mitre)[:120],
        'evidence_refs': list(evidence_refs or [])[:20],
        'verification': verification if verification in VERIFICATION_STATUSES else 'pending',
        'verification_note': str(verification_note)[:600],
        'ts': _now(),
    }
    state['findings'].append(finding)
    save_state(case_dir, state)
    return {'recorded': finding, 'total_findings': len(state['findings'])}


def verify_finding(case_dir, finding_id, verdict, note=''):
    """Consigner le resultat d'une verification independante d'un constat."""
    verdict = verdict if verdict in VERIFICATION_STATUSES else 'unverified'
    state = load_state(case_dir)
    for f in state['findings']:
        if f['id'] == finding_id:
            f['verification'] = verdict
            f['verification_note'] = str(note)[:600]
            save_state(case_dir, state)
            return {'verified': {'id': finding_id, 'verification': verdict}}
    return {'error': f"Constat #{finding_id} introuvable"}


def propose_remediation(case_dir, target_host, command, reason, mitre='', severity='high'):
    """Consigner une action de remediation proposee, en attente de validation humaine."""
    if not target_host or not command or not reason:
        return {'error': 'target_host, command et reason sont requis'}
    severity = severity if severity in SEVERITIES else 'high'
    state = load_state(case_dir)
    remediations = state.setdefault('remediations', [])
    entry = {
        'id': len(remediations) + 1,
        'target_host': str(target_host)[:255],
        'command': str(command)[:1000],
        'reason': str(reason)[:1000],
        'mitre': str(mitre)[:120],
        'severity': severity,
        'status': 'pending_approval',
        'ts': _now(),
    }
    remediations.append(entry)
    save_state(case_dir, state)
    return {
        'proposed': entry,
        'status': 'pending_approval',
        'message': ("Action soumise a validation humaine (Human-in-the-Loop). Elle N'EST PAS "
                    "executee : un analyste doit l'approuver. Poursuis l'enquete."),
    }


def challenge_finding(case_dir, finding_id, alternative, verdict, rationale, new_severity=None):
    """Contre-analyse d'un constat : hypothese alternative testee et verdict.

    upheld     : le constat resiste a l'hypothese alternative ;
    downgraded : il est affaibli (severite / confiance revues a la baisse) ;
    refuted    : l'hypothese alternative l'emporte (constat ramene a 'info').
    """
    if verdict not in CHALLENGE_VERDICTS:
        return {'error': f'verdict parmi {list(CHALLENGE_VERDICTS)}'}
    if not alternative or not rationale:
        return {'error': 'alternative et rationale sont requis'}
    state = load_state(case_dir)
    for f in state['findings']:
        if f['id'] == finding_id:
            f['challenge'] = {'alternative': str(alternative)[:500], 'verdict': verdict,
                              'rationale': str(rationale)[:1000], 'ts': _now()}
            if verdict == 'downgraded':
                if new_severity in SEVERITIES and SEVERITIES.index(new_severity) > SEVERITIES.index(f['severity']):
                    f['severity'] = new_severity
                if f['confidence'] == 'confirmed':
                    f['confidence'] = 'likely'
            elif verdict == 'refuted':
                f['severity'] = 'info'
                f['confidence'] = 'possible'
            save_state(case_dir, state)
            return {'challenged': {'id': finding_id, 'verdict': verdict, 'severity': f['severity'],
                                   'confidence': f['confidence']}}
    return {'error': f'Constat #{finding_id} introuvable'}


def declare_no_incident(case_dir, rationale):
    """Conclure explicitement a l'absence d'incident (cas sain), avec justification."""
    if not rationale:
        return {'error': 'rationale requise'}
    state = load_state(case_dir)
    state['conclusion'] = {'no_incident': True, 'rationale': str(rationale)[:1500], 'ts': _now()}
    save_state(case_dir, state)
    return {'conclusion': state['conclusion']}


def mark_audit(case_dir, audit_name, summary):
    state = load_state(case_dir)
    state.setdefault('audits', {})[audit_name] = {'ts': _now(), 'summary': summary}
    save_state(case_dir, state)


def set_remediation_status(case_dir, remediation_id, status):
    """Refleter la decision de l'analyste dans la memoire du cas."""
    if status not in REMEDIATION_STATUSES:
        return {'error': f'statut invalide: {status}'}
    state = load_state(case_dir)
    for r in state.get('remediations', []):
        if r['id'] == remediation_id:
            r['status'] = status
            save_state(case_dir, state)
            return {'updated': r}
    return {'error': f'Remediation #{remediation_id} introuvable'}


# ============================================================================
# Hypotheses concurrentes et mise a jour bayesienne
# ============================================================================
#
# Chaque hypothese est une proposition binaire H (vs non-H) avec une
# probabilite a priori (prior, defaut 0.5). Chaque preuve rattachee porte un
# RAPPORT DE VRAISEMBLANCE LR = P(preuve | H) / P(preuve | non-H) :
#
#     neutral  = 1   (preuve examinee, sans pouvoir discriminant)
#     weak     = 2
#     moderate = 5
#     strong   = 20
#
# Une preuve qui SOUTIENT H multiplie la cote par LR, une preuve qui la REFUTE
# la divise par LR (LR_refute = 1/x). La mise a jour se fait en log-cote :
#
#     logit(posterior) = logit(prior) + somme(+/- ln LR_i)
#
# (preuves supposees conditionnellement independantes : une meme preuve n'est
# comptee qu'une fois par hypothese et par sens). Les hypotheses d'une meme
# QUESTION sont classees par posterior ; si les deux premieres sont a moins de
# HYPOTHESIS_MARGIN l'une de l'autre, la question est NON TRANCHEE
# ('inconclusive').

EVIDENCE_WEIGHTS = {'neutral': 1.0, 'weak': 2.0, 'moderate': 5.0, 'strong': 20.0}
EVIDENCE_DIRECTIONS = ('supports', 'refutes')
DEFAULT_PRIOR = 0.5
SUPPORT_THRESHOLD = 0.8
REFUTE_THRESHOLD = 0.2
HYPOTHESIS_MARGIN = 0.1
MAX_LIKELIHOOD_RATIO = 100.0
_PRIOR_BOUNDS = (0.01, 0.99)
_TECH_RE = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)


def _logit(p):
    return math.log(p / (1.0 - p))


def _sigmoid(x):
    if x >= 0:
        return 1.0 / (1.0 + math.exp(-x))
    z = math.exp(x)
    return z / (1.0 + z)


def clamp_prior(prior):
    """Prior borne a [0.01, 0.99] (0.5 si invalide)."""
    try:
        value = float(prior)
    except (TypeError, ValueError):
        return DEFAULT_PRIOR
    if math.isnan(value):
        return DEFAULT_PRIOR
    return min(max(value, _PRIOR_BOUNDS[0]), _PRIOR_BOUNDS[1])


def likelihood_ratio(weight):
    """Poids d'une preuve -> rapport de vraisemblance (>= 1), ou None si invalide.
    Accepte un libelle (neutral/weak/moderate/strong) ou un nombre dans [1, 100]."""
    if isinstance(weight, str):
        label = weight.strip().lower()
        if label in EVIDENCE_WEIGHTS:
            return EVIDENCE_WEIGHTS[label]
        try:
            weight = float(label)
        except ValueError:
            return None
    if isinstance(weight, bool) or not isinstance(weight, (int, float)):
        return None
    value = float(weight)
    if math.isnan(value) or value < 1.0 or value > MAX_LIKELIHOOD_RATIO:
        return None
    return value


def posterior_from(prior, evidence):
    """Probabilite a posteriori (log-cote) a partir du prior et des preuves."""
    log_odds = _logit(clamp_prior(prior))
    for item in evidence or []:
        lr = likelihood_ratio(item.get('weight'))
        if not lr:
            continue
        log_odds += math.log(lr) if item.get('direction') == 'supports' else -math.log(lr)
    return round(_sigmoid(log_odds), 4)


def techniques_in(text):
    """Techniques ATT&CK citees (majuscules, sans doublon, ordre conserve)."""
    if isinstance(text, (list, tuple)):
        text = ' '.join(str(t) for t in text)
    return list(dict.fromkeys(t.upper() for t in _TECH_RE.findall(str(text or ''))))


def question_key(question):
    return ' '.join(str(question or '').lower().split())


def _normalize_hypothesis(h):
    """Completer une hypothese (y compris d'un ancien case_state.json) au format structure."""
    text = str(h.get('statement') or h.get('hypothesis') or '')[:300]
    h['hypothesis'] = text
    h['statement'] = text
    h.setdefault('question', None)
    h['techniques'] = techniques_in(h.get('techniques') or [])
    h.setdefault('status', 'open')
    h.setdefault('rationale', '')
    h['prior'] = clamp_prior(h.get('prior', DEFAULT_PRIOR))
    h['evidence'] = [e for e in (h.get('evidence') or []) if isinstance(e, dict)]
    h['posterior'] = posterior_from(h['prior'], h['evidence'])
    return h


def support_count(h):
    return sum(1 for e in h.get('evidence') or [] if e.get('direction') == 'supports')


def refute_count(h):
    return sum(1 for e in h.get('evidence') or [] if e.get('direction') == 'refutes')


def group_hypotheses(hypotheses):
    """{cle de question: [hypotheses]} (hypotheses sans question exclues)."""
    groups = {}
    for h in hypotheses:
        key = question_key(h.get('question'))
        if key:
            groups.setdefault(key, []).append(h)
    return groups


def ranked(group):
    """Hypotheses d'un groupe par posterior decroissant (id croissant a egalite)."""
    return sorted(group, key=lambda h: (-h['posterior'], h['id']))


def leader(group):
    """Hypothese en tete d'un groupe (hors refutees), ou None."""
    alive = [h for h in ranked(group) if h.get('status') != 'refuted']
    return alive[0] if alive else None


def _recompute_group(group, margin=HYPOTHESIS_MARGIN):
    """Statuts deterministes d'un groupe d'hypotheses concurrentes (hors statuts manuels)."""
    for h in group:
        if not h.get('manual_status'):
            refuted = h['posterior'] <= REFUTE_THRESHOLD and refute_count(h) > 0
            h['status'] = 'refuted' if refuted else 'open'
    alive = ranked([h for h in group if h['status'] != 'refuted'])
    if not alive:
        return
    top = alive[0]
    second = alive[1] if len(alive) > 1 else None
    close = second is not None and top['posterior'] - second['posterior'] < margin
    if close and top.get('evidence') and second.get('evidence'):
        for h in (top, second):
            if not h.get('manual_status'):
                h['status'] = 'inconclusive'
    elif (not close and top['posterior'] >= SUPPORT_THRESHOLD and support_count(top)
          and not top.get('manual_status')):
        top['status'] = 'supported'


def _new_hypothesis(state, statement, status, rationale, question=None, techniques=None,
                    prior=None, manual=False):
    entry = {
        'id': max((h.get('id', 0) for h in state['hypotheses']), default=0) + 1,
        'hypothesis': statement,
        'statement': statement,
        'question': (str(question).strip()[:200] or None) if question else None,
        'techniques': techniques_in(techniques or []),
        'status': status,
        'rationale': str(rationale)[:1000],
        'prior': clamp_prior(DEFAULT_PRIOR if prior is None else prior),
        'evidence': [],
        'ts': _now(),
    }
    entry['posterior'] = entry['prior']
    if manual:
        entry['manual_status'] = True
    state['hypotheses'].append(entry)
    return entry


def set_hypothesis(case_dir, hypothesis, status='open', rationale='', question=None,
                   techniques=None, prior=None):
    """Creer ou mettre a jour une hypothese d'enquete.

    L'hypothese est identifiee par son texte : re-appeler avec le meme texte
    mais un nouveau statut met a jour l'entree existante. Champs optionnels
    (hypotheses concurrentes) : question, techniques, prior. Le statut fixe
    ici est MANUEL : weigh_evidence ne le recalcule pas.
    """
    if not hypothesis:
        return {'error': 'hypothesis requise'}
    status = status if status in HYPOTHESIS_STATUSES else 'open'
    state = load_state(case_dir)
    text = str(hypothesis)[:300]
    for h in state['hypotheses']:
        if h['hypothesis'] == text:
            h['status'] = status
            h['manual_status'] = True
            h['rationale'] = str(rationale)[:1000]
            if question:
                h['question'] = str(question).strip()[:200]
            if techniques:
                h['techniques'] = techniques_in(list(h['techniques']) + techniques_in(techniques))
            if prior is not None:
                h['prior'] = clamp_prior(prior)
                h['posterior'] = posterior_from(h['prior'], h['evidence'])
            h['ts'] = _now()
            save_state(case_dir, state)
            return {'updated': h}
    entry = _new_hypothesis(state, text, status, rationale, question, techniques, prior, manual=True)
    save_state(case_dir, state)
    return {'created': entry}


def add_hypothesis(case_dir, question, statement, techniques=None, prior=None, rationale=''):
    """Ajouter une hypothese CONCURRENTE a une question (statut calcule par les preuves)."""
    if not question or not str(question).strip():
        return {'error': "question requise (ex: 'acces initial')"}
    if not statement or not str(statement).strip():
        return {'error': 'statement requis'}
    if prior is not None:
        try:
            prior_value = float(prior)
        except (TypeError, ValueError):
            return {'error': 'prior doit etre un nombre dans ]0, 1['}
        if not 0.0 < prior_value < 1.0:
            return {'error': 'prior doit etre un nombre dans ]0, 1['}
    state = load_state(case_dir)
    text = str(statement).strip()[:300]
    key = question_key(question)
    for h in state['hypotheses']:
        if h['hypothesis'] == text and question_key(h.get('question')) == key:
            return {'error': f"Hypothese deja posee (#{h['id']})", 'existing': h}
    entry = _new_hypothesis(state, text, 'open', rationale, question, techniques, prior)
    save_state(case_dir, state)
    group = group_hypotheses(state['hypotheses']).get(key, [])
    return {'created': entry, 'question': entry['question'],
            'competing': [{'id': h['id'], 'statement': h['statement']} for h in group]}


def weigh_evidence(case_dir, hypothesis_id, direction, weight, finding_id=None, ref=None, note=''):
    """Rattacher une preuve (constat existant ou reference validee) a une hypothese.

    Le posterior de l'hypothese est recalcule (log-cote) et les statuts de son
    groupe de question sont mis a jour. Une meme preuve (constat ou ref) ne
    compte qu'une fois par hypothese et par sens : la re-ponderer remplace son
    poids. La validation de `ref` (identifiant produit par un outil) incombe a
    l'appelant (outil weigh_evidence)."""
    if direction not in EVIDENCE_DIRECTIONS:
        return {'error': f'direction parmi {list(EVIDENCE_DIRECTIONS)}'}
    lr = likelihood_ratio(weight)
    if lr is None:
        return {'error': (f"weight invalide : libelle parmi {sorted(EVIDENCE_WEIGHTS)} ou rapport de "
                          f"vraisemblance numerique dans [1, {int(MAX_LIKELIHOOD_RATIO)}]")}
    if finding_id is None and not ref:
        return {'error': 'la preuve doit citer finding_id (constat existant) ou ref (reference validee)'}
    state = load_state(case_dir)
    target = next((h for h in state['hypotheses'] if h.get('id') == hypothesis_id), None)
    if target is None:
        return {'error': f'Hypothese #{hypothesis_id} introuvable'}
    if finding_id is not None and not any(f.get('id') == finding_id for f in state['findings']):
        return {'error': f'Constat #{finding_id} introuvable : weigh_evidence exige un constat existant'}
    item = {'finding_id': finding_id, 'ref': ref or None, 'direction': direction,
            'weight': lr, 'note': str(note)[:500], 'ts': _now()}
    key = (finding_id, json.dumps(ref or None, sort_keys=True), direction)
    for existing in target['evidence']:
        if (existing.get('finding_id'), json.dumps(existing.get('ref'), sort_keys=True),
                existing.get('direction')) == key:
            existing.update(item)
            break
    else:
        target['evidence'].append(item)
    if direction == 'refutes':
        target['refutation_attempted'] = True
    target['posterior'] = posterior_from(target['prior'], target['evidence'])
    qkey = question_key(target.get('question'))
    if qkey:
        _recompute_group(group_hypotheses(state['hypotheses'])[qkey])
    elif not target.get('manual_status'):
        _recompute_group([target])
    save_state(case_dir, state)
    signed = lr if direction == 'supports' else round(1.0 / lr, 4)
    return {'weighed': {'id': target['id'], 'statement': target['statement'],
                        'prior': target['prior'], 'posterior': target['posterior'],
                        'status': target['status'], 'likelihood_ratio': signed,
                        'evidence_count': len(target['evidence'])},
            'ranking': rank_hypotheses(case_dir, target.get('question'))['questions']}


def rank_hypotheses(case_dir, question=None, margin=HYPOTHESIS_MARGIN):
    """Classement par posterior de chaque question ; signale les questions non tranchees
    (deux premieres hypotheses non refutees a moins de `margin`)."""
    try:
        margin = float(margin)
    except (TypeError, ValueError):
        margin = HYPOTHESIS_MARGIN
    state = load_state(case_dir)
    wanted = question_key(question) if question else None
    out = []
    for key, group in group_hypotheses(state['hypotheses']).items():
        if wanted and key != wanted:
            continue
        order = ranked(group)
        alive = [h for h in order if h['status'] != 'refuted']
        total = sum(h['posterior'] for h in order) or 1.0
        gap = (alive[0]['posterior'] - alive[1]['posterior']) if len(alive) > 1 else None
        out.append({
            'question': group[0]['question'],
            'leader': alive[0]['id'] if alive else None,
            'inconclusive': gap is not None and gap < margin,
            'margin': None if gap is None else round(gap, 4),
            'competing': len(group),
            'ranking': [{'id': h['id'], 'statement': h['statement'], 'status': h['status'],
                         'prior': h['prior'], 'posterior': h['posterior'],
                         'relative': round(h['posterior'] / total, 4),
                         'supports': support_count(h), 'refutes': refute_count(h),
                         'techniques': h['techniques']} for h in order],
        })
    ungrouped = [] if wanted else [
        {'id': h['id'], 'statement': h['statement'], 'status': h['status'],
         'posterior': h['posterior']}
        for h in state['hypotheses'] if not question_key(h.get('question'))]
    return {'questions': out, 'ungrouped': ungrouped,
            'scale': {'likelihood_ratios': EVIDENCE_WEIGHTS, 'refutes': '1/x',
                      'support_threshold': SUPPORT_THRESHOLD,
                      'refute_threshold': REFUTE_THRESHOLD, 'margin': margin}}


def get_state(case_dir):
    """Restituer l'etat courant du cas (plan, findings, hypotheses) + resume."""
    state = load_state(case_dir)
    plan = state.get('plan', [])
    findings = state.get('findings', [])
    hypotheses = state.get('hypotheses', [])
    remediations = state.get('remediations', [])
    return {
        'plan': plan,
        'plan_remaining': sum(1 for s in plan if s.get('status') != 'done'),
        'findings': findings,
        'hypotheses': hypotheses,
        'remediations': remediations,
        'audits': state.get('audits', {}),
        'conclusion': state.get('conclusion'),
        'summary': {
            'findings': len(findings),
            'critical_or_high': sum(1 for f in findings if f['severity'] in ('critical', 'high')),
            'findings_verified': sum(1 for f in findings if f.get('verification') == 'verified'),
            'findings_unverified': sum(1 for f in findings
                                       if f.get('verification') in ('unverified', 'refuted')),
            'hypotheses_confirmed': sum(1 for h in hypotheses if h['status'] in SUPPORTED_STATUSES),
            'hypotheses_inconclusive': sum(1 for h in hypotheses if h['status'] == 'inconclusive'),
            'hypotheses_open': sum(1 for h in hypotheses if h['status'] == 'open'),
            'remediations_pending': sum(1 for r in remediations
                                        if r.get('status') == 'pending_approval'),
            'findings_challenged': sum(1 for f in findings if f.get('challenge')),
        },
    }


def render_markdown(case_dir):
    """Rendre l'etat du cas en Markdown pour annexer au rapport final."""
    state = get_state(case_dir)
    lines = []
    findings = sorted(state['findings'], key=lambda f: SEVERITIES.index(f['severity']))
    if findings:
        _vmark = {'verified': 'verifie', 'unverified': 'non verifie',
                  'refuted': 'refute', 'pending': 'a verifier'}
        lines.append('## Constats (findings)\n')
        lines.append('| # | Severite | Confiance | Verification | Constat | MITRE | Preuve |')
        lines.append('|---|---|---|---|---|---|---|')
        for f in findings:
            evidence = (f['evidence'] or '').replace('\n', ' ').replace('|', '\\|')[:160]
            refs = ', '.join(f"{r['kind']}={r['value']}@{os.path.basename(r['artifact'])}"
                             for r in f.get('evidence_refs') or [])
            if refs:
                evidence = f"{evidence} [{refs}]" if evidence else f"[{refs}]"
            title = (f['title'] or '').replace('|', '\\|')
            verif = _vmark.get(f.get('verification', 'pending'), 'a verifier')
            lines.append(f"| {f['id']} | {f['severity']} | {f['confidence']} | {verif} | "
                         f"{title} | {f['mitre'] or '-'} | {evidence or '-'} |")
        lines.append('')
    challenged = [f for f in findings if f.get('challenge')]
    if challenged:
        _cmark = {'upheld': 'MAINTENU', 'downgraded': 'AFFAIBLI', 'refuted': 'ECARTE'}
        lines.append('## Contre-analyse (hypotheses alternatives)\n')
        for f in challenged:
            c = f['challenge']
            lines.append(f"- Constat #{f['id']} {_cmark.get(c['verdict'], c['verdict'])} — "
                         f"alternative testee : {c['alternative']}")
            lines.append(f"  - Justification : {c['rationale']}")
        lines.append('')
    if state.get('conclusion', {}) and state['conclusion'].get('no_incident'):
        lines.append('## Conclusion : aucun incident etabli\n')
        lines.append(state['conclusion']['rationale'])
        lines.append('')
    if state['hypotheses']:
        lines.extend(_render_hypotheses(state['hypotheses']))
    lines.extend(_render_graph(case_dir))
    lines.extend(_render_detections(case_dir))
    if state['remediations']:
        _rmark = {'pending_approval': 'EN ATTENTE DE VALIDATION', 'approved': 'APPROUVEE',
                  'rejected': 'REJETEE'}
        lines.append('## Remediations proposees (validation humaine requise)\n')
        lines.append('| # | Statut | Hote | Commande | Motif | MITRE |')
        lines.append('|---|---|---|---|---|---|')
        for r in state['remediations']:
            cmd = (r['command'] or '').replace('|', '\\|')
            reason = (r['reason'] or '').replace('\n', ' ').replace('|', '\\|')[:160]
            lines.append(f"| {r['id']} | {_rmark.get(r.get('status'), r.get('status'))} | "
                         f"{r['target_host']} | `{cmd}` | {reason} | {r.get('mitre') or '-'} |")
        lines.append('')
    if state['plan']:
        lines.append('## Plan d\'investigation suivi\n')
        for i, s in enumerate(state['plan'], 1):
            box = '[x]' if s['status'] == 'done' else '[ ]'
            note = f" — {s['note']}" if s.get('note') else ''
            lines.append(f"{i}. {box} {s['step']}{note}")
        lines.append('')
    return '\n'.join(lines)


_HYPO_MARKS = {'supported': '[ETAYEE]', 'confirmed': '[CONFIRMEE]', 'refuted': '[REFUTEE]',
               'open': '[OUVERTE]', 'inconclusive': '[NON TRANCHEE]'}


def _cell(text, limit=160):
    return str(text or '').replace('\n', ' ').replace('|', '\\|')[:limit]


def _render_hypotheses(hypotheses):
    lines = ['## Hypotheses (concurrentes, probabilite a posteriori)\n',
             "Mise a jour bayesienne en log-cote : rapports de vraisemblance faible 2, modere 5, "
             "fort 20 (refutation = 1/x).\n"]
    groups = group_hypotheses(hypotheses)
    for key, group in groups.items():
        order = ranked(group)
        alive = [h for h in order if h['status'] != 'refuted']
        verdict = ''
        if len(alive) > 1 and alive[0]['posterior'] - alive[1]['posterior'] < HYPOTHESIS_MARGIN:
            verdict = ' (NON TRANCHEE : deux hypotheses a moins de la marge)'
        lines.append(f"### Question : {group[0]['question']}{verdict}\n")
        lines.append('| # | Statut | Hypothese | Prior | Posterior | Pour | Contre | ATT&CK |')
        lines.append('|---|---|---|---|---|---|---|---|')
        for h in order:
            lines.append(f"| {h['id']} | {_HYPO_MARKS.get(h['status'], h['status'])} | "
                         f"{_cell(h['statement'])} | {h['prior']:.2f} | {h['posterior']:.2f} | "
                         f"{support_count(h)} | {refute_count(h)} | "
                         f"{', '.join(h['techniques']) or '-'} |")
        for h in order:
            for e in h['evidence']:
                source = (f"constat #{e['finding_id']}" if e.get('finding_id') is not None else
                          f"{(e.get('ref') or {}).get('kind')}={(e.get('ref') or {}).get('value')}"
                          f"@{os.path.basename(str((e.get('ref') or {}).get('artifact', '')))}")
                sign = 'x' if e.get('direction') == 'supports' else '/'
                note = f" : {_cell(e.get('note'), 200)}" if e.get('note') else ''
                lines.append(f"- H#{h['id']} {e.get('direction')} ({sign}{e.get('weight')}) {source}{note}")
        lines.append('')
    loose = [h for h in hypotheses if not question_key(h.get('question'))]
    if loose:
        if groups:
            lines.append('### Autres hypotheses\n')
        for h in loose:
            lines.append(f"- {_HYPO_MARKS.get(h['status'], '')} {h['hypothesis']}"
                         + (f" (posterior {h['posterior']:.2f})" if h['evidence'] else ''))
            if h['rationale']:
                lines.append(f"  - Justification : {h['rationale']}")
        lines.append('')
    return lines


def _read_json(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _render_graph(case_dir):
    graph = _read_json(os.path.join(case_dir, GRAPH_FILENAME))
    if not isinstance(graph, dict) or not graph.get('nodes'):
        return []
    labels = {n.get('id'): n.get('label') or n.get('id') for n in graph.get('nodes') or []}
    pz = graph.get('patient_zero') or {}
    br = graph.get('blast_radius') or {}
    lines = ["## Graphe d'entites : patient zero et rayon d'impact\n",
             f"Graphe : {len(graph['nodes'])} entites, {len(graph.get('edges') or [])} relations "
             f"({GRAPH_FILENAME}).\n"]
    if pz.get('node'):
        path = ' -> '.join(str(labels.get(i, i)) for i in pz.get('path') or [])
        lines.append(f"- Patient zero : {pz['node']} (premier evenement malveillant : "
                     f"{pz.get('timestamp') or 'horodatage inconnu'})")
        if path:
            lines.append(f"- Chemin : {path}")
    else:
        lines.append('- Patient zero : non determine (aucune entite rattachee a un constat).')
    nodes = br.get('nodes') or []
    if br.get('seed'):
        shown = ', '.join(str(n) for n in nodes[:30]) or 'aucune autre entite atteinte'
        lines.append(f"- Rayon d'impact depuis {br['seed']} ({len(nodes)} hote(s)/compte(s)) : {shown}")
    lines.append('')
    return lines


def _render_detections(case_dir):
    index = _read_json(os.path.join(case_dir, DETECTIONS_DIRNAME, DETECTIONS_INDEX))
    rules = (index or {}).get('rules') if isinstance(index, dict) else None
    if not rules:
        return []
    lines = ['## Regles de detection generees\n',
             '| Fichier | Type | Constat | Correspond au malveillant | Faux positifs (corpus benin) |',
             '|---|---|---|---|---|']
    for name, meta in sorted(rules.items()):
        test = meta.get('test') or {}
        hits = test.get('malicious_matched')
        fps = test.get('false_positives')
        lines.append(f"| {DETECTIONS_DIRNAME}/{_cell(name)} | {meta.get('type', '-')} | "
                     f"#{meta.get('finding_id', '-')} | "
                     f"{'-' if hits is None else ('oui' if hits else 'NON')} | "
                     f"{'-' if fps is None else fps} |")
    lines.append('')
    return lines
