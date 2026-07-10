"""Memoire d'enquete structuree.

Chaque cas possede un fichier `case_state.json` dans son dossier, qui
accumule au fil de l'investigation :
- le PLAN (working memory) : les etapes decomposees et leur avancement ;
- les FINDINGS (episodic memory) : constats horodates, lies a des preuves,
  avec severite / confiance / technique MITRE ;
- les HYPOTHESES : pistes formees, confirmees ou refutees avec justification.

Cette memoire permet a l'enqueteur de traiter de gros cas multi-artefacts
sans perdre le fil quand la fenetre de contexte se remplit, et de produire
un rapport riche et trace aux preuves. Le stockage fichier (JSON) est simple,
sans dependance, et testable — un seul job ecrit un cas a la fois.
"""

import datetime
import json
import os

STATE_FILENAME = 'case_state.json'

SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
CONFIDENCES = ('confirmed', 'likely', 'possible')
HYPOTHESIS_STATUSES = ('open', 'confirmed', 'refuted')
VERIFICATION_STATUSES = ('verified', 'unverified', 'refuted')


def _state_path(case_dir):
    return os.path.join(case_dir, STATE_FILENAME)


def load_state(case_dir):
    path = _state_path(case_dir)
    if os.path.isfile(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return {'plan': [], 'findings': [], 'hypotheses': []}


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


def record_finding(case_dir, title, severity='info', evidence='', mitre='', confidence='possible'):
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
        'verification': 'pending',
        'verification_note': '',
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


def set_hypothesis(case_dir, hypothesis, status='open', rationale=''):
    """Creer ou mettre a jour une hypothese d'enquete.

    L'hypothese est identifiee par son texte : re-appeler avec le meme texte
    mais un nouveau statut met a jour l'entree existante.
    """
    if not hypothesis:
        return {'error': 'hypothesis requise'}
    status = status if status in HYPOTHESIS_STATUSES else 'open'
    state = load_state(case_dir)
    text = str(hypothesis)[:300]
    for h in state['hypotheses']:
        if h['hypothesis'] == text:
            h['status'] = status
            h['rationale'] = str(rationale)[:1000]
            h['ts'] = _now()
            save_state(case_dir, state)
            return {'updated': h}
    entry = {
        'id': len(state['hypotheses']) + 1,
        'hypothesis': text,
        'status': status,
        'rationale': str(rationale)[:1000],
        'ts': _now(),
    }
    state['hypotheses'].append(entry)
    save_state(case_dir, state)
    return {'created': entry}


def get_state(case_dir):
    """Restituer l'etat courant du cas (plan, findings, hypotheses) + resume."""
    state = load_state(case_dir)
    plan = state.get('plan', [])
    findings = state.get('findings', [])
    hypotheses = state.get('hypotheses', [])
    return {
        'plan': plan,
        'plan_remaining': sum(1 for s in plan if s.get('status') != 'done'),
        'findings': findings,
        'hypotheses': hypotheses,
        'summary': {
            'findings': len(findings),
            'critical_or_high': sum(1 for f in findings if f['severity'] in ('critical', 'high')),
            'findings_verified': sum(1 for f in findings if f.get('verification') == 'verified'),
            'findings_unverified': sum(1 for f in findings
                                       if f.get('verification') in ('unverified', 'refuted')),
            'hypotheses_confirmed': sum(1 for h in hypotheses if h['status'] == 'confirmed'),
            'hypotheses_open': sum(1 for h in hypotheses if h['status'] == 'open'),
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
            title = (f['title'] or '').replace('|', '\\|')
            verif = _vmark.get(f.get('verification', 'pending'), 'a verifier')
            lines.append(f"| {f['id']} | {f['severity']} | {f['confidence']} | {verif} | "
                         f"{title} | {f['mitre'] or '-'} | {evidence or '-'} |")
        lines.append('')
    if state['hypotheses']:
        lines.append('## Hypotheses\n')
        for h in state['hypotheses']:
            mark = {'confirmed': '[CONFIRMEE]', 'refuted': '[REFUTEE]', 'open': '[OUVERTE]'}.get(h['status'], '')
            lines.append(f"- {mark} {h['hypothesis']}")
            if h['rationale']:
                lines.append(f"  - Justification : {h['rationale']}")
        lines.append('')
    if state['plan']:
        lines.append('## Plan d\'investigation suivi\n')
        for i, s in enumerate(state['plan'], 1):
            box = '[x]' if s['status'] == 'done' else '[ ]'
            note = f" — {s['note']}" if s.get('note') else ''
            lines.append(f"{i}. {box} {s['step']}{note}")
        lines.append('')
    return '\n'.join(lines)
