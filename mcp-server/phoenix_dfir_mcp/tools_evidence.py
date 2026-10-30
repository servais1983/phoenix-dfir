"""Super-timeline, quality control (coverage audits, counter analysis) and report tools.

Registered in the single tool registry of ``toolkit``, which re-exports every
name: callers keep using ``toolkit.<name>``.
"""

import datetime
import os

from . import disk, evidence_db, exports, memory, verifier, volatility, zimmermann, toolkit  # noqa: E402
from .toolkit import _schema, tool  # noqa: E402
from .tools_artifacts import case_artifacts, is_windows_event_export  # noqa: E402

# ============================================================================
# Super-timeline : recherche et chronologie sur tous les artefacts indexes
# ============================================================================

@tool(
    'search_evidence',
    "Recherche plein texte (FTS5) dans TOUS les evenements deja extraits du cas (EVTX, logs, CSV, "
    "Sigma, Hayabusa, Volatility...) : comptes, IP, processus, commandes, chemins. Chaque resultat "
    "porte sa reference de preuve citable (ref : artefact, record_id/pid/line/row). Plusieurs mots "
    "= ET ; utiliser OR entre mots pour une alternative, guillemets pour une expression exacte.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'query': {'type': 'string', 'description': "Termes recherches (ex: 'svc_backup 185.220.101.44')"},
        'artifact': {'type': 'string', 'description': "Limiter a un artefact (nom partiel)"},
        'limit': {'type': 'integer', 'description': 'Nombre max de resultats (defaut 50)'},
    }, ['case_dir', 'query']),
)
def search_evidence(case_dir, query, artifact=None, limit=50):
    return evidence_db.search(case_dir, query, artifact=artifact, limit=limit)


@tool(
    'get_timeline',
    "Super-timeline du cas : evenements de TOUS les artefacts indexes, tries par horodatage UTC, "
    "filtrables par fenetre temporelle, hote, utilisateur, artefact ou texte. Indispensable pour "
    "correler entre sources (ex: connexion -> execution -> persistance -> C2).",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'start': {'type': 'string', 'description': 'Debut (ISO 8601, ex: 2026-10-10T03:00:00Z)'},
        'end': {'type': 'string', 'description': 'Fin (ISO 8601)'},
        'host': {'type': 'string', 'description': 'Filtre hote (partiel)'},
        'user': {'type': 'string', 'description': 'Filtre utilisateur (partiel)'},
        'contains': {'type': 'string', 'description': 'Texte contenu dans l\'evenement'},
        'artifact': {'type': 'string', 'description': 'Filtre artefact (partiel)'},
        'limit': {'type': 'integer', 'description': 'Nombre max d\'evenements (defaut 200)'},
    }, ['case_dir']),
)
def get_timeline(case_dir, start=None, end=None, host=None, user=None, contains=None,
                 artifact=None, limit=200):
    return evidence_db.timeline(case_dir, start=start, end=end, host=host, user=user,
                                contains=contains, artifact=artifact, limit=limit)


@tool(
    'list_sources',
    "Lister les sources indexees du cas : quel outil a ete execute sur quel artefact, avec quel "
    "succes et combien d'evenements, plus l'etendue temporelle couverte.",
    _schema({'case_dir': {'type': 'string', 'description': 'Dossier du cas'}}, ['case_dir']),
)
def list_sources(case_dir):
    return evidence_db.sources(case_dir)


# ============================================================================
# Controle qualite : audits de couverture et contre-analyse
# ============================================================================

_MEMORY_EXT = ('.raw', '.mem', '.vmem', '.dmp', '.lime')


def applicable_tools(path):
    """Groupes d'outils applicables a un artefact : chaque groupe doit etre couvert
    par au moins un de ses outils. Les outils indisponibles sur la machine sont
    signales a part (ils ne constituent pas une lacune de l'enqueteur)."""
    ext = os.path.splitext(path)[1].lower()
    groups, unavailable = [], []
    # Extensions : chaque extension qui reconnait l'artefact ajoute ses groupes
    claimed = False
    for module in toolkit._EXT_MODULES:
        hook = getattr(module, 'applicable', None)
        found = hook(path) if hook else None
        if found is not None:
            claimed = True
            ext_groups, missing = found if isinstance(found, tuple) else (found, [])
            groups.extend(g for g in ext_groups if g not in groups)
            unavailable.extend(m for m in missing if m not in unavailable)
    if claimed:
        return groups, unavailable
    if disk.looks_like_disk(path):
        if disk.tsk_available():
            groups = [('inventaire disque', ('disk_image_info', 'disk_list_files')),
                      ('extraction disque', ('disk_extract_artifacts',)),
                      ('timeline disque', ('disk_timeline',))]
        else:
            unavailable.append('The Sleuth Kit')
    elif ext == '.evtx':
        groups = [('parsing', ('parse_evtx', 'analyze_artifact', 'run_zimmermann')),
                  ('detection', ('sigma_scan', 'run_hayabusa'))]
    elif ext in ('.log', '.txt', '.xml', '.ps1', '.bat', '.sh'):
        groups = [('parsing', ('parse_log_file', 'analyze_artifact'))]
    elif ext == '.csv':
        groups = [('parsing', ('parse_csv', 'analyze_artifact'))]
        if is_windows_event_export(path):
            groups.append(('detection', ('sigma_scan',)))
    elif ext == '.json':
        groups = [('parsing', ('parse_json_file', 'analyze_artifact'))]
        if is_windows_event_export(path):
            groups.append(('detection', ('sigma_scan',)))
    elif ext == '.pf':
        groups = [('parsing', ('parse_prefetch', 'analyze_artifact', 'run_zimmermann'))]
    elif ext == '.lnk':
        groups = [('parsing', ('parse_lnk', 'analyze_artifact', 'run_zimmermann'))]
    elif ext in ('.sqlite', '.db'):
        groups = [('parsing', ('parse_browser_history', 'analyze_artifact', 'run_zimmermann'))]
    elif ext in _MEMORY_EXT:
        if volatility.status()['available']:
            groups = [('memoire', ('run_volatility',))]
        else:
            unavailable.append('Volatility 3')
    elif ext in ('.hve', '.dat', '.mft'):
        if zimmermann.status()['available']:
            groups = [('parsing', ('run_zimmermann',))]
        else:
            unavailable.append('EZ Tools')
    return groups, unavailable


@tool(
    'audit_tool_coverage',
    "Audit de couverture des OUTILS : pour chaque artefact, verifier que les outils applicables "
    "(parsing, detection Sigma/Hayabusa, memoire) ont bien ete executes. Retourne les lacunes a "
    "combler. A appeler en fin d'extraction et pendant la contre-analyse.",
    _schema({'case_dir': {'type': 'string', 'description': 'Dossier du cas'}}, ['case_dir']),
)
def audit_tool_coverage(case_dir):
    if not os.path.isdir(case_dir):
        return {'error': f"Dossier introuvable: {case_dir}"}
    result = compute_tool_coverage(case_dir)
    memory.mark_audit(case_dir, 'tool_coverage', {k: result[k] for k in
                                                  ('artifacts_fully_covered', 'gap_count')})
    return result


def compute_tool_coverage(case_dir):
    """Lacunes de couverture d'outils (sans marquer l'audit comme effectue)."""
    runs = evidence_db.runs_by_artifact(case_dir)
    gaps, unavailable, failed, covered = [], [], [], 0
    for path in case_artifacts(case_dir):
        rel = os.path.relpath(path, case_dir)
        artifact_runs = runs.get(rel, {})
        attempted = set(artifact_runs)
        groups, missing_tools = applicable_tools(path)
        for label in missing_tools:
            unavailable.append({'artifact': rel, 'tool': label})
        # Un outil tente mais en echec (dump corrompu, symboles absents...) couvre
        # l'etape : il est signale a part, sans bloquer indefiniment l'enquete.
        artifact_gaps = [{'artifact': rel, 'step': step, 'run_one_of': list(tools)}
                         for step, tools in groups if not attempted.intersection(tools)]
        for step, tools in groups:
            tried = attempted.intersection(tools)
            if tried and not any(artifact_runs[t] for t in tried):
                failed.append({'artifact': rel, 'step': step, 'failed_tools': sorted(tried)})
        gaps.extend(artifact_gaps)
        if groups and not artifact_gaps:
            covered += 1
    return {'gaps': gaps, 'failed_runs': failed, 'unavailable_tools': unavailable,
            'artifacts_fully_covered': covered, 'gap_count': len(gaps), 'complete': not gaps}


@tool(
    'audit_evidence_coverage',
    "Audit de couverture des PREUVES : artefacts jamais analyses, et artefacts analyses mais jamais "
    "cites dans un constat (pistes potentiellement ignorees). A appeler pendant la contre-analyse.",
    _schema({'case_dir': {'type': 'string', 'description': 'Dossier du cas'}}, ['case_dir']),
)
def audit_evidence_coverage(case_dir):
    if not os.path.isdir(case_dir):
        return {'error': f"Dossier introuvable: {case_dir}"}
    runs = evidence_db.runs_by_artifact(case_dir)
    cited = set()
    for f in memory.get_state(case_dir)['findings']:
        for ref in f.get('evidence_refs') or []:
            cited.add(os.path.basename(str(ref.get('artifact', ''))))
    never_analyzed, analyzed_not_cited, cited_list = [], [], []
    for path in case_artifacts(case_dir):
        rel = os.path.relpath(path, case_dir)
        if not any(runs.get(rel, {}).values()):
            never_analyzed.append(rel)
        elif os.path.basename(rel) in cited:
            cited_list.append(rel)
        else:
            analyzed_not_cited.append(rel)
    summary = {'never_analyzed_count': len(never_analyzed),
               'analyzed_not_cited_count': len(analyzed_not_cited), 'cited_count': len(cited_list)}
    memory.mark_audit(case_dir, 'evidence_coverage', summary)
    return {'never_analyzed': never_analyzed, 'analyzed_not_cited': analyzed_not_cited,
            'cited': cited_list, **summary}


@tool(
    'challenge_finding',
    "CONTRE-ANALYSE d'un constat : formuler l'hypothese alternative la plus plausible (activite "
    "legitime, faux positif d'outil, autre acteur...), chercher les preuves qui la soutiendraient "
    "(search_evidence, get_timeline), puis statuer : 'upheld' (le constat resiste), 'downgraded' "
    "(affaibli, preciser new_severity) ou 'refuted' (l'alternative l'emporte). Obligatoire pour "
    "chaque constat critical/high.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'finding_id': {'type': 'integer', 'description': 'Numero du constat'},
        'alternative': {'type': 'string', 'description': 'Hypothese alternative testee'},
        'verdict': {'type': 'string', 'enum': list(memory.CHALLENGE_VERDICTS)},
        'rationale': {'type': 'string', 'description': 'Preuves pour et contre, avec references'},
        'new_severity': {'type': 'string', 'enum': list(memory.SEVERITIES),
                         'description': 'Nouvelle severite si downgraded'},
    }, ['case_dir', 'finding_id', 'alternative', 'verdict', 'rationale']),
)
def challenge_finding(case_dir, finding_id, alternative, verdict, rationale, new_severity=None):
    return memory.challenge_finding(case_dir, finding_id, alternative, verdict, rationale, new_severity)


@tool(
    'declare_no_incident',
    "Conclure EXPLICITEMENT qu'aucun incident n'est etabli (activite legitime), avec la "
    "justification fondee sur les preuves examinees. Ne jamais inventer de constat pour remplir "
    "une enquete : un cas sain est un resultat valide.",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'rationale': {'type': 'string', 'description': 'Pourquoi aucun incident (preuves examinees)'},
    }, ['case_dir', 'rationale']),
)
def declare_no_incident(case_dir, rationale):
    return memory.declare_no_incident(case_dir, rationale)


# ============================================================================
# Rapport
# ============================================================================

ANNEX_MARKER = '\n\n---\n\n# Annexe - Synthese d\'enquete\n\n'


def report_quality(body, case_dir):
    """Verifier deterministe des constats + liens phrase -> constat verifie du corps du rapport."""
    base = body.split(ANNEX_MARKER, 1)[0]
    summary = verifier.verify_case(case_dir)
    citations = verifier.check_citations(base, summary['verified_ids'])
    return summary, citations


def _with_annex(body, case_dir):
    """Attacher (ou remplacer) l'annexe de synthese memoire au corps du rapport.

    Les constats sont d'abord soumis au verificateur deterministe : seuls les
    constats verifies figurent parmi les conclusions de l'annexe."""
    base = body.split(ANNEX_MARKER, 1)[0].rstrip()
    summary, citations = report_quality(base, case_dir)
    state_md = memory.render_markdown(case_dir)
    if not state_md.strip():
        return base
    head = (f"> Verification deterministe : {summary['verified']}/{summary['findings']} constat(s) "
            f"verifie(s) ; {citations['linked']}/{citations['factual_sentences']} phrase(s) factuelle(s) "
            f"du rapport liee(s) a un constat verifie.\n\n")
    return base + ANNEX_MARKER + head + state_md


def refresh_report_annex(report_path, case_dir):
    """Regenerer l'annexe d'un rapport deja ecrit (apres la verification)."""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()
        refreshed = _with_annex(content, case_dir)
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(refreshed if refreshed.endswith('\n') else refreshed + '\n')
        _write_exports(case_dir, refreshed)
        return True
    except OSError:
        return False


@tool(
    'save_report',
    "Sauvegarder le rapport d'enquete final au format Markdown dans le dossier du cas. "
    "A appeler UNE FOIS en fin d'investigation avec le rapport complet (resume executif, "
    "artefacts analyses, IoCs, timeline, mapping MITRE, conclusions et recommandations).",
    _schema({
        'case_dir': {'type': 'string', 'description': 'Dossier du cas'},
        'title': {'type': 'string', 'description': 'Titre du rapport'},
        'markdown': {'type': 'string', 'description': 'Contenu Markdown complet du rapport'},
    }, ['case_dir', 'title', 'markdown']),
)
def save_report(case_dir, title, markdown):
    if not os.path.isdir(case_dir):
        return {'error': f"Dossier introuvable: {case_dir}"}
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(case_dir, f'rapport_phoenix_{ts}.md')
    header = (f"# {title}\n\n> Report generated by Phoenix DFIR (autonomous investigator) "
              f"le {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    body = markdown if markdown.lstrip().startswith('#') else header + markdown
    # Annexer automatiquement la memoire d'enquete (findings, hypotheses, plan)
    # pour que le rapport soit toujours trace aux preuves accumulees.
    body = _with_annex(body, case_dir)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(body if body.endswith('\n') else body + '\n')
    result = {'saved': True, 'report_path': path, 'size_bytes': os.path.getsize(path)}
    summary, citations = report_quality(body, case_dir)
    result['verification'] = {k: summary[k] for k in ('findings', 'verified', 'unverified', 'refuted')}
    result['citations'] = {k: citations[k] for k in ('factual_sentences', 'linked', 'coverage')}
    if citations['unlinked']:
        result['unlinked_sentences'] = citations['unlinked'][:5]
    written = _write_exports(case_dir, body)
    if written:
        result['exports'] = written
    return result


def _write_exports(case_dir, report_text):
    """Calque ATT&CK Navigator + CSV d'IoCs a cote du rapport (best-effort)."""
    first = (report_text or '').lstrip().splitlines()[:1]
    title = first[0].lstrip('# ').strip() if first else 'Enquete'
    try:
        return exports.write_exports(case_dir, title, report_text)
    except Exception:
        return None
