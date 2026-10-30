"""Extension Cloud & Identite : Microsoft 365, Entra ID, AWS, GCP, Kubernetes.

Outils hors ligne (aucun appel reseau, aucune dependance tierce) :
- cloud_detect_format : identifie le format d'un journal d'apres son contenu ;
- cloud_parse_log     : normalise et indexe les evenements (refs row / line) ;
- cloud_hunt          : detections (spray, fatigue MFA, voyage impossible,
                        consentement OAuth, regles de boite aux lettres,
                        alteration CloudTrail, IAM, exfiltration S3, GCP IAM,
                        Kubernetes...) avec severite, technique ATT&CK et refs.
Les journaux auditd Linux sont traites par l'extension linux_audit.
"""

import os

from .. import toolkit
from . import _cloud_formats as formats
from . import _cloud_rules as rules

AGENT = ('cloud', 'Agent Cloud & Identite')
TOOL_NAMES = ('cloud_detect_format', 'cloud_parse_log', 'cloud_hunt')
READONLY = TOOL_NAMES
INDEXED = ('cloud_parse_log', 'cloud_hunt')
KNOWN_TYPES = {
    '.jsonl': 'JSON lines (journaux cloud / Kubernetes ?)',
    '.ndjson': 'JSON lines (journaux cloud / Kubernetes ?)',
    '.gz': 'Archive gzip (CloudTrail .json.gz ?)',
}
PHASE_TOOLS = {
    'extraction': TOOL_NAMES,
    'correlation': ('cloud_hunt',),
    'contre_analyse': ('cloud_parse_log', 'cloud_hunt'),
}
PHASE_HINTS = {
    'extraction': """- Journaux cloud / identite (M365 Unified Audit Log, Entra ID connexions et audit,
  AWS CloudTrail y compris .json.gz, GCP Cloud Audit Logs, audit Kubernetes) : le format est detecte
  d'apres le contenu (cloud_detect_format) ; executer cloud_parse_log PUIS cloud_hunt sur chacun
  (parse_json_file / parse_csv ne suffisent pas pour ces formats).""",
    'correlation': """- Constats cloud : cloud_hunt fournit severite, technique ATT&CK et refs exactes (row / line).
  Verifier le contexte (get_timeline par utilisateur, IP, compte) puis citer ces refs dans
  record_finding ; relier les etapes (spray -> MFA -> consentement OAuth -> regle de transfert).""",
}

_PREVIEW = 100
_FULL_LIMIT = 200


def _artifact_name(file_path):
    """Nom d'artefact cite dans les refs : chemin relatif au cas actif, sinon nom du fichier."""
    case = toolkit.active_case()
    rel = toolkit._rel_in_case(file_path, case) if case else None
    return rel if rel not in (None, '.') else os.path.basename(file_path)


def _detect_or_error(file_path, families):
    det = formats.detect(file_path)
    if det['format'] not in families:
        return det, {'error': (f"Format non reconnu comme journal cloud / identite / Kubernetes "
                               f"({det.get('reason')}). Formats pris en charge : "
                               f"{', '.join(formats.CLOUD_FORMATS)}."), 'detection': det}
    return det, None


@toolkit.tool(
    'cloud_detect_format',
    "Identifier d'apres le CONTENU le format d'un journal cloud / identite / Linux : M365 Unified "
    "Audit Log (CSV AuditData, JSON), Entra ID connexions ou audit (JSON, Graph, CSV du portail), AWS "
    "CloudTrail (Records[], .json.gz), GCP Cloud Audit Logs, audit Kubernetes, auditd Linux.",
    toolkit._schema({'file_path': {'type': 'string', 'description': 'Chemin du journal'}}, ['file_path']),
)
def cloud_detect_format(file_path):
    det = formats.detect(file_path)
    det['recommended_tools'] = (
        ['cloud_parse_log', 'cloud_hunt'] if det['format'] in formats.CLOUD_FORMATS else
        ['linux_parse_auditd', 'linux_audit_hunt'] if det['format'] == 'linux_auditd' else [])
    return det


@toolkit.tool(
    'cloud_parse_log',
    "Parser et normaliser un journal cloud / identite / Kubernetes (M365 UAL, Entra ID connexions et "
    "audit, AWS CloudTrail, GCP Cloud Audit Logs, audit Kubernetes ; format detecte automatiquement) : "
    "horodatage UTC, principal, IP source, user agent, operation, resultat, ressource cible, "
    "tenant / compte / projet. Tous les evenements sont indexes dans la super-timeline avec une "
    "reference citable : 'line' (JSON lines) ou 'row' (ligne de donnees CSV, ou rang dans Records[] / "
    "value[] d'un document JSON).",
    toolkit._schema({
        'file_path': {'type': 'string', 'description': 'Chemin du journal (.json, .jsonl, .json.gz, .csv, .log)'},
        'max_events': {'type': 'integer',
                       'description': f"Nombre max d'evenements (defaut {formats.DEFAULT_MAX_EVENTS})"},
    }, ['file_path']),
)
def cloud_parse_log(file_path, max_events=formats.DEFAULT_MAX_EVENTS):
    det, error = _detect_or_error(file_path, formats.CLOUD_FORMATS)
    if error:
        return error
    events, stats = formats.load_events(file_path, det, max(1, int(max_events or formats.DEFAULT_MAX_EVENTS)))
    public = [formats.public_view(e) for e in events]
    result = {
        'file': file_path, 'format': det['format'], 'format_label': det['label'],
        'container': det['container'], 'compressed': det['compressed'],
        'ref_kind': 'line' if det['container'] == 'jsonl' else 'row',
        'total_events': len(public), 'skipped_records': stats.get('skipped', 0),
        'truncated': bool(stats.get('truncated')),
        'summary': formats.summarize(events),
        'events': public,
    }
    if det['format'] in SIGMA_SOURCES:
        alerts = _sigma_alerts(file_path, det, max(1, int(max_events or formats.DEFAULT_MAX_EVENTS)))
        if alerts:
            result['alerts'] = alerts
    if len(public) > _FULL_LIMIT:
        # Tout est indexe ; seul un apercu est renvoye au LLM (search_evidence / get_timeline ensuite)
        result['preview'] = public[:_PREVIEW]
    return result


# Cloud formats the SigmaHQ rules read as is (raw records, same row / line refs)
SIGMA_SOURCES = {'aws_cloudtrail': ('aws', 'cloudtrail')}


def _sigma_alerts(file_path, det, max_events):
    from .. import sigma_engine
    if not sigma_engine.available():
        return []
    records = [(kind, number, rec) for kind, number, rec, _fmt in formats.iter_records(file_path, det, max_events)
               if isinstance(rec, dict)]
    product, service = SIGMA_SOURCES[det['format']]
    return sigma_engine.scan_records(records, product, service,
                                     extra_dirs=[sigma_engine.connector_rules_path()])['alerts']


@toolkit.tool(
    'cloud_hunt',
    "Detections deterministes sur un journal cloud / identite / Kubernetes : pulverisation de mots de "
    "passe, fatigue MFA, connexion simple facteur, authentification heritee, voyage impossible "
    "(geolocalisation du journal, hors ligne), consentement OAuth a risque, identifiants de principal de "
    "service, regles de boite aux lettres (transfert, masquage), transfert SMTP ; AWS (StopLogging, "
    "DeleteTrail, CreateAccessKey pour autrui, AdministratorAccess, root, console sans MFA, rafales "
    "GetSecretValue, region inhabituelle, exfiltration S3, cle utilisee depuis une nouvelle IP) ; GCP "
    "(SetIamPolicy externe, cle de compte de service, puits de logs) ; Kubernetes (exec, pod privilegie / "
    "hostPath, enumeration de secrets, cluster-admin, acces anonyme). Chaque constat porte severite, "
    "technique MITRE ATT&CK et refs exactes a citer dans record_finding.",
    toolkit._schema({'file_path': {'type': 'string', 'description': 'Chemin du journal'}}, ['file_path']),
)
def cloud_hunt(file_path):
    det, error = _detect_or_error(file_path, formats.CLOUD_FORMATS)
    if error:
        return error
    events, stats = formats.load_events(file_path, det, 200000)
    findings, alerts, notes, ran = rules.run(events, det['format'], _artifact_name(file_path))
    return {
        'file': file_path, 'format': det['format'], 'format_label': det['label'],
        'events_analyzed': len(events), 'rules_run': ran,
        'finding_count': len(findings), 'findings': findings,
        'notes': notes, 'alerts': alerts,
        'guidance': ("Citer les refs d'un constat dans les evidence_refs de record_finding, avec sa technique "
                     "ATT&CK ; aucun constat ne signifie qu'aucune regle n'a declenche, pas l'absence "
                     "d'incident."),
    }


def applicable(path):
    """Les journaux cloud reconnus passent par cloud_parse_log puis cloud_hunt."""
    try:
        fmt = formats.detect(path)['format']
    except Exception:  # la detection ne doit jamais casser l'audit de couverture
        return None
    if fmt in formats.CLOUD_FORMATS:
        return [('parsing cloud', ('cloud_parse_log',)), ('detection cloud', ('cloud_hunt',))]
    return None
