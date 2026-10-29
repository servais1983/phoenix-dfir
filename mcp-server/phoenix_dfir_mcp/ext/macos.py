"""Extension macOS : journal unifie, TCC, persistance, quarantaine, FSEvents.

Outils hors ligne (bibliotheque standard uniquement : plistlib, sqlite3 en
lecture seule, gzip, struct) :
- macos_detect_artifact    : type d'artefact d'apres le contenu ;
- macos_parse_unifiedlog   : exports `log show` (ndjson, json, texte) ;
- macos_parse_tcc          : autorisations TCC.db ;
- macos_parse_persistence  : LaunchAgents / LaunchDaemons, emond, LoginHook,
                             cron, periodic (BTM : note explicite) ;
- macos_parse_quarantine   : telechargements (QuarantineEventsV2) ;
- macos_parse_knowledgec   : usage des applications (KnowledgeC.db) ;
- macos_parse_fsevents     : pages FSEvents (1SLD / 2SLD / 3SLD) ;
- macos_hunt               : detections avec severite, technique ATT&CK et refs.
Le format natif .tracev3 n'est pas decode (format binaire proprietaire) :
il faut un export `log show --style ndjson` produit sur un Mac.
"""

import os
from collections import Counter

from .. import toolkit
from . import _macos_formats as mf
from . import _macos_fsevents as fse
from . import _macos_persist as persist
from . import _macos_rules as rules

AGENT = ('macos', 'Agent macOS')
PARSERS = ('macos_parse_unifiedlog', 'macos_parse_tcc', 'macos_parse_persistence', 'macos_parse_quarantine',
           'macos_parse_knowledgec', 'macos_parse_fsevents')
TOOL_NAMES = ('macos_detect_artifact',) + PARSERS + ('macos_hunt',)
READONLY = TOOL_NAMES
INDEXED = PARSERS + ('macos_hunt',)
KNOWN_TYPES = {
    '.plist': 'Property list macOS (LaunchAgent / LaunchDaemon / emond ?)',
    '.tracev3': 'Journal unifie macOS natif (non decode : exporter avec log show --style ndjson)',
    '.btm': 'Base BackgroundTaskManagement macOS (non decodee)',
}
PHASE_TOOLS = {
    'extraction': TOOL_NAMES,
    'correlation': ('macos_hunt',),
    'contre_analyse': PARSERS + ('macos_hunt',),
}
PHASE_HINTS = {
    'extraction': """- Artefacts macOS (exports log show ndjson / json / texte, TCC.db, QuarantineEventsV2,
  KnowledgeC.db, plists LaunchAgents / LaunchDaemons / emond, crontab, periodic, fichiers .fseventsd) :
  type detecte d'apres le contenu (macos_detect_artifact) ; executer le parser adapte (macos_parse_unifiedlog,
  macos_parse_tcc, macos_parse_quarantine, macos_parse_persistence, macos_parse_fsevents,
  macos_parse_knowledgec) PUIS macos_hunt sur chacun. Un .tracev3 natif n'est pas decode : demander un
  export log show.""",
    'correlation': """- Constats macOS : macos_hunt cite des refs exactes ('row' = rowid SQLite / rang, 'line').
  Relier telechargement (quarantaine) -> retrait de quarantaine (xattr) -> persistance launchd ->
  autorisation TCC -> collecte (osascript, trousseau) -> nettoyage (FSEvents).""",
}

_PREVIEW = 100
_FULL_LIMIT = 200
_PARSER_FOR = {
    **{t: 'macos_parse_unifiedlog' for t in mf.UNIFIED_TYPES},
    'tcc': 'macos_parse_tcc', 'quarantine': 'macos_parse_quarantine', 'knowledgec': 'macos_parse_knowledgec',
    'fsevents': 'macos_parse_fsevents',
    **{t: 'macos_parse_persistence' for t in mf.PERSISTENCE_TYPES},
}
_HUNTABLE = set(mf.UNIFIED_TYPES) | {'tcc', 'quarantine', 'fsevents', 'launchd_plist', 'emond_rules',
                                     'loginwindow_plist', 'crontab', 'periodic'}
_TRACEV3_NOTE = ("Journal unifie natif .tracev3 : format binaire proprietaire non decode par Phoenix. "
                 "Sur un Mac : log show --archive <fichier.logarchive> --style ndjson > unifiedlog.ndjson, "
                 "puis macos_parse_unifiedlog sur l'export.")


def _artifact_name(file_path):
    case = toolkit.active_case()
    rel = toolkit._rel_in_case(file_path, case) if case else None
    return rel if rel not in (None, '.') else os.path.basename(file_path)


def _public(ev):
    return {k: v for k, v in ev.items() if not k.startswith('_')}


def _wrap(file_path, kind, events, ref_kind, extra=None):
    public = [_public(e) for e in events]
    stamps = sorted(e['timestamp'] for e in events if e.get('timestamp'))
    result = {'file': file_path, 'artifact_type': kind, 'artifact_label': mf.TYPES.get(kind),
              'ref_kind': ref_kind, 'total_events': len(public),
              'time_span': {'first': stamps[0], 'last': stamps[-1]} if stamps else None}
    result.update(extra or {})
    result['events'] = public
    if len(public) > _FULL_LIMIT:
        result['preview'] = public[:_PREVIEW]  # tout est indexe ; seul l'apercu revient au LLM
    return result


def _expect(file_path, kinds, tool):
    det = mf.detect(file_path)
    if det['type'] in kinds:
        return det, None
    hint = _PARSER_FOR.get(det['type'])
    message = f"{tool} : artefact non pris en charge ({det.get('reason')})."
    if det['type'] == 'tracev3':
        message = _TRACEV3_NOTE
    elif hint:
        message += f' Utiliser {hint}.'
    return det, {'error': message, 'detection': det}


@toolkit.tool(
    'macos_detect_artifact',
    "Identifier d'apres le CONTENU un artefact macOS : export du journal unifie (log show ndjson / json / "
    "texte), .tracev3 natif (non decode), dossier .logarchive, TCC.db, QuarantineEventsV2, KnowledgeC.db, "
    "plist LaunchAgent / LaunchDaemon / emond / LoginHook, crontab, periodic, .btm, FSEvents (.fseventsd).",
    toolkit._schema({'file_path': {'type': 'string', 'description': "Chemin de l'artefact ou du dossier"}},
                    ['file_path']),
)
def macos_detect_artifact(file_path):
    det = mf.detect(file_path)
    kind = det['type']
    det['recommended_tools'] = ([_PARSER_FOR[kind]] if kind in _PARSER_FOR else []) + \
        (['macos_hunt'] if kind in _HUNTABLE else [])
    if kind == 'tracev3':
        det['note'] = _TRACEV3_NOTE
    elif kind == 'logarchive':
        exports, natives = mf.logarchive_exports(file_path)
        det['exports'] = exports
        det['tracev3_files'] = natives
        det['note'] = ("Executer macos_parse_unifiedlog sur chaque export ci-dessus (les refs restent "
                       "propres a chaque fichier). " + ('' if exports else _TRACEV3_NOTE))
    return det


@toolkit.tool(
    'macos_parse_unifiedlog',
    "Parser un export du journal unifie macOS (log show --style ndjson, --style json, ou sortie texte "
    "default / syslog / compact) : horodatage UTC, processus et chemin, pid, sous-systeme, categorie, "
    "message, image emettrice, uid, type d'evenement. Indexe dans la super-timeline ; ref 'line' (ndjson, "
    "texte : ligne physique, premiere ligne d'un message multi-ligne) ou 'row' (rang dans le tableau json). "
    "Un .tracev3 natif n'est pas decode.",
    toolkit._schema({
        'file_path': {'type': 'string', 'description': "Chemin de l'export (.ndjson, .json, .log, .txt, .gz)"},
        'max_events': {'type': 'integer', 'description': f"Nombre max d'entrees (defaut {mf.DEFAULT_MAX_EVENTS})"},
    }, ['file_path']),
)
def macos_parse_unifiedlog(file_path, max_events=mf.DEFAULT_MAX_EVENTS):
    det, error = _expect(file_path, mf.UNIFIED_TYPES, 'macos_parse_unifiedlog')
    if error:
        if det['type'] == 'logarchive':
            error['exports'] = mf.logarchive_exports(file_path)[0]
            error['error'] = ("Dossier .logarchive : executer macos_parse_unifiedlog sur chaque export "
                              "liste dans 'exports' (aucun si l'archive ne contient que du .tracev3).")
        return error
    events, stats = mf.load_unified(file_path, det['type'], max(1, int(max_events or mf.DEFAULT_MAX_EVENTS)))
    return _wrap(file_path, det['type'], events, 'row' if det['type'] == 'unifiedlog_json' else 'line', {
        'skipped_lines': stats['skipped'], 'truncated': stats['truncated'], 'notes': stats['notes'],
        'summary': {
            'top_processes': dict(Counter(e.get('process') for e in events if e.get('process')).most_common(20)),
            'top_subsystems': dict(Counter(e.get('subsystem') for e in events if e.get('subsystem')).most_common(15)),
            'message_types': dict(Counter(e.get('message_type') for e in events if e.get('message_type'))),
        }})


@toolkit.tool(
    'macos_parse_tcc',
    "Parser une base TCC.db macOS (lecture seule) : autorisations de confidentialite (service, client, "
    "type de client, auth_value / auth_reason decodes, exigence de signature csreq, objet indirect "
    "AppleEvents, last_modified UTC). Ref 'row' = rowid SQLite de la table access.",
    toolkit._schema({'file_path': {'type': 'string', 'description': 'Chemin de TCC.db'}}, ['file_path']),
)
def macos_parse_tcc(file_path):
    _det, error = _expect(file_path, ('tcc',), 'macos_parse_tcc')
    if error:
        return error
    events, stats = mf.load_tcc(file_path)
    notes = [n for n in (mf.wal_note(file_path),) if n]
    granted = [e for e in events if e.get('auth_value') in (2, 3)]
    return _wrap(file_path, 'tcc', events, 'row', {
        'schema': stats['schema'], 'truncated': stats['truncated'], 'notes': notes,
        'summary': {'granted': len(granted),
                    'services': dict(Counter(e.get('service_label') for e in granted).most_common(20)),
                    'path_clients': sorted({e['client'] for e in granted if e.get('client_type') == 'path'})[:50]}})


@toolkit.tool(
    'macos_parse_persistence',
    "Parser un artefact de persistance macOS : plist LaunchAgent / LaunchDaemon (binaire ou XML : Label, "
    "Program / ProgramArguments, RunAtLoad, KeepAlive, StartInterval, portee deduite du chemin), regles "
    "emond (RunCommand), LoginHook / LogoutHook, crontab, scripts periodic. Les bases .btm "
    "(BackgroundTaskManagement) ne sont pas decodees (note explicite). Ref 'row' (plist : 1, emond : rang "
    "de la regle) ou 'line' (cron, periodic).",
    toolkit._schema({'file_path': {'type': 'string', 'description': "Chemin du plist / crontab / script"}},
                    ['file_path']),
)
def macos_parse_persistence(file_path):
    det, error = _expect(file_path, mf.PERSISTENCE_TYPES, 'macos_parse_persistence')
    if error:
        return error
    events, notes = persist.load(file_path, det['type'])
    ref = 'line' if det['type'] in ('crontab', 'periodic') else 'row'
    return _wrap(file_path, det['type'], events, ref, {'notes': notes, 'decoded': det['type'] != 'btm'})


@toolkit.tool(
    'macos_parse_quarantine',
    "Parser la base de quarantaine macOS (com.apple.LaunchServices.QuarantineEventsV2, lecture seule) : "
    "telechargements avec horodatage UTC, application (agent), URL du fichier, URL et titre d'origine, "
    "expediteur, type (web, piece jointe...). Ref 'row' = rowid de LSQuarantineEvent.",
    toolkit._schema({'file_path': {'type': 'string', 'description': 'Chemin de QuarantineEventsV2'}},
                    ['file_path']),
)
def macos_parse_quarantine(file_path):
    _det, error = _expect(file_path, ('quarantine',), 'macos_parse_quarantine')
    if error:
        return error
    events, stats = mf.load_quarantine(file_path)
    return _wrap(file_path, 'quarantine', events, 'row', {
        'truncated': stats['truncated'], 'notes': [n for n in (mf.wal_note(file_path),) if n],
        'summary': {'agents': dict(Counter(e.get('agent_name') for e in events if e.get('agent_name'))),
                    'download_hosts': dict(Counter(e.get('download_host') for e in events
                                                   if e.get('download_host')).most_common(20))}})


@toolkit.tool(
    'macos_parse_knowledgec',
    "Parser KnowledgeC.db macOS (lecture seule) : usage des applications (/app/usage, /app/inFocus, "
    "/app/activity) avec debut / fin UTC et duree. Ref 'row' = Z_PK de ZOBJECT.",
    toolkit._schema({'file_path': {'type': 'string', 'description': 'Chemin de KnowledgeC.db'}}, ['file_path']),
)
def macos_parse_knowledgec(file_path):
    _det, error = _expect(file_path, ('knowledgec',), 'macos_parse_knowledgec')
    if error:
        return error
    events, stats = mf.load_knowledgec(file_path)
    return _wrap(file_path, 'knowledgec', events, 'row', {
        'truncated': stats['truncated'], 'notes': stats.get('notes', []),
        'summary': {'apps': dict(Counter(e.get('bundle_id') for e in events if e.get('bundle_id')).most_common(30))}})


@toolkit.tool(
    'macos_parse_fsevents',
    "Parser un fichier FSEvents macOS (.fseventsd, gzip) de facon bornee : pages 1SLD / 2SLD / 3SLD, chemin, "
    "identifiant d'evenement, drapeaux decodes (Created, Removed, Renamed, Modified, ExtendedAttrModified / "
    "Removed, PermissionChanged, IsFile / IsDirectory...), inode (v2 / v3). Pas d'horodatage par "
    "enregistrement (format). Ref 'row' = rang de l'enregistrement dans le fichier.",
    toolkit._schema({
        'file_path': {'type': 'string', 'description': 'Chemin du fichier FSEvents'},
        'max_records': {'type': 'integer', 'description': f"Nombre max d'enregistrements (defaut {fse.MAX_RECORDS})"},
    }, ['file_path']),
)
def macos_parse_fsevents(file_path, max_records=fse.MAX_RECORDS):
    _det, error = _expect(file_path, ('fsevents',), 'macos_parse_fsevents')
    if error:
        return error
    events, stats = fse.parse(file_path, max(1, min(int(max_records or fse.MAX_RECORDS), fse.MAX_RECORDS)))
    flags = Counter(n for e in events for n in e['flag_names'].split(',') if n)
    ids = [e['fsevent_id'] for e in events]
    return _wrap(file_path, 'fsevents', events, 'row', {
        'pages': stats['pages'], 'versions': stats['versions'], 'truncated': stats['truncated'],
        'notes': stats['notes'] + ["Aucun horodatage par enregistrement : l'ordre suit l'identifiant "
                                   "d'evenement ; la date du fichier borne l'activite."],
        'summary': {'flags': dict(flags.most_common()),
                    'event_id_range': [min(ids), max(ids)] if ids else None}})


def _load_for_hunt(file_path, kind):
    if kind in mf.UNIFIED_TYPES:
        return mf.load_unified(file_path, kind, 500000)[0]
    if kind == 'tcc':
        return mf.load_tcc(file_path)[0]
    if kind == 'quarantine':
        return mf.load_quarantine(file_path)[0]
    if kind == 'fsevents':
        return fse.parse(file_path)[0]
    return persist.load(file_path, kind)[0]


@toolkit.tool(
    'macos_hunt',
    "Detections deterministes sur un artefact macOS (type detecte d'apres le contenu) : persistance launchd "
    "(binaire cache, dossier modifiable, curl | sh, osascript, python -c, usurpation com.apple.*), emond, "
    "LoginHook, cron / periodic suspects ; autorisations TCC sensibles (acces complet au disque, "
    "enregistrement d'ecran, accessibilite, micro, camera, AppleEvents) accordees a des binaires non signes "
    "ou situes dans des emplacements modifiables ; telechargements depuis des origines suspectes ; journal "
    "unifie (retrait de quarantaine xattr, Gatekeeper desactive, fausse invite de mot de passe osascript, "
    "trousseau, curl | sh, exfiltration curl, manipulation TCC, effacement de journaux) ; FSEvents (fichiers "
    "crees puis supprimes en zone temporaire / cachee, renommages ou suppressions massifs, attribut etendu "
    "retire, nouveau plist launchd). Chaque constat porte severite, technique MITRE ATT&CK et refs exactes.",
    toolkit._schema({'file_path': {'type': 'string', 'description': "Chemin de l'artefact macOS"}}, ['file_path']),
)
def macos_hunt(file_path):
    det = mf.detect(file_path)
    kind = det['type']
    if kind not in _HUNTABLE:
        if kind in ('btm', 'knowledgec'):
            return {'file': file_path, 'artifact_type': kind, 'finding_count': 0, 'findings': [], 'alerts': [],
                    'notes': [f'aucune regle de detection pour {mf.TYPES[kind]}']}
        return {'error': _TRACEV3_NOTE if kind == 'tracev3' else
                f"macos_hunt : artefact non pris en charge ({det.get('reason')}).", 'detection': det}
    events = _load_for_hunt(file_path, kind)
    findings, alerts, notes = rules.run(kind, events, _artifact_name(file_path))
    return {'file': file_path, 'artifact_type': kind, 'artifact_label': mf.TYPES[kind],
            'events_analyzed': len(events), 'finding_count': len(findings), 'findings': findings,
            'alerts': alerts, 'notes': notes,
            'guidance': ("Citer les refs d'un constat dans record_finding (evidence_refs) avec sa technique "
                         "ATT&CK ; aucun constat ne signifie qu'aucune regle n'a declenche, pas l'absence "
                         "d'incident.")}


def applicable(path):
    """Artefacts macOS : parser dedie puis macos_hunt (None si non concerne)."""
    try:
        kind = mf.detect(path)['type']
    except Exception:  # la detection ne doit jamais casser l'audit de couverture
        return None
    if kind is None or kind == 'logarchive':
        return None
    if kind == 'tracev3':
        return [], ['log show (macOS) : export ndjson du journal unifie']
    groups = [(f'parsing macOS ({kind})', (_PARSER_FOR[kind],))]
    if kind in _HUNTABLE:
        groups.append(('detection macOS', ('macos_hunt',)))
    return groups
