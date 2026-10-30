#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enqueteur DFIR autonome cote plateforme.

Pont entre le backend Flask et le module phoenix_dfir_mcp (mcp-server/) :
prepare un dossier de cas a partir des artefacts d'une enquete, lance
l'investigation autonome GitHub Copilot dans le pool de threads et republie
chaque etape en temps reel via WebSocket ('autonomous_progress').

Chaque outil execute est scelle dans la chaine de preuve (custody.py) et
republie en direct sur la console enqueteur DFIR ('agent_step') ; les remediations
proposees par l'enqueteur deviennent des demandes de validation humaine
('hitl_required').

En fin d'enquete : rapport Markdown sauvegarde dans backend/reports/,
IoCs du rapport inseres en base, evenement timeline et journal d'audit.
"""

import datetime
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import threading
import uuid

import custody
import evidence_vault
import jobqueue
from database import get_db, log_audit
from extensions import emit_secure
from parsers import extract_iocs

# phoenix_dfir_mcp vient du paquet installe (pip install -e .) ; un checkout
# source lance sans installation (python app.py) retombe sur mcp-server/.
if importlib.util.find_spec('phoenix_dfir_mcp') is None:
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'mcp-server'))

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')

# Les jobs sont persistes dans la file durable SQLite (jobqueue.py) et
# executes par son pool borne (PHOENIX_JOB_WORKERS), distinct des threads qui
# servent HTTP / WebSocket : une longue enquete n'affame jamais le serveur.
JOB_KIND = 'autonomous_investigation'

# Statuts de la file durable -> statuts historiques de l'API et des evenements
# ('completed' et 'error' restent ceux attendus par les clients existants).
LEGACY_STATUS = {
    jobqueue.QUEUED: 'queued', jobqueue.RUNNING: 'running', jobqueue.DONE: 'completed',
    jobqueue.FAILED: 'error', jobqueue.CANCELLED: 'cancelled',
}
ACTIVE_LEGACY = ('queued', 'running')
MAX_STORED_MESSAGES = 300


class _JobRegistry(dict):
    """Vue memoire des jobs de ce processus (messages en direct).

    La source de verite est la table SQLite `jobs` : un job absent de la
    memoire (termine avant un redemarrage, ou evince) est relu depuis la base
    par get().
    """

    def get(self, key, default=None):
        value = super().get(key)
        if value is not None:
            return value
        stored = _stored(key)
        return job_view(stored) if stored else default


# Etat des jobs autonomes en cours / termines (memoire process). Le registre
# est BORNE : les jobs termines sont evinces au-dela d'un age ou d'un nombre
# maximal (un job en file ou en cours n'est jamais evince). Un job evince
# reste consultable depuis SQLite.
autonomous_jobs = _JobRegistry()
_jobs_lock = threading.Lock()
MAX_FINISHED_JOBS = int(os.environ.get('PHOENIX_MAX_FINISHED_JOBS', '50') or 50)
FINISHED_JOB_TTL_SECONDS = int(os.environ.get('PHOENIX_FINISHED_JOB_TTL', str(24 * 3600)) or 86400)


def _parse_ts(value):
    try:
        return datetime.datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def prune_jobs(now=None, max_finished=None, ttl_seconds=None):
    """Evincer les jobs termines trop anciens ou en surnombre. Retourne le nb evince."""
    now = now or datetime.datetime.now()
    max_finished = MAX_FINISHED_JOBS if max_finished is None else max_finished
    ttl = FINISHED_JOB_TTL_SECONDS if ttl_seconds is None else ttl_seconds
    with _jobs_lock:
        finished = []
        for job_id, job in list(autonomous_jobs.items()):
            if job.get('status') in ACTIVE_LEGACY:
                continue
            ts = _parse_ts(job.get('finished_at')) or _parse_ts(job.get('started_at')) or now
            finished.append((ts, job_id))
        finished.sort()
        evicted = {job_id for ts, job_id in finished if (now - ts).total_seconds() > ttl}
        remaining = [job_id for _ts, job_id in finished if job_id not in evicted]
        if len(remaining) > max_finished:
            evicted.update(remaining[:len(remaining) - max_finished])
        for job_id in evicted:
            autonomous_jobs.pop(job_id, None)
    return len(evicted)


# ============================================================================
# File durable : lecture, liste, quota, annulation
# ============================================================================

def _queue():
    return jobqueue.get_queue()


def _stored(job_id):
    """Job autonome lu en base (None si inconnu ou d'un autre type)."""
    try:
        stored = _queue().get(job_id)
    except Exception:
        return None
    return stored if stored and stored.get('kind') == JOB_KIND else None


def job_view(stored, include_report=True):
    """Job SQLite -> forme historique de GET /api/autonomous/jobs/<id>."""
    progress = stored.get('progress') or {}
    payload = stored.get('payload') or {}
    view = {
        'job_id': stored['id'],
        'investigation_id': stored.get('investigation_id'),
        'status': LEGACY_STATUS.get(stored['status'], stored['status']),
        'state': stored['status'],
        'messages': list(progress.get('messages') or []),
        'progress': {k: v for k, v in progress.items() if k != 'messages'},
        'queued_at': jobqueue.iso(stored.get('created_at')),
        'started_at': jobqueue.iso(stored.get('started_at') or stored.get('created_at')),
        'user_id': stored.get('owner_id'),
        'username': stored.get('owner_name'),
        'question': payload.get('question'),
        'attempts': stored.get('attempts', 0),
        'cancel_requested': bool(stored.get('cancel_requested')),
    }
    if stored.get('finished_at'):
        view['finished_at'] = jobqueue.iso(stored['finished_at'])
    if stored.get('error') and stored['status'] != jobqueue.DONE:
        view['error'] = stored['error']
    result = stored.get('result') or {}
    if isinstance(result, dict):
        for key, value in result.items():
            if key == 'report_content' and not include_report:
                continue
            view.setdefault(key, value)
    return view


def get_job(job_id):
    """Etat d'un job : SQLite (source de verite) complete par la vue memoire
    (messages en direct). Un job inconnu de la base (tests, ancien format)
    est servi depuis la memoire seule."""
    live = dict.get(autonomous_jobs, job_id)
    stored = _stored(job_id)
    if stored is None:
        return live
    view = job_view(stored)
    if live:
        if len(live.get('messages') or []) > len(view['messages']):
            view['messages'] = list(live['messages'])
        for key, value in live.items():
            if key not in ('status', 'messages', 'state', 'progress'):
                view.setdefault(key, value)
    return view


def list_jobs(investigation_id=None, owner_id=None, investigation_ids=None, statuses=None, limit=50):
    """Jobs persistes (plus recents d'abord), sans le contenu des rapports."""
    rows = _queue().list(investigation_id=investigation_id, owner_id=owner_id,
                         investigation_ids=investigation_ids, statuses=statuses,
                         kind=JOB_KIND, limit=limit)
    return [job_view(r, include_report=False) for r in rows]


def active_job_ids(user_id):
    """Jobs en file ou en cours d'un utilisateur (base + vue memoire)."""
    ids = {jid for jid, j in list(autonomous_jobs.items())
           if j.get('status') in ACTIVE_LEGACY and j.get('user_id') == user_id}
    try:
        ids |= _queue().active_ids(user_id)
    except Exception:
        pass
    return ids


def count_jobs(status):
    """Nombre de jobs dans un statut historique ('running', 'queued')."""
    queue_status = next((k for k, v in LEGACY_STATUS.items() if v == status), status)
    ids = {jid for jid, j in list(autonomous_jobs.items()) if j.get('status') == status}
    try:
        ids |= {j['id'] for j in _queue().list(statuses=(queue_status,), kind=JOB_KIND, limit=500)}
    except Exception:
        pass
    return len(ids)


def cancel_job(job_id, actor=None):
    """Demander l'annulation d'un job. Retourne le statut historique obtenu,
    ou None si le job n'est pas dans la file."""
    status = _queue().request_cancel(job_id)
    if status is None:
        return None
    legacy = LEGACY_STATUS.get(status, status)
    job = dict.get(autonomous_jobs, job_id)
    stored = _stored(job_id) or {}
    inv_id = stored.get('investigation_id') or (job or {}).get('investigation_id')
    if job is not None:
        job['cancel_requested'] = True
        if legacy == 'cancelled':
            job.update({'status': 'cancelled', 'finished_at': datetime.datetime.now().isoformat()})
    if legacy == 'cancelled':
        _emit(job_id, inv_id, f"Investigation annulee avant demarrage{f' par {actor}' if actor else ''}.",
              status='cancelled')
    elif legacy == 'running':
        _emit(job_id, inv_id, f"Annulation demandee{f' par {actor}' if actor else ''} : "
                              "arret au prochain point de controle.", cancel_requested=True)
    return legacy


def llm_provider():
    """Fournisseur LLM de l'enqueteur : 'github' (Copilot) ou 'ollama' (local)."""
    from phoenix_dfir_mcp import copilot
    return copilot.provider_name()


def copilot_configured():
    """Le LLM de l'enqueteur est-il utilisable (jeton GitHub, ou Ollama) ?"""
    from phoenix_dfir_mcp import copilot
    return copilot.is_configured()


def copilot_model():
    from phoenix_dfir_mcp import copilot
    return copilot.default_model()


def llm_label():
    from phoenix_dfir_mcp import copilot
    return copilot.provider_label()


_APP = None


def _bind_app(app):
    """Memoriser l'application Flask et enregistrer le handler de la file."""
    global _APP
    if app is not None:
        _APP = app
    _queue().register(JOB_KIND, _handle_queued_job)


def start_queue(app):
    """Demarrer le pool de workers de la file durable (au demarrage du serveur).

    Les jobs 'running' dont le heartbeat est perime (serveur arrete en plein
    travail) sont remis en file une fois, puis passent en echec.
    """
    _bind_app(app)
    return _queue().start()


def _wake_workers():
    _queue().wake()


def start_job(app, investigation_id, question=None, user_id=None, username=None, priority=0):
    """Mettre en file une investigation autonome (persistee en SQLite). Retourne le job_id."""
    prune_jobs()
    _bind_app(app)
    job_id = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    # Vue memoire creee AVANT l'insertion : un worker peut prendre le job aussitot
    autonomous_jobs[job_id] = {
        'job_id': job_id,
        'investigation_id': investigation_id,
        'status': 'queued',
        'state': jobqueue.QUEUED,
        'messages': [],
        'queued_at': now,
        'started_at': now,
        'user_id': user_id,
    }
    _queue().enqueue(JOB_KIND, {'question': question, 'username': username},
                     owner_id=user_id, owner_name=username, investigation_id=investigation_id,
                     priority=priority, job_id=job_id)
    _wake_workers()
    return job_id


def _handle_queued_job(job, ctx):
    """Handler de la file : execute le job puis traduit son issue pour la file
    (exception = echec, JobCancelled = annule, retour = resultat persiste)."""
    job_id = job['id']
    inv_id = job.get('investigation_id')
    payload = job.get('payload') or {}
    live = dict.get(autonomous_jobs, job_id)
    if live is None:
        # Job repris apres un redemarrage : reconstituer la vue memoire
        live = job_view(job)
        autonomous_jobs[job_id] = live
    live.update({'status': 'running', 'state': jobqueue.RUNNING,
                 'started_at': datetime.datetime.now().isoformat(),
                 'attempts': job.get('attempts'), 'user_id': job.get('owner_id')})
    if (job.get('attempts') or 0) > 1:
        _emit(job_id, inv_id, f"Reprise apres interruption du serveur (tentative {job['attempts']}).")
    if _APP is None:
        raise RuntimeError("application Flask non initialisee (autonomous.start_queue)")
    final = _run_job(_APP, job_id, inv_id, payload.get('question'), job.get('owner_id'),
                     payload.get('username') or job.get('owner_name'), ctx=ctx)
    # Journal complet persiste (consultable apres un redemarrage)
    messages = list(final.get('messages') or [])
    try:
        _queue().update_progress(job_id, {
            'message': messages[-1] if messages else None, 'messages_count': len(messages),
            'tools_executed': final.get('tools_seen', 0), 'last_tool': final.get('last_tool'),
            'messages': messages[-MAX_STORED_MESSAGES:]}, emit=False)
    except Exception:
        pass
    status = final.get('status')
    if status == 'cancelled':
        raise jobqueue.JobCancelled(job_id)
    if status == 'error':
        raise RuntimeError(final.get('error') or 'erreur inconnue')
    return {key: final.get(key) for key in _RESULT_KEYS if key in final}


_RESULT_KEYS = ('summary', 'report_id', 'exports', 'report_content', 'steps', 'tools_executed',
                'iocs_extracted', 'metrics')


def _emit(job_id, investigation_id, message, **extra):
    job = dict.get(autonomous_jobs, job_id)
    progress = None
    if job is not None:
        job.setdefault('messages', []).append(message)
        progress = {
            'message': message,
            'messages_count': len(job['messages']),
            'tools_executed': job.get('tools_seen', 0),
            'last_tool': job.get('last_tool'),
            'messages': job['messages'][-MAX_STORED_MESSAGES:],
        }
        if job.get('status') in ACTIVE_LEGACY:
            try:
                _queue().update_progress(job_id, progress, emit=False)
            except Exception:
                pass
    payload = {'job_id': job_id, 'investigation_id': investigation_id, 'message': message}
    if progress:
        payload['progress'] = {k: v for k, v in progress.items() if k != 'messages'}
    payload.update(extra)
    emit_secure('autonomous_progress', payload)


def _file_sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _same_artifact(dest, src, expected_sha256=None):
    """Le fichier deja present dans le cas est-il CET artefact (relance du job) ?"""
    try:
        if os.path.islink(dest):
            return os.path.realpath(dest) == os.path.realpath(src)
        if not os.path.isfile(dest) or os.path.getsize(dest) != os.path.getsize(src):
            return False
        return _file_sha256(dest) == (expected_sha256 or _file_sha256(src))
    except OSError:
        return False


def _case_file_name(name):
    """Nom de fichier sur dans le cas : jamais un fichier interne de Phoenix
    (memoire du cas, base de preuves, briefing PHOENIX.md, rapports...)."""
    from phoenix_dfir_mcp import toolkit
    name = os.path.basename(name.replace('\\', '/')) or 'artefact'
    if name in ('.', '..'):
        name = 'artefact'
    if toolkit.is_internal_file(name):
        name = f'artefact_{name}'
    return name


def _unique_dest(case_dir, name, src, expected_sha256, claimed):
    """Destination unique : 'nom.ext', puis 'nom_2.ext', 'nom_3.ext'... (deux
    artefacts homonymes ne sont plus silencieusement ecartes). Retourne
    (chemin, deja_present)."""
    stem, ext = os.path.splitext(name)
    index = 1
    while True:
        candidate = name if index == 1 else f'{stem}_{index}{ext}'
        dest = os.path.join(case_dir, candidate)
        if candidate not in claimed:
            if not os.path.lexists(dest):
                return dest, False
            if _same_artifact(dest, src, expected_sha256):
                return dest, True
        index += 1


def _prepare_case_dir(app, investigation_id, artifacts):
    """Rassembler les artefacts de l'enquete dans un dossier de cas dedie.

    Les evidences du coffre (lecture seule, souvent volumineuses : dumps RAM)
    sont referencees par lien symbolique plutot que copiees. Deux artefacts de
    meme nom d'origine sont tous deux conserves (suffixe _2, _3...). Retourne
    (case_dir, nombre, coffre_utilise).
    """
    case_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'cases', investigation_id)
    os.makedirs(case_dir, exist_ok=True)
    copied = 0
    uses_vault = False
    claimed = set()
    for art in artifacts:
        src = art.get('file_path') or ''
        if not src or not os.path.isfile(src):
            continue
        dest_name = _case_file_name(
            art.get('original_filename') or art.get('filename') or os.path.basename(src))
        in_vault = evidence_vault.contains(src)
        uses_vault = uses_vault or in_vault
        dest, present = _unique_dest(case_dir, dest_name, src, art.get('file_hash_sha256'), claimed)
        claimed.add(os.path.basename(dest))
        if not present:
            if in_vault:
                try:
                    os.symlink(src, dest)
                except OSError:
                    shutil.copy2(src, dest)
            else:
                shutil.copy2(src, dest)
        copied += 1
    return case_dir, copied, uses_vault


def _vault_roots(case_dir):
    """Evidences du coffre referencees PAR CE CAS (cibles des liens symboliques).
    Seuls ces fichiers sont ajoutes aux racines du job, jamais le coffre entier
    (qui contient les evidences des autres enquetes)."""
    roots = []
    for root, _dirs, files in os.walk(case_dir):
        for fname in files:
            path = os.path.join(root, fname)
            if os.path.islink(path) and evidence_vault.contains(path):
                roots.append(os.path.realpath(path))
    return roots


def _artifact_ref(case_dir, arguments):
    """Reference lisible de l'artefact vise par un outil (relative au cas)."""
    for key in ('file_path', 'case_dir'):
        value = arguments.get(key)
        if isinstance(value, str) and value:
            try:
                rel = os.path.relpath(value, case_dir)
            except ValueError:
                rel = value
            if rel == '.':
                return 'Dossier du cas'
            return value if rel.startswith('..') else rel
    if arguments.get('value'):
        return f"IoC {arguments.get('ioc_type', '')}:{arguments['value']}"
    return ''


_LEVEL_TO_SEVERITY = {'critical': 'critical', 'crit': 'critical', 'high': 'high',
                      'medium': 'medium', 'med': 'medium', 'low': 'low'}


def _tool_insight(name, arguments, result):
    """Resume, technique MITRE et severite d'un appel d'outil (console enqueteur DFIR)."""
    if not isinstance(result, dict):
        return 'Outil execute', '', 'info'
    if result.get('error'):
        return f"Erreur : {result['error']}"[:500], '', 'low'
    if name == 'phase_gate':
        return (result.get('message') or 'Porte qualite', '',
                'info' if result.get('passed') else 'medium')
    if name == 'challenge_finding':
        return (f"Contre-analyse du constat #{arguments.get('finding_id')} : "
                f"{arguments.get('verdict')} (alternative : {arguments.get('alternative', '')})"[:500],
                '', 'info')
    if name in ('audit_tool_coverage', 'audit_evidence_coverage'):
        if name == 'audit_tool_coverage':
            return f"Audit outils : {result.get('gap_count', 0)} lacune(s)", '', 'info'
        return (f"Audit preuves : {result.get('never_analyzed_count', 0)} jamais analyse(s), "
                f"{result.get('analyzed_not_cited_count', 0)} jamais cite(s)", '', 'info')
    if name == 'declare_no_incident':
        return 'Conclusion : aucun incident etabli', '', 'info'
    if name == 'prompt_injection_shield':
        return result.get('message') or 'Injection de prompt neutralisee', 'T1562', 'high'
    if name == 'record_finding':
        refs = ', '.join(f"{r['kind']}={r['value']}"
                         for r in (result.get('recorded') or {}).get('evidence_refs') or [])
        title = arguments.get('title') or 'Constat'
        return (f"{title} [{refs}]" if refs else title, arguments.get('mitre') or '',
                arguments.get('severity') or 'info')
    if name == 'propose_remediation':
        return (f"Remediation proposee sur {arguments.get('target_host')} : validation humaine requise",
                arguments.get('mitre') or '', arguments.get('severity') or 'high')
    if name == 'set_hypothesis':
        return (f"Hypothese [{arguments.get('status', 'open')}] {arguments.get('hypothesis', '')}",
                '', 'info')
    if name == 'verify_finding':
        return (f"Constat #{arguments.get('finding_id')} : {arguments.get('verdict')}", '', 'info')
    if name == 'save_report':
        return 'Rapport d\'enquete sauvegarde', '', 'info'
    if name in ('sigma_scan', 'run_hayabusa'):
        alerts = result.get('alerts') or []
        levels = [str(a.get('level', '')).lower() for a in alerts]
        severity = next((_LEVEL_TO_SEVERITY[lvl] for lvl in ('critical', 'crit', 'high', 'medium', 'med', 'low')
                         if lvl in levels), 'info')
        techniques = []
        for a in alerts:
            tech = a.get('technique') or a.get('mitre_technique') or a.get('mitre_tags')
            if tech and str(tech) not in techniques:
                techniques.append(str(tech))
        total = result.get('total_alerts', len(alerts))
        top = (alerts[0].get('rule') or alerts[0].get('rule_title')) if alerts else None
        summary = f"{total} alerte(s)" + (f" — {top}" if top else '')
        return summary, ', '.join(techniques[:3]), severity
    if name == 'run_volatility':
        return (f"{arguments.get('plugin')} : {result.get('total_rows', 0)} ligne(s) extraite(s)",
                '', 'info')
    for key in ('message', 'summary'):
        if isinstance(result.get(key), str) and result[key]:
            return result[key][:500], '', 'info'
    if 'total' in result:
        return f"{result['total']} element(s)", '', 'info'
    return 'Outil execute', '', 'info'


def _make_tool_recorder(job_id, investigation_id, case_dir, actor):
    """Callback on_tool de l'enqueteur : scelle chaque outil dans la chaine de
    preuve, alimente la console enqueteur DFIR et ouvre les demandes de validation humaine."""
    from phoenix_dfir_mcp import toolkit

    def on_tool(step, name, arguments, result):
        summary, mitre, severity = _tool_insight(name, arguments or {}, result)
        compact_args = toolkit.to_json(arguments or {}, 400)
        entry = custody.safe_record(
            f'{name}({compact_args})', actor, investigation_id=investigation_id,
            agent=toolkit.agent_for(name), artifact_ref=_artifact_ref(case_dir, arguments or {}),
            summary=summary, mitre=mitre, severity=severity,
            details={'tool': name, 'step': step, 'job_id': job_id},
            payload_sha256=custody.sha256_text(toolkit.to_json(result)))
        if entry:
            emit_secure('agent_step', dict(entry, job_id=job_id))
        if name == 'propose_remediation' and isinstance(result, dict) and result.get('proposed'):
            proposed = result['proposed']
            action = custody.create_remediation(
                proposed['target_host'], proposed['command'], proposed['reason'],
                investigation_id=investigation_id, job_id=job_id, mitre=proposed.get('mitre', ''),
                severity=proposed.get('severity', 'high'), requested_by=actor,
                case_dir=case_dir, case_remediation_id=proposed.get('id'))
            sealed = action.pop('custody_entry', None)
            if sealed:
                emit_secure('agent_step', dict(sealed, job_id=job_id))
            emit_secure('hitl_required', action)
            _emit(job_id, investigation_id,
                  f"Validation humaine requise : {action['id']} ({action['target_host']})")

    return on_tool


def _persist_results(app, investigation_id, report_text, user_id, username):
    """Inserer les IoCs du rapport, tracer la timeline et journaliser."""
    iocs = extract_iocs(report_text or '')
    now = datetime.datetime.now().isoformat()
    with app.app_context():
        db = get_db()
        for ioc in iocs:
            try:
                db.execute(
                    "INSERT OR IGNORE INTO iocs (investigation_id, type, value, source) VALUES (?, ?, ?, ?)",
                    (investigation_id, ioc['type'], ioc['value'], 'enqueteur-autonome'),
                )
            except Exception:
                pass
        try:
            db.execute(
                "INSERT INTO timeline_events (id, investigation_id, timestamp, event, severity, source) VALUES (?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), investigation_id, now,
                 "Investigation autonome GitHub Copilot terminee - rapport genere", 'info', 'enqueteur-autonome'),
            )
        except Exception:
            pass
        db.execute("UPDATE investigations SET updated_at=? WHERE id=?", (now, investigation_id))
        db.commit()
        log_audit(
            user_id, username or 'enqueteur-autonome', 'autonomous_investigation',
            target_type='investigation', target_id=investigation_id,
            details=json.dumps({'iocs_extraits': len(iocs)}),
            ip_address=None,
        )
    return len(iocs)


def _publish_exports(case_dir, report_filename):
    """Copier le calque ATT&CK Navigator et le CSV d'IoCs a cote du rapport
    (telechargeables via /api/reports/<id>/download)."""
    from phoenix_dfir_mcp import exports
    published = {}
    stem = report_filename.rsplit('.', 1)[0]
    for key, name, suffix in (('navigator_layer', exports.NAVIGATOR_FILE, '_attack_navigator.json'),
                              ('iocs_csv', exports.IOCS_FILE, '_iocs.csv')):
        src = os.path.join(case_dir, name)
        if os.path.isfile(src):
            dest_name = stem + suffix
            shutil.copy2(src, os.path.join(REPORTS_DIR, dest_name))
            published[key] = dest_name
    return published


def _cooperative_hooks(job_id, investigation_id, on_tool, ctx):
    """Envelopper on_step / on_tool de l'enqueteur : progression + point
    d'annulation cooperative apres chaque etape et chaque outil (JobCancelled
    derive de BaseException et traverse le `except Exception` de l'enqueteur)."""
    def check():
        if ctx is not None:
            ctx.check_cancel()

    def step(msg):
        _emit(job_id, investigation_id, msg)
        check()

    def tool(step_no, name, arguments, result):
        job = dict.get(autonomous_jobs, job_id)
        if job is not None:
            job['tools_seen'] = job.get('tools_seen', 0) + 1
            job['last_tool'] = name
        try:
            on_tool(step_no, name, arguments, result)
        finally:
            check()

    return step, tool, check


def _run_job(app, job_id, investigation_id, question, user_id, username, ctx=None):
    """Executer une investigation autonome. `ctx` (jobqueue.JobContext) fournit
    l'annulation cooperative ; sans ctx (appel direct), aucune annulation.
    Retourne la vue memoire du job (status completed / error / cancelled)."""
    checkpoint = (lambda: ctx.check_cancel()) if ctx is not None else (lambda: None)
    try:
        checkpoint()
        with app.app_context():
            db = get_db()
            inv = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
            artifacts = [dict(row) for row in db.execute(
                "SELECT * FROM artifacts WHERE investigation_id=?", (investigation_id,)).fetchall()]
        inv_name = inv['name'] if inv else investigation_id

        case_dir, copied, uses_vault = _prepare_case_dir(app, investigation_id, artifacts)
        label = llm_label()
        _emit(job_id, investigation_id,
              f"Dossier de cas prepare : {copied} artefact(s). {label} demarre l'enquete...")

        from phoenix_dfir_mcp import investigator, pathpolicy
        # Perimetre PROPRE A CE JOB (variable de contexte du thread) : le dossier
        # du cas et, s'il y en a, les seules evidences du coffre qu'il reference.
        job_roots = _vault_roots(case_dir) if uses_vault else []
        actor = f'enqueteur-autonome ({llm_provider()})'
        custody.safe_record(
            'investigation_started', username or actor, investigation_id=investigation_id,
            agent='Orchestrateur Lead', artifact_ref=f'{copied} artefact(s)',
            summary=f"Investigation autonome lancee ({label}, modele {copilot_model()})",
            details={'job_id': job_id, 'question': question or ''},
            payload_sha256=custody.sha256_json(sorted(
                a.get('file_hash_sha256') or '' for a in artifacts)))
        full_question = f"Enquete '{inv_name}'."
        if inv and inv['description']:
            full_question += f" Contexte : {inv['description']}"
        if question:
            full_question += f" {question}"

        on_step, on_tool, _check = _cooperative_hooks(
            job_id, investigation_id, _make_tool_recorder(job_id, investigation_id, case_dir, actor), ctx)
        checkpoint()
        with pathpolicy.job_scope(case_dir, extra_roots=job_roots):
            result = investigator.investigate(
                case_dir,
                question=full_question,
                on_step=on_step,
                on_tool=on_tool,
            )
        checkpoint()

        # Recuperer le rapport redige par l'enqueteur
        report_text = result.get('summary') or ''
        if result.get('report_path') and os.path.isfile(result['report_path']):
            with open(result['report_path'], 'r', encoding='utf-8') as f:
                report_text = f.read()

        os.makedirs(REPORTS_DIR, exist_ok=True)
        report_filename = f"rapport_autonome_{investigation_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(os.path.join(REPORTS_DIR, report_filename), 'w', encoding='utf-8') as f:
            f.write(report_text if report_text.endswith('\n') else report_text + '\n')
        exports_ids = _publish_exports(case_dir, report_filename)

        iocs_count = _persist_results(app, investigation_id, report_text, user_id, username)
        report_entry = custody.safe_record(
            'report_generated', actor, investigation_id=investigation_id, agent='Orchestrateur Lead',
            artifact_ref=report_filename, summary=f'Rapport final : {iocs_count} IoC(s) extrait(s)',
            details={'job_id': job_id}, payload_sha256=custody.sha256_text(report_text))
        if report_entry:
            emit_secure('agent_step', dict(report_entry, job_id=job_id))

        metrics = result.get('metrics') or {}
        job = autonomous_jobs[job_id]
        job.update({
            'status': 'completed',
            'summary': result.get('summary') or '',
            'report_id': report_filename,
            'exports': exports_ids,
            'report_content': report_text,
            'steps': result.get('steps'),
            'tools_executed': metrics.get('tools_executed', len(result.get('tool_calls') or [])),
            'iocs_extracted': iocs_count,
            'metrics': metrics,
            'finished_at': datetime.datetime.now().isoformat(),
        })
        tokens = metrics.get('total_tokens', 0)
        findings = metrics.get('findings', 0)
        verified = metrics.get('findings_verified', 0)
        _emit(job_id, investigation_id,
              f"Enquete close : rapport {report_filename}, {findings} constat(s) "
              f"({verified} verifie(s)), {iocs_count} IoC(s), {tokens} tokens.",
              status='completed', summary=job['summary'], report_id=report_filename,
              exports=exports_ids,
              report_content=report_text, steps=job['steps'],
              tools_executed=job['tools_executed'], metrics=metrics)

    except jobqueue.JobCancelled:
        job = autonomous_jobs.get(job_id, {})
        job.update({'status': 'cancelled', 'state': jobqueue.CANCELLED, 'error': 'cancelled',
                    'finished_at': datetime.datetime.now().isoformat()})
        autonomous_jobs[job_id] = job
        custody.safe_record(
            'investigation_cancelled', username or 'enqueteur-autonome',
            investigation_id=investigation_id, agent='Orchestrateur Lead',
            summary='Investigation autonome annulee', details={'job_id': job_id})
        _emit(job_id, investigation_id, "Investigation autonome annulee.", status='cancelled')

    except Exception as e:
        job = autonomous_jobs.get(job_id, {})
        job.update({'status': 'error', 'error': str(e),
                    'finished_at': datetime.datetime.now().isoformat()})
        autonomous_jobs[job_id] = job
        _emit(job_id, investigation_id, f"Erreur de l'enqueteur autonome : {e}", status='error', error=str(e))

    return dict.get(autonomous_jobs, job_id) or {}
