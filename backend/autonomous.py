#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enqueteur DFIR autonome cote plateforme.

Pont entre le backend Flask et le module phoenix_dfir_mcp (mcp-server/) :
prepare un dossier de cas a partir des artefacts d'une enquete, lance
l'investigation autonome GitHub Copilot dans le pool de threads et republie
chaque etape en temps reel via WebSocket ('autonomous_progress').

Chaque outil execute est scelle dans la chaine de preuve (custody.py) et
republie en direct sur la console SOC ('agent_step') ; les remediations
proposees par l'enqueteur deviennent des demandes de validation humaine
('hitl_required').

En fin d'enquete : rapport Markdown sauvegarde dans backend/reports/,
IoCs du rapport inseres en base, evenement timeline et journal d'audit.
"""

import datetime
import json
import os
import shutil
import sys
import uuid

import custody
import evidence_vault
from database import get_db, log_audit
from extensions import executor, socketio
from parsers import extract_iocs

# Rendre phoenix_dfir_mcp (mcp-server/) importable
_MCP_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'mcp-server')
if _MCP_DIR not in sys.path:
    sys.path.insert(0, _MCP_DIR)

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')

# Etat des jobs autonomes en cours / termines (memoire process)
autonomous_jobs = {}


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


def start_job(app, investigation_id, question=None, user_id=None, username=None):
    """Demarrer une investigation autonome en arriere-plan. Retourne le job_id."""
    job_id = str(uuid.uuid4())
    autonomous_jobs[job_id] = {
        'job_id': job_id,
        'investigation_id': investigation_id,
        'status': 'running',
        'messages': [],
        'started_at': datetime.datetime.now().isoformat(),
    }
    executor.submit(_run_job, app, job_id, investigation_id, question, user_id, username)
    return job_id


def _emit(job_id, investigation_id, message, **extra):
    job = autonomous_jobs.get(job_id)
    if job is not None:
        job['messages'].append(message)
    payload = {'job_id': job_id, 'investigation_id': investigation_id, 'message': message}
    payload.update(extra)
    socketio.emit('autonomous_progress', payload)


def _prepare_case_dir(app, investigation_id, artifacts):
    """Rassembler les artefacts de l'enquete dans un dossier de cas dedie.

    Les evidences du coffre (lecture seule, souvent volumineuses : dumps RAM)
    sont referencees par lien symbolique plutot que copiees. Retourne
    (case_dir, nombre, coffre_utilise).
    """
    case_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'cases', investigation_id)
    os.makedirs(case_dir, exist_ok=True)
    copied = 0
    uses_vault = False
    for art in artifacts:
        src = art.get('file_path') or ''
        if not src or not os.path.isfile(src):
            continue
        dest_name = art.get('original_filename') or art.get('filename') or os.path.basename(src)
        dest = os.path.join(case_dir, os.path.basename(dest_name))
        in_vault = evidence_vault.contains(src)
        uses_vault = uses_vault or in_vault
        if not os.path.lexists(dest):
            if in_vault:
                try:
                    os.symlink(src, dest)
                except OSError:
                    shutil.copy2(src, dest)
            else:
                shutil.copy2(src, dest)
        copied += 1
    return case_dir, copied, uses_vault


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
    """Resume, technique MITRE et severite d'un appel d'outil (console SOC)."""
    if not isinstance(result, dict):
        return 'Outil execute', '', 'info'
    if result.get('error'):
        return f"Erreur : {result['error']}"[:500], '', 'low'
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
    preuve, alimente la console SOC et ouvre les demandes de validation humaine."""
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
            socketio.emit('agent_step', dict(entry, job_id=job_id))
        if name == 'propose_remediation' and isinstance(result, dict) and result.get('proposed'):
            proposed = result['proposed']
            action = custody.create_remediation(
                proposed['target_host'], proposed['command'], proposed['reason'],
                investigation_id=investigation_id, job_id=job_id, mitre=proposed.get('mitre', ''),
                severity=proposed.get('severity', 'high'), requested_by=actor,
                case_dir=case_dir, case_remediation_id=proposed.get('id'))
            sealed = action.pop('custody_entry', None)
            if sealed:
                socketio.emit('agent_step', dict(sealed, job_id=job_id))
            socketio.emit('hitl_required', action)
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


def _run_job(app, job_id, investigation_id, question, user_id, username):
    try:
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
        if uses_vault:
            # Les liens symboliques du cas pointent vers le coffre (lecture seule)
            pathpolicy.add_root(evidence_vault.vault_dir())
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

        result = investigator.investigate(
            case_dir,
            question=full_question,
            on_step=lambda msg: _emit(job_id, investigation_id, msg),
            on_tool=_make_tool_recorder(job_id, investigation_id, case_dir, actor),
        )

        # Recuperer le rapport redige par l'enqueteur
        report_text = result.get('summary') or ''
        if result.get('report_path') and os.path.isfile(result['report_path']):
            with open(result['report_path'], 'r', encoding='utf-8') as f:
                report_text = f.read()

        os.makedirs(REPORTS_DIR, exist_ok=True)
        report_filename = f"rapport_autonome_{investigation_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        with open(os.path.join(REPORTS_DIR, report_filename), 'w', encoding='utf-8') as f:
            f.write(report_text if report_text.endswith('\n') else report_text + '\n')

        iocs_count = _persist_results(app, investigation_id, report_text, user_id, username)
        report_entry = custody.safe_record(
            'report_generated', actor, investigation_id=investigation_id, agent='Orchestrateur Lead',
            artifact_ref=report_filename, summary=f'Rapport final : {iocs_count} IoC(s) extrait(s)',
            details={'job_id': job_id}, payload_sha256=custody.sha256_text(report_text))
        if report_entry:
            socketio.emit('agent_step', dict(report_entry, job_id=job_id))

        metrics = result.get('metrics') or {}
        job = autonomous_jobs[job_id]
        job.update({
            'status': 'completed',
            'summary': result.get('summary') or '',
            'report_id': report_filename,
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
              report_content=report_text, steps=job['steps'],
              tools_executed=job['tools_executed'], metrics=metrics)

    except Exception as e:
        job = autonomous_jobs.get(job_id, {})
        job.update({'status': 'error', 'error': str(e),
                    'finished_at': datetime.datetime.now().isoformat()})
        autonomous_jobs[job_id] = job
        _emit(job_id, investigation_id, f"Erreur de l'enqueteur autonome : {e}", status='error', error=str(e))
