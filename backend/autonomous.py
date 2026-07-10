#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enqueteur DFIR autonome cote plateforme.

Pont entre le backend Flask et le module phoenix_dfir_mcp (mcp-server/) :
prepare un dossier de cas a partir des artefacts d'une enquete, lance
l'investigation autonome GitHub Copilot dans le pool de threads et republie
chaque etape en temps reel via WebSocket ('autonomous_progress').

En fin d'enquete : rapport Markdown sauvegarde dans backend/reports/,
IoCs du rapport inseres en base, evenement timeline et journal d'audit.
"""

import datetime
import json
import os
import shutil
import sys
import uuid

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


def copilot_configured():
    """GitHub Copilot est-il utilisable (jeton present) ?"""
    return bool(os.environ.get('PHOENIX_GITHUB_TOKEN') or os.environ.get('GITHUB_TOKEN'))


def copilot_model():
    return os.environ.get('PHOENIX_GITHUB_MODEL', 'openai/gpt-4o-mini')


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
    """Copier les artefacts de l'enquete dans un dossier de cas dedie."""
    case_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'cases', investigation_id)
    os.makedirs(case_dir, exist_ok=True)
    copied = 0
    for art in artifacts:
        src = art.get('file_path') or ''
        if not src or not os.path.isfile(src):
            continue
        dest_name = art.get('original_filename') or art.get('filename') or os.path.basename(src)
        dest = os.path.join(case_dir, os.path.basename(dest_name))
        if not os.path.exists(dest):
            shutil.copy2(src, dest)
        copied += 1
    return case_dir, copied


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

        case_dir, copied = _prepare_case_dir(app, investigation_id, artifacts)
        _emit(job_id, investigation_id,
              f"Dossier de cas prepare : {copied} artefact(s). GitHub Copilot demarre l'enquete...")

        from phoenix_dfir_mcp import investigator
        full_question = f"Enquete '{inv_name}'."
        if inv and inv['description']:
            full_question += f" Contexte : {inv['description']}"
        if question:
            full_question += f" {question}"

        result = investigator.investigate(
            case_dir,
            question=full_question,
            on_step=lambda msg: _emit(job_id, investigation_id, msg),
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
