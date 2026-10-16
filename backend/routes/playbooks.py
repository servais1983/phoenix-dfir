#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Playbooks de remediation avec validation humaine en un clic.

GET  /api/playbooks/templates              catalogue (tout utilisateur authentifie)
POST /api/playbooks/render                 apercu d'un script (aucune ecriture)
POST /api/playbooks/propose                proposer (admin / analyst membre) -> WAITING_APPROVAL
POST /api/remediation/<id>/decision        decision (route existante, console.py)
GET  /api/remediation/<id>/script          telecharger un script APPROUVE (membres)

Phoenix n'execute JAMAIS ces scripts : l'approbation autorise l'equipe a les
jouer avec ses propres outils ; script et rollback sont scelles (SHA-256) dans
la chaine de preuve a la proposition et a la decision.
"""

import json

from flask import Blueprint, Response, g, jsonify, request

import access
import custody
import playbooks
from auth import require_auth, require_role
from database import log_audit
from extensions import emit_secure

bp = Blueprint('playbooks', __name__)

_SEVERITIES = ('critical', 'high', 'medium', 'low')
_PARTS = {'script': 'script', 'rollback': 'rollback', 'prechecks': 'prechecks'}
_MIME = {'bash': 'text/x-shellscript', 'powershell': 'text/plain', 'csv': 'text/csv'}
_EXT = {'bash': 'sh', 'powershell': 'ps1', 'csv': 'csv'}


def _render_or_error(data):
    template_id = data.get('template_id')
    params = data.get('params') or {}
    try:
        return playbooks.render(template_id, params), None
    except playbooks.PlaybookError as e:
        return None, (jsonify({'error': 'Parametres de playbook invalides', 'fields': e.errors}), 400)


@bp.route('/api/playbooks/templates', methods=['GET'])
@require_auth
def list_templates():
    return jsonify({'items': playbooks.list_templates(), 'executed_by_phoenix': False,
                    'notice': playbooks.HEADER_NOTICE})


@bp.route('/api/playbooks/render', methods=['POST'])
@require_auth
def render_preview():
    rendered, error = _render_or_error(request.get_json(silent=True) or {})
    if error:
        return error
    return jsonify(rendered)


@bp.route('/api/playbooks/propose', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def propose():
    data = request.get_json(silent=True) or {}
    investigation_id = data.get('investigation_id')
    if not investigation_id:
        return jsonify({'error': "ID d'enquete requis"}), 400
    denied = access.require_investigation_access(investigation_id, write=True)
    if denied:
        return denied
    rendered, error = _render_or_error(data)
    if error:
        return error
    reason = (data.get('reason') or '').strip()[:1000] or rendered['title']
    severity = data.get('severity') if data.get('severity') in _SEVERITIES else 'high'
    mitre = str(data.get('mitre') or rendered['mitre'])[:120]
    job_id = str(data.get('job_id') or '')[:64] or None
    action = custody.create_remediation(
        rendered['target_host'], rendered['summary'], reason, investigation_id=investigation_id,
        job_id=job_id, mitre=mitre, severity=severity, requested_by=g.username, playbook=rendered)
    log_audit(g.user_id, g.username, 'playbook_proposed', target_type='remediation',
              target_id=action['id'],
              details=json.dumps({'investigation_id': investigation_id,
                                  'playbook_id': rendered['template_id'],
                                  'script_sha256': action.get('script_sha256')}),
              ip_address=request.remote_addr)
    sealed = action.pop('custody_entry', None)
    if sealed:
        emit_secure('agent_step', sealed)
    emit_secure('hitl_required', action)
    return jsonify(action), 201


@bp.route('/api/remediation/<action_id>/script', methods=['GET'])
@require_auth
def download_script(action_id):
    action = custody.get_remediation(action_id)
    inv_id = (action or {}).get('investigation_id')
    if not action or not (g.role == 'admin' or (inv_id and access.can_access_investigation(
            g.user_id, g.role, inv_id))):
        return jsonify({'error': 'Action introuvable'}), 404
    if not action.get('playbook_id'):
        return jsonify({'error': "Cette action n'a pas de playbook"}), 404
    if action['status'] != 'APPROVED':
        return jsonify({'error': 'Script telechargeable uniquement apres approbation',
                        'status': action['status']}), 409
    part = request.args.get('part', 'script')
    if part not in _PARTS:
        return jsonify({'error': f'part invalide. Valeurs: {list(_PARTS)}'}), 400
    content = action.get(_PARTS[part]) or ''
    lang = action.get('script_language') or 'bash'
    filename = f"{action['id']}_{action['playbook_id']}_{part}.{_EXT.get(lang, 'txt')}"
    log_audit(g.user_id, g.username, 'playbook_script_download', target_type='remediation',
              target_id=action['id'], details=json.dumps({'part': part}),
              ip_address=request.remote_addr)
    resp = Response(content, mimetype=_MIME.get(lang, 'text/plain'))
    resp.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    resp.headers['X-Phoenix-Script-SHA256'] = custody.sha256_text(content)
    resp.headers['X-Phoenix-Executed-By-Phoenix'] = 'false'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp
