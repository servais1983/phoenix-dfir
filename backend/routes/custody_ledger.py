#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Chaine de preuve probante : arbre de Merkle, preuves d'inclusion,
checkpoints signes et horodates (RFC 3161), bundle d'export.

GET  /api/custody/merkle?investigation_id=      racine + nombre de feuilles (+ dernier checkpoint)
GET  /api/custody/proof/<seq>?investigation_id= preuve d'inclusion d'une entree
GET  /api/custody/checkpoints?investigation_id= checkpoints d'un perimetre
POST /api/custody/checkpoint                    creer un checkpoint (admin / analyst membre)
GET  /api/custody/checkpoints/<id>/verify       reverifier un checkpoint
GET  /api/investigations/<id>/custody-bundle    export zip (membres de l'enquete)

Sans investigation_id, le perimetre est le registre complet : reserve aux admins.
"""

import json
import re

from flask import Blueprint, Response, g, jsonify, request

import access
import custody
import custody_bundle
from auth import require_auth, require_role
from database import log_audit
from extensions import emit_secure

bp = Blueprint('custody_ledger', __name__)


def _scope_denied(investigation_id, write=False):
    """Controle d'acces au perimetre (enquete, ou registre global = admin)."""
    if investigation_id:
        return access.require_investigation_access(investigation_id, write=write)
    if g.role != 'admin':
        return jsonify({'error': "investigation_id requis (registre global reserve aux admins)"}), 400
    return None


@bp.route('/api/custody/merkle', methods=['GET'])
@require_auth
def merkle_root():
    investigation_id = request.args.get('investigation_id') or None
    denied = _scope_denied(investigation_id)
    if denied:
        return denied
    return jsonify(custody.merkle_summary(investigation_id))


@bp.route('/api/custody/proof/<int:seq>', methods=['GET'])
@require_auth
def merkle_inclusion_proof(seq):
    entry = custody.get_entry(seq)
    entry_inv = (entry or {}).get('investigation_id')
    readable = entry is not None and (
        g.role == 'admin' or (entry_inv and access.can_access_investigation(g.user_id, g.role, entry_inv)))
    if not readable:
        return jsonify({'error': 'Entree introuvable'}), 404
    # Perimetre : l'enquete de l'entree par defaut ; ?scope=global pour un admin
    scope_global = request.args.get('scope') == 'global' or not entry_inv
    if scope_global and g.role != 'admin':
        return jsonify({'error': 'Entree introuvable'}), 404
    proof = custody.merkle_proof(seq, None if scope_global else entry_inv)
    if not proof:
        return jsonify({'error': 'Entree introuvable'}), 404
    return jsonify(proof)


@bp.route('/api/custody/checkpoints', methods=['GET'])
@require_auth
def checkpoints_list():
    investigation_id = request.args.get('investigation_id') or None
    denied = _scope_denied(investigation_id)
    if denied:
        return denied
    items = custody.list_checkpoints(investigation_id, limit=max(1, min(request.args.get(
        'limit', 50, type=int), 500)))
    return jsonify({'items': items, 'total': len(items), 'timestamping': custody.timestamp_status()})


@bp.route('/api/custody/checkpoint', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def checkpoint_create():
    data = request.get_json(silent=True) or {}
    investigation_id = data.get('investigation_id') or None
    denied = _scope_denied(investigation_id, write=True)
    if denied:
        return denied
    cp = custody.create_checkpoint(investigation_id, actor=g.username)
    log_audit(g.user_id, g.username, 'custody_checkpoint', target_type='custody_chain',
              target_id=str(cp['id']),
              details=json.dumps({'investigation_id': investigation_id, 'root': cp['root'],
                                  'tree_size': cp['tree_size'], 'tsa_status': cp['tsa_status']}),
              ip_address=request.remote_addr)
    if cp.get('ledger_seq'):
        entry = custody.get_entry(cp['ledger_seq'])
        if entry:
            emit_secure('agent_step', entry)
    return jsonify(cp), 201


@bp.route('/api/custody/checkpoints/<int:checkpoint_id>/verify', methods=['GET'])
@require_auth
def checkpoint_verify(checkpoint_id):
    cp = custody.get_checkpoint(checkpoint_id)
    inv_id = (cp or {}).get('investigation_id')
    if not cp or not (g.role == 'admin' or (inv_id and access.can_access_investigation(
            g.user_id, g.role, inv_id))):
        return jsonify({'error': 'Checkpoint introuvable'}), 404
    return jsonify(custody.verify_checkpoint(cp))


_SAFE_ID = re.compile(r'[^A-Za-z0-9_-]')


@bp.route('/api/investigations/<investigation_id>/custody-bundle', methods=['GET'])
@require_auth
def custody_bundle_export(investigation_id):
    denied = access.require_investigation_access(investigation_id)
    if denied:
        return denied
    from routes.reports import REPORTS_DIR, report_investigation_id
    # Un analyste / admin fige d'abord l'etat courant (checkpoint signe et
    # horodate) ; un viewer exporte l'etat existant sans rien ecrire.
    checkpoint = None
    if access.can_write_investigation(g.user_id, g.role, investigation_id):
        checkpoint = custody.create_checkpoint(investigation_id, actor=g.username)
    data = custody_bundle.build(investigation_id, g.username, REPORTS_DIR, report_investigation_id)
    log_audit(g.user_id, g.username, 'custody_bundle_export', target_type='investigation',
              target_id=investigation_id,
              details=json.dumps({'size': len(data),
                                  'checkpoint_id': checkpoint['id'] if checkpoint else None}),
              ip_address=request.remote_addr)
    resp = Response(data, mimetype='application/zip')
    name = _SAFE_ID.sub('_', str(investigation_id))[:64]
    resp.headers['Content-Disposition'] = f'attachment; filename="custody_bundle_{name}.zip"'
    resp.headers['X-Phoenix-Bundle-SHA256'] = custody.hashlib.sha256(data).hexdigest()
    return resp
