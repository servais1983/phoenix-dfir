#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Console Enqueteur DFIR : chaine de preuve, validation humaine, coffre de preuves et
etat de l'essaim d'agents (outils DFIR + LLM)."""

import datetime
import json
import os

from flask import Blueprint, g, jsonify, request

import autonomous
import custody
import evidence_vault
from auth import require_auth, require_role
from database import get_db, log_audit
from extensions import emit_secure
from helpers import compute_file_hashes

bp = Blueprint('console', __name__)


@bp.route('/api/console/status', methods=['GET'])
@require_auth
def console_status():
    """Etat des agents specialises et de leurs outils."""
    from integrations.sigma_connector import SigmaConnector
    from phoenix_dfir_mcp import disk, hayabusa, volatility, zimmermann

    ez = zimmermann.status()
    vol = volatility.status()
    hay = hayabusa.status()
    dsk = disk.status()
    vault = evidence_vault.vault_dir()
    pending = custody.list_remediations(status='WAITING_APPROVAL')
    return jsonify({
        'llm': {
            'provider': autonomous.llm_provider(),
            'label': autonomous.llm_label(),
            'model': autonomous.copilot_model(),
            'configured': autonomous.copilot_configured(),
        },
        'agents': [
            {'id': 'lead', 'name': 'Orchestrateur Lead', 'tool': f"{autonomous.llm_label()} — {autonomous.copilot_model()}",
             'ready': autonomous.copilot_configured()},
            {'id': 'triage', 'name': 'Agent Triage & Collecte', 'tool': 'Inventaire, hashes, extraction IoCs',
             'ready': True},
            {'id': 'disk', 'name': 'Agent Disque & EVTX',
             'tool': (f"Sigma ({len(SigmaConnector.BUILTIN_RULES)} regles)"
                      f"{' + Hayabusa' if hay['available'] else ''}"
                      f" + EZ Tools {len(ez['available'])}/{len(ez['available']) + len(ez['missing'])}"),
             'ready': True},
            {'id': 'memory', 'name': 'Agent Memoire', 'tool': 'Volatility 3', 'ready': vol['available']},
            {'id': 'disk_image', 'name': 'Agent Images disque',
             'tool': 'Sleuth Kit : E01/raw/VMDK/VHD, supprimes, MACB', 'ready': dsk['available']},
            {'id': 'intel', 'name': 'Agent Threat Intel & Correlation',
             'tool': 'Super-timeline FTS5, MITRE ATT&CK, VirusTotal', 'ready': True},
            {'id': 'quality', 'name': 'Controle qualite & contre-analyse',
             'tool': '5 portes qualite, audits de couverture, hypotheses alternatives', 'ready': True},
        ],
        'tools': {
            'volatility': {'available': vol['available'], 'command': vol['command']},
            'hayabusa': {'available': hay['available'], 'binary': hay['binary']},
            'sleuthkit': {'available': dsk['available'], 'formats': dsk['image_formats']},
            'zimmermann': {'available': sorted(ez['available']), 'missing': ez['missing']},
            'sigma_rules': len(SigmaConnector.BUILTIN_RULES),
            'virustotal': bool(os.environ.get('API_KEY_VT')),
        },
        'vault': {
            'dir': vault,
            'exists': os.path.isdir(vault),
            'read_only': evidence_vault.is_read_only(vault),
        },
        'custody': custody.stats(),
        'remediations_pending': len(pending),
    })


# ============================================================================
# Chaine de preuve
# ============================================================================

@bp.route('/api/custody', methods=['GET'])
@require_auth
def custody_entries():
    investigation_id = request.args.get('investigation_id') or None
    limit = max(1, min(request.args.get('limit', 500, type=int), 2000))
    after_seq = max(0, request.args.get('after_seq', 0, type=int))
    entries = custody.list_entries(investigation_id, limit=limit, after_seq=after_seq)
    return jsonify({'items': entries, 'total': len(entries)})


@bp.route('/api/custody/verify', methods=['GET'])
@require_auth
def custody_verify():
    result = custody.verify_chain()
    log_audit(g.user_id, g.username, 'custody_verify', target_type='custody_chain',
              details=json.dumps({'valid': result['valid'], 'entries': result['entries']}),
              ip_address=request.remote_addr)
    return jsonify(result)


# ============================================================================
# Validation humaine des remediations (Human-in-the-Loop)
# ============================================================================

@bp.route('/api/remediation', methods=['GET'])
@require_auth
def remediation_list():
    status = request.args.get('status') or None
    if status and status not in custody.REMEDIATION_STATUSES:
        return jsonify({'error': f'Statut invalide. Valeurs: {list(custody.REMEDIATION_STATUSES)}'}), 400
    items = custody.list_remediations(status=status,
                                      investigation_id=request.args.get('investigation_id') or None)
    return jsonify({'items': items, 'total': len(items)})


@bp.route('/api/remediation/<action_id>/decision', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def remediation_decide(action_id):
    data = request.get_json(silent=True) or {}
    decision = data.get('decision')
    if decision not in ('approve', 'reject'):
        return jsonify({'error': "decision doit valoir 'approve' ou 'reject'"}), 400
    note = (data.get('note') or '').strip()[:1000]

    action, error = custody.decide_remediation(action_id, decision == 'approve', g.username, note)
    if error == 'not_found':
        return jsonify({'error': 'Action introuvable'}), 404
    if error == 'already_decided':
        return jsonify({'error': f"Action deja traitee ({action['status']})", 'action': action}), 409

    # Refleter la decision dans la memoire du cas (annexe du rapport)
    if action.get('case_dir') and action.get('case_remediation_id') and os.path.isdir(action['case_dir']):
        try:
            from phoenix_dfir_mcp import memory
            memory.set_remediation_status(action['case_dir'], action['case_remediation_id'],
                                          'approved' if decision == 'approve' else 'rejected')
        except Exception:
            pass

    log_audit(g.user_id, g.username, f'remediation_{decision}', target_type='remediation',
              target_id=action_id,
              details=json.dumps({'target_host': action['target_host'], 'command': action['command'],
                                  'note': note}),
              ip_address=request.remote_addr)
    sealed = action.pop('custody_entry', None)
    if sealed:
        emit_secure('agent_step', sealed)
    emit_secure('hitl_resolved', action)
    return jsonify(action)


# ============================================================================
# Coffre de preuves (lecture seule)
# ============================================================================

@bp.route('/api/evidence-vault', methods=['GET'])
@require_auth
def vault_listing():
    return jsonify(evidence_vault.list_files())


@bp.route('/api/evidence-vault/import', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def vault_import():
    """Rattacher des evidences du coffre a une enquete (sans copie) : empreintes
    calculees et acquisition scellee dans la chaine de preuve."""
    data = request.get_json(silent=True) or {}
    investigation_id = data.get('investigation_id')
    paths = data.get('paths') or []
    if not investigation_id:
        return jsonify({'error': "ID d'enquete requis"}), 400
    if not isinstance(paths, list) or not paths:
        return jsonify({'error': 'paths doit etre une liste non vide'}), 400

    db = get_db()
    if not db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone():
        return jsonify({'error': 'Enquete non trouvee'}), 404

    imported, rejected = [], []
    for rel in paths[:200]:
        full = evidence_vault.resolve(rel)
        if not full:
            rejected.append({'path': rel, 'error': 'Hors du coffre ou introuvable'})
            continue
        existing = db.execute(
            "SELECT id FROM artifacts WHERE investigation_id=? AND file_path=?",
            (investigation_id, full)).fetchone()
        if existing:
            rejected.append({'path': rel, 'error': 'Deja rattache a cette enquete'})
            continue
        md5, sha1, sha256 = compute_file_hashes(full)
        size = os.path.getsize(full)
        name = os.path.basename(full)
        cursor = db.execute(
            "INSERT INTO artifacts (investigation_id, filename, original_filename, file_path, file_size, "
            "file_hash_md5, file_hash_sha1, file_hash_sha256, file_type, uploaded_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (investigation_id, name, name, full, size, md5, sha1, sha256,
             os.path.splitext(name)[1].lower(), g.user_id))
        # Valider avant de sceller : la chaine de preuve prend son propre verrou d'ecriture
        db.commit()
        entry = custody.safe_record(
            'evidence_acquired', g.username, investigation_id=investigation_id,
            agent='Agent Triage & Collecte', artifact_ref=f'coffre:{rel}',
            summary=f'Evidence rattachee depuis le coffre (lecture seule), {size} octets',
            details={'md5': md5, 'sha1': sha1, 'size': size, 'source': 'evidence_vault'},
            payload_sha256=sha256)
        imported.append({'path': rel, 'artifact_id': cursor.lastrowid, 'sha256': sha256, 'size': size,
                         'custody_hash': entry['entry_hash'] if entry else None})

    if imported:
        db.execute("UPDATE investigations SET updated_at=? WHERE id=?",
                   (datetime.datetime.now().isoformat(), investigation_id))
    db.commit()
    log_audit(g.user_id, g.username, 'evidence_vault_import', target_type='investigation',
              target_id=investigation_id,
              details=json.dumps({'imported': len(imported), 'rejected': len(rejected)}),
              ip_address=request.remote_addr)
    return jsonify({'imported': imported, 'rejected': rejected})
