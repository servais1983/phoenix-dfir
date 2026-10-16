#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes rapports : generation et telechargement des rapports d'enquete."""

import datetime
import json
import os
import re

from flask import Blueprint, g, jsonify, request, send_file

import access
import custody
from auth import require_auth, require_role
from database import get_db, log_audit, dict_from_row, rows_to_list
from helpers import sanitize_report_id, server_error

bp = Blueprint('reports', __name__)

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')

# rapport_<uuid>_..., rapport_autonome_<uuid>_... (+ exports _attack_navigator.json, _iocs.csv)
_REPORT_INV_RE = re.compile(r'^rapport_(?:autonome_)?([0-9a-fA-F-]{36})_')


def report_investigation_id(report_id):
    """Enquete a laquelle appartient un rapport (deduite de son nom), ou None."""
    match = _REPORT_INV_RE.match(report_id or '')
    return match.group(1) if match else None


@bp.route('/api/reports/generate', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def generate_report():
    """Generer un rapport pour une enquete"""
    try:
        data = request.get_json(silent=True) or {}
        investigation_id = data.get('investigation_id')
        report_format = data.get('format', 'html')

        if not investigation_id:
            return jsonify({'error': 'ID d\'enquete requis'}), 400

        denied = access.require_investigation_access(investigation_id)
        if denied:
            return denied

        db = get_db()
        inv_row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()

        investigation_data = dict_from_row(inv_row)

        # Recuperer les IoCs et artefacts pour le rapport
        investigation_data['iocs'] = rows_to_list(
            db.execute("SELECT * FROM iocs WHERE investigation_id=?", (investigation_id,)).fetchall()
        )
        investigation_data['artifacts'] = rows_to_list(
            db.execute("SELECT * FROM artifacts WHERE investigation_id=?", (investigation_id,)).fetchall()
        )
        investigation_data['timeline_events'] = rows_to_list(
            db.execute("SELECT * FROM timeline_events WHERE investigation_id=? ORDER BY timestamp ASC", (investigation_id,)).fetchall()
        )

        # Rapport construit a partir des donnees SQLite. Le module CLI legacy
        # attend un autre format de dossier et appelle un LLM de facon
        # synchrone : il n'est pas utilise par l'API.
        report_lines = [
            f"# Rapport d'Enquete: {investigation_data.get('name', 'Sans nom')}",
            f"\nDate: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Statut: {investigation_data.get('status', 'N/A')}",
            f"\n## Artefacts ({len(investigation_data['artifacts'])})",
        ]
        for art in investigation_data['artifacts']:
            report_lines.append(f"- {art.get('original_filename', art.get('filename', 'N/A'))} (SHA256: {art.get('file_hash_sha256', 'N/A')})")

        report_lines.append(f"\n## IoCs ({len(investigation_data['iocs'])})")
        for ioc in investigation_data['iocs']:
            report_lines.append(f"- [{ioc.get('type', 'N/A')}] {ioc.get('value', 'N/A')} (source: {ioc.get('source', 'N/A')})")

        report_lines.append(f"\n## Timeline ({len(investigation_data['timeline_events'])})")
        for evt in investigation_data['timeline_events']:
            report_lines.append(f"- {evt.get('timestamp', 'N/A')} [{evt.get('severity', 'info')}] {evt.get('event', 'N/A')}")

        report_content = '\n'.join(report_lines)

        # Sauvegarder le rapport
        os.makedirs(REPORTS_DIR, exist_ok=True)
        report_filename = f"rapport_{investigation_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = os.path.join(REPORTS_DIR, report_filename)

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)

        # Sceller l'empreinte du rapport dans la chaine de preuve et l'horodater
        # (RFC 3161, <rapport>.tsr) si PHOENIX_TSA_URL est defini
        seal = custody.seal_report(report_path, report_filename, investigation_id, g.username)

        # Journaliser la generation
        log_audit(
            g.user_id, g.username, 'generate_report',
            target_type='report', target_id=report_filename,
            details=json.dumps({'investigation_id': investigation_id, 'format': report_format}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'report_id': report_filename,
            'format': report_format,
            'sha256': seal['sha256'],
            'custody_seq': seal['custody_seq'],
            'timestamp': seal['timestamp'],
            'message': 'Rapport genere avec succes'
        })

    except Exception as e:
        return server_error(e)


@bp.route('/api/reports/<report_id>/download', methods=['GET'])
@require_auth
def download_report(report_id):
    """Telecharger un rapport (traversee de chemin bloquee, acces a l'enquete verifie)"""
    try:
        clean_id = sanitize_report_id(report_id)
        if not clean_id:
            return jsonify({'error': 'Identifiant de rapport invalide'}), 400

        # Un rapport est rattache a son enquete : non-membre => 404
        inv_id = report_investigation_id(clean_id)
        if inv_id:
            if not access.can_access_investigation(g.user_id, g.role, inv_id):
                return jsonify({'error': 'Rapport non trouve'}), 404
        elif g.role != 'admin':
            return jsonify({'error': 'Rapport non trouve'}), 404

        report_path = os.path.join(REPORTS_DIR, clean_id)

        if not os.path.isfile(report_path):
            return jsonify({'error': 'Rapport non trouve'}), 404

        return send_file(report_path, as_attachment=True)

    except Exception as e:
        return server_error(e)
