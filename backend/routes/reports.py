#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes rapports : generation et telechargement des rapports d'enquete."""

import datetime
import json
import os

from flask import Blueprint, g, jsonify, request, send_file

from auth import require_auth
from database import get_db, log_audit, dict_from_row, rows_to_list
from helpers import sanitize_report_id
import phoenix_compat

bp = Blueprint('reports', __name__)

REPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'reports')


@bp.route('/api/reports/generate', methods=['POST'])
@require_auth
def generate_report():
    """Generer un rapport pour une enquete"""
    try:
        data = request.get_json()
        investigation_id = data.get('investigation_id')
        report_format = data.get('format', 'html')

        if not investigation_id:
            return jsonify({'error': 'ID d\'enquete requis'}), 400

        db = get_db()
        inv_row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not inv_row:
            return jsonify({'error': 'Enquete non trouvee'}), 404

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

        # Generer le rapport
        if phoenix_compat.PHOENIX_AVAILABLE:
            resume_executif = phoenix_compat.generer_resume_executif_ia(investigation_data)
            report_content = phoenix_compat.creer_contenu_rapport(investigation_data, resume_executif)
        else:
            # Rapport statique construit a partir des donnees SQLite
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
        report_filename = f"rapport_{investigation_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = os.path.join(REPORTS_DIR, report_filename)

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)

        # Journaliser la generation
        log_audit(
            g.user_id, g.username, 'generate_report',
            target_type='report', target_id=report_filename,
            details=json.dumps({'investigation_id': investigation_id, 'format': report_format}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'report_id': report_filename,
            'report_path': report_path,
            'format': report_format,
            'message': 'Rapport genere avec succes'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/reports/<report_id>/download', methods=['GET'])
@require_auth
def download_report(report_id):
    """Telecharger un rapport (avec protection contre la traversee de chemin)"""
    try:
        clean_id = sanitize_report_id(report_id)
        if not clean_id:
            return jsonify({'error': 'Identifiant de rapport invalide'}), 400

        report_path = os.path.join(REPORTS_DIR, clean_id)

        if not os.path.exists(report_path):
            return jsonify({'error': 'Rapport non trouve'}), 404

        return send_file(report_path, as_attachment=True)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
