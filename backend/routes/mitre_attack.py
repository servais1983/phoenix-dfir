#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Route mapping MITRE ATT&CK : techniques et tactiques associees aux IoCs."""

from flask import Blueprint, jsonify

from auth import require_auth
from database import get_db, rows_to_list
from mitre import get_attack_for_ioc

bp = Blueprint('mitre_attack', __name__)


@bp.route('/api/investigations/<investigation_id>/mitre', methods=['GET'])
@require_auth
def get_mitre_mapping(investigation_id):
    """Retourner le mapping MITRE ATT&CK pour une enquete"""
    try:
        db = get_db()
        inv_row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not inv_row:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        # Mapper les IoCs vers les techniques ATT&CK
        iocs = rows_to_list(
            db.execute("SELECT type, value FROM iocs WHERE investigation_id=?", (investigation_id,)).fetchall()
        )

        techniques = {}
        for ioc in iocs:
            mappings = get_attack_for_ioc(ioc['type'])
            for m in mappings:
                tech_id = m['technique']
                if tech_id not in techniques:
                    techniques[tech_id] = {
                        'technique': tech_id,
                        'name': m['name'],
                        'tactic': m['tactic'],
                        'indicators': []
                    }
                techniques[tech_id]['indicators'].append({
                    'type': ioc['type'],
                    'value': ioc['value']
                })

        # Regrouper par tactique
        by_tactic = {}
        for tech in techniques.values():
            tactic = tech['tactic']
            if tactic not in by_tactic:
                by_tactic[tactic] = []
            by_tactic[tactic].append(tech)

        return jsonify({
            'investigation_id': investigation_id,
            'techniques': list(techniques.values()),
            'by_tactic': by_tactic,
            'total_techniques': len(techniques)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
