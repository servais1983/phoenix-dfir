#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Route mapping MITRE ATT&CK : techniques et tactiques associees aux IoCs."""

from flask import Blueprint, jsonify

import access
from auth import require_auth
from database import get_db, rows_to_list
from helpers import server_error
from mitre import get_attack_for_ioc

bp = Blueprint('mitre_attack', __name__)


@bp.route('/api/investigations/<investigation_id>/mitre', methods=['GET'])
@require_auth
def get_mitre_mapping(investigation_id):
    """Retourner le mapping MITRE ATT&CK pour une enquete"""
    try:
        denied = access.require_investigation_access(investigation_id)
        if denied:
            return denied
        db = get_db()

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
        return server_error(e)
