#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Route export STIX 2.1 : bundle complet (identity, indicators, report)."""

import datetime
import uuid

from flask import Blueprint, jsonify

from auth import require_auth
from database import get_db, dict_from_row, rows_to_list
from helpers import build_stix_pattern

bp = Blueprint('stix', __name__)


@bp.route('/api/investigations/<investigation_id>/export/stix', methods=['GET'])
@require_auth
def export_stix(investigation_id):
    """Exporter les IoCs d'une enquete au format STIX 2.1 (bundle JSON)"""
    try:
        db = get_db()
        inv_row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not inv_row:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        investigation = dict_from_row(inv_row)
        iocs = rows_to_list(
            db.execute("SELECT * FROM iocs WHERE investigation_id=?", (investigation_id,)).fetchall()
        )

        # Construire le bundle STIX 2.1
        stix_objects = []
        now = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')

        # Objet identite pour la source
        identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_URL, 'phoenix-dfir')}"
        stix_objects.append({
            'type': 'identity',
            'spec_version': '2.1',
            'id': identity_id,
            'created': now,
            'modified': now,
            'name': 'Phoenix DFIR',
            'identity_class': 'system'
        })

        # Objet rapport representant l'investigation
        report_id_stix = f"report--{investigation_id}"
        indicator_refs = []

        # Mapping des types IoC vers les patterns STIX
        for ioc in iocs:
            ioc_type = ioc['type']
            ioc_value = ioc['value']
            indicator_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, f'{investigation_id}:{ioc_type}:{ioc_value}')}"
            indicator_refs.append(indicator_id)

            # Construire le pattern STIX selon le type d'IoC
            pattern = build_stix_pattern(ioc_type, ioc_value)
            if not pattern:
                continue

            # Mapper la severite vers un score de confiance
            severity_confidence = {
                'critical': 95, 'high': 85, 'medium': 65,
                'low': 40, 'info': 20, 'unknown': 50
            }
            confidence = severity_confidence.get(ioc.get('severity', 'unknown'), 50)

            indicator = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': indicator_id,
                'created': ioc.get('created_at', now),
                'modified': ioc.get('created_at', now),
                'name': f"{ioc_type}: {ioc_value}",
                'description': f"IoC detecte dans l'enquete {investigation.get('name', investigation_id)}. Source: {ioc.get('source', 'N/A')}",
                'indicator_types': ['malicious-activity'],
                'pattern': pattern,
                'pattern_type': 'stix',
                'valid_from': ioc.get('created_at', now),
                'confidence': confidence,
                'created_by_ref': identity_id
            }

            # Ajouter les labels de severite
            if ioc.get('severity') and ioc['severity'] != 'unknown':
                indicator['labels'] = [f"severity:{ioc['severity']}"]

            stix_objects.append(indicator)

        # Ajouter le rapport
        stix_objects.append({
            'type': 'report',
            'spec_version': '2.1',
            'id': report_id_stix,
            'created': investigation.get('created_at', now),
            'modified': investigation.get('updated_at', now),
            'name': investigation.get('name', 'Investigation Phoenix DFIR'),
            'description': investigation.get('description', ''),
            'report_types': ['threat-report'],
            'published': now,
            'object_refs': [identity_id] + indicator_refs,
            'created_by_ref': identity_id
        })

        # Bundle STIX 2.1
        stix_bundle = {
            'type': 'bundle',
            'id': f"bundle--{uuid.uuid5(uuid.NAMESPACE_URL, investigation_id)}",
            'objects': stix_objects
        }

        return jsonify(stix_bundle)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
