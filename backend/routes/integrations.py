#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes integrations : gestion des connecteurs Threat Intelligence."""

import datetime
import json

from flask import Blueprint, g, jsonify, request

from auth import require_auth, require_role
from database import get_db, log_audit, dict_from_row, rows_to_list
from extensions import VALID_IOC_TYPES
from integrations import registry as int_registry

bp = Blueprint('integrations_api', __name__)


@bp.route('/api/integrations', methods=['GET'])
@require_auth
def list_integrations():
    """Lister tous les connecteurs disponibles avec leur statut"""
    try:
        db = get_db()
        connectors = int_registry.list_connectors()

        # Enrichir avec la config sauvegardee en base
        for connector in connectors:
            row = db.execute(
                "SELECT enabled, last_test_status, last_test_message, last_test_at FROM integration_configs WHERE connector_id=?",
                (connector['id'],)
            ).fetchone()
            if row:
                connector['enabled'] = bool(row['enabled'])
                connector['last_test_status'] = row['last_test_status']
                connector['last_test_message'] = row['last_test_message']
                connector['last_test_at'] = row['last_test_at']
            else:
                connector['enabled'] = False
                connector['last_test_status'] = None

        return jsonify({'integrations': connectors, 'total': len(connectors)})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/integrations/<connector_id>', methods=['GET'])
@require_auth
def get_integration(connector_id):
    """Recuperer la configuration d'un connecteur"""
    try:
        cls = int_registry.get_connector_class(connector_id)
        if not cls:
            return jsonify({'error': 'Connecteur inconnu'}), 404

        connector_info = cls(config={}).to_dict()

        db = get_db()
        row = db.execute(
            "SELECT * FROM integration_configs WHERE connector_id=?", (connector_id,)
        ).fetchone()

        if row:
            connector_info['enabled'] = bool(row['enabled'])
            connector_info['last_test_status'] = row['last_test_status']
            connector_info['last_test_message'] = row['last_test_message']
            connector_info['last_test_at'] = row['last_test_at']
            # Retourner la config masquee (pas les secrets en clair)
            saved_config = json.loads(row['config'] or '{}')
            masked = {}
            for key, val in saved_config.items():
                schema_item = next((s for s in connector_info.get('config_schema', []) if s['key'] == key), None)
                if schema_item and schema_item.get('type') == 'password' and val:
                    masked[key] = '***' + val[-4:] if len(val) > 4 else '****'
                else:
                    masked[key] = val
            connector_info['config'] = masked
        else:
            connector_info['enabled'] = False
            connector_info['config'] = {}

        return jsonify(connector_info)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/integrations/<connector_id>', methods=['PUT'])
@require_auth
@require_role('admin')
def update_integration(connector_id):
    """Configurer un connecteur (admin uniquement)"""
    try:
        cls = int_registry.get_connector_class(connector_id)
        if not cls:
            return jsonify({'error': 'Connecteur inconnu'}), 404

        body = request.get_json()
        if not body:
            return jsonify({'error': 'Donnees requises'}), 400

        db = get_db()
        now = datetime.datetime.now().isoformat()

        new_config = body.get('config', {})
        enabled = body.get('enabled', False)

        # Fusionner avec la config existante (pour ne pas ecraser les mots de passe masques)
        existing = db.execute("SELECT config FROM integration_configs WHERE connector_id=?", (connector_id,)).fetchone()
        if existing:
            old_config = json.loads(existing['config'] or '{}')
            for key, val in new_config.items():
                if val and not val.startswith('***'):
                    old_config[key] = val
            final_config = old_config
        else:
            final_config = {k: v for k, v in new_config.items() if v and not v.startswith('***')}

        db.execute("""
            INSERT INTO integration_configs (connector_id, enabled, config, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(connector_id) DO UPDATE SET
                enabled=excluded.enabled, config=excluded.config, updated_at=excluded.updated_at
        """, (connector_id, 1 if enabled else 0, json.dumps(final_config), now))
        db.commit()

        log_audit(
            g.user_id, g.username, 'update_integration',
            target_type='integration', target_id=connector_id,
            details=json.dumps({'enabled': enabled}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'connector_id': connector_id,
            'enabled': enabled,
            'message': f'Connecteur {connector_id} mis a jour'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/integrations/<connector_id>/test', methods=['POST'])
@require_auth
@require_role('admin')
def test_integration(connector_id):
    """Tester la connexion d'un connecteur"""
    try:
        cls = int_registry.get_connector_class(connector_id)
        if not cls:
            return jsonify({'error': 'Connecteur inconnu'}), 404

        # Charger la config
        db = get_db()
        row = db.execute("SELECT config FROM integration_configs WHERE connector_id=?", (connector_id,)).fetchone()
        config = json.loads(row['config']) if row else {}

        # Tester
        instance = cls(config=config)
        result = instance.test_connection()
        now = datetime.datetime.now().isoformat()

        # Sauvegarder le resultat du test
        db.execute("""
            INSERT INTO integration_configs (connector_id, config, last_test_status, last_test_message, last_test_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(connector_id) DO UPDATE SET
                last_test_status=excluded.last_test_status,
                last_test_message=excluded.last_test_message,
                last_test_at=excluded.last_test_at,
                updated_at=excluded.updated_at
        """, (connector_id, json.dumps(config),
              'success' if result.get('success') else 'error',
              result.get('message', ''), now, now))
        db.commit()

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/integrations/<connector_id>/enrich', methods=['POST'])
@require_auth
def enrich_via_integration(connector_id):
    """Enrichir un IoC via un connecteur specifique"""
    try:
        cls = int_registry.get_connector_class(connector_id)
        if not cls:
            return jsonify({'error': 'Connecteur inconnu'}), 404

        db = get_db()
        row = db.execute("SELECT config, enabled FROM integration_configs WHERE connector_id=?", (connector_id,)).fetchone()
        if not row or not row['enabled']:
            return jsonify({'error': 'Connecteur non active'}), 400

        config = json.loads(row['config'])
        instance = cls(config=config)

        body = request.get_json()
        ioc_type = body.get('type')
        ioc_value = body.get('value')
        if not ioc_type or not ioc_value:
            return jsonify({'error': 'type et value requis'}), 400

        result = instance.enrich_ioc(ioc_type, ioc_value)
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/integrations/<connector_id>/push', methods=['POST'])
@require_auth
def push_to_integration(connector_id):
    """Pousser des IoCs vers un connecteur (ex: MISP)"""
    try:
        cls = int_registry.get_connector_class(connector_id)
        if not cls:
            return jsonify({'error': 'Connecteur inconnu'}), 404

        db = get_db()
        row = db.execute("SELECT config, enabled FROM integration_configs WHERE connector_id=?", (connector_id,)).fetchone()
        if not row or not row['enabled']:
            return jsonify({'error': 'Connecteur non active'}), 400

        config = json.loads(row['config'])
        instance = cls(config=config)

        body = request.get_json()
        investigation_id = body.get('investigation_id')

        if not investigation_id:
            return jsonify({'error': 'investigation_id requis'}), 400

        inv_row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not inv_row:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        iocs = rows_to_list(
            db.execute("SELECT type, value, source, severity FROM iocs WHERE investigation_id=?", (investigation_id,)).fetchall()
        )

        result = instance.push_iocs(iocs, dict_from_row(inv_row))

        log_audit(
            g.user_id, g.username, f'push_to_{connector_id}',
            target_type='integration', target_id=investigation_id,
            details=json.dumps({'connector': connector_id, 'ioc_count': len(iocs)}),
            ip_address=request.remote_addr
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/integrations/<connector_id>/pull', methods=['POST'])
@require_auth
def pull_from_integration(connector_id):
    """Recuperer des IoCs depuis un connecteur et les importer"""
    try:
        cls = int_registry.get_connector_class(connector_id)
        if not cls:
            return jsonify({'error': 'Connecteur inconnu'}), 404

        db = get_db()
        row = db.execute("SELECT config, enabled FROM integration_configs WHERE connector_id=?", (connector_id,)).fetchone()
        if not row or not row['enabled']:
            return jsonify({'error': 'Connecteur non active'}), 400

        config = json.loads(row['config'])
        instance = cls(config=config)

        body = request.get_json()
        query = body.get('query', '')
        investigation_id = body.get('investigation_id')
        limit = body.get('limit', 100)

        result = instance.pull_iocs(query=query, limit=limit)

        # Importer automatiquement si investigation_id fourni
        imported = 0
        if result.get('success') and investigation_id and result.get('iocs'):
            inv_exists = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
            if inv_exists:
                for ioc in result['iocs']:
                    ioc_type = ioc.get('type', '')
                    ioc_value = ioc.get('value', '')
                    if ioc_type in VALID_IOC_TYPES and ioc_value:
                        try:
                            cursor = db.execute(
                                "INSERT OR IGNORE INTO iocs (investigation_id, type, value, source) VALUES (?, ?, ?, ?)",
                                (investigation_id, ioc_type, ioc_value, ioc.get('source', connector_id))
                            )
                            if cursor.rowcount > 0:
                                imported += 1
                        except Exception:
                            pass
                db.commit()

        result['imported'] = imported
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500
