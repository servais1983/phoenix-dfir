#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes IoCs : CRUD, import en masse, export CSV et enrichissement VirusTotal."""

import csv
import datetime
import io
import json

from flask import Blueprint, Response, g, jsonify, request

from auth import require_auth
from database import get_db, log_audit, rows_to_list
from extensions import VALID_IOC_TYPES
from helpers import paginate_query
from parsers import extract_iocs
import phoenix_compat

bp = Blueprint('iocs', __name__)


@bp.route('/api/investigations/<investigation_id>/iocs', methods=['GET'])
@require_auth
def get_investigation_iocs(investigation_id):
    """Recuperer la liste paginee des IoCs d'une enquete avec filtres"""
    try:
        db = get_db()
        existing = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        # Filtres optionnels
        where_clauses = ["investigation_id=?"]
        params = [investigation_id]

        type_filter = request.args.get('type', '').strip()
        if type_filter and type_filter in VALID_IOC_TYPES:
            where_clauses.append("type=?")
            params.append(type_filter)

        search = request.args.get('search', '').strip()
        if search:
            where_clauses.append("value LIKE ?")
            params.append(f'%{search}%')

        where_sql = " WHERE " + " AND ".join(where_clauses)

        result = paginate_query(
            f"SELECT * FROM iocs{where_sql} ORDER BY created_at DESC",
            tuple(params),
            f"SELECT COUNT(*) FROM iocs{where_sql}",
            tuple(params)
        )

        # Deserialiser l'enrichissement et les tags JSON
        for item in result['items']:
            if item.get('enrichment'):
                try:
                    item['enrichment'] = json.loads(item['enrichment'])
                except (json.JSONDecodeError, TypeError):
                    pass
            if item.get('tags'):
                try:
                    item['tags'] = json.loads(item['tags'])
                except (json.JSONDecodeError, TypeError):
                    item['tags'] = []

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/investigations/<investigation_id>/iocs', methods=['POST'])
@require_auth
def add_investigation_ioc(investigation_id):
    """Ajouter un IoC a une enquete"""
    try:
        db = get_db()
        existing = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        body = request.get_json()
        if not body:
            return jsonify({'error': 'Aucune donnee fournie'}), 400

        ioc_type = body.get('type')
        ioc_value = body.get('value')
        ioc_source = body.get('source', '')
        ioc_severity = body.get('severity', 'unknown')
        ioc_tags = body.get('tags', [])

        if not ioc_type or not ioc_value:
            return jsonify({'error': 'Les champs "type" et "value" sont requis'}), 400

        if ioc_type not in VALID_IOC_TYPES:
            return jsonify({
                'error': f'Type d\'IoC invalide. Types valides: {", ".join(sorted(VALID_IOC_TYPES))}'
            }), 400

        cursor = db.execute(
            "INSERT OR IGNORE INTO iocs (investigation_id, type, value, source, severity, tags) VALUES (?, ?, ?, ?, ?, ?)",
            (investigation_id, ioc_type, ioc_value, ioc_source, ioc_severity, json.dumps(ioc_tags))
        )
        db.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Cet IoC existe deja pour cette enquete'}), 409

        # Mettre a jour le timestamp de l'investigation
        db.execute("UPDATE investigations SET updated_at=? WHERE id=?", (datetime.datetime.now().isoformat(), investigation_id))
        db.commit()

        # Journaliser l'ajout
        log_audit(
            g.user_id, g.username, 'add_ioc',
            target_type='ioc', target_id=str(cursor.lastrowid),
            details=json.dumps({'type': ioc_type, 'value': ioc_value, 'investigation_id': investigation_id}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'message': 'IoC ajoute avec succes',
            'id': cursor.lastrowid,
            'type': ioc_type,
            'value': ioc_value
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/investigations/<investigation_id>/iocs/<int:ioc_id>', methods=['DELETE'])
@require_auth
def delete_investigation_ioc(investigation_id, ioc_id):
    """Supprimer un IoC specifique par son ID"""
    try:
        db = get_db()
        existing = db.execute(
            "SELECT id, type, value FROM iocs WHERE id=? AND investigation_id=?",
            (ioc_id, investigation_id)
        ).fetchone()

        if not existing:
            return jsonify({'error': 'IoC non trouve'}), 404

        db.execute("DELETE FROM iocs WHERE id=?", (ioc_id,))
        db.commit()

        # Journaliser la suppression
        log_audit(
            g.user_id, g.username, 'delete_ioc',
            target_type='ioc', target_id=str(ioc_id),
            details=json.dumps({'type': existing['type'], 'value': existing['value'], 'investigation_id': investigation_id}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'message': 'IoC supprime avec succes',
            'id': ioc_id
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/investigations/<investigation_id>/iocs/bulk', methods=['POST'])
@require_auth
def bulk_import_iocs(investigation_id):
    """Importer plusieurs IoCs en une seule requete (texte libre ou JSON)"""
    try:
        db = get_db()
        existing = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        body = request.get_json()
        if not body:
            return jsonify({'error': 'Donnees requises'}), 400

        imported = 0
        skipped = 0
        errors = []

        # Mode 1: Liste d'IoCs structuree
        iocs_list = list(body.get('iocs', []))

        # Mode 2: Texte libre pour extraction automatique
        raw_text = body.get('text', '')
        if raw_text:
            extracted = extract_iocs(raw_text)
            iocs_list.extend(extracted)

        for ioc in iocs_list:
            ioc_type = ioc.get('type', '')
            ioc_value = ioc.get('value', '')
            ioc_source = ioc.get('source', 'bulk-import')

            if not ioc_type or not ioc_value:
                skipped += 1
                continue

            if ioc_type not in VALID_IOC_TYPES:
                errors.append(f"Type invalide: {ioc_type}")
                skipped += 1
                continue

            try:
                cursor = db.execute(
                    "INSERT OR IGNORE INTO iocs (investigation_id, type, value, source) VALUES (?, ?, ?, ?)",
                    (investigation_id, ioc_type, ioc_value, ioc_source)
                )
                if cursor.rowcount > 0:
                    imported += 1
                else:
                    skipped += 1
            except Exception as e:
                errors.append(str(e))
                skipped += 1

        db.execute("UPDATE investigations SET updated_at=? WHERE id=?",
                   (datetime.datetime.now().isoformat(), investigation_id))
        db.commit()

        log_audit(
            g.user_id, g.username, 'bulk_import_iocs',
            target_type='ioc', target_id=investigation_id,
            details=json.dumps({'imported': imported, 'skipped': skipped}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'imported': imported,
            'skipped': skipped,
            'errors': errors[:10],
            'message': f'{imported} IoC(s) importes, {skipped} ignores'
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/investigations/<investigation_id>/iocs/export', methods=['GET'])
@require_auth
def export_iocs_csv(investigation_id):
    """Exporter les IoCs au format CSV"""
    try:
        db = get_db()
        existing = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        iocs = rows_to_list(
            db.execute("SELECT type, value, source, severity, created_at FROM iocs WHERE investigation_id=? ORDER BY type, value", (investigation_id,)).fetchall()
        )

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Type', 'Valeur', 'Source', 'Severite', 'Date'])
        for ioc in iocs:
            writer.writerow([ioc['type'], ioc['value'], ioc['source'], ioc.get('severity', ''), ioc['created_at']])

        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=iocs_{investigation_id}.csv'}
        )

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/iocs/enrich', methods=['POST'])
@require_auth
def enrich_ioc():
    """Enrichir un IoC unique via VirusTotal"""
    try:
        body = request.get_json()
        if not body:
            return jsonify({'error': 'Aucune donnee fournie'}), 400

        ioc_type = body.get('type')
        ioc_value = body.get('value')

        if not ioc_type or not ioc_value:
            return jsonify({'error': 'Les champs "type" et "value" sont requis'}), 400

        if phoenix_compat.PHOENIX_AVAILABLE:
            # Appeler la fonction d'enrichissement Phoenix
            enrichment_result = phoenix_compat.enrichir_ioc_vt(ioc_value)
        else:
            # Donnees simulees quand Phoenix n'est pas disponible
            enrichment_result = {
                'source': 'mock',
                'ioc': ioc_value,
                'type': ioc_type,
                'malicious': 0,
                'suspicious': 0,
                'harmless': 70,
                'undetected': 10,
                'reputation': 'Aucune donnee (mode simule)',
                'details': f'Enrichissement simule pour {ioc_value} - Phoenix non disponible'
            }

        # Mettre a jour l'enrichissement en base si un ioc_id est fourni
        ioc_id = body.get('ioc_id')
        if ioc_id:
            db = get_db()
            db.execute(
                "UPDATE iocs SET enrichment=? WHERE id=?",
                (json.dumps(enrichment_result), ioc_id)
            )
            db.commit()

        return jsonify({
            'ioc': ioc_value,
            'type': ioc_type,
            'enrichment': enrichment_result
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
