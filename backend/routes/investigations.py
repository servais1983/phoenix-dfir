#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes investigations : CRUD des enquetes et gestion de leur statut."""

import datetime
import json
import uuid

from flask import Blueprint, g, jsonify, request

from auth import require_auth
from database import get_db, log_audit, dict_from_row, rows_to_list
from helpers import paginate_query

bp = Blueprint('investigations', __name__)


@bp.route('/api/investigations', methods=['GET'])
@require_auth
def get_investigations():
    """Recuperer la liste paginee des enquetes avec filtres optionnels"""
    try:
        # Construire les filtres dynamiques
        where_clauses = []
        params = []

        search = request.args.get('search', '').strip()
        if search:
            where_clauses.append("(name LIKE ? OR description LIKE ?)")
            params.extend([f'%{search}%', f'%{search}%'])

        status_filter = request.args.get('status', '').strip()
        if status_filter and status_filter in ('active', 'closed', 'archived'):
            where_clauses.append("status=?")
            params.append(status_filter)

        where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        result = paginate_query(
            f"SELECT id, name, description, status, created_by, created_at, updated_at FROM investigations{where_sql} ORDER BY updated_at DESC",
            tuple(params),
            f"SELECT COUNT(*) FROM investigations{where_sql}",
            tuple(params)
        )

        # Enrichir chaque investigation avec le nombre d'artefacts et d'IoCs
        db = get_db()
        for item in result['items']:
            inv_id = item['id']
            item['artifacts'] = db.execute(
                "SELECT COUNT(*) FROM artifacts WHERE investigation_id=?", (inv_id,)
            ).fetchone()[0]
            item['iocs'] = db.execute(
                "SELECT COUNT(*) FROM iocs WHERE investigation_id=?", (inv_id,)
            ).fetchone()[0]

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/investigations', methods=['POST'])
@require_auth
def create_investigation():
    """Creer une nouvelle enquete"""
    try:
        data = request.get_json()
        investigation_name = data.get('name', f'Investigation-{datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}')
        description = data.get('description', '')

        investigation_id = str(uuid.uuid4())
        now = datetime.datetime.now().isoformat()

        db = get_db()
        db.execute(
            "INSERT INTO investigations (id, name, description, status, created_by, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?, ?)",
            (investigation_id, investigation_name, description, g.user_id, now, now)
        )
        db.commit()

        # Journaliser la creation
        log_audit(
            g.user_id, g.username, 'create_investigation',
            target_type='investigation', target_id=investigation_id,
            details=json.dumps({'name': investigation_name}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'id': investigation_id,
            'name': investigation_name,
            'status': 'active',
            'message': 'Enquete creee avec succes'
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/investigations/<investigation_id>', methods=['GET'])
@require_auth
def get_investigation(investigation_id):
    """Recuperer les details d'une enquete"""
    try:
        db = get_db()
        row = db.execute(
            "SELECT * FROM investigations WHERE id=?", (investigation_id,)
        ).fetchone()

        if not row:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        inv = dict_from_row(row)

        # Ajouter les artefacts, IoCs et timeline
        inv['artifacts'] = rows_to_list(
            db.execute("SELECT * FROM artifacts WHERE investigation_id=? ORDER BY uploaded_at DESC", (investigation_id,)).fetchall()
        )
        inv['iocs'] = rows_to_list(
            db.execute("SELECT * FROM iocs WHERE investigation_id=? ORDER BY created_at DESC", (investigation_id,)).fetchall()
        )
        inv['timeline_events'] = rows_to_list(
            db.execute("SELECT * FROM timeline_events WHERE investigation_id=? ORDER BY timestamp ASC", (investigation_id,)).fetchall()
        )

        return jsonify(inv)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/investigations/<investigation_id>', methods=['PUT'])
@require_auth
def update_investigation(investigation_id):
    """Mettre a jour les donnees d'une enquete"""
    try:
        db = get_db()
        existing = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        updates = request.get_json()
        if not updates:
            return jsonify({'error': 'Aucune donnee fournie'}), 400

        # Champs modifiables
        champs_modifiables = {'name', 'description'}
        sets = []
        params = []

        for champ in champs_modifiables:
            if champ in updates:
                sets.append(f"{champ}=?")
                params.append(updates[champ])

        if not sets:
            return jsonify({'error': 'Aucun champ modifiable fourni'}), 400

        sets.append("updated_at=?")
        params.append(datetime.datetime.now().isoformat())
        params.append(investigation_id)

        db.execute(f"UPDATE investigations SET {', '.join(sets)} WHERE id=?", params)
        db.commit()

        # Journaliser la mise a jour
        log_audit(
            g.user_id, g.username, 'update_investigation',
            target_type='investigation', target_id=investigation_id,
            details=json.dumps(updates),
            ip_address=request.remote_addr
        )

        row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        return jsonify({
            'id': investigation_id,
            'message': 'Enquete mise a jour avec succes',
            'data': dict_from_row(row)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/investigations/<investigation_id>', methods=['DELETE'])
@require_auth
def delete_investigation(investigation_id):
    """Supprimer une enquete et toutes ses donnees associees (CASCADE)"""
    try:
        db = get_db()
        existing = db.execute("SELECT id, name FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        db.execute("DELETE FROM investigations WHERE id=?", (investigation_id,))
        db.commit()

        # Journaliser la suppression
        log_audit(
            g.user_id, g.username, 'delete_investigation',
            target_type='investigation', target_id=investigation_id,
            details=json.dumps({'name': existing['name']}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'id': investigation_id,
            'message': 'Enquete supprimee avec succes'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@bp.route('/api/investigations/<investigation_id>/status', methods=['PUT'])
@require_auth
def update_investigation_status(investigation_id):
    """Changer le statut d'une enquete (active / closed / archived)"""
    try:
        db = get_db()
        existing = db.execute("SELECT id, status FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        body = request.get_json()
        if not body:
            return jsonify({'error': 'Aucune donnee fournie'}), 400

        new_status = body.get('status')
        statuts_valides = ('active', 'closed', 'archived')
        if new_status not in statuts_valides:
            return jsonify({
                'error': f'Statut invalide. Valeurs valides: {", ".join(statuts_valides)}'
            }), 400

        db.execute(
            "UPDATE investigations SET status=?, updated_at=? WHERE id=?",
            (new_status, datetime.datetime.now().isoformat(), investigation_id)
        )
        db.commit()

        # Journaliser le changement de statut
        log_audit(
            g.user_id, g.username, 'update_investigation_status',
            target_type='investigation', target_id=investigation_id,
            details=json.dumps({'old_status': existing['status'], 'new_status': new_status}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'id': investigation_id,
            'status': new_status,
            'message': f'Statut mis a jour: {new_status}'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
