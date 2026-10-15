#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes investigations : CRUD des enquetes, statut et membres (controle d'acces)."""

import datetime
import json
import uuid

from flask import Blueprint, g, jsonify, request

import access
from auth import require_auth, require_role
from database import get_db, log_audit, dict_from_row, rows_to_list
from helpers import paginate_query, server_error

bp = Blueprint('investigations', __name__)


def _strip_paths(artifacts):
    """Ne jamais exposer le chemin absolu des evidences sur le serveur."""
    for art in artifacts:
        art.pop('file_path', None)
    return artifacts


@bp.route('/api/investigations', methods=['GET'])
@require_auth
def get_investigations():
    """Recuperer la liste paginee des enquetes accessibles avec filtres optionnels"""
    try:
        # Construire les filtres dynamiques
        acl_sql, acl_params = access.access_filter_sql('id')
        where_clauses = [acl_sql]
        params = list(acl_params)

        search = request.args.get('search', '').strip()
        if search:
            where_clauses.append("(name LIKE ? OR description LIKE ?)")
            params.extend([f'%{search}%', f'%{search}%'])

        status_filter = request.args.get('status', '').strip()
        if status_filter and status_filter in ('active', 'closed', 'archived'):
            where_clauses.append("status=?")
            params.append(status_filter)

        where_sql = " WHERE " + " AND ".join(where_clauses)

        result = paginate_query(
            f"SELECT id, name, description, status, created_by, created_at, updated_at FROM investigations{where_sql} ORDER BY updated_at DESC",  # nosec B608 - clauses fixes
            tuple(params),
            f"SELECT COUNT(*) FROM investigations{where_sql}",  # nosec B608
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
        return server_error(e)


@bp.route('/api/investigations', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def create_investigation():
    """Creer une nouvelle enquete (le createur en devient membre)"""
    try:
        data = request.get_json(silent=True) or {}
        investigation_name = data.get('name') or f'Investigation-{datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}'
        description = data.get('description', '')

        investigation_id = str(uuid.uuid4())
        now = datetime.datetime.now().isoformat()

        db = get_db()
        db.execute(
            "INSERT INTO investigations (id, name, description, status, created_by, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?, ?)",
            (investigation_id, investigation_name, description, g.user_id, now, now)
        )
        access.add_member(investigation_id, g.user_id, added_by=g.user_id, db=db)
        db.commit()

        # Les sockets ouverts du createur recoivent les evenements de l'enquete
        import sockets
        sockets.grant_investigation_room(g.user_id, investigation_id)

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
        return server_error(e)


@bp.route('/api/investigations/<investigation_id>', methods=['GET'])
@require_auth
def get_investigation(investigation_id):
    """Recuperer les details d'une enquete"""
    try:
        denied = access.require_investigation_access(investigation_id)
        if denied:
            return denied
        db = get_db()
        row = db.execute(
            "SELECT * FROM investigations WHERE id=?", (investigation_id,)
        ).fetchone()

        inv = dict_from_row(row)

        # Ajouter les artefacts, IoCs et timeline
        inv['artifacts'] = _strip_paths(rows_to_list(
            db.execute("SELECT * FROM artifacts WHERE investigation_id=? ORDER BY uploaded_at DESC", (investigation_id,)).fetchall()
        ))
        inv['iocs'] = rows_to_list(
            db.execute("SELECT * FROM iocs WHERE investigation_id=? ORDER BY created_at DESC", (investigation_id,)).fetchall()
        )
        inv['timeline_events'] = rows_to_list(
            db.execute("SELECT * FROM timeline_events WHERE investigation_id=? ORDER BY timestamp ASC", (investigation_id,)).fetchall()
        )
        inv['can_manage'] = access.can_manage_investigation(g.user_id, g.role, investigation_id, db)
        inv['can_write'] = access.can_write_investigation(g.user_id, g.role, investigation_id, db)

        return jsonify(inv)

    except Exception as e:
        return server_error(e)


@bp.route('/api/investigations/<investigation_id>', methods=['PUT'])
@require_auth
def update_investigation(investigation_id):
    """Mettre a jour les donnees d'une enquete"""
    try:
        denied = access.require_investigation_access(investigation_id, write=True)
        if denied:
            return denied
        db = get_db()

        updates = request.get_json(silent=True)
        if not updates:
            return jsonify({'error': 'Aucune donnee fournie'}), 400

        # Champs modifiables
        champs_modifiables = ('name', 'description')
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

        db.execute(f"UPDATE investigations SET {', '.join(sets)} WHERE id=?", params)  # nosec B608 - colonnes fixes
        db.commit()

        # Journaliser la mise a jour
        log_audit(
            g.user_id, g.username, 'update_investigation',
            target_type='investigation', target_id=investigation_id,
            details=json.dumps({k: updates[k] for k in champs_modifiables if k in updates}),
            ip_address=request.remote_addr
        )

        row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        return jsonify({
            'id': investigation_id,
            'message': 'Enquete mise a jour avec succes',
            'data': dict_from_row(row)
        })

    except Exception as e:
        return server_error(e)


@bp.route('/api/investigations/<investigation_id>', methods=['DELETE'])
@require_auth
@require_role('admin', 'analyst')
def delete_investigation(investigation_id):
    """Supprimer une enquete (admin ou createur) et ses donnees associees (CASCADE)"""
    try:
        denied = access.require_investigation_access(investigation_id)
        if denied:
            return denied
        db = get_db()
        if not access.can_manage_investigation(g.user_id, g.role, investigation_id, db):
            return jsonify({'error': 'Seuls un administrateur ou le createur peuvent supprimer cette enquete'}), 403
        existing = db.execute("SELECT id, name FROM investigations WHERE id=?", (investigation_id,)).fetchone()

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
        return server_error(e)


@bp.route('/api/investigations/<investigation_id>/status', methods=['PUT'])
@require_auth
def update_investigation_status(investigation_id):
    """Changer le statut d'une enquete (active / closed / archived)"""
    try:
        denied = access.require_investigation_access(investigation_id, write=True)
        if denied:
            return denied
        db = get_db()
        existing = db.execute("SELECT id, status FROM investigations WHERE id=?", (investigation_id,)).fetchone()

        body = request.get_json(silent=True)
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
        return server_error(e)


# ============================================================================
# Membres d'une enquete
# ============================================================================

def _members(db, investigation_id):
    inv = db.execute("SELECT created_by FROM investigations WHERE id=?", (investigation_id,)).fetchone()
    rows = db.execute(
        "SELECT m.user_id, u.username, u.display_name, u.role, u.disabled, m.added_by, m.added_at "
        "FROM investigation_members m JOIN users u ON u.id = m.user_id "
        "WHERE m.investigation_id=? ORDER BY m.added_at ASC", (investigation_id,)).fetchall()
    members = rows_to_list(rows)
    for m in members:
        m['is_creator'] = inv is not None and m['user_id'] == inv['created_by']
    return members


@bp.route('/api/investigations/<investigation_id>/members', methods=['GET'])
@require_auth
def list_members(investigation_id):
    denied = access.require_investigation_access(investigation_id)
    if denied:
        return denied
    db = get_db()
    return jsonify({
        'items': _members(db, investigation_id),
        'can_manage': access.can_manage_investigation(g.user_id, g.role, investigation_id, db),
    })


@bp.route('/api/investigations/<investigation_id>/members', methods=['POST'])
@require_auth
def add_member(investigation_id):
    denied = access.require_investigation_access(investigation_id)
    if denied:
        return denied
    db = get_db()
    if not access.can_manage_investigation(g.user_id, g.role, investigation_id, db):
        return jsonify({'error': 'Seuls un administrateur ou le createur gerent les membres'}), 403

    data = request.get_json(silent=True) or {}
    if data.get('user_id') is not None:
        user = db.execute("SELECT id, username, disabled FROM users WHERE id=?",
                          (data.get('user_id'),)).fetchone()
    else:
        user = db.execute("SELECT id, username, disabled FROM users WHERE username=?",
                          (str(data.get('username') or '').strip(),)).fetchone()
    if not user or user['disabled']:
        return jsonify({'error': 'Utilisateur non trouve'}), 404

    added = access.add_member(investigation_id, user['id'], added_by=g.user_id, db=db)
    db.commit()
    if added:
        import sockets
        sockets.grant_investigation_room(user['id'], investigation_id)
        log_audit(g.user_id, g.username, 'add_investigation_member',
                  target_type='investigation', target_id=investigation_id,
                  details=json.dumps({'user_id': user['id'], 'username': user['username']}),
                  ip_address=request.remote_addr)
    return jsonify({'items': _members(db, investigation_id), 'added': added}), (201 if added else 200)


@bp.route('/api/investigations/<investigation_id>/members/<int:user_id>', methods=['DELETE'])
@require_auth
def remove_member(investigation_id, user_id):
    denied = access.require_investigation_access(investigation_id)
    if denied:
        return denied
    db = get_db()
    if not access.can_manage_investigation(g.user_id, g.role, investigation_id, db):
        return jsonify({'error': 'Seuls un administrateur ou le createur gerent les membres'}), 403
    inv = db.execute("SELECT created_by FROM investigations WHERE id=?", (investigation_id,)).fetchone()
    if inv['created_by'] == user_id:
        return jsonify({'error': 'Le createur de l\'enquete ne peut pas etre retire'}), 400
    cursor = db.execute("DELETE FROM investigation_members WHERE investigation_id=? AND user_id=?",
                        (investigation_id, user_id))
    db.commit()
    if not cursor.rowcount:
        return jsonify({'error': 'Membre non trouve'}), 404
    import sockets
    sockets.revoke_investigation_room(user_id, investigation_id)
    log_audit(g.user_id, g.username, 'remove_investigation_member',
              target_type='investigation', target_id=investigation_id,
              details=json.dumps({'user_id': user_id}), ip_address=request.remote_addr)
    return jsonify({'items': _members(db, investigation_id)})
