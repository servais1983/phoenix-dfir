#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phoenix DFIR - Controle d'acces par enquete (case-level access control).

Modele :
- un admin voit et gere toutes les enquetes ;
- les autres utilisateurs ne voient que les enquetes dont ils sont membres
  (table investigation_members, le createur en est membre d'office) ;
- un viewer est en lecture seule, un analyst membre peut ecrire ;
- seuls l'admin et le createur d'une enquete peuvent la supprimer ou en
  gerer les membres.

Un acces refuse renvoie 404 (et non 403) pour ne pas reveler l'existence
d'une enquete a un utilisateur qui n'y a pas acces (anti-enumeration).
"""

from flask import g, jsonify

from database import get_db

WRITE_ROLES = ('admin', 'analyst')
NOT_FOUND_MESSAGE = 'Enquete non trouvee'


def is_admin(role=None):
    return (role if role is not None else getattr(g, 'role', None)) == 'admin'


def is_member(user_id, inv_id, db=None):
    if user_id is None or not inv_id:
        return False
    db = db or get_db()
    row = db.execute(
        "SELECT 1 FROM investigation_members WHERE investigation_id=? AND user_id=?",
        (str(inv_id), user_id)).fetchone()
    return row is not None


def can_access_investigation(user_id, role, inv_id, db=None):
    """Lecture autorisee ? (admin : toujours ; sinon membre de l'enquete)."""
    if not inv_id:
        return False
    db = db or get_db()
    exists = db.execute("SELECT 1 FROM investigations WHERE id=?", (str(inv_id),)).fetchone()
    if not exists:
        return False
    if role == 'admin':
        return True
    return is_member(user_id, inv_id, db)


def can_write_investigation(user_id, role, inv_id, db=None):
    """Ecriture autorisee ? (admin, ou analyst membre de l'enquete)."""
    if role not in WRITE_ROLES:
        return False
    return can_access_investigation(user_id, role, inv_id, db)


def can_manage_investigation(user_id, role, inv_id, db=None):
    """Suppression / gestion des membres : admin ou createur de l'enquete."""
    db = db or get_db()
    row = db.execute("SELECT created_by FROM investigations WHERE id=?", (str(inv_id),)).fetchone()
    if not row:
        return False
    if role == 'admin':
        return True
    return role in WRITE_ROLES and row['created_by'] is not None and row['created_by'] == user_id


def _not_found():
    return jsonify({'error': NOT_FOUND_MESSAGE}), 404


def require_investigation_access(inv_id, write=False):
    """Verifier l'acces de l'utilisateur courant (g) a une enquete.

    Retourne None si l'acces est autorise, sinon une reponse Flask 404 a
    renvoyer telle quelle. Pour une ecriture, un viewer membre recoit 403
    (il connait deja l'enquete), un non-membre 404.
    """
    user_id = getattr(g, 'user_id', None)
    role = getattr(g, 'role', None)
    if not can_access_investigation(user_id, role, inv_id):
        return _not_found()
    if write and role not in WRITE_ROLES:
        return jsonify({'error': 'Acces refuse - role insuffisant'}), 403
    return None


def accessible_investigation_ids(user_id=None, role=None, db=None):
    """Ids des enquetes accessibles, ou None si tout est accessible (admin)."""
    user_id = user_id if user_id is not None else getattr(g, 'user_id', None)
    role = role if role is not None else getattr(g, 'role', None)
    if role == 'admin':
        return None
    if user_id is None:
        return []
    db = db or get_db()
    return [r[0] for r in db.execute(
        "SELECT investigation_id FROM investigation_members WHERE user_id=?", (user_id,)).fetchall()]


def access_filter_sql(column='investigation_id', user_id=None, role=None):
    """Fragment SQL (clause, params) filtrant `column` sur les enquetes accessibles."""
    user_id = user_id if user_id is not None else getattr(g, 'user_id', None)
    role = role if role is not None else getattr(g, 'role', None)
    if role == 'admin':
        return '1=1', ()
    return (f"{column} IN (SELECT investigation_id FROM investigation_members WHERE user_id=?)",
            (user_id,))


def add_member(inv_id, user_id, added_by=None, db=None):
    db = db or get_db()
    cursor = db.execute(
        "INSERT OR IGNORE INTO investigation_members (investigation_id, user_id, added_by) VALUES (?, ?, ?)",
        (str(inv_id), user_id, added_by))
    return cursor.rowcount > 0
