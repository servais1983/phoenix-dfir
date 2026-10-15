#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes statistiques et journal d'audit."""

import datetime
import json

from flask import Blueprint, g, jsonify

import access
from auth import require_auth, require_role
from database import get_db, rows_to_list
from helpers import paginate_query, server_error

bp = Blueprint('stats', __name__)


@bp.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    """Statistiques des enquetes accessibles (toutes pour un admin) avec serie temporelle 7 jours"""
    try:
        db = get_db()
        # Agregats limites aux enquetes accessibles a l'utilisateur
        inv_acl, inv_p = access.access_filter_sql('id')
        child_acl, child_p = access.access_filter_sql('investigation_id')

        def scalar(sql, params=()):
            return db.execute(sql, params).fetchone()[0]

        total_investigations = scalar(f"SELECT COUNT(*) FROM investigations WHERE {inv_acl}", inv_p)  # nosec B608
        active_investigations = scalar(f"SELECT COUNT(*) FROM investigations WHERE status='active' AND {inv_acl}", inv_p)  # nosec B608
        closed_investigations = scalar(f"SELECT COUNT(*) FROM investigations WHERE status='closed' AND {inv_acl}", inv_p)  # nosec B608
        archived_investigations = scalar(f"SELECT COUNT(*) FROM investigations WHERE status='archived' AND {inv_acl}", inv_p)  # nosec B608
        total_iocs = scalar(f"SELECT COUNT(*) FROM iocs WHERE {child_acl}", child_p)  # nosec B608
        total_artifacts = scalar(f"SELECT COUNT(*) FROM artifacts WHERE {child_acl}", child_p)  # nosec B608
        total_timeline_events = scalar(f"SELECT COUNT(*) FROM timeline_events WHERE {child_acl}", child_p)  # nosec B608
        # Nombre d'utilisateurs : information d'administration uniquement
        total_users = scalar("SELECT COUNT(*) FROM users") if g.role == 'admin' else None

        # Repartition des IoCs par type
        ioc_by_type = rows_to_list(db.execute(
            f"SELECT type, COUNT(*) as count FROM iocs WHERE {child_acl} GROUP BY type ORDER BY count DESC",  # nosec B608
            child_p).fetchall())

        # Repartition des severites IoC
        ioc_by_severity = rows_to_list(db.execute(
            f"SELECT severity, COUNT(*) as count FROM iocs WHERE {child_acl} GROUP BY severity ORDER BY count DESC",  # nosec B608
            child_p).fetchall())

        # Series temporelles sur les 7 derniers jours
        seven_days_ago = (datetime.datetime.now() - datetime.timedelta(days=7)).isoformat()

        investigations_timeseries = rows_to_list(db.execute(
            f"SELECT DATE(created_at) as date, COUNT(*) as count FROM investigations WHERE created_at >= ? AND {inv_acl} GROUP BY DATE(created_at) ORDER BY date ASC",  # nosec B608
            (seven_days_ago,) + tuple(inv_p)).fetchall())

        iocs_timeseries = rows_to_list(db.execute(
            f"SELECT DATE(created_at) as date, COUNT(*) as count FROM iocs WHERE created_at >= ? AND {child_acl} GROUP BY DATE(created_at) ORDER BY date ASC",  # nosec B608
            (seven_days_ago,) + tuple(child_p)).fetchall())

        artifacts_timeseries = rows_to_list(db.execute(
            f"SELECT DATE(uploaded_at) as date, COUNT(*) as count FROM artifacts WHERE uploaded_at >= ? AND {child_acl} GROUP BY DATE(uploaded_at) ORDER BY date ASC",  # nosec B608
            (seven_days_ago,) + tuple(child_p)).fetchall())

        return jsonify({
            'total_investigations': total_investigations,
            'active_investigations': active_investigations,
            'closed_investigations': closed_investigations,
            'archived_investigations': archived_investigations,
            'total_iocs': total_iocs,
            'total_artifacts': total_artifacts,
            'total_timeline_events': total_timeline_events,
            'total_users': total_users,
            'ioc_by_type': ioc_by_type,
            'ioc_by_severity': ioc_by_severity,
            'timeseries': {
                'investigations': investigations_timeseries,
                'iocs': iocs_timeseries,
                'artifacts': artifacts_timeseries
            },
            'timestamp': datetime.datetime.now().isoformat()
        })

    except Exception as e:
        return server_error(e)


@bp.route('/api/audit', methods=['GET'])
@require_auth
@require_role('admin')
def get_audit_log():
    """Recuperer le journal d'audit (admin uniquement, pagine)"""
    try:
        result = paginate_query(
            "SELECT * FROM audit_log ORDER BY created_at DESC",
            (),
            "SELECT COUNT(*) FROM audit_log",
            ()
        )

        # Deserialiser les details JSON
        for item in result['items']:
            if item.get('details'):
                try:
                    item['details'] = json.loads(item['details'])
                except (json.JSONDecodeError, TypeError):
                    pass

        return jsonify(result)

    except Exception as e:
        return server_error(e)
