#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes statistiques et journal d'audit."""

import datetime
import json

from flask import Blueprint, jsonify

from auth import require_auth, require_role
from database import get_db, rows_to_list
from helpers import paginate_query

bp = Blueprint('stats', __name__)


@bp.route('/api/stats', methods=['GET'])
@require_auth
def get_stats():
    """Retourner les statistiques globales depuis SQLite avec serie temporelle 7 jours"""
    try:
        db = get_db()

        total_investigations = db.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
        active_investigations = db.execute("SELECT COUNT(*) FROM investigations WHERE status='active'").fetchone()[0]
        closed_investigations = db.execute("SELECT COUNT(*) FROM investigations WHERE status='closed'").fetchone()[0]
        archived_investigations = db.execute("SELECT COUNT(*) FROM investigations WHERE status='archived'").fetchone()[0]
        total_iocs = db.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        total_artifacts = db.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        total_timeline_events = db.execute("SELECT COUNT(*) FROM timeline_events").fetchone()[0]
        total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

        # Repartition des IoCs par type
        ioc_by_type = rows_to_list(
            db.execute("SELECT type, COUNT(*) as count FROM iocs GROUP BY type ORDER BY count DESC").fetchall()
        )

        # Repartition des severites IoC
        ioc_by_severity = rows_to_list(
            db.execute("SELECT severity, COUNT(*) as count FROM iocs GROUP BY severity ORDER BY count DESC").fetchall()
        )

        # Serie temporelle : investigations creees sur les 7 derniers jours
        seven_days_ago = (datetime.datetime.now() - datetime.timedelta(days=7)).isoformat()

        investigations_timeseries = rows_to_list(
            db.execute(
                "SELECT DATE(created_at) as date, COUNT(*) as count FROM investigations WHERE created_at >= ? GROUP BY DATE(created_at) ORDER BY date ASC",
                (seven_days_ago,)
            ).fetchall()
        )

        # Serie temporelle : IoCs crees sur les 7 derniers jours
        iocs_timeseries = rows_to_list(
            db.execute(
                "SELECT DATE(created_at) as date, COUNT(*) as count FROM iocs WHERE created_at >= ? GROUP BY DATE(created_at) ORDER BY date ASC",
                (seven_days_ago,)
            ).fetchall()
        )

        # Serie temporelle : artefacts uploades sur les 7 derniers jours
        artifacts_timeseries = rows_to_list(
            db.execute(
                "SELECT DATE(uploaded_at) as date, COUNT(*) as count FROM artifacts WHERE uploaded_at >= ? GROUP BY DATE(uploaded_at) ORDER BY date ASC",
                (seven_days_ago,)
            ).fetchall()
        )

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
        return jsonify({'error': str(e)}), 500


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
        return jsonify({'error': str(e)}), 500
