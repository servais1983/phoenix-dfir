#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Routes timeline : evenements chronologiques d'une enquete."""

import datetime
import json
import uuid

from flask import Blueprint, g, jsonify, request

import access
from auth import require_auth
from database import get_db, log_audit
from helpers import paginate_query, server_error

bp = Blueprint('timeline', __name__)


@bp.route('/api/investigations/<investigation_id>/timeline', methods=['GET'])
@require_auth
def get_investigation_timeline(investigation_id):
    """Recuperer les evenements de la timeline d'une enquete (pagine)"""
    try:
        denied = access.require_investigation_access(investigation_id)
        if denied:
            return denied

        result = paginate_query(
            "SELECT * FROM timeline_events WHERE investigation_id=? ORDER BY timestamp ASC",
            (investigation_id,),
            "SELECT COUNT(*) FROM timeline_events WHERE investigation_id=?",
            (investigation_id,)
        )

        return jsonify(result)

    except Exception as e:
        return server_error(e)


@bp.route('/api/investigations/<investigation_id>/timeline', methods=['POST'])
@require_auth
def add_timeline_event(investigation_id):
    """Ajouter un evenement a la timeline d'une enquete"""
    try:
        denied = access.require_investigation_access(investigation_id, write=True)
        if denied:
            return denied
        db = get_db()

        body = request.get_json(silent=True)
        if not body:
            return jsonify({'error': 'Aucune donnee fournie'}), 400

        timestamp = body.get('timestamp')
        event = body.get('event')
        severity = body.get('severity', 'info')
        source = body.get('source', '')

        if not timestamp or not event:
            return jsonify({'error': 'Les champs "timestamp" et "event" sont requis'}), 400

        # Valider la severite
        severites_valides = ('info', 'low', 'medium', 'high', 'critical')
        if severity not in severites_valides:
            return jsonify({
                'error': f'Severite invalide. Valeurs valides: {", ".join(severites_valides)}'
            }), 400

        event_id = str(uuid.uuid4())

        db.execute(
            "INSERT INTO timeline_events (id, investigation_id, timestamp, event, severity, source) VALUES (?, ?, ?, ?, ?, ?)",
            (event_id, investigation_id, timestamp, event, severity, source)
        )
        db.execute("UPDATE investigations SET updated_at=? WHERE id=?", (datetime.datetime.now().isoformat(), investigation_id))
        db.commit()

        # Journaliser l'ajout
        log_audit(
            g.user_id, g.username, 'add_timeline_event',
            target_type='timeline_event', target_id=event_id,
            details=json.dumps({'investigation_id': investigation_id, 'event': event[:100]}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'message': 'Evenement ajoute a la timeline avec succes',
            'event': {
                'id': event_id,
                'timestamp': timestamp,
                'event': event,
                'severity': severity,
                'source': source
            }
        }), 201

    except Exception as e:
        return server_error(e)
