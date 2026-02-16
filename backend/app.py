#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR - Backend API Flask
Interface graphique professionnelle pour Phoenix DFIR
Toutes les donnees sont stockees dans SQLite via database.py
"""

import os
import sys
import json
import datetime
import uuid
import hashlib
import secrets
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, request, jsonify, send_file, g
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename

# Ajouter le chemin du module Phoenix original
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

# Import des modules internes
from database import get_db, close_db, init_db, migrate_json_sessions, log_audit, dict_from_row, rows_to_list
from auth import register_auth_routes, require_auth, require_role, decode_token
from parsers import analyze_file_standalone, extract_iocs
from middleware import rate_limit, register_security_headers, register_request_id

# Import des modules Phoenix (optionnel)
try:
    from phoenix import (
        query_local, query_remote, enrichir_ioc_vt,
        analyse_fichier, extraire_et_sauvegarder_conclusions,
        generer_resume_executif_ia, creer_contenu_rapport,
        sauvegarder_session, charger_session
    )
    PHOENIX_AVAILABLE = True
except ImportError as e:
    print(f"Attention: Impossible d'importer les modules Phoenix: {e}")
    PHOENIX_AVAILABLE = False

# ============================================================================
# CONFIGURATION FLASK
# ============================================================================

app = Flask(__name__)

# Cle secrete depuis variable d'environnement ou generation aleatoire
app.config['SECRET_KEY'] = os.environ.get('PHOENIX_SECRET_KEY', secrets.token_hex(64))
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max

# Extensions de fichiers autorisees
ALLOWED_EXTENSIONS = {'.evtx', '.csv', '.json', '.log', '.txt', '.xml', '.pcap', '.pcapng'}

# Types d'IoC valides
VALID_IOC_TYPES = {'ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email', 'filename', 'registry_key', 'cve'}

# Origines CORS autorisees (localhost dev)
CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:5174"
]

CORS(app, origins=CORS_ORIGINS)
socketio = SocketIO(app, cors_allowed_origins=CORS_ORIGINS)

# Creer les dossiers necessaires
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), 'sessions'), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), 'reports'), exist_ok=True)

# Pool de threads pour les analyses (4 workers max)
executor = ThreadPoolExecutor(max_workers=4)

# Progression des analyses en cours
analysis_progress = {}

# Enregistrer les routes d'authentification
register_auth_routes(app)

# Enregistrer les middlewares de securite
register_security_headers(app)
register_request_id(app)

# ============================================================================
# INITIALISATION BASE DE DONNEES AU DEMARRAGE
# ============================================================================

with app.app_context():
    init_db()
    migrate_json_sessions()

# ============================================================================
# TEARDOWN : FERMETURE CONNEXION DB
# ============================================================================

@app.teardown_appcontext
def teardown_db(exception):
    """Fermer la connexion SQLite a la fin de chaque requete"""
    close_db()

# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def _allowed_file(filename):
    """Verifier si l'extension du fichier est autorisee"""
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def _paginate_query(query, params, count_query, count_params):
    """Executer une requete paginee et retourner le format standard"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    # Bornes de securite
    page = max(1, page)
    per_page = max(1, min(per_page, 200))

    offset = (page - 1) * per_page

    db = get_db()
    total = db.execute(count_query, count_params).fetchone()[0]
    rows = db.execute(query + " LIMIT ? OFFSET ?", params + (per_page, offset)).fetchall()

    return {
        'items': rows_to_list(rows),
        'total': total,
        'page': page,
        'per_page': per_page
    }


def _compute_file_hashes(filepath):
    """Calculer les empreintes MD5, SHA1 et SHA256 d'un fichier"""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def _sanitize_report_id(report_id):
    """Assainir le report_id pour prevenir les traversees de chemin"""
    # Retirer tout caractere de traversee de chemin
    clean = os.path.basename(report_id)
    if '..' in clean or '/' in clean or '\\' in clean:
        return None
    if not clean:
        return None
    return clean


def cleanup_old_files():
    """Nettoyer les anciens fichiers uploades de plus de 24h"""
    try:
        uploads_dir = Path(app.config['UPLOAD_FOLDER'])
        cutoff_time = time.time() - (24 * 60 * 60)  # 24 heures

        for file_path in uploads_dir.glob('*'):
            if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
                file_path.unlink()
                print(f"Fichier supprime: {file_path}")

    except Exception as e:
        print(f"Erreur lors du nettoyage: {e}")


# ============================================================================
# ROUTE SANTE (pas d'authentification requise)
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Verification de l'etat du systeme avec test de connectivite DB"""
    db_ok = False
    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
        db_ok = True
    except Exception:
        pass

    return jsonify({
        'status': 'healthy' if db_ok else 'degraded',
        'phoenix_available': PHOENIX_AVAILABLE,
        'database': 'connected' if db_ok else 'error',
        'timestamp': datetime.datetime.now().isoformat(),
        'version': '3.0'
    })

# ============================================================================
# ROUTES INVESTIGATIONS
# ============================================================================

@app.route('/api/investigations', methods=['GET'])
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

        result = _paginate_query(
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


@app.route('/api/investigations', methods=['POST'])
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


@app.route('/api/investigations/<investigation_id>', methods=['GET'])
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


@app.route('/api/investigations/<investigation_id>', methods=['PUT'])
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


@app.route('/api/investigations/<investigation_id>', methods=['DELETE'])
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


@app.route('/api/investigations/<investigation_id>/status', methods=['PUT'])
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

# ============================================================================
# ROUTES IoCs
# ============================================================================

@app.route('/api/investigations/<investigation_id>/iocs', methods=['GET'])
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

        result = _paginate_query(
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


@app.route('/api/investigations/<investigation_id>/iocs', methods=['POST'])
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


@app.route('/api/investigations/<investigation_id>/iocs/<int:ioc_id>', methods=['DELETE'])
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


@app.route('/api/investigations/<investigation_id>/iocs/bulk', methods=['POST'])
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


@app.route('/api/investigations/<investigation_id>/iocs/export', methods=['GET'])
@require_auth
def export_iocs_csv(investigation_id):
    """Exporter les IoCs au format CSV"""
    import io
    import csv
    from flask import Response

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


@app.route('/api/iocs/enrich', methods=['POST'])
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

        if PHOENIX_AVAILABLE:
            # Appeler la fonction d'enrichissement Phoenix
            enrichment_result = enrichir_ioc_vt(ioc_value)
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

# ============================================================================
# ROUTES TIMELINE
# ============================================================================

@app.route('/api/investigations/<investigation_id>/timeline', methods=['GET'])
@require_auth
def get_investigation_timeline(investigation_id):
    """Recuperer les evenements de la timeline d'une enquete (pagine)"""
    try:
        db = get_db()
        existing = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        result = _paginate_query(
            "SELECT * FROM timeline_events WHERE investigation_id=? ORDER BY timestamp ASC",
            (investigation_id,),
            "SELECT COUNT(*) FROM timeline_events WHERE investigation_id=?",
            (investigation_id,)
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/investigations/<investigation_id>/timeline', methods=['POST'])
@require_auth
def add_timeline_event(investigation_id):
    """Ajouter un evenement a la timeline d'une enquete"""
    try:
        db = get_db()
        existing = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        body = request.get_json()
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
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES ARTEFACTS / UPLOAD
# ============================================================================

@app.route('/api/upload', methods=['POST'])
@require_auth
def upload_file():
    """Upload de fichier pour analyse avec validation d'extension et calcul de hashes"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Aucun fichier fourni'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nom de fichier vide'}), 400

        # Securiser le nom de fichier
        filename = secure_filename(file.filename)

        # Valider l'extension
        if not _allowed_file(filename):
            return jsonify({
                'error': f'Extension de fichier non autorisee. Extensions valides: {", ".join(sorted(ALLOWED_EXTENSIONS))}'
            }), 400

        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp_str}_{filename}"

        # Sauvegarder le fichier
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)

        # Calculer les empreintes
        md5_hash, sha1_hash, sha256_hash = _compute_file_hashes(filepath)
        file_size = os.path.getsize(filepath)

        # Inserer l'artefact dans la base si une investigation_id est fournie
        investigation_id = request.form.get('investigation_id')
        artifact_id = None

        if investigation_id:
            db = get_db()
            inv_exists = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
            if inv_exists:
                ext = os.path.splitext(filename)[1].lower()
                cursor = db.execute(
                    "INSERT INTO artifacts (investigation_id, filename, original_filename, file_path, file_size, file_hash_md5, file_hash_sha1, file_hash_sha256, file_type, uploaded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (investigation_id, unique_filename, filename, filepath, file_size, md5_hash, sha1_hash, sha256_hash, ext, g.user_id)
                )
                db.execute("UPDATE investigations SET updated_at=? WHERE id=?", (datetime.datetime.now().isoformat(), investigation_id))
                db.commit()
                artifact_id = cursor.lastrowid

                # Journaliser l'upload
                log_audit(
                    g.user_id, g.username, 'upload_artifact',
                    target_type='artifact', target_id=str(artifact_id),
                    details=json.dumps({'filename': filename, 'investigation_id': investigation_id, 'sha256': sha256_hash}),
                    ip_address=request.remote_addr
                )

        return jsonify({
            'filename': unique_filename,
            'original_filename': filename,
            'filepath': filepath,
            'size': file_size,
            'artifact_id': artifact_id,
            'hashes': {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash
            },
            'message': 'Fichier uploade avec succes'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/investigations/<investigation_id>/artifacts', methods=['GET'])
@require_auth
def get_investigation_artifacts(investigation_id):
    """Recuperer la liste paginee des artefacts d'une enquete"""
    try:
        db = get_db()
        existing = db.execute("SELECT id FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not existing:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        result = _paginate_query(
            "SELECT * FROM artifacts WHERE investigation_id=? ORDER BY uploaded_at DESC",
            (investigation_id,),
            "SELECT COUNT(*) FROM artifacts WHERE investigation_id=?",
            (investigation_id,)
        )

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTE ANALYSE
# ============================================================================

@app.route('/api/analyze', methods=['POST'])
@require_auth
def analyze_file():
    """Analyser un fichier via Phoenix ou le parser standalone"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        query = data.get('query', 'Analyse generale du fichier')
        investigation_id = data.get('investigation_id')
        event_id_filter = data.get('event_id_filter')

        if not filename:
            return jsonify({'error': 'Nom de fichier requis'}), 400

        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        if not os.path.exists(filepath):
            return jsonify({'error': 'Fichier non trouve'}), 404

        # Generer un ID d'analyse unique
        analysis_id = str(uuid.uuid4())
        analysis_progress[analysis_id] = {'progress': 0, 'status': 'starting'}

        # Capturer les infos utilisateur pour le thread
        user_id = g.user_id
        username = g.username

        # Lancer l'analyse dans le pool de threads
        def run_analysis():
            try:
                # Progression: chargement
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 10,
                    'status': 'Chargement du fichier...'
                })

                # Progression: analyse en cours
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 30,
                    'status': 'Analyse en cours...'
                })

                # Effectuer l'analyse
                if PHOENIX_AVAILABLE:
                    # Charger les donnees d'investigation pour Phoenix
                    investigation_data = {}
                    if investigation_id:
                        with app.app_context():
                            db = get_db()
                            inv_row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
                            if inv_row:
                                investigation_data = dict_from_row(inv_row)

                    result = analyse_fichier(filepath, query, investigation_data, event_id_filter)
                    result_text = str(result)

                    # Extraire et sauvegarder les conclusions via Phoenix
                    if investigation_data:
                        updated_data = extraire_et_sauvegarder_conclusions(
                            investigation_data, result_text, filename
                        )
                else:
                    # Mode standalone : parser natif sans IA
                    parsed = analyze_file_standalone(filepath, event_id_filter)
                    result_text = parsed.get('summary', 'Aucun resultat')

                    if parsed.get('error'):
                        result_text = f"Erreur: {parsed['error']}\n{result_text}"

                    # Extraction automatique des IoCs et insertion en base
                    if investigation_id and parsed.get('iocs'):
                        with app.app_context():
                            db = get_db()
                            for ioc in parsed['iocs']:
                                try:
                                    db.execute(
                                        "INSERT OR IGNORE INTO iocs (investigation_id, type, value, source) VALUES (?, ?, ?, ?)",
                                        (investigation_id, ioc['type'], ioc['value'], ioc.get('source', 'auto-extract'))
                                    )
                                except Exception:
                                    pass
                            db.execute("UPDATE investigations SET updated_at=? WHERE id=?", (datetime.datetime.now().isoformat(), investigation_id))
                            db.commit()

                # Progression: extraction des IoCs
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 70,
                    'status': 'Extraction des IoCs...'
                })

                # Extraire les IoCs du resultat textuel et les inserer en base
                if investigation_id and result_text:
                    text_iocs = extract_iocs(result_text)
                    if text_iocs:
                        with app.app_context():
                            db = get_db()
                            for ioc in text_iocs:
                                try:
                                    db.execute(
                                        "INSERT OR IGNORE INTO iocs (investigation_id, type, value, source) VALUES (?, ?, ?, ?)",
                                        (investigation_id, ioc['type'], ioc['value'], ioc.get('source', 'auto-extract'))
                                    )
                                except Exception:
                                    pass
                            db.commit()

                # Mettre a jour le resultat d'analyse de l'artefact en base
                if investigation_id:
                    with app.app_context():
                        db = get_db()
                        db.execute(
                            "UPDATE artifacts SET analysis_result=? WHERE investigation_id=? AND filename=?",
                            (result_text[:50000], investigation_id, filename)
                        )
                        db.commit()

                # Progression: termine
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 100,
                    'status': 'Analyse terminee',
                    'result': result_text
                })

                analysis_progress[analysis_id] = {
                    'progress': 100,
                    'status': 'completed',
                    'result': result_text
                }

                # Journaliser l'analyse (dans le contexte applicatif)
                with app.app_context():
                    log_audit(
                        user_id, username, 'analyze_file',
                        target_type='artifact', target_id=filename,
                        details=json.dumps({'investigation_id': investigation_id, 'query': query[:200]}),
                        ip_address=None
                    )

            except Exception as e:
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 100,
                    'status': 'error',
                    'error': str(e)
                })
                analysis_progress[analysis_id] = {
                    'progress': 100,
                    'status': 'error',
                    'error': str(e)
                }

        # Soumettre au pool de threads
        executor.submit(run_analysis)

        return jsonify({
            'analysis_id': analysis_id,
            'message': 'Analyse demarree',
            'status': 'started'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/analysis/<analysis_id>/status', methods=['GET'])
@require_auth
def get_analysis_status(analysis_id):
    """Recuperer le statut d'une analyse"""
    if analysis_id in analysis_progress:
        return jsonify(analysis_progress[analysis_id])
    else:
        return jsonify({'error': 'Analyse non trouvee'}), 404

# ============================================================================
# ROUTES RAPPORTS
# ============================================================================

@app.route('/api/reports/generate', methods=['POST'])
@require_auth
def generate_report():
    """Generer un rapport pour une enquete"""
    try:
        data = request.get_json()
        investigation_id = data.get('investigation_id')
        report_format = data.get('format', 'html')
        template = data.get('template', 'executive')

        if not investigation_id:
            return jsonify({'error': 'ID d\'enquete requis'}), 400

        db = get_db()
        inv_row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not inv_row:
            return jsonify({'error': 'Enquete non trouvee'}), 404

        investigation_data = dict_from_row(inv_row)

        # Recuperer les IoCs et artefacts pour le rapport
        investigation_data['iocs'] = rows_to_list(
            db.execute("SELECT * FROM iocs WHERE investigation_id=?", (investigation_id,)).fetchall()
        )
        investigation_data['artifacts'] = rows_to_list(
            db.execute("SELECT * FROM artifacts WHERE investigation_id=?", (investigation_id,)).fetchall()
        )
        investigation_data['timeline_events'] = rows_to_list(
            db.execute("SELECT * FROM timeline_events WHERE investigation_id=? ORDER BY timestamp ASC", (investigation_id,)).fetchall()
        )

        # Generer le rapport
        if PHOENIX_AVAILABLE:
            resume_executif = generer_resume_executif_ia(investigation_data)
            report_content = creer_contenu_rapport(investigation_data, resume_executif)
        else:
            # Rapport statique construit a partir des donnees SQLite
            report_lines = [
                f"# Rapport d'Enquete: {investigation_data.get('name', 'Sans nom')}",
                f"\nDate: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Statut: {investigation_data.get('status', 'N/A')}",
                f"\n## Artefacts ({len(investigation_data['artifacts'])})",
            ]
            for art in investigation_data['artifacts']:
                report_lines.append(f"- {art.get('original_filename', art.get('filename', 'N/A'))} (SHA256: {art.get('file_hash_sha256', 'N/A')})")

            report_lines.append(f"\n## IoCs ({len(investigation_data['iocs'])})")
            for ioc in investigation_data['iocs']:
                report_lines.append(f"- [{ioc.get('type', 'N/A')}] {ioc.get('value', 'N/A')} (source: {ioc.get('source', 'N/A')})")

            report_lines.append(f"\n## Timeline ({len(investigation_data['timeline_events'])})")
            for evt in investigation_data['timeline_events']:
                report_lines.append(f"- {evt.get('timestamp', 'N/A')} [{evt.get('severity', 'info')}] {evt.get('event', 'N/A')}")

            report_content = '\n'.join(report_lines)

        # Sauvegarder le rapport
        report_filename = f"rapport_{investigation_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        report_path = os.path.join(reports_dir, report_filename)

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)

        # Journaliser la generation
        log_audit(
            g.user_id, g.username, 'generate_report',
            target_type='report', target_id=report_filename,
            details=json.dumps({'investigation_id': investigation_id, 'format': report_format}),
            ip_address=request.remote_addr
        )

        return jsonify({
            'report_id': report_filename,
            'report_path': report_path,
            'format': report_format,
            'message': 'Rapport genere avec succes'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reports/<report_id>/download', methods=['GET'])
@require_auth
def download_report(report_id):
    """Telecharger un rapport (avec protection contre la traversee de chemin)"""
    try:
        clean_id = _sanitize_report_id(report_id)
        if not clean_id:
            return jsonify({'error': 'Identifiant de rapport invalide'}), 400

        reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
        report_path = os.path.join(reports_dir, clean_id)

        if not os.path.exists(report_path):
            return jsonify({'error': 'Rapport non trouve'}), 404

        return send_file(report_path, as_attachment=True)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTE OUTILS - HASH
# ============================================================================

@app.route('/api/tools/hash', methods=['POST'])
@require_auth
def calculate_file_hash():
    """Calculer les empreintes MD5, SHA1 et SHA256 d'un fichier uploade"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Aucun fichier fourni'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nom de fichier vide'}), 400

        # Lire le contenu du fichier en memoire pour calculer les empreintes
        file_content = file.read()

        md5_hash = hashlib.md5(file_content).hexdigest()
        sha1_hash = hashlib.sha1(file_content).hexdigest()
        sha256_hash = hashlib.sha256(file_content).hexdigest()

        return jsonify({
            'filename': secure_filename(file.filename),
            'size': len(file_content),
            'hashes': {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ROUTES STATISTIQUES
# ============================================================================

@app.route('/api/stats', methods=['GET'])
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

# ============================================================================
# ROUTE JOURNAL D'AUDIT (admin seulement)
# ============================================================================

@app.route('/api/audit', methods=['GET'])
@require_auth
@require_role('admin')
def get_audit_log():
    """Recuperer le journal d'audit (admin uniquement, pagine)"""
    try:
        result = _paginate_query(
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

# ============================================================================
# EXPORT STIX 2.1
# ============================================================================

@app.route('/api/investigations/<investigation_id>/export/stix', methods=['GET'])
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
        now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z')

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
            pattern = _build_stix_pattern(ioc_type, ioc_value)
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


def _build_stix_pattern(ioc_type, ioc_value):
    """Construire un pattern STIX 2.1 a partir d'un type et d'une valeur d'IoC"""
    # Echapper les guillemets simples dans la valeur
    safe_value = ioc_value.replace("'", "\\'")

    pattern_map = {
        'ip': f"[ipv4-addr:value = '{safe_value}']",
        'domain': f"[domain-name:value = '{safe_value}']",
        'hash_md5': f"[file:hashes.MD5 = '{safe_value}']",
        'hash_sha1': f"[file:hashes.'SHA-1' = '{safe_value}']",
        'hash_sha256': f"[file:hashes.'SHA-256' = '{safe_value}']",
        'url': f"[url:value = '{safe_value}']",
        'email': f"[email-addr:value = '{safe_value}']",
        'filename': f"[file:name = '{safe_value}']",
        'registry_key': f"[windows-registry-key:key = '{safe_value}']",
        'cve': f"[vulnerability:name = '{safe_value}']",
    }

    return pattern_map.get(ioc_type)

# ============================================================================
# INTEGRATIONS MANAGEMENT
# ============================================================================

@app.route('/api/integrations', methods=['GET'])
@require_auth
def list_integrations():
    """Lister tous les connecteurs disponibles avec leur statut"""
    try:
        from integrations import registry as int_registry

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


@app.route('/api/integrations/<connector_id>', methods=['GET'])
@require_auth
def get_integration(connector_id):
    """Recuperer la configuration d'un connecteur"""
    try:
        from integrations import registry as int_registry

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


@app.route('/api/integrations/<connector_id>', methods=['PUT'])
@require_auth
@require_role('admin')
def update_integration(connector_id):
    """Configurer un connecteur (admin uniquement)"""
    try:
        from integrations import registry as int_registry

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


@app.route('/api/integrations/<connector_id>/test', methods=['POST'])
@require_auth
@require_role('admin')
def test_integration(connector_id):
    """Tester la connexion d'un connecteur"""
    try:
        from integrations import registry as int_registry

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


@app.route('/api/integrations/<connector_id>/enrich', methods=['POST'])
@require_auth
def enrich_via_integration(connector_id):
    """Enrichir un IoC via un connecteur specifique"""
    try:
        from integrations import registry as int_registry

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


@app.route('/api/integrations/<connector_id>/push', methods=['POST'])
@require_auth
def push_to_integration(connector_id):
    """Pousser des IoCs vers un connecteur (ex: MISP)"""
    try:
        from integrations import registry as int_registry

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


@app.route('/api/integrations/<connector_id>/pull', methods=['POST'])
@require_auth
def pull_from_integration(connector_id):
    """Recuperer des IoCs depuis un connecteur et les importer"""
    try:
        from integrations import registry as int_registry

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

# ============================================================================
# MITRE ATT&CK MAPPING
# ============================================================================

@app.route('/api/investigations/<investigation_id>/mitre', methods=['GET'])
@require_auth
def get_mitre_mapping(investigation_id):
    """Retourner le mapping MITRE ATT&CK pour une enquete"""
    try:
        from mitre import get_attack_for_ioc

        db = get_db()
        inv_row = db.execute("SELECT * FROM investigations WHERE id=?", (investigation_id,)).fetchone()
        if not inv_row:
            return jsonify({'error': 'Enquete non trouvee'}), 404

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
        return jsonify({'error': str(e)}), 500

# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Connexion WebSocket avec verification d'authentification"""
    # Verifier le token passe en query string ou en header
    token = request.args.get('token', '')
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]

    if token:
        payload = decode_token(token)
        if payload:
            print(f"Client connecte: {payload.get('username', 'inconnu')}")
            emit('connected', {'message': 'Connexion etablie avec Phoenix DFIR', 'authenticated': True})
            return

    # Permettre la connexion mais signaler l'absence d'authentification
    print('Client connecte sans authentification')
    emit('connected', {'message': 'Connexion etablie avec Phoenix DFIR', 'authenticated': False})


@socketio.on('disconnect')
def handle_disconnect():
    """Deconnexion WebSocket"""
    print('Client deconnecte')


@socketio.on('join_investigation')
def handle_join_investigation(data):
    """Rejoindre une enquete pour les notifications temps reel"""
    # Verifier l'authentification
    token = request.args.get('token', '')
    if not token:
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]

    payload = decode_token(token) if token else None

    investigation_id = data.get('investigation_id')
    if investigation_id:
        username = payload.get('username', 'anonyme') if payload else 'anonyme'
        emit('joined_investigation', {
            'investigation_id': investigation_id,
            'user': username
        })

# ============================================================================
# POINT D'ENTREE
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("Phoenix DFIR - Backend API")
    print("=" * 60)
    print(f"Phoenix Core disponible: {PHOENIX_AVAILABLE}")
    print(f"Dossier uploads: {app.config['UPLOAD_FOLDER']}")
    print(f"Base de donnees: SQLite")
    print("=" * 60)

    # Nettoyer les anciens fichiers au demarrage
    cleanup_old_files()

    # Mode debug depuis variable d'environnement (False par defaut)
    debug_mode = os.environ.get('PHOENIX_DEBUG', 'false').lower() in ('true', '1', 'yes')

    # Demarrer le serveur
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=debug_mode
    )
