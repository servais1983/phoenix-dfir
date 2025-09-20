#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR - Backend API Flask
Interface graphique professionnelle pour Phoenix DFIR
"""

import os
import sys
import json
import datetime
import uuid
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
import threading
import time

# Ajouter le chemin du module Phoenix original
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))

# Import des modules Phoenix
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

# Configuration Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'phoenix-dfir-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max

# Extensions
CORS(app, origins=["http://localhost:3000", "http://localhost:5173"])
socketio = SocketIO(app, cors_allowed_origins=["http://localhost:3000", "http://localhost:5173"])

# Créer les dossiers nécessaires
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('sessions', exist_ok=True)
os.makedirs('reports', exist_ok=True)

# Variables globales pour les sessions
active_sessions = {}
analysis_progress = {}

# ============================================================================
# ROUTES API
# ============================================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Vérification de l'état du système"""
    return jsonify({
        'status': 'healthy',
        'phoenix_available': PHOENIX_AVAILABLE,
        'timestamp': datetime.datetime.now().isoformat()
    })

@app.route('/api/investigations', methods=['GET'])
def get_investigations():
    """Récupérer la liste des enquêtes"""
    try:
        investigations = []
        sessions_dir = Path('sessions')
        
        for session_file in sessions_dir.glob('*.json'):
            try:
                with open(session_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    investigations.append({
                        'id': session_file.stem,
                        'name': data.get('nom_du_cas', 'Sans nom'),
                        'status': 'active' if session_file.stem in active_sessions else 'inactive',
                        'created': data.get('date_creation', ''),
                        'artifacts': len(data.get('artefacts_analyses', [])),
                        'iocs': sum(len(iocs) for iocs in data.get('iocs', {}).values()),
                        'lastActivity': data.get('derniere_activite', data.get('date_creation', ''))
                    })
            except Exception as e:
                print(f"Erreur lors du chargement de {session_file}: {e}")
                continue
        
        return jsonify(investigations)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/investigations', methods=['POST'])
def create_investigation():
    """Créer une nouvelle enquête"""
    try:
        data = request.get_json()
        investigation_name = data.get('name', f'Investigation-{datetime.datetime.now().strftime("%Y%m%d-%H%M%S")}')
        
        # Créer la structure de données de l'enquête
        investigation_data = {
            'nom_du_cas': investigation_name,
            'date_creation': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'derniere_activite': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'artefacts_analyses': [],
            'timeline_events': [],
            'iocs': {
                'ips': [],
                'hashes': [],
                'domaines': []
            }
        }
        
        # Générer un ID unique
        investigation_id = str(uuid.uuid4())
        
        # Sauvegarder la session
        session_file = f'sessions/{investigation_id}.json'
        with open(session_file, 'w', encoding='utf-8') as f:
            json.dump(investigation_data, f, indent=2, ensure_ascii=False)
        
        # Ajouter aux sessions actives
        active_sessions[investigation_id] = investigation_data
        
        return jsonify({
            'id': investigation_id,
            'name': investigation_name,
            'status': 'created',
            'message': 'Enquête créée avec succès'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/investigations/<investigation_id>', methods=['GET'])
def get_investigation(investigation_id):
    """Récupérer les détails d'une enquête"""
    try:
        session_file = f'sessions/{investigation_id}.json'
        
        if os.path.exists(session_file):
            with open(session_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return jsonify(data)
        else:
            return jsonify({'error': 'Enquête non trouvée'}), 404
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Upload de fichier pour analyse"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Aucun fichier fourni'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Nom de fichier vide'}), 400
        
        # Sécuriser le nom de fichier
        filename = secure_filename(file.filename)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{filename}"
        
        # Sauvegarder le fichier
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        return jsonify({
            'filename': unique_filename,
            'original_filename': filename,
            'filepath': filepath,
            'size': os.path.getsize(filepath),
            'message': 'Fichier uploadé avec succès'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
def analyze_file():
    """Analyser un fichier"""
    try:
        data = request.get_json()
        filename = data.get('filename')
        query = data.get('query', 'Analyse générale du fichier')
        investigation_id = data.get('investigation_id')
        event_id_filter = data.get('event_id_filter')
        
        if not filename:
            return jsonify({'error': 'Nom de fichier requis'}), 400
        
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Fichier non trouvé'}), 404
        
        # Générer un ID d'analyse unique
        analysis_id = str(uuid.uuid4())
        analysis_progress[analysis_id] = {'progress': 0, 'status': 'starting'}
        
        # Lancer l'analyse dans un thread séparé
        def run_analysis():
            try:
                # Simuler progression
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 10,
                    'status': 'Chargement du fichier...'
                })
                
                # Charger la session d'enquête si fournie
                investigation_data = {}
                if investigation_id:
                    session_file = f'sessions/{investigation_id}.json'
                    if os.path.exists(session_file):
                        with open(session_file, 'r', encoding='utf-8') as f:
                            investigation_data = json.load(f)
                
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 30,
                    'status': 'Analyse en cours...'
                })
                
                # Effectuer l'analyse avec Phoenix
                if PHOENIX_AVAILABLE:
                    result = analyse_fichier(filepath, query, investigation_data, event_id_filter)
                else:
                    result = f"Analyse simulée du fichier {filename} avec la question: {query}"
                
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 70,
                    'status': 'Extraction des IoCs...'
                })
                
                # Extraire et sauvegarder les conclusions
                if PHOENIX_AVAILABLE and investigation_data:
                    updated_data = extraire_et_sauvegarder_conclusions(
                        investigation_data, str(result), filename
                    )
                    
                    # Sauvegarder la session mise à jour
                    if investigation_id:
                        session_file = f'sessions/{investigation_id}.json'
                        with open(session_file, 'w', encoding='utf-8') as f:
                            json.dump(updated_data, f, indent=2, ensure_ascii=False)
                
                socketio.emit('analysis_progress', {
                    'analysis_id': analysis_id,
                    'progress': 100,
                    'status': 'Analyse terminée',
                    'result': str(result)
                })
                
                analysis_progress[analysis_id] = {
                    'progress': 100,
                    'status': 'completed',
                    'result': str(result)
                }
                
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
        
        # Démarrer l'analyse
        thread = threading.Thread(target=run_analysis)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'analysis_id': analysis_id,
            'message': 'Analyse démarrée',
            'status': 'started'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analysis/<analysis_id>/status', methods=['GET'])
def get_analysis_status(analysis_id):
    """Récupérer le statut d'une analyse"""
    if analysis_id in analysis_progress:
        return jsonify(analysis_progress[analysis_id])
    else:
        return jsonify({'error': 'Analyse non trouvée'}), 404

@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """Générer un rapport"""
    try:
        data = request.get_json()
        investigation_id = data.get('investigation_id')
        report_format = data.get('format', 'html')
        template = data.get('template', 'executive')
        
        if not investigation_id:
            return jsonify({'error': 'ID d\'enquête requis'}), 400
        
        # Charger les données d'enquête
        session_file = f'sessions/{investigation_id}.json'
        if not os.path.exists(session_file):
            return jsonify({'error': 'Enquête non trouvée'}), 404
        
        with open(session_file, 'r', encoding='utf-8') as f:
            investigation_data = json.load(f)
        
        # Générer le rapport
        if PHOENIX_AVAILABLE:
            resume_executif = generer_resume_executif_ia(investigation_data)
            report_content = creer_contenu_rapport(investigation_data, resume_executif)
        else:
            report_content = f"# Rapport d'Enquête: {investigation_data.get('nom_du_cas', 'Sans nom')}\n\nRapport simulé généré le {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Sauvegarder le rapport
        report_filename = f"rapport_{investigation_id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = os.path.join('reports', report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        return jsonify({
            'report_id': report_filename,
            'report_path': report_path,
            'format': report_format,
            'message': 'Rapport généré avec succès'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/<report_id>/download', methods=['GET'])
def download_report(report_id):
    """Télécharger un rapport"""
    try:
        report_path = os.path.join('reports', report_id)
        
        if not os.path.exists(report_path):
            return jsonify({'error': 'Rapport non trouvé'}), 404
        
        return send_file(report_path, as_attachment=True)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Connexion WebSocket"""
    print('Client connecté')
    emit('connected', {'message': 'Connexion établie avec Phoenix DFIR'})

@socketio.on('disconnect')
def handle_disconnect():
    """Déconnexion WebSocket"""
    print('Client déconnecté')

@socketio.on('join_investigation')
def handle_join_investigation(data):
    """Rejoindre une enquête"""
    investigation_id = data.get('investigation_id')
    if investigation_id:
        # Ajouter le client à la room de l'enquête
        # (pour les notifications en temps réel)
        emit('joined_investigation', {'investigation_id': investigation_id})

# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

def cleanup_old_files():
    """Nettoyer les anciens fichiers"""
    try:
        # Nettoyer les uploads de plus de 24h
        uploads_dir = Path(app.config['UPLOAD_FOLDER'])
        cutoff_time = time.time() - (24 * 60 * 60)  # 24 heures
        
        for file_path in uploads_dir.glob('*'):
            if file_path.stat().st_mtime < cutoff_time:
                file_path.unlink()
                print(f"Fichier supprimé: {file_path}")
                
    except Exception as e:
        print(f"Erreur lors du nettoyage: {e}")

# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

if __name__ == '__main__':
    print("=" * 60)
    print("🔥 Phoenix DFIR - Backend API")
    print("=" * 60)
    print(f"Phoenix Core disponible: {PHOENIX_AVAILABLE}")
    print(f"Dossier uploads: {app.config['UPLOAD_FOLDER']}")
    print("=" * 60)
    
    # Nettoyer les anciens fichiers au démarrage
    cleanup_old_files()
    
    # Démarrer le serveur
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True
    )
