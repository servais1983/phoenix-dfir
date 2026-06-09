#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR - Fonctions utilitaires partagees par les blueprints.
"""

import hashlib
import os
import time
from pathlib import Path

from flask import request

from database import get_db, rows_to_list
from extensions import ALLOWED_EXTENSIONS


def allowed_file(filename):
    """Verifier si l'extension du fichier est autorisee"""
    ext = os.path.splitext(filename)[1].lower()
    return ext in ALLOWED_EXTENSIONS


def paginate_query(query, params, count_query, count_params):
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


def compute_file_hashes(filepath):
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


def sanitize_report_id(report_id):
    """Assainir le report_id pour prevenir les traversees de chemin"""
    # Retirer tout caractere de traversee de chemin
    clean = os.path.basename(report_id)
    if '..' in clean or '/' in clean or '\\' in clean:
        return None
    if not clean:
        return None
    return clean


def cleanup_old_files(app):
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


def build_stix_pattern(ioc_type, ioc_value):
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
