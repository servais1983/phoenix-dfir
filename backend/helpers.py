#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR - Fonctions utilitaires partagees par les blueprints.
"""

import hashlib
import logging
import os
import time
from pathlib import Path

from flask import g, jsonify, request

from database import get_db, rows_to_list
from extensions import ALLOWED_EXTENSIONS


_logger = logging.getLogger('phoenix')


def server_error(exc=None, message='Erreur interne du serveur', status=500):
    """Reponse d'erreur generique : le detail reste dans les logs serveur.

    Le client recoit un message neutre et l'identifiant de requete, qui
    permet de retrouver la trace complete cote serveur.
    """
    request_id = getattr(g, 'request_id', None)
    if exc is not None:
        _logger.error('request_failed', exc_info=exc,
                      extra={'request_id': request_id, 'path': request.path if request else None})
    return jsonify({'error': message, 'request_id': request_id}), status


def resolve_upload_path(upload_folder, name):
    """Chemin absolu d'un fichier uploade designe par son nom stocke, ou None.

    Refuse tout ce qui n'est pas un simple nom de fichier situe directement
    dans le dossier d'uploads : '..', chemins absolus, separateurs, fichiers
    caches, et liens symboliques pointant hors du dossier.
    """
    if not isinstance(name, str) or not name or '\x00' in name:
        return None
    if name in ('.', '..') or name.startswith('.') or '/' in name or '\\' in name:
        return None
    if os.path.isabs(name) or os.path.basename(name) != name:
        return None
    root = os.path.realpath(upload_folder)
    target = os.path.realpath(os.path.join(root, name))
    if os.path.dirname(target) != root:
        return None
    if not os.path.isfile(target):
        return None
    return target


def path_within(path, root):
    """Le chemin (resolu) est-il strictement contenu dans root ?"""
    if not path or not root:
        return False
    real_root = os.path.realpath(root)
    target = os.path.realpath(path)
    return target.startswith(real_root + os.sep)


_CSV_FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')


def csv_safe(value):
    """Neutraliser l'injection de formules (CSV injection) dans un tableur."""
    if value is None:
        return ''
    text = str(value)
    if text.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + text
    return text


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
    """Nettoyer les uploads orphelins de plus de 24h.

    Les fichiers references par un artefact en base (evidences d'enquete)
    ne sont JAMAIS supprimes : seuls les uploads sans enquete (outil de
    hash, uploads abandonnes) sont purges.
    """
    try:
        uploads_dir = Path(app.config['UPLOAD_FOLDER'])
        cutoff_time = time.time() - (24 * 60 * 60)  # 24 heures

        with app.app_context():
            db = get_db()
            protected = {row[0] for row in db.execute(
                "SELECT filename FROM artifacts WHERE filename IS NOT NULL").fetchall()}
            protected |= {os.path.basename(row[0]) for row in db.execute(
                "SELECT file_path FROM artifacts WHERE file_path IS NOT NULL").fetchall()}

        for file_path in uploads_dir.glob('*'):
            if not file_path.is_file() or file_path.name in protected:
                continue
            if file_path.stat().st_mtime < cutoff_time:
                file_path.unlink()
                print(f"Fichier orphelin supprime: {file_path}")

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
