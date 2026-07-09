#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dossier de depot surveille : tout se fait seul.

Deposez vos evidences (EVTX, CSV, JSON, logs, Prefetch, LNK...) dans le
dossier d'inbox (par defaut backend/evidence_inbox/, configurable via
PHOENIX_EVIDENCE_DIR) :

1. Le watcher detecte les fichiers des qu'ils sont stables (taille inchangee
   entre deux scans) ;
2. il cree automatiquement une enquete et y rattache les artefacts
   (un sous-dossier depose = une enquete portant son nom ; les fichiers
   libres deposes ensemble = une enquete horodatee) ;
3. si GitHub Copilot est configure (GITHUB_TOKEN), l'enqueteur autonome
   demarre immediatement et le rapport arrive dans backend/reports/.

Desactivation : PHOENIX_INBOX_ENABLED=false. Le deplacement des fichiers via
os.replace rend le traitement sur pour un seul processus surveillant l'inbox
(configuration par defaut : 1 worker).
"""

import datetime
import os
import shutil
import threading
import time
import uuid

import autonomous
from database import get_db, log_audit
from extensions import socketio
from helpers import compute_file_hashes

_INBOX_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'evidence_inbox')
_IGNORED_SUFFIXES = ('.tmp', '.part', '.partial', '.crdownload', '.swp')
_README_NAME = 'LISEZMOI.txt'

_README_CONTENT = """Phoenix DFIR - Dossier de depot des evidences
=============================================

Deposez ici vos evidences (fichiers EVTX, CSV, JSON, logs, Prefetch, LNK,
historiques navigateurs...) : tout se fait seul.

- Un SOUS-DOSSIER depose ici = une enquete portant son nom.
- Des FICHIERS deposes directement ici = une enquete horodatee commune.

Des que les fichiers sont completement copies, Phoenix :
1. cree l'enquete et y rattache les artefacts (hashes calcules) ;
2. lance l'enqueteur autonome GitHub Copilot (si GITHUB_TOKEN est configure) ;
3. genere le rapport dans backend/reports/ et l'interface web.

Ce fichier est ignore par le watcher.
"""

_state = {'thread': None, 'active': False}


def inbox_dir():
    return os.environ.get('PHOENIX_EVIDENCE_DIR', _INBOX_DEFAULT)


def is_active():
    return _state['active']


def poll_seconds():
    try:
        return max(2, int(os.environ.get('PHOENIX_INBOX_POLL_SECONDS', '10')))
    except ValueError:
        return 10


def start_watcher(app):
    """Demarrer le thread de surveillance (idempotent)."""
    if os.environ.get('PHOENIX_INBOX_ENABLED', 'true').lower() in ('false', '0', 'no'):
        return None
    if _state['thread'] and _state['thread'].is_alive():
        return _state['thread']

    directory = inbox_dir()
    os.makedirs(directory, exist_ok=True)
    readme = os.path.join(directory, _README_NAME)
    if not os.path.exists(readme):
        try:
            with open(readme, 'w', encoding='utf-8') as f:
                f.write(_README_CONTENT)
        except OSError:
            pass

    thread = threading.Thread(target=_watch_loop, args=(app,), daemon=True,
                              name='phoenix-inbox-watcher')
    _state['thread'] = thread
    _state['active'] = True
    thread.start()
    return thread


def _watch_loop(app):
    previous_signature = None
    while True:
        try:
            entries = _scan_entries()
            signature = _signature(entries)
            # Ne traiter que lorsque le contenu est stable entre deux scans
            if entries and signature == previous_signature:
                _process_entries(app, entries)
                previous_signature = None
            else:
                previous_signature = signature
        except Exception as e:
            try:
                app.logger.warning('Watcher inbox: %s', e)
            except Exception:
                pass
            previous_signature = None
        time.sleep(poll_seconds())


def _scan_entries():
    """Lister les elements a traiter : (chemin, est_dossier)."""
    directory = inbox_dir()
    if not os.path.isdir(directory):
        return []
    entries = []
    for name in sorted(os.listdir(directory)):
        if name == _README_NAME or name.startswith('.') or name.lower().endswith(_IGNORED_SUFFIXES):
            continue
        path = os.path.join(directory, name)
        entries.append((path, os.path.isdir(path)))
    return entries


def _entry_size(path, is_dir):
    if not is_dir:
        try:
            return os.path.getsize(path)
        except OSError:
            return -1
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _signature(entries):
    return tuple((path, is_dir, _entry_size(path, is_dir)) for path, is_dir in entries)


def _iter_files(path, is_dir):
    if not is_dir:
        yield path
        return
    for root, _dirs, files in os.walk(path):
        for f in sorted(files):
            yield os.path.join(root, f)


def _process_entries(app, entries):
    """Transformer les depots en enquetes : 1 dossier = 1 cas, fichiers libres = 1 cas commun."""
    loose_files = [p for p, is_dir in entries if not is_dir]
    folders = [p for p, is_dir in entries if is_dir]

    for folder in folders:
        _create_case(app, os.path.basename(folder), list(_iter_files(folder, True)), cleanup=folder)
    if loose_files:
        name = f"Depot du {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
        _create_case(app, name, loose_files)


def _create_case(app, name, files, cleanup=None):
    """Creer l'enquete, rattacher les fichiers, lancer l'enqueteur autonome."""
    if not files:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)
        return

    investigation_id = str(uuid.uuid4())
    now = datetime.datetime.now().isoformat()
    upload_dir = app.config['UPLOAD_FOLDER']
    os.makedirs(upload_dir, exist_ok=True)

    with app.app_context():
        db = get_db()
        db.execute(
            "INSERT INTO investigations (id, name, description, status, created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?)",
            (investigation_id, name,
             'Enquete creee automatiquement depuis le dossier de depot (evidence inbox).', now, now),
        )
        attached = 0
        for src in files:
            fname = os.path.basename(src)
            unique = f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{attached}_{fname}"
            dest = os.path.join(upload_dir, unique)
            try:
                os.replace(src, dest)
            except OSError:
                try:
                    shutil.move(src, dest)
                except OSError:
                    continue
            md5, sha1, sha256 = compute_file_hashes(dest)
            ext = os.path.splitext(fname)[1].lower()
            db.execute(
                "INSERT INTO artifacts (investigation_id, filename, original_filename, file_path, file_size, file_hash_md5, file_hash_sha1, file_hash_sha256, file_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (investigation_id, unique, fname, dest, os.path.getsize(dest), md5, sha1, sha256, ext),
            )
            attached += 1
        db.commit()
        log_audit(None, 'inbox-watcher', 'inbox_case_created',
                  target_type='investigation', target_id=investigation_id,
                  details=f'{{"artefacts": {attached}, "name": "{name}"}}', ip_address=None)

    if cleanup:
        shutil.rmtree(cleanup, ignore_errors=True)

    socketio.emit('notification', {
        'type': 'inbox',
        'message': f"Depot detecte : enquete '{name}' creee ({attached} artefact(s)).",
        'investigation_id': investigation_id,
    })

    if attached and autonomous.copilot_configured():
        autonomous.start_job(app, investigation_id, username='inbox-watcher')
    elif attached:
        socketio.emit('notification', {
            'type': 'inbox',
            'message': ("Enquete creee mais GitHub Copilot n'est pas configure "
                        "(GITHUB_TOKEN) : investigation autonome non lancee."),
            'investigation_id': investigation_id,
        })
