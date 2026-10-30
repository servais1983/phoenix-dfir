#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Coffre de preuves (evidence vault) monte en LECTURE SEULE.

Les evidences volumineuses (dumps RAM, $MFT, EVTX, images) sont deposees sur
l'hote dans un dossier monte en lecture seule dans le conteneur
(docker-compose : ./evidence_vault:/mnt/evidence:ro). Phoenix ne les copie ni
ne les modifie : l'import dans une enquete calcule les empreintes
MD5/SHA1/SHA256, rattache l'artefact par reference et scelle l'acquisition
dans la chaine de preuve.

Emplacement : PHOENIX_EVIDENCE_VAULT, sinon /mnt/evidence s'il existe, sinon
<depot>/evidence_vault (installation locale).
"""

import datetime
import os

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAX_LISTED = 2000


def vault_dir():
    explicit = os.environ.get('PHOENIX_EVIDENCE_VAULT', '').strip()
    if explicit:
        return explicit
    if os.path.isdir('/mnt/evidence'):
        return '/mnt/evidence'
    return os.path.join(_REPO_ROOT, 'evidence_vault')


def _within(target, root, strict=False):
    target, root = os.path.normcase(target), os.path.normcase(root)
    if target == root:
        return not strict
    try:
        return os.path.commonpath([target, root]) == root
    except ValueError:  # lecteurs differents (Windows)
        return False


def is_read_only(path=None):
    path = path or vault_dir()
    return os.path.isdir(path) and not os.access(path, os.W_OK)


def resolve(rel_path):
    """Chemin absolu d'un fichier du coffre, ou None s'il sort du coffre
    (traversee de repertoire, lien symbolique vers l'exterieur...)."""
    if not rel_path or not isinstance(rel_path, str):
        return None
    root = os.path.realpath(vault_dir())
    target = os.path.realpath(os.path.join(root, rel_path))
    if not _within(target, root, strict=True):
        return None
    return target if os.path.isfile(target) else None


def contains(path):
    """Le chemin (absolu) est-il situe dans le coffre ?"""
    return _within(os.path.realpath(path), os.path.realpath(vault_dir()))


def list_files():
    root = vault_dir()
    info = {
        'vault_dir': root,
        'exists': os.path.isdir(root),
        'read_only': is_read_only(root),
        'files': [],
        'truncated': False,
    }
    if not info['exists']:
        return info
    real_root = os.path.realpath(root)
    for current, dirs, files in os.walk(real_root):
        dirs[:] = sorted(d for d in dirs if not d.startswith('.'))
        for fname in sorted(files):
            if fname.startswith('.'):
                continue
            if len(info['files']) >= MAX_LISTED:
                info['truncated'] = True
                return info
            path = os.path.join(current, fname)
            try:
                st = os.stat(path)
            except OSError:
                continue
            info['files'].append({
                'path': os.path.relpath(path, real_root),
                'name': fname,
                'size': st.st_size,
                'extension': os.path.splitext(fname)[1].lower(),
                'modified_at': datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec='seconds'),
            })
    return info
