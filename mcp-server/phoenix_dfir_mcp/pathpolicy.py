"""Politique d'acces fichier (sandboxing) pour les outils DFIR.

Les outils sont pilotes par un LLM autonome : sans garde-fou, rien n'empeche
un chemin comme /etc/passwd ou ~/.ssh/id_rsa d'etre lu. Cette politique
restreint les lectures aux racines explicitement autorisees (dossier du cas,
uploads, dossier de depot, outils Zimmermann...).

Comportement :
- Si aucune racine n'est enregistree ET PHOENIX_TOOL_ROOTS n'est pas defini,
  la politique est permissive (retro-compatible : CLI ad hoc, tests).
- Des qu'au moins une racine est active (enregistree par l'enqueteur pour le
  dossier du cas, ou via PHOENIX_TOOL_ROOTS cote plateforme), tout acces hors
  de ces racines est refuse.

L'enqueteur autonome enregistre le dossier du cas au demarrage : une
investigation est donc automatiquement confinee a l'arborescence du cas.
"""

import os
import threading

_lock = threading.Lock()
_roots = set()


def _normalize(path):
    return os.path.realpath(os.path.abspath(os.path.expanduser(path)))


def _env_roots():
    raw = os.environ.get('PHOENIX_TOOL_ROOTS', '')
    return {_normalize(p) for p in raw.split(os.pathsep) if p.strip()}


def add_root(path):
    """Autoriser une racine (et son arborescence) pour les lectures d'outils."""
    if not path:
        return
    with _lock:
        _roots.add(_normalize(path))


def reset():
    """Vider les racines enregistrees (utilise par les tests)."""
    with _lock:
        _roots.clear()


def active_roots():
    return set(_roots) | _env_roots()


def is_allowed(path):
    """Le chemin est-il autorise par la politique courante ?"""
    roots = active_roots()
    if not roots:
        return True  # permissif tant qu'aucune racine n'est configuree
    target = _normalize(path)
    for root in roots:
        if target == root or target.startswith(root + os.sep):
            return True
    return False


def check(path):
    """Retourner None si autorise, sinon un dict d'erreur pret a renvoyer."""
    if is_allowed(path):
        return None
    return {'error': (f"Acces refuse par la politique de securite : '{path}' est hors des "
                      f"dossiers autorises. Restez dans l'arborescence du cas.")}
