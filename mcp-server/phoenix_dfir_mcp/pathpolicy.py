"""Politique d'acces fichier (sandboxing) pour les outils DFIR.

Les outils sont pilotes par un LLM autonome : sans garde-fou, rien n'empeche
un chemin comme /etc/passwd ou ~/.ssh/id_rsa d'etre lu. Cette politique
restreint les lectures aux racines explicitement autorisees (dossier du cas,
evidences du coffre referencees par le cas...).

Deux niveaux de racines :

- RACINES DE JOB (par investigation) : portees par une variable de contexte
  (contextvars), donc propres a chaque thread / tache. Une investigation
  autonome ouvre un `job_scope(case_dir)` : tant qu'il est actif, SEULES les
  racines de ce job sont autorisees (le dossier du cas et ce que le job a
  explicitement ajoute). Deux investigations concurrentes dans des threads
  distincts sont donc isolees : une injection de prompt dans le cas A ne peut
  ni lire ni ecrire le cas B.
- RACINES STATIQUES (hors job) : PHOENIX_TOOL_ROOTS et `add_root()` appele
  hors de tout job. Elles servent au serveur MCP stdio (un seul utilisateur)
  et a la CLI ; elles ne s'appliquent PAS a l'interieur d'un job.

Hors job, si aucune racine statique n'est configuree, la politique est
permissive (retro-compatible : CLI ad hoc, tests), sauf en mode strict
(`set_strict(True)`, active par le serveur MCP et `phoenix web`) : tout acces
est alors refuse tant qu'aucune racine n'est declaree (PHOENIX_TOOL_ROOTS).

Les comparaisons de chemins passent par `within()` : chemins resolus
(realpath), casse normalisee (normcase, Windows) et `commonpath`, ce qui gere
les lettres de lecteur et les chemins UNC.
"""

import contextlib
import contextvars
import os
import threading

_lock = threading.Lock()
_roots = set()
_strict = False


class JobScope:
    """Perimetre d'un job d'investigation : dossier du cas + racines propres."""

    __slots__ = ('case_dir', 'roots', '_lock')

    def __init__(self, case_dir, roots):
        self.case_dir = case_dir
        self.roots = set(roots)
        self._lock = threading.Lock()

    def add(self, path):
        with self._lock:
            self.roots.add(_normalize(path))

    def snapshot(self):
        with self._lock:
            return set(self.roots)


_job = contextvars.ContextVar('phoenix_dfir_job', default=None)


def _normalize(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(os.path.expanduser(os.fspath(path)))))


def _contains(target, root, pathmod=os.path, strict=False):
    """Is `target` inside `root`? Both are absolute; compared case-insensitively
    where the platform is (pathmod.normcase). Different drives never match."""
    target, root = pathmod.normcase(target), pathmod.normcase(root)
    if target == root:
        return not strict
    try:
        return pathmod.commonpath([target, root]) == root
    except ValueError:  # different drives, or mixing absolute and relative paths
        return False


def within(path, root, strict=False):
    """Is `path` inside `root` once both are resolved? strict=True excludes root itself."""
    try:
        return _contains(_normalize(path), _normalize(root), strict=strict)
    except (OSError, TypeError, ValueError):
        return False


def set_strict(enabled=True):
    """Strict mode: outside a job, deny everything until a root is declared."""
    global _strict
    _strict = bool(enabled)


def is_strict():
    return _strict


def _env_roots():
    raw = os.environ.get('PHOENIX_TOOL_ROOTS', '')
    return {_normalize(p) for p in raw.split(os.pathsep) if p.strip()}


# ----------------------------------------------------------------------------
# Perimetre de job (par contexte d'execution)
# ----------------------------------------------------------------------------

def current_job():
    """Perimetre du job actif dans ce contexte, ou None."""
    return _job.get()


def current_case():
    """Dossier du cas du job actif (chemin absolu), ou None hors job."""
    job = _job.get()
    return job.case_dir if job else None


def begin_job(case_dir, extra_roots=()):
    """Ouvrir le perimetre d'un job. Retourne un jeton pour `end_job`.

    Un job imbrique sur le MEME dossier de cas herite des racines du job
    parent (ex. evidences du coffre ajoutees par le backend avant de lancer
    l'enqueteur) ; un job sur un autre cas repart de zero.
    """
    case_abs = os.path.abspath(case_dir)
    roots = {_normalize(case_dir)}
    roots.update(_normalize(p) for p in extra_roots if p)
    parent = _job.get()
    if parent is not None and parent.case_dir == case_abs:
        roots.update(parent.snapshot())
    return _job.set(JobScope(case_abs, roots))


def end_job(token):
    _job.reset(token)


@contextlib.contextmanager
def job_scope(case_dir, extra_roots=()):
    """Contexte d'un job : `with job_scope(case): ...` (reinitialise en sortie)."""
    token = begin_job(case_dir, extra_roots)
    try:
        yield _job.get()
    finally:
        end_job(token)


# ----------------------------------------------------------------------------
# Racines
# ----------------------------------------------------------------------------

def add_root(path):
    """Autoriser une racine (et son arborescence).

    Dans un job : la racine n'est ajoutee qu'a CE job. Hors job : racine
    statique (serveur MCP stdio, CLI)."""
    if not path:
        return
    job = _job.get()
    if job is not None:
        job.add(path)
        return
    with _lock:
        _roots.add(_normalize(path))


def reset():
    """Vider les racines statiques enregistrees et quitter le mode strict (tests)."""
    global _strict
    with _lock:
        _roots.clear()
    _strict = False


def active_roots():
    job = _job.get()
    if job is not None:
        return job.snapshot()
    with _lock:
        static = set(_roots)
    return static | _env_roots()


def is_allowed(path):
    """Le chemin est-il autorise par la politique courante ?"""
    job = _job.get()
    roots = active_roots()
    if not roots and job is None:
        # permissif tant qu'aucune racine n'est configuree (hors job), sauf en mode strict
        return not _strict
    try:
        target = _normalize(path)
    except (OSError, TypeError, ValueError):
        return False
    return any(_contains(target, root) for root in roots)


def check(path):
    """Retourner None si autorise, sinon un dict d'erreur pret a renvoyer."""
    if is_allowed(path):
        return None
    if _strict and not active_roots() and _job.get() is None:
        return {'error': (f"Access denied: no allowed folder is configured for '{path}'. "
                          "Set PHOENIX_TOOL_ROOTS to the case folders (separated by os.pathsep).")}
    return {'error': (f"Acces refuse par la politique de securite : '{path}' est hors des "
                      f"dossiers autorises. Restez dans l'arborescence du cas.")}
