"""Fichiers produits par les extensions de raisonnement dans le dossier du cas.

Le graphe (entity_graph.json) et les regles de detection (detections/
phoenix_detection_*) ne sont pas des preuves : ils sont declares internes pour
ne jamais apparaitre comme artefacts a analyser (inventaire, audits de
couverture, portes qualite).
"""

from .. import toolkit

_NAMES = set()
_PREFIXES = set()


def register(names=(), prefixes=()):
    _NAMES.update(names)
    _PREFIXES.update(prefixes)
    current = toolkit.is_internal_file
    if getattr(current, '_phoenix_reasoning', False):
        return

    def is_internal_file(fname, _base=current):
        return (_base(fname) or fname in _NAMES
                or any(fname.startswith(p) for p in _PREFIXES))

    is_internal_file._phoenix_reasoning = True
    toolkit.is_internal_file = is_internal_file
