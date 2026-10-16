"""Fichiers produits par les extensions de raisonnement dans le dossier du cas.

Le graphe (entity_graph.json) et les regles de detection (detections/
phoenix_detection_*) ne sont pas des preuves : ils sont declares internes pour
ne jamais apparaitre comme artefacts a analyser (inventaire, audits de
couverture, portes qualite).
"""

from .. import toolkit


def register(names=(), prefixes=()):
    """Declarer des fichiers internes (voir toolkit.is_internal_file)."""
    toolkit.EXT_INTERNAL_FILES.update(names)
    toolkit.EXT_INTERNAL_PREFIXES.update(prefixes)
