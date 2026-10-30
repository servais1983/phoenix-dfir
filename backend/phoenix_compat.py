#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR - Import optionnel du CLI legacy (legacy/phoenix.py).

The legacy CLI provides LLM-assisted file analysis and VirusTotal
enrichment. Its LLM calls go through phoenix_dfir_mcp.copilot: local LLM by
default, cloud only with PHOENIX_ALLOW_CLOUD_LLM=1. Its dependencies
(requirements-optional.txt) are not always installed, and the LLM may be
unreachable: the platform then falls back to its deterministic native
parsers.
"""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'legacy'))

try:
    from phoenix import (  # noqa: F401
        query_local, query_remote, enrichir_ioc_vt,
        analyse_fichier, extraire_et_sauvegarder_conclusions,
        generer_resume_executif_ia, creer_contenu_rapport,
        sauvegarder_session, charger_session, LLM_ERROR_PREFIX
    )
    PHOENIX_AVAILABLE = True
except KeyboardInterrupt:
    raise
except BaseException as e:  # noqa: B036 - certains providers levent des PanicException pyo3 a l'import
    print(f"Attention: Impossible d'importer les modules Phoenix: {e}")
    PHOENIX_AVAILABLE = False
    query_local = query_remote = enrichir_ioc_vt = None
    analyse_fichier = extraire_et_sauvegarder_conclusions = None
    generer_resume_executif_ia = creer_contenu_rapport = None
    sauvegarder_session = charger_session = None
    LLM_ERROR_PREFIX = 'Erreur: LLM indisponible'


def llm_failed(result):
    """Did the legacy analysis fail because no LLM answered?"""
    return str(result).startswith(LLM_ERROR_PREFIX)
