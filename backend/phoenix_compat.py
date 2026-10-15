#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phoenix DFIR - Import optionnel du CLI legacy (legacy/phoenix.py).

Le CLI historique fournit l'analyse assistee par IA et l'enrichissement
VirusTotal. L'IA repose exclusivement sur GitHub Copilot (API GitHub
Models, jeton GITHUB_TOKEN ou PHOENIX_GITHUB_TOKEN avec scope models:read).
Ses dependances (requirements-optional.txt) ne sont pas toujours
installees : la plateforme bascule alors en mode standalone avec ses
parsers natifs.
"""

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'legacy'))

try:
    from phoenix import (  # noqa: F401
        query_local, query_remote, enrichir_ioc_vt,
        analyse_fichier, extraire_et_sauvegarder_conclusions,
        generer_resume_executif_ia, creer_contenu_rapport,
        sauvegarder_session, charger_session
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
