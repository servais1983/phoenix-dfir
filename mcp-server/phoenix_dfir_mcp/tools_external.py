"""External tool adapters as tools: EZ Tools, Volatility 3 and Hayabusa.

Registered in the single tool registry of ``toolkit``, which re-exports every
name: callers keep using ``toolkit.<name>``.
"""

from . import hayabusa, volatility, zimmermann  # noqa: E402
from .toolkit import _schema, tool  # noqa: E402

# ============================================================================
# Outils Eric Zimmermann
# ============================================================================

@tool(
    'zimmermann_status',
    "Verifier la disponibilite des outils forensiques Eric Zimmermann (EvtxECmd, PECmd, LECmd, "
    "MFTECmd, AmcacheParser, AppCompatCacheParser, SBECmd, JLECmd, RECmd, SrumECmd...) : "
    "runtime dotnet, chemin d'installation (EZ_TOOLS_PATH) et outils trouves.",
    _schema({}),
)
def zimmermann_status():
    return zimmermann.status()


@tool(
    'run_zimmermann',
    "Executer un outil Eric Zimmermann sur un artefact (sortie CSV parsee) : EvtxECmd (EVTX), "
    "PECmd (Prefetch), LECmd (LNK), JLECmd (JumpLists), MFTECmd ($MFT/$J), AmcacheParser (Amcache.hve), "
    "AppCompatCacheParser (SYSTEM hive/Shimcache), SBECmd (ShellBags), RECmd (registre), "
    "SrumECmd (SRUM), SQLECmd (SQLite). Utiliser zimmermann_status d'abord ; en cas "
    "d'indisponibilite, se rabattre sur les parsers natifs (parse_evtx, parse_prefetch, parse_lnk...).",
    _schema({
        'tool': {'type': 'string', 'enum': sorted(zimmermann.EZ_TOOLS),
                 'description': "Nom de l'outil Zimmermann"},
        'file_path': {'type': 'string', 'description': "Artefact a traiter (fichier, ou dossier pour SBECmd/SQLECmd)"},
        'max_rows': {'type': 'integer', 'description': 'Nombre max de lignes CSV retournees (defaut 200)'},
    }, ['tool', 'file_path']),
)
def run_zimmermann(tool, file_path, max_rows=200):
    return zimmermann.run(tool, file_path, max_rows=max_rows)


# ============================================================================
# Memoire vive (Volatility 3) et timeline EVTX (Hayabusa)
# ============================================================================

@tool(
    'volatility_status',
    "Verifier la disponibilite de Volatility 3 (analyse de dumps memoire) et lister les plugins "
    "autorises.",
    _schema({}),
)
def volatility_status():
    return volatility.status()


@tool(
    'run_volatility',
    "Executer un plugin Volatility 3 sur un dump memoire (.raw/.mem/.vmem/.dmp/.lime) : processus "
    "(windows.pslist/pstree/psscan), lignes de commande (windows.cmdline), injection de code / "
    "process hollowing (windows.malfind), connexions reseau / beacons C2 (windows.netscan), "
    "services (windows.svcscan), DLL, handles, privileges... Filtre --pid optionnel. "
    "Appeler volatility_status d'abord.",
    _schema({
        'file_path': {'type': 'string', 'description': 'Chemin du dump memoire'},
        'plugin': {'type': 'string', 'enum': sorted(volatility.PLUGINS),
                   'description': 'Plugin Volatility 3 (liste blanche, lecture seule)'},
        'pid': {'type': 'integer', 'description': 'Filtrer sur un PID (plugins compatibles)'},
        'max_rows': {'type': 'integer', 'description': 'Nombre max de lignes retournees (defaut 300)'},
    }, ['file_path', 'plugin']),
)
def run_volatility(file_path, plugin, pid=None, max_rows=300):
    return volatility.run(file_path, plugin, pid=pid, max_rows=max_rows)


@tool(
    'hayabusa_status',
    "Verifier la disponibilite de Hayabusa (timeline de detection EVTX, milliers de regles "
    "Sigma/Hayabusa).",
    _schema({}),
)
def hayabusa_status():
    return hayabusa.status()


@tool(
    'run_hayabusa',
    "Executer Hayabusa json-timeline sur un fichier EVTX ou un dossier d'EVTX : alertes Sigma/"
    "Hayabusa triees par severite (regle, Event ID, RecordID, tactiques MITRE, details). Complete "
    "sigma_scan avec une couverture de regles bien plus large. Appeler hayabusa_status d'abord.",
    _schema({
        'file_path': {'type': 'string', 'description': "Fichier .evtx ou dossier d'EVTX"},
        'min_level': {'type': 'string', 'enum': list(hayabusa.MIN_LEVELS),
                      'description': 'Niveau minimal des alertes (defaut medium)'},
        'max_alerts': {'type': 'integer', 'description': "Nombre max d'alertes retournees (defaut 300)"},
    }, ['file_path']),
)
def run_hayabusa(file_path, min_level='medium', max_alerts=300):
    return hayabusa.run(file_path, min_level=min_level, max_alerts=max_alerts)
