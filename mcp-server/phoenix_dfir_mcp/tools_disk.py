"""Disk image tools (The Sleuth Kit).

Registered in the single tool registry of ``toolkit``, which re-exports every
name: callers keep using ``toolkit.<name>``.
"""

from . import disk  # noqa: E402
from .toolkit import _schema, tool  # noqa: E402

# ============================================================================
# Images disque (The Sleuth Kit)
# ============================================================================

@tool(
    'disk_status',
    "Verifier la disponibilite de The Sleuth Kit (analyse d'images disque E01/raw/dd/VMDK/VHD) et "
    "les formats d'image supportes.",
    _schema({}),
)
def disk_status():
    return disk.status()


@tool(
    'disk_image_info',
    "Inspecter une image disque SANS la monter : table de partitions (offsets) et systeme de "
    "fichiers de chaque partition (NTFS, FAT, ext4...). Premiere etape sur toute image disque.",
    _schema({'file_path': {'type': 'string', 'description': "Chemin de l'image (.E01, .dd, .raw, .img...)"}},
            ['file_path']),
)
def disk_image_info(file_path):
    return disk.image_info(file_path)


@tool(
    'disk_list_files',
    "Lister l'arborescence d'une image disque (lecture seule), fichiers SUPPRIMES inclus "
    "(deleted=true), avec inode citable. Filtrer par chemin partiel ou deleted_only.",
    _schema({
        'file_path': {'type': 'string', 'description': "Chemin de l'image"},
        'offset': {'type': 'integer', 'description': 'Offset de partition en secteurs (defaut : toutes)'},
        'path_filter': {'type': 'string', 'description': "Filtre sur le chemin (ex: 'Users/jdoe')"},
        'deleted_only': {'type': 'boolean', 'description': 'Seulement les fichiers supprimes'},
        'max_entries': {'type': 'integer', 'description': "Nombre max d'entrees (defaut 500)"},
    }, ['file_path']),
)
def disk_list_files(file_path, offset=None, path_filter=None, deleted_only=False, max_entries=500):
    return disk.list_files(file_path, offset=offset, path_filter=path_filter,
                           deleted_only=deleted_only, max_entries=max_entries)


@tool(
    'disk_timeline',
    "Timeline MACB du systeme de fichiers d'une image disque (modification, acces, changement, "
    "creation de chaque fichier, supprimes inclus). Les evenements sont indexes dans la "
    "super-timeline du cas pour etre correles avec les journaux (get_timeline).",
    _schema({
        'file_path': {'type': 'string', 'description': "Chemin de l'image"},
        'offset': {'type': 'integer', 'description': 'Offset de partition (defaut : toutes)'},
        'path_filter': {'type': 'string', 'description': 'Filtre sur le chemin'},
    }, ['file_path']),
)
def disk_timeline(file_path, offset=None, path_filter=None):
    result = disk.timeline(file_path, offset=offset, path_filter=path_filter)
    if isinstance(result, dict) and isinstance(result.get('events'), list):
        # Tout est indexe ; seul un apercu est renvoye au LLM
        result['preview'] = result['events'][:100]
    return result


@tool(
    'disk_extract_artifacts',
    "Extraire d'une image disque les artefacts forensiques connus (journaux EVTX, ruches de "
    "registre SYSTEM/SOFTWARE/SAM/NTUSER, Amcache, Prefetch, LNK, historiques navigateurs et "
    "PowerShell, taches planifiees, $MFT, logs et crontabs Linux, cles SSH...) vers le dossier du "
    "cas, avec manifeste de provenance (inode, SHA-256). Les fichiers extraits deviennent des "
    "artefacts a analyser avec les parsers. Profils : windows, linux, auto ; ou patterns "
    "personnalises ('Users/*/Documents/**').",
    _schema({
        'file_path': {'type': 'string', 'description': "Chemin de l'image"},
        'case_dir': {'type': 'string', 'description': 'Dossier du cas (destination)'},
        'offset': {'type': 'integer', 'description': 'Offset de partition (defaut : toutes)'},
        'profile': {'type': 'string', 'enum': sorted(disk.PROFILES), 'description': 'Profil (defaut auto)'},
        'patterns': {'type': 'array', 'items': {'type': 'string'},
                     'description': "Motifs de chemins supplementaires ('*' un niveau, '**' recursif)"},
        'include_deleted': {'type': 'boolean', 'description': 'Inclure les fichiers supprimes (defaut oui)'},
    }, ['file_path', 'case_dir']),
)
def disk_extract_artifacts(file_path, case_dir, offset=None, profile='auto', patterns=None,
                           include_deleted=True):
    return disk.extract_artifacts(file_path, case_dir, offset=offset, profile=profile,
                                  patterns=patterns, include_deleted=include_deleted)
