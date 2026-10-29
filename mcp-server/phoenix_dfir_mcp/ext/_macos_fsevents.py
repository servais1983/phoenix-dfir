"""FSEvents (.fseventsd) : parser borne des pages DLS.

Un fichier de /.fseventsd (nom = identifiant hexadecimal du dernier
evenement) est compresse en gzip (un ou plusieurs membres) ; le flux
decompresse est une suite de pages :

    en-tete de page (12 octets)
        0   4  signature '1SLD' (v1), '2SLD' (v2) ou '3SLD' (v3)
        4   4  inconnu
        8   4  taille de la page en octets, en-tete compris (uint32 LE)
    enregistrements, jusqu'a la fin de la page
        chemin    UTF-8 termine par NUL (relatif a la racine du volume)
        8 octets  identifiant d'evenement (uint64 LE)
        4 octets  drapeaux (uint32 LE)
        8 octets  identifiant de noeud / inode (v2 et v3)
        4 octets  inconnu (v3 uniquement)

Les enregistrements ne portent PAS d'horodatage : seul l'ordre des
identifiants d'evenement et la date du fichier situent l'activite. Le
parser est borne (taille decompressee, nombre d'enregistrements) et
s'arrete proprement sur une page tronquee ou une signature inattendue.
"""

import gzip
import os
import struct
import zlib

MAX_DECOMPRESSED = 64 << 20
MAX_RECORDS = 200000
_HEADER = 12
_TAIL = {b'1SLD': ('<QI', 12, 1), b'2SLD': ('<QIQ', 20, 2), b'3SLD': ('<QIQI', 24, 3)}

FLAGS = (
    (0x00000001, 'IsDirectory'),
    (0x00000002, 'Mount'),
    (0x00000004, 'Unmount'),
    (0x00000020, 'EndOfTransaction'),
    (0x00000800, 'LastHardLinkRemoved'),
    (0x00001000, 'IsHardLink'),
    (0x00004000, 'IsSymbolicLink'),
    (0x00008000, 'IsFile'),
    (0x00010000, 'PermissionChanged'),
    (0x00020000, 'ExtendedAttrModified'),
    (0x00040000, 'ExtendedAttrRemoved'),
    (0x00100000, 'DocumentRevisioning'),
    (0x00400000, 'ItemCloned'),
    (0x01000000, 'Created'),
    (0x02000000, 'Removed'),
    (0x04000000, 'InodeMetaModified'),
    (0x08000000, 'Renamed'),
    (0x10000000, 'Modified'),
    (0x20000000, 'Exchange'),
    (0x40000000, 'FinderInfoModified'),
    (0x80000000, 'FolderCreated'),
)
FLAG = {name: bit for bit, name in FLAGS}


def decode_flags(value):
    return [name for bit, name in FLAGS if value & bit]


def _read(path, limit):
    """Flux decompresse borne ; un membre gzip tronque conserve ce qui a ete lu."""
    with open(path, 'rb') as f:
        magic = f.read(2)
    opener = gzip.open if magic == b'\x1f\x8b' else open
    notes, chunks, total = [], [], 0
    try:
        with opener(path, 'rb') as f:
            while total <= limit:
                chunk = f.read(min(1 << 20, limit + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
    except (OSError, EOFError, zlib.error) as exc:
        notes.append(f'flux gzip tronque ou corrompu ({type(exc).__name__}) : lecture partielle')
    data = b''.join(chunks)
    return data[:limit], len(data) > limit, notes


def parse(path, max_records=MAX_RECORDS, max_bytes=MAX_DECOMPRESSED):
    """Enregistrements FSEvents normalises (ref 'row' = rang dans le fichier, a partir de 1)."""
    data, truncated, notes = _read(path, max_bytes)
    events, versions, pages = [], set(), 0
    off = 0
    stop = False
    while off + _HEADER <= len(data) and not stop:
        magic = data[off:off + 4]
        if magic not in _TAIL:
            notes.append(f'signature inattendue a l\'offset {off} : analyse arretee')
            break
        page_len = struct.unpack_from('<I', data, off + 8)[0]
        end = off + page_len
        if page_len <= _HEADER or end > len(data):
            notes.append(f'page tronquee a l\'offset {off} (taille annoncee {page_len})')
            end = len(data)
        fmt, size, version = _TAIL[magic]
        versions.add(version)
        pages += 1
        pos = off + _HEADER
        while pos < end:
            nul = data.find(b'\x00', pos, end)
            if nul < 0 or nul + 1 + size > end:
                break
            path_text = data[pos:nul].decode('utf-8', errors='replace')
            fields = struct.unpack_from(fmt, data, nul + 1)
            pos = nul + 1 + size
            if len(events) >= max_records:
                truncated = stop = True
                break
            row = len(events) + 1
            flags = fields[1]
            names = decode_flags(flags)
            ev = {
                'row': row, '_ref': ('row', row),
                'source': 'macos_fsevents',
                'path': '/' + path_text.lstrip('/') if path_text else '/',
                'fsevent_id': fields[0],
                'flags': f'0x{flags:08x}',
                'flag_names': ','.join(names),
                'version': version,
                'page': pages,
            }
            if version >= 2:
                ev['inode'] = fields[2]
            ev['event'] = f"[{ev['flag_names']}] {ev['path']}"
            ev['_flags'] = flags
            events.append(ev)
        off = end if end > off else len(data)
    if not pages:
        notes.append('aucune page FSEvents valide')
    stats = {'pages': pages, 'versions': sorted(versions), 'truncated': truncated, 'notes': notes,
             'decompressed_bytes': len(data)}
    try:
        stats['file_mtime'] = os.path.getmtime(path)
    except OSError:
        pass
    return events, stats


def has(ev, *names):
    return any(ev['_flags'] & FLAG[n] for n in names)
