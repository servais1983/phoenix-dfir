"""Analyse forensique d'images disque (The Sleuth Kit).

Formats : E01 / EWF (segments .E02... detectes automatiquement), raw / dd /
.img / .001, VMDK, VHD, AFF — selon le support compile dans TSK
(`img_stat -i list`). Systemes de fichiers : NTFS, FAT/exFAT, ext2/3/4,
HFS+, ISO9660...

L'image n'est JAMAIS montee ni modifiee : TSK lit les structures du systeme
de fichiers directement (lecture seule), y compris les fichiers supprimes
encore references. Quatre operations :

- image_info        : table de partitions (mmls) et systeme de fichiers (fsstat) ;
- list_files        : arborescence recursive (fls), fichiers supprimes inclus ;
- timeline          : horodatages MACB de tous les fichiers (fls -m, bodyfile) ;
- extract_artifacts : extraction ciblee (icat) des artefacts forensiques connus
                      (journaux EVTX, ruches de registre, Prefetch, historiques
                      navigateurs et PowerShell, logs Linux...) dans le dossier
                      du cas, avec un manifeste de provenance (image, partition,
                      inode, chemin, SHA-256) — chaque fichier extrait devient un
                      artefact analysable par les parsers.
"""

import datetime
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess  # nosec B404 - binaires TSK, arguments en liste, pas de shell
import threading

from . import sandbox, workspace

DISK_EXTENSIONS = ('.e01', '.ex01', '.dd', '.img', '.001', '.vmdk', '.vhd', '.vhdx', '.aff')
AMBIGUOUS_EXTENSIONS = ('.raw', '.bin')  # disque OU memoire : decide sur le contenu
EXTRACT_DIR = 'extracted'
MANIFEST = 'extraction_manifest.json'

_TIMEOUT = 1800
_MAX_EXTRACT_BYTES = 2 * 1024 ** 3  # 2 Go par fichier extrait
_MAX_LIST = 200000

# Artefacts extraits par profil : motifs de chemins (insensibles a la casse,
# relatifs a la racine du systeme de fichiers, '*' = un niveau, '**' = recursif)
PROFILES = {
    'windows': [
        'Windows/System32/winevt/Logs/*.evtx',
        'Windows/System32/config/SYSTEM', 'Windows/System32/config/SOFTWARE',
        'Windows/System32/config/SAM', 'Windows/System32/config/SECURITY',
        'Windows/AppCompat/Programs/Amcache.hve',
        'Windows/Prefetch/*.pf',
        'Windows/System32/Tasks/**',
        'Windows/System32/sru/SRUDB.dat',
        'Users/*/NTUSER.DAT', 'Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat',
        'Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk',
        'Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt',
        'Users/*/AppData/Local/Google/Chrome/User Data/*/History',
        'Users/*/AppData/Local/Microsoft/Edge/User Data/*/History',
        'Users/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/places.sqlite',
        '$MFT',
    ],
    'linux': [
        'var/log/auth.log*', 'var/log/secure*', 'var/log/syslog*', 'var/log/messages*',
        'var/log/audit/audit.log*', 'var/log/apache2/*.log', 'var/log/nginx/*.log',
        'etc/passwd', 'etc/group', 'etc/crontab', 'etc/cron.d/*', 'var/spool/cron/crontabs/*',
        'root/.bash_history', 'home/*/.bash_history', 'root/.ssh/authorized_keys',
        'home/*/.ssh/authorized_keys', 'etc/systemd/system/*.service',
    ],
}
PROFILES['auto'] = PROFILES['windows'] + PROFILES['linux']

_FLS_LINE = re.compile(r'^(?P<type>\S+)\s+(?P<deleted>\*\s+)?(?P<inode>[\d-]+)(?:\(realloc\))?:\t(?P<path>.*)$')


# ----------------------------------------------------------------------------
# Detection et disponibilite
# ----------------------------------------------------------------------------

def tsk_available():
    return all(shutil.which(b) for b in ('mmls', 'fsstat', 'fls', 'icat'))


def status():
    formats = []
    if shutil.which('img_stat'):
        try:
            out = sandbox.run(['img_stat', '-i', 'list'], timeout=30)
            formats = re.findall(r'^\s+(\w+)\s+\(', (out.stdout or '') + (out.stderr or ''), re.M)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            pass
    return {
        'available': tsk_available(),
        'image_formats': formats,
        'profiles': {k: len(v) for k, v in PROFILES.items()},
        'sandbox': sandbox.status(),
        'help': ("Installer The Sleuth Kit (paquet 'sleuthkit' : mmls, fsstat, fls, icat). "
                 "Le support E01 necessite TSK compile avec libewf ('img_stat -i list')."),
    }


def looks_like_disk(path):
    """Image disque ? Extension dediee, ou signature MBR / GPT / secteur
    d'amorce de systeme de fichiers pour les extensions ambigues (.raw)."""
    ext = os.path.splitext(path)[1].lower()
    if ext in DISK_EXTENSIONS:
        return True
    if ext not in AMBIGUOUS_EXTENSIONS or not os.path.isfile(path):
        return False
    try:
        with open(path, 'rb') as f:
            head = f.read(4096)
    except OSError:
        return False
    if len(head) >= 1024 and head[512:520] == b'EFI PART':
        return True
    if len(head) >= 512 and head[510:512] == b'\x55\xaa':
        # MBR ou secteur d'amorce NTFS / FAT
        return True
    if len(head) >= 1082 and head[1080:1082] == b'\x53\xef':  # superbloc ext2/3/4
        return True
    return False


def _run(args, timeout=_TIMEOUT, binary=False):
    # Le dernier argument des commandes TSK est toujours l'image (preuve en lecture seule)
    return sandbox.run(args, evidence=[args[-1]], timeout=timeout, text=not binary)


def _check(file_path):
    if not os.path.isfile(file_path):
        return {'error': f'Image introuvable : {file_path}'}
    if not tsk_available():
        return {'error': "The Sleuth Kit indisponible (mmls/fsstat/fls/icat).", 'help': status()['help']}
    return sandbox.check()


# ----------------------------------------------------------------------------
# Partitions et systemes de fichiers
# ----------------------------------------------------------------------------

def partitions(file_path):
    """Partitions (offset en secteurs) ; une image sans table de partitions
    est traitee comme un systeme de fichiers unique a l'offset 0."""
    proc = _run(['mmls', file_path], timeout=120)
    parts = []
    for line in (proc.stdout or '').splitlines():
        m = re.match(r'^\s*\d+:\s+(\d+:\d+|Meta|-+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.*)$', line)
        if m and ':' in m.group(1):
            parts.append({'slot': m.group(1), 'offset': int(m.group(2)),
                          'length_sectors': int(m.group(4)), 'description': m.group(5).strip()})
    if not parts:
        parts = [{'slot': 'image', 'offset': 0, 'length_sectors': None,
                  'description': 'Systeme de fichiers sans table de partitions'}]
    return parts


def fs_info(file_path, offset):
    proc = _run(['fsstat', '-o', str(offset), file_path], timeout=120)
    if proc.returncode != 0:
        return None
    info = {}
    for line in (proc.stdout or '').splitlines():
        for key, label in (('fs_type', 'File System Type:'), ('volume_name', 'Volume Name:'),
                           ('volume_id', 'Volume Serial Number:'), ('volume_id', 'Volume ID:'),
                           ('os', 'OEM Name:'), ('last_mount', 'Last Mounted at:'),
                           ('last_written', 'Last Written at:')):
            if line.startswith(label) and key not in info:
                info[key] = line.split(':', 1)[1].strip()
    return info


def image_info(file_path):
    err = _check(file_path)
    if err:
        return err
    parts = partitions(file_path)
    filesystems = []
    for p in parts:
        fs = fs_info(file_path, p['offset'])
        if fs:
            filesystems.append(dict(p, **fs))
    return {
        'image': file_path,
        'size_bytes': os.path.getsize(file_path),
        'partitions': parts,
        'filesystems': filesystems,
        'hint': ("Utiliser l'offset d'un systeme de fichiers pour list_files / timeline / "
                 "extract_artifacts." if filesystems else
                 "Aucun systeme de fichiers reconnu (image chiffree, corrompue ou format non supporte)."),
    }


def _default_offsets(file_path):
    return [p['offset'] for p in partitions(file_path) if fs_info(file_path, p['offset'])]


# ----------------------------------------------------------------------------
# Fichiers
# ----------------------------------------------------------------------------

def _fls(file_path, offset):
    proc = _run(['fls', '-r', '-p', '-o', str(offset), file_path])
    entries = []
    for line in (proc.stdout or '').splitlines():
        m = _FLS_LINE.match(line)
        if not m:
            continue
        entries.append({
            'path': m.group('path'),
            'inode': m.group('inode'),
            'type': m.group('type'),
            'deleted': bool(m.group('deleted')),
        })
        if len(entries) >= _MAX_LIST:
            break
    return entries, proc


def list_files(file_path, offset=None, path_filter=None, deleted_only=False, max_entries=500):
    err = _check(file_path)
    if err:
        return err
    offsets = [offset] if offset is not None else _default_offsets(file_path)
    if not offsets:
        return {'error': 'Aucun systeme de fichiers exploitable dans cette image.'}
    rows, total, deleted = [], 0, 0
    pattern = (path_filter or '').lower()
    for off in offsets:
        entries, proc = _fls(file_path, off)
        if proc.returncode != 0 and not entries:
            continue
        for e in entries:
            if deleted_only and not e['deleted']:
                continue
            if pattern and pattern not in e['path'].lower():
                continue
            total += 1
            deleted += e['deleted']
            if len(rows) < max_entries:
                rows.append(dict(e, offset=off))
    return {'image': file_path, 'total': total, 'deleted': deleted, 'returned': len(rows),
            'truncated': total > len(rows), 'entries': rows}


def _parse_bodyfile(text, offset):
    """Bodyfile TSK -> un evenement par horodatage MACB."""
    events = []
    for line in text.splitlines():
        parts = line.split('|')
        if len(parts) < 11:
            continue
        name, inode, mode, size = parts[1], parts[2], parts[3], parts[6]
        deleted = '(deleted' in name
        for label, raw in (('m', parts[8]), ('a', parts[7]), ('c', parts[9]), ('b', parts[10])):
            try:
                epoch = int(raw)
            except ValueError:
                continue
            if epoch <= 0:
                continue
            ts = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
            events.append({
                'timestamp': ts.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'macb': label,
                'path': name,
                'inode': inode,
                'mode': mode,
                'size': size,
                'deleted': deleted,
                'offset': offset,
            })
    return events


def timeline(file_path, offset=None, path_filter=None, max_events=200000):
    """Horodatages MACB (m=modification, a=acces, c=changement MFT/inode,
    b=creation) de tous les fichiers ; les evenements sont indexes dans la
    super-timeline du cas pour etre correles avec les journaux."""
    err = _check(file_path)
    if err:
        return err
    offsets = [offset] if offset is not None else _default_offsets(file_path)
    events = []
    for off in offsets:
        proc = _run(['fls', '-r', '-m', '/', '-o', str(off), file_path])
        events.extend(_parse_bodyfile(proc.stdout or '', off))
    if path_filter:
        events = [e for e in events if path_filter.lower() in e['path'].lower()]
    events.sort(key=lambda e: e['timestamp'])
    total = len(events)
    events = events[:max_events]
    return {'image': file_path, 'total_events': total, 'returned': len(events),
            'truncated': total > len(events), 'events': events,
            'note': "Evenements indexes dans la super-timeline : utiliser get_timeline / search_evidence."}


# ----------------------------------------------------------------------------
# Extraction
# ----------------------------------------------------------------------------

def _match(path, pattern):
    """Correspondance insensible a la casse ; '*' ne traverse pas '/', '**' oui."""
    regex = ''
    i = 0
    while i < len(pattern):
        if pattern.startswith('**', i):
            regex += '.*'
            i += 2
        elif pattern[i] == '*':
            regex += '[^/]*'
            i += 1
        else:
            regex += re.escape(pattern[i]) if pattern[i] not in '?' else '[^/]'
            i += 1
    return re.fullmatch(regex, path, re.IGNORECASE) is not None


def _safe_target(base, image_tag, off, rel_path):
    """Chemin de sortie confine au dossier d'extraction (aucune traversee)."""
    clean = [p for p in rel_path.replace('\\', '/').split('/') if p not in ('', '.', '..')]
    target = os.path.realpath(os.path.join(base, image_tag, f'p{off}', *clean))
    root = os.path.realpath(base)
    if not target.startswith(root + os.sep):
        return None
    return target


_CHUNK = 1 << 20


def _icat_to_file(image, off, inode, target, max_bytes=None, timeout=_TIMEOUT):
    """Extraire un inode via icat en STREAMING vers `target` (jamais tout en
    memoire), avec plafond de taille : au-dela, l'extraction est interrompue et
    le fichier partiel supprime. Retourne (statut, taille, sha256)."""
    limit = _MAX_EXTRACT_BYTES if max_bytes is None else max_bytes
    digest = hashlib.sha256()
    size = 0
    status = 'ok'
    proc = sandbox.popen(['icat', '-o', str(off), image, str(inode)], evidence=[image],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    watchdog = threading.Timer(timeout, proc.kill)  # icat bloque : on l'abat
    watchdog.daemon = True
    watchdog.start()
    try:
        with open(target, 'wb') as out:
            while True:
                chunk = proc.stdout.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    status = f'taille > {limit} octets (extraction interrompue)'
                    break
                digest.update(chunk)
                out.write(chunk)
    except OSError as exc:
        status = f'ecriture impossible : {exc}'
    finally:
        watchdog.cancel()
        if status != 'ok':
            proc.kill()
        proc.stdout.close()
        try:
            returncode = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            returncode = proc.wait()
            status = 'icat : delai depasse'
    if status == 'ok' and returncode != 0 and size == 0:
        status = 'icat en echec'
    if status != 'ok':
        try:
            os.remove(target)
        except OSError:
            pass
        return status, size, None
    return status, size, digest.hexdigest()


def extract_artifacts(file_path, case_dir, offset=None, profile='auto', patterns=None,
                      include_deleted=True, max_files=2000):
    """Extraire les artefacts forensiques de l'image vers <case>/extracted/."""
    err = _check(file_path)
    if err:
        return err
    if not os.path.isdir(case_dir):
        return {'error': f'Dossier du cas introuvable : {case_dir}'}
    globs = list(patterns or []) or PROFILES.get(profile)
    if not globs:
        return {'error': f'Profil inconnu : {profile}. Profils : {sorted(PROFILES)}'}
    offsets = [offset] if offset is not None else _default_offsets(file_path)
    if not offsets:
        return {'error': 'Aucun systeme de fichiers exploitable dans cette image.'}

    base = os.path.join(workspace.derived_root(case_dir), EXTRACT_DIR)
    image_tag = re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(file_path))
    extracted, skipped = [], []
    for off in offsets:
        entries, _proc = _fls(file_path, off)
        for e in entries:
            if len(extracted) >= max_files:
                break
            if not e['type'].startswith('r/') or (e['deleted'] and not include_deleted):
                continue
            if not any(_match(e['path'], g) for g in globs):
                continue
            target = _safe_target(base, image_tag, off, e['path'])
            if not target:
                skipped.append({'path': e['path'], 'reason': 'chemin refuse'})
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            status, size, digest = _icat_to_file(file_path, off, e['inode'], target)
            if status != 'ok':
                skipped.append({'path': e['path'], 'reason': status})
                continue
            extracted.append({
                'source_path': e['path'],
                'inode': e['inode'],
                'offset': off,
                'deleted': e['deleted'],
                'extracted_to': workspace.rel(target, case_dir),
                'size': size,
                'sha256': digest,
            })
    manifest_path = os.path.join(base, image_tag, MANIFEST)
    if extracted:
        os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
        previous = []
        if os.path.isfile(manifest_path):
            with open(manifest_path, 'r', encoding='utf-8') as f:
                previous = json.load(f).get('files', [])
        known = {(x['offset'], x['inode']) for x in previous}
        merged = previous + [x for x in extracted if (x['offset'], x['inode']) not in known]
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump({'image': os.path.basename(file_path), 'files': merged}, f, indent=2,
                      ensure_ascii=False)
    return {
        'image': file_path,
        'profile': profile if not patterns else 'custom',
        'extracted_count': len(extracted),
        'extracted': extracted[:300],
        'skipped': skipped[:50],
        'manifest': workspace.rel(manifest_path, case_dir) if extracted else None,
        'next': ("Les fichiers extraits sont desormais des artefacts du cas : les analyser avec "
                 "les parsers adaptes (parse_evtx, sigma_scan, parse_prefetch, run_zimmermann...)."),
    }


def is_manifest(fname):
    return fnmatch.fnmatch(fname, MANIFEST)
