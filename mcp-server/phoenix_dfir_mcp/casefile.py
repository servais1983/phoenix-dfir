"""Standard case layout, evidence manifest and integrity verification.

A case folder::

    <case>/
        evidence/         originals, read-only, never modified by Phoenix
        derived/          what the tools produce (extracted files, carved payloads)
        reports/          triage and investigation reports
        custody/          integrity verification records
        manifest.sha256   SHA-256 of every evidence file (sha256sum format)

The SHA-256 is computed while the evidence is copied in (``ingest``) and
checked again by ``verify``, typically when the case is closed. Both
operations are recorded in the custody ledger.
"""

import datetime
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path

from . import ledger, workspace

EVIDENCE = workspace.EVIDENCE_DIR
DERIVED = workspace.DERIVED_DIR
REPORTS = 'reports'
CUSTODY = 'custody'
LAYOUT = (EVIDENCE, DERIVED, REPORTS, CUSTODY)
MANIFEST = 'manifest.sha256'
_CHUNK = 1024 * 1024


class CaseError(ValueError):
    """Invalid case operation (missing file, overwrite refused...)."""


def init_case(case_dir):
    """Create the standard layout (idempotent) and return the case Path."""
    case = Path(case_dir).resolve()
    for name in LAYOUT:
        (case / name).mkdir(parents=True, exist_ok=True)
    return case


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(_CHUNK), b''):
            digest.update(block)
    return digest.hexdigest()


def read_manifest(case_dir):
    """Return {posix relative path: sha256} from manifest.sha256."""
    path = Path(case_dir) / MANIFEST
    entries = {}
    if not path.is_file():
        return entries
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        digest, _, rel = line.partition('  ')
        if len(digest) != 64 or not rel:
            raise CaseError(f'Malformed manifest line: {line!r}')
        entries[rel] = digest.lower()
    return entries


def _write_manifest(case, entries):
    tmp = case / (MANIFEST + '.tmp')
    tmp.write_text(''.join(f'{entries[rel]}  {rel}\n' for rel in sorted(entries)), encoding='utf-8')
    os.replace(tmp, case / MANIFEST)


def make_read_only(path):
    """Best effort: drop the write permission. Returns a warning or None."""
    try:
        mode = os.stat(path).st_mode
        os.chmod(path, mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    except (OSError, NotImplementedError) as e:
        return f'could not make {path} read-only: {e}'
    return None


def _copy_hashed(src, dst):
    """Copy src to dst and return the SHA-256 of the bytes written."""
    digest = hashlib.sha256()
    with open(src, 'rb') as fin, open(dst, 'xb') as fout:
        for block in iter(lambda: fin.read(_CHUNK), b''):
            digest.update(block)
            fout.write(block)
    shutil.copystat(src, dst)
    return digest.hexdigest()


def _sources(paths):
    for raw in paths:
        src = Path(raw)
        if src.is_file():
            yield src, src.name
        elif src.is_dir():
            for item in sorted(p for p in src.rglob('*') if p.is_file()):
                yield item, (Path(src.name) / item.relative_to(src)).as_posix()
        else:
            raise CaseError(f'Evidence not found: {raw}')


def ingest(case_dir, paths, actor='phoenix-cli'):
    """Copy evidence into <case>/evidence, hash it, make it read-only, record it."""
    case = init_case(case_dir)
    entries = read_manifest(case)
    added, warnings = [], []
    for src, name in _sources(paths):
        rel = f'{EVIDENCE}/{name}'
        dst = case / EVIDENCE / Path(name)
        if dst.exists() or rel in entries:
            raise CaseError(f'Evidence already present, overwrite refused: {rel}')
        dst.parent.mkdir(parents=True, exist_ok=True)
        source_hash = sha256_file(src)
        copied_hash = _copy_hashed(src, dst)
        if copied_hash != source_hash:
            dst.unlink()
            raise CaseError(f'Copy of {src} does not match its source hash')
        warning = make_read_only(dst)
        if warning:
            warnings.append(warning)
        elif sys.platform == 'win32' and not warnings:
            warnings.append('Windows: only the read-only attribute is set, NTFS ACLs are unchanged.')
        entries[rel] = copied_hash
        _write_manifest(case, entries)
        ledger.record('evidence_ingested', actor, agent='phoenix-ingest', artifact_ref=str(dst),
                      summary=f'{rel} ingested ({dst.stat().st_size} bytes)', payload_sha256=copied_hash,
                      details={'case': str(case), 'path': rel, 'source': str(src.resolve()),
                               'sha256': copied_hash, 'size': dst.stat().st_size})
        added.append({'path': rel, 'sha256': copied_hash, 'size': dst.stat().st_size})
    return {'case': str(case), 'added': added, 'warnings': warnings, 'manifest': str(case / MANIFEST)}


def verify(case_dir, actor='phoenix-cli'):
    """Re-hash every evidence file against the manifest and record the result."""
    case = Path(case_dir).resolve()
    if not case.is_dir():
        raise CaseError(f'Case folder not found: {case_dir}')
    entries = read_manifest(case)
    if not entries:
        raise CaseError(f'No {MANIFEST} in {case}: ingest the evidence first (phoenix ingest).')
    ok, mismatched, missing = [], [], []
    for rel, expected in sorted(entries.items()):
        path = case / Path(rel)
        if not path.is_file():
            missing.append(rel)
            continue
        actual = sha256_file(path)
        if actual == expected:
            ok.append(rel)
        else:
            mismatched.append({'path': rel, 'expected': expected, 'actual': actual})
    evidence_root = case / EVIDENCE
    listed = set(entries)
    unlisted = sorted(p.relative_to(case).as_posix() for p in evidence_root.rglob('*')
                      if p.is_file() and p.relative_to(case).as_posix() not in listed) if evidence_root.is_dir() else []
    valid = not mismatched and not missing and not unlisted
    now = datetime.datetime.now(datetime.timezone.utc)
    result = {'case': str(case), 'valid': valid, 'checked': len(entries), 'ok': len(ok),
              'mismatched': mismatched, 'missing': missing, 'unlisted': unlisted,
              'verified_at': now.isoformat(timespec='seconds')}
    entry = ledger.record('evidence_verified', actor, agent='phoenix-verify', artifact_ref=str(case),
                          severity='info' if valid else 'high',
                          summary=(f'{len(ok)}/{len(entries)} evidence files match the manifest' if valid
                                   else f'Integrity failure: {len(mismatched)} modified, {len(missing)} missing, '
                                        f'{len(unlisted)} not in the manifest'),
                          payload_sha256=sha256_file(case / MANIFEST), details=result)
    result['ledger_seq'] = entry.get('seq')
    (case / CUSTODY).mkdir(exist_ok=True)
    record_path = case / CUSTODY / f"verify_{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    record_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    result['record'] = str(record_path)
    return result
