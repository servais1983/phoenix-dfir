#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Chain of custody export bundle (zip) for one investigation.

Contents:
    README.txt                    verification instructions (English)
    verify_bundle.py              standalone verifier (Python 3 stdlib only)
    ledger.json                   ledger entries of the investigation (raw, as hashed)
    chain_verification.json       server-side verification of the whole hash chain
    merkle.json                   Merkle root, leaves and an inclusion proof per entry
    checkpoints/checkpoint-N.json signed checkpoint statements (exact signed bytes)
    checkpoints/checkpoint-N.sig  raw signature bytes
    checkpoints/checkpoint-N.tsr  RFC 3161 TimeStampResp (when a TSA is configured)
    checkpoints/index.json        checkpoint metadata and server verification
    signing_key.json / checkpoint_signing_public.pem
    reports/<report>              generated reports of the investigation
    reports/<report>.tsr          their RFC 3161 tokens (when timestamped)
    reports/report_hashes.json    SHA-256 of every report and the sealing ledger entry
"""

import datetime
import io
import json
import os
import zipfile

import custody
import merkle

_REPORT_SUFFIXES = ('.md', '.json', '.csv', '.html', '.pdf', '.txt')

README = """PHOENIX DFIR - CHAIN OF CUSTODY BUNDLE
=====================================

Investigation: {investigation_id}
Exported at:   {exported_at} (UTC)
Exported by:   {exported_by}

1. Ledger (ledger.json)
   Every action on the evidence (acquisition, tool run, finding, remediation
   decision, report) is an entry of an append-only SHA-256 hash chain:
     entry_hash = SHA256(json.dumps({{seq, ts, investigation_id, actor, agent,
                  action, artifact_ref, summary, mitre, severity, details,
                  payload_sha256, prev_hash}}, ensure_ascii=False, sort_keys=True))
   `details` is hashed as the exact JSON string stored in ledger.json.
   prev_hash links to the previous entry of the WHOLE ledger (other
   investigations included), so links are checked server side: see
   chain_verification.json. Each entry_hash can be recomputed offline.

2. Merkle tree (merkle.json)
   RFC 6962 / RFC 9162 tree over the entries of this investigation, ordered by
   seq. Leaf data = the 32 raw bytes of entry_hash.
     leaf = SHA256(0x00 || entry_hash_bytes), node = SHA256(0x01 || left || right)
   merkle.json holds the root and an inclusion (audit) path for every entry.

3. Checkpoints (checkpoints/)
   A checkpoint freezes the Merkle root at a given size. checkpoint-N.json is
   the exact signed statement (canonical JSON). Signature algorithm and key
   are in signing_key.json. With Ed25519:
     openssl pkeyutl -verify -pubin -inkey checkpoint_signing_public.pem \\
        -rawin -in checkpoints/checkpoint-N.json -sigfile checkpoints/checkpoint-N.sig
   HMAC-SHA256 signatures can only be checked by the server operator.

4. RFC 3161 trusted timestamps (*.tsr)
   checkpoint-N.tsr timestamps SHA256(checkpoint-N.json); reports/<r>.tsr
   timestamps SHA256(reports/<r>). Phoenix checks the messageImprint and the
   nonce of each token. It does NOT verify the TSA signature chain: do it with
   the CA certificate of your TSA:
     openssl ts -reply -in checkpoints/checkpoint-N.tsr -text
     openssl ts -verify -data checkpoints/checkpoint-N.json \\
        -in checkpoints/checkpoint-N.tsr -CAfile tsa-ca.pem
     openssl ts -verify -data reports/<r> -in reports/<r>.tsr -CAfile tsa-ca.pem

5. Automated offline checks
     python3 verify_bundle.py .
   recomputes every entry_hash, the Merkle root, every inclusion proof, the
   root of each checkpoint and the SHA-256 of every report. Exit code 0 means
   all checks passed.
"""

VERIFIER = r'''#!/usr/bin/env python3
"""Offline verifier of a Phoenix DFIR chain of custody bundle (stdlib only)."""
import hashlib
import json
import os
import sys

FIELDS = ('seq', 'ts', 'investigation_id', 'actor', 'agent', 'action', 'artifact_ref',
          'summary', 'mitre', 'severity', 'details', 'payload_sha256', 'prev_hash')


def entry_hash(e):
    canonical = {k: e.get(k) for k in FIELDS}
    data = json.dumps(canonical, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def leaf(d):
    return hashlib.sha256(b'\x00' + d).digest()


def node(l, r):
    return hashlib.sha256(b'\x01' + l + r).digest()


def mth(hashes):
    if not hashes:
        return hashlib.sha256(b'').digest()
    if len(hashes) == 1:
        return hashes[0]
    k = 1
    while k * 2 < len(hashes):
        k *= 2
    return node(mth(hashes[:k]), mth(hashes[k:]))


def verify_inclusion(data, index, size, proof, root):
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf(data)
    for p in proof:
        p = bytes.fromhex(p)
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = node(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r.hex() == root


def main(base):
    ok = True
    def check(cond, msg):
        nonlocal ok
        print(('OK    ' if cond else 'FAIL  ') + msg)
        ok = ok and cond
    ledger = json.load(open(os.path.join(base, 'ledger.json'), encoding='utf-8'))['entries']
    for e in ledger:
        check(entry_hash(e) == e['entry_hash'], f"entry #{e['seq']} hash")
    m = json.load(open(os.path.join(base, 'merkle.json'), encoding='utf-8'))
    hashes = [leaf(bytes.fromhex(e['entry_hash'])) for e in ledger]
    check(mth(hashes).hex() == m['root'], f"Merkle root {m['root']} over {len(hashes)} leaves")
    for p in m['proofs']:
        check(verify_inclusion(bytes.fromhex(p['entry_hash']), p['leaf_index'], p['tree_size'],
                               p['proof'], m['root']), f"inclusion proof of entry #{p['seq']}")
    cp_index = os.path.join(base, 'checkpoints', 'index.json')
    if os.path.isfile(cp_index):
        for cp in json.load(open(cp_index, encoding='utf-8')):
            raw = open(os.path.join(base, 'checkpoints', cp['file']), 'rb').read()
            st = json.loads(raw)
            check(hashlib.sha256(raw).hexdigest() == cp['statement_sha256'],
                  f"checkpoint {cp['id']} statement hash")
            sub = [leaf(bytes.fromhex(e['entry_hash'])) for e in ledger
                   if st['last_seq'] is not None and e['seq'] <= st['last_seq']]
            check(len(sub) == st['tree_size'] and mth(sub).hex() == st['root'],
                  f"checkpoint {cp['id']} root {st['root']}")
    rh = os.path.join(base, 'reports', 'report_hashes.json')
    if os.path.isfile(rh):
        for r in json.load(open(rh, encoding='utf-8')):
            path = os.path.join(base, 'reports', r['report_id'])
            if os.path.isfile(path):
                check(hashlib.sha256(open(path, 'rb').read()).hexdigest() == r['sha256'],
                      f"report {r['report_id']} sha256")
    print('ALL CHECKS PASSED' if ok else 'SOME CHECKS FAILED')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else '.'))
'''


def _reports_of(investigation_id, reports_dir, report_investigation_id):
    if not os.path.isdir(reports_dir):
        return []
    out = []
    for name in sorted(os.listdir(reports_dir)):
        if not name.endswith(_REPORT_SUFFIXES):
            continue
        if report_investigation_id(name) != investigation_id:
            continue
        path = os.path.join(reports_dir, name)
        if os.path.isfile(path) and not os.path.islink(path):
            out.append((name, path))
    return out


def build(investigation_id, exported_by, reports_dir, report_investigation_id):
    """Build the bundle zip in memory and return its bytes."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    entries = custody.ledger_entries(investigation_id, raw=True)
    tree = merkle.build_ledger_tree(entries)
    proofs = []
    leaves = [merkle.ledger_leaf(e['entry_hash']) for e in entries]
    for i, e in enumerate(entries):
        proofs.append({'seq': e['seq'], 'entry_hash': e['entry_hash'], 'leaf_index': i,
                       'tree_size': len(leaves),
                       'proof': [p.hex() for p in merkle.inclusion_proof(i, leaves)]})

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        def put_json(name, obj):
            z.writestr(name, json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True))

        z.writestr('README.txt', README.format(investigation_id=investigation_id, exported_at=now,
                                               exported_by=exported_by))
        z.writestr('verify_bundle.py', VERIFIER)
        put_json('ledger.json', {'investigation_id': investigation_id, 'exported_at': now,
                                 'hashed_fields': list(custody._HASHED_FIELDS), 'entries': entries})
        put_json('chain_verification.json', custody.verify_chain())
        put_json('merkle.json', dict(tree, proofs=proofs, investigation_id=investigation_id))

        signing = custody.signing_info()
        put_json('signing_key.json', signing)
        if signing.get('public_key_pem'):
            z.writestr('checkpoint_signing_public.pem', signing['public_key_pem'])

        index = []
        for cp in reversed(custody.list_checkpoints(investigation_id, limit=500)):
            json_path, tsr_path = custody.checkpoint_paths(cp['id'])
            stem = f"checkpoint-{cp['id']}"
            statement_bytes = custody.canonical_json(cp['statement'])
            z.writestr(f'checkpoints/{stem}.json', statement_bytes)
            if cp['signature_alg'] == 'Ed25519':
                z.writestr(f'checkpoints/{stem}.sig', bytes.fromhex(cp['signature']))
            has_tsr = os.path.isfile(tsr_path)
            if has_tsr:
                z.write(tsr_path, f'checkpoints/{stem}.tsr')
            index.append({
                'id': cp['id'], 'file': f'{stem}.json', 'tsr': f'{stem}.tsr' if has_tsr else None,
                'created_at': cp['created_at'], 'root': cp['root'], 'tree_size': cp['tree_size'],
                'last_seq': cp['last_seq'], 'statement_sha256': cp['statement_sha256'],
                'signature_alg': cp['signature_alg'], 'signature': cp['signature'],
                'key_id': cp['key_id'], 'tsa_status': cp['tsa_status'],
                'tsa_gen_time': cp['tsa_gen_time'], 'ledger_seq': cp['ledger_seq'],
                'server_verification': custody.verify_checkpoint(cp),
            })
        put_json('checkpoints/index.json', index)

        sealed = {}
        for e in entries:
            if e['action'] == 'report_generated':
                sealed.setdefault(e['artifact_ref'], []).append(
                    {'seq': e['seq'], 'payload_sha256': e['payload_sha256']})
        report_rows = []
        for name, path in _reports_of(investigation_id, reports_dir, report_investigation_id):
            digest, size = custody.file_sha256(path)
            z.write(path, f'reports/{name}')
            tsr = path + '.tsr'
            if os.path.isfile(tsr):
                z.write(tsr, f'reports/{name}.tsr')
            seals = sealed.get(name, [])
            report_rows.append({
                'report_id': name, 'sha256': digest.hex(), 'size': size,
                'tsr': f'{name}.tsr' if os.path.isfile(tsr) else None,
                'ledger_entries': seals,
                'matches_ledger': any(s['payload_sha256'] == digest.hex() for s in seals),
            })
        put_json('reports/report_hashes.json', report_rows)
    return buf.getvalue()
