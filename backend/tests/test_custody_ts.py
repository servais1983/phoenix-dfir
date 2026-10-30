#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Legally robust chain of custody: Merkle tree (RFC 6962 vectors, proofs,
tamper detection), signed checkpoints, RFC 3161 TimeStampReq DER encoding and
TimeStampResp parsing (network always mocked), report sealing and the
custody bundle export."""

import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess  # nosec B404 - runs the bundled verifier in tests only
import sys
import tempfile
import unittest
import zipfile
from unittest import mock


os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['PHOENIX_DEBUG'] = 'false'

import merkle  # noqa: E402
import timestamping as tsp  # noqa: E402

# RFC 6962 reference leaves (Certificate Transparency merkle_tree_test vectors)
CT_LEAVES = [b'', b'\x00', b'\x10', b'\x20\x21', b'\x30\x31', b'\x40\x41\x42\x43',
             b'\x50\x51\x52\x53\x54\x55\x56\x57', bytes(range(0x60, 0x70))]
CT_ROOTS = [
    '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
    'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
    'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
    '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
    'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
    '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
]
# Audit path of leaf 0 in the 8-leaf reference tree
CT_PROOF_0_8 = [
    '96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7',
    '5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e',
    '6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4',
]

# Known-good TimeStampReq for SHA256("") with certReq TRUE.
# Without nonce, byte-identical to:
#   openssl ts -query -digest e3b0c442...b855 -sha256 -cert -no_nonce
# 30 39                                 SEQUENCE (57)
#    02 01 01                           version 1
#    30 31                              MessageImprint
#       30 0d 06 09 608648016503040201  AlgorithmIdentifier id-sha256
#             05 00                     parameters NULL
#       04 20 e3b0...b855               hashedMessage (32 bytes)
#    01 01 ff                           certReq TRUE
EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
REQ_NO_NONCE = ('30390201013031300d060960864801650304020105000420' + EMPTY_SHA256 + '0101ff')
# Same request with nonce 0x0102030405060708 inserted before certReq:
#    02 08 0102030405060708             nonce INTEGER, outer length 0x39 + 10 = 0x43
REQ_NONCE = ('30430201013031300d060960864801650304020105000420' + EMPTY_SHA256
             + '020801020304050607080101ff')


def craft_response(digest, nonce, status=0, gen_time=b'20261015120000Z', serial=4242,
                   hash_oid=tsp.OID_SHA256):
    """Build a minimal but structurally valid TimeStampResp (unsigned CMS)."""
    imprint = tsp.der_sequence(tsp.der_sequence(tsp.der_oid(hash_oid), tsp.der_null()),
                               tsp.der_octet_string(digest))
    items = [tsp.der_integer(1), tsp.der_oid('1.3.6.1.4.1.99999.1'), imprint,
             tsp.der_integer(serial), tsp.tlv(0x18, gen_time)]
    if nonce is not None:
        items.append(tsp.der_integer(nonce))
    tst_info = tsp.der_sequence(*items)
    encap = tsp.der_sequence(tsp.der_oid(tsp.OID_TST_INFO), tsp.tlv(0xa0, tsp.der_octet_string(tst_info)))
    signed_data = tsp.der_sequence(
        tsp.der_integer(3),
        tsp.tlv(0x31, tsp.der_sequence(tsp.der_oid(tsp.OID_SHA256), tsp.der_null())),
        encap,
        tsp.tlv(0x31, b''))
    token = tsp.der_sequence(tsp.der_oid(tsp.OID_SIGNED_DATA), tsp.tlv(0xa0, signed_data))
    status_info = tsp.der_sequence(tsp.der_integer(status))
    return tsp.der_sequence(status_info, token) if status in (0, 1) else tsp.der_sequence(status_info)


def fake_tsa(url, body, timeout):
    """Mocked HTTP layer: answer the request with a matching crafted token."""
    req = tsp.parse_request(body)
    return craft_response(bytes.fromhex(req['digest']), req['nonce'])


class MerkleVectorsTest(unittest.TestCase):

    def test_reference_roots(self):
        self.assertEqual(merkle.root_hex([]), merkle.EMPTY_ROOT)
        for n in range(1, 9):
            self.assertEqual(merkle.root_hex(CT_LEAVES[:n]), CT_ROOTS[n - 1], n)

    def test_reference_proof(self):
        proof = [p.hex() for p in merkle.inclusion_proof(0, CT_LEAVES)]
        self.assertEqual(proof, CT_PROOF_0_8)

    def test_all_proofs_verify(self):
        for n in range(1, 9):
            root = CT_ROOTS[n - 1]
            for i in range(n):
                proof = merkle.inclusion_proof(i, CT_LEAVES[:n])
                self.assertTrue(merkle.verify_inclusion(CT_LEAVES[i], i, n, proof, root), (i, n))

    def test_tamper_detection(self):
        proof = merkle.inclusion_proof(5, CT_LEAVES)
        root = CT_ROOTS[7]
        self.assertFalse(merkle.verify_inclusion(b'tampered', 5, 8, proof, root))
        self.assertFalse(merkle.verify_inclusion(CT_LEAVES[5], 4, 8, proof, root))
        # Wrong tree size (the proof length no longer fits)
        self.assertFalse(merkle.verify_inclusion(CT_LEAVES[5], 5, 6, proof, root))
        self.assertFalse(merkle.verify_inclusion(CT_LEAVES[5], 5, 16, proof, root))
        bad = list(proof)
        bad[0] = bytes(32)
        self.assertFalse(merkle.verify_inclusion(CT_LEAVES[5], 5, 8, bad, root))
        self.assertFalse(merkle.verify_inclusion(CT_LEAVES[5], 5, 8, proof[:-1], root))
        self.assertFalse(merkle.verify_inclusion(CT_LEAVES[5], 5, 8, proof, 'zz'))
        with self.assertRaises(IndexError):
            merkle.inclusion_proof(8, CT_LEAVES)


class TimestampDerTest(unittest.TestCase):

    def test_request_known_good_bytes(self):
        digest = hashlib.sha256(b'').digest()
        self.assertEqual(tsp.build_request(digest, nonce=None, cert_req=True).hex(), REQ_NO_NONCE)
        self.assertEqual(tsp.build_request(digest, nonce=0x0102030405060708, cert_req=True).hex(), REQ_NONCE)

    def test_request_roundtrip(self):
        digest = hashlib.sha256(b'phoenix').digest()
        parsed = tsp.parse_request(tsp.build_request(digest, nonce=2 ** 63 - 1))
        self.assertEqual(parsed, {'version': 1, 'hash_algorithm': tsp.OID_SHA256, 'digest': digest.hex(),
                                  'nonce': 2 ** 63 - 1, 'cert_req': True})
        with self.assertRaises(ValueError):
            tsp.build_request(b'short')

    def test_integer_and_oid_encoding(self):
        vectors = {0: '020100', 127: '02017f', 128: '02020080', 256: '02020100', -1: '0201ff',
                   -128: '020180', -129: '0202ff7f'}
        for value, expected in vectors.items():
            self.assertEqual(tsp.der_integer(value).hex(), expected)
            self.assertEqual(tsp.decode_integer(tsp.read_tlv(bytes.fromhex(expected))[1]), value)
        self.assertEqual(tsp.der_oid(tsp.OID_SHA256).hex(), '0609608648016503040201')
        self.assertEqual(tsp.decode_oid(tsp.read_tlv(tsp.der_oid('1.2.840.113549.1.7.2'))[1]),
                         '1.2.840.113549.1.7.2')
        long_value = tsp.der_octet_string(b'x' * 300)
        self.assertEqual(long_value[:4].hex(), '0482012c')

    def test_response_parsing_and_checks(self):
        digest = hashlib.sha256(b'checkpoint').digest()
        resp = craft_response(digest, 77, gen_time=b'20261015120000.5Z')
        ok, info = tsp.verify_response(resp, digest, 77)
        self.assertTrue(ok, info)
        self.assertEqual(info['serial_number'], 4242)
        self.assertEqual(info['nonce'], 77)
        self.assertEqual(info['gen_time'], '2026-10-15T12:00:00.500000+00:00')
        self.assertEqual(info['policy'], '1.3.6.1.4.1.99999.1')

        self.assertFalse(tsp.verify_response(resp, digest, 78)[0])  # nonce mismatch
        self.assertFalse(tsp.verify_response(resp, hashlib.sha256(b'x').digest(), 77)[0])
        self.assertFalse(tsp.verify_response(craft_response(digest, 77, status=2), digest, 77)[0])
        self.assertFalse(tsp.verify_response(craft_response(digest, 77, hash_oid='1.3.14.3.2.26'),
                                             digest, 77)[0])
        self.assertFalse(tsp.verify_response(b'\x30\x05garbage', digest, 77)[0])
        self.assertFalse(tsp.verify_response(b'', digest, 77)[0])

    def test_client_disabled_and_mocked(self):
        digest = hashlib.sha256(b'x').digest()
        with mock.patch.dict(os.environ, {'PHOENIX_TSA_URL': ''}):
            self.assertEqual(tsp.timestamp_digest(digest)['status'], 'disabled')
        with mock.patch.dict(os.environ, {'PHOENIX_TSA_URL': 'https://tsa.example.test/tsr'}):
            with mock.patch.object(tsp, '_http_post', side_effect=fake_tsa) as post:
                out = tsp.timestamp_digest(digest)
                self.assertEqual(out['status'], 'granted')
                self.assertEqual(out['tsa_host'], 'tsa.example.test')
                post.assert_called_once()
            with mock.patch.object(tsp, '_http_post', side_effect=OSError('down')):
                self.assertEqual(tsp.timestamp_digest(digest)['status'], 'error')
            # Replayed token (stale nonce) is refused
            with mock.patch.object(tsp, '_http_post', return_value=craft_response(digest, 1)):
                bad = tsp.timestamp_digest(digest)
                self.assertEqual(bad['status'], 'error')
                self.assertIn('nonce', bad['error'])
        with mock.patch.dict(os.environ, {'PHOENIX_TSA_URL': 'file:///etc/passwd'}):
            self.assertEqual(tsp.timestamp_digest(digest)['status'], 'error')


class CustodyLedgerApiTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')
        cls.store = tempfile.mkdtemp(prefix='phoenix_custody_')
        cls.reports = tempfile.mkdtemp(prefix='phoenix_reports_')
        cls._env = mock.patch.dict(os.environ, {'PHOENIX_CUSTODY_DIR': cls.store,
                                                'PHOENIX_TSA_URL': '', 'PHOENIX_CHECKPOINT_EVERY': '0'})
        cls._env.start()
        import database
        database.DB_PATH = cls.db_path
        database.init_db()
        from app import app
        app.config['TESTING'] = True
        cls.app = app
        cls.client = app.test_client()
        from routes import reports as reports_routes
        cls._reports_patch = mock.patch.object(reports_routes, 'REPORTS_DIR', cls.reports)
        cls._reports_patch.start()
        from tests.auth_helpers import add_member, bootstrap_admin, create_user
        cls.admin = bootstrap_admin(cls.client, 'cts_admin', 'Custody-Admin-2026!')['token']
        cls.analyst = create_user(cls.client, cls.admin, 'cts_analyst', 'Custody-Analyst-2026!')['token']
        cls.viewer = create_user(cls.client, cls.admin, 'cts_viewer', 'Custody-Viewer-2026!',
                                 role='viewer')['token']
        cls.outsider = create_user(cls.client, cls.admin, 'cts_out', 'Custody-Outsider-2026!')['token']
        resp = cls.client.post('/api/investigations', json={'name': 'Custody case'},
                               headers={'Authorization': f'Bearer {cls.analyst}'})
        cls.inv = resp.get_json()['id']
        add_member(cls.client, cls.analyst, cls.inv, 'cts_viewer')
        import custody
        for i in range(5):
            custody.record(f'tool_{i}', 'tester', investigation_id=cls.inv, summary=f'step {i}',
                           details={'i': i, 'txt': 'évidence'})
            custody.record(f'other_{i}', 'tester', investigation_id=None)

    @classmethod
    def tearDownClass(cls):
        cls._reports_patch.stop()
        cls._env.stop()
        shutil.rmtree(cls.store, ignore_errors=True)
        shutil.rmtree(cls.reports, ignore_errors=True)
        os.close(cls.db_fd)
        os.unlink(cls.db_path)

    def _h(self, token):
        return {'Authorization': f'Bearer {token}'}

    def test_merkle_endpoint_access(self):
        import custody
        resp = self.client.get(f'/api/custody/merkle?investigation_id={self.inv}', headers=self._h(self.viewer))
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        entries = custody.ledger_entries(self.inv)
        self.assertEqual(body['leaf_count'], len(entries))
        self.assertEqual(body['root'], merkle.root_hex([bytes.fromhex(e['entry_hash']) for e in entries]))
        self.assertEqual(self.client.get(f'/api/custody/merkle?investigation_id={self.inv}',
                                         headers=self._h(self.outsider)).status_code, 404)
        self.assertEqual(self.client.get('/api/custody/merkle', headers=self._h(self.analyst)).status_code, 400)
        glob = self.client.get('/api/custody/merkle', headers=self._h(self.admin)).get_json()
        self.assertGreaterEqual(glob['leaf_count'], 10)

    def test_inclusion_proof_endpoint(self):
        import custody
        entry = custody.ledger_entries(self.inv)[2]
        resp = self.client.get(f"/api/custody/proof/{entry['seq']}", headers=self._h(self.viewer))
        self.assertEqual(resp.status_code, 200)
        p = resp.get_json()
        self.assertEqual(p['scope'], f'investigation:{self.inv}')
        self.assertTrue(merkle.verify_inclusion(bytes.fromhex(p['entry_hash']), p['leaf_index'],
                                                p['tree_size'], p['proof'], p['root']))
        self.assertEqual(self.client.get(f"/api/custody/proof/{entry['seq']}",
                                         headers=self._h(self.outsider)).status_code, 404)
        self.assertEqual(self.client.get(f"/api/custody/proof/{entry['seq']}?scope=global",
                                         headers=self._h(self.viewer)).status_code, 404)
        g = self.client.get(f"/api/custody/proof/{entry['seq']}?scope=global", headers=self._h(self.admin))
        gp = g.get_json()
        self.assertEqual(gp['scope'], 'global')
        self.assertTrue(merkle.verify_inclusion(bytes.fromhex(gp['entry_hash']), gp['leaf_index'],
                                                gp['tree_size'], gp['proof'], gp['root']))
        # Entry without investigation: admin only
        orphan = custody.ledger_entries()[1]
        self.assertIsNone(orphan['investigation_id'])
        self.assertEqual(self.client.get(f"/api/custody/proof/{orphan['seq']}",
                                         headers=self._h(self.analyst)).status_code, 404)
        self.assertEqual(self.client.get('/api/custody/proof/999999', headers=self._h(self.admin)).status_code, 404)

    def test_checkpoint_timestamped_and_tamper_detected(self):
        import custody
        with mock.patch.dict(os.environ, {'PHOENIX_TSA_URL': 'https://tsa.example.test/'}), \
                mock.patch.object(tsp, '_http_post', side_effect=fake_tsa):
            self.assertEqual(self.client.post('/api/custody/checkpoint', json={'investigation_id': self.inv},
                                              headers=self._h(self.viewer)).status_code, 403)
            resp = self.client.post('/api/custody/checkpoint', json={'investigation_id': self.inv},
                                    headers=self._h(self.analyst))
        self.assertEqual(resp.status_code, 201, resp.get_json())
        cp = resp.get_json()
        self.assertEqual(cp['tsa_status'], 'granted')
        self.assertEqual(cp['tsr_file'], f"checkpoint-{cp['id']}.tsr")
        json_path, tsr_path = custody.checkpoint_paths(cp['id'])
        self.assertTrue(os.path.isfile(tsr_path))
        with open(json_path, 'rb') as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), cp['statement_sha256'])
        sealed = custody.get_entry(cp['ledger_seq'])
        self.assertEqual(sealed['action'], 'merkle_checkpoint')
        self.assertEqual(sealed['payload_sha256'], cp['statement_sha256'])

        report = self.client.get(f"/api/custody/checkpoints/{cp['id']}/verify", headers=self._h(self.viewer))
        self.assertTrue(report.get_json()['valid'], report.get_json())
        self.assertTrue(report.get_json()['timestamp']['valid'])
        self.assertEqual(self.client.get(f"/api/custody/checkpoints/{cp['id']}/verify",
                                         headers=self._h(self.outsider)).status_code, 404)

        # Tamper with a covered entry: root no longer matches
        target = custody.ledger_entries(self.inv)[0]
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('UPDATE custody_chain SET entry_hash=? WHERE seq=?', ('ab' * 32, target['seq']))
            conn.commit()
            self.assertFalse(custody.verify_checkpoint(custody.get_checkpoint(cp['id']))['root_matches'])
        finally:
            conn.execute('UPDATE custody_chain SET entry_hash=? WHERE seq=?', (target['entry_hash'], target['seq']))
            conn.commit()
            conn.close()
        self.assertTrue(custody.verify_checkpoint(custody.get_checkpoint(cp['id']))['valid'])

        # Forged signature is detected
        forged = dict(custody.get_checkpoint(cp['id']))
        forged['signature'] = '00' * (len(forged['signature']) // 2)
        self.assertFalse(custody.verify_checkpoint(forged)['signature_valid'])

        listing = self.client.get(f'/api/custody/checkpoints?investigation_id={self.inv}',
                                  headers=self._h(self.viewer)).get_json()
        self.assertIn(cp['id'], [c['id'] for c in listing['items']])

    def test_periodic_checkpoint(self):
        import custody
        before = len(custody.list_checkpoints(None, limit=500))
        with mock.patch.dict(os.environ, {'PHOENIX_CHECKPOINT_EVERY': '1'}):
            custody.record('periodic_probe', 'tester')
        after = custody.list_checkpoints(None, limit=500)
        self.assertEqual(len(after), before + 1)
        self.assertEqual(after[0]['tsa_status'], 'disabled')

    def test_console_status_exposes_timestamping(self):
        resp = self.client.get('/api/console/status', headers=self._h(self.viewer))
        self.assertEqual(resp.status_code, 200)
        ts = resp.get_json()['timestamping']
        self.assertFalse(ts['enabled'])
        self.assertIn('checkpoints', ts)
        self.assertFalse(ts['signature_chain_verified'])

    def test_report_sealed_and_timestamped(self):
        import custody
        with mock.patch.dict(os.environ, {'PHOENIX_TSA_URL': 'https://tsa.example.test/'}), \
                mock.patch.object(tsp, '_http_post', side_effect=fake_tsa):
            resp = self.client.post('/api/reports/generate', json={'investigation_id': self.inv},
                                    headers=self._h(self.analyst))
        self.assertEqual(resp.status_code, 200, resp.get_json())
        body = resp.get_json()
        path = os.path.join(self.reports, body['report_id'])
        with open(path, 'rb') as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), body['sha256'])
        self.assertEqual(body['timestamp']['status'], 'granted')
        self.assertTrue(os.path.isfile(path + '.tsr'))
        with open(path + '.tsr', 'rb') as f:
            self.assertTrue(tsp.verify_response(f.read(), bytes.fromhex(body['sha256']))[0])
        sealed = custody.get_entry(body['custody_seq'])
        self.assertEqual(sealed['action'], 'report_generated')
        self.assertEqual(sealed['payload_sha256'], body['sha256'])

    def test_bundle_contents_and_offline_verifier(self):
        self.client.post('/api/reports/generate', json={'investigation_id': self.inv},
                         headers=self._h(self.analyst))
        self.assertEqual(self.client.get(f'/api/investigations/{self.inv}/custody-bundle',
                                         headers=self._h(self.outsider)).status_code, 404)
        import custody
        n_before = len(custody.list_checkpoints(self.inv, limit=500))
        viewer = self.client.get(f'/api/investigations/{self.inv}/custody-bundle', headers=self._h(self.viewer))
        self.assertEqual(viewer.status_code, 200)
        self.assertEqual(len(custody.list_checkpoints(self.inv, limit=500)), n_before)  # read-only
        resp = self.client.get(f'/api/investigations/{self.inv}/custody-bundle', headers=self._h(self.analyst))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.mimetype, 'application/zip')
        data = resp.get_data()
        self.assertEqual(resp.headers['X-Phoenix-Bundle-SHA256'], hashlib.sha256(data).hexdigest())
        z = zipfile.ZipFile(io.BytesIO(data))
        names = set(z.namelist())
        for required in ('README.txt', 'verify_bundle.py', 'ledger.json', 'merkle.json',
                         'chain_verification.json', 'signing_key.json', 'checkpoints/index.json',
                         'reports/report_hashes.json'):
            self.assertIn(required, names)
        self.assertTrue(any(n.startswith('checkpoints/checkpoint-') and n.endswith('.json') for n in names))
        self.assertTrue(any(n.startswith('reports/rapport_') and n.endswith('.md') for n in names))
        readme = z.read('README.txt').decode()
        self.assertIn('openssl ts -verify', readme)
        self.assertIn('does NOT verify the TSA signature chain', readme)
        ledger = json.loads(z.read('ledger.json'))
        self.assertTrue(all(e['investigation_id'] == self.inv for e in ledger['entries']))
        m = json.loads(z.read('merkle.json'))
        self.assertEqual(len(m['proofs']), m['leaf_count'])
        rh = json.loads(z.read('reports/report_hashes.json'))
        self.assertTrue(rh and all(r['matches_ledger'] for r in rh))

        out = tempfile.mkdtemp(prefix='phoenix_bundle_')
        try:
            z.extractall(out)
            run = subprocess.run([sys.executable, '-I', os.path.join(out, 'verify_bundle.py'), out],  # nosec B603
                                 capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn('ALL CHECKS PASSED', run.stdout)
            # Tampered ledger: the offline verifier fails
            path = os.path.join(out, 'ledger.json')
            with open(path, encoding='utf-8') as f:
                doc = json.load(f)
            doc['entries'][0]['summary'] = 'forged'
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(doc, f)
            run = subprocess.run([sys.executable, '-I', os.path.join(out, 'verify_bundle.py'), out],  # nosec B603
                                 capture_output=True, text=True, timeout=60)
            self.assertEqual(run.returncode, 1)
        finally:
            shutil.rmtree(out, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
