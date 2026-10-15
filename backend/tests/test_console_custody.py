#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de la console enqueteur DFIR : chaine de preuve SHA-256, validation humaine
(Human-in-the-Loop), coffre de preuves en lecture seule et enregistrement
des outils de l'enqueteur autonome."""

import io
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['PHOENIX_DEBUG'] = 'false'


class ConsoleCustodyTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')
        import database
        database.DB_PATH = cls.db_path
        database.init_db()

        from app import app
        app.config['TESTING'] = True
        cls.app = app
        cls.client = app.test_client()

        from tests.auth_helpers import bootstrap_admin, create_user
        cls.token = bootstrap_admin(cls.client, 'dfir_tester', 'Phx-Dfir-Test-2026!', 'DFIR')['token']
        cls.viewer_token = create_user(cls.client, cls.token, 'viewer_only', 'Viewer-Only-2026!',
                                       role='viewer')['token']

        cls.vault = tempfile.mkdtemp(prefix='phoenix_vault_')
        os.makedirs(os.path.join(cls.vault, 'host1'))
        with open(os.path.join(cls.vault, 'host1', 'memdump.raw'), 'wb') as f:
            f.write(b'\x00' * 2048)
        with open(os.path.join(cls.vault, 'Security.log'), 'w') as f:
            f.write('Failed password for root from 203.0.113.9\n')
        cls._env = mock.patch.dict(os.environ, {'PHOENIX_EVIDENCE_VAULT': cls.vault})
        cls._env.start()

    @classmethod
    def tearDownClass(cls):
        cls._env.stop()
        shutil.rmtree(cls.vault, ignore_errors=True)
        os.close(cls.db_fd)
        os.unlink(cls.db_path)

    def _headers(self, token=None):
        return {'Authorization': f'Bearer {token or self.token}', 'Content-Type': 'application/json'}

    def _create_investigation(self, name='Cas DFIR'):
        resp = self.client.post('/api/investigations', json={'name': name}, headers=self._headers())
        return resp.get_json()['id']

    # ------------------------------------------------------------------
    # Chaine de preuve
    # ------------------------------------------------------------------

    def test_chaine_lineaire_et_verifiable(self):
        import custody
        a = custody.record('test_a', 'tester', summary='premier')
        b = custody.record('test_b', 'tester', summary='second', payload_sha256=custody.sha256_text('x'))
        self.assertEqual(b['prev_hash'], a['entry_hash'])
        self.assertEqual(b['seq'], a['seq'] + 1)
        self.assertEqual(len(b['entry_hash']), 64)
        resp = self.client.get('/api/custody/verify', headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()['valid'])

    def test_alteration_detectee(self):
        import custody
        entry = custody.record('a_alterer', 'tester', summary='original')
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute('UPDATE custody_chain SET summary=? WHERE seq=?', ('falsifie', entry['seq']))
            conn.commit()
            result = custody.verify_chain()
            self.assertFalse(result['valid'])
            self.assertEqual(result['broken_at'], entry['seq'])
        finally:
            # Restaurer pour ne pas polluer les autres tests
            conn.execute('UPDATE custody_chain SET summary=? WHERE seq=?', ('original', entry['seq']))
            conn.commit()
            conn.close()
        self.assertTrue(custody.verify_chain()['valid'])

    def test_suppression_detectee(self):
        import custody
        custody.record('x1', 'tester')
        mid = custody.record('x2', 'tester')
        custody.record('x3', 'tester')
        conn = sqlite3.connect(self.db_path)
        row = conn.execute('SELECT * FROM custody_chain WHERE seq=?', (mid['seq'],)).fetchone()
        try:
            conn.execute('DELETE FROM custody_chain WHERE seq=?', (mid['seq'],))
            conn.commit()
            result = custody.verify_chain()
            self.assertFalse(result['valid'])
        finally:
            conn.execute('INSERT INTO custody_chain VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', row)
            conn.commit()
            conn.close()
        self.assertTrue(custody.verify_chain()['valid'])

    def test_upload_scelle_l_acquisition(self):
        inv = self._create_investigation('Upload scelle')
        data = {'file': (io.BytesIO(b'4625 failed logon 198.51.100.4\n'), 'auth.log'),
                'investigation_id': inv}
        resp = self.client.post('/api/upload', data=data, content_type='multipart/form-data',
                                headers={'Authorization': f'Bearer {self.token}'})
        self.assertEqual(resp.status_code, 200)
        sha256 = resp.get_json()['hashes']['sha256']
        entries = self.client.get(f'/api/custody?investigation_id={inv}',
                                  headers=self._headers()).get_json()['items']
        acquired = [e for e in entries if e['action'] == 'evidence_acquired']
        self.assertEqual(len(acquired), 1)
        self.assertEqual(acquired[0]['payload_sha256'], sha256)

    def test_custody_requiert_auth(self):
        self.assertEqual(self.client.get('/api/custody').status_code, 401)
        self.assertEqual(self.client.get('/api/custody/verify').status_code, 401)

    # ------------------------------------------------------------------
    # Validation humaine (HITL)
    # ------------------------------------------------------------------

    def test_cycle_validation_humaine(self):
        import custody
        inv = self._create_investigation('HITL')
        action = custody.create_remediation(
            'SRV-AD-01', 'isoler SRV-AD-01 ; bloquer 185.220.101.44', 'Beacon C2 actif',
            investigation_id=inv, mitre='T1071')
        self.assertEqual(action['status'], 'WAITING_APPROVAL')
        self.assertTrue(action['id'].startswith('ACT-'))

        pending = self.client.get('/api/remediation?status=WAITING_APPROVAL',
                                  headers=self._headers()).get_json()['items']
        self.assertIn(action['id'], [p['id'] for p in pending])

        # Un viewer ne peut pas decider
        resp = self.client.post(f"/api/remediation/{action['id']}/decision",
                                json={'decision': 'approve'}, headers=self._headers(self.viewer_token))
        self.assertEqual(resp.status_code, 403)

        resp = self.client.post(f"/api/remediation/{action['id']}/decision",
                                json={'decision': 'approve', 'note': 'Valide par le CERT'},
                                headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertEqual(body['status'], 'APPROVED')
        self.assertEqual(body['decided_by'], 'dfir_tester')

        # Decision unique
        resp = self.client.post(f"/api/remediation/{action['id']}/decision",
                                json={'decision': 'reject'}, headers=self._headers())
        self.assertEqual(resp.status_code, 409)

        actions = [e['action'] for e in self.client.get(
            f'/api/custody?investigation_id={inv}', headers=self._headers()).get_json()['items']]
        self.assertIn('remediation_requested', actions)
        self.assertIn('remediation_approved', actions)
        self.assertTrue(custody.verify_chain()['valid'])

    def test_rejet_et_erreurs(self):
        import custody
        action = custody.create_remediation('PC-42', 'kill 4192', 'Processus injecte')
        resp = self.client.post(f"/api/remediation/{action['id']}/decision",
                                json={'decision': 'reject'}, headers=self._headers())
        self.assertEqual(resp.get_json()['status'], 'REJECTED')
        resp = self.client.post('/api/remediation/ACT-INCONNU/decision',
                                json={'decision': 'approve'}, headers=self._headers())
        self.assertEqual(resp.status_code, 404)
        resp = self.client.post(f"/api/remediation/{action['id']}/decision",
                                json={'decision': 'peut-etre'}, headers=self._headers())
        self.assertEqual(resp.status_code, 400)
        resp = self.client.get('/api/remediation?status=FOO', headers=self._headers())
        self.assertEqual(resp.status_code, 400)

    # ------------------------------------------------------------------
    # Coffre de preuves
    # ------------------------------------------------------------------

    def test_listing_coffre(self):
        resp = self.client.get('/api/evidence-vault', headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['exists'])
        paths = {f['path'] for f in data['files']}
        self.assertIn(os.path.join('host1', 'memdump.raw'), paths)
        self.assertIn('Security.log', paths)

    def test_import_coffre_sans_copie_et_traversee_refusee(self):
        inv = self._create_investigation('Coffre')
        resp = self.client.post('/api/evidence-vault/import', headers=self._headers(), json={
            'investigation_id': inv,
            'paths': ['Security.log', '../../etc/passwd', 'inexistant.raw']})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual([i['path'] for i in data['imported']], ['Security.log'])
        self.assertEqual(len(data['rejected']), 2)
        self.assertTrue(data['imported'][0]['custody_hash'])

        # Reference (pas de copie) vers le coffre
        import database
        with self.app.app_context():
            row = database.get_db().execute(
                'SELECT file_path FROM artifacts WHERE investigation_id=?', (inv,)).fetchone()
        self.assertEqual(os.path.realpath(row['file_path']),
                         os.path.realpath(os.path.join(self.vault, 'Security.log')))

        # Doublon refuse
        again = self.client.post('/api/evidence-vault/import', headers=self._headers(), json={
            'investigation_id': inv, 'paths': ['Security.log']}).get_json()
        self.assertEqual(again['imported'], [])

        # Le dossier de cas reference le coffre par lien symbolique
        import autonomous
        with self.app.app_context():
            artifacts = [dict(r) for r in database.get_db().execute(
                'SELECT * FROM artifacts WHERE investigation_id=?', (inv,)).fetchall()]
        case_dir, count, uses_vault = autonomous._prepare_case_dir(self.app, inv, artifacts)
        self.assertEqual(count, 1)
        self.assertTrue(uses_vault)
        self.assertTrue(os.path.islink(os.path.join(case_dir, 'Security.log')))

    def test_import_coffre_viewer_interdit(self):
        inv = self._create_investigation('Coffre viewer')
        from tests.auth_helpers import add_member
        add_member(self.client, self.token, inv, 'viewer_only')
        resp = self.client.post('/api/evidence-vault/import', headers=self._headers(self.viewer_token),
                                json={'investigation_id': inv, 'paths': ['Security.log']})
        self.assertEqual(resp.status_code, 403)

    # ------------------------------------------------------------------
    # Enregistrement des outils de l'enqueteur
    # ------------------------------------------------------------------

    def test_enregistreur_outils_et_hitl(self):
        import autonomous
        import custody
        inv = self._create_investigation('Enregistreur')
        case_dir = tempfile.mkdtemp()
        emitted = []
        with mock.patch.object(autonomous, 'emit_secure',
                               side_effect=lambda ev, data: emitted.append((ev, data))):
            on_tool = autonomous._make_tool_recorder('job-1', inv, case_dir, 'enqueteur-autonome (test)')
            on_tool(1, 'record_finding', {'case_dir': case_dir, 'title': 'Process hollowing svchost',
                                          'severity': 'critical', 'mitre': 'T1055.012'},
                    {'recorded': {'id': 1}})
            on_tool(2, 'propose_remediation', {'case_dir': case_dir, 'target_host': 'SRV-AD-01'},
                    {'proposed': {'id': 1, 'target_host': 'SRV-AD-01', 'command': 'isoler',
                                  'reason': 'beacon', 'mitre': 'T1071', 'severity': 'critical'}})
        events = [e for e, _ in emitted]
        # finding + propose_remediation + scellement de la demande HITL
        self.assertEqual(events.count('agent_step'), 3)
        hitl = next(d for e, d in emitted if e == 'hitl_required')
        self.assertNotIn('custody_entry', hitl)
        self.assertIn('hitl_required', events)
        step = next(d for e, d in emitted if e == 'agent_step')
        self.assertEqual(step['agent'], 'Orchestrateur Lead')
        self.assertEqual(step['severity'], 'critical')
        self.assertEqual(step['mitre'], 'T1055.012')
        self.assertEqual(len(step['entry_hash']), 64)
        self.assertEqual(step['job_id'], 'job-1')
        pending = custody.list_remediations(status='WAITING_APPROVAL', investigation_id=inv)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]['case_dir'], case_dir)
        shutil.rmtree(case_dir, ignore_errors=True)

    def test_tool_insight_sigma(self):
        import autonomous
        summary, mitre, severity = autonomous._tool_insight('sigma_scan', {}, {
            'alerts': [{'rule_title': 'LSASS access', 'level': 'high', 'technique': 'T1003.001'}]})
        self.assertIn('LSASS', summary)
        self.assertEqual(severity, 'high')
        self.assertEqual(mitre, 'T1003.001')
        summary, _m, severity = autonomous._tool_insight('parse_evtx', {}, {'error': 'boom'})
        self.assertEqual(severity, 'low')
        self.assertIn('boom', summary)

    # ------------------------------------------------------------------
    # Statut de la console
    # ------------------------------------------------------------------

    def test_statut_soc(self):
        resp = self.client.get('/api/console/status', headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual({a['id'] for a in data['agents']}, {'lead', 'triage', 'disk', 'memory', 'disk_image', 'intel', 'quality'})
        self.assertIn('volatility', data['tools'])
        self.assertIn('hayabusa', data['tools'])
        self.assertEqual(data['vault']['dir'], self.vault)
        self.assertIn('entries', data['custody'])

    def test_statut_autonome_expose_le_fournisseur(self):
        with mock.patch.dict(os.environ, {'PHOENIX_LLM_PROVIDER': 'ollama'}):
            data = self.client.get('/api/autonomous/status', headers=self._headers()).get_json()
        self.assertEqual(data['llm_provider'], 'ollama')
        self.assertTrue(data['copilot_configured'])


if __name__ == '__main__':
    unittest.main()


class WebSocketAuthTestCase(unittest.TestCase):
    """Les evenements temps reel ne doivent jamais atteindre un client anonyme."""

    @classmethod
    def setUpClass(cls):
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')
        import database
        database.DB_PATH = cls.db_path
        database.init_db()
        from app import app
        app.config['TESTING'] = True
        cls.app = app
        cls.client = app.test_client()
        from tests.auth_helpers import bootstrap_admin, create_user
        cls.admin_token = bootstrap_admin(cls.client, 'admin_ws', 'Admin-Ws-Strong-2026!')['token']
        login = create_user(cls.client, cls.admin_token, 'analyste_ws', 'Analyste-Ws-2026!')
        cls.token = login['token']
        cls.user_id = login['user']['id']
        import auth
        cls.refresh = auth.create_token(cls.user_id, 'analyste_ws', 'analyst', token_type='refresh')
        resp = cls.client.post('/api/investigations', json={'name': 'Cas WS'},
                               headers={'Authorization': f'Bearer {cls.token}'})
        cls.inv_id = resp.get_json()['id']

    @classmethod
    def tearDownClass(cls):
        os.close(cls.db_fd)
        os.unlink(cls.db_path)

    def _client(self, **kwargs):
        from extensions import socketio
        return socketio.test_client(self.app, **kwargs)

    def test_connexion_anonyme_refusee(self):
        client = self._client()
        self.assertFalse(client.is_connected())

    def test_jeton_invalide_ou_refresh_refuse(self):
        self.assertFalse(self._client(auth={'token': 'faux.jeton.x'}).is_connected())
        # Un refresh token ne vaut pas un access token
        self.assertFalse(self._client(auth={'token': self.refresh}).is_connected())

    def test_client_authentifie_recoit_les_evenements(self):
        from extensions import emit_secure
        client = self._client(auth={'token': self.token})
        self.assertTrue(client.is_connected())
        client.get_received()  # vider 'connected'
        emit_secure('agent_step', {'seq': 1, 'summary': 'secret', 'investigation_id': self.inv_id})
        received = client.get_received()
        self.assertEqual([r['name'] for r in received], ['agent_step'])
        # Evenement sans enquete : administrateurs uniquement
        emit_secure('agent_step', {'seq': 2, 'summary': 'global'})
        self.assertEqual(client.get_received(), [])
        client.disconnect()

    def test_jeton_en_query_string_refuse(self):
        # Le jeton en query string (journalise par les proxys) n'est plus accepte
        client = self._client(query_string=f'token={self.token}')
        self.assertFalse(client.is_connected())
