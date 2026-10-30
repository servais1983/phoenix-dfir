#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de regression securite : traversee de chemin, IDOR / controle d'acces
par enquete, roles, inscription, rate limiting, verrouillage, revocation des
sessions, cookie de refresh, injection CSV, isolation WebSocket."""

import io
import os
import tempfile
import threading
import time
import unittest
from unittest import mock


os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['PHOENIX_DEBUG'] = 'false'
os.environ.pop('REDIS_URL', None)

from tests.auth_helpers import add_member, bootstrap_admin, create_user  # noqa: E402

ADMIN_PW = 'Admin-Sec-Strong-2026!'
ALICE_PW = 'Alice-Sec-Strong-2026!'
BOB_PW = 'Bob-Sec-Strong-2026!x'
VIC_PW = 'Victor-Sec-Strong-2026!'


def _h(token):
    return {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}


class _Base(unittest.TestCase):
    """Base vide + admin, deux analystes (alice, bob) et un viewer (victor)."""

    @classmethod
    def setUpClass(cls):
        import database
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')
        database.close_db()
        database.DB_PATH = cls.db_path
        database.init_db()

        from app import app
        app.config['TESTING'] = True
        cls.app = app
        cls.client = app.test_client()
        cls.admin = bootstrap_admin(cls.client, 'sec_admin', ADMIN_PW)['token']
        cls.alice_login = create_user(cls.client, cls.admin, 'alice', ALICE_PW, role='analyst')
        cls.alice = cls.alice_login['token']
        cls.bob_login = create_user(cls.client, cls.admin, 'bob', BOB_PW, role='analyst')
        cls.bob = cls.bob_login['token']
        cls.victor_login = create_user(cls.client, cls.admin, 'victor', VIC_PW, role='viewer')
        cls.victor = cls.victor_login['token']

    @classmethod
    def tearDownClass(cls):
        import database
        database.close_db()
        os.close(cls.db_fd)
        os.unlink(cls.db_path)

    def _inv(self, token, name='Cas'):
        resp = self.client.post('/api/investigations', json={'name': name}, headers=_h(token))
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['id']

    def _upload(self, token, inv_id=None, content=b'Failed password from 203.0.113.9\n', name='auth.log'):
        data = {'file': (io.BytesIO(content), name)}
        if inv_id:
            data['investigation_id'] = inv_id
        return self.client.post('/api/upload', data=data, content_type='multipart/form-data',
                                headers={'Authorization': f'Bearer {token}'})


# ============================================================================
# 1. Traversee de chemin sur /api/analyze
# ============================================================================

class AnalyzeTraversalTestCase(_Base):

    def test_traversee_refusee(self):
        for name in ('../.secret_key', '../auth.py', '/etc/passwd', '..', '.', '',
                     'sub/../../auth.py', '..\\auth.py', '.hidden'):
            resp = self.client.post('/api/analyze', json={'filename': name}, headers=_h(self.alice))
            self.assertIn(resp.status_code, (400, 404), name)
            self.assertNotIn('analysis_id', resp.get_json() or {}, name)

    def test_lien_symbolique_sortant_refuse(self):
        upload_dir = self.app.config['UPLOAD_FOLDER']
        link = os.path.join(upload_dir, 'evil_link.log')
        target = os.path.join(os.path.dirname(upload_dir), 'auth.py')
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest('symlink indisponible')
        try:
            resp = self.client.post('/api/analyze', json={'filename': 'evil_link.log'},
                                    headers=_h(self.alice))
            self.assertEqual(resp.status_code, 404)
        finally:
            os.unlink(link)

    def test_artifact_id_et_controle_acces(self):
        inv = self._inv(self.alice, 'Analyse')
        up = self._upload(self.alice, inv).get_json()
        self.assertTrue(up['artifact_id'])
        with mock.patch('routes.analysis.executor') as ex:
            resp = self.client.post('/api/analyze', json={'artifact_id': up['artifact_id']},
                                    headers=_h(self.alice))
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(ex.submit.called)
            analysis_id = resp.get_json()['analysis_id']
            # Bob (non membre) : ni l'artefact, ni le fichier par nom, ni le suivi
            resp = self.client.post('/api/analyze', json={'artifact_id': up['artifact_id']},
                                    headers=_h(self.bob))
            self.assertEqual(resp.status_code, 404)
            resp = self.client.post('/api/analyze', json={'filename': up['filename']},
                                    headers=_h(self.bob))
            self.assertEqual(resp.status_code, 404)
            self.assertEqual(self.client.get(f'/api/analysis/{analysis_id}/status',
                                             headers=_h(self.bob)).status_code, 404)
            self.assertEqual(self.client.get(f'/api/analysis/{analysis_id}/status',
                                             headers=_h(self.alice)).status_code, 200)
            # Retro-compat : nom stocke valide dans le dossier d'uploads
            resp = self.client.post('/api/analyze', json={'filename': up['filename']},
                                    headers=_h(self.alice))
            self.assertEqual(resp.status_code, 200)
            # Viewer : lecture seule
            resp = self.client.post('/api/analyze', json={'artifact_id': up['artifact_id']},
                                    headers=_h(self.victor))
            self.assertEqual(resp.status_code, 403)

    def test_upload_noms_uniques_sans_chemin_serveur(self):
        a = self._upload(self.alice).get_json()
        b = self._upload(self.alice).get_json()
        self.assertNotIn('filepath', a)
        self.assertNotEqual(a['filename'], b['filename'])
        self.assertEqual(a['hashes']['sha256'], b['hashes']['sha256'])
        self.assertNotIn(self.app.config['UPLOAD_FOLDER'], str(a))

    def test_outil_hash_par_blocs(self):
        import hashlib
        content = os.urandom(3 * 1024 * 1024 + 17)
        resp = self.client.post('/api/tools/hash', data={'file': (io.BytesIO(content), 'x.bin')},
                                content_type='multipart/form-data',
                                headers={'Authorization': f'Bearer {self.victor}'})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['size'], len(content))
        self.assertEqual(data['hashes']['sha256'], hashlib.sha256(content).hexdigest())


# ============================================================================
# 2. IDOR et roles
# ============================================================================

class AccessControlTestCase(_Base):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        resp = cls.client.post('/api/investigations', json={'name': 'Secret Alice'}, headers=_h(cls.alice))
        cls.inv = resp.get_json()['id']
        resp = cls.client.post(f'/api/investigations/{cls.inv}/iocs',
                               json={'type': 'ip', 'value': '198.51.100.77'}, headers=_h(cls.alice))
        cls.ioc_id = resp.get_json()['id']
        cls.client.post(f'/api/investigations/{cls.inv}/timeline',
                        json={'timestamp': '2026-01-01T00:00:00Z', 'event': 'x'}, headers=_h(cls.alice))
        resp = cls.client.post('/api/reports/generate', json={'investigation_id': cls.inv},
                               headers=_h(cls.alice))
        cls.report_id = resp.get_json()['report_id']

    def test_lecture_croisee_404(self):
        inv = self.inv
        for url in (f'/api/investigations/{inv}', f'/api/investigations/{inv}/iocs',
                    f'/api/investigations/{inv}/timeline', f'/api/investigations/{inv}/artifacts',
                    f'/api/investigations/{inv}/export/stix', f'/api/investigations/{inv}/mitre',
                    f'/api/investigations/{inv}/iocs/export', f'/api/investigations/{inv}/members',
                    f'/api/reports/{self.report_id}/download',
                    f'/api/custody?investigation_id={inv}', f'/api/remediation?investigation_id={inv}'):
            resp = self.client.get(url, headers=_h(self.bob))
            self.assertEqual(resp.status_code, 404, url)
            # Meme reponse qu'une enquete inexistante (anti-enumeration)
        self.assertEqual(self.client.get('/api/investigations/00000000-0000-0000-0000-000000000000',
                                         headers=_h(self.bob)).status_code, 404)

    def test_ecriture_croisee_404(self):
        inv = self.inv
        calls = [
            ('put', f'/api/investigations/{inv}', {'name': 'pwn'}),
            ('put', f'/api/investigations/{inv}/status', {'status': 'closed'}),
            ('delete', f'/api/investigations/{inv}', None),
            ('post', f'/api/investigations/{inv}/iocs', {'type': 'ip', 'value': '1.2.3.4'}),
            ('delete', f'/api/investigations/{inv}/iocs/{self.ioc_id}', None),
            ('post', f'/api/investigations/{inv}/iocs/bulk', {'text': '9.9.9.9'}),
            ('post', f'/api/investigations/{inv}/timeline', {'timestamp': 't', 'event': 'e'}),
            ('post', '/api/reports/generate', {'investigation_id': inv}),
            ('post', '/api/iocs/enrich', {'type': 'ip', 'value': '1.1.1.1', 'ioc_id': self.ioc_id}),
            ('post', '/api/autonomous/investigate', {'investigation_id': inv}),
            ('post', f'/api/investigations/{inv}/members', {'username': 'bob'}),
        ]
        for method, url, body in calls:
            resp = getattr(self.client, method)(url, json=body, headers=_h(self.bob))
            self.assertEqual(resp.status_code, 404, (method, url, resp.get_json()))
        # Upload vers l'enquete d'autrui
        self.assertEqual(self._upload(self.bob, inv).status_code, 404)
        # L'enquete est intacte
        data = self.client.get(f'/api/investigations/{inv}', headers=_h(self.alice)).get_json()
        self.assertEqual(data['name'], 'Secret Alice')
        self.assertEqual(len(data['iocs']), 1)

    def test_listes_filtrees(self):
        bob_inv = self._inv(self.bob, 'Cas Bob')
        items = self.client.get('/api/investigations', headers=_h(self.bob)).get_json()['items']
        ids = {i['id'] for i in items}
        self.assertIn(bob_inv, ids)
        self.assertNotIn(self.inv, ids)
        admin_ids = {i['id'] for i in self.client.get('/api/investigations?per_page=200',
                                                      headers=_h(self.admin)).get_json()['items']}
        self.assertTrue({self.inv, bob_inv} <= admin_ids)
        stats = self.client.get('/api/stats', headers=_h(self.bob)).get_json()
        self.assertEqual(stats['total_iocs'], 0)
        self.assertIsNone(stats['total_users'])
        custody = self.client.get('/api/custody', headers=_h(self.bob)).get_json()['items']
        self.assertTrue(all(e['investigation_id'] == bob_inv for e in custody))

    def test_rapport_et_job_autonome(self):
        self.assertEqual(self.client.get(f'/api/reports/{self.report_id}/download',
                                         headers=_h(self.alice)).status_code, 200)
        import autonomous
        autonomous.autonomous_jobs['job-sec-1'] = {
            'job_id': 'job-sec-1', 'investigation_id': self.inv, 'status': 'completed',
            'messages': [], 'user_id': self.alice_login['user']['id']}
        try:
            self.assertEqual(self.client.get('/api/autonomous/jobs/job-sec-1',
                                             headers=_h(self.bob)).status_code, 404)
            self.assertEqual(self.client.get('/api/autonomous/jobs/job-sec-1',
                                             headers=_h(self.alice)).status_code, 200)
            self.assertEqual(self.client.get('/api/autonomous/jobs/job-sec-1',
                                             headers=_h(self.admin)).status_code, 200)
        finally:
            autonomous.autonomous_jobs.pop('job-sec-1', None)

    def test_quota_jobs_autonomes(self):
        import autonomous
        inv = self._inv(self.alice, 'Quota')
        self._upload(self.alice, inv)
        alice_id = self.alice_login['user']['id']
        for i in range(2):
            autonomous.autonomous_jobs[f'job-quota-{i}'] = {
                'job_id': f'job-quota-{i}', 'investigation_id': inv, 'status': 'running',
                'messages': [], 'user_id': alice_id}
        try:
            with mock.patch.object(autonomous, 'copilot_configured', return_value=True), \
                    mock.patch.object(autonomous, 'start_job', return_value='job-x') as start, \
                    mock.patch.dict(os.environ, {'PHOENIX_MAX_JOBS_PER_USER': '2'}):
                resp = self.client.post('/api/autonomous/investigate', json={'investigation_id': inv},
                                        headers=_h(self.alice))
                self.assertEqual(resp.status_code, 429)
                self.assertFalse(start.called)
        finally:
            for i in range(2):
                autonomous.autonomous_jobs.pop(f'job-quota-{i}', None)

    def test_viewer_lecture_seule(self):
        inv = self._inv(self.alice, 'Partage viewer')
        add_member(self.client, self.alice, inv, 'victor')
        self.assertEqual(self.client.get(f'/api/investigations/{inv}', headers=_h(self.victor)).status_code, 200)
        self.assertEqual(self.client.get(f'/api/investigations/{inv}/iocs', headers=_h(self.victor)).status_code, 200)
        for method, url, body in (
                ('post', f'/api/investigations/{inv}/iocs', {'type': 'ip', 'value': '5.5.5.5'}),
                ('put', f'/api/investigations/{inv}', {'name': 'x'}),
                ('post', f'/api/investigations/{inv}/timeline', {'timestamp': 't', 'event': 'e'}),
                ('delete', f'/api/investigations/{inv}', None),
                ('post', '/api/investigations', {'name': 'viewer'}),
                ('post', '/api/reports/generate', {'investigation_id': inv}),
                ('post', '/api/integrations/misp/push', {'investigation_id': inv}),
                ('post', '/api/integrations/misp/pull', {'investigation_id': inv}),
        ):
            resp = getattr(self.client, method)(url, json=body, headers=_h(self.victor))
            self.assertEqual(resp.status_code, 403, (method, url))
        self.assertEqual(self._upload(self.victor, inv).status_code, 403)

    def test_membres_et_suppression(self):
        inv = self._inv(self.alice, 'Equipe')
        add_member(self.client, self.alice, inv, 'bob')
        # Bob membre : lecture et ecriture
        self.assertEqual(self.client.get(f'/api/investigations/{inv}', headers=_h(self.bob)).status_code, 200)
        self.assertEqual(self.client.post(f'/api/investigations/{inv}/iocs', json={'type': 'ip', 'value': '7.7.7.7'},
                                          headers=_h(self.bob)).status_code, 201)
        # ... mais ni gestion des membres ni suppression (createur ou admin)
        self.assertEqual(self.client.post(f'/api/investigations/{inv}/members', json={'username': 'victor'},
                                          headers=_h(self.bob)).status_code, 403)
        self.assertEqual(self.client.delete(f'/api/investigations/{inv}', headers=_h(self.bob)).status_code, 403)
        # Le createur ne peut pas etre retire
        alice_id = self.alice_login['user']['id']
        self.assertEqual(self.client.delete(f'/api/investigations/{inv}/members/{alice_id}',
                                            headers=_h(self.alice)).status_code, 400)
        # Retrait de bob : il perd l'acces
        bob_id = self.bob_login['user']['id']
        self.assertEqual(self.client.delete(f'/api/investigations/{inv}/members/{bob_id}',
                                            headers=_h(self.alice)).status_code, 200)
        self.assertEqual(self.client.get(f'/api/investigations/{inv}', headers=_h(self.bob)).status_code, 404)
        self.assertEqual(self.client.delete(f'/api/investigations/{inv}', headers=_h(self.alice)).status_code, 200)

    def test_remediation_decision_membre(self):
        import custody
        inv = self._inv(self.alice, 'HITL secu')
        action = custody.create_remediation('SRV-1', 'isoler', 'beacon', investigation_id=inv)
        pending = self.client.get('/api/remediation', headers=_h(self.bob)).get_json()['items']
        self.assertNotIn(action['id'], [p['id'] for p in pending])
        resp = self.client.post(f"/api/remediation/{action['id']}/decision", json={'decision': 'approve'},
                                headers=_h(self.bob))
        self.assertEqual(resp.status_code, 404)
        resp = self.client.post(f"/api/remediation/{action['id']}/decision", json={'decision': 'approve'},
                                headers=_h(self.alice))
        self.assertEqual(resp.status_code, 200)

    def test_csv_neutralise_les_formules(self):
        inv = self._inv(self.alice, 'CSV')
        for value in ('=HYPERLINK("http://evil")', '+cmd|calc', '-2+3', '@SUM(A1)'):
            self.client.post(f'/api/investigations/{inv}/iocs', json={'type': 'filename', 'value': value,
                                                                      'source': '=1+1'},
                             headers=_h(self.alice))
        body = self.client.get(f'/api/investigations/{inv}/iocs/export',
                               headers=_h(self.alice)).get_data(as_text=True)
        import csv
        rows = list(csv.reader(io.StringIO(body)))[1:]
        self.assertEqual(len(rows), 4)
        for row in rows:
            self.assertTrue(row[1].startswith("'"), row)
            self.assertEqual(row[2], "'=1+1")
        from helpers import csv_safe
        self.assertEqual(csv_safe('\tx'), "'\tx")
        self.assertEqual(csv_safe('\rx'), "'\rx")
        self.assertEqual(csv_safe('normal'), 'normal')

    def test_secrets_integrations_masques(self):
        self.client.put('/api/integrations/virustotal', json={'config': {'api_key': 'vt-secret-key-ABCD'},
                                                              'enabled': True}, headers=_h(self.admin))
        admin_cfg = self.client.get('/api/integrations/virustotal', headers=_h(self.admin)).get_json()['config']
        self.assertEqual(admin_cfg['api_key'], '***ABCD')
        user_cfg = self.client.get('/api/integrations/virustotal', headers=_h(self.alice)).get_json()['config']
        self.assertEqual(user_cfg['api_key'], '********')
        self.assertNotIn('ABCD', user_cfg['api_key'])
        self.assertEqual(self.client.put('/api/integrations/virustotal', json={'enabled': False},
                                         headers=_h(self.alice)).status_code, 403)

    def test_erreurs_generiques(self):
        with mock.patch('routes.stats.access.access_filter_sql', side_effect=RuntimeError('chemin /secret')):
            resp = self.client.get('/api/stats', headers=_h(self.alice))
        self.assertEqual(resp.status_code, 500)
        body = resp.get_json()
        self.assertNotIn('secret', body['error'])
        self.assertIn('request_id', body)


# ============================================================================
# 3. Inscription, admin initial, administration des utilisateurs
# ============================================================================

class RegistrationTestCase(unittest.TestCase):

    def setUp(self):
        import database
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        database.close_db()
        database.DB_PATH = self.db_path
        database.init_db()
        from app import app
        app.config['TESTING'] = True
        app.config.pop('PHOENIX_ALLOW_REGISTRATION', None)
        self.app = app
        self.client = app.test_client()

    def tearDown(self):
        import database
        database.close_db()
        self.app.config.pop('PHOENIX_ALLOW_REGISTRATION', None)
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def _register(self, username, setup_token=None, client=None):
        body = {'username': username, 'password': 'Reg-Strong-Pass-2026!'}
        if setup_token is not None:
            body['setup_token'] = setup_token
        return (client or self.client).post('/api/auth/register', json=body)

    def test_setup_token_requis(self):
        import auth
        status = self.client.get('/api/auth/setup-status').get_json()
        self.assertEqual(status, {'needs_setup': True, 'registration_open': False})
        self.assertEqual(self._register('first').status_code, 403)
        self.assertEqual(self._register('first', 'mauvais-jeton').status_code, 403)
        resp = self._register('first', auth.get_setup_token())
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.get_json()['user']['role'], 'admin')
        self.assertFalse(self.client.get('/api/auth/setup-status').get_json()['needs_setup'])

    def test_inscription_fermee_par_defaut(self):
        bootstrap_admin(self.client, 'root_admin', 'Root-Admin-Strong-2026!')
        resp = self._register('intrus')
        self.assertEqual(resp.status_code, 403)
        self.app.config['PHOENIX_ALLOW_REGISTRATION'] = True
        resp = self._register('viewer1')
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.get_json()['user']['role'], 'viewer')

    def test_premier_admin_atomique(self):
        import auth
        token = auth.get_setup_token()
        results = []
        barrier = threading.Barrier(4)

        def worker(i):
            client = self.app.test_client()
            barrier.wait()
            results.append(self._register(f'concurrent{i}', token, client=client).status_code)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(results.count(201), 1, results)
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        admins = conn.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0]
        conn.close()
        self.assertEqual(admins, 1)

    def test_bootstrap_env(self):
        import auth
        with mock.patch.dict(os.environ, {'PHOENIX_ADMIN_USERNAME': 'envadmin',
                                          'PHOENIX_ADMIN_PASSWORD': 'Env-Admin-Strong-2026!'}):
            with self.app.app_context():
                auth.bootstrap_users()
        resp = self.client.post('/api/auth/login', json={'username': 'envadmin',
                                                         'password': 'Env-Admin-Strong-2026!'})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['user']['role'], 'admin')

    def test_administration_utilisateurs(self):
        admin = bootstrap_admin(self.client, 'boss', 'Boss-Admin-Strong-2026!')['token']
        analyst = create_user(self.client, admin, 'ana', 'Ana-Strong-Pass-2026!', role='analyst')
        uid = analyst['user']['id']
        # Non-admin : 403
        self.assertEqual(self.client.post('/api/auth/users', json={'username': 'x', 'password': 'Xx-Strong-2026!!',
                                                                   'role': 'admin'},
                                          headers=_h(analyst['token'])).status_code, 403)
        # Changement de role : ancien jeton revoque (token_version)
        resp = self.client.put(f'/api/auth/users/{uid}/role', json={'role': 'viewer'}, headers=_h(admin))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['role'], 'viewer')
        self.assertEqual(self.client.get('/api/auth/me', headers=_h(analyst['token'])).status_code, 401)
        # Dernier admin protege
        me = self.client.get('/api/auth/me', headers=_h(admin)).get_json()
        self.assertEqual(self.client.put(f"/api/auth/users/{me['id']}/role", json={'role': 'analyst'},
                                         headers=_h(admin)).status_code, 409)
        # Desactivation : connexion impossible
        self.assertEqual(self.client.delete(f'/api/auth/users/{uid}', headers=_h(admin)).status_code, 200)
        self.assertEqual(self.client.post('/api/auth/login', json={'username': 'ana',
                                                                   'password': 'Ana-Strong-Pass-2026!'}).status_code, 401)
        audit = self.client.get('/api/audit?per_page=200', headers=_h(admin)).get_json()['items']
        actions = {a['action'] for a in audit}
        self.assertTrue({'admin_create_user', 'admin_set_role', 'admin_disable_user'} <= actions)


# ============================================================================
# 4. Rate limiting, verrouillage, sessions
# ============================================================================

class SessionSecurityTestCase(_Base):

    def test_xff_ne_contourne_pas_le_rate_limit(self):
        self.app.config['TESTING'] = False
        try:
            codes = []
            for i in range(12):
                resp = self.client.post('/api/auth/login', json={'username': f'spoof{i}', 'password': 'x'},
                                        headers={'X-Forwarded-For': f'10.0.{i}.1'},
                                        environ_base={'REMOTE_ADDR': '192.0.2.250'})
                codes.append(resp.status_code)
        finally:
            self.app.config['TESTING'] = True
        self.assertIn(429, codes)
        self.assertEqual(codes[-1], 429)

    def test_client_ip_ignore_xff(self):
        from middleware import _client_ip
        with self.app.test_request_context('/', headers={'X-Forwarded-For': '6.6.6.6'},
                                           environ_base={'REMOTE_ADDR': '192.0.2.10'}):
            self.assertEqual(_client_ip(), '192.0.2.10')

    def test_verrouillage_par_utilisateur(self):
        create_user(self.client, self.admin, 'locky', 'Locky-Strong-Pass-2026!')
        for i in range(10):
            resp = self.client.post('/api/auth/login', json={'username': 'locky', 'password': f'faux{i}'})
            self.assertEqual(resp.status_code, 401)
        resp = self.client.post('/api/auth/login', json={'username': 'locky', 'password': 'Locky-Strong-Pass-2026!'})
        self.assertEqual(resp.status_code, 429)
        self.assertNotIn('locky', resp.get_json()['error'])
        # Un autre compte n'est pas affecte
        self.assertEqual(self.client.post('/api/auth/login', json={'username': 'alice', 'password': ALICE_PW}).status_code, 200)

    def test_changement_mot_de_passe_revoque_les_sessions(self):
        login = create_user(self.client, self.admin, 'pwchange', 'Pw-Change-Strong-2026!')
        other = self.client.post('/api/auth/login', json={'username': 'pwchange', 'password': 'Pw-Change-Strong-2026!'})
        other_access = other.get_json()['token']
        refresh = next(h.split(';', 1)[0].split('=', 1)[1] for h in other.headers.getlist('Set-Cookie')
                       if h.startswith('phoenix_refresh='))
        resp = self.client.put('/api/auth/password', json={'current_password': 'Pw-Change-Strong-2026!',
                                                           'new_password': 'Pw-Change-Strong-2027!'},
                               headers=_h(login['token']))
        self.assertEqual(resp.status_code, 200)
        # Toutes les sessions : access tokens et refresh token
        self.assertEqual(self.client.get('/api/auth/me', headers=_h(other_access)).status_code, 401)
        client = self.app.test_client()
        client.set_cookie('phoenix_refresh', refresh, path='/api/auth')
        self.assertEqual(client.post('/api/auth/refresh').status_code, 401)
        self.assertEqual(self.client.post('/api/auth/refresh', json={'refresh_token': refresh}).status_code, 401)

    def test_refresh_par_cookie(self):
        client = self.app.test_client()
        login = client.post('/api/auth/login', json={'username': 'alice', 'password': ALICE_PW})
        cookie = next(h for h in login.headers.getlist('Set-Cookie') if h.startswith('phoenix_refresh='))
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)
        self.assertIn('Path=/api/auth', cookie)
        self.assertNotIn('refresh_token', login.get_json())
        resp = client.post('/api/auth/refresh')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['user']['username'], 'alice')
        with mock.patch.dict(os.environ, {'PHOENIX_COOKIE_SECURE': 'true'}):
            login = client.post('/api/auth/login', json={'username': 'alice', 'password': ALICE_PW})
        cookie = next(h for h in login.headers.getlist('Set-Cookie') if h.startswith('phoenix_refresh='))
        self.assertIn('Secure', cookie)

    def test_metrics_token(self):
        with mock.patch.dict(os.environ, {'PHOENIX_METRICS_TOKEN': 'scrape-secret'}):
            self.assertEqual(self.client.get('/metrics').status_code, 401)
            self.assertEqual(self.client.get('/metrics', headers={'Authorization': 'Bearer nope'}).status_code, 401)
            ok = self.client.get('/metrics', headers={'Authorization': 'Bearer scrape-secret'})
            self.assertIn(ok.status_code, (200, 503))
            self.assertEqual(self.client.get('/livez').status_code, 200)

    def test_secret_obligatoire_en_production(self):
        import auth
        with mock.patch.dict(os.environ, {'PHOENIX_ENV': 'production', 'PHOENIX_SECRET_KEY': ''}):
            with self.assertRaises(RuntimeError):
                auth._load_secret_key()


# ============================================================================
# 5. Isolation WebSocket par enquete
# ============================================================================

class SocketIsolationTestCase(_Base):

    def _sock(self, token):
        from extensions import socketio
        client = socketio.test_client(self.app, auth={'token': token})
        self.assertTrue(client.is_connected())
        client.get_received()
        return client

    def test_salles_par_enquete(self):
        from extensions import emit_secure
        inv = self._inv(self.alice, 'WS isolation')
        alice_ws, bob_ws, admin_ws = self._sock(self.alice), self._sock(self.bob), self._sock(self.admin)
        try:
            emit_secure('agent_step', {'investigation_id': inv, 'summary': 'secret'})
            self.assertEqual([r['name'] for r in alice_ws.get_received()], ['agent_step'])
            self.assertEqual(bob_ws.get_received(), [])
            self.assertEqual([r['name'] for r in admin_ws.get_received()], ['agent_step'])

            # join_investigation sans acces : refuse
            bob_ws.emit('join_investigation', {'investigation_id': inv})
            self.assertEqual([r['name'] for r in bob_ws.get_received()], ['join_investigation_error'])
            emit_secure('agent_step', {'investigation_id': inv})
            self.assertEqual(bob_ws.get_received(), [])

            # Ajout comme membre : la salle est rejointe immediatement
            add_member(self.client, self.alice, inv, 'bob')
            emit_secure('agent_step', {'investigation_id': inv})
            self.assertEqual([r['name'] for r in bob_ws.get_received()], ['agent_step'])
        finally:
            for c in (alice_ws, bob_ws, admin_ws):
                if c.is_connected():
                    c.disconnect()

    def test_nouvelle_enquete_rejointe_par_le_createur(self):
        from extensions import emit_secure
        bob_ws = self._sock(self.bob)
        try:
            inv = self._inv(self.bob, 'Apres connexion')
            emit_secure('notification', {'investigation_id': inv, 'message': 'x'})
            self.assertEqual([r['name'] for r in bob_ws.get_received()], ['notification'])
        finally:
            bob_ws.disconnect()

    def test_jeton_expire_deconnecte(self):
        import auth
        from extensions import emit_secure
        state = auth.get_user_state(self.bob_login['user']['id'])
        short = auth.create_token(state['id'], 'bob', 'analyst', expiry=1,
                                  token_version=state['token_version'])
        inv = self._inv(self.bob, 'Expiration')
        ws = self._sock(short)
        time.sleep(1.2)
        emit_secure('agent_step', {'investigation_id': inv})
        self.assertFalse(ws.is_connected())

    def test_jeton_revoque_deconnecte(self):
        import sockets
        from extensions import emit_secure
        login = create_user(self.client, self.admin, 'wsrevoke', 'Ws-Revoke-Strong-2026!')
        ws = self._sock(login['token'])
        inv = self._inv(login['token'], 'Revocation')
        self.client.put('/api/auth/password', json={'current_password': 'Ws-Revoke-Strong-2026!',
                                                    'new_password': 'Ws-Revoke-Strong-2027!'},
                        headers=_h(login['token']))
        sockets.prune_sessions(force_full=True)
        emit_secure('agent_step', {'investigation_id': inv})
        self.assertFalse(ws.is_connected())


if __name__ == '__main__':
    unittest.main(verbosity=2)


def test_origine_websocket_lue_depuis_environ_sans_contexte_flask():
    """Le handshake WebSocket (eventlet) n'a pas de contexte de requete Flask :
    la meme origine doit etre reconnue via l'environ WSGI, une origine
    etrangere refusee."""
    from extensions import _socketio_origin_allowed
    environ = {'HTTP_HOST': 'phoenix.local:5000', 'wsgi.url_scheme': 'http'}
    assert _socketio_origin_allowed('http://phoenix.local:5000', environ)
    assert _socketio_origin_allowed('https://phoenix.local:5000', environ)
    assert not _socketio_origin_allowed('https://evil.example', environ)
    assert not _socketio_origin_allowed('https://evil.example')
