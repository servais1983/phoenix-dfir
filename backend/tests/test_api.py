"""
Phoenix DFIR - Tests API
Tests unitaires et d'integration pour l'API REST
"""

import os
import sys
import json
import tempfile
import unittest

# Ajouter le repertoire backend au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Configurer l'environnement de test
os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['PHOENIX_DEBUG'] = 'false'


class PhoenixAPITestCase(unittest.TestCase):
    """Tests pour l'API Phoenix DFIR"""

    @classmethod
    def setUpClass(cls):
        """Configuration initiale des tests"""
        # Utiliser une base de donnees temporaire
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')

        import database
        database.DB_PATH = cls.db_path
        database.init_db()

        from app import app, socketio
        app.config['TESTING'] = True
        cls.app = app
        cls.client = app.test_client()

        # Creer un utilisateur de test
        cls.test_user = cls._register_user('testadmin', 'password123', 'Admin Test')

    @classmethod
    def _register_user(cls, username, password, display_name):
        """Helper: enregistrer un utilisateur"""
        resp = cls.client.post('/api/auth/register', json={
            'username': username,
            'password': password,
            'display_name': display_name
        })
        data = resp.get_json()
        return data

    def _auth_headers(self, token=None):
        """Helper: headers avec token d'authentification"""
        t = token or self.test_user.get('token', '')
        return {'Authorization': f'Bearer {t}', 'Content-Type': 'application/json'}

    # ======================================================================
    # Tests Health
    # ======================================================================

    def test_01_health_check(self):
        """GET /api/health retourne le statut du systeme"""
        resp = self.client.get('/api/health')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'healthy')

    # ======================================================================
    # Tests Authentication
    # ======================================================================

    def test_02_register_success(self):
        """POST /api/auth/register cree un nouvel utilisateur"""
        resp = self.client.post('/api/auth/register', json={
            'username': 'analyst1',
            'password': 'securepass',
            'display_name': 'Analyste 1'
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn('token', data)
        self.assertEqual(data['user']['username'], 'analyst1')

    def test_03_register_duplicate(self):
        """POST /api/auth/register echoue si utilisateur existe"""
        resp = self.client.post('/api/auth/register', json={
            'username': 'testadmin',
            'password': 'password123'
        })
        self.assertEqual(resp.status_code, 409)

    def test_04_register_short_password(self):
        """POST /api/auth/register echoue si mot de passe trop court"""
        resp = self.client.post('/api/auth/register', json={
            'username': 'newuser',
            'password': '123'
        })
        self.assertEqual(resp.status_code, 400)

    def test_05_login_success(self):
        """POST /api/auth/login authentifie un utilisateur"""
        resp = self.client.post('/api/auth/login', json={
            'username': 'testadmin',
            'password': 'password123'
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('token', data)

    def test_06_login_wrong_password(self):
        """POST /api/auth/login echoue avec mauvais mot de passe"""
        resp = self.client.post('/api/auth/login', json={
            'username': 'testadmin',
            'password': 'wrongpassword'
        })
        self.assertEqual(resp.status_code, 401)

    def test_07_auth_required(self):
        """Les endpoints proteges necessitent un token"""
        resp = self.client.get('/api/investigations')
        self.assertEqual(resp.status_code, 401)

    def test_08_auth_me(self):
        """GET /api/auth/me retourne l'utilisateur connecte"""
        resp = self.client.get('/api/auth/me', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['username'], 'testadmin')

    # ======================================================================
    # Tests Investigations
    # ======================================================================

    def test_10_create_investigation(self):
        """POST /api/investigations cree une investigation"""
        resp = self.client.post('/api/investigations', json={
            'name': 'Incident Ransomware',
            'description': 'Analyse du ransomware detecte le 15/02/2026'
        }, headers=self._auth_headers())
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn('id', data)
        self.assertEqual(data['name'], 'Incident Ransomware')
        self.__class__.test_inv_id = data['id']

    def test_11_list_investigations(self):
        """GET /api/investigations retourne la liste paginee"""
        resp = self.client.get('/api/investigations', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('items', data)
        self.assertIn('total', data)
        self.assertGreater(data['total'], 0)

    def test_12_get_investigation(self):
        """GET /api/investigations/<id> retourne les details"""
        inv_id = getattr(self.__class__, 'test_inv_id', None)
        if not inv_id:
            self.skipTest('Pas d\'investigation de test')
        resp = self.client.get(f'/api/investigations/{inv_id}', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['id'], inv_id)

    def test_13_update_investigation_status(self):
        """PUT /api/investigations/<id>/status change le statut"""
        inv_id = getattr(self.__class__, 'test_inv_id', None)
        if not inv_id:
            self.skipTest('Pas d\'investigation de test')
        resp = self.client.put(f'/api/investigations/{inv_id}/status', json={
            'status': 'closed'
        }, headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'closed')

    # ======================================================================
    # Tests IoCs
    # ======================================================================

    def test_20_add_ioc(self):
        """POST /api/investigations/<id>/iocs ajoute un IoC"""
        inv_id = getattr(self.__class__, 'test_inv_id', None)
        if not inv_id:
            self.skipTest('Pas d\'investigation de test')
        resp = self.client.post(f'/api/investigations/{inv_id}/iocs', json={
            'type': 'ip',
            'value': '185.220.101.42',
            'source': 'firewall_logs'
        }, headers=self._auth_headers())
        self.assertIn(resp.status_code, [200, 201])
        data = resp.get_json()
        self.assertEqual(data['value'], '185.220.101.42')

    def test_21_add_multiple_ioc_types(self):
        """Tester differents types d'IoC"""
        inv_id = getattr(self.__class__, 'test_inv_id', None)
        if not inv_id:
            self.skipTest('Pas d\'investigation de test')

        iocs = [
            {'type': 'domain', 'value': 'malware.evil.com'},
            {'type': 'hash_sha256', 'value': 'a' * 64},
            {'type': 'url', 'value': 'https://malware.evil.com/payload.exe'},
            {'type': 'email', 'value': 'attacker@evil.com'},
            {'type': 'cve', 'value': 'CVE-2024-12345'},
        ]

        for ioc in iocs:
            resp = self.client.post(f'/api/investigations/{inv_id}/iocs', json=ioc,
                                    headers=self._auth_headers())
            self.assertIn(resp.status_code, [200, 201],
                          f'Echec ajout IoC type={ioc["type"]}: {resp.status_code}')

    def test_22_list_iocs(self):
        """GET /api/investigations/<id>/iocs retourne la liste"""
        inv_id = getattr(self.__class__, 'test_inv_id', None)
        if not inv_id:
            self.skipTest('Pas d\'investigation de test')
        resp = self.client.get(f'/api/investigations/{inv_id}/iocs', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('items', data)
        self.assertGreaterEqual(data['total'], 6)

    # ======================================================================
    # Tests Timeline
    # ======================================================================

    def test_30_add_timeline_event(self):
        """POST /api/investigations/<id>/timeline ajoute un evenement"""
        inv_id = getattr(self.__class__, 'test_inv_id', None)
        if not inv_id:
            self.skipTest('Pas d\'investigation de test')
        resp = self.client.post(f'/api/investigations/{inv_id}/timeline', json={
            'timestamp': '2026-02-15T10:30:00Z',
            'event': 'Detection initiale du ransomware par EDR',
            'severity': 'critical'
        }, headers=self._auth_headers())
        self.assertIn(resp.status_code, [200, 201])

    def test_31_list_timeline(self):
        """GET /api/investigations/<id>/timeline retourne les evenements"""
        inv_id = getattr(self.__class__, 'test_inv_id', None)
        if not inv_id:
            self.skipTest('Pas d\'investigation de test')
        resp = self.client.get(f'/api/investigations/{inv_id}/timeline', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('items', data)
        self.assertGreater(data['total'], 0)

    # ======================================================================
    # Tests Stats
    # ======================================================================

    def test_40_stats(self):
        """GET /api/stats retourne les statistiques"""
        resp = self.client.get('/api/stats', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('total_investigations', data)
        self.assertIn('total_iocs', data)

    # ======================================================================
    # Tests STIX Export
    # ======================================================================

    def test_50_stix_export(self):
        """GET /api/investigations/<id>/export/stix exporte en STIX"""
        inv_id = getattr(self.__class__, 'test_inv_id', None)
        if not inv_id:
            self.skipTest('Pas d\'investigation de test')
        resp = self.client.get(f'/api/investigations/{inv_id}/export/stix', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['type'], 'bundle')
        self.assertIn('objects', data)
        self.assertGreater(len(data['objects']), 0)

    # ======================================================================
    # Tests Audit
    # ======================================================================

    def test_60_audit_log(self):
        """GET /api/audit retourne le journal d'audit (admin)"""
        resp = self.client.get('/api/audit', headers=self._auth_headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('items', data)
        self.assertGreater(data['total'], 0)

    # ======================================================================
    # Tests Security
    # ======================================================================

    def test_70_path_traversal_blocked(self):
        """Les tentatives de path traversal sont bloquees"""
        resp = self.client.get('/api/reports/download/../../../etc/passwd',
                               headers=self._auth_headers())
        self.assertIn(resp.status_code, [400, 404])

    def test_71_invalid_token(self):
        """Un token invalide est rejete"""
        headers = {'Authorization': 'Bearer fake.invalid.token'}
        resp = self.client.get('/api/investigations', headers=headers)
        self.assertEqual(resp.status_code, 401)

    # ======================================================================
    # Cleanup
    # ======================================================================

    @classmethod
    def tearDownClass(cls):
        """Nettoyage apres les tests"""
        os.close(cls.db_fd)
        os.unlink(cls.db_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
