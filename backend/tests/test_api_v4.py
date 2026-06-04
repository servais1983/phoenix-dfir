"""Tests des endpoints introduits par Phoenix DFIR v4.0."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['PHOENIX_DEBUG'] = 'false'
os.environ.pop('REDIS_URL', None)


class PhoenixV4APITestCase(unittest.TestCase):
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

        resp = cls.client.post('/api/auth/register', json={
            'username': 'v4admin',
            'password': 'V4-Admin-Strong-1!',
            'display_name': 'V4 Admin',
        })
        body = resp.get_json()
        cls.access_token = body['access_token']
        cls.refresh_token = body['refresh_token']

    def _auth(self, token=None):
        return {'Authorization': f'Bearer {token or self.access_token}',
                'Content-Type': 'application/json'}

    # --- Health / Readiness ---

    def test_livez(self):
        resp = self.client.get('/livez')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'alive')
        self.assertIn('version', data)

    def test_readyz(self):
        resp = self.client.get('/readyz')
        self.assertIn(resp.status_code, (200, 503))
        data = resp.get_json()
        self.assertIn('ready', data)
        self.assertIn('checks', data)
        self.assertIn('database', data['checks'])
        self.assertIn('cache', data['checks'])

    def test_health_includes_cache(self):
        resp = self.client.get('/api/health')
        data = resp.get_json()
        self.assertIn('cache', data)

    def test_healthz_alias_works(self):
        resp = self.client.get('/healthz')
        self.assertEqual(resp.status_code, 200)

    # --- Metrics endpoint ---

    def test_metrics_endpoint(self):
        # Generer un trafic
        self.client.get('/api/health')
        resp = self.client.get('/metrics')
        # 200 si prometheus_client dispo, 503 sinon
        self.assertIn(resp.status_code, (200, 503))
        if resp.status_code == 200:
            body = resp.get_data(as_text=True)
            self.assertIn('phoenix_http_requests_total', body)

    # --- Auth flow v4 ---

    def test_login_returns_token_pair(self):
        resp = self.client.post('/api/auth/login', json={
            'username': 'v4admin', 'password': 'V4-Admin-Strong-1!',
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)
        self.assertEqual(data['token_type'], 'Bearer')
        self.assertIn('expires_in', data)

    def test_refresh_token_returns_new_pair_and_revokes_old(self):
        # Login frais pour eviter de polluer cls.refresh_token
        login = self.client.post('/api/auth/login', json={
            'username': 'v4admin', 'password': 'V4-Admin-Strong-1!',
        }).get_json()
        refresh = login['refresh_token']

        resp = self.client.post('/api/auth/refresh', json={'refresh_token': refresh})
        self.assertEqual(resp.status_code, 200)
        new_tokens = resp.get_json()
        self.assertIn('access_token', new_tokens)
        self.assertNotEqual(new_tokens['refresh_token'], refresh)

        # L'ancien refresh est revoque
        resp2 = self.client.post('/api/auth/refresh', json={'refresh_token': refresh})
        self.assertEqual(resp2.status_code, 401)

    def test_refresh_with_invalid_token_rejected(self):
        resp = self.client.post('/api/auth/refresh', json={'refresh_token': 'invalid.token.here'})
        self.assertEqual(resp.status_code, 401)

    def test_refresh_with_access_token_rejected(self):
        # Un access token ne doit pas pouvoir etre echange contre un refresh
        resp = self.client.post('/api/auth/refresh', json={'refresh_token': self.access_token})
        self.assertEqual(resp.status_code, 401)

    def test_logout_revokes_token(self):
        login = self.client.post('/api/auth/login', json={
            'username': 'v4admin', 'password': 'V4-Admin-Strong-1!',
        }).get_json()
        access = login['access_token']

        # Verifier que /me fonctionne
        resp = self.client.get('/api/auth/me', headers={'Authorization': f'Bearer {access}'})
        self.assertEqual(resp.status_code, 200)

        # Logout
        resp = self.client.post('/api/auth/logout',
                                headers={'Authorization': f'Bearer {access}'},
                                json={'refresh_token': login['refresh_token']})
        self.assertEqual(resp.status_code, 200)

        # /me echoue maintenant
        resp = self.client.get('/api/auth/me', headers={'Authorization': f'Bearer {access}'})
        self.assertEqual(resp.status_code, 401)

    def test_change_password_requires_current(self):
        # Register un user dedie pour pouvoir le casser sans toucher v4admin
        self.client.post('/api/auth/register', json={
            'username': 'pwuser', 'password': 'PwUser-Strong-1!@',
            'display_name': 'PW',
        })
        login = self.client.post('/api/auth/login', json={
            'username': 'pwuser', 'password': 'PwUser-Strong-1!@',
        }).get_json()
        access = login['access_token']

        # Mauvais mot de passe actuel
        resp = self.client.put(
            '/api/auth/password',
            headers={'Authorization': f'Bearer {access}'},
            json={'current_password': 'wrong', 'new_password': 'NewPwUser-Strong-2!@'},
        )
        self.assertEqual(resp.status_code, 401)

        # Bon mot de passe
        resp = self.client.put(
            '/api/auth/password',
            headers={'Authorization': f'Bearer {access}'},
            json={'current_password': 'PwUser-Strong-1!@',
                  'new_password': 'NewPwUser-Strong-2!@'},
        )
        self.assertEqual(resp.status_code, 200)

        # Login avec le nouveau
        resp = self.client.post('/api/auth/login', json={
            'username': 'pwuser', 'password': 'NewPwUser-Strong-2!@',
        })
        self.assertEqual(resp.status_code, 200)

    def test_change_password_rejects_weak_new(self):
        # Login fresh user
        self.client.post('/api/auth/register', json={
            'username': 'pwuser2', 'password': 'PwUser2-Strong-1!@',
            'display_name': 'PW2',
        })
        login = self.client.post('/api/auth/login', json={
            'username': 'pwuser2', 'password': 'PwUser2-Strong-1!@',
        }).get_json()
        access = login['access_token']

        resp = self.client.put(
            '/api/auth/password',
            headers={'Authorization': f'Bearer {access}'},
            json={'current_password': 'PwUser2-Strong-1!@', 'new_password': 'short'},
        )
        self.assertEqual(resp.status_code, 400)

    def test_register_weak_password_rejected(self):
        resp = self.client.post('/api/auth/register', json={
            'username': 'weakuser', 'password': 'password',
        })
        self.assertEqual(resp.status_code, 400)

    def test_register_username_chars(self):
        resp = self.client.post('/api/auth/register', json={
            'username': 'bad user!', 'password': 'V4-Strong-Pass-9!@',
        })
        self.assertEqual(resp.status_code, 400)

    @classmethod
    def tearDownClass(cls):
        os.close(cls.db_fd)
        os.unlink(cls.db_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
