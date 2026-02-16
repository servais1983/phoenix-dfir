"""
Phoenix DFIR - Tests Integrations
Tests du framework d'integration et des connecteurs
"""

import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'


class TestIntegrationRegistry(unittest.TestCase):
    """Tests du registre d'integrations"""

    def test_registry_has_connectors(self):
        """Le registre contient tous les connecteurs"""
        from integrations import registry
        ids = registry.get_connector_ids()
        self.assertIn('misp', ids)
        self.assertIn('cortex', ids)
        self.assertIn('virustotal', ids)
        self.assertIn('abuseipdb', ids)
        self.assertIn('shodan', ids)
        self.assertIn('otx', ids)
        self.assertIn('yara', ids)
        self.assertIn('sigma', ids)

    def test_registry_list_connectors(self):
        """list_connectors retourne les metadonnees de tous les connecteurs"""
        from integrations import registry
        connectors = registry.list_connectors()
        self.assertEqual(len(connectors), 8)
        for c in connectors:
            self.assertIn('id', c)
            self.assertIn('name', c)
            self.assertIn('category', c)
            self.assertIn('config_schema', c)
            self.assertIn('capabilities', c)

    def test_create_instance(self):
        """create_instance retourne une instance configuree"""
        from integrations import registry
        instance = registry.create_instance('misp', {'url': 'https://test.misp', 'api_key': 'abc'})
        self.assertIsNotNone(instance)
        self.assertEqual(instance.get_config('url'), 'https://test.misp')

    def test_create_unknown_returns_none(self):
        """create_instance retourne None pour un connecteur inconnu"""
        from integrations import registry
        instance = registry.create_instance('nonexistent')
        self.assertIsNone(instance)


class TestBaseConnector(unittest.TestCase):
    """Tests de la classe de base"""

    def test_default_methods_return_not_supported(self):
        """Les methodes par defaut retournent 'non supporte'"""
        from integrations.base import BaseConnector
        c = BaseConnector()
        result = c.push_iocs([])
        self.assertFalse(result['success'])
        result = c.pull_iocs()
        self.assertFalse(result['success'])
        result = c.enrich_ioc('ip', '8.8.8.8')
        self.assertFalse(result['success'])

    def test_to_dict(self):
        """to_dict serialise correctement"""
        from integrations.base import BaseConnector
        c = BaseConnector()
        d = c.to_dict()
        self.assertEqual(d['id'], 'base')
        self.assertIsInstance(d['capabilities'], list)


class TestMISPConnector(unittest.TestCase):
    """Tests specifiques MISP"""

    def test_type_mappings(self):
        """Les mappings de type sont complets et bidirectionnels"""
        from integrations.misp_connector import MISPConnector
        # Tous les types Phoenix ont un mapping MISP
        for ptype in ('ip', 'domain', 'hash_md5', 'hash_sha256', 'url', 'email', 'cve'):
            self.assertIn(ptype, MISPConnector.IOC_TYPE_MAP)

    def test_test_connection_no_config(self):
        """test_connection echoue sans config"""
        from integrations.misp_connector import MISPConnector
        c = MISPConnector(config={})
        result = c.test_connection()
        self.assertFalse(result['success'])

    def test_capabilities(self):
        """MISP a push, pull, search, test"""
        from integrations.misp_connector import MISPConnector
        c = MISPConnector()
        caps = c.get_capabilities()
        self.assertIn('test_connection', caps)
        self.assertIn('push_iocs', caps)
        self.assertIn('pull_iocs', caps)
        self.assertIn('search', caps)


class TestVirusTotalConnector(unittest.TestCase):
    """Tests specifiques VirusTotal"""

    def test_endpoint_map(self):
        """Les endpoints VT sont definis pour les types courants"""
        from integrations.virustotal_connector import VirusTotalConnector
        for t in ('ip', 'domain', 'hash_sha256', 'url'):
            self.assertIn(t, VirusTotalConnector.ENDPOINT_MAP)

    def test_no_api_key(self):
        """test_connection echoue sans cle API"""
        from integrations.virustotal_connector import VirusTotalConnector
        c = VirusTotalConnector(config={})
        result = c.test_connection()
        self.assertFalse(result['success'])


class TestAbuseIPDBConnector(unittest.TestCase):
    """Tests specifiques AbuseIPDB"""

    def test_only_supports_ip(self):
        """AbuseIPDB ne supporte que les IPs"""
        from integrations.abuseipdb_connector import AbuseIPDBConnector
        c = AbuseIPDBConnector(config={'api_key': 'test'})
        result = c.enrich_ioc('domain', 'evil.com')
        self.assertFalse(result['success'])
        self.assertIn('IP', result['message'])


class TestShodanConnector(unittest.TestCase):
    """Tests specifiques Shodan"""

    def test_supports_ip_and_domain(self):
        """Shodan supporte IP et domaine, pas les autres"""
        from integrations.shodan_connector import ShodanConnector
        c = ShodanConnector(config={'api_key': 'test'})
        result = c.enrich_ioc('email', 'test@test.com')
        self.assertFalse(result['success'])


class TestOTXConnector(unittest.TestCase):
    """Tests specifiques OTX"""

    def test_section_map(self):
        """OTX mappe les types courants"""
        from integrations.otx_connector import OTXConnector
        for t in ('ip', 'domain', 'hash_sha256', 'url', 'email', 'cve'):
            self.assertIn(t, OTXConnector.OTX_SECTION_MAP)


class TestSigmaConnector(unittest.TestCase):
    """Tests specifiques Sigma"""

    def test_builtin_rules_exist(self):
        """Des regles Sigma integrees sont disponibles"""
        from integrations.sigma_connector import SigmaConnector
        c = SigmaConnector()
        self.assertGreater(len(c.BUILTIN_RULES), 5)

    def test_search_with_matching_events(self):
        """Les regles Sigma matchent correctement"""
        from integrations.sigma_connector import SigmaConnector
        c = SigmaConnector()
        events = [
            {'event_id': 4625, 'description': 'Failed login'},
            {'event_id': 1102, 'description': 'Log cleared'},
            {'event_id': 4688, 'description': 'Process created'},
        ]
        result = c.search('', events=events)
        self.assertTrue(result['success'])
        self.assertGreater(result['total_alerts'], 0)
        # 4625 doit trigger Brute Force
        rule_ids = [a['rule_id'] for a in result['alerts']]
        self.assertIn('phoenix-brute-force', rule_ids)
        self.assertIn('phoenix-log-clearing', rule_ids)

    def test_search_no_events(self):
        """Retourne erreur sans evenements"""
        from integrations.sigma_connector import SigmaConnector
        c = SigmaConnector()
        result = c.search('')
        self.assertFalse(result['success'])

    def test_pull_returns_rules(self):
        """pull_iocs retourne les regles"""
        from integrations.sigma_connector import SigmaConnector
        c = SigmaConnector()
        result = c.pull_iocs()
        self.assertTrue(result['success'])
        self.assertGreater(result['total'], 0)

    def test_test_connection(self):
        """test_connection reussit toujours pour Sigma"""
        from integrations.sigma_connector import SigmaConnector
        c = SigmaConnector()
        result = c.test_connection()
        self.assertTrue(result['success'])


class TestCortexConnector(unittest.TestCase):
    """Tests specifiques Cortex"""

    def test_datatype_map(self):
        """Cortex mappe les types courants"""
        from integrations.cortex_connector import CortexConnector
        for t in ('ip', 'domain', 'hash_sha256', 'url', 'email'):
            self.assertIn(t, CortexConnector.DATATYPE_MAP)


class TestIntegrationAPI(unittest.TestCase):
    """Tests des endpoints API d'integrations"""

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

        # Creer un admin
        resp = cls.client.post('/api/auth/register', json={
            'username': 'intadmin', 'password': 'password123', 'display_name': 'Int Admin'
        })
        cls.token = resp.get_json().get('token', '')

    def _headers(self):
        return {'Authorization': f'Bearer {self.token}', 'Content-Type': 'application/json'}

    def test_list_integrations(self):
        """GET /api/integrations retourne tous les connecteurs"""
        resp = self.client.get('/api/integrations', headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('integrations', data)
        self.assertEqual(data['total'], 8)

    def test_get_integration_detail(self):
        """GET /api/integrations/<id> retourne les details"""
        resp = self.client.get('/api/integrations/misp', headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['id'], 'misp')
        self.assertIn('config_schema', data)

    def test_get_unknown_integration(self):
        """GET /api/integrations/<unknown> retourne 404"""
        resp = self.client.get('/api/integrations/nonexistent', headers=self._headers())
        self.assertEqual(resp.status_code, 404)

    def test_update_integration(self):
        """PUT /api/integrations/<id> met a jour la config"""
        resp = self.client.put('/api/integrations/virustotal', json={
            'config': {'api_key': 'test-vt-key-12345'},
            'enabled': True
        }, headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get('enabled') or data.get('message'))

    def test_test_integration(self):
        """POST /api/integrations/<id>/test teste la connexion"""
        resp = self.client.post('/api/integrations/sigma/test', headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])

    @classmethod
    def tearDownClass(cls):
        os.close(cls.db_fd)
        os.unlink(cls.db_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
