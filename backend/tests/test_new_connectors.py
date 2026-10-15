"""Tests des 5 nouveaux connecteurs v4.0 (sans appels reseau)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from integrations import registry
from integrations.greynoise_connector import GreyNoiseConnector
from integrations.urlscan_connector import URLScanConnector
from integrations.threatfox_connector import ThreatFoxConnector
from integrations.malwarebazaar_connector import MalwareBazaarConnector
from integrations.urlhaus_connector import URLhausConnector


class TestConnectorsRegistered(unittest.TestCase):
    def test_all_new_connectors_in_registry(self):
        ids = registry.get_connector_ids()
        for cid in ('greynoise', 'urlscan', 'threatfox', 'malwarebazaar', 'urlhaus'):
            self.assertIn(cid, ids, f'{cid} non enregistre')


class TestGreyNoise(unittest.TestCase):
    def test_metadata(self):
        c = GreyNoiseConnector()
        d = c.to_dict()
        self.assertEqual(d['id'], 'greynoise')
        self.assertEqual(d['category'], 'threat_intel')
        self.assertIn('enrich_ioc', d['capabilities'])

    def test_unsupported_type_returns_error(self):
        c = GreyNoiseConnector(config={'api_key': 'x'})
        result = c.enrich_ioc('hash_md5', 'aaaa')
        self.assertFalse(result['success'])


class TestURLScan(unittest.TestCase):
    def test_metadata(self):
        d = URLScanConnector().to_dict()
        self.assertEqual(d['id'], 'urlscan')
        self.assertEqual(d['category'], 'threat_intel')

    def test_test_connection_requires_key(self):
        result = URLScanConnector().test_connection()
        self.assertFalse(result['success'])

    def test_unsupported_type(self):
        result = URLScanConnector(config={'api_key': 'x'}).enrich_ioc('hash_md5', 'a')
        self.assertFalse(result['success'])


class TestThreatFox(unittest.TestCase):
    def test_metadata(self):
        d = ThreatFoxConnector().to_dict()
        self.assertEqual(d['id'], 'threatfox')

    def test_type_map_covers_common_types(self):
        for t in ('ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256'):
            self.assertIn(t, ThreatFoxConnector.TYPE_MAP)

    def test_unsupported_type(self):
        c = ThreatFoxConnector(config={'auth_key': 'x'})
        result = c.enrich_ioc('email', 'a@b.com')
        self.assertFalse(result['success'])


class TestMalwareBazaar(unittest.TestCase):
    def test_metadata(self):
        d = MalwareBazaarConnector().to_dict()
        self.assertEqual(d['id'], 'malwarebazaar')

    def test_hash_only(self):
        c = MalwareBazaarConnector(config={'auth_key': 'x'})
        for t in ('ip', 'domain', 'url', 'email'):
            self.assertFalse(c.enrich_ioc(t, 'value')['success'])


class TestURLhaus(unittest.TestCase):
    def test_metadata(self):
        d = URLhausConnector().to_dict()
        self.assertEqual(d['id'], 'urlhaus')

    def test_unsupported_types(self):
        c = URLhausConnector(config={'auth_key': 'x'})
        for t in ('ip', 'email', 'hash_sha1', 'cve'):
            self.assertFalse(c.enrich_ioc(t, 'value')['success'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
