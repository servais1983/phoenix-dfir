"""
Phoenix DFIR - Tests MITRE ATT&CK Mapping
"""

import os
import sys
import unittest
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mitre import get_attack_for_event, get_attack_for_ioc, get_attack_summary, enrich_events_with_attack


class TestMitreMapping(unittest.TestCase):
    """Tests du mapping MITRE ATT&CK"""

    def test_event_brute_force(self):
        """Event 4625 mappe vers T1110 Brute Force"""
        result = get_attack_for_event(4625)
        self.assertTrue(len(result) > 0)
        self.assertEqual(result[0]['technique'], 'T1110')

    def test_event_log_clearing(self):
        """Event 1102 mappe vers T1070.001 Clear Windows Event Logs"""
        result = get_attack_for_event(1102)
        self.assertTrue(len(result) > 0)
        self.assertEqual(result[0]['technique'], 'T1070.001')

    def test_event_scheduled_task(self):
        """Event 4698 mappe vers T1053.005 Scheduled Task"""
        result = get_attack_for_event(4698)
        self.assertTrue(len(result) > 0)
        self.assertIn('T1053.005', result[0]['technique'])

    def test_unknown_event(self):
        """Un Event ID inconnu retourne une liste vide"""
        result = get_attack_for_event(99999)
        self.assertEqual(result, [])

    def test_ioc_ip_mapping(self):
        """Un IoC de type IP mappe vers C2"""
        result = get_attack_for_ioc('ip')
        self.assertTrue(len(result) > 0)
        self.assertEqual(result[0]['tactic'], 'Command and Control')

    def test_ioc_email_mapping(self):
        """Un IoC de type email mappe vers Phishing"""
        result = get_attack_for_ioc('email')
        self.assertTrue(len(result) > 0)
        self.assertEqual(result[0]['technique'], 'T1566')

    def test_ioc_cve_mapping(self):
        """Un IoC de type CVE mappe vers Exploit Public-Facing"""
        result = get_attack_for_ioc('cve')
        self.assertTrue(len(result) > 0)
        self.assertEqual(result[0]['technique'], 'T1190')

    def test_unknown_ioc_type(self):
        """Un type d'IoC inconnu retourne une liste vide"""
        result = get_attack_for_ioc('unknown')
        self.assertEqual(result, [])

    def test_attack_summary(self):
        """get_attack_summary regroupe correctement par tactique"""
        event_ids = [4625, 1102, 4688]
        summary = get_attack_summary(event_ids)
        self.assertIn('Credential Access', summary)
        self.assertIn('Defense Evasion', summary)
        self.assertIn('Execution', summary)

    def test_enrich_events(self):
        """enrich_events_with_attack ajoute les mappings ATT&CK"""
        events = [
            {'event_id': 4625, 'description': 'Failed login'},
            {'event_id': 4688, 'description': 'Process created'},
            {'description': 'No event ID'},
        ]
        enriched = enrich_events_with_attack(events)
        self.assertIn('mitre_attack', enriched[0])
        self.assertIn('mitre_attack', enriched[1])
        self.assertNotIn('mitre_attack', enriched[2])


class TestMitreMiddleware(unittest.TestCase):
    """Tests du middleware de securite"""

    def test_rate_limiter(self):
        """Le sliding window du cache compte correctement les hits"""
        from cache import Cache
        c = Cache()
        key = f'test-rl-{uuid.uuid4().hex}'
        # 5 hits acceptes
        for i in range(5):
            self.assertEqual(c.sliding_window_hit(key, 60), i + 1)
        # 6eme hit retourne 6 (au-dessus du seuil)
        self.assertEqual(c.sliding_window_hit(key, 60), 6)

    def test_rate_limiter_different_ips(self):
        """Le rate limiter est par cle, isolant les IPs"""
        from cache import Cache
        c = Cache()
        suffix = uuid.uuid4().hex
        for _ in range(5):
            c.sliding_window_hit(f'rl-ip1-{suffix}', 60)

        # ip1 est a 6 maintenant, ip2 commence a 1
        self.assertEqual(c.sliding_window_hit(f'rl-ip1-{suffix}', 60), 6)
        self.assertEqual(c.sliding_window_hit(f'rl-ip2-{suffix}', 60), 1)

    def test_validate_uuid(self):
        """validate_uuid accepte les UUIDs valides"""
        from middleware import validate_uuid
        import uuid
        self.assertTrue(validate_uuid(str(uuid.uuid4())))
        self.assertFalse(validate_uuid('not-a-uuid'))
        self.assertFalse(validate_uuid(''))

    def test_sanitize_string(self):
        """sanitize_string nettoie les chaines"""
        from middleware import sanitize_string
        self.assertEqual(sanitize_string('  hello  '), 'hello')
        self.assertEqual(sanitize_string('a' * 1000, max_length=10), 'a' * 10)
        self.assertEqual(sanitize_string(123), '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
