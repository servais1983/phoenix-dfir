"""Tests de l'expansion de la bibliotheque Sigma."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from integrations.sigma_connector import SigmaConnector


class TestSigmaRules(unittest.TestCase):
    def setUp(self):
        self.c = SigmaConnector()

    def test_at_least_25_rules(self):
        """v4.0 livre 25+ regles couvrant les principales tactiques MITRE."""
        self.assertGreaterEqual(len(self.c.BUILTIN_RULES), 25)

    def test_all_rules_have_required_fields(self):
        required = {'id', 'title', 'description', 'level', 'logsource', 'detection'}
        for rule in self.c.BUILTIN_RULES:
            self.assertTrue(required.issubset(rule.keys()),
                            f"Champs manquants dans {rule.get('id')}: {required - rule.keys()}")

    def test_all_rules_have_unique_ids(self):
        ids = [r['id'] for r in self.c.BUILTIN_RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_mitre_tactics_covered(self):
        tactics = {r.get('tactic') for r in self.c.BUILTIN_RULES if r.get('tactic')}
        # Au minimum on couvre ces tactiques cles
        for t in ('credential_access', 'defense_evasion', 'persistence',
                  'execution', 'lateral_movement', 'impact'):
            self.assertIn(t, tactics, f'Tactique {t} non couverte')

    def test_ransomware_rules_present(self):
        ids = {r['id'] for r in self.c.BUILTIN_RULES}
        self.assertIn('phoenix-vss-delete', ids)
        self.assertIn('phoenix-wbadmin-delete', ids)

    def test_credential_dumping_rules_present(self):
        ids = {r['id'] for r in self.c.BUILTIN_RULES}
        self.assertIn('phoenix-lsass-access', ids)
        self.assertIn('phoenix-ntds-extract', ids)

    def test_contains_criterion_matches_substring_case_insensitive(self):
        events = [{
            'event_id': 1,
            'image': 'C:\\Windows\\System32\\PowerShell.exe',
            'command_line': '-EncodedCommand AAAA',
        }]
        result = self.c.search('', events=events)
        rule_ids = {a['rule_id'] for a in result['alerts']}
        self.assertIn('phoenix-powershell-encoded', rule_ids)

    def test_contains_criterion_filters_out_non_matches(self):
        events = [{
            'event_id': 1,
            'image': 'C:\\Windows\\System32\\powershell.exe',
            'command_line': '-NoProfile -File script.ps1',
        }]
        result = self.c.search('', events=events)
        rule_ids = {a['rule_id'] for a in result['alerts']}
        self.assertNotIn('phoenix-powershell-encoded', rule_ids)

    def test_logon_type_equality_criterion(self):
        events = [
            {'event_id': 4624, 'logon_type': 10},  # RDP
            {'event_id': 4624, 'logon_type': 2},   # Interactive
        ]
        result = self.c.search('', events=events)
        rdp_alerts = [a for a in result['alerts'] if a['rule_id'] == 'phoenix-rdp-success']
        self.assertEqual(len(rdp_alerts), 1)

    def test_threshold_triggers_only_when_exceeded(self):
        # phoenix-brute-force a threshold=5
        events_4 = [{'event_id': 4625} for _ in range(4)]
        result = self.c.search('', events=events_4)
        bf_alerts = [a for a in result['alerts'] if a['rule_id'] == 'phoenix-brute-force']
        self.assertEqual(len(bf_alerts), 0)

        events_5 = [{'event_id': 4625} for _ in range(5)]
        result = self.c.search('', events=events_5)
        bf_alerts = [a for a in result['alerts'] if a['rule_id'] == 'phoenix-brute-force']
        self.assertEqual(len(bf_alerts), 1)

    def test_tactic_filter(self):
        events = [
            {'event_id': 1102},  # log clearing (defense_evasion)
            {'event_id': 7045},  # new service (persistence)
        ]
        result = self.c.search('', events=events, tactic='persistence')
        for a in result['alerts']:
            self.assertEqual(a['tactic'], 'persistence')

    def test_psexec_detection_requires_psexesvc_name(self):
        events = [{'event_id': 7045, 'service_name': 'PSEXESVC'}]
        result = self.c.search('', events=events)
        ids = {a['rule_id'] for a in result['alerts']}
        self.assertIn('phoenix-psexec', ids)

        events = [{'event_id': 7045, 'service_name': 'MyLegitService'}]
        result = self.c.search('', events=events)
        ids = {a['rule_id'] for a in result['alerts']}
        # phoenix-new-service matche (event_id seul), mais pas phoenix-psexec
        self.assertNotIn('phoenix-psexec', ids)
        self.assertIn('phoenix-new-service', ids)


if __name__ == '__main__':
    unittest.main(verbosity=2)
