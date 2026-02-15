"""
Phoenix DFIR - Sigma Rule Connector
Conversion et application de regles Sigma pour la detection
"""

import os
import json
from integrations.base import BaseConnector
from integrations import registry


@registry.register
class SigmaConnector(BaseConnector):
    CONNECTOR_ID = 'sigma'
    CONNECTOR_NAME = 'Sigma'
    CONNECTOR_DESCRIPTION = 'Regles de detection generiques - Compatible SIEM universel'
    CONNECTOR_ICON = 'file-code'
    CONNECTOR_URL = 'https://sigmahq.io'
    CONNECTOR_CATEGORY = 'rule_engine'

    CONFIG_SCHEMA = [
        {'key': 'rules_path', 'label': 'Dossier des regles Sigma', 'type': 'text', 'required': False, 'placeholder': '/path/to/sigma/rules'},
    ]

    # Regles Sigma integrees pour les cas courants
    BUILTIN_RULES = [
        {
            'id': 'phoenix-brute-force',
            'title': 'Brute Force Detection',
            'description': 'Detection de tentatives de brute force (Event ID 4625)',
            'level': 'high',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4625], 'threshold': 5},
        },
        {
            'id': 'phoenix-log-clearing',
            'title': 'Security Log Cleared',
            'description': 'Detection de suppression de logs (Event ID 1102)',
            'level': 'critical',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [1102]},
        },
        {
            'id': 'phoenix-new-service',
            'title': 'New Service Installed',
            'description': 'Detection d\'installation de service (Event ID 7045)',
            'level': 'medium',
            'logsource': {'product': 'windows', 'service': 'system'},
            'detection': {'event_id': [7045]},
        },
        {
            'id': 'phoenix-scheduled-task',
            'title': 'Scheduled Task Created',
            'description': 'Detection de creation de tache planifiee (Event ID 4698)',
            'level': 'medium',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4698]},
        },
        {
            'id': 'phoenix-privilege-escalation',
            'title': 'Special Privileges Assigned',
            'description': 'Detection d\'elevation de privileges (Event ID 4672)',
            'level': 'low',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4672]},
        },
        {
            'id': 'phoenix-account-created',
            'title': 'User Account Created',
            'description': 'Detection de creation de compte (Event ID 4720)',
            'level': 'medium',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4720]},
        },
        {
            'id': 'phoenix-pass-the-hash',
            'title': 'Possible Pass-the-Hash',
            'description': 'Detection de logon type 9 (Event ID 4624 + logon type 9)',
            'level': 'high',
            'logsource': {'product': 'windows', 'service': 'security'},
            'detection': {'event_id': [4624], 'logon_type': 9},
        },
    ]

    def test_connection(self):
        """Verifier les regles Sigma disponibles"""
        rules_path = self.get_config('rules_path', '')
        custom_count = 0

        if rules_path and os.path.isdir(rules_path):
            for fname in os.listdir(rules_path):
                if fname.endswith(('.yml', '.yaml')):
                    custom_count += 1

        return {
            'success': True,
            'message': f'{len(self.BUILTIN_RULES)} regles integrees, {custom_count} regles personnalisees',
            'builtin_rules': len(self.BUILTIN_RULES),
            'custom_rules': custom_count,
        }

    def search(self, query, **kwargs):
        """Appliquer les regles Sigma sur des evenements"""
        events = kwargs.get('events', [])
        if not events:
            return {'success': False, 'message': 'Liste d\'evenements requise'}

        alerts = []
        for rule in self.BUILTIN_RULES:
            detection = rule.get('detection', {})
            rule_event_ids = detection.get('event_id', [])

            for event in events:
                event_id = event.get('event_id')
                if event_id and event_id in rule_event_ids:
                    # Verifier les conditions supplementaires
                    match = True
                    if 'logon_type' in detection:
                        match = event.get('logon_type') == detection['logon_type']
                    if 'threshold' in detection:
                        # Le seuil est gere au niveau aggregation, on flag quand meme
                        pass

                    if match:
                        alerts.append({
                            'rule_id': rule['id'],
                            'rule_title': rule['title'],
                            'description': rule['description'],
                            'level': rule['level'],
                            'event': event,
                        })

        return {
            'success': True,
            'alerts': alerts,
            'total_alerts': len(alerts),
            'rules_evaluated': len(self.BUILTIN_RULES),
            'events_scanned': len(events),
            'message': f'{len(alerts)} alerte(s) Sigma declenchee(s)',
        }

    def pull_iocs(self, query=None, limit=100):
        """Retourner la liste des regles Sigma disponibles"""
        rules = []
        for rule in self.BUILTIN_RULES:
            rules.append({
                'type': 'sigma_rule',
                'value': rule['id'],
                'source': 'phoenix-builtin',
                'severity': rule['level'],
                'metadata': rule,
            })
        return {
            'success': True,
            'iocs': rules,
            'total': len(rules),
            'message': f'{len(rules)} regles Sigma disponibles',
        }
