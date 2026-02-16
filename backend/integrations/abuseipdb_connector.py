"""
Phoenix DFIR - AbuseIPDB Connector
Verification de reputation d'adresses IP
"""

from integrations.base import BaseConnector
from integrations import registry


@registry.register
class AbuseIPDBConnector(BaseConnector):
    CONNECTOR_ID = 'abuseipdb'
    CONNECTOR_NAME = 'AbuseIPDB'
    CONNECTOR_DESCRIPTION = 'Base de donnees de reputation IP - Verifiez et signalez les IPs malveillantes'
    CONNECTOR_ICON = 'globe'
    CONNECTOR_URL = 'https://www.abuseipdb.com'
    CONNECTOR_CATEGORY = 'threat_intel'

    CONFIG_SCHEMA = [
        {'key': 'api_key', 'label': 'Cle API AbuseIPDB', 'type': 'password', 'required': True, 'placeholder': 'Votre cle API'},
    ]

    API_URL = 'https://api.abuseipdb.com/api/v2'

    def _headers(self):
        return {
            'Key': self.get_config('api_key', ''),
            'Accept': 'application/json',
        }

    def test_connection(self):
        """Verifier la cle API"""
        api_key = self.get_config('api_key', '')
        if not api_key:
            return {'success': False, 'message': 'Cle API requise'}

        # Tester avec une IP connue (Google DNS)
        resp = self._safe_request(
            'GET', f'{self.API_URL}/check',
            headers=self._headers(),
            params={'ipAddress': '8.8.8.8', 'maxAgeInDays': 1}
        )
        if resp is None:
            return {'success': False, 'message': 'Impossible de contacter AbuseIPDB'}
        if resp.status_code == 200:
            return {'success': True, 'message': 'Connecte a AbuseIPDB'}
        if resp.status_code in (401, 422):
            return {'success': False, 'message': 'Cle API invalide'}
        return {'success': False, 'message': f'Erreur: HTTP {resp.status_code}'}

    def enrich_ioc(self, ioc_type, ioc_value):
        """Enrichir une IP via AbuseIPDB"""
        if ioc_type != 'ip':
            return {'success': False, 'message': 'AbuseIPDB ne supporte que les IPs'}

        resp = self._safe_request(
            'GET', f'{self.API_URL}/check',
            headers=self._headers(),
            params={'ipAddress': ioc_value, 'maxAgeInDays': 90, 'verbose': True}
        )
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}

        if resp.status_code == 200:
            data = resp.json().get('data', {})
            return {
                'success': True,
                'source': 'abuseipdb',
                'abuse_confidence_score': data.get('abuseConfidenceScore', 0),
                'total_reports': data.get('totalReports', 0),
                'country_code': data.get('countryCode', ''),
                'isp': data.get('isp', ''),
                'domain': data.get('domain', ''),
                'is_tor': data.get('isTor', False),
                'is_whitelisted': data.get('isWhitelisted', False),
                'last_reported_at': data.get('lastReportedAt'),
                'message': f'Score abus: {data.get("abuseConfidenceScore", 0)}% ({data.get("totalReports", 0)} rapports)',
            }
        return {'success': False, 'message': f'Erreur: HTTP {resp.status_code}'}
