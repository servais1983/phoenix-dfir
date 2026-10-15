"""
Phoenix DFIR - GreyNoise Connector
Identifie le bruit Internet vs cible : trafic massif de scanners vs activite ciblee.
https://docs.greynoise.io/reference/get_v3-community-ip
"""

from integrations.base import BaseConnector
from integrations import registry


@registry.register
class GreyNoiseConnector(BaseConnector):
    CONNECTOR_ID = 'greynoise'
    CONNECTOR_NAME = 'GreyNoise'
    CONNECTOR_DESCRIPTION = 'Distingue le bruit Internet (scanners) du trafic cible suspect'
    CONNECTOR_ICON = 'radar'
    CONNECTOR_URL = 'https://greynoise.io'
    CONNECTOR_CATEGORY = 'threat_intel'

    CONFIG_SCHEMA = [
        {'key': 'api_key', 'label': 'Cle API GreyNoise', 'type': 'password', 'required': False,
         'placeholder': 'Optionnel : Community sans cle, Enterprise avec cle'},
    ]

    COMMUNITY_API = 'https://api.greynoise.io/v3/community'
    ENTERPRISE_API = 'https://api.greynoise.io/v2/noise/context'

    def _headers(self):
        h = {'Accept': 'application/json'}
        key = self.get_config('api_key', '')
        if key:
            h['key'] = key
        return h

    def test_connection(self):
        """Tester via une IP connue (Cloudflare DNS)."""
        resp = self._safe_request('GET', f'{self.COMMUNITY_API}/1.1.1.1', headers=self._headers())
        if resp is None:
            return {'success': False, 'message': 'Impossible de contacter GreyNoise'}
        if resp.status_code in (200, 404):
            mode = 'Enterprise' if self.get_config('api_key') else 'Community'
            return {'success': True, 'message': f'GreyNoise {mode} accessible'}
        if resp.status_code == 401:
            return {'success': False, 'message': 'Cle API invalide'}
        if resp.status_code == 429:
            return {'success': False, 'message': 'Rate limit atteint (Community: 50/jour)'}
        return {'success': False, 'message': f'HTTP {resp.status_code}'}

    def enrich_ioc(self, ioc_type, ioc_value):
        """GreyNoise ne couvre que les IPs."""
        if ioc_type != 'ip':
            return {'success': False, 'message': f'Type {ioc_type} non supporte (IPs uniquement)'}

        api_key = self.get_config('api_key', '')
        url = f'{self.ENTERPRISE_API}/{ioc_value}' if api_key else f'{self.COMMUNITY_API}/{ioc_value}'
        resp = self._safe_request('GET', url, headers=self._headers())
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}

        if resp.status_code == 404:
            return {
                'success': True,
                'source': 'greynoise',
                'noise': False,
                'riot': False,
                'classification': 'unknown',
                'message': 'IP inconnue de GreyNoise',
            }
        if resp.status_code != 200:
            return {'success': False, 'message': f'HTTP {resp.status_code}'}

        data = resp.json()
        classification = data.get('classification', 'unknown')
        return {
            'success': True,
            'source': 'greynoise',
            'noise': data.get('noise', False),
            'riot': data.get('riot', False),  # Known-good (CDN/cloud)
            'classification': classification,  # benign, malicious, unknown
            'name': data.get('name', ''),
            'last_seen': data.get('last_seen', ''),
            'message': f'GreyNoise: {classification} ({"noise" if data.get("noise") else "targeted"})',
        }
