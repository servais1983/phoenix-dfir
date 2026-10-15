"""
Phoenix DFIR - AlienVault OTX Connector
Open Threat Exchange - Threat Intelligence gratuite et communautaire
"""

from integrations.base import BaseConnector
from integrations import registry


@registry.register
class OTXConnector(BaseConnector):
    CONNECTOR_ID = 'otx'
    CONNECTOR_NAME = 'AlienVault OTX'
    CONNECTOR_DESCRIPTION = 'Open Threat Exchange - Threat Intelligence communautaire gratuite'
    CONNECTOR_ICON = 'users'
    CONNECTOR_URL = 'https://otx.alienvault.com'
    CONNECTOR_CATEGORY = 'threat_intel'

    CONFIG_SCHEMA = [
        {'key': 'api_key', 'label': 'Cle API OTX', 'type': 'password', 'required': True, 'placeholder': 'Votre cle API OTX'},
    ]

    API_URL = 'https://otx.alienvault.com/api/v1'

    # Mapping Phoenix type -> OTX section/type
    OTX_SECTION_MAP = {
        'ip': ('indicators/IPv4', 'general'),
        'domain': ('indicators/domain', 'general'),
        'hash_md5': ('indicators/file', 'general'),
        'hash_sha1': ('indicators/file', 'general'),
        'hash_sha256': ('indicators/file', 'general'),
        'url': ('indicators/url', 'general'),
        'email': ('indicators/email', 'general'),
        'cve': ('indicators/cve', 'general'),
    }

    def _headers(self):
        return {'X-OTX-API-KEY': self.get_config('api_key', '')}

    def test_connection(self):
        """Verifier la cle API OTX"""
        api_key = self.get_config('api_key', '')
        if not api_key:
            return {'success': False, 'message': 'Cle API requise'}

        resp = self._safe_request(
            'GET', f'{self.API_URL}/user/me',
            headers=self._headers()
        )
        if resp is None:
            return {'success': False, 'message': 'Impossible de contacter OTX'}
        if resp.status_code == 200:
            data = resp.json()
            return {
                'success': True,
                'message': f'Connecte en tant que {data.get("username", "?")}',
                'username': data.get('username'),
            }
        return {'success': False, 'message': f'Erreur: HTTP {resp.status_code}'}

    def enrich_ioc(self, ioc_type, ioc_value):
        """Enrichir un IoC via OTX"""
        mapping = self.OTX_SECTION_MAP.get(ioc_type)
        if not mapping:
            return {'success': False, 'message': f'Type {ioc_type} non supporte par OTX'}

        section, subsection = mapping
        resp = self._safe_request(
            'GET', f'{self.API_URL}/{section}/{ioc_value}/{subsection}',
            headers=self._headers()
        )
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}

        if resp.status_code == 200:
            data = resp.json()
            pulses = data.get('pulse_info', {}).get('count', 0)
            pulse_names = [p.get('name', '') for p in data.get('pulse_info', {}).get('pulses', [])[:5]]
            return {
                'success': True,
                'source': 'otx',
                'pulse_count': pulses,
                'pulses': pulse_names,
                'reputation': data.get('reputation', 0),
                'country': data.get('country_name', ''),
                'asn': data.get('asn', ''),
                'message': f'OTX: {pulses} pulse(s) de menace associees',
            }
        if resp.status_code == 404:
            return {'success': True, 'source': 'otx', 'pulse_count': 0, 'message': 'Non trouve dans OTX'}
        return {'success': False, 'message': f'Erreur OTX: HTTP {resp.status_code}'}

    def pull_iocs(self, query=None, limit=100):
        """Recuperer les IoCs des pulses auxquels on est abonne"""
        resp = self._safe_request(
            'GET', f'{self.API_URL}/pulses/subscribed',
            headers=self._headers(),
            params={'limit': min(limit, 50), 'modified_since': query or ''}
        )
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}

        if resp.status_code == 200:
            data = resp.json()
            iocs = []
            type_map = {
                'IPv4': 'ip', 'domain': 'domain', 'URL': 'url',
                'FileHash-MD5': 'hash_md5', 'FileHash-SHA1': 'hash_sha1',
                'FileHash-SHA256': 'hash_sha256', 'email': 'email', 'CVE': 'cve',
            }
            for pulse in data.get('results', []):
                for indicator in pulse.get('indicators', []):
                    phoenix_type = type_map.get(indicator.get('type'))
                    if phoenix_type:
                        iocs.append({
                            'type': phoenix_type,
                            'value': indicator.get('indicator', ''),
                            'source': f"otx-pulse-{pulse.get('id', '?')}",
                        })
                    if len(iocs) >= limit:
                        break

            return {
                'success': True,
                'iocs': iocs[:limit],
                'total': len(iocs),
                'message': f'{len(iocs)} IoCs recuperes depuis OTX',
            }
        return {'success': False, 'message': f'Erreur: HTTP {resp.status_code}'}
