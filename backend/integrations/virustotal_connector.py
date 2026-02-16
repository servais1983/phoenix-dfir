"""
Phoenix DFIR - VirusTotal Connector
Integration avec l'API VirusTotal v3 pour l'enrichissement d'IoCs
"""

from integrations.base import BaseConnector
from integrations import registry


@registry.register
class VirusTotalConnector(BaseConnector):
    CONNECTOR_ID = 'virustotal'
    CONNECTOR_NAME = 'VirusTotal'
    CONNECTOR_DESCRIPTION = 'Analyse de fichiers, URLs, IPs et domaines via VirusTotal'
    CONNECTOR_ICON = 'shield-check'
    CONNECTOR_URL = 'https://www.virustotal.com'
    CONNECTOR_CATEGORY = 'threat_intel'

    CONFIG_SCHEMA = [
        {'key': 'api_key', 'label': 'Cle API VirusTotal', 'type': 'password', 'required': True, 'placeholder': 'Votre cle API VT'},
    ]

    VT_API = 'https://www.virustotal.com/api/v3'

    # Mapping Phoenix type -> VT endpoint
    ENDPOINT_MAP = {
        'ip': 'ip_addresses',
        'domain': 'domains',
        'hash_md5': 'files',
        'hash_sha1': 'files',
        'hash_sha256': 'files',
        'url': 'urls',
    }

    def _headers(self):
        return {'x-apikey': self.get_config('api_key', '')}

    def test_connection(self):
        """Verifier la cle API VT"""
        api_key = self.get_config('api_key', '')
        if not api_key:
            return {'success': False, 'message': 'Cle API requise'}

        resp = self._safe_request(
            'GET', f'{self.VT_API}/users/me',
            headers=self._headers()
        )
        if resp is None:
            return {'success': False, 'message': 'Impossible de contacter VirusTotal'}
        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            return {
                'success': True,
                'message': f'Connecte (quotas: {data.get("quotas", {}).get("api_requests_daily", {}).get("allowed", "?")} req/jour)',
            }
        if resp.status_code == 401:
            return {'success': False, 'message': 'Cle API invalide'}
        return {'success': False, 'message': f'Erreur VT: HTTP {resp.status_code}'}

    def enrich_ioc(self, ioc_type, ioc_value):
        """Enrichir un IoC via l'API VT v3"""
        endpoint = self.ENDPOINT_MAP.get(ioc_type)
        if not endpoint:
            return {'success': False, 'message': f'Type {ioc_type} non supporte'}

        # Pour les URLs, il faut encoder en base64
        if ioc_type == 'url':
            import base64
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip('=')
            lookup_url = f'{self.VT_API}/urls/{url_id}'
        else:
            lookup_url = f'{self.VT_API}/{endpoint}/{ioc_value}'

        resp = self._safe_request('GET', lookup_url, headers=self._headers())
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion VT'}

        if resp.status_code == 200:
            data = resp.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            return {
                'success': True,
                'source': 'virustotal',
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'harmless': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': data.get('reputation', 0),
                'tags': data.get('tags', []),
                'last_analysis_date': data.get('last_analysis_date'),
                'message': f'VT: {stats.get("malicious", 0)} malicious, {stats.get("suspicious", 0)} suspicious',
            }
        if resp.status_code == 404:
            return {'success': True, 'source': 'virustotal', 'malicious': 0, 'message': 'Non trouve dans VT'}
        return {'success': False, 'message': f'Erreur VT: HTTP {resp.status_code}'}

    def search(self, query, **kwargs):
        """Recherche VT Intelligence"""
        resp = self._safe_request(
            'GET', f'{self.VT_API}/intelligence/search',
            headers=self._headers(),
            params={'query': query, 'limit': kwargs.get('limit', 20)}
        )
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}
        if resp.status_code == 200:
            data = resp.json()
            return {'success': True, 'results': data.get('data', []), 'total': len(data.get('data', []))}
        return {'success': False, 'message': f'Erreur VT: HTTP {resp.status_code}'}
