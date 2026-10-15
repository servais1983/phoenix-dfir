"""
Phoenix DFIR - urlscan.io Connector
Soumission et recherche d'URLs analysees (screenshots, DOM, indicators).
https://urlscan.io/docs/api/
"""

from integrations.base import BaseConnector
from integrations import registry


@registry.register
class URLScanConnector(BaseConnector):
    CONNECTOR_ID = 'urlscan'
    CONNECTOR_NAME = 'urlscan.io'
    CONNECTOR_DESCRIPTION = 'Analyse d\'URLs (rendu, screenshots, IoCs reseau)'
    CONNECTOR_ICON = 'globe'
    CONNECTOR_URL = 'https://urlscan.io'
    CONNECTOR_CATEGORY = 'threat_intel'

    CONFIG_SCHEMA = [
        {'key': 'api_key', 'label': 'Cle API urlscan.io', 'type': 'password', 'required': True,
         'placeholder': 'Votre cle API'},
        {'key': 'visibility', 'label': 'Visibilite par defaut (public/unlisted/private)',
         'type': 'text', 'required': False, 'placeholder': 'unlisted'},
    ]

    API = 'https://urlscan.io/api/v1'

    def _headers(self):
        return {
            'API-Key': self.get_config('api_key', ''),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

    def test_connection(self):
        api_key = self.get_config('api_key', '')
        if not api_key:
            return {'success': False, 'message': 'Cle API requise'}
        # Pas d'endpoint /user dedie : on tente une recherche minuscule
        resp = self._safe_request(
            'GET', f'{self.API}/search/',
            headers=self._headers(),
            params={'q': 'domain:example.com', 'size': 1},
        )
        if resp is None:
            return {'success': False, 'message': 'Impossible de contacter urlscan.io'}
        if resp.status_code == 200:
            return {'success': True, 'message': 'Connecte a urlscan.io'}
        if resp.status_code == 401:
            return {'success': False, 'message': 'Cle API invalide'}
        if resp.status_code == 429:
            return {'success': False, 'message': 'Rate limit atteint'}
        return {'success': False, 'message': f'HTTP {resp.status_code}'}

    def enrich_ioc(self, ioc_type, ioc_value):
        """Rechercher dans urlscan.io. Supporte URL, domain, IP."""
        if ioc_type not in ('url', 'domain', 'ip'):
            return {'success': False, 'message': f'Type {ioc_type} non supporte'}

        if ioc_type == 'url':
            query = f'page.url:"{ioc_value}"'
        elif ioc_type == 'domain':
            query = f'page.domain:{ioc_value}'
        else:
            query = f'page.ip:{ioc_value}'

        resp = self._safe_request(
            'GET', f'{self.API}/search/',
            headers=self._headers(),
            params={'q': query, 'size': 10},
        )
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}
        if resp.status_code != 200:
            return {'success': False, 'message': f'HTTP {resp.status_code}'}

        data = resp.json()
        results = data.get('results', [])
        malicious_count = sum(1 for r in results if r.get('verdicts', {}).get('overall', {}).get('malicious'))

        return {
            'success': True,
            'source': 'urlscan',
            'total_scans': data.get('total', 0),
            'malicious_scans': malicious_count,
            'results_sample': [
                {
                    'url': r.get('page', {}).get('url'),
                    'ip': r.get('page', {}).get('ip'),
                    'country': r.get('page', {}).get('country'),
                    'screenshot': r.get('screenshot'),
                    'time': r.get('task', {}).get('time'),
                }
                for r in results[:5]
            ],
            'message': f'urlscan: {data.get("total", 0)} scans, {malicious_count} marques malicieux',
        }

    def submit(self, url, visibility=None, tags=None):
        """Soumettre une URL pour analyse."""
        api_key = self.get_config('api_key', '')
        if not api_key:
            return {'success': False, 'message': 'Cle API requise'}

        body = {
            'url': url,
            'visibility': visibility or self.get_config('visibility', 'unlisted'),
        }
        if tags:
            body['tags'] = tags

        resp = self._safe_request('POST', f'{self.API}/scan/', headers=self._headers(), json=body)
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}
        if resp.status_code in (200, 201):
            data = resp.json()
            return {
                'success': True,
                'uuid': data.get('uuid'),
                'result_url': data.get('result'),
                'api_url': data.get('api'),
                'message': 'URL soumise, resultat dans 10-30s',
            }
        return {'success': False, 'message': f'HTTP {resp.status_code}'}
