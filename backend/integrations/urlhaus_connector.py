"""
Phoenix DFIR - URLhaus (abuse.ch) Connector
URLs malveillantes (delivery de malware) suivies par abuse.ch.
https://urlhaus-api.abuse.ch/
"""

from integrations.base import BaseConnector
from integrations import registry


@registry.register
class URLhausConnector(BaseConnector):
    CONNECTOR_ID = 'urlhaus'
    CONNECTOR_NAME = 'URLhaus'
    CONNECTOR_DESCRIPTION = 'URLs malveillantes (delivery malware, abuse.ch)'
    CONNECTOR_ICON = 'link'
    CONNECTOR_URL = 'https://urlhaus.abuse.ch'
    CONNECTOR_CATEGORY = 'threat_intel'

    CONFIG_SCHEMA = [
        {'key': 'auth_key', 'label': 'Auth-Key abuse.ch', 'type': 'password', 'required': True,
         'placeholder': 'Compte gratuit sur auth.abuse.ch'},
    ]

    API = 'https://urlhaus-api.abuse.ch/v1/'

    def _headers(self):
        return {'Auth-Key': self.get_config('auth_key', '')}

    def test_connection(self):
        if not self.get_config('auth_key', ''):
            return {'success': False, 'message': 'Auth-Key requise'}
        resp = self._safe_request(
            'POST', f'{self.API}url/', headers=self._headers(),
            data={'url': 'http://example.com/'},
        )
        if resp is None:
            return {'success': False, 'message': 'Impossible de contacter URLhaus'}
        if resp.status_code == 200:
            data = resp.json()
            if data.get('query_status') in ('ok', 'no_results'):
                return {'success': True, 'message': 'URLhaus accessible'}
            if data.get('query_status') == 'illegal_auth':
                return {'success': False, 'message': 'Auth-Key invalide'}
        return {'success': False, 'message': f'HTTP {resp.status_code}'}

    def enrich_ioc(self, ioc_type, ioc_value):
        if ioc_type == 'url':
            return self._lookup_url(ioc_value)
        if ioc_type == 'domain':
            return self._lookup_host(ioc_value)
        if ioc_type in ('hash_md5', 'hash_sha256'):
            return self._lookup_payload(ioc_type, ioc_value)
        return {'success': False, 'message': f'Type {ioc_type} non supporte'}

    def _lookup_url(self, url_value):
        resp = self._safe_request(
            'POST', f'{self.API}url/', headers=self._headers(), data={'url': url_value},
        )
        if resp is None or resp.status_code != 200:
            return {'success': False, 'message': f'HTTP {resp.status_code if resp else "?"}'}
        data = resp.json()
        if data.get('query_status') == 'no_results':
            return {'success': True, 'source': 'urlhaus', 'found': False, 'message': 'URL inconnue'}
        if data.get('query_status') != 'ok':
            return {'success': False, 'message': f'Erreur: {data.get("query_status")}'}
        return {
            'success': True,
            'source': 'urlhaus',
            'found': True,
            'threat': data.get('threat'),
            'url_status': data.get('url_status'),
            'date_added': data.get('date_added'),
            'tags': data.get('tags') or [],
            'reporter': data.get('reporter'),
            'message': f'URLhaus: {data.get("threat")} ({data.get("url_status")})',
        }

    def _lookup_host(self, host):
        resp = self._safe_request(
            'POST', f'{self.API}host/', headers=self._headers(), data={'host': host},
        )
        if resp is None or resp.status_code != 200:
            return {'success': False, 'message': f'HTTP {resp.status_code if resp else "?"}'}
        data = resp.json()
        if data.get('query_status') == 'no_results':
            return {'success': True, 'source': 'urlhaus', 'found': False, 'message': 'Host inconnu'}
        if data.get('query_status') != 'ok':
            return {'success': False, 'message': f'Erreur: {data.get("query_status")}'}
        return {
            'success': True,
            'source': 'urlhaus',
            'found': True,
            'firstseen': data.get('firstseen'),
            'url_count': data.get('url_count'),
            'blacklists': data.get('blacklists') or {},
            'message': f'URLhaus host: {data.get("url_count")} URLs malveillantes',
        }

    def _lookup_payload(self, ioc_type, hash_value):
        key = 'md5_hash' if ioc_type == 'hash_md5' else 'sha256_hash'
        resp = self._safe_request(
            'POST', f'{self.API}payload/', headers=self._headers(), data={key: hash_value},
        )
        if resp is None or resp.status_code != 200:
            return {'success': False, 'message': f'HTTP {resp.status_code if resp else "?"}'}
        data = resp.json()
        if data.get('query_status') == 'no_results':
            return {'success': True, 'source': 'urlhaus', 'found': False, 'message': 'Payload inconnu'}
        if data.get('query_status') != 'ok':
            return {'success': False, 'message': f'Erreur: {data.get("query_status")}'}
        return {
            'success': True,
            'source': 'urlhaus',
            'found': True,
            'file_type': data.get('file_type'),
            'file_size': data.get('file_size'),
            'signature': data.get('signature'),
            'url_count': data.get('url_count'),
            'first_seen': data.get('firstseen'),
            'message': f'URLhaus payload: {data.get("signature") or "unknown"}',
        }
