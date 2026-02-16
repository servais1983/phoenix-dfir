"""
Phoenix DFIR - Shodan Connector
Recherche d'informations sur les hotes et services exposes
"""

from integrations.base import BaseConnector
from integrations import registry


@registry.register
class ShodanConnector(BaseConnector):
    CONNECTOR_ID = 'shodan'
    CONNECTOR_NAME = 'Shodan'
    CONNECTOR_DESCRIPTION = 'Moteur de recherche pour appareils connectes - Ports, services, vulnerabilites'
    CONNECTOR_ICON = 'radar'
    CONNECTOR_URL = 'https://www.shodan.io'
    CONNECTOR_CATEGORY = 'threat_intel'

    CONFIG_SCHEMA = [
        {'key': 'api_key', 'label': 'Cle API Shodan', 'type': 'password', 'required': True, 'placeholder': 'Votre cle API Shodan'},
    ]

    API_URL = 'https://api.shodan.io'

    def test_connection(self):
        """Verifier la cle API Shodan"""
        api_key = self.get_config('api_key', '')
        if not api_key:
            return {'success': False, 'message': 'Cle API requise'}

        resp = self._safe_request(
            'GET', f'{self.API_URL}/api-info',
            params={'key': api_key}
        )
        if resp is None:
            return {'success': False, 'message': 'Impossible de contacter Shodan'}
        if resp.status_code == 200:
            data = resp.json()
            return {
                'success': True,
                'message': f'Connecte (credits restants: {data.get("query_credits", 0)})',
                'plan': data.get('plan', 'free'),
            }
        return {'success': False, 'message': f'Erreur: HTTP {resp.status_code}'}

    def enrich_ioc(self, ioc_type, ioc_value):
        """Enrichir une IP via Shodan"""
        if ioc_type not in ('ip', 'domain'):
            return {'success': False, 'message': 'Shodan supporte IPs et domaines'}

        api_key = self.get_config('api_key', '')

        if ioc_type == 'ip':
            resp = self._safe_request(
                'GET', f'{self.API_URL}/shodan/host/{ioc_value}',
                params={'key': api_key}
            )
        else:
            resp = self._safe_request(
                'GET', f'{self.API_URL}/dns/resolve',
                params={'key': api_key, 'hostnames': ioc_value}
            )

        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}

        if resp.status_code == 200:
            data = resp.json()
            if ioc_type == 'ip':
                ports = data.get('ports', [])
                vulns = data.get('vulns', [])
                return {
                    'success': True,
                    'source': 'shodan',
                    'os': data.get('os'),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'country_code': data.get('country_code', ''),
                    'city': data.get('city', ''),
                    'ports': ports,
                    'vulns': vulns[:20],
                    'hostnames': data.get('hostnames', []),
                    'last_update': data.get('last_update'),
                    'message': f'{len(ports)} ports ouverts, {len(vulns)} vulns',
                }
            else:
                return {
                    'success': True,
                    'source': 'shodan',
                    'resolved_ips': data,
                    'message': f'Domaine resolu: {data}',
                }
        if resp.status_code == 404:
            return {'success': True, 'source': 'shodan', 'message': 'Hote non trouve dans Shodan'}
        return {'success': False, 'message': f'Erreur: HTTP {resp.status_code}'}

    def search(self, query, **kwargs):
        """Recherche Shodan"""
        api_key = self.get_config('api_key', '')
        resp = self._safe_request(
            'GET', f'{self.API_URL}/shodan/host/search',
            params={'key': api_key, 'query': query, 'page': kwargs.get('page', 1)}
        )
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}
        if resp.status_code == 200:
            data = resp.json()
            return {
                'success': True,
                'total': data.get('total', 0),
                'results': [{'ip': m.get('ip_str'), 'port': m.get('port'), 'org': m.get('org')} for m in data.get('matches', [])[:50]],
            }
        return {'success': False, 'message': f'Erreur: HTTP {resp.status_code}'}
