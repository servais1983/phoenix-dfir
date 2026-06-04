"""
Phoenix DFIR - ThreatFox (abuse.ch) Connector
IoCs lies aux campagnes malware actives.
https://threatfox.abuse.ch/api/
"""

from integrations.base import BaseConnector
from integrations import registry


@registry.register
class ThreatFoxConnector(BaseConnector):
    CONNECTOR_ID = 'threatfox'
    CONNECTOR_NAME = 'ThreatFox'
    CONNECTOR_DESCRIPTION = 'IoCs malware activement traques (abuse.ch)'
    CONNECTOR_ICON = 'bug'
    CONNECTOR_URL = 'https://threatfox.abuse.ch'
    CONNECTOR_CATEGORY = 'threat_intel'

    CONFIG_SCHEMA = [
        {'key': 'auth_key', 'label': 'Auth-Key abuse.ch', 'type': 'password', 'required': True,
         'placeholder': 'Compte gratuit sur auth.abuse.ch'},
    ]

    API = 'https://threatfox-api.abuse.ch/api/v1/'

    # Mapping Phoenix type -> ThreatFox ioc_type
    TYPE_MAP = {
        'ip': 'ip:port',
        'domain': 'domain',
        'url': 'url',
        'hash_md5': 'md5_hash',
        'hash_sha1': 'sha1_hash',
        'hash_sha256': 'sha256_hash',
    }

    def _headers(self):
        return {
            'Auth-Key': self.get_config('auth_key', ''),
            'Content-Type': 'application/json',
        }

    def test_connection(self):
        if not self.get_config('auth_key', ''):
            return {'success': False, 'message': 'Auth-Key requise'}
        resp = self._safe_request(
            'POST', self.API, headers=self._headers(),
            json={'query': 'taginfo', 'tag': 'TestTag', 'limit': 1},
        )
        if resp is None:
            return {'success': False, 'message': 'Impossible de contacter ThreatFox'}
        if resp.status_code == 200:
            data = resp.json()
            if data.get('query_status') in ('ok', 'no_result'):
                return {'success': True, 'message': 'ThreatFox accessible'}
            if data.get('query_status') == 'illegal_auth':
                return {'success': False, 'message': 'Auth-Key invalide'}
        return {'success': False, 'message': f'HTTP {resp.status_code}'}

    def enrich_ioc(self, ioc_type, ioc_value):
        tf_type = self.TYPE_MAP.get(ioc_type)
        if not tf_type:
            return {'success': False, 'message': f'Type {ioc_type} non supporte'}

        resp = self._safe_request(
            'POST', self.API, headers=self._headers(),
            json={'query': 'search_ioc', 'search_term': ioc_value, 'exact_match': True},
        )
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}
        if resp.status_code != 200:
            return {'success': False, 'message': f'HTTP {resp.status_code}'}

        data = resp.json()
        status = data.get('query_status')
        if status == 'no_result':
            return {
                'success': True, 'source': 'threatfox', 'matches': 0,
                'message': 'Non trouve dans ThreatFox',
            }
        if status != 'ok':
            return {'success': False, 'message': f'Erreur ThreatFox: {status}'}

        results = data.get('data', [])
        return {
            'success': True,
            'source': 'threatfox',
            'matches': len(results),
            'malware_families': list({r.get('malware_printable', 'unknown') for r in results}),
            'tags': list({tag for r in results for tag in (r.get('tags') or [])}),
            'confidence_max': max((r.get('confidence_level', 0) for r in results), default=0),
            'first_seen': min((r.get('first_seen', '') for r in results), default=''),
            'message': f'ThreatFox: {len(results)} match(es)',
        }

    def pull_iocs(self, query=None, limit=100):
        """Recupere les IoCs recents (last 7 days par defaut)."""
        days = 7 if limit <= 100 else 30
        resp = self._safe_request(
            'POST', self.API, headers=self._headers(),
            json={'query': 'get_iocs', 'days': days},
        )
        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion'}
        if resp.status_code != 200:
            return {'success': False, 'message': f'HTTP {resp.status_code}'}

        data = resp.json()
        if data.get('query_status') != 'ok':
            return {'success': False, 'message': f'Erreur: {data.get("query_status")}'}

        # Convertir au format Phoenix
        reverse_map = {v: k for k, v in self.TYPE_MAP.items()}
        iocs = []
        for entry in (data.get('data') or [])[:limit]:
            tf_type = entry.get('ioc_type', '')
            phoenix_type = reverse_map.get(tf_type)
            if not phoenix_type:
                continue
            iocs.append({
                'type': phoenix_type,
                'value': entry.get('ioc', ''),
                'source': 'threatfox',
                'severity': 'high' if entry.get('confidence_level', 0) >= 75 else 'medium',
                'metadata': {
                    'malware': entry.get('malware_printable'),
                    'first_seen': entry.get('first_seen'),
                    'tags': entry.get('tags'),
                    'confidence': entry.get('confidence_level'),
                },
            })

        return {
            'success': True,
            'iocs': iocs,
            'total': len(iocs),
            'message': f'{len(iocs)} IoC(s) ThreatFox importes ({days}j)',
        }
