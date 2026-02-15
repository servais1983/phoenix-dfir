"""
Phoenix DFIR - MISP Connector
Integration avec MISP (Malware Information Sharing Platform)
Push/Pull IoCs, creation d'evenements, recherche d'attributs
"""

from integrations.base import BaseConnector
from integrations import registry


@registry.register
class MISPConnector(BaseConnector):
    CONNECTOR_ID = 'misp'
    CONNECTOR_NAME = 'MISP'
    CONNECTOR_DESCRIPTION = 'Malware Information Sharing Platform - Partage et correlation de Threat Intelligence'
    CONNECTOR_ICON = 'shield-alert'
    CONNECTOR_URL = 'https://www.misp-project.org'
    CONNECTOR_CATEGORY = 'threat_intel'

    CONFIG_SCHEMA = [
        {'key': 'url', 'label': 'URL du serveur MISP', 'type': 'url', 'required': True, 'placeholder': 'https://misp.example.com'},
        {'key': 'api_key', 'label': 'Cle API MISP', 'type': 'password', 'required': True, 'placeholder': 'Votre cle d\'automatisation MISP'},
        {'key': 'verify_ssl', 'label': 'Verifier SSL', 'type': 'boolean', 'required': False, 'placeholder': 'true'},
    ]

    # Mapping Phoenix IoC type -> MISP attribute type
    IOC_TYPE_MAP = {
        'ip': 'ip-dst',
        'domain': 'domain',
        'hash_md5': 'md5',
        'hash_sha1': 'sha1',
        'hash_sha256': 'sha256',
        'url': 'url',
        'email': 'email-src',
        'filename': 'filename',
        'registry_key': 'regkey',
        'cve': 'vulnerability',
    }

    # Mapping inverse MISP -> Phoenix
    MISP_TYPE_MAP = {v: k for k, v in IOC_TYPE_MAP.items()}

    def _headers(self):
        return {
            'Authorization': self.get_config('api_key', ''),
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

    def _base_url(self):
        url = self.get_config('url', '').rstrip('/')
        return url

    def _verify_ssl(self):
        val = self.get_config('verify_ssl', 'true')
        return str(val).lower() not in ('false', '0', 'no')

    def test_connection(self):
        """Tester la connexion MISP via /servers/getVersion"""
        url = self.get_config('url', '')
        api_key = self.get_config('api_key', '')
        if not url or not api_key:
            return {'success': False, 'message': 'URL et cle API requis'}

        resp = self._safe_request(
            'GET', f'{self._base_url()}/servers/getVersion.json',
            headers=self._headers(), verify=self._verify_ssl()
        )
        if resp is None:
            return {'success': False, 'message': 'Impossible de contacter le serveur MISP'}
        if resp.status_code == 200:
            data = resp.json()
            return {
                'success': True,
                'message': f'Connecte a MISP v{data.get("version", "?")}',
                'version': data.get('version'),
            }
        return {'success': False, 'message': f'Erreur MISP: HTTP {resp.status_code}'}

    def push_iocs(self, iocs, investigation=None):
        """Creer un evenement MISP et y ajouter les IoCs"""
        event_info = 'Phoenix DFIR Export'
        if investigation:
            event_info = f"Phoenix DFIR - {investigation.get('name', 'Investigation')}"

        # Construire les attributs MISP
        attributes = []
        for ioc in iocs:
            misp_type = self.IOC_TYPE_MAP.get(ioc.get('type'))
            if not misp_type:
                continue
            attr = {
                'type': misp_type,
                'value': ioc['value'],
                'comment': f"Source: {ioc.get('source', 'phoenix-dfir')}",
                'to_ids': True,
                'category': 'Network activity' if ioc['type'] in ('ip', 'domain', 'url') else 'Payload delivery',
            }
            attributes.append(attr)

        if not attributes:
            return {'success': False, 'message': 'Aucun IoC compatible MISP'}

        # Creer l'evenement
        event_payload = {
            'Event': {
                'info': event_info,
                'distribution': 0,  # Organisation uniquement
                'threat_level_id': 2,  # Medium
                'analysis': 1,  # Ongoing
                'Attribute': attributes,
            }
        }

        resp = self._safe_request(
            'POST', f'{self._base_url()}/events/add',
            headers=self._headers(), json=event_payload, verify=self._verify_ssl()
        )

        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion MISP'}
        if resp.status_code in (200, 201):
            data = resp.json()
            event_id = data.get('Event', {}).get('id')
            return {
                'success': True,
                'message': f'{len(attributes)} IoCs envoyes vers MISP (Event #{event_id})',
                'event_id': event_id,
                'count': len(attributes),
            }
        return {'success': False, 'message': f'Erreur MISP: HTTP {resp.status_code}'}

    def pull_iocs(self, query=None, limit=100):
        """Rechercher des IoCs dans MISP"""
        search_payload = {
            'returnFormat': 'json',
            'limit': limit,
            'enforceWarninglist': True,
        }
        if query:
            search_payload['value'] = query

        resp = self._safe_request(
            'POST', f'{self._base_url()}/attributes/restSearch',
            headers=self._headers(), json=search_payload, verify=self._verify_ssl()
        )

        if resp is None:
            return {'success': False, 'message': 'Erreur de connexion MISP'}
        if resp.status_code == 200:
            data = resp.json()
            attributes = data.get('response', {}).get('Attribute', [])

            iocs = []
            for attr in attributes[:limit]:
                phoenix_type = self.MISP_TYPE_MAP.get(attr.get('type'))
                if phoenix_type:
                    iocs.append({
                        'type': phoenix_type,
                        'value': attr.get('value', ''),
                        'source': f"misp-event-{attr.get('event_id', '?')}",
                        'tags': [t.get('name', '') for t in attr.get('Tag', [])],
                    })

            return {
                'success': True,
                'iocs': iocs,
                'total': len(iocs),
                'message': f'{len(iocs)} IoCs recuperes depuis MISP',
            }
        return {'success': False, 'message': f'Erreur MISP: HTTP {resp.status_code}'}

    def search(self, query, **kwargs):
        """Recherche MISP par valeur d'attribut"""
        return self.pull_iocs(query=query, limit=kwargs.get('limit', 50))
