"""
Phoenix DFIR - Cortex Connector
Integration avec Cortex (TheHive Project) pour l'analyse automatisee
Lancement d'analyzers et recuperation de rapports
"""

from integrations.base import BaseConnector
from integrations import registry


@registry.register
class CortexConnector(BaseConnector):
    CONNECTOR_ID = 'cortex'
    CONNECTOR_NAME = 'Cortex'
    CONNECTOR_DESCRIPTION = 'Moteur d\'analyse automatisee - Lancez des analyzers sur vos observables'
    CONNECTOR_ICON = 'brain'
    CONNECTOR_URL = 'https://thehive-project.org'
    CONNECTOR_CATEGORY = 'sandbox'

    CONFIG_SCHEMA = [
        {'key': 'url', 'label': 'URL du serveur Cortex', 'type': 'url', 'required': True, 'placeholder': 'https://cortex.example.com'},
        {'key': 'api_key', 'label': 'Cle API Cortex', 'type': 'password', 'required': True, 'placeholder': 'Votre cle API Cortex'},
    ]

    # Mapping Phoenix IoC type -> Cortex data type
    DATATYPE_MAP = {
        'ip': 'ip',
        'domain': 'domain',
        'hash_md5': 'hash',
        'hash_sha1': 'hash',
        'hash_sha256': 'hash',
        'url': 'url',
        'email': 'mail',
        'filename': 'filename',
        'registry_key': 'registry',
    }

    def _headers(self):
        return {
            'Authorization': f'Bearer {self.get_config("api_key", "")}',
            'Content-Type': 'application/json',
        }

    def _base_url(self):
        return self.get_config('url', '').rstrip('/')

    def test_connection(self):
        """Tester la connexion Cortex via /api/status"""
        url = self.get_config('url', '')
        api_key = self.get_config('api_key', '')
        if not url or not api_key:
            return {'success': False, 'message': 'URL et cle API requis'}

        resp = self._safe_request(
            'GET', f'{self._base_url()}/api/status',
            headers=self._headers()
        )
        if resp is None:
            return {'success': False, 'message': 'Impossible de contacter Cortex'}
        if resp.status_code == 200:
            data = resp.json()
            return {
                'success': True,
                'message': f'Connecte a Cortex (v{data.get("versions", {}).get("Cortex", "?")})',
                'analyzers': data.get('config', {}).get('analysisCount', 0),
            }
        return {'success': False, 'message': f'Erreur Cortex: HTTP {resp.status_code}'}

    def enrich_ioc(self, ioc_type, ioc_value):
        """Lancer tous les analyzers disponibles pour cet observable"""
        cortex_type = self.DATATYPE_MAP.get(ioc_type)
        if not cortex_type:
            return {'success': False, 'message': f'Type {ioc_type} non supporte par Cortex'}

        # Lister les analyzers compatibles
        resp = self._safe_request(
            'GET', f'{self._base_url()}/api/analyzer/type/{cortex_type}',
            headers=self._headers()
        )
        if resp is None or resp.status_code != 200:
            return {'success': False, 'message': 'Impossible de recuperer les analyzers'}

        analyzers = resp.json()
        if not analyzers:
            return {'success': False, 'message': f'Aucun analyzer pour le type {cortex_type}'}

        # Lancer le premier analyzer disponible
        analyzer_id = analyzers[0].get('id')
        job_payload = {
            'data': ioc_value,
            'dataType': cortex_type,
            'tlp': 2,
            'pap': 2,
        }

        resp = self._safe_request(
            'POST', f'{self._base_url()}/api/analyzer/{analyzer_id}/run',
            headers=self._headers(), json=job_payload
        )

        if resp is None:
            return {'success': False, 'message': 'Erreur lors du lancement de l\'analyse'}
        if resp.status_code in (200, 201):
            data = resp.json()
            return {
                'success': True,
                'message': f'Analyse lancee avec {analyzers[0].get("name", analyzer_id)}',
                'job_id': data.get('id'),
                'analyzer': analyzers[0].get('name'),
                'available_analyzers': [a.get('name') for a in analyzers],
            }
        return {'success': False, 'message': f'Erreur Cortex: HTTP {resp.status_code}'}

    def search(self, query, **kwargs):
        """Lister les analyzers disponibles"""
        resp = self._safe_request(
            'GET', f'{self._base_url()}/api/analyzer',
            headers=self._headers()
        )
        if resp is None or resp.status_code != 200:
            return {'success': False, 'message': 'Erreur de connexion'}

        analyzers = resp.json()
        return {
            'success': True,
            'analyzers': [{'id': a.get('id'), 'name': a.get('name'), 'dataTypeList': a.get('dataTypeList', [])} for a in analyzers],
            'total': len(analyzers),
        }
