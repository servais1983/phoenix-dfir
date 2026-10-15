"""
Phoenix DFIR - Base Connector
Classe abstraite pour tous les connecteurs d'integration
"""

import time
import requests


class BaseConnector:
    """Classe de base pour tous les connecteurs externes"""

    # Metadata du connecteur (a surcharger)
    CONNECTOR_ID = 'base'
    CONNECTOR_NAME = 'Base Connector'
    CONNECTOR_DESCRIPTION = ''
    CONNECTOR_ICON = 'plug'
    CONNECTOR_URL = ''
    CONNECTOR_CATEGORY = 'other'  # threat_intel, sandbox, siem, ticketing, rule_engine

    # Configuration requise (liste de dicts: {key, label, type, required, placeholder})
    CONFIG_SCHEMA = []

    def __init__(self, config=None):
        self.config = config or {}
        self._session = None

    @property
    def session(self):
        """Session HTTP reutilisable avec timeout par defaut"""
        if self._session is None:
            self._session = requests.Session()
            self._session.timeout = 30
            self._session.headers.update({
                'User-Agent': 'Phoenix-DFIR/3.0',
                'Accept': 'application/json',
            })
        return self._session

    def get_config(self, key, default=None):
        """Recuperer une valeur de configuration"""
        return self.config.get(key, default)

    def test_connection(self):
        """Tester la connexion au service (a surcharger)"""
        return {'success': False, 'message': 'Non implemente'}

    def push_iocs(self, iocs, investigation=None):
        """Envoyer des IoCs vers la plateforme (a surcharger)"""
        return {'success': False, 'message': 'Non supporte par ce connecteur'}

    def pull_iocs(self, query=None, limit=100):
        """Recuperer des IoCs depuis la plateforme (a surcharger)"""
        return {'success': False, 'message': 'Non supporte par ce connecteur'}

    def enrich_ioc(self, ioc_type, ioc_value):
        """Enrichir un IoC unique (a surcharger)"""
        return {'success': False, 'message': 'Non supporte par ce connecteur'}

    def search(self, query, **kwargs):
        """Recherche generique (a surcharger)"""
        return {'success': False, 'message': 'Non supporte par ce connecteur'}

    def get_capabilities(self):
        """Retourner les capacites de ce connecteur"""
        caps = []
        # Verifier quelles methodes sont surchargees
        for method_name in ('test_connection', 'push_iocs', 'pull_iocs', 'enrich_ioc', 'search'):
            method = getattr(type(self), method_name, None)
            base_method = getattr(BaseConnector, method_name, None)
            if method is not None and method is not base_method:
                caps.append(method_name)
        return caps

    def to_dict(self):
        """Serialiser les metadonnees du connecteur"""
        return {
            'id': self.CONNECTOR_ID,
            'name': self.CONNECTOR_NAME,
            'description': self.CONNECTOR_DESCRIPTION,
            'icon': self.CONNECTOR_ICON,
            'url': self.CONNECTOR_URL,
            'category': self.CONNECTOR_CATEGORY,
            'config_schema': self.CONFIG_SCHEMA,
            'capabilities': self.get_capabilities(),
        }

    def _safe_request(self, method, url, **kwargs):
        """Requete HTTP avec gestion d'erreurs standardisee"""
        try:
            resp = self.session.request(method, url, **kwargs)
            resp.raise_for_status()
            return resp
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.HTTPError:
            return resp
