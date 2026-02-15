"""
Phoenix DFIR - Integration Registry
Registre central des connecteurs disponibles
"""


class IntegrationRegistry:
    """Registre de tous les connecteurs d'integration"""

    def __init__(self):
        self._connectors = {}

    def register(self, connector_class):
        """Enregistrer un connecteur"""
        self._connectors[connector_class.CONNECTOR_ID] = connector_class
        return connector_class

    def get_connector_class(self, connector_id):
        """Recuperer la classe d'un connecteur"""
        return self._connectors.get(connector_id)

    def create_instance(self, connector_id, config=None):
        """Creer une instance configuree d'un connecteur"""
        cls = self.get_connector_class(connector_id)
        if cls is None:
            return None
        return cls(config=config)

    def list_connectors(self):
        """Lister tous les connecteurs disponibles"""
        return [cls(config={}).to_dict() for cls in self._connectors.values()]

    def get_connector_ids(self):
        """Retourner les IDs de tous les connecteurs"""
        return list(self._connectors.keys())
