"""
Phoenix DFIR - Integrations Framework
Connecteurs vers les plateformes externes de Threat Intelligence et DFIR
"""

from integrations.registry import IntegrationRegistry

registry = IntegrationRegistry()

# Importer tous les connecteurs pour qu'ils s'enregistrent automatiquement
from integrations.misp_connector import MISPConnector
from integrations.cortex_connector import CortexConnector
from integrations.virustotal_connector import VirusTotalConnector
from integrations.abuseipdb_connector import AbuseIPDBConnector
from integrations.shodan_connector import ShodanConnector
from integrations.otx_connector import OTXConnector
from integrations.yara_connector import YARAConnector
from integrations.sigma_connector import SigmaConnector
