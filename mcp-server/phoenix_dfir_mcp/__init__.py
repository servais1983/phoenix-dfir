"""Phoenix DFIR MCP - Serveur MCP + enqueteur DFIR autonome pilote par GitHub Copilot.

Expose la boite a outils forensique de Phoenix (parsers natifs EVTX/CSV/JSON/
logs/Prefetch/LNK/navigateurs, extraction d'IoCs, regles Sigma, mapping MITRE
ATT&CK, VirusTotal, outils Eric Zimmermann) :

- comme serveur MCP stdio, orchestrable par GitHub Copilot (mode agent) ;
- comme enqueteur autonome, ou GitHub Copilot (API GitHub Models) choisit
  lui-meme les outils en boucle agentique jusqu'au rapport final.
"""

__version__ = "1.0.0"
