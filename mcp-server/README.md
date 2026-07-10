# Phoenix DFIR MCP — Enquêteur DFIR autonome piloté par GitHub Copilot

Serveur **MCP** (Model Context Protocol) exposant la boîte à outils forensique
de Phoenix, orchestrable automatiquement par **GitHub Copilot** : un véritable
enquêteur DFIR supplémentaire, capable de résoudre un cas seul, rapidement,
quel que soit le format des artefacts (EVTX, CSV, JSON, logs, Prefetch, LNK,
historiques navigateurs, ruches registre...).

## Deux modes d'utilisation

### 1. Mode agent — GitHub Copilot orchestre les outils (VS Code)

Le dépôt inclut `.vscode/mcp.json` : ouvrez le projet dans VS Code avec GitHub
Copilot, activez le **mode agent** dans Copilot Chat, et le serveur
`phoenix-dfir` apparaît avec tous ses outils. Demandez par exemple :

> *« Investigue le dossier `./cases/incident-42` et rédige le rapport complet. »*

Copilot appelle alors lui-même `list_artifacts`, `parse_evtx`, `sigma_scan`,
`extract_iocs`, `virustotal_lookup`, `run_zimmermann`... jusqu'au
`save_report` final.

### 2. Mode autonome — l'enquêteur résout le cas seul (CLI)

```bash
cd mcp-server
export GITHUB_TOKEN="github_pat_..."   # permission "Models: read"
python -m phoenix_dfir_mcp investigate /chemin/du/cas \
  -q "Suspicion de ransomware, poste DESKTOP-A12" \
  -m openai/gpt-4o        # optionnel
```

GitHub Copilot (API GitHub Models, *function calling*) mène l'enquête en
boucle agentique : inventaire → parsing de chaque artefact → détection Sigma →
corrélation d'IoCs → enrichissement VirusTotal → timeline → mapping MITRE
ATT&CK → **rapport Markdown sauvegardé dans le dossier du cas**.

Autres commandes :

```bash
python -m phoenix_dfir_mcp tools   # lister les outils exposés
python -m phoenix_dfir_mcp serve   # démarrer le serveur MCP stdio manuellement
```

## Outils exposés

| Outil | Rôle |
|---|---|
| `list_artifacts` | Inventaire récursif du cas (types, tailles, MD5/SHA256) |
| `analyze_artifact` | Analyse automatique quel que soit le format |
| `parse_evtx` | Journaux Windows EVTX + mapping MITRE |
| `parse_csv` / `parse_json_file` / `parse_log_file` | Formats tabulaires, JSON, logs texte |
| `parse_prefetch` / `parse_lnk` / `parse_browser_history` | Preuves d'exécution et d'accès |
| `extract_iocs` | IPs, domaines, URLs, hashes, emails, CVE |
| `sigma_scan` | 26 règles Sigma intégrées (brute force, PtH, Kerberoasting, LSASS...) |
| `mitre_map_events` | Event IDs → tactiques/techniques ATT&CK |
| `virustotal_lookup` | Enrichissement d'IoC (nécessite `API_KEY_VT`) |
| `zimmermann_status` / `run_zimmermann` | Outils Eric Zimmermann (voir ci-dessous) |
| `set_investigation_plan` / `complete_plan_step` | Plan d'enquête décomposé et suivi |
| `record_finding` | Consigner un constat lié à une preuve (sévérité, MITRE, confiance) |
| `set_hypothesis` | Former / confirmer / réfuter une hypothèse |
| `verify_finding` | Statuer la vérification d'un constat (vérifié / non vérifié / réfuté) |
| `get_case_state` | Restituer plan, constats et hypothèses accumulés |
| `save_report` | Rapport d'enquête Markdown final (annexe la synthèse mémoire) |

### Intelligence d'enquête

L'enquêteur ne se contente pas d'enchaîner des outils. Il applique une
méthodologie DFIR structurée :

- **Planification** : décomposition du cas en 3-7 étapes avant la collecte,
  suivies jusqu'à complétion (évite le « scope creep »).
- **Mémoire d'enquête** (`case_state.json` dans le dossier du cas) : constats
  horodatés et hypothèses accumulés — l'enquête tient sur de gros cas
  multi-artefacts sans saturer la fenêtre de contexte.
- **Vérification indépendante** : après l'investigation, une passe en lecture
  seule re-contrôle chaque constat contre la preuve brute à la source et le
  statue *vérifié / non vérifié / réfuté* (réduit les faux positifs). Les
  constats non reproduits sont marqués `unverified` par prudence.
- **Monitoring d'exécution** : si le même outil est rejoué à l'identique ou
  si des outils échouent en série, un conseil correctif est injecté (mentor).
- **Revue adviser** : une passe critique vérifie que chaque conclusion est
  étayée et que timeline / IoCs / MITRE / recommandations sont présents ;
  relance l'enquêteur si des lacunes subsistent (borné à 2 revues).
- **Sandboxing** (`PHOENIX_TOOL_ROOTS`) : les outils de lecture sont confinés à
  l'arborescence du cas — tout accès hors des racines autorisées est refusé
  (protège contre la lecture de fichiers sensibles). L'enquêteur enregistre
  automatiquement le dossier du cas comme racine autorisée.
- **Observabilité** : tokens consommés, appels LLM, constats vérifiés et
  verdict de revue sont remontés (métriques exposées dans l'UI et le CLI).

## Outils Eric Zimmermann (EZ Tools)

`run_zimmermann` exécute les outils de référence d'Eric Zimmermann avec sortie
CSV parsée : **EvtxECmd, PECmd, LECmd, JLECmd, MFTECmd, AmcacheParser,
AppCompatCacheParser, RECmd, SBECmd, SrumECmd, SQLECmd, WxTCmd**.

Installation :

1. Téléchargez les EZ Tools : <https://ericzimmerman.github.io/> (script
   `Get-ZimmermanTools`).
2. Définissez `EZ_TOOLS_PATH` vers le dossier d'installation.
3. Sous Linux/macOS, installez le runtime **dotnet** (les outils sont des
   binaires .NET multiplateformes).

Sans EZ Tools, l'enquêteur bascule automatiquement sur les parsers natifs
Phoenix — l'investigation reste entièrement fonctionnelle.

## Configuration

| Variable | Rôle |
|---|---|
| `GITHUB_TOKEN` / `PHOENIX_GITHUB_TOKEN` | Jeton GitHub (permission *Models: read*) — **obligatoire** pour le mode autonome |
| `PHOENIX_GITHUB_MODEL` | Modèle GitHub Models (défaut `openai/gpt-4o-mini`) |
| `API_KEY_VT` | Clé VirusTotal pour l'enrichissement d'IoCs (optionnel) |
| `EZ_TOOLS_PATH` | Dossier des outils Eric Zimmermann (optionnel) |

Dépendances : `pip install -r requirements.txt` (+ `python-evtx` pour le
parsing EVTX natif). Le protocole MCP est implémenté nativement (JSON-RPC
stdio) : aucune dépendance MCP externe.

## Compatibilité clients MCP

Le serveur parle le protocole MCP standard sur stdio : GitHub Copilot (VS
Code, mode agent), mais aussi tout autre client MCP. Exemple de déclaration
générique :

```json
{
  "command": "python",
  "args": ["-m", "phoenix_dfir_mcp", "serve"],
  "cwd": "<repo>/mcp-server"
}
```

## Sécurité

Le serveur lit les fichiers locaux qui lui sont désignés et peut exécuter les
EZ Tools : ne l'exposez qu'à des clients de confiance, sur des copies de
travail de vos preuves (jamais les originaux), conformément à vos procédures
de chaîne de custody.
