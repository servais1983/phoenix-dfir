<p align="center">
  <img src="phoenix.png" alt="Phoenix DFIR" width="180" />
</p>

<h1 align="center">Phoenix DFIR</h1>

<p align="center">
  <strong>Plateforme d'investigation numerique et de reponse aux incidents,<br/>
  avec un enqueteur IA autonome dont chaque conclusion est prouvee.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.10-orange?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/tests-341%20passed-brightgreen?style=flat-square" alt="Tests" />
  <img src="https://img.shields.io/badge/MCP-39%20outils-purple?style=flat-square" alt="Outils MCP" />
  <img src="https://img.shields.io/badge/LLM-Ollama%20%7C%20OpenAI%20%7C%20GitHub%20Models-black?style=flat-square" alt="LLM" />
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/react-19-blue?style=flat-square&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/docker-ready-blue?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="Licence" />
</p>

<p align="center">
  <a href="#demarrage-rapide">Demarrage rapide</a> ·
  <a href="#lenqueteur-autonome">Enqueteur autonome</a> ·
  <a href="#couverture-forensique">Couverture</a> ·
  <a href="#modele-de-confiance">Confiance</a> ·
  <a href="#evaluation">Evaluation</a> ·
  <a href="#api-rest">API</a> ·
  <a href="#architecture">Architecture</a>
</p>

---

## En bref

Phoenix DFIR transforme un dossier d'evidences — journaux EVTX, dumps memoire,
**images disque**, logs, artefacts d'execution — en un rapport d'enquete
argumente, horodate et verifiable.

- **Un enqueteur autonome en cinq phases**, chacune validee par une porte
  qualite deterministe : aucune phase n'est close sur la seule parole du LLM.
- **Zero constat sans preuve** : chaque conclusion cite un RecordID EVTX, un
  PID, une ligne de log, une ligne CSV ou un inode reellement observe par un
  outil deterministe ; un identifiant invente est rejete.
- **Chaine de preuve SHA-256** : acquisitions, executions d'outils, constats et
  decisions sont scelles dans un registre chaine ; toute alteration est detectee.
- **L'humain decide** : les actions de confinement sont proposees, jamais
  executees, et attendent la validation d'un analyste.
- **Souverainete des donnees** : fonctionne entierement en local avec Ollama ;
  OpenAI et GitHub Models sont optionnels.
- **Mesurable** : un banc d'evaluation annote (techniques ATT&CK, IoCs, faits
  exacts, faux positifs) sert de garde-fou de non-regression.

---

## Sommaire

1. [L'enqueteur autonome](#lenqueteur-autonome)
2. [Couverture forensique](#couverture-forensique)
3. [Modele de confiance](#modele-de-confiance)
4. [Console Enqueteur DFIR](#console-enqueteur-dfir)
5. [Plateforme d'investigation](#plateforme-dinvestigation)
6. [Evaluation](#evaluation)
7. [Demarrage rapide](#demarrage-rapide)
8. [Configuration](#configuration)
9. [API REST](#api-rest)
10. [Architecture](#architecture)
11. [Qualite et CI](#qualite-et-ci)
12. [Contribution et licence](#contribution)

---

## L'enqueteur autonome

Deposez les evidences d'un cas — par glisser-deposer, dans le dossier surveille
ou dans le coffre en lecture seule — et l'enqueteur conduit l'investigation de
bout en bout. Il s'appuie sur un serveur **MCP** (Model Context Protocol)
exposant **39 outils forensiques**, utilisable aussi bien en autonomie que
depuis un client MCP (mode agent de VS Code inclus via `.vscode/mcp.json`).

### Cinq phases, cinq portes

| Phase | Objectif | Porte qualite (deterministe) |
|---|---|---|
| **1. Inventaire** | Recenser les artefacts, identifier les images disque et dumps memoire, poser un plan | Plan d'enquete enregistre |
| **2. Extraction** | Passer chaque artefact dans ses outils applicables ; extraire les artefacts des images disque ; alimenter la super-timeline | Chaque artefact traite, sorties indexees |
| **3. Correlation** | Relier les evenements, former des hypotheses, consigner des constats cites et mappes ATT&CK — ou conclure explicitement a l'absence d'incident | Constats references et mappes, ou `declare_no_incident` |
| **4. Contre-analyse** | Confronter chaque constat critique ou eleve a une hypothese alternative ; auditer la couverture des outils et des preuves | Constats statues (maintenu / affaibli / ecarte), audits executes |
| **5. Rapport** | Rediger le rapport, generer le calque ATT&CK Navigator et le CSV d'IoCs | Sections obligatoires presentes |

Chaque phase dispose de ses propres consignes et d'une **liste blanche
d'outils**. Si sa porte echoue, la phase est relancee avec la liste exacte des
lacunes (deux relances au plus) ; au-dela, l'enquete se poursuit avec des
resultats partiels explicitement signales. Chaque porte est scellee dans la
chaine de preuve.

### Methode d'enquete

- **Briefing** — un fichier `PHOENIX.md` (contexte, perimetre, questions) depose
  avec les preuves oriente chacune des phases.
- **Super-timeline** — toutes les sorties d'outils sont normalisees (horodatage
  UTC, hote, utilisateur, processus, references) dans un index **SQLite FTS5**
  interrogeable (`search_evidence`, `get_timeline`, `list_sources`).
- **Memoire d'enquete** — plan, constats et hypotheses sont persistes dans le
  dossier du cas : l'enquete tient sur des cas volumineux sans saturer le
  contexte du modele.
- **Verification independante** — une passe en lecture seule re-confronte
  chaque constat a la preuve brute et le statue *verifie*, *non verifie* ou
  *refute*.
- **Surveillance d'execution** — detection des boucles et des erreurs
  repetees, avec consignes correctives injectees.
- **Rapport de secours** — si le modele echoue a rediger, un rapport
  deterministe est produit a partir de la memoire du cas.

### Trois facons de l'utiliser

| Mode | Usage |
|---|---|
| **Interface web** | Page *Enqueteur IA* : depot des evidences, journal en temps reel, metriques (constats, tokens, portes), rapport et exports telechargeables |
| **Dossier surveille** | `backend/evidence_inbox/` : un sous-dossier depose = un cas cree et resolu automatiquement |
| **Ligne de commande** | `python -m phoenix_dfir_mcp investigate <dossier_du_cas>` |

Documentation detaillee : [`mcp-server/README.md`](mcp-server/README.md).

---

## Couverture forensique

| Domaine | Formats | Capacites |
|---|---|---|
| **Journaux Windows** | EVTX | Parser natif avec mapping MITRE, 27 regles Sigma integrees, timeline de detection Hayabusa |
| **Memoire vive** | raw, mem, vmem, dmp, lime | Volatility 3 : pslist/pstree, cmdline, malfind, netscan, svcscan... (plugins en liste blanche) |
| **Images disque** | E01/Ex01, dd/raw/img/001, VMDK, VHD/VHDX, AFF | The Sleuth Kit **sans montage** : partitions, arborescence, **fichiers supprimes**, timeline **MACB**, extraction ciblee d'artefacts avec SHA-256 |
| **Artefacts Windows** | Prefetch, LNK, $MFT, ruches, Amcache, SRUM, Jump Lists | Parsers natifs + EvtxECmd, PECmd, LECmd, JLECmd, MFTECmd, AmcacheParser, AppCompatCacheParser, RECmd, SBECmd, SrumECmd, SQLECmd, WxTCmd |
| **Navigateurs** | Historiques Chromium / Firefox (SQLite) | URLs visitees, telechargements, horodatages |
| **Logs et donnees** | LOG, syslog, auth.log, CSV, JSON, XML | Parsing generique, horodatages multi-formats, references par ligne |
| **Reseau** | PCAP | Inventaire et extraction d'indicateurs |
| **Indicateurs** | Tous formats texte | Extraction IP, domaines, URLs, hashes, emails, CVE ; enrichissement VirusTotal |

### Images disque : du conteneur a la preuve

1. `disk_image_info` — table de partitions, offset et type de chaque systeme de fichiers.
2. `disk_list_files` — arborescence d'une partition, filtre de chemin, fichiers supprimes.
3. `disk_timeline` — timeline MACB indexee dans la super-timeline.
4. `disk_extract_artifacts` — profils `windows`, `linux` ou `auto` (EVTX, ruches,
   Amcache, Prefetch, taches planifiees, SRUM, NTUSER/UsrClass, LNK, historique
   PowerShell, historiques navigateur, $MFT, journaux Linux, crontabs, cles SSH,
   services systemd). Chaque fichier extrait est hache (SHA-256) et consigne dans
   `extraction_manifest.json`, puis analyse comme n'importe quel artefact du cas.

L'image originale n'est jamais montee ni modifiee. Les constats issus du
systeme de fichiers citent l'**inode** (y compris composite NTFS, ex. `128-128-1`).

---

## Modele de confiance

Les artefacts d'une enquete sont, par nature, controles par l'attaquant.
Phoenix est concu pour que le LLM ne puisse ni etre manipule par eux, ni
affirmer ce qu'il n'a pas observe.

| Garantie | Mecanisme |
|---|---|
| **Constats ancres** | `record_finding` exige des references (`record_id`, `pid`, `line`, `row`, `inode`) validees contre l'index des identifiants reellement produits par les outils (`PHOENIX_STRICT_EVIDENCE`) |
| **Resistance a l'injection** | Chaque sortie d'outil est nettoyee (caracteres invisibles, inversions bidirectionnelles), les formulations d'injection FR/EN et jetons de role sont neutralises, puis la sortie est encapsulee comme donnee non fiable avec un nonce. La tentative devient un constat d'anti-forensique |
| **Integrite des preuves** | Coffre monte en lecture seule ; images disque jamais montees ; empreintes MD5/SHA1/SHA256 a l'acquisition, SHA-256 par fichier extrait |
| **Tracabilite** | Registre append-only chaine par SHA-256 ; `GET /api/custody/verify` detecte alteration, suppression ou insertion |
| **Controle humain** | Les remediations restent `WAITING_APPROVAL` jusqu'a la decision d'un analyste ; Phoenix ne les execute jamais |
| **Confinement des outils** | Les outils pilotes par le LLM sont limites a l'arborescence du cas (`PHOENIX_TOOL_ROOTS`) ; plugins Volatility et commandes externes en liste blanche |
| **Confidentialite** | Mode 100 % local avec Ollama ; le fournisseur effectif est affiche en console |

---

## Console Enqueteur DFIR

Une console unique dediee a l'enqueteur :

- **Essaim d'agents** — Orchestrateur, Triage & Collecte, Disque & EVTX,
  Images disque, Memoire, Threat Intel — avec leur disponibilite reelle
  (outils installes, fournisseur LLM).
- **Chronologie temps reel** (WebSocket authentifie) — agent, action exacte,
  artefact, technique ATT&CK, severite, portes de phase.
- **Inspecteur de preuve** — empreinte du maillon, maillon precedent, empreinte
  de la sortie de l'outil.
- **Validation humaine** — approbation ou rejet motive des actions proposees,
  decision scellee.
- **Coffre de preuves** — rattachement sans copie d'evidences volumineuses
  (dumps memoire, images disque de plusieurs Go) a une enquete.
- **Verification d'integrite** de toute la chaine en un clic.

---

## Plateforme d'investigation

**Gestion des cas** — enquetes, artefacts, IoCs, timeline interactive, rapports
Markdown, export **STIX 2.1**, mapping **MITRE ATT&CK** natif.

**Detection** — 27 regles Sigma integrees sur 8 tactiques (acces aux
identifiants, evasion, persistance, execution, mouvement lateral, commande et
controle, impact...), seuils par regle, support YARA.

**Threat Intelligence** — 13 connecteurs configurables depuis l'interface :

| Connecteur | Capacites |
|---|---|
| MISP | Push / pull d'IoCs, recherche d'attributs, creation d'evenements |
| Cortex | Lancement d'analyzers sur observables |
| VirusTotal | Enrichissement IP, domaine, hash, URL |
| AbuseIPDB | Reputation IP, ISP, detection Tor |
| Shodan | Ports, services, vulnerabilites |
| AlienVault OTX | Pulses, enrichissement, abonnements |
| GreyNoise | Bruit Internet vs trafic cible |
| urlscan.io | Historique et soumission d'URLs |
| ThreatFox | IoCs de campagnes actives |
| MalwareBazaar | Echantillons par empreinte |
| URLhaus | URLs de distribution de charges |
| YARA | Regles sur artefacts |
| Sigma | Moteur de detection integre |

**Securite applicative** — JWT access (15 min) + refresh (7 j) avec rotation et
revocation, RBAC (admin / analyst / user), PBKDF2-SHA256 600 000 iterations,
politique de mots de passe, rate limiting distribue (Redis), en-tetes de
securite durcis (CSP, COOP/CORP), journal d'audit.

**Observabilite** — logs JSON structures, metriques Prometheus (`/metrics`),
sondes `/livez` et `/readyz`, suivi de la consommation de tokens LLM.

---

## Evaluation

Un enqueteur IA ne vaut que ce que l'on peut mesurer. Le banc d'evaluation
rejoue l'enqueteur sur des cas annotes et produit un tableau de bord Markdown
et JSON.

```bash
cd mcp-server
python -m phoenix_dfir_mcp eval ../eval/suite -o resultats
python -m phoenix_dfir_mcp eval ../eval/suite --min-recall 0.8 --max-forbidden 0 \
    --min-pass-rate 0.75 --min-fact-exact 0.75   # code retour 1 sous les seuils
```

| Metrique | Mesure |
|---|---|
| Rappel ATT&CK | Techniques attendues retrouvees dans les constats |
| Techniques interdites | Faux positifs explicites |
| Rappel des IoCs | Indicateurs attendus cites dans le rapport |
| **Faits exacts** | Reponses du corrige factuel presentes dans le rapport |
| Ancrage | Part des constats acceptes (references reellement observees) |
| Injection | Artefacts pieges detectes |
| Faux positifs sur cas sains | Constats >= medium sur un cas sans incident |
| Cout | Appels LLM, tokens, duree |

La suite livree couvre un brute force SSH, une execution PowerShell avec
artefact piege, un beaconing C2, une activite d'administration legitime et une
**exfiltration reconstituee depuis une image disque** (archive supprimee,
destination HTTP, compte utilisateur) notee sur corrige factuel. Details et
format des cas : [`eval/README.md`](eval/README.md).

---

## Demarrage rapide

### Docker Compose (recommande)

```bash
git clone https://github.com/servais1983/phoenix-dfir.git
cd phoenix-dfir
cp .env.example .env          # definir au minimum PHOENIX_SECRET_KEY
docker compose up --build -d
```

Ouvrir <http://localhost:5000>. Le **premier compte cree devient
administrateur**. L'image embarque Volatility 3, Hayabusa et The Sleuth Kit ;
le dossier `./evidence_vault` est monte en lecture seule et un Ollama local est
joignable via `host.docker.internal`.

Windows / Docker Desktop (WSL 2, exclusion Defender, Ollama, GPU) :
[`docs/WINDOWS_DOCKER.md`](docs/WINDOWS_DOCKER.md).

### Stack production

Phoenix + Redis (rate limiting distribue, cache) + Nginx (TLS, compression) :

```bash
python -c "import secrets; print(secrets.token_hex(64))"   # -> PHOENIX_SECRET_KEY dans .env
docker compose -f docker-compose.prod.yml up -d
```

Placer les certificats dans `deploy/tls/` et activer les directives SSL de
`deploy/nginx.conf`.

### Lanceurs locaux

```bash
./start.sh        # Linux / macOS
start.bat         # Windows
```

Verifient Python 3.10+ et Node.js 20+, installent les dependances puis
demarrent le frontend (`:5173`) et le backend (`:5000`).

### Installation manuelle

```bash
# Backend
cd backend
pip install -r requirements.txt
gunicorn --config gunicorn.conf.py app:app      # ou : python app.py

# Frontend
npm ci && npm run dev

# Outils forensiques optionnels (Debian / Ubuntu)
sudo apt-get install sleuthkit                  # images disque
pip install volatility3                         # memoire vive
```

### LLM

| Fournisseur | Configuration | Donnees |
|---|---|---|
| **Ollama** (recommande) | `PHOENIX_LLM_PROVIDER=ollama`, modele compatible *tool calling* (ex. `qwen2.5-coder:14b`) | Restent sur le reseau d'investigation |
| OpenAI ou compatible | `OPENAI_API_KEY`, `OPENAI_BASE_URL` | Envoyees au fournisseur |
| GitHub Models | `GITHUB_TOKEN` (permission *Models: read*) | Envoyees au fournisseur |

`PHOENIX_LLM_PROVIDER=auto` (defaut en Docker) choisit Ollama s'il repond,
puis OpenAI, puis GitHub Models. Sans LLM, toutes les fonctions d'analyse
deterministes restent disponibles.

---

## Configuration

| Variable | Role | Defaut |
|---|---|---|
| `PHOENIX_SECRET_KEY` | Cle de signature JWT (**obligatoire en production**) | generee dans `.secret_key` |
| `PHOENIX_LLM_PROVIDER` | `auto`, `ollama`, `openai`, `github` | `github` (`auto` en Docker) |
| `OLLAMA_BASE_URL` / `PHOENIX_OLLAMA_MODEL` | Serveur et modele Ollama | `http://localhost:11434` / `qwen2.5-coder:14b` |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `PHOENIX_OPENAI_MODEL` | Fournisseur OpenAI ou compatible | — / api.openai.com / `gpt-4o-mini` |
| `GITHUB_TOKEN` / `PHOENIX_GITHUB_MODEL` | GitHub Models | — / `openai/gpt-4o-mini` |
| `PHOENIX_INVESTIGATION_MODE` | `phased` (cinq phases) ou `loop` (boucle unique) | `phased` |
| `PHOENIX_STRICT_EVIDENCE` | Constats obligatoirement references | `true` |
| `PHOENIX_EVIDENCE_VAULT` | Coffre de preuves en lecture seule | `/mnt/evidence` ou `./evidence_vault` |
| `PHOENIX_EVIDENCE_DIR` | Dossier de depot surveille | `backend/evidence_inbox` |
| `PHOENIX_INBOX_ENABLED` / `PHOENIX_INBOX_POLL_SECONDS` | Surveillance du depot | `true` / `10` |
| `PHOENIX_TOOL_ROOTS` | Racines autorisees aux outils pilotes par le LLM | dossier du cas |
| `PHOENIX_VOLATILITY_CMD` / `PHOENIX_VOLATILITY_SYMBOLS` | Volatility 3 et symboles hors ligne | `vol` du PATH |
| `PHOENIX_HAYABUSA_CMD` / `PHOENIX_HAYABUSA_RULES` | Binaire et regles Hayabusa | `hayabusa` du PATH |
| `EZ_TOOLS_PATH` | Dossier des EZ Tools | — |
| `REDIS_URL` | Cache et rate limiting distribues | en memoire |
| `PHOENIX_ACCESS_TOKEN_EXPIRY` / `PHOENIX_REFRESH_TOKEN_EXPIRY` | Durees des jetons (s) | `900` / `604800` |
| `PHOENIX_PBKDF2_ITERATIONS` | Iterations de hachage | `600000` |
| `PHOENIX_CORS_ORIGINS` | Origines supplementaires (acces equipe) | localhost |
| `PHOENIX_PORT` / `PHOENIX_WORKERS` / `PHOENIX_LOG_LEVEL` | Serveur | `5000` / `1` / `INFO` |

Les outils externes (Sleuth Kit, Volatility, Hayabusa, EZ Tools) sont
optionnels : absents, ils se declarent indisponibles et l'enqueteur se replie
sur les parsers natifs.

---

## API REST

Toutes les routes `/api/*` (hors authentification et sante) exigent un jeton
`Authorization: Bearer <access_token>`.

<details>
<summary><strong>Authentification</strong></summary>

| Methode | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Inscription (5/min) |
| POST | `/api/auth/login` | Connexion (10/min) — `access_token` + `refresh_token` |
| POST | `/api/auth/refresh` | Rotation de la paire de jetons |
| POST | `/api/auth/logout` | Revocation |
| PUT | `/api/auth/password` | Changement de mot de passe |
| GET | `/api/auth/me` | Utilisateur courant |
| GET | `/api/auth/users` | Utilisateurs (admin) |

</details>

<details>
<summary><strong>Enquetes, artefacts, IoCs, timeline</strong></summary>

| Methode | Endpoint | Description |
|---|---|---|
| GET / POST | `/api/investigations` | Liste paginee (`?search=`, `?status=`) / creation |
| GET / PUT / DELETE | `/api/investigations/:id` | Detail / mise a jour / suppression |
| PUT | `/api/investigations/:id/status` | Statut |
| POST | `/api/upload` | Upload avec empreintes |
| GET | `/api/investigations/:id/artifacts` | Artefacts |
| POST | `/api/analyze` · GET `/api/analysis/:id/status` | Analyse asynchrone |
| GET / POST | `/api/investigations/:id/iocs` | IoCs |
| POST | `/api/investigations/:id/iocs/bulk` | Import en masse |
| GET | `/api/investigations/:id/iocs/export` | Export CSV |
| GET / POST | `/api/investigations/:id/timeline` | Timeline |
| GET | `/api/investigations/:id/mitre` | Mapping ATT&CK |
| GET | `/api/investigations/:id/export/stix` | Bundle STIX 2.1 |
| POST | `/api/reports/generate` · GET `/api/reports/:id/download` | Rapports |

</details>

<details>
<summary><strong>Enqueteur autonome et console</strong></summary>

| Methode | Endpoint | Description |
|---|---|---|
| GET | `/api/console/status` | Agents, outils disponibles, LLM, coffre, tete de chaine |
| GET | `/api/custody?investigation_id=` | Maillons de la chaine de preuve |
| GET | `/api/custody/verify` | Verification d'integrite de toute la chaine |
| GET | `/api/remediation?status=` | Remediations proposees |
| POST | `/api/remediation/:id/decision` | `{decision: approve\|reject, note}` (analyst / admin) |
| GET | `/api/evidence-vault` | Contenu du coffre |
| POST | `/api/evidence-vault/import` | Rattacher des evidences a une enquete |

</details>

<details>
<summary><strong>Integrations et systeme</strong></summary>

| Methode | Endpoint | Description |
|---|---|---|
| GET | `/api/integrations` | Connecteurs et statut |
| PUT | `/api/integrations/:id` | Configuration (admin) |
| POST | `/api/integrations/:id/test` | Test de connexion |
| POST | `/api/integrations/:id/enrich` · `/push` · `/pull` | Enrichissement, echange d'IoCs |
| GET | `/livez` · `/readyz` · `/api/health` | Sondes |
| GET | `/metrics` | Metriques Prometheus |
| GET | `/api/stats` · `/api/audit` | Statistiques, journal d'audit (admin) |

</details>

---

## Architecture

```text
                 ┌──────────────────────────── Interface React 19 ────────────────────────────┐
                 │  Console Enqueteur DFIR · Enqueteur IA · Enquetes · Timeline · IoCs · ...   │
                 └──────────────┬───────────────────────────────────────▲─────────────────────┘
                          REST (JWT)                             WebSocket authentifie
                 ┌──────────────▼───────────────────────────────────────┴─────────────────────┐
                 │  Backend Flask : API, RBAC, chaine de preuve, HITL, coffre, depot surveille │
                 └──────────────┬─────────────────────────────────────────────────────────────┘
                                │
                 ┌──────────────▼──────────────── phoenix_dfir_mcp ───────────────────────────┐
                 │  Moteur 5 phases + portes ── LLM (Ollama / OpenAI / GitHub Models)          │
                 │        │                      ▲ bouclier anti-injection                    │
                 │  39 outils : parsers · Sigma · ATT&CK · Hayabusa · Volatility 3 ·           │
                 │              The Sleuth Kit · EZ Tools · VirusTotal · memoire · rapport     │
                 │        │                                                                   │
                 │  Super-timeline SQLite FTS5 ── validation des references (strict evidence) │
                 └─────────────────────────────────────────────────────────────────────────────┘
```

```text
phoenix-dfir/
├── backend/                  API Flask
│   ├── routes/               Blueprints (enquetes, artefacts, console, autonomous...)
│   ├── integrations/         13 connecteurs (BaseConnector + registre)
│   ├── custody.py            Chaine de preuve SHA-256 et remediations HITL
│   ├── evidence_vault.py     Coffre de preuves en lecture seule
│   ├── parsers.py            Parsers natifs et extraction d'IoCs
│   └── tests/                Suite pytest
├── mcp-server/phoenix_dfir_mcp/
│   ├── phases.py             Moteur cinq phases et portes qualite
│   ├── investigator.py       Boucle agentique, verification, revue
│   ├── toolkit.py            Registre des 39 outils (MCP + function calling)
│   ├── disk.py               Images disque (The Sleuth Kit)
│   ├── volatility.py         Memoire vive (Volatility 3)
│   ├── hayabusa.py           Timeline EVTX
│   ├── zimmermann.py         EZ Tools
│   ├── evidence_db.py        Super-timeline SQLite FTS5
│   ├── shield.py             Bouclier anti-injection
│   ├── memory.py             Memoire d'enquete
│   ├── exports.py            Calque ATT&CK Navigator, CSV d'IoCs
│   ├── evaluation.py         Banc d'evaluation
│   ├── copilot.py            Client LLM hybride
│   └── server.py             Serveur MCP stdio
├── src/                      Frontend React (pages, services, contextes)
├── eval/                     Cas annotes et generateur de l'image disque de test
├── evidence_vault/           Coffre (monte en lecture seule en Docker)
├── docs/WINDOWS_DOCKER.md    Deploiement Windows / Docker Desktop
├── deploy/                   Nginx (stack production)
└── Dockerfile                Build multi-etapes (Node + Python + outils DFIR)
```

---

## Qualite et CI

```bash
cd backend && PHOENIX_SECRET_KEY=test python -m pytest tests/ -q   # backend
npm run lint && npm test                                           # frontend
```

Plus de **340 tests** : API et securite, parsers, regles Sigma, connecteurs,
chaine de preuve, bouclier anti-injection, references strictes, moteur a
phases, super-timeline, images disque (integration reelle avec The Sleuth
Kit), banc d'evaluation et un scenario de bout en bout sur image disque
(cinq portes validees, 100 % de faits exacts).

Pipeline GitHub Actions :

| Job | Contenu |
|---|---|
| `backend-tests` | Python 3.10 / 3.11 / 3.12, The Sleuth Kit installe |
| `security-scan` | Bandit (SAST) + pip-audit |
| `sbom` | SBOM CycloneDX |
| `frontend-build` | Lint, tests Vitest, build et taille du bundle |
| `docker-build` | Build buildx, smoke test `/livez`, `/api/health`, `/metrics` |

---

## Contribution

1. Creer une branche : `git checkout -b feature/ma-fonctionnalite`
2. Ajouter les tests correspondants et verifier la suite complete
3. Ouvrir une Pull Request

Ajouter un connecteur : un fichier dans `backend/integrations/` heritant de
`BaseConnector` et enregistre par `@registry.register`.
Ajouter un outil d'enquete : une entree dans `mcp-server/phoenix_dfir_mcp/toolkit.py`
et, si besoin, son autorisation dans les phases concernees (`phases.py`).
Ajouter un cas d'evaluation : voir [`eval/README.md`](eval/README.md).

Signalement de vulnerabilite : [`SECURITY.md`](SECURITY.md).

## Licence

Distribue sous licence MIT — voir [LICENSE](LICENSE).

<p align="center"><sub><strong>Phoenix DFIR</strong> — investigation numerique et reponse aux incidents</sub></p>
