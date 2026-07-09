# Changelog

Tous les changements notables sont consignes dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/), le projet adhere au
[Semantic Versioning](https://semver.org/).

---

## [4.3.1] - 2026-07-09

### Fixed — Durcissement production apres test E2E reel complet (30 verifications)

Un test de bout en bout contre un backend reellement demarre (auth, uploads,
boucle Copilot via HTTP, WebSocket, depot inbox, EVTX Windows reel) a revele
et corrige :

- **WebSocket jamais delivre depuis les threads de travail** : le serveur
  eventlet ignorait les `socketio.emit()` des analyses/enqueteur/watcher.
  `eventlet.monkey_patch()` applique en tete d'`app.py` (aligne dev et prod
  gunicorn). La progression temps reel fonctionne desormais reellement.
- **Frontend jamais servi en mono-conteneur** : l'image Docker copiait le
  build dans `/app/frontend` mais Flask ne le servait pas. Le backend sert
  desormais le build (SPA fallback inclus) : interface complete sur
  `http://<hote>:5000` (`PHOENIX_FRONTEND_DIR`, ou `dist/` a la racine).
- **CORS/WebSocket bloques hors localhost** : origines configurables via
  `PHOENIX_CORS_ORIGINS` (exposee dans les deux stacks compose) + la propre
  origine du serveur automatiquement acceptee (acces equipe via IP).
  Frontend : URL API/WebSocket auto-detectee sur la meme origine que la
  page ; le champ "URL du Backend" des parametres est desormais effectif.
- **Parsing EVTX fiabilise** : moteur Rust `evtx` (pyevtx-rs, wheels
  precompiles) en priorite, python-evtx en repli. Valide sur un vrai
  journal Security Windows (999 evenements, alertes Sigma reelles).
  `requirements-optional.txt` ne peut plus echouer en bloc (hexdump retire).
- **Evidences protegees** : `cleanup_old_files` ne supprime plus que les
  uploads orphelins — les artefacts rattaches a une enquete ne sont JAMAIS
  purges.

---

## [4.3.0] - 2026-07-09

### Added — Enqueteur autonome integre a la plateforme : tout se fait seul

- **Page "Enqueteur IA"** dans l'interface web : glisser-deposer des
  evidences (tous formats forensiques), creation automatique de l'enquete,
  upload, lancement de l'investigation autonome GitHub Copilot, journal en
  temps reel (WebSocket `autonomous_progress`) et rapport final affiche et
  telechargeable.
- **Dossier de depot surveille** (`backend/watcher.py`) : deposez des
  fichiers ou un dossier dans `backend/evidence_inbox/` (configurable via
  `PHOENIX_EVIDENCE_DIR`) — enquete creee, artefacts rattaches (hashes
  calcules) et enqueteur autonome lance automatiquement. Un sous-dossier
  depose = un cas portant son nom. Desactivable via
  `PHOENIX_INBOX_ENABLED=false`.
- **API** : `GET /api/autonomous/status`, `POST /api/autonomous/investigate`
  (lance un job en arriere-plan), `GET /api/autonomous/jobs/<id>`.
  Le runner (`backend/autonomous.py`) copie les artefacts de l'enquete dans
  un dossier de cas, delegue a `phoenix_dfir_mcp.investigator`, sauvegarde
  le rapport dans `backend/reports/`, insere les IoCs extraits en base,
  trace la timeline et journalise l'audit.
- **Formats d'upload etendus** : `.pf`, `.lnk`, `.sqlite`, `.db`, `.ps1`,
  `.bat`, `.sh`, `.hve`, `.dat` acceptes en plus des formats existants.
- **Demarrage facile** : `start.bat` / `start.sh` affichent l'etat GitHub
  Copilot et le dossier de depot ; Dockerfile embarque `mcp-server/` et
  `legacy/`, volume `phoenix-inbox` ajoute aux deux stacks docker-compose.
- **Tests** : 14 tests (routes autonomous, runner complet avec Copilot
  simule, watcher : detection, cas par dossier, fichiers partiels ignores).
  Suite backend complete : 211 tests verts.

---

## [4.2.0] - 2026-07-09

### Added — Enqueteur DFIR autonome : serveur MCP orchestre par GitHub Copilot

- **Nouveau module `mcp-server/`** (`phoenix_dfir_mcp`) : serveur MCP (Model
  Context Protocol, stdio, JSON-RPC implemente nativement, zero dependance)
  exposant 16 outils forensiques reutilisant le backend Phoenix :
  `list_artifacts` (inventaire + hashes), parsers natifs tous formats
  (EVTX, CSV, JSON, logs, Prefetch, LNK, historiques navigateurs),
  `extract_iocs`, `sigma_scan` (26 regles integrees), `mitre_map_events`,
  `virustotal_lookup`, `save_report`.
- **Outils Eric Zimmermann integres** (`run_zimmermann` / `zimmermann_status`) :
  EvtxECmd, PECmd, LECmd, JLECmd, MFTECmd, AmcacheParser,
  AppCompatCacheParser, RECmd, SBECmd, SrumECmd, SQLECmd, WxTCmd — execution
  via dotnet (EZ_TOOLS_PATH), sortie CSV parsee, degradation gracieuse vers
  les parsers natifs si absents.
- **Mode agent VS Code** : `.vscode/mcp.json` inclus — GitHub Copilot (mode
  agent) decouvre et orchestre les outils DFIR directement.
- **Enqueteur autonome** : `python -m phoenix_dfir_mcp investigate <cas>` —
  GitHub Copilot (API GitHub Models, function calling) resout le cas seul en
  boucle agentique : inventaire → parsing de chaque artefact → detection
  Sigma → correlation d'IoCs → enrichissement → timeline → mapping MITRE →
  rapport Markdown sauvegarde dans le dossier du cas.
- **Tests** : 22 tests (registre d'outils, protocole MCP, normalisation
  Sigma, EZ Tools, boucle agentique avec Copilot simule) integres a la CI.

---

## [4.1.0] - 2026-07-09

### Added — GitHub Copilot comme fournisseur IA unique

- **GitHub Copilot (API GitHub Models)** devient le seul fournisseur IA des
  analyses (`legacy/phoenix.py`) : artefacts, extraction d'IoCs/timeline et
  resumes executifs. Configuration par variables d'environnement :
  `GITHUB_TOKEN` ou `PHOENIX_GITHUB_TOKEN` (permission *Models: read*) et
  `PHOENIX_GITHUB_MODEL` (defaut `openai/gpt-4o-mini`). Ne requiert que
  `requests`, deja present dans `requirements.txt`.
- **Parametres UI** : champs GitHub Copilot Token et modele dans la page
  Parametres.
- **Deploiement** : variables IA transmises dans `docker-compose.yml`,
  `docker-compose.prod.yml` et documentees dans `.env.example`,
  `README.md` et `INSTALLATION.md`.
- **Tests** : 7 tests backend du fournisseur GitHub Copilot
  (`backend/tests/test_phoenix_ai.py`), ignores proprement si les
  dependances optionnelles du CLI (typer, pandas) sont absentes.

### Removed — Anciens fournisseurs IA

- **Ollama et Google Gemini supprimes** : plus d'imports `ollama` /
  `google-generativeai`, plus de cles/modeles associes (`API_KEY_GOOGLE`,
  `MODEL_LOCAL`, `MODEL_REMOTE`), champs retires de la page Parametres
  (avec nettoyage du localStorage) et des dependances
  (`requirements-optional.txt`, `legacy/requirements.txt`).
- **`legacy/phoenix_service.py` supprime** : portage inutilise du CLI,
  base sur Ollama/Gemini.
- Sans jeton GitHub, l'analyse IA retourne une erreur explicite ; la
  plateforme reste fonctionnelle avec ses parsers natifs (standalone).

### Changed

- `typer` et `pandas` ajoutes a `backend/requirements-optional.txt` pour
  activer le moteur d'analyse IA.
- `query_local` / `query_remote` conserves comme alias retro-compatibles
  de `query_github` ; la cle VirusTotal est configurable via `API_KEY_VT`.

---

## [4.0.1] - 2026-06-09

### Changed — Qualite & maintenabilite

- **Backend refactorise en blueprints** : `app.py` (2000 lignes) decoupe en 11
  blueprints sous `backend/routes/` (health, investigations, iocs, timeline,
  artifacts, analysis, reports, stats, stix, integrations, mitre_attack) +
  `extensions.py`, `helpers.py`, `sockets.py`, `phoenix_compat.py`. Chemins
  API, point d'entree gunicorn (`app:app`) et comportement inchanges.
- **Dependances backend fiabilisees** : `python-evtx` (et les providers IA)
  deplaces dans `backend/requirements-optional.txt` installe en best-effort
  partout (sa dependance `hexdump` ne compile plus avec les setuptools
  recents et bloquait toute l'installation).
- **Code legacy isole** : `phoenix.py`, `phoenix_service.py` et le
  `requirements.txt` racine regroupes dans `legacy/` avec documentation.
- **Builds frontend reproductibles** : `package-lock.json` versionne,
  `npm ci` en CI et dans le Dockerfile, migration react-day-picker 8 -> 9
  (suppression du conflit de peer deps avec date-fns et du `.npmrc`
  `legacy-peer-deps`).

### Added

- **Tests frontend** : Vitest + jsdom, 21 tests couvrant les helpers de
  tokens, les intercepteurs axios (injection Bearer, auto-refresh 401,
  deconnexion), `apiService` et `cn`. Integres a la CI avec le lint.

### Fixed

- 29 erreurs ESLint (imports/variables inutilises, try/catch inutiles,
  globals Node manquants pour `scripts/` et les fichiers de config).
- Versions alignees : `package.json` 4.0.x, badge React 19 dans le README.

---

## [4.0.0] - 2026-06-04

### Added — Production hardening

- **Cache & rate limit distribues** : `backend/cache.py` abstrait Redis (ZSET
  sliding window, pipelines) avec fallback in-memory thread-safe. Active via
  `REDIS_URL`.
- **Observabilite** : `backend/observability.py` fournit un formatter JSON
  pour stdout (compatible Loki/ELK/CloudWatch) et expose un endpoint
  `/metrics` Prometheus avec counters HTTP, auth failures, integration calls,
  rate limit blocks, artifacts analyzed et la gauge `phoenix_investigations_active`.
- **Health probes Kubernetes-ready** :
  - `/livez` : liveness sans dependances, repond toujours 200 si le process vit
  - `/readyz` : readiness verifiant DB + Redis, repond 503 si une dep est KO
  - `/api/health` conserve, enrichi du backend cache
- **Refresh tokens** : access (15min) + refresh (7j) avec **rotation** a chaque
  refresh et **revocation server-side** via cache (jti TTL aligne sur exp).
- **Politique de mots de passe forte** : 12+ caracteres, 3+ classes
  (maj/min/chiffres/special), denylist des 30+ mots faibles. PBKDF2-SHA256
  porte a 600 000 iterations, format de hash **versionne**
  (`pbkdf2_sha256$iter$salt$key`) et **upgrade transparent** au login.
- **Nouveaux endpoints d'auth** : `POST /api/auth/refresh`, `POST /api/auth/logout`,
  `PUT /api/auth/password`.
- **Stack de production** : `docker-compose.prod.yml` lance Phoenix + Redis 7 +
  Nginx 1.27 avec health checks, `no-new-privileges`, `cap_drop: ALL`,
  Redis maxmemory + appendonly, et logs json-file en rotation 10m/5.
- **Reverse proxy Nginx** (`deploy/nginx.conf`) : WebSocket Socket.IO,
  X-Forwarded-* propagation, /metrics IP-restreint au sous-reseau interne,
  json access logs, gzip.
- **Gunicorn + eventlet** : `backend/gunicorn.conf.py` pour servir Flask-SocketIO
  en production avec max_requests + jitter contre les fuites memoire.

### Added — Forensic capabilities

- **Parsers** :
  - **Prefetch (.pf)** : SCCA Win7/8 non-compresse + detection MAM/XPRESS
    (Win10/11) avec fallback via `pyscca` si disponible
  - **Browser history (.sqlite)** : Chromium (`urls`, WebKit epoch) et Firefox
    (`moz_places`, PRTime) - copie locale pour eviter les locks
  - **LNK (.lnk)** : parser MS-SHLLINK natif - target path, args, working dir,
    timestamps FILETIME, escalation de severite sur patterns suspects
- **Sigma rules** : passage de 7 a **26 regles** couvrant 9 tactiques MITRE
  (credential_access, defense_evasion, persistence, privilege_escalation,
  execution, lateral_movement, command_and_control, impact, plus discovery)
- **Moteur de matching Sigma** etendu : criteres `*_contains`
  (image, command_line, target_object, service_name), criteres d'egalite
  (logon_type, ticket_encryption), comptage de threshold approprie, filtre
  par tactique

### Added — Integrations (5 nouveaux connecteurs)

- **GreyNoise** : noise Internet vs trafic cible, Community (sans cle) +
  Enterprise (avec cle), classification benign/malicious/unknown, flag RIOT
- **urlscan.io** : recherche historique d'URLs (par URL, domain, IP),
  soumission d'URL pour analyse rendue, recuperation de screenshots
- **ThreatFox** (abuse.ch) : recherche d'IoCs malware actifs avec exact match,
  import en masse des IoCs des 7 ou 30 derniers jours
- **MalwareBazaar** (abuse.ch) : lookup d'echantillons par MD5/SHA1/SHA256,
  recuperation des hashes recents, metadata signature + tags
- **URLhaus** (abuse.ch) : lookup d'URLs, hosts et payloads par hash

### Added — CI / Tooling

- Job `security-scan` : Bandit (SAST) + pip-audit (dependances vulnerables)
  avec rapports JSON uploades en artifacts (retention 30j)
- Job `sbom` : generation d'un SBOM CycloneDX JSON des dependances Python
  (retention 90j)
- Job `frontend-build` : artifact upload du dist/ (retention 7j)
- Job `docker-build` : utilisation de `docker/build-push-action@v5` avec
  cache GitHub Actions (`type=gha`), smoke test sur `/livez`, `/api/health`
  et `/metrics`
- `pip` cache et `npm` cache actives sur les jobs python/node

### Added — Tests

- **168 tests** (+ 87 vs v3.0). Nouveaux modules :
  - `tests/test_cache.py` (10) : in-memory, TTL, sliding window, thread safety
  - `tests/test_auth.py` (16) : hashing format/upgrade, password policy, tokens
  - `tests/test_observability.py` (5) : JSON formatter, Prometheus
  - `tests/test_new_connectors.py` (12) : 5 nouveaux connecteurs
  - `tests/test_new_parsers.py` (10) : Prefetch, browser history, LNK
  - `tests/test_sigma_rules.py` (12) : 26 regles + moteur de matching
  - `tests/test_api_v4.py` (14) : `/livez`, `/readyz`, `/metrics`, flow refresh

### Changed

- Security headers : CSP durcie (suppression `'unsafe-inline'` pour scripts),
  ajout COOP/CORP, Permissions-Policy etendue (payment), suppression du header
  `Server:`
- IP client : prise en compte `X-Forwarded-For` (premier element) pour le
  rate limiting derriere un proxy
- Request-ID : validation regex + longueur max 64
- `app.py` : remplacement de `datetime.utcnow()` deprecie par
  `datetime.now(timezone.utc)`
- Rate limit : bypass automatique en mode Flask `TESTING` pour eviter les
  interferences entre classes de test

### Security

- Fin du stockage du hash dans le format "salt+key hex" non versionne :
  conserve en lecture (verify_password reste compatible) mais ecrit
  systematiquement le nouveau format au login (upgrade transparent).
- Logging des echecs de login dans le journal d'audit
  (`action=login_failed`).

### Notes de migration depuis v3.0

- **Mots de passe** : les utilisateurs avec un mot de passe ne respectant pas
  la nouvelle politique pourront toujours **se connecter** (verify_password
  retro-compatible), mais devront en choisir un nouveau via
  `PUT /api/auth/password` avant qu'une eventuelle reinitialisation
  ne soit imposee.
- **Tokens v3** : la variable `PHOENIX_TOKEN_EXPIRY` continue de fonctionner et
  override `PHOENIX_ACCESS_TOKEN_EXPIRY`. Les anciens tokens d'access restent
  valides jusqu'a expiration mais ne peuvent pas etre rafraichis (ils n'ont
  pas de jti / refresh associe).
- **Reverse proxy** : si vous deployez derriere un proxy, configurer
  `X-Forwarded-For` est desormais necessaire pour un rate limiting correct.
- **Healthchecks** : le healthcheck Docker du `docker-compose.yml` racine et de
  `docker-compose.prod.yml` cible `/readyz` (plus precis). Le healthcheck
  d'image (`HEALTHCHECK` Dockerfile) cible `/livez`.

---

## [3.0.0] - 2026-02-15

### Added
- Framework d'integration avec 8 connecteurs : MISP, Cortex, VirusTotal,
  AbuseIPDB, Shodan, AlienVault OTX, YARA, Sigma
- 7 regles Sigma integrees
- Export STIX 2.1 natif (bundle, identity, report, indicators)
- Mapping MITRE ATT&CK (20+ Event IDs, 9 types d'IoCs)
- 81 tests
- CI GitHub Actions sur Python 3.10/3.11/3.12

### Security
- Authentification JWT avec roles (admin/analyst/viewer)
- Rate limiting in-memory
- Security headers (CSP, HSTS, X-Frame, nosniff, Referrer-Policy)
- Request ID tracking
- Path traversal protection
- Audit log complet
