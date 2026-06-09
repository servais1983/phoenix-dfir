<p align="center">
  <img src="phoenix.png" alt="Phoenix DFIR" width="200" />
</p>

<h1 align="center">Phoenix DFIR</h1>

<p align="center">
  <strong>Plateforme d'Investigation Forensique Numerique et de Reponse aux Incidents</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.0-orange?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/tests-189%20passed-brightgreen?style=flat-square" alt="Tests" />
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/react-19-blue?style=flat-square&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/docker-ready-blue?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/connectors-13-blue?style=flat-square" alt="Connectors" />
  <img src="https://img.shields.io/badge/sigma%20rules-26-purple?style=flat-square" alt="Sigma" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
</p>

---

## Vue d'ensemble

Phoenix DFIR est une plateforme complete d'investigation forensique numerique deployable en un seul conteneur Docker ou en stack production (Phoenix + Redis + Nginx). Elle combine l'analyse d'artefacts forensiques (EVTX, CSV, JSON, LOG, XML, PCAP, Prefetch, LNK, historique navigateur SQLite), la gestion des IoCs, le mapping MITRE ATT&CK, l'export STIX 2.1, **13 connecteurs** vers les plateformes externes de Threat Intelligence et **26 regles Sigma** integrees couvrant les tactiques MITRE, le tout avec une interface web moderne et une API REST securisee (JWT access + refresh tokens, RBAC, rate limiting distribue, observabilite Prometheus).

### Pourquoi Phoenix DFIR

| Critere | TheHive | DFIR-IRIS | Velociraptor | **Phoenix DFIR v4.0** |
|---|---|---|---|---|
| Deploiement | Java + Cassandra + ES | Docker multi-service | Binaire Go | **1 conteneur OU stack prod (Phoenix+Redis+Nginx)** |
| Integrations natives | Cortex | MISP (partiel) | VQL | **13 plateformes** |
| MITRE ATT&CK | Plugin | Plugin | Partiel | **Natif (tactique + technique)** |
| STIX 2.1 | Plugin | Non | Non | **Natif** |
| Regles Sigma | Non | Non | Non | **Natif (26 regles, 9 tactiques)** |
| YARA | Non | Non | Oui | **Natif** |
| Extraction auto IoCs | Non | Non | Non | **Regex multi-types** |
| Parsers forensiques | Logs basiques | Logs | Tres complet | **EVTX, CSV, JSON, LOG, PCAP, Prefetch, LNK, Browser History** |
| Auth | Local | LDAP | TLS client | **JWT access (15min) + refresh (7j) + revocation server-side** |
| Rate limiting | Non | Non | Non | **Distribue (Redis ZSET sliding window)** |
| Observabilite | Limitee | Limitee | Variable | **JSON logs + Prometheus /metrics** |
| Health probes | Basique | Basique | Variable | **/livez + /readyz (k8s-ready)** |
| Mot de passe | Politique faible | Variable | Variable | **PBKDF2-SHA256 600k iter + politique 12+ chars / 3 classes** |
| CI/CD | Manuel | Manuel | GitHub Actions | **GitHub Actions: tests + Bandit SAST + pip-audit + SBOM CycloneDX** |
| Tests | Variable | Variable | Oui | **189 tests (168 backend + 21 frontend), 0 failures** |

---

## Fonctionnalites

### Investigation Forensique
- Gestion complete des enquetes (creation, statut, archivage)
- Upload et analyse d'artefacts multi-formats : EVTX, CSV, JSON, LOG, XML, PCAP, **Prefetch (.pf)**, **LNK (.lnk)**, **historique navigateur SQLite (Chromium / Firefox)**
- Calcul automatique des empreintes MD5, SHA1, SHA256
- Timeline interactive avec severite et filtres
- Extraction automatique d'IoCs par analyse regex (IP, domaines, hashes, URLs, emails, CVE)
- Recherche et filtrage sur investigations et IoCs

### Threat Intelligence (13 connecteurs)
- **VirusTotal** : enrichissement IP/domain/hash/URL via API v3
- **AbuseIPDB** : score de reputation IP, ISP, Tor detection
- **Shodan** : ports ouverts, vulnerabilites, services
- **AlienVault OTX** : pulses, abonnements, enrichissement
- **MISP** : push/pull d'IoCs, recherche d'attributs, creation d'evenements
- **Cortex** : lancement d'analyzers automatises
- **GreyNoise** *(nouveau v4.0)* : noise Internet vs trafic cible
- **urlscan.io** *(nouveau v4.0)* : analyse d'URLs, screenshots, historiques
- **ThreatFox** (abuse.ch) *(nouveau v4.0)* : IoCs de campagnes malware actives
- **MalwareBazaar** (abuse.ch) *(nouveau v4.0)* : recherche d'echantillons malware par hash
- **URLhaus** (abuse.ch) *(nouveau v4.0)* : URLs de delivery malware
- Import en masse d'IoCs (JSON structure ou texte libre avec extraction auto)
- Export CSV des indicateurs

### Detection et Mapping
- Mapping MITRE ATT&CK natif (20+ Event IDs Windows, 9 types d'IoCs)
- Regroupement par tactique avec indicateurs associes
- **26 regles Sigma integrees** couvrant 9 tactiques MITRE : credential access (Kerberoasting, NTDS, LSASS, Pass-the-Hash), defense evasion (log clearing, Defender disabled, firewall disabled), persistence (services, scheduled tasks, registry Run, WMI subscription), execution (encoded PowerShell, WMIC, mshta, rundll32), lateral movement (PsExec, RDP), C2 (BITSAdmin, certutil), impact (VSS deletion, wbadmin, bcdedit recovery)
- Moteur de matching avance : substring-contains (image, command_line, target_object, service_name), criteres d'egalite (logon_type), seuils par regle, filtre par tactique
- Support YARA pour le matching de regles sur artefacts
- Export STIX 2.1 complet (bundle, identity, report, indicators, confidence scoring)

### Securite v4.0
- Authentification JWT : access tokens (15 min) + refresh tokens (7 jours) avec **rotation** et **revocation server-side** (jti dans cache)
- Endpoints d'authentification : `register`, `login`, `refresh`, `logout`, `password` (change), `me`, `users`
- Politique de mots de passe : 12+ caracteres, 3+ classes (maj/min/chiffres/special), denylist des mots faibles
- Hachage PBKDF2-SHA256 **600 000 iterations** avec format versionne et **upgrade transparent** au login
- Rate limiting **distribue via Redis** (sliding window ZSET) avec fallback in-memory
- IP client respecte X-Forwarded-For derriere proxy
- Security headers durcis : CSP sans unsafe-inline pour scripts, COOP/CORP, Permissions-Policy
- Request ID tracking (`X-Request-ID`) pour le tracage distribue
- Protection contre les traversees de chemin
- Validation et sanitisation des entrees (UUID regex, longueur max, NUL stripping)
- Journal d'audit complet incluant les echecs de login

### Observabilite
- **Logs structures JSON** sur stdout avec request_id, user, duration_ms (compatibles Loki / ELK / CloudWatch)
- **Endpoint `/metrics`** Prometheus exposant : `phoenix_http_requests_total`, `phoenix_http_request_duration_seconds`, `phoenix_auth_failures_total`, `phoenix_rate_limit_blocks_total`, `phoenix_integration_calls_total`, `phoenix_artifacts_analyzed_total`, `phoenix_investigations_active`
- **Health probes Kubernetes-ready** : `/livez` (liveness, sans dependances) et `/readyz` (DB + Redis)
- `/api/health` retro-compat avec etat detaille

### Interface
- SPA React 19 avec code splitting et lazy loading
- Design sombre professionnel optimise pour les analystes
- Notifications temps reel via WebSocket (Socket.IO)
- Raccourcis clavier (Alt+1 a Alt+9)
- Error boundary global
- Sidebar retractable avec navigation contextuelle

---

## Integrations Externes

Phoenix DFIR fournit un framework d'integration extensible avec 13 connecteurs prets a l'emploi :

| Plateforme | Categorie | Capacites |
|---|---|---|
| **MISP** | Threat Intelligence | Push IoCs, Pull IoCs, Recherche d'attributs, Creation d'evenements |
| **Cortex** | Analyse automatisee | Listing des analyzers, Lancement d'analyses sur observables |
| **VirusTotal** | Threat Intelligence | Enrichissement IP, Domain, Hash, URL via API v3 |
| **AbuseIPDB** | Reputation IP | Score d'abus, nombre de rapports, ISP, detection Tor |
| **Shodan** | Reconnaissance | Ports ouverts, vulnerabilites, services, geolocalisation |
| **AlienVault OTX** | Threat Intelligence | Pulses de menace, enrichissement, import abonnements |
| **GreyNoise** *(v4)* | Threat Intelligence | Distinction noise vs trafic cible, RIOT (known-good), Community + Enterprise |
| **urlscan.io** *(v4)* | Threat Intelligence | Recherche historique d'URLs, soumission, screenshots |
| **ThreatFox** *(v4)* | Threat Intelligence | IoCs malware actifs, recherche + import recents (J-7/J-30) |
| **MalwareBazaar** *(v4)* | Threat Intelligence | Lookup d'echantillons malware par MD5/SHA1/SHA256 |
| **URLhaus** *(v4)* | Threat Intelligence | URLs malveillantes, hosts, payloads par hash |
| **YARA** | Moteur de regles | Matching sur artefacts, regles personnalisees |
| **Sigma** | Detection | 26 regles integrees, moteur de matching avance |

La configuration se fait via l'interface web (page Integrations) ou via l'API REST. Chaque connecteur peut etre active, configure et teste independamment.

---

## Demarrage Rapide

### Docker mono-conteneur (developpement / petite installation)

```bash
git clone https://github.com/servais1983/phoenix-dfir.git
cd phoenix-dfir
docker build -t phoenix-dfir .
docker run -d -p 5000:5000 -v phoenix-data:/app/data phoenix-dfir
```

L'application est accessible sur `http://localhost:5000`. Le premier utilisateur enregistre obtient automatiquement le role administrateur. En mode mono-conteneur, le rate limiting et le cache utilisent l'in-memory fallback (1 worker).

### Stack production (recommandee)

Stack complete avec Redis (rate limit distribue + cache) et Nginx (reverse proxy, TLS, headers, gzip) :

```bash
cp .env.example .env
# Editer .env : a minima generer un PHOENIX_SECRET_KEY
python -c "import secrets; print(secrets.token_hex(64))"

docker compose -f docker-compose.prod.yml up -d
```

L'application est accessible sur `http://localhost` (ou `https://` apres avoir place vos certificats dans `deploy/tls/` et decommente les directives SSL dans `deploy/nginx.conf`).

### Installation manuelle

**Prerequisites** : Python 3.10+, Node.js 20+

```bash
# Backend
cd backend
pip install -r requirements.txt
# Mode production avec gunicorn + eventlet :
gunicorn --config gunicorn.conf.py app:app
# Mode developpement (Flask dev server) :
# python app.py

# Frontend (developpement)
npm ci
npm run dev
```

### Variables d'environnement

| Variable | Description | Defaut |
|---|---|---|
| `PHOENIX_SECRET_KEY` | **Obligatoire en prod**, cle secrete JWT | Auto-generee dans `.secret_key` |
| `PHOENIX_ACCESS_TOKEN_EXPIRY` | Duree des access tokens (secondes) | 900 (15min) |
| `PHOENIX_REFRESH_TOKEN_EXPIRY` | Duree des refresh tokens (secondes) | 604800 (7j) |
| `PHOENIX_TOKEN_EXPIRY` | **Retro-compat v3** : override l'access expiry | non defini |
| `PHOENIX_PBKDF2_ITERATIONS` | Iterations PBKDF2-SHA256 | 600000 |
| `PHOENIX_LOG_LEVEL` | DEBUG / INFO / WARNING / ERROR | INFO |
| `PHOENIX_DEBUG` | Mode debug Flask | false |
| `PHOENIX_PORT` | Port du serveur | 5000 |
| `PHOENIX_WORKERS` | Nb de workers gunicorn | 1 |
| `REDIS_URL` | URL Redis pour cache + rate limit | (in-memory si absent) |

---

## API REST

### Authentification
| Methode | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Inscription (rate limited 5/min). Renvoie `access_token` + `refresh_token` |
| POST | `/api/auth/login` | Connexion (rate limited 10/min). Renvoie `access_token` + `refresh_token` |
| POST | `/api/auth/refresh` | Echange un refresh token contre une nouvelle paire (rotation) |
| POST | `/api/auth/logout` | Revoque l'access courant + le refresh fourni |
| PUT | `/api/auth/password` | Change son mot de passe (revoque le token courant) |
| GET | `/api/auth/me` | Utilisateur courant |
| GET | `/api/auth/users` | Liste des utilisateurs (admin) |

### Investigations
| Methode | Endpoint | Description |
|---|---|---|
| GET | `/api/investigations` | Liste paginee avec filtres (`?search=`, `?status=`) |
| POST | `/api/investigations` | Creer une enquete |
| GET | `/api/investigations/:id` | Details complets |
| PUT | `/api/investigations/:id` | Mettre a jour |
| DELETE | `/api/investigations/:id` | Supprimer (cascade) |
| PUT | `/api/investigations/:id/status` | Changer le statut |

### IoCs
| Methode | Endpoint | Description |
|---|---|---|
| GET | `/api/investigations/:id/iocs` | Liste avec filtres (`?type=`, `?search=`) |
| POST | `/api/investigations/:id/iocs` | Ajouter un IoC |
| DELETE | `/api/investigations/:id/iocs/:ioc_id` | Supprimer |
| POST | `/api/investigations/:id/iocs/bulk` | Import en masse (JSON ou texte libre) |
| GET | `/api/investigations/:id/iocs/export` | Export CSV |
| POST | `/api/iocs/enrich` | Enrichir via VirusTotal |

### Timeline
| Methode | Endpoint | Description |
|---|---|---|
| GET | `/api/investigations/:id/timeline` | Evenements pagines |
| POST | `/api/investigations/:id/timeline` | Ajouter un evenement |

### Artefacts et Analyse
| Methode | Endpoint | Description |
|---|---|---|
| POST | `/api/upload` | Upload de fichier avec hash automatique |
| GET | `/api/investigations/:id/artifacts` | Liste des artefacts |
| POST | `/api/analyze` | Lancer une analyse (async) |
| GET | `/api/analysis/:id/status` | Statut de l'analyse |
| POST | `/api/tools/hash` | Calcul d'empreintes |

### Rapports et Exports
| Methode | Endpoint | Description |
|---|---|---|
| POST | `/api/reports/generate` | Generer un rapport |
| GET | `/api/reports/:id/download` | Telecharger |
| GET | `/api/investigations/:id/export/stix` | Export STIX 2.1 |
| GET | `/api/investigations/:id/mitre` | Mapping MITRE ATT&CK |

### Integrations
| Methode | Endpoint | Description |
|---|---|---|
| GET | `/api/integrations` | Liste des connecteurs et statut |
| GET | `/api/integrations/:id` | Detail et configuration |
| PUT | `/api/integrations/:id` | Configurer (admin) |
| POST | `/api/integrations/:id/test` | Tester la connexion |
| POST | `/api/integrations/:id/enrich` | Enrichir un IoC |
| POST | `/api/integrations/:id/push` | Pousser les IoCs vers la plateforme |
| POST | `/api/integrations/:id/pull` | Importer des IoCs depuis la plateforme |

### Systeme
| Methode | Endpoint | Description |
|---|---|---|
| GET | `/livez` | Liveness probe (Kubernetes) - 200 si process vivant |
| GET | `/readyz` | Readiness probe - 200 si DB + Redis OK |
| GET | `/healthz` | Alias `/api/health` |
| GET | `/api/health` | Etat detaille systeme + DB + cache (retro-compat) |
| GET | `/metrics` | Metriques Prometheus (`text/plain; version=0.0.4`) |
| GET | `/api/stats` | Statistiques globales et series temporelles |
| GET | `/api/audit` | Journal d'audit (admin) |

---

## Architecture

```
phoenix-dfir/
  backend/
    app.py                    # Point d'entree Flask (config + enregistrement)
    routes/                   # Blueprints API (health, investigations, iocs,
                              #  timeline, artifacts, analysis, reports, stats,
                              #  stix, integrations, mitre_attack)
    extensions.py             # SocketIO, executor, constantes partagees
    helpers.py                # Pagination, hashes, sanitisation, patterns STIX
    sockets.py                # Evenements WebSocket
    phoenix_compat.py         # Import optionnel du CLI legacy
    database.py               # Schema SQLite + migrations
    auth.py                   # JWT auth + RBAC
    parsers.py                # Parsers EVTX/CSV/JSON/LOG + extraction IoCs
    middleware.py              # Rate limiting, security headers, request ID
    mitre.py                  # Mapping MITRE ATT&CK
    integrations/
      __init__.py             # Auto-registration des connecteurs
      base.py                 # BaseConnector (pattern strategy)
      registry.py             # IntegrationRegistry (pattern registre)
      misp_connector.py       # MISP - Threat Intelligence
      cortex_connector.py     # Cortex - Analyse automatisee
      virustotal_connector.py # VirusTotal - Enrichissement
      abuseipdb_connector.py  # AbuseIPDB - Reputation IP
      shodan_connector.py     # Shodan - Reconnaissance
      otx_connector.py        # AlienVault OTX - Threat Intel
      yara_connector.py       # YARA - Matching de regles
      sigma_connector.py      # Sigma - Detection
    tests/
      test_api.py             # 31 tests API
      test_parsers.py         # 11 tests parsers
      test_mitre.py           # 14 tests MITRE + middleware
      test_integrations.py    # 25 tests integrations
  src/
    App.jsx                   # SPA avec routing, sidebar, auth
    components/
      ErrorBoundary.jsx       # Error boundary global
      ui/                     # Composants shadcn/ui
    pages/
      DashboardPage.jsx       # Statistiques, graphiques, quick actions
      InvestigationsPage.jsx  # CRUD enquetes
      AnalyzerPage.jsx        # Upload + analyse de fichiers
      TimelinePage.jsx        # Timeline interactive
      IocsPage.jsx            # Gestion des IoCs
      ReportsPage.jsx         # Generation de rapports
      IntegrationsPage.jsx    # Configuration des connecteurs
      HashToolPage.jsx        # Outil de calcul de hashes
      AuditPage.jsx           # Journal d'audit
      SettingsPage.jsx        # Parametres et exports
      LoginPage.jsx           # Authentification
    services/
      api.js                  # Client API (30+ methodes)
      api.test.js             # Tests Vitest (tokens, intercepteurs, refresh)
    context/
      AuthContext.jsx          # Gestion de l'authentification
      AppContext.jsx           # Etat global de l'application
  legacy/                     # CLI Phoenix v1 (Typer + IA, optionnel)
  Dockerfile                  # Multi-stage build (Node + Python)
  .github/workflows/ci.yml   # CI/CD (Python 3.10-3.12 + Node 20 + Docker)
```

---

## Tests

```bash
# Backend (168 tests)
cd backend
PHOENIX_SECRET_KEY=test python -m pytest tests/ -v

# Frontend (21 tests Vitest)
npm test
```

**189 tests** couvrant :
- API REST : authentification (register/login/refresh/logout/password), CRUD investigations, IoCs, timeline, stats, audit
- API v4 : `/livez`, `/readyz`, `/metrics`, token rotation, revocation, politique mots de passe
- Cache : fallback in-memory, TTL, sliding window, thread safety
- Auth : hashing PBKDF2 versionne, upgrade transparent, decode/revoke
- Observabilite : JSON formatter, Prometheus counters/histograms
- Parsers : EVTX, CSV, JSON, LOG, Prefetch (SCCA + MAM), LNK (MS-SHLLINK), browser history (Chromium + Firefox), extraction IoCs
- MITRE ATT&CK : mapping Event IDs, mapping IoC types, resume par tactique
- Middleware : rate limiting, validation UUID, sanitisation
- Sigma : 26 regles, criteres contains/equality, threshold, filtre par tactique, couverture MITRE
- Integrations : registre, 13 connecteurs, endpoints API, configuration
- Frontend : helpers de tokens, intercepteurs axios, auto-refresh 401, apiService

---

## CI/CD

Le pipeline GitHub Actions execute 5 jobs :

1. **backend-tests** (matrix Python 3.10/3.11/3.12) : suite complete des 168 tests backend
2. **security-scan** : Bandit SAST sur le backend + pip-audit sur les dependances (rapports en artifacts)
3. **sbom** : generation d'un SBOM CycloneDX JSON des dependances Python
4. **frontend-build** : lint (0 erreur) + 21 tests Vitest + compilation et rapport de taille du bundle (artifact upload)
5. **docker-build** : build avec buildx + cache GHA, smoke test (`/livez`, `/api/health`, `/metrics`)

---

## Contribution

1. Fork le projet
2. Creer une branche (`git checkout -b feature/nom-de-la-feature`)
3. Commiter les changements
4. Pousser la branche (`git push origin feature/nom-de-la-feature`)
5. Ouvrir une Pull Request

Pour ajouter un nouveau connecteur d'integration, creer un fichier dans `backend/integrations/` heritant de `BaseConnector` et utilisant le decorateur `@registry.register`.

---

## Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de details.

---

<p align="center">
  <strong>Phoenix DFIR</strong> - Plateforme d'Investigation Forensique
</p>
