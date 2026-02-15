<p align="center">
  <img src="phoenix.png" alt="Phoenix DFIR" width="200" />
</p>

<h1 align="center">Phoenix DFIR</h1>

<p align="center">
  <strong>Plateforme d'Investigation Forensique Numerique et de Reponse aux Incidents</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0-orange?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/tests-81%20passed-brightgreen?style=flat-square" alt="Tests" />
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/react-18-blue?style=flat-square&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/docker-ready-blue?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
</p>

---

## Vue d'ensemble

Phoenix DFIR est une plateforme complete d'investigation forensique numerique deployable en un seul conteneur Docker. Elle combine l'analyse d'artefacts, la gestion des IoCs, le mapping MITRE ATT&CK, l'export STIX 2.1 et l'integration avec 8 plateformes externes de Threat Intelligence, le tout avec une interface web moderne et une API REST securisee.

### Pourquoi Phoenix DFIR

| Critere | TheHive | DFIR-IRIS | Velociraptor | **Phoenix DFIR** |
|---|---|---|---|---|
| Deploiement | Java + Cassandra + ES | Docker multi-service | Binaire Go | **1 conteneur Docker** |
| Integrations natives | Cortex | MISP (partiel) | VQL | **8 plateformes** |
| MITRE ATT&CK | Plugin | Plugin | Partiel | **Natif** |
| STIX 2.1 | Plugin | Non | Non | **Natif** |
| Regles Sigma | Non | Non | Non | **Natif (7 regles integrees)** |
| YARA | Non | Non | Oui | **Natif** |
| Extraction auto IoCs | Non | Non | Non | **Regex multi-types** |
| Bulk import IoCs | Oui | Oui | Non | **JSON + texte libre** |
| Security headers | Non par defaut | Non par defaut | Non par defaut | **CSP, HSTS, X-Frame, nosniff** |
| Rate limiting | Non | Non | Non | **Natif (in-memory)** |
| CI/CD | Manuel | Manuel | GitHub Actions | **GitHub Actions (3 jobs)** |
| Tests | Variable | Variable | Oui | **81 tests, 0 failures** |

---

## Fonctionnalites

### Investigation Forensique
- Gestion complete des enquetes (creation, statut, archivage)
- Upload et analyse d'artefacts multi-formats (EVTX, CSV, JSON, LOG, XML, PCAP)
- Calcul automatique des empreintes MD5, SHA1, SHA256
- Timeline interactive avec severite et filtres
- Extraction automatique d'IoCs par analyse regex (IP, domaines, hashes, URLs, emails, CVE)
- Recherche et filtrage sur investigations et IoCs

### Threat Intelligence
- Enrichissement d'IoCs via VirusTotal, AbuseIPDB, Shodan, AlienVault OTX
- Push/Pull vers MISP (creation d'evenements, recherche d'attributs)
- Analyse automatisee via Cortex (lancement d'analyzers)
- Import en masse d'IoCs (JSON structure ou texte libre avec extraction auto)
- Export CSV des indicateurs

### Detection et Mapping
- Mapping MITRE ATT&CK natif (20+ Event IDs Windows, 9 types d'IoCs)
- Regroupement par tactique avec indicateurs associes
- 7 regles Sigma integrees (brute force, log clearing, persistence, privilege escalation)
- Support YARA pour le matching de regles sur artefacts
- Export STIX 2.1 complet (bundle, identity, report, indicators, confidence scoring)

### Securite
- Authentification JWT avec gestion de roles (admin, analyst, viewer)
- Rate limiting sur les endpoints d'authentification (10 req/min)
- Security headers : Content-Security-Policy, HSTS, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy
- Request ID tracking (X-Request-ID) pour le tracage distribue
- Protection contre les traversees de chemin
- Validation et sanitisation des entrees
- Journal d'audit complet de toutes les actions

### Interface
- SPA React 18 avec code splitting et lazy loading
- Design sombre professionnel optimise pour les analystes
- Notifications temps reel via WebSocket (Socket.IO)
- Raccourcis clavier (Alt+1 a Alt+9)
- Error boundary global
- Sidebar retractable avec navigation contextuelle

---

## Integrations Externes

Phoenix DFIR fournit un framework d'integration extensible avec 8 connecteurs prets a l'emploi :

| Plateforme | Categorie | Capacites |
|---|---|---|
| **MISP** | Threat Intelligence | Push IoCs, Pull IoCs, Recherche d'attributs, Creation d'evenements |
| **Cortex** | Analyse automatisee | Listing des analyzers, Lancement d'analyses sur observables |
| **VirusTotal** | Threat Intelligence | Enrichissement IP, Domain, Hash, URL via API v3 |
| **AbuseIPDB** | Reputation IP | Score d'abus, nombre de rapports, ISP, detection Tor |
| **Shodan** | Reconnaissance | Ports ouverts, vulnerabilites, services, geolocalisation |
| **AlienVault OTX** | Threat Intelligence | Pulses de menace, enrichissement, import abonnements |
| **YARA** | Moteur de regles | Matching sur artefacts, regles personnalisees |
| **Sigma** | Detection | 7 regles integrees, matching sur Event IDs Windows |

La configuration se fait via l'interface web (page Integrations) ou via l'API REST. Chaque connecteur peut etre active, configure et teste independamment.

---

## Demarrage Rapide

### Docker (recommande)

```bash
git clone https://github.com/servais1983/phoenix-dfir.git
cd phoenix-dfir
docker build -t phoenix-dfir .
docker run -d -p 5000:5000 -v phoenix-data:/app/data phoenix-dfir
```

L'application est accessible sur `http://localhost:5000`. Le premier utilisateur enregistre obtient automatiquement le role administrateur.

### Installation manuelle

**Prerequisites** : Python 3.10+, Node.js 20+

```bash
# Backend
cd backend
pip install -r requirements.txt
python app.py

# Frontend (developpement)
npm ci
npm run dev
```

### Variables d'environnement

| Variable | Description | Defaut |
|---|---|---|
| `PHOENIX_SECRET_KEY` | Cle secrete JWT | Auto-generee |
| `PHOENIX_TOKEN_EXPIRY` | Duree du token en secondes | 86400 (24h) |
| `PHOENIX_DEBUG` | Mode debug | false |
| `PHOENIX_PORT` | Port du serveur | 5000 |

---

## API REST

### Authentification
| Methode | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Inscription (rate limited) |
| POST | `/api/auth/login` | Connexion (rate limited) |
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
| GET | `/api/health` | Etat du systeme et connectivite DB |
| GET | `/api/stats` | Statistiques globales et series temporelles |
| GET | `/api/audit` | Journal d'audit (admin) |

---

## Architecture

```
phoenix-dfir/
  backend/
    app.py                    # Application Flask (1500+ lignes, 35+ endpoints)
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
    context/
      AuthContext.jsx          # Gestion de l'authentification
      AppContext.jsx           # Etat global de l'application
  Dockerfile                  # Multi-stage build (Node + Python)
  .github/workflows/ci.yml   # CI/CD (Python 3.10-3.12 + Node 20 + Docker)
```

---

## Tests

```bash
cd backend
python -m pytest tests/ -v
```

81 tests couvrant :
- API REST : authentification, CRUD investigations, IoCs, timeline, stats, audit, securite
- Parsers : extraction IoCs (IP, domaines, hashes, emails, URLs, CVE), parsing CSV/JSON/LOG
- MITRE ATT&CK : mapping Event IDs, mapping IoC types, resume par tactique
- Middleware : rate limiting, validation UUID, sanitisation
- Integrations : registre, 8 connecteurs, endpoints API, configuration

---

## CI/CD

Le pipeline GitHub Actions execute trois jobs :

1. **Backend tests** : Python 3.10, 3.11, 3.12 - parsers et API
2. **Frontend build** : Node.js 20 - compilation et rapport de taille du bundle
3. **Docker build** : Construction de l'image et test du health check

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
