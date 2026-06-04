# Changelog

Tous les changements notables sont consignes dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/), le projet adhere au
[Semantic Versioning](https://semver.org/).

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
