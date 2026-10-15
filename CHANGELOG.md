# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

---

## [4.11.0] - 2026-10-15

### Security

- **Path traversal in `/api/analyze`** (critical): analysis now takes an
  `artifact_id` resolved from the database; a bare upload name is only
  accepted when it resolves inside the uploads folder. The JWT signing key
  could previously be read through this endpoint.
- **Accounts**: self-registration is closed by default. The first admin is
  created from `PHOENIX_ADMIN_USERNAME` / `PHOENIX_ADMIN_PASSWORD` or with a
  one-time setup token printed in the server log; admins manage users and
  roles (admin, analyst, viewer) from Settings.
- **Case-level access control**: investigations have members; every route,
  list and export checks membership (404 when denied). Viewers are read-only.
- **Real-time isolation**: WebSocket events are delivered per investigation
  room; expired or revoked sessions are disconnected; the token is no longer
  accepted in the query string.
- **Sessions**: refresh token in an HttpOnly, SameSite=Strict cookie; access
  token kept in memory; all sessions revoked on password, role or status
  change.
- **Brute force**: the client IP is no longer taken from a spoofable
  `X-Forwarded-For` (set `PHOENIX_TRUSTED_PROXIES` behind a proxy); per-account
  lockout after repeated failures.
- **AI investigator isolation**: tool sandbox, forced case directory and
  evidence index are scoped to each job; the prompt-injection shield handles
  Unicode lookalikes and more phrasings.
- **Hardening**: streamed hashing and disk extraction, size caps on JSON and
  log lines, symlinks rejected in the inbox, unique upload names, CSV formula
  neutralization, IoC validation and URL encoding in connectors, masked
  integration secrets, generic error messages, optional `/metrics` token,
  per-user job quota.
- **Dependencies**: Flask 3.1, Werkzeug 3.1, flask-cors 6, python-socketio 5.17,
  npm packages updated (0 known advisories).

### Fixed

- Production stack: gunicorn pinned below 26, which removed the eventlet worker
  used by `docker-compose.prod.yml`.
- WebSocket transport refused same-origin connections under eventlet (the
  origin check now reads the WSGI environ).
- Uploads from the analyzer page were not attached to the selected case.

---

## [4.10.0] - 2026-10-15

### Added: Disk images (The Sleuth Kit)

- **`phoenix_dfir_mcp/disk.py` module**: reads disk images **without
  mounting** them (E01/Ex01, dd/raw/img/001, VMDK, VHD/VHDX, AFF) using The
  Sleuth Kit. `.raw`/`.bin` files are classified as disk or memory by
  signature (MBR, GPT, NTFS, ext).
- **Five MCP tools**: `disk_status`, `disk_image_info` (partitions, offsets,
  file system), `disk_list_files` (directory tree, path filter, **deleted
  files**), `disk_timeline` (**MACB** timeline indexed into the FTS5
  super-timeline), `disk_extract_artifacts` (`windows`, `linux` and `auto`
  profiles: EVTX, registry hives, Amcache, Prefetch, scheduled tasks, SRUM,
  NTUSER/UsrClass, LNK, PowerShell history, browser histories, $MFT, Linux
  logs, crontabs, SSH keys, systemd services).
- Extraction to `extracted/<image>/p<offset>/` with a **per-file SHA-256**
  and an `extraction_manifest.json` manifest. Extracted files automatically
  enter the coverage gate of subsequent phases.
- **Inode citations**: new `inode` reference type (including the composite
  `128-128-1` form), validated against the evidence index.
- Console: **Disk images** agent showing actual The Sleuth Kit
  availability. Image extensions are accepted on upload and in the vault.
- The Sleuth Kit is installed in the Docker image and in CI.

### Added: Benchmark with factual answer key

- `ground_truth.json` accepts **facts** (`facts`): question, accepted
  answers, related terms. Two scores: `fact_exact` (exact answer cited in
  the report) and `fact_detection` (topic addressed). A `--min-fact-exact`
  threshold is available for evaluation CI.
- New **`disk_image_data_exfiltration`** case: a reproducible ext4 image
  (`eval/build_disk_case.py`) of a workstation where a confidential folder is
  archived, exfiltrated over HTTP and then deleted; four factual questions.
- End-to-end test: 5/5 quality gates passed and 100% exact facts on this
  case.

### Changed

- Documentation fully rewritten (README, Windows/Docker guide, evaluation
  bench, MCP server).

---

## [4.9.0] - 2026-10-15

### Added: Five-phase investigation with quality gates

- **Phase engine** (`phoenix_dfir_mcp/phases.py`, default): Inventory,
  Extraction, Correlation, Counter-analysis, Report. Per-phase prompt and
  tool allowlist; **deterministic quality gates** (case memory, evidence
  index, report sections); retry with the exact list of gaps (at most 2),
  then continuation with partial results flagged; compact state passed
  between phases; deterministic fallback report. Each gate is sealed in the
  chain of custody and visible in the console.
- **SQLite FTS5 super-timeline** (`evidence_db.py`): all deterministic tool
  outputs are normalized (UTC timestamp, host, user, process, evidence
  references); new tools `search_evidence`, `get_timeline`, `list_sources`.
  Citation validation also relies on this persistent index (valid across
  restarts).
- **Counter-analysis**: `challenge_finding` (upheld / weakened / dismissed)
  and the `audit_tool_coverage` / `audit_evidence_coverage` audits;
  `declare_no_incident` to close a clean case without inventing findings.
- **`PHOENIX.md` briefing** injected into every phase (`.md` upload
  allowed).
- **Exports**: ATT&CK Navigator layer and IoC CSV, downloadable from the AI
  Investigator page; dismissed findings are excluded.
- Evaluation bench: `--mode phased|loop` to compare the two engines.

---

## [4.8.0] - 2026-10-15

### Security

- **Authenticated WebSocket**: the client sent no token, and the server
  accepted every connection and broadcast investigation events (investigator
  steps, findings, chain of custody, validation requests) to all clients.
  The access token is now sent on every (re)connection, anonymous or invalid
  connections and connections using a refresh token are rejected, and all
  events are emitted only to the authenticated clients room
  (`extensions.emit_secure`).

### Added

- **Investigator evaluation bench** (`phoenix_dfir_mcp/evaluation.py`,
  `python -m phoenix_dfir_mcp eval`): annotated cases (`ground_truth.json`),
  ATT&CK technique recall, forbidden techniques, IoC recall, evidence
  grounding (findings rejected when they lack an observed reference),
  injection detection, false positives on clean cases, cost; Markdown/JSON
  reports and blocking thresholds. Initial suite of 4 cases in `eval/suite/`.

### Changed

- The "SOC Console" becomes the **DFIR Investigator Console** (page,
  navigation, `GET /api/console/status` API, documentation): Phoenix is a
  forensic investigation tool, not a SOC console.

---

## [4.7.0] - 2026-10-13

### Added: LLM loop security

- **Prompt injection shield** (`phoenix_dfir_mcp/shield.py`): every tool
  output handed to the LLM (investigator, verification and adviser passes,
  stdio MCP server) is sanitized (control characters, zero-width characters,
  bidi overrides). English and French injection phrasing, role tokens
  (ChatML, Llama) and hidden tool calls are neutralized, and the output is
  then wrapped in a `<donnees_outil>` envelope with a random nonce. A
  detected attempt becomes an anti-forensics finding (verified, one per
  artifact), is sealed in the chain of custody and counted
  (`prompt_injections_neutralized`). The original artifact is never
  modified.
- **Strict structured output**: `record_finding` requires `evidence_refs`
  (`record_id`, `pid`, `line`, `row`), validated against an index of the
  identifiers actually produced by the deterministic tools. Parsers now
  expose `record_id` (EVTX), `line` (logs) and `row` (CSV); `sigma_scan`
  keeps the RecordID. Can be disabled with `PHOENIX_STRICT_EVIDENCE=false`.
- **Hybrid LLM**: `openai` provider (`OPENAI_API_KEY`, `OPENAI_BASE_URL`,
  `PHOENIX_OPENAI_MODEL`) and `auto` provider (local Ollama if it responds,
  otherwise OpenAI, otherwise GitHub Copilot; probe cached for 60 s). Docker
  uses `auto` by default.

---

## [4.6.0] - 2026-10-13

### Added: Investigator console, chain of custody, human validation, memory forensics

- **SHA-256 chain of custody** (`backend/custody.py`, `custody_chain`
  table): an append-only ledger in which each link seals its content and the
  hash of the previous link. Sealed items: evidence acquisitions (upload,
  watched folder, vault), each tool run by the investigator (hash of its
  output), findings, remediations and decisions, and the final report.
  `GET /api/custody/verify` detects tampering, deletion or insertion.
- **Human validation (human in the loop)**: new MCP tool
  `propose_remediation`. The action moves to `WAITING_APPROVAL` and an
  analyst or admin approves or rejects it
  (`POST /api/remediation/:id/decision`). Phoenix never executes the action;
  the decision is sealed, logged and recorded in the report appendix.
- **Investigator console** (new React page): swarm of specialized agents
  with actual tool availability, real-time timeline (WebSocket events
  `agent_step`, `hitl_required`, `hitl_resolved`), hash inspector, integrity
  verification, evidence vault, and launching the investigator on an
  existing investigation.
- **Read-only evidence vault** (`./evidence_vault:/mnt/evidence:ro`,
  `backend/evidence_vault.py`): attachment without copying (symbolic links
  in the case folder), computed hashes, path traversal rejected.
- **Volatility 3** (`phoenix_dfir_mcp/volatility.py`): `volatility_status`,
  `run_volatility` (20 allowlisted plugins, read-only, flattened JSON
  output, `--pid` filter). Upload of `.raw/.mem/.vmem/.dmp/.lime` dumps.
- **Hayabusa** (`phoenix_dfir_mcp/hayabusa.py`): `hayabusa_status`,
  `run_hayabusa` (json-timeline, alerts sorted by severity).
- **Air-gapped local LLM**: `PHOENIX_LLM_PROVIDER=ollama` (Ollama's
  OpenAI-compatible API, `OLLAMA_BASE_URL`, `PHOENIX_OLLAMA_MODEL`).
- **Docker**: `INSTALL_DFIR_TOOLS` build arg (Volatility 3 and Hayabusa,
  enabled by docker-compose), read-only vault mount, `host.docker.internal`
  for Ollama. New `docs/WINDOWS_DOCKER.md` guide (WSL 2, Defender
  exclusion, icacls).
- **27 MCP tools**; test suite: 241 backend and 25 frontend tests.

### Fixed

- Chain of custody writes now happen after pending transactions are
  committed (watcher, vault import), which avoids a SQLite lock.

---

## [4.5.0] - 2026-07-09

### Added: Independent finding verification and tool sandboxing

- **Verification layer**: after the investigation, an independent
  (read-only) pass rechecks each finding against the RAW evidence at its
  source and marks it `verified` / `unverified` / `refuted`, which reduces
  false positives (new `verify_finding` tool, extended memory,
  `phoenix_dfir_mcp/investigator._run_verification`). The report shows a
  "Verification" column and the metrics expose `findings_verified` /
  `findings_unverified` ("Verified" tile in the UI). Findings that cannot be
  reproduced are marked `unverified` as a precaution.
- **File access sandboxing** (`phoenix_dfir_mcp/pathpolicy.py`):
  LLM-driven tools are confined to the case directory tree, and any access
  outside the allowed roots is denied (protects against reading
  `/etc/passwd`, SSH keys, etc.). The investigator registers the case folder
  automatically; additional roots can be set with `PHOENIX_TOOL_ROOTS`.
  Permissive while no root is configured (backward compatible).
- **22 MCP tools** (+`verify_finding`); new tests (sandbox allow/deny,
  `PHOENIX_TOOL_ROOTS`, verification pass, default marking). Backend suite:
  222 tests. Validated in a real E2E run (37/37): verification and
  sandboxing work from the Copilot loop through to the web interface.

---

## [4.4.0] - 2026-07-09

### Added: Investigation intelligence (planning, memory, adviser, observability)

The autonomous investigator moves from a reactive loop to a genuinely
structured investigation process:

- **Planning** (`set_investigation_plan`, `complete_plan_step`): the case is
  broken down into 3 to 7 steps tracked through to completion.
- **Structured investigation memory** (`phoenix_dfir_mcp/memory.py`,
  `case_state.json`): timestamped findings linked to evidence
  (`record_finding`: severity, confidence, MITRE technique) and hypotheses
  (`set_hypothesis`: open/confirmed/refuted), retrievable with
  `get_case_state`. Large multi-artifact cases can be handled without
  saturating the context window. The report automatically appends this
  summary (findings table, hypotheses, plan followed).
- **Execution monitoring**: detection of loops (same tool replayed 3 times)
  and repeated errors, with corrective advice injected (mentor).
- **Adviser review**: a final critical pass checks that the investigation is
  complete and supported (evidence, timeline, IoCs, MITRE,
  recommendations) and restarts the investigator if gaps remain (capped at 2
  reviews).
- **Observability**: tokens consumed (prompt/completion/total), LLM calls,
  number of findings and review verdict are reported in the UI (metric
  tiles) and in the CLI/job result.
- 5 new MCP tools (21 in total); new tests (memory, loop detection, adviser
  restart, loop with metrics). Backend suite: 214 tests. Validated in a real
  E2E run (35/35): plan, findings, hypotheses, adviser and tokens flow from
  the Copilot loop through to the web interface.

---

## [4.3.1] - 2026-07-09

### Fixed: Production hardening after a full real E2E test (30 checks)

An end-to-end test against a real running backend (auth, uploads, Copilot
loop over HTTP, WebSocket, inbox drop, real Windows EVTX) revealed and fixed
the following:

- **WebSocket never delivered from worker threads**: the eventlet server
  ignored `socketio.emit()` calls from analyses, the investigator and the
  watcher. `eventlet.monkey_patch()` is now applied at the top of `app.py`
  (aligning dev and gunicorn prod). Real-time progress now actually works.
- **Frontend never served in single-container mode**: the Docker image
  copied the build into `/app/frontend` but Flask did not serve it. The
  backend now serves the build (including SPA fallback), so the full
  interface is available at `http://<host>:5000` (`PHOENIX_FRONTEND_DIR`, or
  `dist/` at the root).
- **CORS/WebSocket blocked outside localhost**: origins are configurable via
  `PHOENIX_CORS_ORIGINS` (exposed in both compose stacks), and the server's
  own origin is accepted automatically (team access by IP). Frontend: the
  API/WebSocket URL is auto-detected from the page's origin, and the
  "Backend URL" field in settings now takes effect.
- **More reliable EVTX parsing**: the Rust `evtx` engine (pyevtx-rs,
  prebuilt wheels) is used first, with python-evtx as a fallback. Validated
  on a real Windows Security log (999 events, real Sigma alerts).
  `requirements-optional.txt` can no longer fail as a whole (hexdump
  removed).
- **Protected evidence**: `cleanup_old_files` now only deletes orphaned
  uploads; artifacts attached to an investigation are NEVER purged.

---

## [4.3.0] - 2026-07-09

### Added: Autonomous investigator built into the platform, end to end

- **AI Investigator page** in the web interface: drag and drop evidence
  (all forensic formats), automatic investigation creation, upload, launch
  of the autonomous GitHub Copilot investigation, real-time log (WebSocket
  `autonomous_progress`), and the final report displayed and downloadable.
- **Watched drop folder** (`backend/watcher.py`): drop files or a folder
  into `backend/evidence_inbox/` (configurable via `PHOENIX_EVIDENCE_DIR`)
  and an investigation is created, artifacts are attached (hashes
  computed) and the autonomous investigator starts automatically. Each
  dropped subfolder becomes a case named after it. Can be disabled with
  `PHOENIX_INBOX_ENABLED=false`.
- **API**: `GET /api/autonomous/status`, `POST /api/autonomous/investigate`
  (starts a background job), `GET /api/autonomous/jobs/<id>`.
  The runner (`backend/autonomous.py`) copies the investigation's artifacts
  into a case folder, delegates to `phoenix_dfir_mcp.investigator`, saves
  the report in `backend/reports/`, inserts extracted IoCs into the
  database, records the timeline and writes the audit log.
- **Extended upload formats**: `.pf`, `.lnk`, `.sqlite`, `.db`, `.ps1`,
  `.bat`, `.sh`, `.hve`, `.dat` are accepted in addition to existing
  formats.
- **Easy startup**: `start.bat` / `start.sh` display the GitHub Copilot
  status and the drop folder. The Dockerfile bundles `mcp-server/` and
  `legacy/`, and a `phoenix-inbox` volume is added to both docker-compose
  stacks.
- **Tests**: 14 tests (autonomous routes, full runner with mocked Copilot,
  watcher: detection, per-folder cases, partial files ignored). Full
  backend suite: 211 passing tests.

---

## [4.2.0] - 2026-07-09

### Added: Autonomous DFIR investigator, MCP server orchestrated by GitHub Copilot

- **New `mcp-server/` module** (`phoenix_dfir_mcp`): MCP server (Model
  Context Protocol, stdio, native JSON-RPC implementation, zero
  dependencies) exposing 16 forensic tools that reuse the Phoenix backend:
  `list_artifacts` (inventory and hashes), native parsers for all formats
  (EVTX, CSV, JSON, logs, Prefetch, LNK, browser histories),
  `extract_iocs`, `sigma_scan` (26 built-in rules), `mitre_map_events`,
  `virustotal_lookup`, `save_report`.
- **Integrated Eric Zimmerman tools** (`run_zimmermann` /
  `zimmermann_status`): EvtxECmd, PECmd, LECmd, JLECmd, MFTECmd,
  AmcacheParser, AppCompatCacheParser, RECmd, SBECmd, SrumECmd, SQLECmd,
  WxTCmd, run via dotnet (EZ_TOOLS_PATH), with CSV output parsed and
  graceful fallback to the native parsers when they are missing.
- **VS Code agent mode**: `.vscode/mcp.json` included, so GitHub Copilot
  (agent mode) discovers and orchestrates the DFIR tools directly.
- **Autonomous investigator**: `python -m phoenix_dfir_mcp investigate
  <case>`. GitHub Copilot (GitHub Models API, function calling) solves the
  case on its own in an agentic loop: inventory → parsing of each artifact →
  Sigma detection → IoC correlation → enrichment → timeline → MITRE mapping
  → Markdown report saved in the case folder.
- **Tests**: 22 tests (tool registry, MCP protocol, Sigma normalization, EZ
  Tools, agentic loop with mocked Copilot) integrated into CI.

---

## [4.1.0] - 2026-07-09

### Added: GitHub Copilot as the sole AI provider

- **GitHub Copilot (GitHub Models API)** becomes the only AI provider for
  analyses (`legacy/phoenix.py`): artifacts, IoC/timeline extraction and
  executive summaries. Configured through environment variables:
  `GITHUB_TOKEN` or `PHOENIX_GITHUB_TOKEN` (*Models: read* permission) and
  `PHOENIX_GITHUB_MODEL` (default `openai/gpt-4o-mini`). Only requires
  `requests`, already in `requirements.txt`.
- **UI settings**: GitHub Copilot token and model fields on the Settings
  page.
- **Deployment**: AI variables passed through in `docker-compose.yml` and
  `docker-compose.prod.yml`, and documented in `.env.example`, `README.md`
  and `INSTALLATION.md`.
- **Tests**: 7 backend tests for the GitHub Copilot provider
  (`backend/tests/test_phoenix_ai.py`), skipped cleanly when the CLI's
  optional dependencies (typer, pandas) are missing.

### Removed: Former AI providers

- **Ollama and Google Gemini removed**: no more `ollama` /
  `google-generativeai` imports or related keys/models (`API_KEY_GOOGLE`,
  `MODEL_LOCAL`, `MODEL_REMOTE`); fields removed from the Settings page
  (with localStorage cleanup) and from the dependencies
  (`requirements-optional.txt`, `legacy/requirements.txt`).
- **`legacy/phoenix_service.py` removed**: an unused port of the CLI based
  on Ollama/Gemini.
- Without a GitHub token, AI analysis returns an explicit error; the
  platform remains functional with its native parsers (standalone).

### Changed

- `typer` and `pandas` added to `backend/requirements-optional.txt` to
  enable the AI analysis engine.
- `query_local` / `query_remote` kept as backward-compatible aliases of
  `query_github`; the VirusTotal key is configurable via `API_KEY_VT`.

---

## [4.0.1] - 2026-06-09

### Changed: Quality and maintainability

- **Backend refactored into blueprints**: `app.py` (2000 lines) split into
  11 blueprints under `backend/routes/` (health, investigations, iocs,
  timeline, artifacts, analysis, reports, stats, stix, integrations,
  mitre_attack) plus `extensions.py`, `helpers.py`, `sockets.py`,
  `phoenix_compat.py`. API paths, gunicorn entry point (`app:app`) and
  behavior are unchanged.
- **More reliable backend dependencies**: `python-evtx` (and the AI
  providers) moved to `backend/requirements-optional.txt`, installed on a
  best-effort basis everywhere (its `hexdump` dependency no longer builds
  with recent setuptools and was blocking the whole installation).
- **Legacy code isolated**: `phoenix.py`, `phoenix_service.py` and the root
  `requirements.txt` grouped under `legacy/` with documentation.
- **Reproducible frontend builds**: `package-lock.json` committed, `npm ci`
  in CI and in the Dockerfile, react-day-picker migrated from 8 to 9
  (removing the peer dependency conflict with date-fns and the
  `legacy-peer-deps` `.npmrc`).

### Added

- **Frontend tests**: Vitest and jsdom, 21 tests covering the token
  helpers, axios interceptors (Bearer injection, 401 auto-refresh, logout),
  `apiService` and `cn`. Integrated into CI along with linting.

### Fixed

- 29 ESLint errors (unused imports/variables, useless try/catch, missing
  Node globals for `scripts/` and config files).
- Versions aligned: `package.json` 4.0.x, React 19 badge in the README.

---

## [4.0.0] - 2026-06-04

### Added: Production hardening

- **Distributed cache and rate limiting**: `backend/cache.py` abstracts
  Redis (ZSET sliding window, pipelines) with a thread-safe in-memory
  fallback. Enabled via `REDIS_URL`.
- **Observability**: `backend/observability.py` provides a JSON formatter
  for stdout (ready for any log aggregation platform) and exposes a Prometheus
  `/metrics` endpoint with counters for HTTP, auth failures, integration
  calls, rate limit blocks and artifacts analyzed, plus the
  `phoenix_investigations_active` gauge.
- **Kubernetes-ready health probes**:
  - `/livez`: liveness without dependencies, always returns 200 while the
    process is alive
  - `/readyz`: readiness checking DB and Redis, returns 503 if a dependency
    is down
  - `/api/health` kept, now including the cache backend
- **Refresh tokens**: access (15 min) and refresh (7 days) tokens with
  **rotation** on every refresh and **server-side revocation** through the
  cache (jti TTL aligned with exp).
- **Strong password policy**: 12+ characters, 3+ character classes
  (upper/lower/digits/special), denylist of 30+ weak words. PBKDF2-SHA256
  raised to 600,000 iterations, **versioned** hash format
  (`pbkdf2_sha256$iter$salt$key`) and **transparent upgrade** at login.
- **New auth endpoints**: `POST /api/auth/refresh`, `POST /api/auth/logout`,
  `PUT /api/auth/password`.
- **Production stack**: `docker-compose.prod.yml` runs Phoenix, Redis 7 and
  Nginx 1.27 with health checks, `no-new-privileges`, `cap_drop: ALL`,
  Redis maxmemory and appendonly, and json-file logs rotated at 10m/5.
- **Nginx reverse proxy** (`deploy/nginx.conf`): Socket.IO WebSocket,
  X-Forwarded-* propagation, /metrics restricted to the internal subnet,
  JSON access logs, gzip.
- **Gunicorn and eventlet**: `backend/gunicorn.conf.py` serves
  Flask-SocketIO in production with max_requests and jitter to guard against
  memory leaks.

### Added: Forensic capabilities

- **Parsers**:
  - **Prefetch (.pf)**: uncompressed Win7/8 SCCA plus MAM/XPRESS detection
    (Win10/11), with a `pyscca` fallback when available
  - **Browser history (.sqlite)**: Chromium (`urls`, WebKit epoch) and
    Firefox (`moz_places`, PRTime), using a local copy to avoid locks
  - **LNK (.lnk)**: native MS-SHLLINK parser (target path, args, working
    dir, FILETIME timestamps), with severity escalation on suspicious
    patterns
- **Sigma rules**: increased from 7 to **26 rules** covering 9 MITRE tactics
  (credential_access, defense_evasion, persistence, privilege_escalation,
  execution, lateral_movement, command_and_control, impact, and discovery)
- **Extended Sigma matching engine**: `*_contains` criteria (image,
  command_line, target_object, service_name), equality criteria
  (logon_type, ticket_encryption), proper threshold counting, filtering by
  tactic

### Added: Integrations (5 new connectors)

- **GreyNoise**: Internet noise vs targeted traffic, Community (no key) and
  Enterprise (with key), benign/malicious/unknown classification, RIOT flag
- **urlscan.io**: historical URL search (by URL, domain, IP), URL submission
  for rendered analysis, screenshot retrieval
- **ThreatFox** (abuse.ch): search for active malware IoCs with exact match,
  bulk import of IoCs from the last 7 or 30 days
- **MalwareBazaar** (abuse.ch): sample lookup by MD5/SHA1/SHA256, retrieval
  of recent hashes, signature metadata and tags
- **URLhaus** (abuse.ch): lookup of URLs, hosts and payloads by hash

### Added: CI and tooling

- `security-scan` job: Bandit (SAST) and pip-audit (vulnerable
  dependencies) with JSON reports uploaded as artifacts (30-day retention)
- `sbom` job: generates a CycloneDX JSON SBOM of the Python dependencies
  (90-day retention)
- `frontend-build` job: uploads dist/ as an artifact (7-day retention)
- `docker-build` job: uses `docker/build-push-action@v5` with the GitHub
  Actions cache (`type=gha`), smoke test on `/livez`, `/api/health` and
  `/metrics`
- `pip` and `npm` caches enabled on the Python/Node jobs

### Added: Tests

- **168 tests** (87 more than v3.0). New modules:
  - `tests/test_cache.py` (10): in-memory, TTL, sliding window, thread safety
  - `tests/test_auth.py` (16): hash format/upgrade, password policy, tokens
  - `tests/test_observability.py` (5): JSON formatter, Prometheus
  - `tests/test_new_connectors.py` (12): 5 new connectors
  - `tests/test_new_parsers.py` (10): Prefetch, browser history, LNK
  - `tests/test_sigma_rules.py` (12): 26 rules and the matching engine
  - `tests/test_api_v4.py` (14): `/livez`, `/readyz`, `/metrics`, refresh flow

### Changed

- Security headers: stricter CSP (`'unsafe-inline'` removed for scripts),
  COOP/CORP added, extended Permissions-Policy (payment), `Server:` header
  removed
- Client IP: `X-Forwarded-For` (first element) is taken into account for
  rate limiting behind a proxy
- Request-ID: regex validation and a maximum length of 64
- `app.py`: deprecated `datetime.utcnow()` replaced with
  `datetime.now(timezone.utc)`
- Rate limit: automatically bypassed in Flask `TESTING` mode to avoid
  interference between test classes

### Security

- The unversioned "salt+key hex" hash format is no longer written: it is
  still accepted on read (verify_password remains compatible), but the new
  format is always written at login (transparent upgrade).
- Failed logins are recorded in the audit log (`action=login_failed`).

### Migration notes from v3.0

- **Passwords**: users whose password does not meet the new policy can
  still **log in** (verify_password is backward compatible), but must choose
  a new one via `PUT /api/auth/password` before a reset is enforced.
- **v3 tokens**: the `PHOENIX_TOKEN_EXPIRY` variable still works and
  overrides `PHOENIX_ACCESS_TOKEN_EXPIRY`. Existing access tokens remain
  valid until they expire but cannot be refreshed (they have no jti or
  associated refresh token).
- **Reverse proxy**: when deploying behind a proxy, configuring
  `X-Forwarded-For` is now required for correct rate limiting.
- **Healthchecks**: the Docker healthcheck in the root `docker-compose.yml`
  and in `docker-compose.prod.yml` targets `/readyz` (more precise). The
  image healthcheck (Dockerfile `HEALTHCHECK`) targets `/livez`.

---

## [3.0.0] - 2026-02-15

### Added
- Integration framework with 8 connectors: MISP, Cortex, VirusTotal,
  AbuseIPDB, Shodan, AlienVault OTX, YARA, Sigma
- 7 built-in Sigma rules
- Native STIX 2.1 export (bundle, identity, report, indicators)
- MITRE ATT&CK mapping (20+ Event IDs, 9 IoC types)
- 81 tests
- GitHub Actions CI on Python 3.10/3.11/3.12

### Security
- JWT authentication with roles (admin/analyst/viewer)
- In-memory rate limiting
- Security headers (CSP, HSTS, X-Frame, nosniff, Referrer-Policy)
- Request ID tracking
- Path traversal protection
- Complete audit log
