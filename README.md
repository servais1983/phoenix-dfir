<p align="center">
  <img src="phoenix.png" alt="Phoenix DFIR" width="180" />
</p>

<h1 align="center">Phoenix DFIR</h1>

<p align="center">
  <strong>Digital forensics and incident response platform,<br/>
  with an autonomous AI investigator that backs every conclusion with evidence.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.10-orange?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/tests-341%20passed-brightgreen?style=flat-square" alt="Tests" />
  <img src="https://img.shields.io/badge/MCP-39%20tools-purple?style=flat-square" alt="MCP tools" />
  <img src="https://img.shields.io/badge/LLM-Ollama%20%7C%20OpenAI%20%7C%20GitHub%20Models-black?style=flat-square" alt="LLM" />
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/react-19-blue?style=flat-square&logo=react&logoColor=white" alt="React" />
  <img src="https://img.shields.io/badge/docker-ready-blue?style=flat-square&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License" />
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#the-autonomous-investigator">Autonomous investigator</a> ·
  <a href="#forensic-coverage">Coverage</a> ·
  <a href="#trust-model">Trust</a> ·
  <a href="#evaluation">Evaluation</a> ·
  <a href="#rest-api">API</a> ·
  <a href="#architecture">Architecture</a>
</p>

---

## At a glance

Phoenix DFIR turns a folder of evidence (EVTX logs, memory dumps, **disk
images**, text logs, execution artifacts) into a reasoned, timestamped and
verifiable investigation report.

- **An autonomous investigator in five phases**, each validated by a
  deterministic quality gate: no phase is closed on the LLM's word alone.
- **No finding without evidence**: every conclusion cites an EVTX RecordID, a
  PID, a log line, a CSV row or an inode actually observed by a deterministic
  tool. A fabricated identifier is rejected.
- **SHA-256 chain of custody**: acquisitions, tool executions, findings and
  decisions are sealed in a hash-chained ledger; any tampering is detected.
- **Humans decide**: containment actions are proposed, never executed, and
  wait for an analyst's approval.
- **Data sovereignty**: runs fully on-premises with Ollama. OpenAI and GitHub
  Models are optional.
- **Measurable**: an annotated evaluation suite (ATT&CK techniques, IoCs, exact
  facts, false positives) acts as a regression guard.

---

## Contents

1. [The autonomous investigator](#the-autonomous-investigator)
2. [Forensic coverage](#forensic-coverage)
3. [Trust model](#trust-model)
4. [DFIR Investigator Console](#dfir-investigator-console)
5. [Investigation platform](#investigation-platform)
6. [Evaluation](#evaluation)
7. [Quick start](#quick-start)
8. [Configuration](#configuration)
9. [REST API](#rest-api)
10. [Architecture](#architecture)
11. [Quality and CI](#quality-and-ci)
12. [Contributing and license](#contributing)

---

## The autonomous investigator

Drop the evidence for a case (via drag and drop, into the watched folder, or
into the read-only vault) and the investigator runs the investigation end to
end. It is built on an **MCP** (Model Context Protocol) server exposing **39
forensic tools**, usable autonomously or from any MCP client (including VS
Code agent mode through `.vscode/mcp.json`).

### Five phases, five gates

| Phase | Goal | Quality gate (deterministic) |
|---|---|---|
| **1. Inventory** | Enumerate artifacts, identify disk images and memory dumps, draw up a plan | Investigation plan recorded |
| **2. Extraction** | Run each artifact through its applicable tools; extract artifacts from disk images; feed the super-timeline | Every artifact processed, outputs indexed |
| **3. Correlation** | Link events, form hypotheses, record cited findings mapped to ATT&CK, or explicitly conclude that there was no incident | Findings referenced and mapped, or `declare_no_incident` |
| **4. Counter-analysis** | Challenge every critical or high finding with an alternative hypothesis; audit tool and evidence coverage | Findings ruled on (upheld / weakened / dismissed), audits run |
| **5. Report** | Write the report, generate the ATT&CK Navigator layer and the IoC CSV | Mandatory sections present |

Each phase has its own instructions and its own **tool allowlist**. If its
gate fails, the phase is rerun with the exact list of gaps (at most two
retries); beyond that, the investigation continues with partial results that
are explicitly flagged. Every gate is sealed in the chain of custody.

### Investigation method

- **Briefing**: a `PHOENIX.md` file (context, scope, questions) placed next to
  the evidence steers every phase.
- **Super-timeline**: all tool outputs are normalized (UTC timestamp, host,
  user, process, references) into a queryable **SQLite FTS5** index
  (`search_evidence`, `get_timeline`, `list_sources`).
- **Investigation memory**: plan, findings and hypotheses are persisted in the
  case folder, so the investigation scales to large cases without saturating
  the model's context.
- **Independent verification**: a read-only pass checks each finding against
  the raw evidence again and rules it *verified*, *unverified* or *refuted*.
- **Execution monitoring**: loops and repeated errors are detected and
  corrective instructions are injected.
- **Fallback report**: if the model fails to write the report, a deterministic
  report is produced from the case memory.

### Three ways to use it

| Mode | Usage |
|---|---|
| **Web interface** | *AI Investigator* page: evidence upload, live log, metrics (findings, tokens, gates), downloadable report and exports |
| **Watched folder** | `backend/evidence_inbox/`: each subfolder dropped in becomes a case that is created and resolved automatically |
| **Command line** | `python -m phoenix_dfir_mcp investigate <case_dir>` |

Detailed documentation: [`mcp-server/README.md`](mcp-server/README.md).

---

## Forensic coverage

| Domain | Formats | Capabilities |
|---|---|---|
| **Windows event logs** | EVTX | Native parser with MITRE mapping, 27 built-in Sigma rules, Hayabusa detection timeline |
| **Memory** | raw, mem, vmem, dmp, lime | Volatility 3: pslist/pstree, cmdline, malfind, netscan, svcscan... (allowlisted plugins) |
| **Disk images** | E01/Ex01, dd/raw/img/001, VMDK, VHD/VHDX, AFF | The Sleuth Kit **without mounting**: partitions, file tree, **deleted files**, **MACB** timeline, targeted artifact extraction with SHA-256 |
| **Windows artifacts** | Prefetch, LNK, $MFT, hives, Amcache, SRUM, Jump Lists | Native parsers + EvtxECmd, PECmd, LECmd, JLECmd, MFTECmd, AmcacheParser, AppCompatCacheParser, RECmd, SBECmd, SrumECmd, SQLECmd, WxTCmd |
| **Browsers** | Chromium / Firefox history (SQLite) | Visited URLs, downloads, timestamps |
| **Logs and data** | LOG, syslog, auth.log, CSV, JSON, XML | Generic parsing, multi-format timestamps, per-line references |
| **Network** | PCAP | Inventory and indicator extraction |
| **Indicators** | Any text format | Extraction of IPs, domains, URLs, hashes, emails, CVEs; VirusTotal enrichment |

### Disk images: from container to evidence

1. `disk_image_info`: partition table, offset and type of each file system.
2. `disk_list_files`: file tree of a partition, path filter, deleted files.
3. `disk_timeline`: MACB timeline indexed into the super-timeline.
4. `disk_extract_artifacts`: `windows`, `linux` or `auto` profiles (EVTX,
   hives, Amcache, Prefetch, scheduled tasks, SRUM, NTUSER/UsrClass, LNK,
   PowerShell history, browser history, $MFT, Linux logs, crontabs, SSH keys,
   systemd services). Each extracted file is hashed (SHA-256) and recorded in
   `extraction_manifest.json`, then analyzed like any other case artifact.

The original image is never mounted or modified. Findings derived from the
file system cite the **inode** (including NTFS composite inodes, e.g.
`128-128-1`).

---

## Trust model

Investigation artifacts are, by nature, attacker-controlled. Phoenix is
designed so that the LLM can neither be manipulated by them nor assert
anything it has not observed.

| Guarantee | Mechanism |
|---|---|
| **Grounded findings** | `record_finding` requires references (`record_id`, `pid`, `line`, `row`, `inode`) validated against the index of identifiers actually produced by the tools (`PHOENIX_STRICT_EVIDENCE`) |
| **Injection resistance** | Every tool output is sanitized (invisible characters, bidirectional overrides), French and English injection phrasing and role tokens are neutralized, and the output is then wrapped as untrusted data with a nonce. The attempt itself becomes an anti-forensics finding |
| **Evidence integrity** | Vault mounted read-only; disk images never mounted; MD5/SHA1/SHA256 hashes at acquisition, SHA-256 per extracted file |
| **Traceability** | Append-only ledger chained with SHA-256; `GET /api/custody/verify` detects modification, deletion or insertion |
| **Human control** | Remediations stay in `WAITING_APPROVAL` until an analyst decides; Phoenix never executes them |
| **Tool confinement** | LLM-driven tools are restricted to the case directory tree (`PHOENIX_TOOL_ROOTS`); Volatility plugins and external commands are allowlisted |
| **Confidentiality** | 100 % local mode with Ollama; the active provider is shown in the console |

---

## DFIR Investigator Console

A single console dedicated to the investigator:

- **Agent swarm**: Orchestrator, Triage and Collection, Disk and EVTX, Disk
  Images, Memory, Threat Intel, each shown with its actual availability
  (installed tools, LLM provider).
- **Live timeline** (authenticated WebSocket): agent, exact action, artifact,
  ATT&CK technique, severity, phase gates.
- **Evidence inspector**: hash of the chain link, previous link, hash of the
  tool output.
- **Human approval**: approve or reject proposed actions with a stated reason;
  the decision is sealed.
- **Evidence vault**: attach large evidence (memory dumps, multi-GB disk
  images) to an investigation without copying it.
- **One-click integrity check** of the entire chain.

---

## Investigation platform

**Case management**: investigations, artifacts, IoCs, interactive timeline,
Markdown reports, **STIX 2.1** export, native **MITRE ATT&CK** mapping.

**Detection**: 27 built-in Sigma rules across 8 tactics (credential access,
defense evasion, persistence, execution, lateral movement, command and
control, impact...), per-rule thresholds, YARA support.

**Threat intelligence**: 13 connectors configurable from the interface:

| Connector | Capabilities |
|---|---|
| MISP | IoC push / pull, attribute search, event creation |
| Cortex | Run analyzers on observables |
| VirusTotal | IP, domain, hash and URL enrichment |
| AbuseIPDB | IP reputation, ISP, Tor detection |
| Shodan | Ports, services, vulnerabilities |
| AlienVault OTX | Pulses, enrichment, subscriptions |
| GreyNoise | Internet background noise vs targeted traffic |
| urlscan.io | URL history and submission |
| ThreatFox | IoCs from active campaigns |
| MalwareBazaar | Samples by hash |
| URLhaus | Payload distribution URLs |
| YARA | Rules on artifacts |
| Sigma | Built-in detection engine |

**Application security**: JWT access (15 min) + refresh (7 days) tokens with
rotation and revocation, RBAC (admin / analyst / user), PBKDF2-SHA256 with
600,000 iterations, password policy, distributed rate limiting (Redis),
hardened security headers (CSP, COOP/CORP), audit log.

**Observability**: structured JSON logs, Prometheus metrics (`/metrics`),
`/livez` and `/readyz` probes, LLM token usage tracking.

---

## Evaluation

An AI investigator is only as good as what can be measured. The evaluation
suite replays the investigator on annotated cases and produces a Markdown and
JSON scorecard.

```bash
cd mcp-server
python -m phoenix_dfir_mcp eval ../eval/suite -o results
python -m phoenix_dfir_mcp eval ../eval/suite --min-recall 0.8 --max-forbidden 0 \
    --min-pass-rate 0.75 --min-fact-exact 0.75   # exit code 1 below thresholds
```

| Metric | What it measures |
|---|---|
| ATT&CK recall | Expected techniques found in the findings |
| Forbidden techniques | Explicit false positives |
| IoC recall | Expected indicators cited in the report |
| **Exact facts** | Answers from the factual answer key present in the report |
| Grounding | Share of accepted findings (references actually observed) |
| Injection | Booby-trapped artifacts detected |
| False positives on clean cases | Findings >= medium on a case with no incident |
| Cost | LLM calls, tokens, duration |

The bundled suite covers an SSH brute force, a PowerShell execution with a
booby-trapped artifact, C2 beaconing, legitimate administrative activity and
an **exfiltration reconstructed from a disk image** (deleted archive, HTTP
destination, user account) scored against a factual answer key. Details and
case format: [`eval/README.md`](eval/README.md).

---

## Quick start

### Docker Compose (recommended)

```bash
git clone https://github.com/servais1983/phoenix-dfir.git
cd phoenix-dfir
cp .env.example .env          # set at least PHOENIX_SECRET_KEY
docker compose up --build -d
```

Open <http://localhost:5000>. On first start the backend prints a one-time
**setup token** in its logs (`docker compose logs phoenix-dfir`): enter it in
the login page's *Installation* form to create the **administrator** account
(or set `PHOENIX_ADMIN_USERNAME` / `PHOENIX_ADMIN_PASSWORD`). Self-registration
is closed by default; the admin creates the other accounts in *Settings*. The image ships with Volatility 3, Hayabusa and The Sleuth
Kit; the `./evidence_vault` folder is mounted read-only and a local Ollama
instance is reachable through `host.docker.internal`.

Windows / Docker Desktop (WSL 2, Defender exclusion, Ollama, GPU):
[`docs/WINDOWS_DOCKER.md`](docs/WINDOWS_DOCKER.md).

### Production stack

Phoenix + Redis (distributed rate limiting, cache) + Nginx (TLS, compression):

```bash
python -c "import secrets; print(secrets.token_hex(64))"   # -> PHOENIX_SECRET_KEY in .env
docker compose -f docker-compose.prod.yml up -d
```

Put the certificates in `deploy/tls/` and enable the SSL directives in
`deploy/nginx.conf`.

### Local launchers

```bash
./start.sh        # Linux / macOS
start.bat         # Windows
```

They check for Python 3.10+ and Node.js 20+, install dependencies, then start
the frontend (`:5173`) and the backend (`:5000`).

### Manual installation

```bash
# Backend
cd backend
pip install -r requirements.txt
gunicorn --config gunicorn.conf.py app:app      # or: python app.py

# Frontend
npm ci && npm run dev

# Optional forensic tools (Debian / Ubuntu)
sudo apt-get install sleuthkit                  # disk images
pip install volatility3                         # memory
```

### LLM

| Provider | Configuration | Data |
|---|---|---|
| **Ollama** (recommended) | `PHOENIX_LLM_PROVIDER=ollama`, a model that supports *tool calling* (e.g. `qwen2.5-coder:14b`) | Stays on the investigation network |
| OpenAI or compatible | `OPENAI_API_KEY`, `OPENAI_BASE_URL` | Sent to the provider |
| GitHub Models | `GITHUB_TOKEN` (*Models: read* permission) | Sent to the provider |

`PHOENIX_LLM_PROVIDER=auto` (the default in Docker) picks Ollama if it
responds, then OpenAI, then GitHub Models. Without an LLM, all deterministic
analysis features remain available.

---

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `PHOENIX_SECRET_KEY` | JWT signing key (**required in production**) | generated in `.secret_key` (0600, dev only) |
| `PHOENIX_ENV` | `production` refuses to start without `PHOENIX_SECRET_KEY` | unset |
| `PHOENIX_ADMIN_USERNAME` / `PHOENIX_ADMIN_PASSWORD` | Initial admin created at startup when no user exists | unset (one-time setup token printed in the logs) |
| `PHOENIX_ALLOW_REGISTRATION` | Open self-registration (new accounts are `viewer`) | `false` |
| `PHOENIX_TRUSTED_PROXIES` | Number of trusted reverse proxies (enables `X-Forwarded-*` via ProxyFix) | `0` (set `1` behind the bundled nginx) |
| `PHOENIX_COOKIE_SECURE` | Force the `Secure` flag on the refresh cookie (automatic over HTTPS) | `false` |
| `PHOENIX_METRICS_TOKEN` | Bearer token required on `/metrics` when set | unset (public) |
| `PHOENIX_MAX_JOBS_PER_USER` | Concurrent autonomous investigations per user | `2` |
| `PHOENIX_LOGIN_LOCKOUT_THRESHOLD` / `PHOENIX_LOGIN_LOCKOUT_WINDOW` | Failed logins per username before lockout / window (s) | `10` / `900` |
| `PHOENIX_LLM_PROVIDER` | `auto`, `ollama`, `openai`, `github` | `github` (`auto` in Docker) |
| `OLLAMA_BASE_URL` / `PHOENIX_OLLAMA_MODEL` | Ollama server and model | `http://localhost:11434` / `qwen2.5-coder:14b` |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `PHOENIX_OPENAI_MODEL` | OpenAI or compatible provider | none / api.openai.com / `gpt-4o-mini` |
| `GITHUB_TOKEN` / `PHOENIX_GITHUB_MODEL` | GitHub Models | none / `openai/gpt-4o-mini` |
| `PHOENIX_INVESTIGATION_MODE` | `phased` (five phases) or `loop` (single loop) | `phased` |
| `PHOENIX_STRICT_EVIDENCE` | Findings must carry references | `true` |
| `PHOENIX_EVIDENCE_VAULT` | Read-only evidence vault | `/mnt/evidence` or `./evidence_vault` |
| `PHOENIX_EVIDENCE_DIR` | Watched drop folder | `backend/evidence_inbox` |
| `PHOENIX_INBOX_ENABLED` / `PHOENIX_INBOX_POLL_SECONDS` | Drop folder monitoring | `true` / `10` |
| `PHOENIX_TOOL_ROOTS` | Root paths allowed for LLM-driven tools | case folder |
| `PHOENIX_VOLATILITY_CMD` / `PHOENIX_VOLATILITY_SYMBOLS` | Volatility 3 and offline symbols | `vol` from PATH |
| `PHOENIX_HAYABUSA_CMD` / `PHOENIX_HAYABUSA_RULES` | Hayabusa binary and rules | `hayabusa` from PATH |
| `EZ_TOOLS_PATH` | EZ Tools folder | none |
| `REDIS_URL` | Distributed cache and rate limiting | in memory |
| `PHOENIX_ACCESS_TOKEN_EXPIRY` / `PHOENIX_REFRESH_TOKEN_EXPIRY` | Token lifetimes (s) | `900` / `604800` |
| `PHOENIX_PBKDF2_ITERATIONS` | Hashing iterations | `600000` |
| `PHOENIX_CORS_ORIGINS` | Additional origins (team access) | localhost |
| `PHOENIX_PORT` / `PHOENIX_WORKERS` / `PHOENIX_LOG_LEVEL` | Server | `5000` / `1` / `INFO` |

External tools (The Sleuth Kit, Volatility, Hayabusa, EZ Tools) are optional:
when missing, they report themselves as unavailable and the investigator falls
back to the native parsers.

---

## REST API

All `/api/*` routes (except authentication and health) require an
`Authorization: Bearer <access_token>` token.

<details>
<summary><strong>Authentication</strong></summary>

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/auth/setup-status` | Public: `needs_setup`, `registration_open` |
| POST | `/api/auth/register` | First admin (requires `setup_token`) or self sign-up as `viewer` when `PHOENIX_ALLOW_REGISTRATION=true` (5/min) |
| POST | `/api/auth/login` | Log in (10/min, username lockout): returns `access_token`, refresh token in an HttpOnly cookie |
| POST | `/api/auth/refresh` | Rotate the session from the refresh cookie |
| POST | `/api/auth/logout` | Revocation, clears the cookie |
| PUT | `/api/auth/password` | Change password (revokes every session) |
| GET | `/api/auth/me` | Current user |
| GET / POST | `/api/auth/users` | List / create users (admin) |
| PUT | `/api/auth/users/<id>/role` | Change role `admin`, `analyst`, `viewer` (admin, revokes sessions) |
| PUT / DELETE | `/api/auth/users/<id>/disabled`, `/api/auth/users/<id>` | Disable / re-enable an account (admin) |
| GET / POST / DELETE | `/api/investigations/<id>/members[/<user_id>]` | Case members (admin or case creator manage) |

Access control: an investigation and everything under it (artifacts, IoCs,
timeline, reports, exports, jobs, custody, remediations, real-time events) is
visible only to its members and to admins; other users get `404`. `viewer`
is read-only, `analyst` members can write, only an admin or the creator can
delete a case or manage its members.

</details>

<details>
<summary><strong>Investigations, artifacts, IoCs, timeline</strong></summary>

| Method | Endpoint | Description |
|---|---|---|
| GET / POST | `/api/investigations` | Paginated list (`?search=`, `?status=`) / create |
| GET / PUT / DELETE | `/api/investigations/:id` | Detail / update / delete |
| PUT | `/api/investigations/:id/status` | Status |
| POST | `/api/upload` | Upload with hashes |
| GET | `/api/investigations/:id/artifacts` | Artifacts |
| POST | `/api/analyze` · GET `/api/analysis/:id/status` | Asynchronous analysis |
| GET / POST | `/api/investigations/:id/iocs` | IoCs |
| POST | `/api/investigations/:id/iocs/bulk` | Bulk import |
| GET | `/api/investigations/:id/iocs/export` | CSV export |
| GET / POST | `/api/investigations/:id/timeline` | Timeline |
| GET | `/api/investigations/:id/mitre` | ATT&CK mapping |
| GET | `/api/investigations/:id/export/stix` | STIX 2.1 bundle |
| POST | `/api/reports/generate` · GET `/api/reports/:id/download` | Reports |

</details>

<details>
<summary><strong>Autonomous investigator and console</strong></summary>

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/console/status` | Agents, available tools, LLM, vault, chain head |
| GET | `/api/custody?investigation_id=` | Chain of custody links |
| GET | `/api/custody/verify` | Integrity check of the entire chain |
| GET | `/api/remediation?status=` | Proposed remediations |
| POST | `/api/remediation/:id/decision` | `{decision: approve\|reject, note}` (analyst / admin) |
| GET | `/api/evidence-vault` | Vault contents |
| POST | `/api/evidence-vault/import` | Attach evidence to an investigation |

</details>

<details>
<summary><strong>Integrations and system</strong></summary>

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/integrations` | Connectors and status |
| PUT | `/api/integrations/:id` | Configuration (admin) |
| POST | `/api/integrations/:id/test` | Connection test |
| POST | `/api/integrations/:id/enrich` · `/push` · `/pull` | Enrichment, IoC exchange |
| GET | `/livez` · `/readyz` · `/api/health` | Probes |
| GET | `/metrics` | Prometheus metrics |
| GET | `/api/stats` · `/api/audit` | Statistics, audit log (admin) |

</details>

---

## Architecture

```text
                 ┌──────────────────────────────── React 19 UI ────────────────────────────────┐
                 │  DFIR Investigator Console · AI Investigator · Cases · Timeline · IoCs ...  │
                 └──────────────┬───────────────────────────────────────▲──────────────────────┘
                          REST (JWT)                            authenticated WebSocket
                 ┌──────────────▼───────────────────────────────────────┴──────────────────────┐
                 │  Flask backend: API, RBAC, chain of custody, HITL, vault, watched folder    │
                 └──────────────┬──────────────────────────────────────────────────────────────┘
                                │
                 ┌──────────────▼──────────────── phoenix_dfir_mcp ────────────────────────────┐
                 │  5-phase engine + gates ── LLM (Ollama / OpenAI / GitHub Models)            │
                 │        │                      ▲ anti-injection shield                       │
                 │  39 tools: parsers · Sigma · ATT&CK · Hayabusa · Volatility 3 ·             │
                 │            The Sleuth Kit · EZ Tools · VirusTotal · memory · report         │
                 │        │                                                                    │
                 │  SQLite FTS5 super-timeline ── reference validation (strict evidence)       │
                 └─────────────────────────────────────────────────────────────────────────────┘
```

```text
phoenix-dfir/
├── backend/                  Flask API
│   ├── routes/               Blueprints (investigations, artifacts, console, autonomous...)
│   ├── integrations/         13 connectors (BaseConnector + registry)
│   ├── custody.py            SHA-256 chain of custody and HITL remediations
│   ├── evidence_vault.py     Read-only evidence vault
│   ├── parsers.py            Native parsers and IoC extraction
│   └── tests/                pytest suite
├── mcp-server/phoenix_dfir_mcp/
│   ├── phases.py             Five-phase engine and quality gates
│   ├── investigator.py       Agentic loop, verification, review
│   ├── toolkit.py            Registry of the 39 tools (MCP + function calling)
│   ├── disk.py               Disk images (The Sleuth Kit)
│   ├── volatility.py         Memory (Volatility 3)
│   ├── hayabusa.py           EVTX timeline
│   ├── zimmermann.py         EZ Tools
│   ├── evidence_db.py        SQLite FTS5 super-timeline
│   ├── shield.py             Anti-injection shield
│   ├── memory.py             Investigation memory
│   ├── exports.py            ATT&CK Navigator layer, IoC CSV
│   ├── evaluation.py         Evaluation suite
│   ├── copilot.py            Hybrid LLM client
│   └── server.py             MCP stdio server
├── src/                      React frontend (pages, services, contexts)
├── eval/                     Annotated cases and test disk image generator
├── evidence_vault/           Vault (mounted read-only in Docker)
├── docs/WINDOWS_DOCKER.md    Windows / Docker Desktop deployment
├── deploy/                   Nginx (production stack)
└── Dockerfile                Multi-stage build (Node + Python + DFIR tools)
```

---

## Quality and CI

```bash
cd backend && PHOENIX_SECRET_KEY=test python -m pytest tests/ -q   # backend
npm run lint && npm test                                           # frontend
```

More than **340 tests**: API and security, parsers, Sigma rules, connectors,
chain of custody, anti-injection shield, strict references, phase engine,
super-timeline, disk images (real integration with The Sleuth Kit),
evaluation suite, and an end-to-end scenario on a disk image (all five gates
passed, 100 % exact facts).

GitHub Actions pipeline:

| Job | Contents |
|---|---|
| `backend-tests` | Python 3.10 / 3.11 / 3.12, The Sleuth Kit installed |
| `security-scan` | Bandit (SAST) + pip-audit |
| `sbom` | CycloneDX SBOM |
| `frontend-build` | Lint, Vitest tests, build and bundle size |
| `docker-build` | buildx build, smoke test of `/livez`, `/api/health`, `/metrics` |

---

## Contributing

1. Create a branch: `git checkout -b feature/my-feature`
2. Add matching tests and run the full suite
3. Open a pull request

Adding a connector: a file in `backend/integrations/` that inherits from
`BaseConnector` and is registered with `@registry.register`.
Adding an investigation tool: an entry in `mcp-server/phoenix_dfir_mcp/toolkit.py`
and, if needed, its authorization in the relevant phases (`phases.py`).
Adding an evaluation case: see [`eval/README.md`](eval/README.md).

Reporting a vulnerability: [`SECURITY.md`](SECURITY.md).

## License

Released under the MIT license. See [LICENSE](LICENSE).

<p align="center"><sub><strong>Phoenix DFIR</strong>: digital forensics and incident response</sub></p>
