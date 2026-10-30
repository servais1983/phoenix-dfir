<p align="center">
  <img src="phoenix.png" alt="Phoenix DFIR" width="180" />
</p>

<h1 align="center">Phoenix DFIR</h1>

<p align="center">
  <strong>Digital forensics and incident response platform,<br/>
  with an autonomous AI investigator that backs every conclusion with evidence.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.14-orange?style=flat-square" alt="Version" />
  <img src="https://img.shields.io/badge/tests-881%20passed-brightgreen?style=flat-square" alt="Tests" />
  <img src="https://img.shields.io/badge/MCP-74%20tools-purple?style=flat-square" alt="MCP tools" />
  <img src="https://img.shields.io/badge/LLM-local%20first%20(Ollama%20%7C%20llama.cpp%20%7C%20LM%20Studio%20%7C%20Jan)-black?style=flat-square" alt="LLM" />
  <img src="https://img.shields.io/badge/OS-Windows%20%7C%20macOS%20%7C%20Linux-blue?style=flat-square" alt="OS" />
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
images**, **network captures**, **cloud and identity audit logs**, Linux and
Kubernetes audit trails, execution artifacts) into a reasoned, timestamped and
verifiable investigation report.

- **An autonomous investigator in five phases**, each validated by a
  deterministic quality gate: no phase is closed on the LLM's word alone.
- **No finding without evidence**: every conclusion cites an EVTX RecordID, a
  PID, a log line, a CSV row or an inode actually observed by a deterministic
  tool. A fabricated identifier is rejected.
- **Evidential chain of custody**: acquisitions, tool executions, findings and
  decisions are sealed in a hash-chained ledger with Merkle checkpoints and
  optional RFC 3161 trusted timestamps; any tampering is detected.
- **Competing hypotheses**: the investigator weighs alternative explanations
  with evidence-based Bayesian scoring and must try to refute its leading one.
- **Attack graph**: entities and relations are rebuilt into a graph with
  patient zero, blast radius and a chronological replay.
- **Humans decide**: containment actions are proposed as ready-to-run
  playbooks, never executed, and wait for an analyst's approval.
- **Local first**: the LLM runs on your machine (Ollama or llama.cpp). Cloud
  providers are refused unless explicitly allowed, and that consent is
  recorded in the chain of custody. There is never a silent cloud fallback.
- **Works without any LLM**: `phoenix triage` runs every applicable tool and
  reports only the detections they emitted, with their references. Same input,
  same output, byte for byte.
- **Windows, macOS and Linux**: one installable package (`pipx install`), a
  `phoenix` command line, and `phoenix doctor` to see what each machine can do.
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
end. It is built on an **MCP** (Model Context Protocol) server exposing **74
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

### Specialized agents and contracts

Each phase is led by a specialized agent and offers only the tools of its
team (`phoenix agents`): triage and collection, logs (EVTX and Sigma), memory,
disk and timeline, network, cloud and identity, IoC enrichment, ATT&CK and
correlation, verifier, writer, under an orchestrator. An agent has a model
role, a tool allowlist, a token budget (`PHOENIX_AGENT_MAX_TOKENS`) and, when
it writes structured output, a Pydantic v2 contract exported as JSON Schema
(`phoenix schemas`). Findings and hypotheses are validated against their
contract before they are recorded; a structured LLM answer gets at most two
new attempts, each told the exact validation errors. Tokens are logged per
agent in the investigation metrics. The deterministic triage analyzes up to
`PHOENIX_EXTRACTION_WORKERS` artifacts at the same time with a byte-identical
report.

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
- **Competing hypotheses**: alternatives are grouped by question (for example
  initial access: phishing or exposed RDP). Each piece of evidence carries a
  likelihood ratio and updates the posterior in log-odds; the counter-analysis
  gate requires an attempt to refute the leading hypothesis.
- **Entity graph**: users, hosts, processes, files, IPs, domains, cloud
  principals, registry keys and services, linked by evidence-backed relations
  (`graph_build`, `graph_neighbors`, `graph_patient_zero`, `graph_blast_radius`).
- **Case memory**: the current case is compared with past cases on shared IoCs,
  techniques, tools and finding text to surface recurring campaigns.
- **Detection engineering**: the investigator turns its findings into Sigma and
  YARA rules, then tests them against the case and against a benign corpus to
  keep false positives at zero.

### Three ways to use it

| Mode | Usage |
|---|---|
| **Web interface** | *AI Investigator* page: evidence upload, live log, metrics (findings, tokens, gates), downloadable report and exports |
| **Watched folder** | `backend/evidence_inbox/`: each subfolder dropped in becomes a case that is created and resolved automatically |
| **Command line** | `phoenix investigate <case_dir>` (falls back to `phoenix triage` when no LLM answers) |

Detailed documentation: [`mcp-server/README.md`](mcp-server/README.md).

---

## Forensic coverage

| Domain | Formats | Capabilities |
|---|---|---|
| **Windows event logs** | EVTX | Native parser with MITRE mapping, 29 built-in Sigma rules, SigmaHQ rules through pySigma, Hayabusa detection timeline |
| **Memory** | raw, mem, vmem, dmp, lime | Volatility 3: pslist/pstree, cmdline, malfind, netscan, svcscan... (allowlisted plugins) |
| **Disk images** | E01/Ex01, dd/raw/img/001, VMDK, VHD/VHDX, AFF | The Sleuth Kit **without mounting**: partitions, file tree, **deleted files**, **MACB** timeline, targeted artifact extraction with SHA-256 |
| **Windows artifacts** | Prefetch, LNK, $MFT, hives, Amcache, SRUM, Jump Lists | Native parsers + EvtxECmd, PECmd, LECmd, JLECmd, MFTECmd, AmcacheParser, AppCompatCacheParser, RECmd, SBECmd, SrumECmd, SQLECmd, WxTCmd |
| **Browsers** | Chromium / Firefox history (SQLite) | Visited URLs, downloads, timestamps |
| **Logs and data** | LOG, syslog, auth.log, CSV, JSON, XML | Generic parsing, multi-format timestamps, per-line references |
| **Windows event exports** | JSON, JSON Lines, CSV with an EventID field | Same Sigma rules as native EVTX, rows cited as evidence |
| **Network** | PCAP, PCAPNG | Pure Python analysis with TCP reassembly: flows, DNS, HTTP with file carving, TLS (SNI, JA3, JA3S, JA4, certificates); beaconing, exfiltration, DNS tunneling, DGA, cleartext credentials |
| **Cloud and identity** | Microsoft 365 Unified Audit Log, Entra ID sign-in and audit logs, AWS CloudTrail, GCP Cloud Audit Logs | Format detected from content; password spray, MFA fatigue, impossible travel, risky OAuth consent, mailbox forwarding rules, trail tampering, IAM persistence, S3 exfiltration, external owner grants |
| **Linux and containers** | auditd, Kubernetes audit logs | Reverse shells, persistence (SSH keys, sudoers, cron, systemd, preload), audit tampering, log clearing; pod exec, privileged pods, cluster-admin bindings, secrets enumeration |
| **macOS** | Unified log exports (ndjson, json, text), TCC.db, LaunchAgents and LaunchDaemons, QuarantineEventsV2, KnowledgeC, FSEvents | Persistence, TCC permission abuse, Gatekeeper bypass, fake password prompts, keychain dumping, risky downloads, mass deletion or renaming |
| **Obfuscated scripts** | PowerShell, JavaScript, VBScript, batch | Static multi-layer decoding (base64, UTF-16LE, gzip, char codes, format operator, XOR...) with a recipe trace; nothing is executed |
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
| **Verified findings only** | A deterministic verifier marks a finding `verified` only when its references exist and every entity it names appears in the referenced events; the report only keeps verified findings and every factual sentence cites one as `[F<id>]` |
| **Injection resistance** | Every tool output is sanitized (invisible characters, bidirectional overrides), French and English injection phrasing and role tokens are neutralized, and the output is then wrapped as untrusted data with a nonce. The attempt itself becomes an anti-forensics finding |
| **Evidence integrity** | Vault mounted read-only; disk images never mounted; MD5/SHA1/SHA256 hashes at acquisition, SHA-256 per extracted file |
| **Traceability** | Append-only ledger chained with SHA-256; `GET /api/custody/verify` detects modification, deletion or insertion |
| **Legal robustness** | Merkle tree over the ledger, signed checkpoints, RFC 3161 trusted timestamps on checkpoints and reports, and an evidence bundle that a third party can verify offline |
| **Safe remediation** | Playbook parameters are validated against strict allowlists and quoted, so a hostile value from an artifact cannot inject commands into a generated script |
| **Human control** | Remediations stay in `WAITING_APPROVAL` until an analyst decides; Phoenix never executes them |
| **Tool confinement** | LLM-driven tools are restricted to the case directory tree (`PHOENIX_TOOL_ROOTS`); Volatility plugins and external commands are allowlisted |
| **Confidentiality** | 100 % local mode with Ollama; the active provider is shown in the console |
| **Tool sandbox** | `PHOENIX_TOOL_SANDBOX=bwrap` or `docker` runs The Sleuth Kit, Volatility, Hayabusa and EZ Tools with no network, evidence read-only and a single writable output folder; tools refuse to run if the sandbox is unavailable |
| **Dual-LLM mode** | `PHOENIX_DUAL_LLM=true`: a quarantined extractor with no tools turns raw output into validated, typed facts; the planning model never reads artifact text |

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
- **One-click integrity check** of the entire chain, Merkle root and inclusion
  proof for any entry, signed checkpoints and an exportable evidence bundle
  with an offline verifier.
- **Attack graph page**: interactive graph of the case with patient zero,
  blast radius, ATT&CK chips and a time slider that replays the attack chain.
- **Remediation playbooks**: 16 templates (firewall blocks, AD, Entra ID and
  AWS account actions, host isolation, persistence cleanup) rendered from
  strictly validated parameters, with pre-checks and rollback. Approval is one
  click; the script can only be downloaded once approved, and Phoenix never
  runs it.

---

## Investigation platform

**Case management**: investigations, artifacts, IoCs, interactive timeline,
Markdown reports, **STIX 2.1** export, native **MITRE ATT&CK** mapping.

**Detection**: 29 built-in Sigma rules across 8 tactics (credential access,
defense evasion, persistence, execution, lateral movement, command and
control, impact...), per-rule thresholds, YARA support. With the `sigma`
extra, pySigma also runs SigmaHQ rules on the same events: a subset of the
`r2026-07-01` release ships with Phoenix (Detection Rule License 1.1, author
and link kept on every alert), `phoenix rules sync` installs the full release
and `phoenix rules import <archive.zip>` adds your own rules. Every alert keeps
the `record_id` or `row` of the event it matched. The built-in rules are also
published as Sigma YAML (`phoenix rules export-builtin`).

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
phoenix eval eval/suite -o results              # needs a local LLM (Ollama or llama.cpp)
phoenix eval eval/suite --min-recall 0.8 --max-forbidden 0 \
    --min-pass-rate 0.75 --min-fact-exact 0.75   # exit code 1 below thresholds
python eval/triage_acceptance.py                 # deterministic triage, no LLM
phoenix eval eval/suite --criteria               # the four phase 2 criteria (local LLM)
phoenix eval eval/suite --deterministic          # same criteria without LLM (triage + verifier)
```

Four criteria gate a release (`--criteria`, or one at a time with `--require`):

| Criterion | Target |
|---|---|
| `attack_recall` | ATT&CK recall over the **verified** findings >= 0.8 |
| `benign_forbidden` | No forbidden technique reported on a benign case |
| `injection_detected` | Every booby-trapped case has its injection flagged |
| `factual_sentences_linked` | 100 % of the factual report sentences cite a verified finding whose events contain what the sentence states |

`--deterministic` runs every applicable tool, turns each detection into a
finding with the references the tool emitted, lets the verifier rule on it and
scores the deterministic report. CI gates the three criteria it can measure
without a model; the recall is measured locally with Ollama, llama.cpp, LM
Studio or Jan.

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

The bundled suite has 20 cases: SSH brute force, PowerShell execution with a
booby-trapped artifact, C2 beaconing (firewall export and PCAP), DNS
tunneling, HTTP exfiltration with file carving, **exfiltration reconstructed
from a disk image**, Kerberoasting and DCSync, Golden Ticket, ransomware with
anti-forensics, fileless PowerShell, Microsoft 365 business email compromise
with OAuth consent, AWS key compromise, GCP external owner, Kubernetes
privileged escape, Linux auditd persistence, a macOS infostealer, and three benign cases to measure
false positives. Cases are scored against a factual answer key. Details and
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

### Install on Windows, macOS or Linux

```bash
pipx install "phoenix-dfir[all] @ git+https://github.com/servais1983/phoenix-dfir.git"
# or, from a clone: pip install -e ".[all,dev]"

phoenix doctor                                   # LLM, external tools, modules, storage
phoenix ingest  cases/acme-01 /path/to/evidence  # copy, hash, make read-only, record
phoenix triage  cases/acme-01                    # deterministic triage, no LLM
phoenix investigate cases/acme-01                # local LLM investigation
phoenix verify  cases/acme-01                    # re-hash against manifest.sha256
phoenix rules                                    # Sigma rule folders and usable rules
phoenix rules sync                               # full SigmaHQ r2026-07-01 release
phoenix web                                      # console on http://127.0.0.1:5000
```

Extras: `web`, `sigma`, `memory` (Volatility 3), `yara`, `disk`, `evtx`,
`analytics` (DuckDB), `intel`, or `all`. `phoenix web` uses waitress on every
OS (real-time events over long polling); Docker on Linux keeps gunicorn with
WebSocket. Installed packages keep their data in the per-user data folder of
the OS (`phoenix doctor` shows where).

### Case folders and integrity

`phoenix ingest` creates the standard layout:

```text
cases/acme-01/
├── evidence/          originals, read-only, never modified
├── derived/           extracted files, carved payloads
├── reports/           triage.json, triage.md, investigation reports
├── custody/           verify_<UTC>.json integrity records
└── manifest.sha256    SHA-256 of every evidence file (sha256sum format)
```

The SHA-256 is computed while the evidence is copied in and checked again by
`phoenix verify` (modified, missing and unlisted files are reported, exit
code 1). Ingestion, triage runs, verifications and cloud LLM consents are all
sealed in the custody ledger.

### Production stack

Phoenix + Redis (distributed rate limiting, cache) + Nginx (TLS, compression):

```bash
python -c "import secrets; print(secrets.token_hex(64))"   # -> PHOENIX_SECRET_KEY in .env
docker compose -f docker-compose.prod.yml up -d
```

Put the certificates in `deploy/tls/` and enable the SSL directives in
`deploy/nginx.conf`.

The server runs gunicorn with a single `gthread` worker (Socket.IO needs sticky
sessions); scale with `PHOENIX_THREADS`, since each open WebSocket holds one
thread. Investigations run in a durable job queue stored in SQLite: they
survive a restart, can be cancelled (`POST /api/autonomous/jobs/<id>/cancel`),
respect `PHOENIX_MAX_JOBS_PER_USER` and run on `PHOENIX_JOB_WORKERS` threads
apart from the web threads.


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
pip install -e ".[all]"
phoenix web                                     # every OS (waitress)
cd backend && gunicorn --config gunicorn.conf.py app:app   # Linux production server

# Frontend
npm ci && npm run dev

# Optional forensic tools (Debian / Ubuntu)
sudo apt-get install sleuthkit                  # disk images
pip install volatility3                         # memory
```

### LLM

| Provider | Configuration | Data |
|---|---|---|
| **Ollama** (default) | `PHOENIX_LLM_PROVIDER=ollama`, a model that supports *tool calling* (e.g. `qwen2.5-coder:14b`) | Stays on the machine or the investigation network |
| **llama.cpp** | `PHOENIX_LLM_PROVIDER=llamacpp`, `llama-server` on `PHOENIX_LLAMACPP_URL` | Stays on the machine or the investigation network |
| **LM Studio** | `PHOENIX_LLM_PROVIDER=lmstudio`, local server started in LM Studio (`http://localhost:1234/v1`) | Stays on the machine or the investigation network |
| **Jan** | `PHOENIX_LLM_PROVIDER=jan`, Jan local API server (`http://localhost:1337/v1`), `PHOENIX_JAN_API_KEY` if set in Jan | Stays on the machine or the investigation network |
| OpenAI or compatible | `PHOENIX_ALLOW_CLOUD_LLM=1`, `OPENAI_API_KEY`, `OPENAI_BASE_URL` | Sent to the provider, consent recorded |
| GitHub Models | `PHOENIX_ALLOW_CLOUD_LLM=1`, `GITHUB_TOKEN` (*Models: read* permission) | Sent to the provider, consent recorded |

`PHOENIX_LLM_PROVIDER=auto` picks the first local server that answers (Ollama,
llama.cpp, LM Studio, then Jan) and never a cloud provider. For LM Studio and
Jan, the model is `PHOENIX_LMSTUDIO_MODEL` / `PHOENIX_JAN_MODEL`, or else the
first model the local server lists; pick one that supports *tool calling*. A local provider pointed at a
public host is refused like a cloud one: only loopback, private addresses,
container service names, `host.docker.internal` and `PHOENIX_LLM_LOCAL_HOSTS`
count as local. Calls use temperature 0 and a fixed seed (`PHOENIX_LLM_SEED`),
with at most two retries on transient errors. Without an LLM, `phoenix triage`
and all deterministic analysis features remain available.

#### One model per role

Every LLM driven process asks for a role, and Phoenix picks the best model the
local server actually has for it:

| Role | Used by | What matters |
|---|---|---|
| `investigator` | Five-phase engine, loop engine, independent verification | Reliable tool calling, large context |
| `reviewer` | Adviser review of the final report | Strongest reasoning model available |
| `extractor` | Quarantined dual-LLM extraction | Fast mid-sized model, strict JSON |
| `analyst` | File analysis of the web console | Plain text answers |

The ranking reads the model names the server lists: model family (tool calling
quality: gpt-oss, Qwen3, Qwen2.5, Mistral Small, Llama 3.1/3.3...), parameter
count (up to `PHOENIX_LLM_MAX_PARAMS_B`, 32 by default; mixture-of-experts
models count their active parameters for speed), and kind (embedding, vision
and base models are never picked; R1 style reasoning models are kept for the
review). It is deterministic, and an explicit choice always wins:
`PHOENIX_LLM_MODEL_<ROLE>` for one role, the provider variable (for example
`PHOENIX_LMSTUDIO_MODEL`) for every role.

```bash
phoenix models            # servers, available models, model chosen per role
phoenix models --check    # also asks each chosen model for a real tool call
```

The console shows the model of each role on the *AI Investigator* page, and
`GET /api/llm/models` returns the full plan.

Suggested downloads for LM Studio, Jan or Ollama (quantized Q4_K_M or MXFP4),
by GPU memory:

| GPU memory | Investigator and reviewer | Extractor |
|---|---|---|
| 8 GB | Qwen3 8B | Qwen3 4B |
| 16 GB | gpt-oss 20B | Qwen3 8B |
| 24 GB and more | Qwen3 30B A3B or Mistral Small 3.x 24B | Qwen3 14B |

Run `phoenix models --check` after loading them: a model that does not return
a tool call is not fit for the `investigator` role.

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
| `PHOENIX_LLM_PROVIDER` | `ollama`, `llamacpp`, `lmstudio`, `jan`, `auto` (local only), `openai`, `github` | `ollama` |
| `OLLAMA_BASE_URL` / `PHOENIX_OLLAMA_MODEL` | Ollama server and model | `http://localhost:11434` / `qwen2.5-coder:14b` |
| `PHOENIX_LLAMACPP_URL` / `PHOENIX_LLAMACPP_MODEL` | llama.cpp server (OpenAI compatible) | `http://127.0.0.1:8080/v1` / `local` |
| `PHOENIX_LMSTUDIO_URL` / `PHOENIX_LMSTUDIO_MODEL` | LM Studio local server | `http://localhost:1234/v1` / first listed model |
| `PHOENIX_JAN_URL` / `PHOENIX_JAN_MODEL` / `PHOENIX_JAN_API_KEY` | Jan local API server | `http://localhost:1337/v1` / first listed model / unset |
| `PHOENIX_LLM_LOCAL_HOSTS` | Extra host names treated as local | unset |
| `PHOENIX_LLM_SEED` | Fixed seed of every LLM call | `42` |
| `PHOENIX_LLM_MODEL_INVESTIGATOR` / `_REVIEWER` / `_EXTRACTOR` / `_ANALYST` | Model of one role | best listed model |
| `PHOENIX_LLM_MAX_PARAMS_B` | Comfortable model size (billions of parameters) for the ranking | `32` |
| `PHOENIX_ALLOW_CLOUD_LLM` | `1` allows OpenAI and GitHub Models (consent recorded in the ledger) | unset (refused) |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `PHOENIX_OPENAI_MODEL` | OpenAI or compatible provider | none / api.openai.com / `gpt-4o-mini` |
| `GITHUB_TOKEN` / `PHOENIX_GITHUB_MODEL` | GitHub Models | none / `openai/gpt-4o-mini` |
| `PHOENIX_INVESTIGATION_MODE` | `phased` (five phases) or `loop` (single loop) | `phased` |
| `PHOENIX_STRICT_EVIDENCE` | Findings must carry references | `true` |
| `PHOENIX_EVIDENCE_VAULT` | Read-only evidence vault (set to `/mnt/evidence` in the Docker image) | `./evidence_vault` in a clone, data folder when installed |
| `PHOENIX_DATA_DIR` / `PHOENIX_DB_PATH` | Data folder and database of an installed package | per-user data folder of the OS |
| `PHOENIX_EVIDENCE_DIR` | Watched drop folder | `backend/evidence_inbox` |
| `PHOENIX_INBOX_ENABLED` / `PHOENIX_INBOX_POLL_SECONDS` | Drop folder monitoring | `true` / `10` |
| `PHOENIX_TOOL_ROOTS` | Root paths allowed for LLM-driven tools (`os.pathsep` separated); **required** by `phoenix serve-mcp`, which denies all file access without it | case folder |
| `PHOENIX_VOLATILITY_CMD` / `PHOENIX_VOLATILITY_SYMBOLS` | Volatility 3 and offline symbols | `vol` from PATH |
| `PHOENIX_HAYABUSA_CMD` / `PHOENIX_HAYABUSA_RULES` | Hayabusa binary and rules | `hayabusa` from PATH |
| `PHOENIX_TSK_CMD` | `fls` or the folder holding The Sleuth Kit binaries | from PATH |
| `PHOENIX_TSHARK_CMD` | TShark (optional, the PCAP tools are pure Python) | `tshark` from PATH |
| `EZ_TOOLS_PATH` / `PHOENIX_EZTOOLS_CMD` | EZ Tools folder | none |
| `REDIS_URL` | Distributed cache and rate limiting | in memory |
| `PHOENIX_ACCESS_TOKEN_EXPIRY` / `PHOENIX_REFRESH_TOKEN_EXPIRY` | Token lifetimes (s) | `900` / `604800` |
| `PHOENIX_PBKDF2_ITERATIONS` | Hashing iterations | `600000` |
| `PHOENIX_CORS_ORIGINS` | Additional origins (team access) | localhost |
| `PHOENIX_TSA_URL` / `PHOENIX_TSA_TIMEOUT` | RFC 3161 Time Stamping Authority for checkpoints and reports | disabled / `10` |
| `PHOENIX_CUSTODY_DIR` / `PHOENIX_CUSTODY_SIGNING_KEY` | Checkpoint store and Ed25519 signing key (PEM) | `backend/uploads/custody` / generated |
| `PHOENIX_CHECKPOINT_EVERY` | Ledger entries between automatic checkpoints (`0` disables) | `100` |
| `PHOENIX_GRAPH_WATCH` | Push live attack graph updates (`0` disables) | `1` |
| `PHOENIX_CASES_ROOT` / `PHOENIX_CASEMEM_INDEX` | Roots indexed by the case memory and index file | case folders |
| `PHOENIX_PCAP_MAX_PACKETS` / `PHOENIX_PCAP_MAX_STREAM_BYTES` / `PHOENIX_PCAP_MAX_CARVE_MB` | Network capture analysis limits | `1000000` / 4 MB / 25 MB |
| `PHOENIX_DEOBF_MAX_BYTES` | Maximum input size for deobfuscation | 1 MB |
| `PHOENIX_TOOL_SANDBOX` / `PHOENIX_TOOL_SANDBOX_FALLBACK` | Tool isolation: `none`, `bwrap` or `docker`; `none` fallback allows unsandboxed runs | `none` / unset |
| `PHOENIX_SANDBOX_IMAGE` / `PHOENIX_SANDBOX_MEMORY` / `PHOENIX_SANDBOX_CPUS` | Docker sandbox image and limits | `phoenix-dfir-tools:latest` / `4g` / `2` |
| `PHOENIX_DUAL_LLM` / `PHOENIX_EXTRACTOR_MODEL` | Quarantined extraction model | `false` / planner model |
| `PHOENIX_JOB_WORKERS` / `PHOENIX_JOB_STALE_SECONDS` | Investigation job workers and stale heartbeat delay | `2` / `120` |
| `PHOENIX_THREADS` | Web threads (gunicorn: one per open WebSocket; `phoenix web`: waitress) | `64` (gunicorn) / `16` (`phoenix web`) |
| `PHOENIX_HOST` / `PHOENIX_PORT` / `PHOENIX_LOG_LEVEL` | Server (`phoenix web` listens on 127.0.0.1 by default) | `127.0.0.1` / `5000` / `INFO` |

External tools (The Sleuth Kit, Volatility, Hayabusa, EZ Tools, TShark) are
optional and go through adapters (`detect`, `version`, `capabilities`, `run`):
when missing, they report themselves as "not available" with their fallback,
and nothing is ever simulated. `phoenix doctor` lists them with their version.

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
| GET | `/api/investigations/:id/graph` · `/api/autonomous/jobs/:id/graph` | Entity graph (patient zero, blast radius) |
| GET | `/api/llm/models` | Local LLM servers, available models and the model chosen per role |
| GET | `/api/playbooks/templates` · POST `/api/playbooks/render` | Remediation templates and preview |
| POST | `/api/playbooks/propose` | Propose a playbook for human approval (analyst / admin member) |
| GET | `/api/remediation/:id/script?part=script\|rollback\|prechecks` | Download an approved script |
| GET | `/api/custody/merkle?investigation_id=` · `/api/custody/proof/:seq` | Merkle root and inclusion proof |
| GET / POST | `/api/custody/checkpoints` · `/api/custody/checkpoint` | Signed checkpoints (RFC 3161 timestamp when configured) |
| GET | `/api/investigations/:id/custody-bundle` | Evidence bundle (ledger, proofs, checkpoints, tokens, offline verifier) |

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
                 │  5-phase engine + gates ── local LLM (Ollama / llama.cpp), cloud on opt-in  │
                 │        │                      ▲ anti-injection shield                       │
                 │  74 tools: parsers · Sigma · ATT&CK · Hayabusa · Volatility 3 ·             │
                 │            The Sleuth Kit · EZ Tools · PCAP · cloud · auditd · K8s ·        │
                 │            hypotheses · entity graph · case memory · rule generation        │
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
│   ├── merkle.py             Merkle tree, inclusion proofs, signed checkpoints
│   ├── timestamping.py       RFC 3161 trusted timestamping
│   ├── custody_bundle.py     Evidence bundle with offline verifier
│   ├── playbooks.py          Remediation playbook templates
│   ├── evidence_vault.py     Read-only evidence vault
│   ├── parsers.py            Native parsers and IoC extraction
│   └── tests/                pytest suite
├── mcp-server/phoenix_dfir_mcp/
│   ├── phases.py             Five-phase engine and quality gates
│   ├── investigator.py       Agentic loop, verification, review
│   ├── toolkit.py            Core tool registry (MCP + function calling), evidence index
│   ├── tools_*.py            Core tools by family: artifacts, external, case, disk, evidence
│   ├── agents.py             Specialized agents: role, tool allowlist, budget
│   ├── contracts.py          Pydantic v2 contracts of the LLM outputs (JSON Schema)
│   ├── verifier.py           Deterministic verifier of findings and report citations
│   ├── sigma_engine.py       pySigma on case events (SigmaHQ subset, sync, import)
│   ├── ext/                  Self-registering tool extensions (cloud, Linux audit,
│   │                         network, deobfuscation, hypotheses, graph, case memory,
│   │                         detection engineering)
│   ├── graph.py              Entity graph, patient zero, blast radius
│   ├── disk.py               Disk images (The Sleuth Kit)
│   ├── volatility.py         Memory (Volatility 3)
│   ├── hayabusa.py           EVTX timeline
│   ├── zimmermann.py         EZ Tools
│   ├── evidence_db.py        SQLite FTS5 super-timeline
│   ├── shield.py             Anti-injection shield
│   ├── memory.py             Investigation memory
│   ├── exports.py            ATT&CK Navigator layer, IoC CSV
│   ├── evaluation.py         Evaluation suite
│   ├── triage.py             Deterministic triage (no LLM)
│   ├── casefile.py           Case layout, manifest.sha256, verification
│   ├── adapters/             External tool adapters (detect, version, run)
│   ├── doctor.py             Installation diagnostic
│   ├── web.py                Cross-platform console server (waitress)
│   ├── copilot.py            Local-first LLM client
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
pip install -e ".[web,sigma,dev]"
cd backend && PHOENIX_SECRET_KEY=test python -m pytest -q          # backend
ruff check . && bandit -r backend mcp-server -ll -ii -x backend/tests
npm run lint && npm test                                           # frontend
```

More than **850 tests**: API and security, parsers, Sigma rules, connectors,
chain of custody, anti-injection shield, strict references, phase engine,
super-timeline, disk images (real integration with The Sleuth Kit),
evaluation suite, and an end-to-end scenario on a disk image (all five gates
passed, 100 % exact facts).

GitHub Actions pipeline:

| Job | Contents |
|---|---|
| `backend-tests` | Ubuntu, Windows and macOS with Python 3.10 and 3.12 (3.11 on Ubuntu), The Sleuth Kit on Ubuntu, then `phoenix doctor` |
| `install` | `pipx install .` on the three OSes, then the installed `phoenix` CLI |
| `eval-deterministic` | Triage acceptance criteria, byte-identical output, untouched evaluation suite |
| `lint` | Ruff |
| `security-scan` | Bandit and pip-audit, both blocking |
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
Adding an investigation tool: a module in `mcp-server/phoenix_dfir_mcp/ext/` that
registers its tools and declares its agent, phases and covered artifact types
(see `ext/__init__.py`); it is discovered automatically.
Adding an evaluation case: see [`eval/README.md`](eval/README.md).

Reporting a vulnerability: [`SECURITY.md`](SECURITY.md).

## License

Released under the MIT license. See [LICENSE](LICENSE).

<p align="center"><sub><strong>Phoenix DFIR</strong>: digital forensics and incident response</sub></p>
