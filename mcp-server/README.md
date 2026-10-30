# Phoenix DFIR MCP: Local-First DFIR Investigator

An **MCP** (Model Context Protocol) server, a deterministic triage engine and
an autonomous investigator built on the Phoenix forensic toolkit. The
investigator runs on a **local LLM** (Ollama or llama.cpp) by default; cloud
providers are only used on explicit opt-in. Without any LLM, `phoenix triage`
still produces a referenced report. It handles EVTX, CSV, JSON, logs,
Prefetch, LNK, browser histories, registry hives, memory dumps, disk images,
network captures and cloud audit logs.

## Command line

```bash
pip install -e ".[all]"            # from the repository root (or pipx install)
phoenix doctor                     # what this machine can do
phoenix ingest  <case> <evidence>  # evidence/ read-only, manifest.sha256, ledger
phoenix triage  <case>             # deterministic, no LLM, same output every run
phoenix investigate <case>         # local LLM investigation (falls back to triage)
phoenix verify  <case>             # integrity check against manifest.sha256
phoenix models [--check]           # local models and the model chosen per role
phoenix serve-mcp                  # stdio MCP server (needs PHOENIX_TOOL_ROOTS)
phoenix web                        # investigator console (waitress, every OS)
phoenix eval eval/suite -o results # evaluation suite (local LLM)
```

`python -m phoenix_dfir_mcp <command>` works the same from a source checkout.

### Deterministic triage

`phoenix triage` runs every tool that applies to each artifact and keeps, as
findings, only the detections the tools themselves emitted **with an observed
reference** (`record_id`, `row`, `line`, `pid`, `inode` or `sha256`). Parser
events are never promoted to findings and nothing is inferred. The case folder
is only read: derived data (files extracted from a disk image, carved
payloads) goes to a temporary folder, or to `derived/` for a case with the
standard layout, and is triaged in a second pass. Output: Markdown or JSON
(`--format json`), written to `reports/` with `-o` or on a standard case.

## Usage modes

### 1. Agent mode: GitHub Copilot orchestrates the tools (VS Code)

The repository includes `.vscode/mcp.json`: open the project in VS Code with GitHub
Copilot, enable **agent mode** in Copilot Chat, and the `phoenix-dfir` server
appears with all its tools. The server only reads the folders listed in
`PHOENIX_TOOL_ROOTS` (`cases/` in the bundled configuration). For example, ask:

> *"Investigate the `./cases/incident-42` folder and write the full report."*

Copilot then calls `list_artifacts`, `parse_evtx`, `sigma_scan`,
`extract_iocs`, `virustotal_lookup`, `run_zimmermann`... on its own, up to the
final `save_report`.

### 2. Autonomous mode: the investigator solves the case alone (CLI)

```bash
ollama pull qwen2.5-coder:14b          # or llama.cpp, LM Studio or Jan: PHOENIX_LLM_PROVIDER=llamacpp|lmstudio|jan
phoenix investigate /path/to/case \
  -q "Suspected ransomware, host DESKTOP-A12"
```

The local LLM (*function calling*, temperature 0, fixed seed) runs the
investigation: inventory → parsing of each artifact → Sigma detection → IoC
correlation → timeline → MITRE ATT&CK mapping → **Markdown report saved in the
case folder**. When no LLM answers, the command says so and runs
`phoenix triage` instead (`--no-triage-fallback` keeps the error).

Other commands:

```bash
phoenix tools       # list the exposed tools
phoenix serve-mcp   # start the stdio MCP server manually (alias: serve)
```

## Exposed tools

The server exposes 74 tools: 39 core tools and 35 tools from the extensions described below. Core tools:

| Tool | Purpose |
|---|---|
| `list_artifacts` | Recursive case inventory (types, sizes, MD5/SHA256) |
| `analyze_artifact` | Automatic analysis whatever the format |
| `parse_evtx` | Windows EVTX logs + MITRE mapping |
| `parse_csv` / `parse_json_file` / `parse_log_file` | Tabular, JSON and plain-text log formats |
| `parse_prefetch` / `parse_lnk` / `parse_browser_history` | Evidence of execution and access |
| `extract_iocs` | IPs, domains, URLs, hashes, emails, CVEs |
| `sigma_scan` | 30 built-in Sigma rules across 8 tactics (brute force, PtH, Kerberoasting, LSASS...) |
| `mitre_map_events` | Event IDs → ATT&CK tactics/techniques |
| `virustotal_lookup` | IoC enrichment (requires `API_KEY_VT`) |
| `zimmermann_status` / `run_zimmermann` | Eric Zimmermann tools (see below) |
| `set_investigation_plan` / `complete_plan_step` | Step-by-step investigation plan and tracking |
| `record_finding` | Record an evidence-backed finding (severity, MITRE, confidence) |
| `set_hypothesis` | Form, confirm or refute a hypothesis |
| `verify_finding` | Set the verification status of a finding (verified / unverified / refuted) |
| `volatility_status` / `run_volatility` | Volatility 3 on memory dumps: pslist/pstree, cmdline, malfind, netscan, svcscan... (allowlisted plugins, read-only) |
| `hayabusa_status` / `run_hayabusa` | Hayabusa detection timeline on EVTX (thousands of Sigma/Hayabusa rules) |
| `disk_status` / `disk_image_info` | Disk images (The Sleuth Kit): availability, partitions and offsets, file system |
| `disk_list_files` | Partition file tree without mounting, path filter, **deleted** files |
| `disk_timeline` | File system MACB timeline, indexed into the FTS5 super-timeline |
| `disk_extract_artifacts` | Targeted extraction (`windows` / `linux` / `auto` profiles) with SHA-256 and manifest |
| `propose_remediation` | Propose a containment action subject to **human approval** (never executed by the investigator) |
| `get_case_state` | Return the accumulated plan, findings and hypotheses |
| `save_report` | Final Markdown investigation report (appends the memory summary) |

### Five-phase investigation with quality gates

`investigate` runs Inventory → Extraction → Correlation → Counter-analysis → Report
(`phases.py`). Each phase has its own instructions and tool allowlist. A deterministic
quality gate validates it (otherwise the phase is rerun with the exact gaps). Related tools:

| Tool | Purpose |
|---|---|
| `search_evidence` / `get_timeline` / `list_sources` | SQLite FTS5 super-timeline of every tool output in the case |
| `audit_tool_coverage` / `audit_evidence_coverage` | Applicable tools never run, artifacts never analyzed or never cited |
| `challenge_finding` | Counter-analysis of a finding (alternative hypothesis; upheld / downgraded / refuted) |
| `declare_no_incident` | Explicit conclusion that no incident occurred (no invented findings) |

A `PHOENIX.md` file in the case folder serves as a briefing injected into every phase.
`save_report` also generates `attack_navigator_layer.json` and `iocs.csv`. Legacy engine:
`--mode loop` or `PHOENIX_INVESTIGATION_MODE=loop`.

### LLM loop security

- **Injection shield** (`shield.py`): every tool output (autonomous investigator *and* stdio MCP
  server) is sanitized, injections hidden in artifacts are neutralized, and the output is then
  wrapped in `<donnees_outil … fiabilite="non-fiable">` with a random nonce.
- **Strict structured output**: `record_finding` requires `evidence_refs` (`record_id`, `pid`,
  `line`, `row`, `inode`) validated against the index of identifiers actually produced by the tools.

### Investigative intelligence

The investigator does more than chain tools together. It applies a
structured DFIR methodology:

- **Planning**: the case is broken down into 3 to 7 steps before collection,
  tracked through to completion (prevents scope creep).
- **Investigation memory** (`case_state.json` in the case folder): timestamped
  findings and accumulated hypotheses, so the investigation scales to large
  multi-artifact cases without saturating the context window.
- **Independent verification**: after the investigation, a read-only pass
  rechecks each finding against the raw source evidence and marks it
  *verified / unverified / refuted* (reduces false positives). Findings
  that cannot be reproduced are marked `unverified` as a precaution.
- **Execution monitoring**: if the same tool is replayed identically or
  tools fail repeatedly, corrective guidance is injected (mentor).
- **Adviser review**: a critical pass checks that every conclusion is
  supported and that the timeline, IoCs, MITRE mapping and recommendations are present.
  It reruns the investigator if gaps remain (capped at 2 reviews).
- **Sandboxing** (`PHOENIX_TOOL_ROOTS`): read tools are confined to
  the case tree, and any access outside the allowed roots is denied
  (protects against reading sensitive files). The investigator automatically
  registers the case folder as an allowed root. `phoenix serve-mcp` starts in
  strict mode: with no root configured, every file access is denied. Paths are
  compared once resolved, case-insensitively on Windows, with drive letters
  and UNC paths handled.
- **Observability**: tokens consumed, LLM calls, verified findings and the
  review verdict are reported (metrics exposed in the UI and the CLI).

## Tool extensions

Modules in `phoenix_dfir_mcp/ext/` are discovered automatically. Each one
registers its tools and declares its agent, the phases where its tools are
allowed, the artifact types it covers (used by the coverage audit) and its
internal files. A module that fails to load is skipped and reported without
breaking the other tools. See `ext/__init__.py` for the contract.

### Cloud, identity, Kubernetes and Linux auditd

Five offline tools handle cloud and Linux audit logs. The format is detected
from content, not extension: Microsoft 365 Unified Audit Log (CSV with
AuditData, JSON lines), Entra ID sign-in and audit logs (JSON or CSV exports),
AWS CloudTrail (`Records[]`, `.json.gz`, event history CSV), GCP Cloud Audit
Logs, Kubernetes audit logs and Linux auditd (`audit.log`).

- `cloud_detect_format` identifies the format; `cloud_parse_log` and
  `linux_parse_auditd` normalize events (UTC time, principal, source IP, user
  agent, operation, result, target, tenant or account) and index them.
- `cloud_hunt` and `linux_audit_hunt` return findings with severity, ATT&CK
  technique and the exact `row` or `line` references to cite.
- Detections: password spray, MFA fatigue, legacy authentication, impossible
  travel (geolocation from the log only), risky OAuth consent, mailbox
  forwarding rules, CloudTrail tampering, IAM persistence, S3 exfiltration,
  GCP external owner grants, Kubernetes exec, privileged pods, cluster-admin
  bindings and secrets enumeration, auditd persistence, audit tampering and
  log clearing.

### Network captures and deobfuscation

- `net_pcap_summary`, `net_dns`, `net_http`, `net_tls` and `net_detect`
  analyze PCAP and PCAPNG files offline in pure Python, with bounded TCP
  reassembly (`PHOENIX_PCAP_MAX_PACKETS`, `PHOENIX_PCAP_MAX_STREAM_BYTES`,
  `PHOENIX_PCAP_MAX_TOTAL_STREAM_BYTES`, `PHOENIX_PCAP_MAX_FLOWS`).
- `net_tls` reports SNI, ALPN, JA3, JA3S, JA4 and visible certificates.
- `net_http` lists requests and uploads; `carve=true` writes transferred files
  to `<case>/extracted/pcap/<capture>/` with a SHA-256 manifest
  (`PHOENIX_PCAP_MAX_CARVE_MB`). Nothing is executed.
- `net_detect` reports beaconing, exfiltration, DNS tunneling, DGA names,
  cleartext credentials, suspicious user agents and non-standard ports.
- Network events are cited with kind `row` and the packet number.
- `deobfuscate_text` and `deobfuscate_artifact` statically decode base64
  (including PowerShell `-EncodedCommand`), hex, URL, HTML, gzip and deflate,
  char codes, reversal, concatenation, the format operator, backticks, XOR and
  ROT13, with a recipe trace, extracted IoCs and indicators (download cradles,
  AMSI bypass, reflective loading). Size (`PHOENIX_DEOBF_MAX_BYTES`), depth and
  time are capped.

### Competing hypotheses and entity graph

- `add_hypothesis` groups exclusive alternatives under one question (for
  example initial access: phishing or exposed RDP).
- `weigh_evidence` attaches a finding or a validated reference as supporting
  or refuting evidence with a likelihood ratio (neutral 1, weak 2, moderate 5,
  strong 20; refuting uses 1/x). Posteriors are updated in log-odds.
- `rank_hypotheses` orders each question and flags it inconclusive when the
  top two are within 0.1.
- The correlation gate requires two competing hypotheses when an incident is
  found; the counter-analysis gate requires an attempt to refute the leading
  one.
- `graph_build` writes `entity_graph.json` (users, hosts, processes, files,
  IPs, domains, URLs, accounts, registry keys, services) with evidence
  references on every relation; `graph_neighbors`, `graph_patient_zero` and
  `graph_blast_radius` pivot on it. The graph is rebuilt after correlation
  and counter-analysis.

### Case memory and detection engineering

- `casemem_similar_cases` ranks past cases under `PHOENIX_CASES_ROOT` by shared
  IoCs, techniques, tools and finding text; `casemem_index_case` adds the
  current case after the report. Nothing outside the configured roots is read.
- `detect_generate_sigma` and `detect_generate_yara` turn findings and
  extracted files into rules saved in `<case>/detections/`.
- `detect_test_rule` checks that a rule matches the malicious events and
  raises no alert on a benign corpus.

### macOS

Offline parsers detect macOS artifacts by content: `log show` exports of the
unified log (ndjson, json or text; native `.tracev3` is reported, not decoded),
TCC.db, QuarantineEventsV2 and KnowledgeC.db (read-only, cited by rowid),
LaunchAgents, LaunchDaemons, emond, LoginHook, cron and periodic scripts, and
FSEvents pages (1SLD, 2SLD, 3SLD). `macos_hunt` reports findings with ATT&CK
techniques and exact `row` or `line` references.

### Analytics

`analytics_query` runs read-only SQL over the case events (DuckDB when
installed, otherwise SQLite with an authorizer, a single SELECT, a row limit
and a timeout). `analytics_stack` lists the least frequent processes,
parent-child pairs, users, user agents or destinations, per host and time
window. `analytics_export_parquet` writes `<case>/analytics/events.parquet`
when DuckDB is installed.

### Tool sandbox and dual-LLM mode

- `PHOENIX_TOOL_SANDBOX=bwrap` or `docker` runs every external binary isolated:
  evidence read-only under `/evidence`, output only under `/out`, no network.
  Docker mode drops all capabilities and applies pids, memory and CPU limits
  (`PHOENIX_SANDBOX_IMAGE` must provide the same binaries). If the sandbox is
  unavailable the tool fails closed unless `PHOENIX_TOOL_SANDBOX_FALLBACK=none`.
  When the backend itself runs in a container, prefer bwrap: docker volume
  paths must be host paths.
- `PHOENIX_DUAL_LLM=true`: a quarantined extractor (no tools, temperature 0,
  strict JSON schema, `PHOENIX_EXTRACTOR_MODEL`) turns each tool output into
  typed facts. Every value must appear in the output and every reference must
  exist, instruction-like strings are dropped, and the planner only receives
  these facts plus deterministic fields. The token cost of both models is
  reported.

### Windows event exports

`sigma_scan` also accepts JSON, JSON Lines and CSV exports of Windows events
(any file with an `EventID` field). The coverage audit then requires it on
those files, and CSV alerts are cited by row.

## Disk images (The Sleuth Kit)

Formats: **E01/Ex01, dd/raw/img/001, VMDK, VHD/VHDX, AFF**. A `.raw` / `.bin`
file is classified as disk or memory based on its signature (MBR, GPT, NTFS, ext).
The image is never mounted or modified:

1. `disk_image_info`: partition table and the offset of each file system;
2. `disk_list_files` / `disk_timeline`: file tree (including deleted files) and
   MACB timeline, citable by inode (`{"artifact": "disque.E01", "kind": "inode", "value": "128-128-1"}`);
3. `disk_extract_artifacts`: copies relevant artifacts to
   `extracted/<image>/p<offset>/` (SHA-256 hash per file,
   `extraction_manifest.json`). They are then analyzed by the parsers,
   Sigma, Hayabusa or the EZ Tools like any other artifact in the case.

Installation: the `sleuthkit` package (already included in the Docker image). Without
The Sleuth Kit, the disk tools report themselves as unavailable and the investigation
continues on the other artifacts.

## Eric Zimmermann tools (EZ Tools)

`run_zimmermann` runs Eric Zimmermann's reference tools and parses their CSV
output: **EvtxECmd, PECmd, LECmd, JLECmd, MFTECmd, AmcacheParser,
AppCompatCacheParser, RECmd, SBECmd, SrumECmd, SQLECmd, WxTCmd**.

Installation:

1. Download the EZ Tools: <https://ericzimmerman.github.io/> (the
   `Get-ZimmermanTools` script).
2. Set `EZ_TOOLS_PATH` to the installation folder.
3. On Linux/macOS, install the **dotnet** runtime (the tools are
   cross-platform .NET binaries).

Without the EZ Tools, the investigator automatically falls back to the native
Phoenix parsers, and the investigation remains fully functional.

## Configuration

| Variable | Purpose |
|---|---|
| `PHOENIX_LLM_PROVIDER` | `ollama` (default), `llamacpp`, `lmstudio`, `jan`, `auto` (first local server that answers, never a cloud one), `openai`, `github` |
| `PHOENIX_LLAMACPP_URL` / `PHOENIX_LLAMACPP_MODEL` | llama.cpp server (default `http://127.0.0.1:8080/v1`) and model name |
| `PHOENIX_LMSTUDIO_URL` / `PHOENIX_LMSTUDIO_MODEL` | LM Studio local server (default `http://localhost:1234/v1`); model defaults to the first one listed |
| `PHOENIX_JAN_URL` / `PHOENIX_JAN_MODEL` / `PHOENIX_JAN_API_KEY` | Jan local API server (default `http://localhost:1337/v1`), model, optional API key |
| `PHOENIX_LLM_SEED` / `PHOENIX_LLM_LOCAL_HOSTS` | Fixed seed (default `42`) / extra host names treated as local |
| `PHOENIX_LLM_MODEL_<ROLE>` / `PHOENIX_LLM_MAX_PARAMS_B` | Model of one role (`INVESTIGATOR`, `REVIEWER`, `EXTRACTOR`, `ANALYST`); otherwise the best model the local server lists for the role (`phoenix models`) / comfortable size cap (default 32) |
| `PHOENIX_ALLOW_CLOUD_LLM` | `1` allows `openai` and `github`; each client records an `llm_cloud_consent` entry in the custody ledger first |
| `GITHUB_TOKEN` / `PHOENIX_GITHUB_TOKEN` | GitHub Models token (*Models: read* permission), cloud opt-in only |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `PHOENIX_OPENAI_MODEL` | OpenAI provider (or a compatible API), cloud opt-in only |
| `PHOENIX_TOOL_ROOTS` | Folders the tools may read (`os.pathsep` separated), required by `phoenix serve-mcp` |
| `PHOENIX_STRICT_EVIDENCE` | `true` (default): `record_finding` requires a RecordID / PID / line observed in a tool output |
| `OLLAMA_BASE_URL` / `PHOENIX_OLLAMA_MODEL` | Ollama server (default `http://localhost:11434`) and a *tools*-capable model (default `qwen2.5-coder:14b`) |
| `PHOENIX_VOLATILITY_CMD` / `PHOENIX_VOLATILITY_SYMBOLS` | Volatility 3 command (default `vol`) and offline symbol tables |
| `PHOENIX_HAYABUSA_CMD` / `PHOENIX_HAYABUSA_RULES` | Hayabusa binary and rules folder |
| `PHOENIX_TSK_CMD` / `PHOENIX_TSHARK_CMD` | The Sleuth Kit (`fls` or its folder) and TShark |
| `PHOENIX_GITHUB_MODEL` | GitHub Models model (default `openai/gpt-4o-mini`) |
| `API_KEY_VT` | VirusTotal key for IoC enrichment (optional) |
| `EZ_TOOLS_PATH` | Eric Zimmermann tools folder (optional) |

Dependencies: `pip install -e ".[all]"` from the repository root (extras:
`web`, `sigma`, `memory`, `yara`, `disk`, `evtx`, `analytics`, `intel`). The MCP
protocol is implemented natively (JSON-RPC over stdio): no external MCP
dependency. Every external tool goes through an adapter
(`phoenix_dfir_mcp/adapters/`: `detect`, `version`, `capabilities`, `run`);
a missing tool reports "not available" and is never simulated.

## MCP client compatibility

The server speaks the standard MCP protocol over stdio: GitHub Copilot (VS
Code, agent mode), as well as any other MCP client. Example of a generic
declaration:

```json
{
  "command": "phoenix",
  "args": ["serve-mcp"],
  "env": { "PHOENIX_TOOL_ROOTS": "<cases folder>" }
}
```

## Security

The server reads the local files it is pointed at and can run the
EZ Tools: expose it only to trusted clients, on working copies
of your evidence (never the originals), in line with your chain of custody
procedures.
