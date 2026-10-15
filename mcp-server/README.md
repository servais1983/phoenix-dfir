# Phoenix DFIR MCP: Autonomous DFIR Investigator Powered by GitHub Copilot

An **MCP** (Model Context Protocol) server that exposes the Phoenix forensic
toolkit so that **GitHub Copilot** can orchestrate it automatically. It acts as
an additional DFIR investigator on your team, able to solve a case on its own,
quickly, whatever the artifact format (EVTX, CSV, JSON, logs, Prefetch, LNK,
browser histories, registry hives...).

## Two usage modes

### 1. Agent mode: GitHub Copilot orchestrates the tools (VS Code)

The repository includes `.vscode/mcp.json`: open the project in VS Code with GitHub
Copilot, enable **agent mode** in Copilot Chat, and the `phoenix-dfir` server
appears with all its tools. For example, ask:

> *"Investigate the `./cases/incident-42` folder and write the full report."*

Copilot then calls `list_artifacts`, `parse_evtx`, `sigma_scan`,
`extract_iocs`, `virustotal_lookup`, `run_zimmermann`... on its own, up to the
final `save_report`.

### 2. Autonomous mode: the investigator solves the case alone (CLI)

```bash
cd mcp-server
export GITHUB_TOKEN="github_pat_..."   # permission "Models: read"
python -m phoenix_dfir_mcp investigate /path/to/case \
  -q "Suspected ransomware, host DESKTOP-A12" \
  -m openai/gpt-4o        # optional
```

GitHub Copilot (GitHub Models API, *function calling*) runs the investigation as
an agentic loop: inventory → parsing of each artifact → Sigma detection →
IoC correlation → VirusTotal enrichment → timeline → MITRE ATT&CK
mapping → **Markdown report saved in the case folder**.

Other commands:

```bash
python -m phoenix_dfir_mcp tools   # list the exposed tools
python -m phoenix_dfir_mcp serve   # start the stdio MCP server manually
```

## Exposed tools

The server exposes 39 tools. Core tools:

| Tool | Purpose |
|---|---|
| `list_artifacts` | Recursive case inventory (types, sizes, MD5/SHA256) |
| `analyze_artifact` | Automatic analysis whatever the format |
| `parse_evtx` | Windows EVTX logs + MITRE mapping |
| `parse_csv` / `parse_json_file` / `parse_log_file` | Tabular, JSON and plain-text log formats |
| `parse_prefetch` / `parse_lnk` / `parse_browser_history` | Evidence of execution and access |
| `extract_iocs` | IPs, domains, URLs, hashes, emails, CVEs |
| `sigma_scan` | 27 built-in Sigma rules across 8 tactics (brute force, PtH, Kerberoasting, LSASS...) |
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
  registers the case folder as an allowed root.
- **Observability**: tokens consumed, LLM calls, verified findings and the
  review verdict are reported (metrics exposed in the UI and the CLI).

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
| `GITHUB_TOKEN` / `PHOENIX_GITHUB_TOKEN` | GitHub token (*Models: read* permission), required for autonomous mode with GitHub Copilot |
| `PHOENIX_LLM_PROVIDER` | `github` (default), `ollama` (local, air-gapped), `openai`, or `auto`: Ollama if it responds, otherwise OpenAI, otherwise GitHub |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `PHOENIX_OPENAI_MODEL` | OpenAI provider (or a compatible API) |
| `PHOENIX_STRICT_EVIDENCE` | `true` (default): `record_finding` requires a RecordID / PID / line observed in a tool output |
| `OLLAMA_BASE_URL` / `PHOENIX_OLLAMA_MODEL` | Ollama server (default `http://localhost:11434`) and a *tools*-capable model (default `qwen2.5-coder:14b`) |
| `PHOENIX_VOLATILITY_CMD` / `PHOENIX_VOLATILITY_SYMBOLS` | Volatility 3 command (default `vol`) and offline symbol tables |
| `PHOENIX_HAYABUSA_CMD` / `PHOENIX_HAYABUSA_RULES` | Hayabusa binary and rules folder |
| `PHOENIX_GITHUB_MODEL` | GitHub Models model (default `openai/gpt-4o-mini`) |
| `API_KEY_VT` | VirusTotal key for IoC enrichment (optional) |
| `EZ_TOOLS_PATH` | Eric Zimmermann tools folder (optional) |

Dependencies: `pip install -r requirements.txt` (+ `python-evtx` for native
EVTX parsing). The MCP protocol is implemented natively (JSON-RPC over
stdio): no external MCP dependency.

## MCP client compatibility

The server speaks the standard MCP protocol over stdio: GitHub Copilot (VS
Code, agent mode), as well as any other MCP client. Example of a generic
declaration:

```json
{
  "command": "python",
  "args": ["-m", "phoenix_dfir_mcp", "serve"],
  "cwd": "<repo>/mcp-server"
}
```

## Security

The server reads the local files it is pointed at and can run the
EZ Tools: expose it only to trusted clients, on working copies
of your evidence (never the originals), in line with your chain of custody
procedures.
