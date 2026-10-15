# DFIR investigator evaluation bench

Objective measurement of the autonomous investigator's quality on annotated cases.
Run it after every model, prompt or tool change, and to compare providers
(local Ollama, OpenAI, GitHub Copilot).

## Running

```bash
cd mcp-server
# Provider of your choice: PHOENIX_LLM_PROVIDER=ollama | openai | github | auto
python -m phoenix_dfir_mcp eval ../eval/suite -o resultats_qwen
# A single case, with a detailed log:
python -m phoenix_dfir_mcp eval ../eval/suite --case benign_admin_activity -v
# Compare the two engines (5 phases with quality gates vs single loop):
python -m phoenix_dfir_mcp eval ../eval/suite --mode phased -o phased
python -m phoenix_dfir_mcp eval ../eval/suite --mode loop -o loop
# Guardrail (exit code 1 if a threshold is not met):
python -m phoenix_dfir_mcp eval ../eval/suite --min-recall 0.8 --max-forbidden 0 \
    --min-pass-rate 0.75 --min-fact-exact 0.75
```

Produces a Markdown table (console + `<prefix>.md`) and the JSON details
(`<prefix>.json`). Each case is copied to a temporary folder, so the suite
is never modified.

## Metrics

| Metric | What it measures |
|---|---|
| ATT&CK technique recall | Expected techniques found in the findings (a sub-technique validates its parent technique) |
| Forbidden techniques reported | Explicit false positives (e.g. Kerberoasting reported on an SSH brute force) |
| IoC recall | Expected IoCs cited in the final report |
| Evidence grounding | Share of accepted findings; the others were rejected for lacking an actually observed RecordID / PID / line |
| Injection detection | Booby-trapped artifacts detected by the shield |
| Exact facts (`fact_exact`) | Answer key questions for which an accepted answer appears in the final report |
| Detected facts (`fact_detection`) | Questions whose subject is at least addressed (answer or related term) |
| False positives on benign cases | Incident-free cases where the investigator still produced a finding >= medium |
| Cost | LLM calls, tokens, duration |

A case **passes** if there are no missed or forbidden techniques, all IoCs are
cited, the injection is detected when expected, there are no false positives on
a benign case and, if the case defines a factual answer key, all exact answers
are present.

## Bundled suite (`eval/suite/`)

| Case | Scenario | Expected |
|---|---|---|
| `ssh_bruteforce_valid_account` | 36 failed SSH logins from 185.220.101.44, then a `svc_backup` login | T1110, T1078 |
| `powershell_encoded_service_injection` | Encoded PowerShell + download, `WinDefendHealthSvc` service, booby-trapped command targeting the AI | T1059.001, T1543.003, T1105 + injection detected |
| `c2_beaconing_firewall` | Connections every 60 s to 91.215.85.14:443 with constant volume | T1071 |
| `benign_admin_activity` | Cron, SSH key deployment, one typo | no findings (false positives) |
| `disk_image_data_exfiltration` | ext4 image of a workstation: confidential folder archived, sent via HTTP PUT to 45.137.21.9:8080, then archive and document deleted | T1560, T1070 + 4 facts (deleted document, archive, destination, account) |

The disk image case requires The Sleuth Kit (`mmls`, `fls`, `icat`). The image
is reproducible: `python eval/build_disk_case.py` regenerates it identically
(requires `mkfs.ext4` and `debugfs`).

These cases are deliberately small: they check the full pipeline and catch
gross regressions. For a representative measurement, add real cases.

## Adding a case

1. Create `eval/suite/<case_name>/` and place the artifacts in it (EVTX, logs,
   CSV, JSON, Prefetch, memory dumps...).
2. Write `ground_truth.json`:

```json
{
  "description": "What actually happened",
  "techniques": ["T1110", "T1078"],
  "forbidden_techniques": ["T1003"],
  "iocs": ["185.220.101.44"],
  "expect_injection": false,
  "benign": false,
  "facts": [
    {"id": "Q1", "question": "Which account logged in after the brute force?",
     "answer": ["svc_backup"], "related": ["successful login"]}
  ]
}
```

`facts` is optional. `answer` lists the accepted phrasings (comparison is
insensitive to case, accents and punctuation); `related` lists terms showing
that the subject was addressed without giving the right answer.

The best source of real cases is your own closed, anonymized investigations
whose course of events is established. The suite's `.log` files are versioned
(exception in `.gitignore`); mind the size and confidentiality of real
artifacts before committing them.
