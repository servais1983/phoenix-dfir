# Legacy code (Phoenix v1)

This folder contains the original Phoenix CLI, which predates the web platform:

- `phoenix.py`: the original Typer CLI (AI-assisted file analysis through
  GitHub Copilot via the GitHub Models API, VirusTotal enrichment, JSON sessions).
- `requirements.txt`: CLI-specific dependencies (`typer`, `pandas`,
  `requests`, `python-evtx`).

The Flask backend (`backend/`) tries to import `phoenix.py` optionally
for its AI analysis functions. Without it (or without its dependencies), the platform
runs in standalone mode with its native parsers.

To use the CLI:

```bash
pip install -r legacy/requirements.txt
export GITHUB_TOKEN="github_pat_..."   # GitHub token, "Models: read" permission
python legacy/phoenix.py --help
```

The AI relies exclusively on GitHub Copilot: set `GITHUB_TOKEN` (or
`PHOENIX_GITHUB_TOKEN`) and, optionally, `PHOENIX_GITHUB_MODEL` (default
`openai/gpt-4o-mini`). The VirusTotal key is configured through `API_KEY_VT`.
