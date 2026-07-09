# Code legacy (Phoenix v1)

Ce dossier contient le CLI historique de Phoenix, antérieur à la plateforme web :

- `phoenix.py` : CLI Typer original (analyse de fichiers assistée par IA via
  GitHub Copilot — API GitHub Models —, enrichissement VirusTotal, sessions JSON).
- `requirements.txt` : dépendances propres au CLI (`typer`, `pandas`,
  `requests`, `python-evtx`).

Le backend Flask (`backend/`) tente d'importer `phoenix.py` de manière optionnelle
pour les fonctions d'analyse IA ; sans lui (ou sans ses dépendances), la plateforme
fonctionne en mode standalone avec ses parsers natifs.

Pour utiliser le CLI :

```bash
pip install -r legacy/requirements.txt
export GITHUB_TOKEN="github_pat_..."   # jeton GitHub, permission "Models: read"
python legacy/phoenix.py --help
```

L'IA repose exclusivement sur GitHub Copilot : définissez `GITHUB_TOKEN` (ou
`PHOENIX_GITHUB_TOKEN`) et, optionnellement, `PHOENIX_GITHUB_MODEL` (défaut
`openai/gpt-4o-mini`). La clé VirusTotal se configure via `API_KEY_VT`.
