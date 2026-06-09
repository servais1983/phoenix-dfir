# Code legacy (Phoenix v1)

Ce dossier contient le CLI historique de Phoenix, antérieur à la plateforme web :

- `phoenix.py` : CLI Typer original (analyse de fichiers assistée par IA via Ollama
  ou Gemini, enrichissement VirusTotal, sessions JSON).
- `phoenix_service.py` : portage du CLI en classe de service (non utilisé par le backend).
- `requirements.txt` : dépendances propres au CLI (`typer`, `ollama`,
  `google-generativeai`, `pandas`, `python-evtx`).

Le backend Flask (`backend/`) tente d'importer `phoenix.py` de manière optionnelle
pour les fonctions d'analyse IA ; sans lui (ou sans ses dépendances), la plateforme
fonctionne en mode standalone avec ses parsers natifs.

Pour utiliser le CLI :

```bash
pip install -r legacy/requirements.txt
python legacy/phoenix.py --help
```

Renseignez vos clés API (Google, VirusTotal) via les constantes en tête de
`phoenix.py` avant utilisation.
