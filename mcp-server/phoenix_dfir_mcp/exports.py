"""Exports d'enquete : calque ATT&CK Navigator et liste d'IoCs (CSV).

- ``attack_navigator_layer.json`` : calque importable dans MITRE ATT&CK
  Navigator (https://mitre-attack.github.io/attack-navigator/), une technique
  par constat retenu, score selon la severite, commentaire = constats.
- ``iocs.csv`` : IoCs extraits du rapport et des preuves citees, pour import
  dans un SIEM, un EDR ou MISP.

Les constats refutes (verification independante ou contre-analyse) sont exclus.
"""

import csv
import json
import os
import re

from . import memory

_SCORES = {'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'info': 10}
_TECH_RE = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)

NAVIGATOR_FILE = 'attack_navigator_layer.json'
IOCS_FILE = 'iocs.csv'


def retained_findings(case_dir):
    """Constats non refutes (ni par la verification, ni par la contre-analyse)."""
    out = []
    for f in memory.get_state(case_dir)['findings']:
        if f.get('verification') == 'refuted':
            continue
        if (f.get('challenge') or {}).get('verdict') == 'refuted':
            continue
        out.append(f)
    return out


def navigator_layer(case_dir, title):
    techniques = {}
    for f in retained_findings(case_dir):
        for tech in {t.upper() for t in _TECH_RE.findall(f.get('mitre') or '')}:
            entry = techniques.setdefault(tech, {'score': 0, 'comments': []})
            entry['score'] = max(entry['score'], _SCORES.get(f['severity'], 10))
            entry['comments'].append(f"#{f['id']} {f['title']}")
    return {
        'name': f'Phoenix DFIR - {title}'[:120],
        'versions': {'layer': '4.5', 'navigator': '5.1.0'},
        'domain': 'enterprise-attack',
        'description': "Techniques ATT&CK etablies par l'enquete Phoenix DFIR (constats non refutes).",
        'techniques': [
            {'techniqueID': tech, 'score': data['score'], 'enabled': True,
             'comment': ' | '.join(data['comments'])[:1000]}
            for tech, data in sorted(techniques.items())
        ],
        'gradient': {'colors': ['#fff3b0', '#ff9f43', '#c0392b'], 'minValue': 0, 'maxValue': 100},
        'legendItems': [{'label': sev, 'color': color} for sev, color in
                        (('critical', '#c0392b'), ('high', '#ff9f43'), ('medium', '#ffd166'))],
    }


def iocs_rows(case_dir, report_text):
    """IoCs du rapport + des preuves des constats retenus, dedupliques."""
    from parsers import extract_iocs  # backend Phoenix (rendu importable par toolkit)
    texts = [report_text or '']
    texts += [f"{f.get('title', '')} {f.get('evidence', '')}" for f in retained_findings(case_dir)]
    seen, rows = set(), []
    for ioc in extract_iocs('\n'.join(texts)):
        key = (ioc['type'], ioc['value'].lower())
        if key not in seen:
            seen.add(key)
            rows.append({'type': ioc['type'], 'value': ioc['value'], 'source': 'phoenix-dfir'})
    return rows


def write_exports(case_dir, title, report_text):
    """Ecrire le calque Navigator et le CSV d'IoCs dans le dossier du cas."""
    layer_path = os.path.join(case_dir, NAVIGATOR_FILE)
    with open(layer_path, 'w', encoding='utf-8') as f:
        json.dump(navigator_layer(case_dir, title), f, ensure_ascii=False, indent=2)
    rows = iocs_rows(case_dir, report_text)
    iocs_path = os.path.join(case_dir, IOCS_FILE)
    with open(iocs_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['type', 'value', 'source'])
        writer.writeheader()
        writer.writerows(rows)
    return {'navigator_layer': layer_path, 'iocs_csv': iocs_path, 'iocs_count': len(rows)}
