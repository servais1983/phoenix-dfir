"""Deterministic triage: run the applicable tools on a case, no LLM involved.

The triage engine runs every tool that applies to each artifact of a case
(``toolkit.applicable_tools``) and keeps, as findings, only the detections the
tools themselves emitted (``alerts`` and ``findings`` entries that carry a
severity) AND that cite at least one observed reference (``record_id``,
``row``, ``line``, ``pid``, ``inode`` or ``sha256``). Parser events are never
promoted to findings, and nothing is inferred: the output is the same for
the same input, byte for byte.

The engine never writes into the case folder. Tools are called directly,
without the evidence index; derived data (files extracted from a disk image,
carved payloads) goes to a temporary folder (or ``derived_dir``) and is
triaged in turn, labelled ``derived/...``. The report is only written where
the caller asks (``write_report``).
"""

import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from . import __version__, pathpolicy, toolkit, workspace

REF_KEYS = ('record_id', 'row', 'line', 'pid', 'inode', 'sha256')
ENTITY_KEYS = ('src', 'dst', 'dst_port', 'host', 'hostname', 'computer', 'ip', 'client', 'server',
               'user', 'username', 'account', 'target_user', 'service_name', 'process', 'image',
               'command_line', 'domain', 'sni', 'ja3_hash', 'path', 'file', 'event_id')
DETECTION_KEYS = ('alerts', 'findings')
SEVERITIES = ('critical', 'high', 'medium', 'low', 'info')
_RANK = {s: i for i, s in enumerate(SEVERITIES)}
MAX_REFS = 25
_CHUNK = 1024 * 1024


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(_CHUNK), b''):
            digest.update(block)
    return digest.hexdigest()


def _severity(item):
    value = str(item.get('severity') or item.get('level') or '').strip().lower()
    return value if value in _RANK else None


def _techniques(item):
    found = []
    for key in ('technique', 'technique_id', 'mitre', 'techniques', 'mitre_techniques'):
        value = item.get(key)
        values = value if isinstance(value, (list, tuple)) else [value]
        for v in values:
            if isinstance(v, str) and v.strip() and v.strip().upper().startswith('T'):
                found.append(v.strip().upper())
    return sorted(set(found))


def _refs(item):
    return {k: item[k] for k in REF_KEYS if item.get(k) not in (None, '', [])}


def _entities(item):
    out = {}
    for key in ENTITY_KEYS:
        value = item.get(key)
        if isinstance(value, (str, int, float)) and value not in ('', None):
            out[key] = value
    return out


def _title(item):
    for key in ('rule_title', 'title', 'name', 'type', 'rule_id', 'id'):
        if item.get(key):
            return str(item[key])
    return 'Detection'


def _tool_args(name, artifact, case_dir):
    props = toolkit.TOOLS[name]['input_schema'].get('properties', {})
    args = {}
    if 'file_path' in props:
        args['file_path'] = artifact
    if 'case_dir' in props:
        args['case_dir'] = case_dir
    return args


def _detections(result):
    """Yield the detection entries a tool emitted (with a known severity)."""
    if not isinstance(result, dict):
        return
    for key in DETECTION_KEYS:
        items = result.get(key)
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and _severity(item):
                yield item


def _triage_artifact(path, label, case, groups, counters):
    tool_groups, unavailable = toolkit.applicable_tools(path)
    entry = {'path': label, 'size': os.path.getsize(path), 'sha256': _sha256(path),
             'tools_run': [], 'tools_unavailable': sorted(unavailable), 'errors': []}
    for name in sorted({t for _, tools in tool_groups for t in tools}):
        try:
            result = toolkit.TOOLS[name]['func'](**_tool_args(name, path, str(case)))
        except Exception as e:  # a failing tool is reported, never hidden
            entry['errors'].append({'tool': name, 'error': f'{type(e).__name__}: {e}'})
            continue
        if isinstance(result, dict) and result.get('error'):
            entry['errors'].append({'tool': name, 'error': str(result['error'])})
        entry['tools_run'].append(name)
        for item in _detections(result):
            refs = _refs(item)
            if not refs:
                counters['unreferenced'] += 1
                continue
            severity = _severity(item)
            techniques = _techniques(item)
            key = (label, name, _title(item), severity, tuple(techniques))
            group = groups.setdefault(key, {
                'severity': severity, 'title': _title(item), 'tool': name, 'artifact': label,
                'techniques': techniques, 'description': str(item.get('description') or ''),
                'entities': _entities(item), 'refs': [], 'count': 0})
            group['count'] += 1
            if len(group['refs']) < MAX_REFS and refs not in group['refs']:
                group['refs'].append(refs)
    return entry


def _sorted_artifacts(root):
    root = Path(root)
    return sorted(((p, Path(p).relative_to(root).as_posix()) for p in toolkit.case_artifacts(str(root))),
                  key=lambda item: item[1])


def run_triage(case_dir, derived_dir=None):
    """Triage a case folder and return a deterministic report (dict).

    Derived data goes to `derived_dir`, or to a temporary folder removed
    afterwards. The case folder itself is only read.
    """
    case = Path(case_dir).resolve()
    if not case.is_dir():
        raise ValueError(f'Case folder not found: {case_dir}')
    temp = None if derived_dir else tempfile.mkdtemp(prefix='phoenix-triage-')
    derived = Path(derived_dir or temp).resolve()
    artifacts, groups, counters = [], {}, {'unreferenced': 0}
    try:
        with workspace.derived_scope(str(derived)), pathpolicy.job_scope(str(case), [str(derived)]):
            # Standard layout: the evidence is under evidence/ (derived/ is handled below)
            layout = workspace.has_layout(str(case))
            root = case / workspace.EVIDENCE_DIR if layout else case
            prefix = f'{workspace.EVIDENCE_DIR}/' if layout else ''
            for path, rel in _sorted_artifacts(root):
                artifacts.append(_triage_artifact(path, prefix + rel, case, groups, counters))
            # Second pass: what the tools derived (extracted files, carved payloads)
            for path, rel in _sorted_artifacts(derived):
                artifacts.append(_triage_artifact(path, f'derived/{rel}', case, groups, counters))
    finally:
        if temp:
            shutil.rmtree(temp, ignore_errors=True)
    unreferenced = counters['unreferenced']

    findings = sorted(groups.values(), key=lambda f: (_RANK[f['severity']], f['artifact'], f['tool'], f['title'],
                                                      json.dumps(f['refs'][:1], sort_keys=True, default=str)))
    for i, finding in enumerate(findings, 1):
        finding['id'] = f'F-{i:03d}'
    by_severity = {s: sum(1 for f in findings if f['severity'] == s) for s in SEVERITIES}
    return {
        'engine': 'phoenix-triage',
        'version': __version__,
        'deterministic': True,
        'llm': None,
        'case': case.name,
        'artifacts': artifacts,
        'findings': [{k: f[k] for k in ('id', 'severity', 'title', 'tool', 'artifact', 'techniques',
                                         'count', 'refs', 'entities', 'description')} for f in findings],
        'summary': {
            'artifacts': len(artifacts),
            'findings': len(findings),
            'by_severity': by_severity,
            'techniques': sorted({t for f in findings for t in f['techniques']}),
            'detections_without_reference': unreferenced,
            'tools_unavailable': sorted({t for a in artifacts for t in a['tools_unavailable']}),
            'tool_errors': sum(len(a['errors']) for a in artifacts),
        },
    }


def to_json(report):
    return json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True, default=str) + '\n'


def _ref_text(refs):
    return ', '.join(f'{k}={v}' for r in refs for k, v in r.items())


def render_markdown(report):
    s = report['summary']
    counts = ', '.join(f'{n} {sev}' for sev, n in s['by_severity'].items() if n)
    lines = [f"# Phoenix DFIR triage: {report['case']}", '',
             f"Deterministic triage (no LLM), engine {report['engine']} {report['version']}.", '',
             f"- Artifacts: {s['artifacts']}",
             f"- Findings: {s['findings']}" + (f' ({counts})' if counts else ''),
             f"- ATT&CK techniques: {', '.join(s['techniques']) or 'none'}"]
    if s['tools_unavailable']:
        lines.append(f"- Tools not available: {', '.join(s['tools_unavailable'])}")
    if s['tool_errors']:
        lines.append(f"- Tool errors: {s['tool_errors']}")
    if s['detections_without_reference']:
        lines.append(f"- Detections ignored (no observed reference): {s['detections_without_reference']}")
    lines += ['', '## Findings', '']
    if not report['findings']:
        lines.append('No detection was emitted by the tools.')
    for f in report['findings']:
        techniques = f" [{', '.join(f['techniques'])}]" if f['techniques'] else ''
        lines.append(f"### {f['id']} {f['severity'].upper()} {f['title']}{techniques}")
        lines.append('')
        lines.append(f"- Source: `{f['artifact']}` via `{f['tool']}` ({f['count']} occurrence(s))")
        lines.append(f"- References: {_ref_text(f['refs'])}")
        if f['entities']:
            lines.append('- Entities: ' + ', '.join(f'{k}={v}' for k, v in f['entities'].items()))
        if f['description']:
            lines.append(f"- {f['description']}")
        lines.append('')
    lines += ['## Artifacts', '', '| Artifact | SHA-256 | Tools | Not available | Errors |', '|---|---|---|---|---|']
    for a in report['artifacts']:
        lines.append(f"| `{a['path']}` | `{a['sha256']}` | {', '.join(a['tools_run']) or '-'} | "
                     f"{', '.join(a['tools_unavailable']) or '-'} | {len(a['errors'])} |")
    return '\n'.join(lines) + '\n'


def write_report(report, out_dir):
    """Write triage.json and triage.md into out_dir and return their paths."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path, md_path = out / 'triage.json', out / 'triage.md'
    json_path.write_text(to_json(report), encoding='utf-8')
    md_path.write_text(render_markdown(report), encoding='utf-8')
    return str(json_path), str(md_path)
