"""`phoenix doctor`: what this installation can and cannot do, on this OS.

Read-only diagnostic: it probes, it never installs or changes anything. The
LLM probe only contacts local servers (loopback or investigation network).
"""

import importlib.util
import os
import platform
import sys

from . import __version__, adapters, copilot, pathpolicy, sandbox, sigma_engine

PYTHON_MODULES = (
    ('evtx', 'evtx', 'EVTX parsing (Rust engine)'),
    ('yaml', 'sigma', 'Sigma rules in YAML (PyYAML)'),
    ('yara', 'yara', 'YARA scanning (yara-python)'),
    ('volatility3', 'memory', 'Volatility 3 as a Python module'),
    ('duckdb', 'analytics', 'SQL analytics and Parquet export'),
    ('flask', 'web', 'Web console backend'),
    ('flask_socketio', 'web', 'Real-time web events'),
    ('waitress', 'web', 'Cross-platform web server'),
    ('platformdirs', None, 'Per-OS data folders'),
)


def _module(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _llm():
    provider = copilot.provider_name()
    info = {
        'provider': provider,
        'label': copilot.provider_label(provider),
        'cloud': copilot.is_cloud(provider),
        'cloud_allowed': copilot.cloud_allowed(),
        'configured': copilot.is_configured(provider),
        'model': copilot.default_model(provider),
        'seed': copilot.llm_seed(),
    }
    info['reachable'] = copilot.llm_reachable(provider)
    from . import models
    plan = models.plan(provider)
    info['available_models'] = plan['available']
    info['roles'] = {role: {'model': r['model'], 'source': r['source']} for role, r in plan['roles'].items()}
    info['deterministic_triage'] = True  # phoenix triage never needs an LLM
    return info


def _sigma():
    info = sigma_engine.status()
    info['builtin_rules'] = len(sigma_engine.builtin_rules())
    if info['available']:
        rules, errors = sigma_engine.load_rules([sigma_engine.connector_rules_path()])
        info.update(rules=len(rules), invalid=len(errors))
    return info


def _storage():
    from . import _paths
    out = {'backend_dir': None, 'database': None, 'evidence_vault': None, 'data_dir': None}
    try:
        backend = _paths.ensure_backend_importable()
        import datadirs
        out.update(backend_dir=str(backend), database=datadirs.default_db_path(),
                   evidence_vault=datadirs.default_vault_dir(),
                   source_checkout=datadirs.is_source_checkout())
        out['data_dir'] = str(datadirs.data_dir()) if not datadirs.is_source_checkout() else None
    except Exception as e:  # reported, not fatal
        out['error'] = f'{type(e).__name__}: {e}'
    return out


def collect():
    """Return the diagnostic as a dict (stable keys, JSON serialisable)."""
    tools = adapters.statuses()
    modules = [{'module': name, 'extra': extra, 'purpose': purpose, 'installed': _module(name)}
               for name, extra, purpose in PYTHON_MODULES]
    return {
        'phoenix': __version__,
        'python': platform.python_version(),
        'executable': sys.executable,
        'os': {'system': platform.system(), 'release': platform.release(), 'machine': platform.machine()},
        'llm': _llm(),
        'tools': tools,
        'python_modules': modules,
        'sandbox': sandbox.status(),
        'sigma': _sigma(),
        'path_policy': {'strict': pathpolicy.is_strict(),
                        'roots': sorted(pathpolicy.active_roots()),
                        'env': os.environ.get('PHOENIX_TOOL_ROOTS') or None},
        'storage': _storage(),
        'summary': {
            'tools_available': sorted(t['name'] for t in tools if t['available']),
            'tools_not_available': sorted(t['name'] for t in tools if not t['available']),
            'missing_modules': sorted(m['module'] for m in modules if not m['installed']),
        },
    }


def render_text(report):
    llm = report['llm']
    lines = [f"Phoenix DFIR {report['phoenix']} on {report['os']['system']} {report['os']['release']} "
             f"({report['os']['machine']}), Python {report['python']}", '',
             'LLM',
             f"  provider: {llm['label']} ({llm['provider']}), model {llm['model']}, seed {llm['seed']}",
             f"  reachable: {'yes' if llm['reachable'] else 'no'}"
             + ('' if llm['reachable'] else ' (phoenix investigate falls back to phoenix triage)'),
             f"  cloud LLM allowed: {'yes' if llm['cloud_allowed'] else 'no'} (PHOENIX_ALLOW_CLOUD_LLM)"]
    for role, info in llm.get('roles', {}).items():
        lines.append(f"  {role}: {info['model']} ({info['source']})")
    lines += ['', 'External tools']
    for tool in report['tools']:
        if tool['available']:
            version = f" {tool['version']}" if tool['version'] else ''
            lines.append(f"  [ok]   {tool['label']}{version}: {' '.join(tool['command'])}")
        else:
            fallback = f" Fallback: {tool['fallback']}." if tool['fallback'] else ''
            lines.append(f"  [--]   {tool['label']}: not available. {tool['help']}{fallback}")
    lines += ['', 'Python modules']
    for m in report['python_modules']:
        hint = f' (pip install "phoenix-dfir[{m["extra"]}]")' if m['extra'] and not m['installed'] else ''
        lines.append(f"  [{'ok' if m['installed'] else '--'}]   {m['module']}: {m['purpose']}{hint}")
    sb = report['sandbox']
    lines += ['', 'Tool sandbox', f"  mode: {sb.get('mode')}, effective: {sb.get('effective')}, "
                                  f"isolated: {'yes' if sb.get('isolated') else 'no'}"]
    sg = report['sigma']
    lines += ['', 'Sigma rules', f"  built in: {sg['builtin_rules']} (always run)"]
    if sg['available']:
        lines.append(f"  pySigma {sg.get('pysigma')}: {sg.get('rules', 0)} usable rules, {sg.get('invalid', 0)} invalid"
                     " (phoenix rules sync for the full SigmaHQ release)")
    else:
        lines.append(f"  pySigma: {sg['detail']}")
    pp = report['path_policy']
    lines += ['', 'Path policy', f"  strict: {'yes' if pp['strict'] else 'no'}, roots: {', '.join(pp['roots']) or 'none'}"]
    st = report['storage']
    lines += ['', 'Storage']
    for key in ('database', 'evidence_vault', 'data_dir', 'error'):
        if st.get(key):
            lines.append(f'  {key}: {st[key]}')
    return '\n'.join(lines) + '\n'
