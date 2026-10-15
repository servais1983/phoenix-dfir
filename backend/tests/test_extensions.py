"""Mecanisme d'extensions d'outils (phoenix_dfir_mcp/ext)."""

import importlib
import os
import sys
import textwrap

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'mcp-server'))

from phoenix_dfir_mcp import ext, toolkit  # noqa: E402


def test_extension_enregistre_outils_agent_phases_et_couverture(tmp_path, monkeypatch):
    mod_path = os.path.join(os.path.dirname(ext.__file__), '_demo_ext_test.py')
    with open(mod_path, 'w', encoding='utf-8') as f:
        f.write(textwrap.dedent('''
            from .. import toolkit
            AGENT = ('demo', 'Agent Demo')
            READONLY = ('demo_parse',)
            INDEXED = ('demo_parse',)
            KNOWN_TYPES = {'.demo': 'Artefact demo'}
            PHASE_TOOLS = {'extraction': ('demo_parse',)}
            PHASE_HINTS = {'extraction': '- Les fichiers .demo passent par demo_parse.'}

            @toolkit.tool('demo_parse', 'Parser demo', {'type': 'object', 'properties': {}})
            def demo_parse():
                return {'ok': True}

            def applicable(path):
                return [('parsing', ('demo_parse',))] if path.endswith('.demo') else None
        '''))
    try:
        monkeypatch.setattr(ext, 'EXTENSIONS', ('_demo_ext_test',))
        toolkit._load_extensions()
        assert 'demo_parse' in toolkit.TOOLS
        assert 'demo_parse' in toolkit.READONLY_TOOLS and 'demo_parse' in toolkit.INDEXED_TOOLS
        assert toolkit.agent_for('demo_parse') == 'Agent Demo'
        assert toolkit.applicable_tools('x.demo') == ([('parsing', ('demo_parse',))], [])
        assert 'demo_parse' in toolkit.EXT_PHASE_TOOLS['extraction']
    finally:
        os.remove(mod_path)
        toolkit.TOOLS.pop('demo_parse', None)
        toolkit._EXT_MODULES[:] = [m for m in toolkit._EXT_MODULES
                                   if not m.__name__.endswith('_demo_ext_test')]
        sys.modules.pop('phoenix_dfir_mcp.ext._demo_ext_test', None)


def test_extension_cassee_ignoree(monkeypatch):
    monkeypatch.setattr(ext, 'EXTENSIONS', ('module_inexistant',))
    toolkit._load_extensions()
    assert 'module_inexistant' in toolkit.EXT_ERRORS
    toolkit.EXT_ERRORS.pop('module_inexistant')
