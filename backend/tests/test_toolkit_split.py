#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The core tools are split by family; the registry and toolkit.<name> stay the API."""

import importlib

from phoenix_dfir_mcp import toolkit

FAMILIES = ('tools_artifacts', 'tools_external', 'tools_case', 'tools_disk', 'tools_evidence')


def _family(name):
    return toolkit.TOOLS[name]['func'].__module__.rsplit('.', 1)[-1]


def test_every_tool_comes_from_a_family_module_or_an_extension():
    for name in toolkit.TOOLS:
        module = toolkit.TOOLS[name]['func'].__module__
        assert _family(name) in FAMILIES or module.startswith('phoenix_dfir_mcp.ext.'), name


def test_every_core_tool_is_reexported_by_toolkit():
    core = [n for n in toolkit.TOOLS if _family(n) in FAMILIES]
    assert len(core) == 38  # 39 core tools, set_hypothesis is replaced by the hypotheses extension
    for name in core:
        func = toolkit.TOOLS[name]['func']
        assert getattr(toolkit, func.__name__) is func


def test_core_tools_are_registered_family_by_family():
    order = [_family(n) for n in toolkit.TOOLS if _family(n) in FAMILIES]
    assert list(dict.fromkeys(order)) == list(FAMILIES)
    assert order == sorted(order, key=FAMILIES.index)  # contiguous: the MCP tool list order is kept


def test_family_modules_share_the_registry_state():
    artifacts = importlib.import_module('phoenix_dfir_mcp.tools_artifacts')
    assert artifacts._KNOWN_TYPES is toolkit._KNOWN_TYPES
    assert artifacts.EXT_INTERNAL_DIRS is toolkit.EXT_INTERNAL_DIRS
