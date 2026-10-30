"""Derived data location (workspace.derived_root)."""

import os

from phoenix_dfir_mcp import workspace


def test_flat_case_keeps_derived_data_in_the_case(tmp_path):
    assert workspace.derived_root(str(tmp_path)) == os.path.abspath(str(tmp_path))


def test_standard_layout_uses_the_derived_folder(tmp_path):
    (tmp_path / 'evidence').mkdir()
    assert workspace.derived_root(str(tmp_path)) == os.path.join(os.path.abspath(str(tmp_path)), 'derived')


def test_scope_overrides_and_restores(tmp_path):
    case, out = tmp_path / 'case', tmp_path / 'out'
    case.mkdir()
    with workspace.derived_scope(str(out)) as root:
        assert workspace.derived_root(str(case)) == root == os.path.abspath(str(out))
        assert workspace.rel(os.path.join(root, 'extracted', 'a.log'), str(case)) == 'extracted/a.log'
    assert workspace.derived_root(str(case)) == os.path.abspath(str(case))


def test_rel_inside_case_is_relative_to_the_case(tmp_path):
    (tmp_path / 'evidence').mkdir()
    target = tmp_path / 'derived' / 'extracted' / 'x.evtx'
    assert workspace.rel(str(target), str(tmp_path)) == 'derived/extracted/x.evtx'
