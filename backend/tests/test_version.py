"""The version is single-sourced from phoenix_dfir_mcp.__version__."""

import json
import re
from pathlib import Path

import extensions
import phoenix_dfir_mcp

ROOT = Path(__file__).resolve().parents[2]


def test_backend_version_matches_package():
    assert extensions.PHOENIX_VERSION == phoenix_dfir_mcp.__version__


def test_frontend_version_matches_package():
    package = json.loads((ROOT / 'package.json').read_text(encoding='utf-8'))
    assert package['version'] == phoenix_dfir_mcp.__version__


def test_changelog_top_entry_matches_package():
    text = (ROOT / 'CHANGELOG.md').read_text(encoding='utf-8')
    released = re.findall(r'^## \[(\d+\.\d+\.\d+)\]', text, flags=re.M)
    assert released and released[0] == phoenix_dfir_mcp.__version__


def test_mcp_server_reports_package_version():
    from phoenix_dfir_mcp import server
    assert server.SERVER_INFO['version'] == phoenix_dfir_mcp.__version__
