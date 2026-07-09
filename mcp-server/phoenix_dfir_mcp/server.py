"""Serveur MCP (Model Context Protocol) stdio pour la boite a outils DFIR.

Implementation directe du protocole MCP (JSON-RPC 2.0, messages delimites
par des sauts de ligne sur stdio) sans dependance externe — compatible avec
GitHub Copilot en mode agent (VS Code : .vscode/mcp.json), Claude Desktop et
tout client MCP standard.

Methodes supportees : initialize, notifications/initialized, ping,
tools/list, tools/call.
"""

import json
import sys

from . import __version__, toolkit

PROTOCOL_VERSION = '2024-11-05'

SERVER_INFO = {
    'name': 'phoenix-dfir',
    'version': __version__,
}


def handle_message(msg):
    """Traiter un message JSON-RPC MCP. Retourne la reponse (dict) ou None
    pour les notifications."""
    method = msg.get('method', '')
    msg_id = msg.get('id')
    params = msg.get('params') or {}

    # Notifications : pas de reponse
    if msg_id is None:
        return None

    if method == 'initialize':
        client_version = params.get('protocolVersion') or PROTOCOL_VERSION
        result = {
            'protocolVersion': client_version,
            'capabilities': {'tools': {}},
            'serverInfo': SERVER_INFO,
            'instructions': (
                "Boite a outils DFIR Phoenix : inventaire d'artefacts, parsers "
                "EVTX/CSV/JSON/logs/Prefetch/LNK/navigateurs, extraction d'IoCs, "
                "regles Sigma, mapping MITRE ATT&CK, VirusTotal, outils Eric "
                "Zimmermann et redaction de rapport. Pour investiguer un cas : "
                "commencer par list_artifacts, analyser chaque artefact, lancer "
                "sigma_scan sur les EVTX, correler les IoCs puis save_report."
            ),
        }
        return {'jsonrpc': '2.0', 'id': msg_id, 'result': result}

    if method == 'ping':
        return {'jsonrpc': '2.0', 'id': msg_id, 'result': {}}

    if method == 'tools/list':
        return {'jsonrpc': '2.0', 'id': msg_id, 'result': {'tools': toolkit.list_tools()}}

    if method == 'tools/call':
        name = params.get('name', '')
        arguments = params.get('arguments') or {}
        result = toolkit.run_tool(name, arguments)
        is_error = isinstance(result, dict) and bool(result.get('error'))
        return {
            'jsonrpc': '2.0',
            'id': msg_id,
            'result': {
                'content': [{'type': 'text', 'text': toolkit.to_json(result)}],
                'isError': is_error,
            },
        }

    return {
        'jsonrpc': '2.0',
        'id': msg_id,
        'error': {'code': -32601, 'message': f'Methode non supportee: {method}'},
    }


def serve(stdin=None, stdout=None):
    """Boucle stdio : une ligne = un message JSON-RPC."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            response = {
                'jsonrpc': '2.0', 'id': None,
                'error': {'code': -32700, 'message': 'JSON invalide'},
            }
            stdout.write(json.dumps(response, ensure_ascii=False) + '\n')
            stdout.flush()
            continue
        response = handle_message(msg)
        if response is not None:
            stdout.write(json.dumps(response, ensure_ascii=False) + '\n')
            stdout.flush()
