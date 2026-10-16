#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Attack graph (entity graph) of an investigation.

The investigation engine writes <case_dir>/entity_graph.json. This module
reads it, validates it against the version 1 contract and sanitizes it
before it reaches the browser:

    {"version": 1, "generated_at": ISO,
     "nodes": [{"id", "type", "label", "first_seen", "last_seen", "malicious",
                "technique_ids": ["T1059.001"], "finding_ids": [1]}],
     "edges": [{"id", "source", "target", "type", "first_seen", "last_seen",
                "refs": [{"artifact", "kind", "value"}], "technique_ids", "finding_ids"}],
     "patient_zero": {"node", "timestamp", "path": [ids]},
     "blast_radius": {"seed", "nodes": [ids]}}

Sanitizing: strings are truncated and stripped of control characters,
timestamps that are not ISO 8601 become null, ATT&CK ids must match
T####(.###), edges must reference known nodes, duplicates are dropped and
the graph is capped (MAX_NODES / MAX_EDGES, `truncated` reports it).
"""

import datetime
import json
import os
import re

GRAPH_FILE = 'entity_graph.json'
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_NODES = 2000
MAX_EDGES = 5000
MAX_REFS = 50
MAX_IDS = 100
MAX_PATH = 500

NODE_TYPES = ('host', 'user', 'ip', 'domain', 'process', 'file', 'registry', 'service',
              'url', 'hash', 'account', 'task', 'other')

_CONTROL = re.compile(r'[\x00-\x1f\x7f]')
_TECHNIQUE = re.compile(r'T\d{4}(?:\.\d{3})?')
_EDGE_TYPE = re.compile(r'[a-z0-9_]{1,64}')


class GraphError(ValueError):
    """The graph file is missing, unreadable or not a v1 graph."""


def graph_path(case_dir):
    return os.path.join(case_dir, GRAPH_FILE)


def _text(value, limit=256):
    if value is None:
        return ''
    if not isinstance(value, (str, int, float)):
        return ''
    return _CONTROL.sub(' ', str(value))[:limit].strip()


def _iso(value):
    if not isinstance(value, str) or not value or len(value) > 64:
        return None
    try:
        datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    return value


def _techniques(values):
    if not isinstance(values, list):
        return []
    out = []
    for v in values:
        if isinstance(v, str) and _TECHNIQUE.fullmatch(v.strip().upper()) and v.strip().upper() not in out:
            out.append(v.strip().upper())
        if len(out) >= MAX_IDS:
            break
    return out


def _finding_ids(values):
    if not isinstance(values, list):
        return []
    out = []
    for v in values:
        if isinstance(v, bool):
            continue
        if isinstance(v, int) and v >= 0 and v not in out:
            out.append(v)
        elif isinstance(v, str) and v.isdigit() and int(v) not in out:
            out.append(int(v))
        if len(out) >= MAX_IDS:
            break
    return out


def _refs(values):
    if not isinstance(values, list):
        return []
    out = []
    for r in values[:MAX_REFS]:
        if isinstance(r, dict):
            out.append({'artifact': _text(r.get('artifact'), 512), 'kind': _text(r.get('kind'), 64),
                        'value': _text(r.get('value'), 512)})
    return out


def sanitize(raw):
    """Validate a decoded graph and return the sanitized contract dict."""
    if not isinstance(raw, dict):
        raise GraphError('graph must be a JSON object')
    version = raw.get('version', 1)
    if version != 1:
        raise GraphError(f'unsupported graph version {version!r}')
    raw_nodes = raw.get('nodes') if isinstance(raw.get('nodes'), list) else []
    raw_edges = raw.get('edges') if isinstance(raw.get('edges'), list) else []

    nodes, ids = [], set()
    for n in raw_nodes:
        if len(nodes) >= MAX_NODES:
            break
        if not isinstance(n, dict):
            continue
        node_id = _text(n.get('id'), 256)
        if not node_id or node_id in ids:
            continue
        ntype = _text(n.get('type'), 32).lower()
        ids.add(node_id)
        nodes.append({
            'id': node_id,
            'type': ntype if ntype in NODE_TYPES else 'other',
            'label': _text(n.get('label'), 256) or node_id,
            'first_seen': _iso(n.get('first_seen')),
            'last_seen': _iso(n.get('last_seen')),
            'malicious': n.get('malicious') is True,
            'technique_ids': _techniques(n.get('technique_ids')),
            'finding_ids': _finding_ids(n.get('finding_ids')),
        })

    edges, edge_ids = [], set()
    for i, e in enumerate(raw_edges):
        if len(edges) >= MAX_EDGES:
            break
        if not isinstance(e, dict):
            continue
        src, dst = _text(e.get('source'), 256), _text(e.get('target'), 256)
        if src not in ids or dst not in ids:
            continue
        edge_id = _text(e.get('id'), 128) or f'e{i + 1}'
        if edge_id in edge_ids:
            edge_id = f'{edge_id}~{i + 1}'
        edge_ids.add(edge_id)
        etype = _text(e.get('type'), 64).lower()
        edges.append({
            'id': edge_id,
            'source': src,
            'target': dst,
            'type': etype if _EDGE_TYPE.fullmatch(etype) else 'related_to',
            'first_seen': _iso(e.get('first_seen')),
            'last_seen': _iso(e.get('last_seen')),
            'refs': _refs(e.get('refs')),
            'technique_ids': _techniques(e.get('technique_ids')),
            'finding_ids': _finding_ids(e.get('finding_ids')),
        })

    pz = raw.get('patient_zero') if isinstance(raw.get('patient_zero'), dict) else {}
    pz_node = _text(pz.get('node'), 256)
    path = pz.get('path') if isinstance(pz.get('path'), list) else []
    br = raw.get('blast_radius') if isinstance(raw.get('blast_radius'), dict) else {}
    br_seed = _text(br.get('seed'), 256)
    br_nodes = br.get('nodes') if isinstance(br.get('nodes'), list) else []

    def _known(values, limit):
        out = []
        for v in values[:limit * 2]:
            t = _text(v, 256)
            if t in ids and t not in out:
                out.append(t)
            if len(out) >= limit:
                break
        return out

    return {
        'version': 1,
        'generated_at': _iso(raw.get('generated_at')),
        'nodes': nodes,
        'edges': edges,
        'patient_zero': {
            'node': pz_node if pz_node in ids else None,
            'timestamp': _iso(pz.get('timestamp')),
            'path': [p for p in (_text(x, 256) for x in path[:MAX_PATH]) if p in ids],
        },
        'blast_radius': {
            'seed': br_seed if br_seed in ids else None,
            'nodes': _known(br_nodes, MAX_NODES),
        },
        'truncated': {
            'nodes': len(raw_nodes) > MAX_NODES,
            'edges': len(raw_edges) > MAX_EDGES,
        },
    }


def load(case_dir):
    """Read and sanitize <case_dir>/entity_graph.json.

    Returns (graph, mtime). Raises FileNotFoundError when the graph has not
    been built yet and GraphError when it is invalid."""
    path = graph_path(case_dir)
    st = os.stat(path)  # FileNotFoundError when not built yet
    if st.st_size > MAX_FILE_BYTES:
        raise GraphError('graph file too large')
    with open(path, 'r', encoding='utf-8') as f:
        try:
            raw = json.load(f)
        except ValueError as e:
            raise GraphError(f'invalid JSON: {e}') from e
    return sanitize(raw), st.st_mtime


def mtime(case_dir):
    try:
        return os.stat(graph_path(case_dir)).st_mtime
    except OSError:
        return None
