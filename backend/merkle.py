#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Merkle tree over the chain of custody ledger (RFC 6962 / RFC 9162 layout).

Hashing (identical to Certificate Transparency):

    leaf_hash(d)  = SHA256(0x00 || d)
    node_hash(l,r)= SHA256(0x01 || l || r)
    MTH({})       = SHA256("")
    MTH(D[n])     = node_hash(MTH(D[0:k]), MTH(D[k:n]))  with k the largest
                    power of two strictly smaller than n.

For the ledger, the leaf data of an entry is the raw 32 bytes of its
entry_hash (the SHA-256 that already seals the entry content and its link
to the previous entry). The domain separation bytes 0x00 / 0x01 prevent
second preimage attacks between leaves and interior nodes.

Inclusion proofs follow RFC 6962 section 2.1.1 (PATH) and are verified with
the RFC 9162 section 2.1.3.2 algorithm, so any independent CT tooling can
check them. Pure standard library: no dependency.
"""

import hashlib

EMPTY_ROOT = hashlib.sha256(b'').hexdigest()


def leaf_hash(data):
    return hashlib.sha256(b'\x00' + data).digest()


def node_hash(left, right):
    return hashlib.sha256(b'\x01' + left + right).digest()


def _split(n):
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _root_of_hashes(hashes):
    n = len(hashes)
    if n == 0:
        return hashlib.sha256(b'').digest()
    if n == 1:
        return hashes[0]
    k = _split(n)
    return node_hash(_root_of_hashes(hashes[:k]), _root_of_hashes(hashes[k:]))


def root_from_leaves(leaves):
    """Merkle tree head (bytes) of a list of raw leaf data (bytes)."""
    return _root_of_hashes([leaf_hash(d) for d in leaves])


def root_hex(leaves):
    return root_from_leaves(leaves).hex()


def _path(index, hashes):
    n = len(hashes)
    if n <= 1:
        return []
    k = _split(n)
    if index < k:
        return _path(index, hashes[:k]) + [_root_of_hashes(hashes[k:])]
    return _path(index - k, hashes[k:]) + [_root_of_hashes(hashes[:k])]


def inclusion_proof(index, leaves):
    """Audit path (list of bytes) for leaf `index` in the tree of `leaves`."""
    if not 0 <= index < len(leaves):
        raise IndexError('leaf index out of range')
    return _path(index, [leaf_hash(d) for d in leaves])


def verify_inclusion(leaf_data, index, tree_size, proof, root):
    """RFC 9162 2.1.3.2: True when `leaf_data` sits at `index` in a tree of
    `tree_size` leaves whose head is `root`. proof/root accept bytes or hex."""
    def _b(value):
        return bytes.fromhex(value) if isinstance(value, str) else value
    try:
        proof = [_b(p) for p in proof]
        root = _b(root)
    except (TypeError, ValueError):
        return False
    if not 0 <= index < tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash(leaf_data)
    for p in proof:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def ledger_leaf(entry_hash_hex):
    """Leaf data of a ledger entry: raw bytes of its entry_hash."""
    return bytes.fromhex(entry_hash_hex)


def build_ledger_tree(entries):
    """Summary of the tree over ledger entries (ordered by seq)."""
    leaves = [ledger_leaf(e['entry_hash']) for e in entries]
    return {
        'algorithm': 'RFC6962-SHA256 (leaf = entry_hash bytes)',
        'leaf_count': len(leaves),
        'root': root_hex(leaves),
        'first_seq': entries[0]['seq'] if entries else None,
        'last_seq': entries[-1]['seq'] if entries else None,
    }


def ledger_proof(entries, seq):
    """Inclusion proof of the entry `seq` within `entries` (ordered by seq),
    or None if the entry is not part of them."""
    index = next((i for i, e in enumerate(entries) if e['seq'] == seq), None)
    if index is None:
        return None
    leaves = [ledger_leaf(e['entry_hash']) for e in entries]
    proof = inclusion_proof(index, leaves)
    return {
        'seq': seq,
        'entry_hash': entries[index]['entry_hash'],
        'leaf_index': index,
        'tree_size': len(leaves),
        'root': root_hex(leaves),
        'proof': [p.hex() for p in proof],
        'leaf_hash': leaf_hash(leaves[index]).hex(),
    }
