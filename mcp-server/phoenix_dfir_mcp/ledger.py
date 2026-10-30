"""Custody ledger access for the CLI and the MCP package (backend/custody.py)."""

from . import _paths


class LedgerError(RuntimeError):
    """The custody ledger could not record the entry."""


def record(action, actor='phoenix-cli', **kwargs):
    """Seal an entry in the custody hash chain and return it (dict)."""
    try:
        _paths.ensure_backend_importable()
        import custody
        custody.init_schema()
        return custody.record(action, actor, **kwargs)
    except Exception as e:
        raise LedgerError(f'custody ledger unavailable: {e}') from e
