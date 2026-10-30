"""External tool adapters (detect, version, capabilities, run)."""

from .base import Adapter, ToolNotAvailable, parse_command, which
from .tools import ADAPTERS, EZTools, Hayabusa, SleuthKit, TShark, Volatility


def get(name):
    return ADAPTERS[name]


def statuses():
    return [adapter.status() for adapter in ADAPTERS.values()]


__all__ = ['ADAPTERS', 'Adapter', 'EZTools', 'Hayabusa', 'SleuthKit', 'TShark', 'ToolNotAvailable',
           'Volatility', 'get', 'parse_command', 'statuses', 'which']
