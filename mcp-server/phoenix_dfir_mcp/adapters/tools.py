"""Adapters for the external tools Phoenix drives."""

import glob
import importlib.util
import os
import shutil
import sys

from .base import Adapter, which


class Volatility(Adapter):
    name = 'volatility'
    label = 'Volatility 3'
    env = 'PHOENIX_VOLATILITY_CMD'
    candidates = ('vol', 'vol.py', 'volatility3')
    version_args = ('-h',)
    version_pattern = r'Volatility 3 Framework (\d+\.\d+(?:\.\d+)?)'
    help = 'pip install "phoenix-dfir[memory]" (volatility3), or set PHOENIX_VOLATILITY_CMD.'

    def detect_extra(self):
        try:
            if importlib.util.find_spec('volatility3') is not None:
                return [sys.executable, '-m', 'volatility3']
        except (ImportError, ValueError):
            pass
        return None

    def capabilities(self):
        from .. import volatility
        return {'plugins': sorted(volatility.PLUGINS)}


class Hayabusa(Adapter):
    name = 'hayabusa'
    label = 'Hayabusa'
    env = 'PHOENIX_HAYABUSA_CMD'
    candidates = ('hayabusa',)
    version_args = ('help',)
    version_pattern = r'[Vv]?(\d+\.\d+\.\d+)'
    fallback = 'built-in Sigma engine (sigma_scan)'
    help = 'Download Hayabusa and put it on the PATH, or set PHOENIX_HAYABUSA_CMD.'

    def detect_extra(self):
        # Versioned binary (hayabusa-3.x.y-lin-x64-musl) on the PATH
        for directory in os.environ.get('PATH', '').split(os.pathsep):
            for match in sorted(glob.glob(os.path.join(directory, 'hayabusa-*'))):
                if os.access(match, os.X_OK) and not match.endswith('.zip'):
                    return [match]
        return None

    def capabilities(self):
        return {'commands': ['json-timeline'], 'min_levels': ['informational', 'low', 'medium', 'high', 'critical']}


class SleuthKit(Adapter):
    """The Sleuth Kit: several binaries. PHOENIX_TSK_CMD names fls or the folder holding them."""

    name = 'tsk'
    label = 'The Sleuth Kit'
    env = 'PHOENIX_TSK_CMD'
    candidates = ('fls',)
    version_args = ('-V',)
    version_pattern = r'ver (\d+\.\d+(?:\.\d+)?)'
    binaries = ('mmls', 'fsstat', 'fls', 'icat')
    help = "Install The Sleuth Kit (package 'sleuthkit': mmls, fsstat, fls, icat), or set PHOENIX_TSK_CMD."

    def _folder(self):
        explicit = os.environ.get(self.env, '').strip().strip('"')
        if explicit:
            return explicit if os.path.isdir(explicit) else os.path.dirname(explicit)
        return None

    def binary(self, name):
        folder = self._folder()
        if folder:
            # shutil.which with path= honours PATHEXT (.exe, .bat...) on Windows
            return shutil.which(name, path=folder)
        return which(name)

    def detect(self):
        paths = [self.binary(b) for b in self.binaries]
        return [paths[self.binaries.index('fls')]] if all(paths) else None

    def capabilities(self):
        return {'binaries': {b: self.binary(b) for b in self.binaries + ('img_stat',)}}


class EZTools(Adapter):
    """Eric Zimmerman tools: one adapter for the allowlisted set (EZ_TOOLS_PATH)."""

    name = 'eztools'
    label = 'EZ Tools'
    env = 'PHOENIX_EZTOOLS_CMD'  # folder of the EZ Tools (alias of EZ_TOOLS_PATH)
    help = 'Install the EZ Tools and set EZ_TOOLS_PATH (dotnet runtime needed on Linux and macOS).'
    fallback = 'native Prefetch, LNK and browser parsers'

    def _available_tools(self):
        from .. import zimmermann
        return {tool: zimmermann._find_binary(tool)[0] for tool in sorted(zimmermann.EZ_TOOLS)}

    def detect(self):
        found = [cmd for cmd in self._available_tools().values() if cmd]
        return found[0] if found else None

    def version(self):
        return None  # each tool has its own version; listed in capabilities

    def capabilities(self):
        tools = self._available_tools()
        return {'available': sorted(t for t, cmd in tools.items() if cmd),
                'missing': sorted(t for t, cmd in tools.items() if not cmd),
                'dotnet': which('dotnet')}


class TShark(Adapter):
    name = 'tshark'
    label = 'TShark'
    env = 'PHOENIX_TSHARK_CMD'
    candidates = ('tshark',)
    version_pattern = r'TShark \(Wireshark\) (\d+\.\d+(?:\.\d+)?)'
    fallback = 'built-in pure Python PCAP parser (net_* tools)'
    help = 'Install Wireshark (tshark) or set PHOENIX_TSHARK_CMD. Optional: the net_* tools work without it.'

    def capabilities(self):
        return {'statistics': ['io,phs']}


ADAPTERS = {a.name: a for a in (Volatility(), Hayabusa(), SleuthKit(), EZTools(), TShark())}
