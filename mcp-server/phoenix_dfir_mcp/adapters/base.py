"""Common adapter for an external forensic tool.

An adapter answers four questions, the same way on every OS:

- ``detect()``: the command to run (argument list) or None. Order:
  ``PHOENIX_<TOOL>_CMD``, then the tool names on the PATH (``.exe`` is tried
  on Windows), then tool specific locations.
- ``version()``: the version reported by the tool itself, or None.
- ``capabilities()``: what Phoenix can do with it (allowlisted plugins,
  formats...), static data.
- ``run(args)``: run it through the tool sandbox (``sandbox.run``), with an
  argument list, never a shell.

When a tool is missing, ``status()`` says "not available" and names the
fallback, if any. Nothing is ever simulated.
"""

import os
import re
import shlex
import shutil
import subprocess  # nosec B404 - argument lists only, never a shell

from .. import sandbox

VERSION_TIMEOUT = 20


class ToolNotAvailable(RuntimeError):
    """The external tool is not installed or not configured."""


def parse_command(value):
    """Split a PHOENIX_<TOOL>_CMD value into an argument list.

    A value that is an existing file is kept whole (paths with spaces);
    otherwise it is split like a command line, and surrounding quotes are
    removed (Windows paths keep their backslashes).
    """
    value = (value or '').strip()
    if not value:
        return None
    if os.path.isfile(value):
        return [value]
    parts = shlex.split(value, posix=(os.name != 'nt'))
    return [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in '"\'' else p for p in parts] or None


def which(name):
    """shutil.which, trying name.exe as well (Windows)."""
    return shutil.which(name) or (shutil.which(f'{name}.exe') if not name.lower().endswith('.exe') else None)


class Adapter:
    name = ''
    label = ''
    env = ''
    candidates = ()
    version_args = ('--version',)
    version_pattern = r'(\d+\.\d+(?:\.\d+)?)'
    fallback = None
    help = ''

    def detect_extra(self):
        """Tool specific locations (override). Return an argument list or None."""
        return None

    def detect(self):
        explicit = parse_command(os.environ.get(self.env, '')) if self.env else None
        if explicit:
            # Configured explicitly: use it if its program exists, never guess another one
            return explicit if (os.path.isfile(explicit[0]) or which(explicit[0])) else None
        for name in self.candidates:
            path = which(name)
            if path:
                return [path]
        return self.detect_extra()

    def available(self):
        return bool(self.detect())

    def _version_output(self, cmd):
        try:
            proc = subprocess.run(list(cmd) + list(self.version_args), capture_output=True, text=True,  # nosec B603
                                  timeout=VERSION_TIMEOUT, check=False)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return ''
        return f'{proc.stdout or ""}\n{proc.stderr or ""}'

    def version(self):
        cmd = self.detect()
        if not cmd:
            return None
        match = re.search(self.version_pattern, self._version_output(cmd))
        return match.group(1) if match else None

    def capabilities(self):
        return {}

    def run(self, args, evidence=(), output_dir=None, tool_paths=(), cwd=None, timeout=None, text=True):
        cmd = self.detect()
        if not cmd:
            raise ToolNotAvailable(f'{self.label or self.name} is not available. {self.help}')
        return sandbox.run(list(cmd) + list(args), evidence=evidence, output_dir=output_dir,
                           tool_paths=tool_paths, cwd=cwd, timeout=timeout, text=text)

    def status(self):
        cmd = self.detect()
        return {
            'name': self.name,
            'label': self.label or self.name,
            'available': bool(cmd),
            'status': 'available' if cmd else 'not available',
            'command': cmd,
            'version': self.version() if cmd else None,
            'env': self.env or None,
            'capabilities': self.capabilities(),
            'fallback': self.fallback,
            'help': None if cmd else self.help,
        }
