#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests du bac a sable des binaires forensiques externes (sandbox.py) :
reecriture des arguments et des chemins (docker / bwrap), fail closed,
streaming icat, exposition dans les *_status et integration bubblewrap reelle."""

import io
import os
import shutil
import subprocess  # nosec B404 - tests uniquement
import sys

import pytest


from phoenix_dfir_mcp import disk, hayabusa, sandbox, toolkit, volatility, zimmermann  # noqa: E402

# bwrap and docker confinement mount POSIX paths: Linux and macOS only (they
# fail closed on Windows, see test_isolated_modes_fail_closed_on_windows)
posix_sandbox = pytest.mark.skipif(os.name == 'nt', reason='bwrap/docker sandbox mounts are Linux and macOS only')


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for var in ('PHOENIX_TOOL_SANDBOX', 'PHOENIX_TOOL_SANDBOX_FALLBACK', 'PHOENIX_SANDBOX_IMAGE',
                'PHOENIX_SANDBOX_MEMORY', 'PHOENIX_SANDBOX_CPUS', 'PHOENIX_SANDBOX_PIDS',
                'PHOENIX_SANDBOX_USER', 'PHOENIX_SANDBOX_RO_PATHS'):
        monkeypatch.delenv(var, raising=False)
    sandbox.reset_cache()
    yield
    sandbox.reset_cache()


def _available(monkeypatch, ok=True, reason='absent'):
    monkeypatch.setattr(sandbox, 'probe', lambda mode=None: (True, None) if ok else (False, reason))


def _pairs(argv, flag):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == flag]


# ============================================================================
# Docker : arguments et reecriture des chemins
# ============================================================================

@posix_sandbox
def test_docker_options_de_confinement(monkeypatch):
    monkeypatch.setenv('PHOENIX_SANDBOX_IMAGE', 'forensics:1.2')
    monkeypatch.setenv('PHOENIX_SANDBOX_MEMORY', '2g')
    monkeypatch.setenv('PHOENIX_SANDBOX_CPUS', '1.5')
    monkeypatch.setenv('PHOENIX_SANDBOX_USER', '1000:1000')
    argv, _m = sandbox.wrap_docker(['/usr/bin/fls', '-r', '-o', '2048', '/cases/a/disk.dd'],
                                   evidence=['/cases/a/disk.dd'], name='phoenix-sbx-t')
    assert argv[:3] == ['docker', 'run', '--rm']
    joined = ' '.join(argv)
    for opt in ('--network none', '--read-only', '--cap-drop ALL',
                '--security-opt no-new-privileges', '--pids-limit 256', '--memory 2g',
                '--cpus 1.5', '--user 1000:1000', '--tmpfs /tmp:rw,noexec,nosuid,size=512m',
                '--name phoenix-sbx-t'):
        assert opt in joined, opt
    assert _pairs(argv, '-v') == ['/cases/a/disk.dd:/evidence/disk.dd:ro']
    i = argv.index('forensics:1.2')
    assert argv[i + 1:] == ['fls', '-r', '-o', '2048', '/evidence/disk.dd']


@posix_sandbox
def test_docker_sortie_et_outils_reecrits(monkeypatch, tmp_path):
    out = str(tmp_path / 'out')
    rules = '/opt/hayabusa/rules'
    argv, _m = sandbox.wrap_docker(
        ['/opt/hayabusa/hayabusa', 'json-timeline', '-f', '/cases/a/Security.evtx', '-o',
         os.path.join(out, 'timeline.jsonl'), '-r', rules],
        evidence=['/cases/a/Security.evtx'], output_dir=out, tool_paths=['/opt/hayabusa'],
        cwd='/opt/hayabusa')
    mounts = _pairs(argv, '-v')
    assert '/cases/a/Security.evtx:/evidence/Security.evtx:ro' in mounts
    assert f'{out}:/out:rw' in mounts
    assert '/opt/hayabusa:/tools/hayabusa:ro' in mounts
    assert all(m.endswith(':ro') for m in mounts if not m.startswith(out))
    assert _pairs(argv, '-w') == ['/tools/hayabusa']
    tail = argv[argv.index(sandbox.image()) + 1:]
    assert tail == ['/tools/hayabusa/hayabusa', 'json-timeline', '-f', '/evidence/Security.evtx',
                    '-o', '/out/timeline.jsonl', '-r', '/tools/hayabusa/rules']


@posix_sandbox
def test_docker_image_segmentee_et_collisions(monkeypatch):
    argv, m = sandbox.wrap_docker(
        ['python3.12', '-m', 'volatility3', '-f', '/c/a/mem.raw', '-f2', '/c/b/mem.raw',
         '/c/x/disk.E01'],
        evidence=['/c/a/mem.raw', '/c/b/mem.raw', '/c/x/disk.E01'])
    mounts = _pairs(argv, '-v')
    assert '/c/a/mem.raw:/evidence/mem.raw:ro' in mounts
    assert '/c/b/mem.raw:/evidence/mem.raw_2:ro' in mounts
    assert '/c/x:/evidence/x:ro' in mounts  # E01 : segments .E02... montes avec le parent
    tail = argv[argv.index(sandbox.image()) + 1:]
    assert tail == ['python3', '-m', 'volatility3', '-f', '/evidence/mem.raw', '-f2',
                    '/evidence/mem.raw_2', '/evidence/x/disk.E01']


def test_chemin_non_montable_refuse():
    with pytest.raises(sandbox.SandboxError):
        sandbox.wrap_docker(['fls', '/c/a:b.dd'], evidence=['/c/a:b.dd'])
    with pytest.raises(sandbox.SandboxError):
        sandbox.wrap_bwrap(['fls', '/c/a,b.dd'], evidence=['/c/a,b.dd'])


def test_argument_hors_montage_inchange():
    m = sandbox._mounts(['/cases/a/disk.dd'], None, ())
    assert m.rewrite('/etc/passwd') == '/etc/passwd'
    assert m.rewrite('/cases/a/disk.dd.bak') == '/cases/a/disk.dd.bak'
    assert m.rewrite('2048') == '2048'


# ============================================================================
# Bubblewrap : arguments et reecriture des chemins
# ============================================================================

@posix_sandbox
def test_bwrap_options_de_confinement(tmp_path):
    out = str(tmp_path / 'out')
    argv, _m = sandbox.wrap_bwrap(['/usr/bin/icat', '-o', '63', '/cases/a/disk.dd', '128'],
                                  evidence=['/cases/a/disk.dd'], output_dir=out,
                                  tool_paths=['/opt/ez'], bwrap='/usr/bin/bwrap')
    assert argv[0] == '/usr/bin/bwrap'
    for flag in ('--unshare-all', '--die-with-parent', '--new-session', '--clearenv'):
        assert flag in argv
    assert '--share-net' not in argv
    i = argv.index('--ro-bind', 0)
    assert argv[i:i + 3] == ['--ro-bind', '/usr', '/usr']
    for path in ('/lib', '/bin'):
        assert path in argv  # lien symbolique reproduit ou montage lecture seule
    triples = [tuple(argv[k:k + 3]) for k, a in enumerate(argv) if a in ('--ro-bind', '--bind')]
    assert ('--ro-bind', '/cases/a/disk.dd', '/evidence/disk.dd') in triples
    assert ('--bind', out, '/out') in triples
    assert ('--ro-bind', '/opt/ez', '/tools/ez') in triples
    assert [t for t in triples if t[0] == '--bind'] == [('--bind', out, '/out')]  # seul point d'ecriture
    sep = argv.index('--')
    assert argv[sep + 1:] == ['/usr/bin/icat', '-o', '63', '/evidence/disk.dd', '128']


@posix_sandbox
def test_bwrap_cwd_reecrit():
    argv, _m = sandbox.wrap_bwrap(['/opt/h/hayabusa', '-f', '/c/S.evtx'], evidence=['/c/S.evtx'],
                                  tool_paths=['/opt/h'], cwd='/opt/h')
    assert _pairs(argv, '--chdir') == ['/tools/h']
    assert argv[argv.index('--') + 1] == '/tools/h/hayabusa'


# ============================================================================
# Fail closed, repli explicite, statut
# ============================================================================

def test_mode_par_defaut_inchange(monkeypatch):
    calls = []
    monkeypatch.setattr(sandbox.subprocess, 'run', lambda cmd, **k: calls.append((cmd, k)) or
                        subprocess.CompletedProcess(cmd, 0, 'ok', ''))
    sandbox.run(['mmls', '/c/d.dd'], evidence=['/c/d.dd'], timeout=5)
    assert calls[0][0] == ['mmls', '/c/d.dd']
    assert sandbox.status() == {'mode': 'none', 'fallback': 'refuse', 'available': True,
                                'effective': 'none', 'isolated': False}


@pytest.mark.parametrize('mode', ['docker', 'bwrap'])
def test_fail_closed_si_indisponible(monkeypatch, mode):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', mode)
    _available(monkeypatch, ok=False, reason='binaire introuvable')
    monkeypatch.setattr(sandbox.subprocess, 'run', lambda *a, **k: pytest.fail('execute sans bac a sable'))
    monkeypatch.setattr(sandbox.subprocess, 'Popen', lambda *a, **k: pytest.fail('execute sans bac a sable'))
    with pytest.raises(sandbox.SandboxUnavailable) as exc:
        sandbox.run(['mmls', '/c/d.dd'], evidence=['/c/d.dd'])
    assert 'PHOENIX_TOOL_SANDBOX_FALLBACK=none' in str(exc.value)
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox.popen(['icat', '/c/d.dd', '5'], evidence=['/c/d.dd'], stdout=subprocess.PIPE)
    st = sandbox.status()
    assert st['mode'] == mode and st['available'] is False and st['effective'] is None
    assert sandbox.check()['error'].startswith(f"Bac a sable '{mode}' indisponible")


def test_mode_invalide_fail_closed(monkeypatch):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', 'chroot')
    with pytest.raises(sandbox.SandboxUnavailable):
        sandbox.effective_mode()


def test_repli_explicite(monkeypatch):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', 'bwrap')
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX_FALLBACK', 'none')
    _available(monkeypatch, ok=False)
    seen = []
    monkeypatch.setattr(sandbox.subprocess, 'run', lambda cmd, **k: seen.append(cmd) or
                        subprocess.CompletedProcess(cmd, 0, '', ''))
    sandbox.run(['mmls', '/c/d.dd'], evidence=['/c/d.dd'])
    assert seen == [['mmls', '/c/d.dd']]
    assert sandbox.status()['effective'] == 'none' and sandbox.check() is None


def test_outils_refuses_sans_bac_a_sable(monkeypatch, tmp_path):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', 'docker')
    _available(monkeypatch, ok=False, reason='image absente')
    monkeypatch.setattr(sandbox.subprocess, 'run', lambda *a, **k: pytest.fail('execute'))
    image = tmp_path / 'd.dd'
    image.write_bytes(b'\x00' * 512)
    dump = tmp_path / 'm.raw'
    dump.write_bytes(b'\x00')
    evtx = tmp_path / 'S.evtx'
    evtx.write_bytes(b'\x00')
    monkeypatch.setattr(disk, 'tsk_available', lambda: True)
    monkeypatch.setattr(volatility, '_find_command', lambda: ['vol'])
    monkeypatch.setattr(hayabusa, '_find_binary', lambda: '/usr/bin/true')
    monkeypatch.setattr(zimmermann, '_find_binary', lambda tool: (['/usr/bin/PECmd'], 'exe'))
    results = [disk.image_info(str(image)), volatility.run(str(dump), 'windows.pslist'),
               hayabusa.run(str(evtx)), zimmermann.run('PECmd', str(evtx))]
    for r in results:
        assert "Bac a sable 'docker' indisponible" in r['error'] and r['sandbox']['available'] is False


def test_statut_expose_dans_chaque_outil(monkeypatch):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', 'docker')
    monkeypatch.setenv('PHOENIX_SANDBOX_IMAGE', 'img:9')
    _available(monkeypatch, ok=True)
    for name in ('disk_status', 'volatility_status', 'hayabusa_status', 'zimmermann_status'):
        st = toolkit.run_tool(name, {})['sandbox']
        assert st['mode'] == 'docker' and st['isolated'] and st['image'] == 'img:9', name
        assert st['limits'] == {'memory': '4g', 'cpus': '2', 'pids': '256'}


def test_sonde_docker_sans_binaire(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, 'which', lambda name: None)
    assert sandbox._probe_docker() == (False, "binaire 'docker' introuvable")
    assert sandbox._probe_bwrap()[0] is False


# ============================================================================
# Execution isolee simulee (run / popen)
# ============================================================================

@posix_sandbox
def test_run_docker_commande_effective(monkeypatch):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', 'docker')
    _available(monkeypatch)
    seen = {}

    def fake_run(cmd, **kwargs):
        seen['cmd'], seen['kw'] = cmd, kwargs
        return subprocess.CompletedProcess(cmd, 0, 'out', '')
    monkeypatch.setattr(sandbox.subprocess, 'run', fake_run)
    proc = sandbox.run(['fsstat', '-o', '0', '/c/d.dd'], evidence=['/c/d.dd'], timeout=9)
    assert proc.stdout == 'out'
    assert seen['cmd'][1:3] == ['run', '--rm'] and seen['cmd'][-1] == '/evidence/d.dd'
    assert seen['kw']['timeout'] == 9


def test_run_docker_delai_abat_le_conteneur(monkeypatch):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', 'docker')
    _available(monkeypatch)
    killed = []

    def fake_run(cmd, **kwargs):
        if cmd[1] == 'kill':
            killed.append(cmd[2])
            return subprocess.CompletedProcess(cmd, 0, '', '')
        raise subprocess.TimeoutExpired(cmd, kwargs.get('timeout'))
    monkeypatch.setattr(sandbox.subprocess, 'run', fake_run)
    with pytest.raises(subprocess.TimeoutExpired):
        sandbox.run(['fls', '/c/d.dd'], evidence=['/c/d.dd'], timeout=1)
    assert killed and killed[0].startswith('phoenix-sbx-')


class _FakePopen:
    def __init__(self, cmd, **kwargs):
        self.cmd = cmd
        self.kwargs = kwargs
        self.stdout = io.BytesIO(b'B' * 5000)
        self.killed = False

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        return 0


@posix_sandbox
@pytest.mark.parametrize('mode', ['docker', 'bwrap'])
def test_streaming_icat_isole(monkeypatch, tmp_path, mode):
    import hashlib
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', mode)
    _available(monkeypatch)
    created = []
    monkeypatch.setattr(sandbox.subprocess, 'Popen',
                        lambda cmd, **k: created.append(_FakePopen(cmd, **k)) or created[-1])
    monkeypatch.setattr(sandbox, '_docker_kill', lambda name: created.append(('kill', name)))
    image = str(tmp_path / 'disk.dd')
    target = tmp_path / 'out.bin'
    status, size, digest = disk._icat_to_file(image, 63, '128', str(target), max_bytes=1 << 20)
    assert status == 'ok' and size == 5000 and target.read_bytes() == b'B' * 5000
    assert digest == hashlib.sha256(b'B' * 5000).hexdigest()
    cmd = created[0].cmd
    assert cmd[-4:] == ['-o', '63', '/evidence/disk.dd', '128']
    assert created[0].kwargs['stdout'] == subprocess.PIPE
    # Plafond depasse : kill() abat aussi le conteneur docker
    created.clear()
    status, _s, _d = disk._icat_to_file(image, 63, '128', str(target), max_bytes=1000)
    assert status.startswith('taille') and created[0].killed
    if mode == 'docker':
        assert created[1][0] == 'kill' and created[1][1].startswith('phoenix-sbx-')


def test_popen_mode_none_renvoie_popen_brut(monkeypatch):
    monkeypatch.setattr(sandbox.subprocess, 'Popen', lambda cmd, **k: _FakePopen(cmd, **k))
    proc = sandbox.popen(['icat', 'img', '5'], evidence=['img'], stdout=subprocess.PIPE)
    assert isinstance(proc, _FakePopen) and proc.cmd == ['icat', 'img', '5']


@posix_sandbox
def test_volatility_isole_reecrit_dump_et_symboles(monkeypatch, tmp_path):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', 'bwrap')
    monkeypatch.setenv('PHOENIX_VOLATILITY_SYMBOLS', '/opt/symbols')
    _available(monkeypatch)
    seen = {}
    monkeypatch.setattr(sandbox.subprocess, 'run', lambda cmd, **k: seen.setdefault('cmd', cmd) and
                        subprocess.CompletedProcess(cmd, 0, '[]', ''))
    monkeypatch.setattr(volatility, '_find_command', lambda: ['/usr/local/bin/vol'])
    dump = tmp_path / 'mem.raw'
    dump.write_bytes(b'\x00')
    r = volatility.run(str(dump), 'windows.pslist')
    assert r['sandbox'] == 'bwrap' and r['exit_code'] == 0
    tail = seen['cmd'][seen['cmd'].index('--') + 1:]
    assert tail == ['/usr/local/bin/vol', '-q', '-r', 'json', '-f', '/evidence/mem.raw', '-s',
                    '/tools/symbols', 'windows.pslist']


# ============================================================================
# Integration reelle bubblewrap (si installe et utilisable)
# ============================================================================

def _bwrap_usable():
    if not shutil.which('bwrap'):
        return False
    sandbox.reset_cache()
    os.environ['PHOENIX_TOOL_SANDBOX'] = 'bwrap'
    try:
        return sandbox.probe('bwrap')[0]
    finally:
        os.environ.pop('PHOENIX_TOOL_SANDBOX', None)
        sandbox.reset_cache()


needs_bwrap = pytest.mark.skipif(not _bwrap_usable(), reason='bubblewrap absent ou inutilisable')


@needs_bwrap
def test_bwrap_reel_sans_reseau_et_preuve_en_lecture_seule(monkeypatch, tmp_path):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', 'bwrap')
    evidence = tmp_path / 'case' / 'evidence.bin'
    evidence.parent.mkdir()
    evidence.write_bytes(b'PREUVE')
    out = tmp_path / 'out'
    out.mkdir()
    script = (
        "import socket, sys, os\n"
        "data = open(sys.argv[1], 'rb').read()\n"
        "try:\n"
        "    open(sys.argv[1], 'ab').write(b'X'); ro = 'writable'\n"
        "except OSError:\n"
        "    ro = 'readonly'\n"
        "try:\n"
        "    socket.create_connection(('1.1.1.1', 53), timeout=3); net = 'network'\n"
        "except OSError:\n"
        "    net = 'nonet'\n"
        "ifaces = sorted(os.listdir('/sys/class/net')) if os.path.isdir('/sys/class/net') else []\n"
        "open(os.path.join(sys.argv[2], 'r.txt'), 'w').write('ok')\n"
        "print(sys.argv[1], sys.argv[2], data.decode(), ro, net)\n")
    python = os.path.realpath(sys.executable)
    if not python.startswith('/usr/'):
        pytest.skip('interpreteur Python hors de /usr (non monte dans le bac a sable)')
    proc = sandbox.run([python, '-I', '-c', script, str(evidence), str(out)],
                       evidence=[str(evidence)], output_dir=str(out), timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.split() == ['/evidence/evidence.bin', '/out', 'PREUVE', 'readonly', 'nonet']
    assert evidence.read_bytes() == b'PREUVE'
    assert (out / 'r.txt').read_text() == 'ok'  # /out est le seul point d'ecriture


@needs_bwrap
def test_bwrap_reel_streaming_et_hote_invisible(monkeypatch, tmp_path):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', 'bwrap')
    secret = tmp_path / 'secret.txt'
    secret.write_text('confidentiel')
    evidence = tmp_path / 'img.dd'
    evidence.write_bytes(b'Z' * 300000)
    proc = sandbox.popen(['cat', str(evidence)], evidence=[str(evidence)],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    data = proc.stdout.read()
    proc.stdout.close()
    assert proc.wait(timeout=30) == 0 and data == b'Z' * 300000
    probe = sandbox.run(['cat', str(secret)], evidence=[str(evidence)], timeout=30)
    assert probe.returncode != 0 and 'confidentiel' not in probe.stdout


@pytest.mark.skipif(os.name != 'nt', reason='Windows only')
@pytest.mark.parametrize('mode', ['docker', 'bwrap'])
def test_isolated_modes_fail_closed_on_windows(monkeypatch, mode):
    monkeypatch.setenv('PHOENIX_TOOL_SANDBOX', mode)
    monkeypatch.delenv('PHOENIX_TOOL_SANDBOX_FALLBACK', raising=False)
    sandbox._probe_cache.clear()
    ok, reason = sandbox.probe(mode)
    assert not ok and 'not supported on Windows' in reason
    assert sandbox.check()['error']
