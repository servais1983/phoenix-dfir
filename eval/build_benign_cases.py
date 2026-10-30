#!/usr/bin/env python3
"""Generate benign counter-example cases, one per deterministic detector.

Each case holds legitimate activity that looks like what a detector looks for,
so the evaluation measures its false positives:

    benign_ssh_typos              a few mistyped SSH passwords, then key based logins
    benign_backup_renames         a backup tool renaming files to .bak and .old
    benign_ntp_and_polling        NTP every 64 s, a jittered HTTPS presence poller
    benign_kerberos_truncated     a Security log that starts after the TGT requests
    benign_admin_powershell       an administrator downloading a package with Invoke-WebRequest
    benign_admin_history          an administrator archiving logs to the internal NAS and cleaning up

No external dependency. Usage:
    python eval/build_benign_cases.py [suite_folder]
"""

import csv
import datetime
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SUITE = os.path.join(HERE, 'suite')
T0 = datetime.datetime(2026, 10, 14, 7, 0, 0, tzinfo=datetime.timezone.utc)


def _iso(seconds):
    return (T0 + datetime.timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


def _syslog(seconds):
    return (T0 + datetime.timedelta(seconds=seconds)).strftime('%b %d %H:%M:%S')


def _truth(case_dir, truth):
    base = {'techniques': [], 'iocs': [], 'expect_injection': False, 'benign': True}
    base.update(truth)
    with open(os.path.join(case_dir, 'ground_truth.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump(base, f, indent=2, ensure_ascii=False)
        f.write('\n')


def _write_csv(path, header, rows):
    with open(path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(header)
        writer.writerows(rows)


def build_ssh_typos(case_dir):
    lines = []
    pid = 7100
    for k, (user, src) in enumerate((('deploy', '10.10.1.20'), ('j.martin', '10.10.5.23'), ('j.martin', '10.10.5.23'))):
        pid += 1
        lines.append(f'{_syslog(k * 30)} web-prod-03 sshd[{pid}]: Failed password for {user} from {src} '
                     f'port {50100 + k} ssh2')
    pid += 1
    lines.append(f'{_syslog(95)} web-prod-03 sshd[{pid}]: Accepted password for j.martin from 10.10.5.23 '
                 'port 50110 ssh2')
    for k in range(6):
        pid += 1
        lines.append(f'{_syslog(600 + k * 900)} web-prod-03 sshd[{pid}]: Accepted publickey for deploy from '
                     f'10.10.1.20 port {51000 + k} ssh2: ED25519 SHA256:q2vR8e5u1Nn0WbW8T2c3m4Fj9Lw0pZ7QxY6kA1sD3fG')
        lines.append(f'{_syslog(601 + k * 900)} web-prod-03 sudo: deploy : TTY=pts/1 ; PWD=/srv/app ; '
                     'USER=root ; COMMAND=/usr/bin/systemctl reload nginx')
    with open(os.path.join(case_dir, 'auth.log'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')


def build_backup_renames(case_dir):
    rows = []
    for k in range(40):
        folder = ('Compta', 'RH', 'Projets', 'Direction')[k % 4]
        src = f'D:\\Partages\\{folder}\\rapport_{k:03d}.xlsx'
        ext = '.bak' if k % 2 == 0 else '.old'
        rows.append([_iso(k * 2), 'SRV-FICHIERS-02', 'svc_sauvegarde', 'C:\\Program Files\\Veeam\\VeeamAgent.exe',
                     'rename', src, src + ext])
    for k in range(20):  # Office saves through a temporary file: the target is not source + extension
        doc = f'D:\\Partages\\Compta\\budget_{k:02d}.docx'
        rows.append([_iso(200 + k * 30), 'SRV-FICHIERS-02', 'c.petit', 'C:\\Program Files\\Microsoft Office\\'
                     'root\\Office16\\WINWORD.EXE', 'rename', f'D:\\Partages\\Compta\\~WRD{k:04d}.tmp', doc])
    _write_csv(os.path.join(case_dir, 'file_activity.csv'),
               ['timestamp', 'host', 'user', 'process', 'operation', 'source_path', 'target_path'], rows)


def build_ntp_and_polling(case_dir):
    rnd = random.Random(11)
    rows = []
    for k in range(30):  # NTP: perfectly regular, constant size, UDP 123
        rows.append([_iso(k * 64), '10.10.8.40', 'PC-RH-02', '51.145.123.29', '123', 'udp', '76', '76', 'allow'])
    t = 0
    for _k in range(30):  # presence poller: HTTPS, interval 20 to 40 s, sizes vary
        t += rnd.randint(20, 40)
        rows.append([_iso(t), '10.10.8.40', 'PC-RH-02', '52.113.194.132', '443', 'tcp', str(rnd.randint(700, 2600)),
                     str(rnd.randint(1500, 9000)), 'allow'])
    rows.sort(key=lambda r: r[0])
    _write_csv(os.path.join(case_dir, 'firewall_export.csv'),
               ['timestamp', 'src_ip', 'src_host', 'dst_ip', 'dst_port', 'protocol', 'bytes_out', 'bytes_in',
                'action'], rows)


def build_kerberos_truncated(case_dir):
    """The log starts at 07:00; svc_report got its TGT at 06:40 (not in the log)."""
    events, record = [], 552900

    def add(seconds, event_id, message, **fields):
        nonlocal record
        record += 1
        item = {'timestamp': _iso(seconds), 'EventID': event_id, 'RecordID': record,
                'Computer': 'DC02.corp.local', 'Channel': 'Security', 'message': message}
        item.update(fields)
        events.append(item)

    for k in range(3):  # service tickets of an account whose TGT predates the log
        add(5 + k * 600, 4769, 'Service ticket requested by svc_report', TargetUserName='svc_report@CORP.LOCAL',
            ServiceName='SQL02$', IpAddress='::ffff:10.10.6.12', TicketEncryptionType='0x12',
            TicketOptions='0x40810000', Status='0x0')
    for k, user in enumerate(('a.bernard', 'c.petit', 'l.moreau')):
        add(300 + k * 120, 4768, f'TGT requested for {user}', TargetUserName=user, TargetDomainName='CORP',
            IpAddress=f'::ffff:10.10.5.{60 + k}', TicketEncryptionType='0x12', Status='0x0')
        add(302 + k * 120, 4769, f'Service ticket requested by {user}', TargetUserName=f'{user}@CORP.LOCAL',
            ServiceName='FS02$', IpAddress=f'::ffff:10.10.5.{60 + k}', TicketEncryptionType='0x12',
            TicketOptions='0x40810000', Status='0x0')
    with open(os.path.join(case_dir, 'dc02_security.json'), 'w', encoding='utf-8', newline='\n') as f:
        json.dump(events, f, indent=1, ensure_ascii=False)
        f.write('\n')


def build_admin_powershell(case_dir):
    lines = [
        f'{_iso(0)} SRV-APP-04 Microsoft-Windows-PowerShell/Operational EventID=4104 User=CORP\\adm.durand '
        "ScriptBlockText=Invoke-WebRequest -Uri https://repo.corp.local/packages/agent-7.4.1.msi "
        "-OutFile C:\\Temp\\agent-7.4.1.msi",
        f'{_iso(40)} SRV-APP-04 Security EventID=4688 User=CORP\\adm.durand '
        'NewProcessName=C:\\Windows\\System32\\msiexec.exe CommandLine=msiexec.exe /i C:\\Temp\\agent-7.4.1.msi /qn',
        f'{_iso(95)} SRV-APP-04 System EventID=7036 ServiceName=CorpAgent State=running',
        f'{_iso(120)} SRV-APP-04 Microsoft-Windows-PowerShell/Operational EventID=4104 User=CORP\\adm.durand '
        'ScriptBlockText=Get-Service CorpAgent | Select-Object Status, StartType',
    ]
    with open(os.path.join(case_dir, 'srv-app-04_events.log'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')


def build_admin_history(case_dir):
    """An administrator archives logs, copies the archive to the internal backup share, cleans up."""
    lines = [
        'Get-ChildItem D:\\Logs\\IIS -Filter *.log',
        'Compress-Archive -Path D:\\Logs\\IIS -DestinationPath D:\\Backup\\iis_2026-10.zip',
        'Copy-Item D:\\Backup\\iis_2026-10.zip \\\\nas01.corp.local\\archives\\',
        'Invoke-WebRequest -Uri https://repo.corp.local/tools/logrotate.ps1 -OutFile C:\\Temp\\logrotate.ps1',
        'Remove-Item D:\\Logs\\IIS\\u_ex2609*.log',
        'Remove-Item C:\\Temp\\logrotate.ps1',
    ]
    # PSReadLine history exported from C:\\Users\\adm.durand\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine
    with open(os.path.join(case_dir, 'ConsoleHost_history.txt'), 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')


CASES = {
    'benign_ssh_typos': (build_ssh_typos, {
        'description': ('Three mistyped SSH passwords from internal workstations, then password and key based '
                        'logins of the same accounts and sudo service reloads. No incident.'),
        'forbidden_techniques': ['T1110', 'T1078']}),
    'benign_backup_renames': (build_backup_renames, {
        'description': ('A backup agent renames 40 files to .bak and .old, and Word saves documents through '
                        'temporary files. No encryption.'),
        'forbidden_techniques': ['T1486', 'T1070.006']}),
    'benign_ntp_and_polling': (build_ntp_and_polling, {
        'description': ('A workstation synchronises its clock over NTP every 64 s and a collaboration client '
                        'polls its presence service over HTTPS every 20 to 40 s. No beacon.'),
        'forbidden_techniques': ['T1071', 'T1571']}),
    'benign_kerberos_truncated': (build_kerberos_truncated, {
        'description': ('A domain controller Security log that starts after the TGT request of a reporting '
                        'service account: its service tickets have no TGT in the log. No forged ticket.'),
        'forbidden_techniques': ['T1558.001', 'T1558.003']}),
    'benign_admin_history': (build_admin_history, {
        'description': ('An administrator archives IIS logs, copies the archive to the internal NAS, downloads '
                        'a script from the internal repository and removes old logs. No exfiltration.'),
        'forbidden_techniques': ['T1560', 'T1048', 'T1070.004']}),
    'benign_admin_powershell': (build_admin_powershell, {
        'description': ('An administrator downloads an agent package from the internal repository with '
                        'Invoke-WebRequest and installs it with msiexec. No incident.'),
        'forbidden_techniques': ['T1105', 'T1059.001', 'T1543.003']}),
}


def build_all(suite=SUITE):
    for name, (builder, truth) in CASES.items():
        path = os.path.join(suite, name)
        os.makedirs(path, exist_ok=True)
        builder(path)
        _truth(path, truth)
    return sorted(CASES)


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else SUITE
    for name in build_all(target):
        print(name)
    print(f'Cases written in {target}')
