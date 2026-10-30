#!/usr/bin/env python3
"""Generate a large Windows Security export to measure the engines on volume.

Writes ``count`` events (default 100 000) as a JSON array: routine logons and
process creations, with a few planted detections at known positions:

    position 1000      security log cleared (1102)
    position count//2  encoded PowerShell command (4688)
    position count-10  security log cleared (1102)

Deterministic (fixed seed). Not part of the evaluation suite (size): the
volume test generates it in a temporary folder.

Usage:
    python eval/build_volume_events.py <output.json> [count]
"""

import datetime
import json
import random
import sys

T0 = datetime.datetime(2026, 10, 16, 0, 0, 0, tzinfo=datetime.timezone.utc)
FIRST_RECORD = 7_000_000


def planted(count):
    """{position: kind} of the planted detections."""
    return {1000: 'log_cleared', count // 2: 'encoded_powershell', count - 10: 'log_cleared'}


def events(count):
    rnd = random.Random(42)
    users = [f'user{n:03d}' for n in range(200)]
    marks = planted(count)
    for i in range(count):
        ts = (T0 + datetime.timedelta(milliseconds=i * 250)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        base = {'timestamp': ts, 'RecordID': FIRST_RECORD + i, 'Computer': 'SRV-VOL-01.corp.local',
                'Channel': 'Security'}
        kind = marks.get(i)
        if kind == 'log_cleared':
            yield {**base, 'EventID': 1102, 'message': 'The audit log was cleared', 'SubjectUserName': 'adm.x',
                   'Provider': 'Microsoft-Windows-Eventlog'}
        elif kind == 'encoded_powershell':
            yield {**base, 'EventID': 4688, 'SubjectUserName': 'user007',
                   'NewProcessName': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                   'CommandLine': 'powershell.exe -nop -w hidden -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'}
        elif rnd.random() < 0.7:
            yield {**base, 'EventID': 4624, 'TargetUserName': rnd.choice(users), 'LogonType': 3,
                   'IpAddress': f'10.10.{rnd.randrange(1, 20)}.{rnd.randrange(1, 250)}'}
        else:
            yield {**base, 'EventID': 4688, 'SubjectUserName': rnd.choice(users),
                   'NewProcessName': 'C:\\Windows\\System32\\svchost.exe', 'CommandLine': 'svchost.exe -k netsvcs'}


def write(path, count=100_000):
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('[\n')
        for i, event in enumerate(events(count)):
            f.write((',\n' if i else '') + json.dumps(event, ensure_ascii=False))
        f.write('\n]\n')
    return path


if __name__ == '__main__':
    out = sys.argv[1]
    total = int(sys.argv[2]) if len(sys.argv) > 2 else 100_000
    write(out, total)
    print(f'{total} events written to {out}')
