"""Acceptance of the deterministic triage (no LLM) on three versioned cases.

    python eval/triage_acceptance.py [--suite eval/suite]

Criteria:
- net_c2_beacon_pcap: beaconing to 185.225.73.90 found, cited by row;
- ad_kerberoasting_dcsync: T1558.003 found, cited by record_id;
- benign_admin_activity: no finding of medium severity or above.

Exit code 0 when every criterion holds, 1 otherwise.
"""

import argparse
import sys
from pathlib import Path

from phoenix_dfir_mcp import triage


def _beacon(report):
    return any(f['entities'].get('dst') == '185.225.73.90' and 'T1071.001' in f['techniques']
               and f['refs'] and all('row' in r for r in f['refs']) for f in report['findings'])


def _kerberoast(report):
    return any('T1558.003' in f['techniques'] and f['refs'] and all('record_id' in r for r in f['refs'])
               for f in report['findings'])


def _benign(report):
    return not [f for f in report['findings'] if f['severity'] in ('critical', 'high', 'medium')]


CRITERIA = (
    ('net_c2_beacon_pcap', 'beaconing to 185.225.73.90 cited by row', _beacon),
    ('ad_kerberoasting_dcsync', 'T1558.003 cited by record_id', _kerberoast),
    ('benign_admin_activity', 'no finding >= medium', _benign),
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--suite', default=str(Path(__file__).resolve().parent / 'suite'))
    args = parser.parse_args(argv)
    failures = 0
    print('| Case | Criterion | Findings | Result |')
    print('|---|---|---|---|')
    for case, label, check in CRITERIA:
        report = triage.run_triage(Path(args.suite) / case)
        ok = check(report)
        failures += not ok
        counts = ', '.join(f'{n} {s}' for s, n in report['summary']['by_severity'].items() if n) or 'none'
        print(f"| {case} | {label} | {counts} | {'PASS' if ok else 'FAIL'} |")
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
