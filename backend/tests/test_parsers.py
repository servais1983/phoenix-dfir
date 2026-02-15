"""
Phoenix DFIR - Tests Parsers
Tests des parsers standalone (CSV, JSON, LOG)
"""

import os
import sys
import json
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from parsers import extract_iocs, parse_csv, parse_json, parse_log


class TestIoCExtraction(unittest.TestCase):
    """Tests extraction automatique d'IoCs"""

    def test_extract_ips(self):
        text = "Connexion depuis 185.220.101.42 et 8.8.8.8"
        iocs = extract_iocs(text)
        ips = [i['value'] for i in iocs if i['type'] == 'ip']
        self.assertIn('185.220.101.42', ips)
        self.assertIn('8.8.8.8', ips)

    def test_ignore_private_ips(self):
        text = "IP locale 192.168.1.1 et 10.0.0.1"
        iocs = extract_iocs(text)
        ips = [i['value'] for i in iocs if i['type'] == 'ip']
        self.assertEqual(len(ips), 0)

    def test_extract_domains(self):
        text = "Resolution DNS vers malware.evil.com et c2.attacker.net"
        iocs = extract_iocs(text)
        domains = [i['value'] for i in iocs if i['type'] == 'domain']
        self.assertIn('malware.evil.com', domains)
        self.assertIn('c2.attacker.net', domains)

    def test_extract_hashes(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        text = f"MD5: {md5}\nSHA256: {sha256}"
        iocs = extract_iocs(text)
        types = {i['type']: i['value'] for i in iocs}
        self.assertIn('hash_md5', types)
        self.assertIn('hash_sha256', types)

    def test_extract_emails(self):
        text = "Email de phishing: attacker@evil.com"
        iocs = extract_iocs(text)
        emails = [i['value'] for i in iocs if i['type'] == 'email']
        self.assertIn('attacker@evil.com', emails)

    def test_extract_urls(self):
        text = "Payload telecharge depuis https://malware.evil.com/payload.exe"
        iocs = extract_iocs(text)
        urls = [i['value'] for i in iocs if i['type'] == 'url']
        self.assertTrue(any('malware.evil.com' in u for u in urls))

    def test_extract_cves(self):
        text = "Exploitation de CVE-2024-12345 confirmee"
        iocs = extract_iocs(text)
        cves = [i['value'] for i in iocs if i['type'] == 'cve']
        self.assertIn('CVE-2024-12345', cves)


class TestCSVParser(unittest.TestCase):
    """Tests parser CSV"""

    def test_parse_basic_csv(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("timestamp,source_ip,event\n")
            f.write("2026-02-15 10:00:00,185.220.101.42,Brute force SSH\n")
            f.write("2026-02-15 10:01:00,8.8.8.8,DNS query\n")
            f.name
        try:
            result = parse_csv(f.name)
            self.assertNotIn('error', result)
            self.assertEqual(result['total_rows'], 2)
            self.assertGreater(len(result['iocs']), 0)
        finally:
            os.unlink(f.name)


class TestJSONParser(unittest.TestCase):
    """Tests parser JSON"""

    def test_parse_json_array(self):
        data = [
            {"timestamp": "2026-02-15T10:00:00Z", "event": "Login from 185.220.101.42", "severity": "high"},
            {"timestamp": "2026-02-15T10:01:00Z", "event": "File download", "severity": "info"}
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
        try:
            result = parse_json(f.name)
            self.assertNotIn('error', result)
            self.assertEqual(len(result['events']), 2)
        finally:
            os.unlink(f.name)


class TestLogParser(unittest.TestCase):
    """Tests parser LOG"""

    def test_parse_syslog(self):
        lines = [
            "Feb 15 10:00:00 server sshd[1234]: Failed password for admin from 185.220.101.42 port 22",
            "Feb 15 10:00:01 server sshd[1234]: Failed password for admin from 185.220.101.42 port 22",
            "Feb 15 10:00:02 server kernel: WARNING: possible break-in attempt",
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write('\n'.join(lines))
        try:
            result = parse_log(f.name)
            self.assertNotIn('error', result)
            self.assertGreaterEqual(result['total_lines'], 3)
            self.assertGreater(len(result['iocs']), 0)
            # Verifier detection severite
            self.assertTrue(any(e['severity'] in ('high', 'medium') for e in result['events']))
        finally:
            os.unlink(f.name)

    def test_severity_detection(self):
        lines = [
            "2026-02-15 10:00:00 CRITICAL: System compromised",
            "2026-02-15 10:00:01 ERROR: Authentication failed",
            "2026-02-15 10:00:02 WARNING: Suspicious activity",
            "2026-02-15 10:00:03 INFO: Normal operation",
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write('\n'.join(lines))
        try:
            result = parse_log(f.name)
            self.assertEqual(result['severity_counts'].get('critical', 0), 1)
            self.assertEqual(result['severity_counts'].get('high', 0), 1)
            self.assertEqual(result['severity_counts'].get('medium', 0), 1)
        finally:
            os.unlink(f.name)


if __name__ == '__main__':
    unittest.main(verbosity=2)
