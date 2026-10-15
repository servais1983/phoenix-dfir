"""Tests des nouveaux parsers v4.0 (Prefetch, LNK, browser history)."""

import os
import sqlite3
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from parsers import parse_prefetch, parse_lnk, parse_browser_history, analyze_file_standalone


class TestPrefetchParser(unittest.TestCase):
    def test_invalid_signature_returns_error(self):
        with tempfile.NamedTemporaryFile(suffix='.pf', delete=False) as f:
            f.write(b'XXXX' + b'\x00' * 1024)
            path = f.name
        try:
            result = parse_prefetch(path)
            self.assertIn('error', result)
        finally:
            os.unlink(path)

    def test_compressed_mam_detected(self):
        with tempfile.NamedTemporaryFile(suffix='.pf', delete=False) as f:
            f.write(b'MAM\x04' + b'\x00' * 200)
            path = f.name
        try:
            result = parse_prefetch(path)
            # Soit on a pyscca et ca marche, soit on signale la compression
            self.assertTrue(result.get('compressed') or 'pyscca' in result.get('error', '').lower())
        finally:
            os.unlink(path)

    def test_uncompressed_scca_header_parses(self):
        # Construire un header SCCA minimaliste version 23 (Win7)
        version = 23
        exec_name = 'NOTEPAD.EXE'.encode('utf-16le').ljust(60, b'\x00')
        prefetch_hash = 0xCAFEBABE
        run_count = 7

        header = bytearray(0x100)
        struct.pack_into('<I', header, 0, version)
        header[4:8] = b'SCCA'
        header[0x10:0x10 + 60] = exec_name
        struct.pack_into('<I', header, 0x4C, prefetch_hash)
        struct.pack_into('<I', header, 0x98, run_count)

        with tempfile.NamedTemporaryFile(suffix='.pf', delete=False) as f:
            f.write(bytes(header))
            path = f.name
        try:
            result = parse_prefetch(path)
            self.assertNotIn('error', result)
            self.assertEqual(result['executable'].rstrip('\x00'), 'NOTEPAD.EXE')
            self.assertEqual(result['run_count'], 7)
        finally:
            os.unlink(path)


class TestBrowserHistoryParser(unittest.TestCase):
    def _build_chromium_db(self, path):
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                visit_count INTEGER, last_visit_time INTEGER
            )
        """)
        cur.executemany(
            "INSERT INTO urls (url, title, visit_count, last_visit_time) VALUES (?,?,?,?)",
            [
                ('https://malware.evil.com/payload.exe', 'Malware', 1, 13350000000000000),
                ('https://google.com/search', 'Google', 25, 13350001000000000),
                ('http://10.20.30.40/internal', 'Internal', 3, 13350002000000000),
            ]
        )
        conn.commit()
        conn.close()

    def _build_firefox_db(self, path):
        conn = sqlite3.connect(path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                visit_count INTEGER, last_visit_date INTEGER
            )
        """)
        cur.execute(
            "INSERT INTO moz_places (url, title, visit_count, last_visit_date) VALUES (?,?,?,?)",
            ('https://bad.actor.org/c2', 'C2 panel', 1, 1700000000000000),
        )
        conn.commit()
        conn.close()

    def test_chromium_history_parses(self):
        with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
            path = f.name
        try:
            self._build_chromium_db(path)
            result = parse_browser_history(path)
            self.assertNotIn('error', result)
            self.assertEqual(result['browser'], 'chromium')
            self.assertEqual(result['total_visits'], 3)
            # IoCs extraits (URL + domaine)
            ioc_types = {i['type'] for i in result['iocs']}
            self.assertIn('domain', ioc_types)
        finally:
            os.unlink(path)

    def test_firefox_history_parses(self):
        with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
            path = f.name
        try:
            self._build_firefox_db(path)
            result = parse_browser_history(path)
            self.assertNotIn('error', result)
            self.assertEqual(result['browser'], 'firefox')
            self.assertEqual(result['total_visits'], 1)
        finally:
            os.unlink(path)

    def test_unknown_schema_returns_error(self):
        with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
            path = f.name
        try:
            conn = sqlite3.connect(path)
            conn.execute('CREATE TABLE foo (x INTEGER)')
            conn.commit()
            conn.close()
            result = parse_browser_history(path)
            self.assertIn('error', result)
        finally:
            os.unlink(path)


class TestLNKParser(unittest.TestCase):
    def _build_lnk(self, link_flags=0x0, target='C:\\Windows\\System32\\cmd.exe', arguments=''):
        """Construit un LNK minimaliste avec quelques champs StringData."""
        header = bytearray(0x4C)
        struct.pack_into('<I', header, 0, 0x4C)
        header[4:20] = b'\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46'
        # link_flags : 0x80 unicode + flags fournis
        full_flags = 0x80 | link_flags
        struct.pack_into('<I', header, 20, full_flags)

        body = bytearray(header)

        # On va ajouter LinkInfo si HasLinkInfo
        if link_flags & 0x2:
            # LinkInfo minimal qui pointe vers target en ANSI
            target_ansi = target.encode('latin-1') + b'\x00'
            local_base_offset = 0x20
            linkinfo = bytearray(local_base_offset + len(target_ansi))
            struct.pack_into('<I', linkinfo, 0x10, local_base_offset)
            linkinfo[local_base_offset:local_base_offset + len(target_ansi)] = target_ansi
            linkinfo_size = len(linkinfo)
            struct.pack_into('<I', linkinfo, 0, linkinfo_size)
            body += linkinfo

        # StringData : HasArguments (0x20) si arguments
        if link_flags & 0x20 and arguments:
            arg_utf16 = arguments.encode('utf-16le')
            count = len(arguments)
            body += struct.pack('<H', count) + arg_utf16

        return bytes(body)

    def test_invalid_clsid_rejected(self):
        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            # Header avec CLSID errone
            bad = bytearray(0x4C)
            struct.pack_into('<I', bad, 0, 0x4C)
            f.write(bytes(bad))
            path = f.name
        try:
            result = parse_lnk(path)
            self.assertIn('error', result)
        finally:
            os.unlink(path)

    def test_lnk_with_target_path(self):
        data = self._build_lnk(link_flags=0x2, target='C:\\Windows\\System32\\cmd.exe')
        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(data)
            path = f.name
        try:
            result = parse_lnk(path)
            self.assertNotIn('error', result)
            self.assertEqual(result['target_path'], 'C:\\Windows\\System32\\cmd.exe')
        finally:
            os.unlink(path)

    def test_lnk_high_severity_on_suspicious_arguments(self):
        # HasLinkInfo (0x2) + HasArguments (0x20)
        data = self._build_lnk(link_flags=0x22,
                               target='C:\\Windows\\System32\\powershell.exe',
                               arguments='-EncodedCommand AAAA')
        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(data)
            path = f.name
        try:
            result = parse_lnk(path)
            self.assertEqual(result['severity'], 'high')
        finally:
            os.unlink(path)

    def test_too_short_file_error(self):
        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(b'short')
            path = f.name
        try:
            result = parse_lnk(path)
            self.assertIn('error', result)
        finally:
            os.unlink(path)


class TestDispatcher(unittest.TestCase):
    def test_lnk_extension_routes_to_lnk_parser(self):
        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(b'short')
            path = f.name
        try:
            result = analyze_file_standalone(path)
            # On attend une erreur lnk specifique
            self.assertIn('error', result)
        finally:
            os.unlink(path)

    def test_pf_extension_routes_to_prefetch(self):
        with tempfile.NamedTemporaryFile(suffix='.pf', delete=False) as f:
            f.write(b'XXXX' + b'\x00' * 100)
            path = f.name
        try:
            result = analyze_file_standalone(path)
            self.assertIn('error', result)
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
