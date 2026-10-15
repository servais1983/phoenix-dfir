"""Tests du module auth : tokens, refresh, revocation, password policy."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ.pop('REDIS_URL', None)

from auth import (
    create_token, decode_token, revoke_token,
    hash_password, verify_password, password_needs_rehash,
)
from middleware import validate_password


class TestPasswordHashing(unittest.TestCase):
    def test_hash_then_verify(self):
        h = hash_password('SuperSecret-Pa$$w0rd!')
        self.assertTrue(verify_password(h, 'SuperSecret-Pa$$w0rd!'))
        self.assertFalse(verify_password(h, 'wrong'))

    def test_new_hash_format(self):
        h = hash_password('SuperSecret-Pa$$w0rd!')
        self.assertTrue(h.startswith('pbkdf2_sha256$'))

    def test_legacy_format_still_verifies(self):
        # Format ancien : 32 octets de salt + 32 octets de cle, en hex
        import hashlib as hl
        salt = b'a' * 32
        key = hl.pbkdf2_hmac('sha256', b'legacy-pass', salt, 100000)
        legacy_hash = (salt + key).hex()
        self.assertTrue(verify_password(legacy_hash, 'legacy-pass'))
        self.assertFalse(verify_password(legacy_hash, 'wrong-pass'))

    def test_password_needs_rehash_legacy(self):
        legacy = 'a' * 128  # format ancien sans prefix
        self.assertTrue(password_needs_rehash(legacy))

    def test_password_needs_rehash_low_iter(self):
        old = 'pbkdf2_sha256$10000$aa$bb'
        self.assertTrue(password_needs_rehash(old))


class TestPasswordPolicy(unittest.TestCase):
    def test_too_short(self):
        ok, _ = validate_password('Short1!')
        self.assertFalse(ok)

    def test_in_denylist(self):
        ok, _ = validate_password('password123')
        self.assertFalse(ok)

    def test_only_one_class(self):
        ok, _ = validate_password('abcdefghijkl')
        self.assertFalse(ok)

    def test_only_two_classes(self):
        ok, _ = validate_password('Abcdefghijkl')
        self.assertFalse(ok)

    def test_three_classes_ok(self):
        ok, _ = validate_password('Abcdefghijk1')
        self.assertTrue(ok)

    def test_four_classes_ok(self):
        ok, _ = validate_password('Abcdef-ghi-1!')
        self.assertTrue(ok)

    def test_non_string_rejected(self):
        ok, _ = validate_password(None)
        self.assertFalse(ok)
        ok, _ = validate_password(12345678)
        self.assertFalse(ok)


class TestTokens(unittest.TestCase):
    def test_create_decode_access_token(self):
        t = create_token(1, 'alice', 'admin', token_type='access')
        payload = decode_token(t, expected_type='access')
        self.assertIsNotNone(payload)
        self.assertEqual(payload['username'], 'alice')
        self.assertEqual(payload['role'], 'admin')
        self.assertEqual(payload['type'], 'access')
        self.assertIn('jti', payload)

    def test_decode_with_wrong_type_returns_none(self):
        access = create_token(1, 'a', 'admin', token_type='access')
        # On le decode en pretendant que c'est un refresh
        self.assertIsNone(decode_token(access, expected_type='refresh'))

    def test_refresh_token_decode(self):
        r = create_token(1, 'alice', 'admin', token_type='refresh')
        payload = decode_token(r, expected_type='refresh')
        self.assertIsNotNone(payload)
        self.assertEqual(payload['type'], 'refresh')

    def test_tampered_signature_rejected(self):
        t = create_token(1, 'alice', 'admin')
        # Modifier le dernier caractere de la signature
        parts = t.split('.')
        parts[2] = parts[2][:-1] + ('A' if parts[2][-1] != 'A' else 'B')
        tampered = '.'.join(parts)
        self.assertIsNone(decode_token(tampered))

    def test_expired_token_rejected(self):
        t = create_token(1, 'alice', 'admin', token_type='access', expiry=-1)
        # Le token est deja expire
        self.assertIsNone(decode_token(t))

    def test_revoke_token_blocks_decode(self):
        t = create_token(1, 'alice', 'admin', token_type='access')
        payload = decode_token(t)
        self.assertIsNotNone(payload)
        # Revoquer
        revoke_token(payload)
        self.assertIsNone(decode_token(t))


if __name__ == '__main__':
    unittest.main(verbosity=2)
