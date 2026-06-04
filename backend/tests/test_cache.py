"""Tests du cache abstraction layer (in-memory backend)."""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Garantir le mode in-memory pour les tests
os.environ.pop('REDIS_URL', None)

from cache import Cache, _InMemoryBackend


class TestInMemoryCache(unittest.TestCase):
    """Verifie le comportement du fallback in-memory."""

    def setUp(self):
        self.c = Cache()

    def test_backend_is_memory_when_no_redis(self):
        self.assertEqual(self.c.backend_name, 'memory')
        self.assertTrue(self.c.ping())

    def test_set_get_simple(self):
        self.c.set('k1', 'value1')
        self.assertEqual(self.c.get('k1'), 'value1')

    def test_set_get_json_compatible(self):
        self.c.set('k2', {'a': 1, 'b': [1, 2]})
        self.assertEqual(self.c.get('k2'), {'a': 1, 'b': [1, 2]})

    def test_get_missing_returns_none(self):
        self.assertIsNone(self.c.get('does-not-exist'))

    def test_delete(self):
        self.c.set('todel', 'x')
        self.c.delete('todel')
        self.assertIsNone(self.c.get('todel'))

    def test_exists(self):
        self.c.set('exists-key', 'v')
        self.assertTrue(self.c.exists('exists-key'))
        self.assertFalse(self.c.exists('missing-key'))

    def test_ttl_expiration(self):
        self.c.set('shortlived', 'v', ttl=1)
        self.assertEqual(self.c.get('shortlived'), 'v')
        time.sleep(1.1)
        self.assertIsNone(self.c.get('shortlived'))

    def test_incr_creates_then_increments(self):
        self.assertEqual(self.c.incr('counter'), 1)
        self.assertEqual(self.c.incr('counter'), 2)
        self.assertEqual(self.c.incr('counter'), 3)

    def test_incr_with_ttl(self):
        self.assertEqual(self.c.incr('cnt-ttl', ttl=1), 1)
        self.assertEqual(self.c.incr('cnt-ttl', ttl=1), 2)
        time.sleep(1.1)
        # Apres expiration, le compteur repart de 1
        self.assertEqual(self.c.incr('cnt-ttl', ttl=1), 1)

    def test_sliding_window_hit_counts(self):
        key = 'sw-test'
        for i in range(1, 6):
            self.assertEqual(self.c.sliding_window_hit(key, 60), i)

    def test_sliding_window_per_key(self):
        # Cles isolees
        self.assertEqual(self.c.sliding_window_hit('a-key', 60), 1)
        self.assertEqual(self.c.sliding_window_hit('b-key', 60), 1)
        self.assertEqual(self.c.sliding_window_hit('a-key', 60), 2)

    def test_in_memory_backend_thread_safety_minimal(self):
        """Verifier que le lock evite les corruptions sous concurrence."""
        from threading import Thread
        backend = _InMemoryBackend()
        results = []

        def worker():
            for _ in range(100):
                backend.incr('shared', ttl=60)
            results.append(True)

        threads = [Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 5 threads * 100 incr = 500
        self.assertEqual(backend._counters['shared'][0], 500)


if __name__ == '__main__':
    unittest.main(verbosity=2)
