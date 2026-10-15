"""Tests pour le module observability (logging JSON + Prometheus)."""

import io
import json
import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from observability import JSONFormatter, PROMETHEUS_AVAILABLE


class TestJSONFormatter(unittest.TestCase):
    def setUp(self):
        self.formatter = JSONFormatter()

    def _make_record(self, level=logging.INFO, msg='test', **extra):
        record = logging.LogRecord(
            name='phoenix', level=level, pathname='x.py', lineno=10,
            msg=msg, args=(), exc_info=None,
        )
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    def test_basic_json_output(self):
        record = self._make_record(msg='hello')
        out = self.formatter.format(record)
        parsed = json.loads(out)
        self.assertEqual(parsed['msg'], 'hello')
        self.assertEqual(parsed['level'], 'INFO')
        self.assertEqual(parsed['logger'], 'phoenix')
        self.assertIn('ts', parsed)

    def test_extra_fields_serialized(self):
        record = self._make_record(msg='req', request_id='abc123', user='alice')
        parsed = json.loads(self.formatter.format(record))
        self.assertEqual(parsed['request_id'], 'abc123')
        self.assertEqual(parsed['user'], 'alice')

    def test_non_serializable_extra_falls_back_to_str(self):
        class Obj:
            def __str__(self):
                return 'obj-repr'

        record = self._make_record(msg='x', custom=Obj())
        parsed = json.loads(self.formatter.format(record))
        self.assertEqual(parsed['custom'], 'obj-repr')

    def test_exception_included(self):
        try:
            raise ValueError('boom')
        except ValueError:
            record = logging.LogRecord(
                name='phoenix', level=logging.ERROR, pathname='x.py', lineno=1,
                msg='err', args=(), exc_info=sys.exc_info(),
            )
        out = json.loads(self.formatter.format(record))
        self.assertIn('exc', out)
        self.assertIn('ValueError', out['exc'])


@unittest.skipUnless(PROMETHEUS_AVAILABLE, 'prometheus_client requis')
class TestPrometheusMetrics(unittest.TestCase):
    def test_counters_callable(self):
        from observability import http_requests_total, auth_failures_total
        # Doit pouvoir incrementer sans erreur
        http_requests_total.labels(method='GET', endpoint='/test', status='200').inc()
        auth_failures_total.labels(reason='invalid_password').inc()

    def test_metrics_registry_serializes(self):
        from prometheus_client import generate_latest
        from observability import metrics_registry, http_requests_total
        http_requests_total.labels(method='POST', endpoint='/x', status='201').inc()
        body = generate_latest(metrics_registry).decode()
        self.assertIn('phoenix_http_requests_total', body)


if __name__ == '__main__':
    unittest.main(verbosity=2)
