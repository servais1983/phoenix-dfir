"""
Phoenix DFIR - Observability layer
- JSON structured logging avec request_id
- Prometheus metrics: counters, histograms (HTTP) + gauges custom
- Endpoint /metrics expose au format Prometheus
"""

import json
import logging
import os
import sys
import time
from typing import Optional

from flask import request, g, Response


# ============================================================================
# JSON STRUCTURED LOGGER
# ============================================================================

class JSONFormatter(logging.Formatter):
    """Formatteur JSON pour ingestion par Loki/ELK/Cloudwatch."""

    def format(self, record):
        payload = {
            'ts': time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(record.created)) + f'.{int(record.msecs):03d}Z',
            'level': record.levelname,
            'logger': record.name,
            'msg': record.getMessage(),
        }
        if record.exc_info:
            payload['exc'] = self.formatException(record.exc_info)
        # Champs additionnels passes via extra=
        for key, value in record.__dict__.items():
            if key in {
                'name', 'msg', 'args', 'levelname', 'levelno', 'pathname', 'filename',
                'module', 'exc_info', 'exc_text', 'stack_info', 'lineno', 'funcName',
                'created', 'msecs', 'relativeCreated', 'thread', 'threadName',
                'processName', 'process', 'message', 'taskName',
            }:
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = str(value)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(level: Optional[str] = None):
    """Configurer le logging racine en JSON sur stdout."""
    log_level = (level or os.environ.get('PHOENIX_LOG_LEVEL', 'INFO')).upper()
    root = logging.getLogger()
    root.setLevel(log_level)

    # Retirer les handlers existants (Flask en ajoute par defaut)
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)

    # Baisser le bruit des libs tres bavardes
    for noisy in ('urllib3', 'werkzeug', 'engineio.server', 'socketio.server'):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return logging.getLogger('phoenix')


logger = logging.getLogger('phoenix')


# ============================================================================
# PROMETHEUS METRICS
# ============================================================================

# Try to use prometheus_client, fallback to no-op if not installed
try:
    from prometheus_client import (
        Counter, Histogram, Gauge, CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest,
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


class _NoopMetric:
    def __init__(self, *a, **kw):
        pass

    def labels(self, *a, **kw):
        return self

    def inc(self, *a, **kw):
        return self

    def observe(self, *a, **kw):
        return self

    def set(self, *a, **kw):
        return self


if PROMETHEUS_AVAILABLE:
    metrics_registry = CollectorRegistry()

    http_requests_total = Counter(
        'phoenix_http_requests_total',
        'Total HTTP requests',
        ['method', 'endpoint', 'status'],
        registry=metrics_registry,
    )
    http_request_duration_seconds = Histogram(
        'phoenix_http_request_duration_seconds',
        'HTTP request duration in seconds',
        ['method', 'endpoint'],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        registry=metrics_registry,
    )
    auth_failures_total = Counter(
        'phoenix_auth_failures_total',
        'Total authentication failures',
        ['reason'],
        registry=metrics_registry,
    )
    rate_limit_blocks_total = Counter(
        'phoenix_rate_limit_blocks_total',
        'Total requests blocked by rate limit',
        ['scope'],
        registry=metrics_registry,
    )
    integration_calls_total = Counter(
        'phoenix_integration_calls_total',
        'Total calls to external integrations',
        ['connector', 'operation', 'status'],
        registry=metrics_registry,
    )
    integration_call_duration_seconds = Histogram(
        'phoenix_integration_call_duration_seconds',
        'Duration of external integration calls',
        ['connector', 'operation'],
        buckets=(0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
        registry=metrics_registry,
    )
    artifacts_analyzed_total = Counter(
        'phoenix_artifacts_analyzed_total',
        'Total artifacts analyzed',
        ['file_type', 'result'],
        registry=metrics_registry,
    )
    investigations_active = Gauge(
        'phoenix_investigations_active',
        'Number of currently active investigations',
        registry=metrics_registry,
    )
else:
    metrics_registry = None
    http_requests_total = _NoopMetric()
    http_request_duration_seconds = _NoopMetric()
    auth_failures_total = _NoopMetric()
    rate_limit_blocks_total = _NoopMetric()
    integration_calls_total = _NoopMetric()
    integration_call_duration_seconds = _NoopMetric()
    artifacts_analyzed_total = _NoopMetric()
    investigations_active = _NoopMetric()


def register_metrics_middleware(app):
    """Branche la collecte de metriques HTTP sur l'app Flask."""

    @app.before_request
    def _metrics_before():
        g._metrics_start = time.time()

    @app.after_request
    def _metrics_after(response):
        try:
            endpoint = request.endpoint or 'unknown'
            # Ne pas tracker le scrape lui-meme pour eviter le bruit
            if endpoint == 'metrics_endpoint':
                return response
            method = request.method
            status = str(response.status_code)
            http_requests_total.labels(method=method, endpoint=endpoint, status=status).inc()
            start = getattr(g, '_metrics_start', None)
            if start is not None:
                duration = time.time() - start
                http_request_duration_seconds.labels(method=method, endpoint=endpoint).observe(duration)
                # Log access en JSON
                logger.info(
                    'http_request',
                    extra={
                        'request_id': getattr(g, 'request_id', None),
                        'method': method,
                        'path': request.path,
                        'endpoint': endpoint,
                        'status': response.status_code,
                        'duration_ms': round(duration * 1000, 2),
                        'remote_addr': request.headers.get('X-Forwarded-For', request.remote_addr or ''),
                        'user': getattr(g, 'username', None),
                    },
                )
        except Exception:
            # L'observabilite ne doit JAMAIS casser une requete
            pass
        return response

    @app.route('/metrics', methods=['GET'])
    def metrics_endpoint():
        if not PROMETHEUS_AVAILABLE:
            return Response('# prometheus_client non installe\n', mimetype='text/plain'), 503
        data = generate_latest(metrics_registry)
        return Response(data, mimetype=CONTENT_TYPE_LATEST)
