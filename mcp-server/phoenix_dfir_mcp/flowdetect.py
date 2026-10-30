"""Beaconing on flow exports (firewall, proxy, NetFlow as CSV or JSON), no LLM.

Rows are grouped by (source, destination, port). A group is a beacon when it
has at least ``MIN_CONNECTIONS`` connections to an external address at a
regular interval (coefficient of variation of the intervals at most
``MAX_JITTER``) with near constant volumes (at most ``MAX_SIZE_CV``): the same
thresholds as the packet capture detection (``net_detect``). Each alert cites
the ``row`` of the first connection and lists the others.
"""

import datetime
import ipaddress
import statistics

MIN_CONNECTIONS = 6
MAX_JITTER = 0.2
MAX_SIZE_CV = 0.25
MIN_INTERVAL_S = 1.0
WEB_PORTS = {80, 443, 8080, 8443}

_SRC = ('src_ip', 'source_ip', 'src', 'srcaddr', 'client_ip', 'SourceIp')
_DST = ('dst_ip', 'destination_ip', 'dst', 'dstaddr', 'server_ip', 'DestinationIp')
_PORT = ('dst_port', 'destination_port', 'dport', 'dstport', 'DestinationPort')
_TIME = ('timestamp', 'time', 'ts', 'start', 'date')
_BYTES = ('bytes_out', 'sent_bytes', 'bytes_sent', 'bytes', 'out_bytes')
_HOST = ('src_host', 'source_host', 'hostname', 'host')


def _first(data, keys):
    for k in keys:
        v = data.get(k)
        if v not in (None, ''):
            return v
    return None


def _external(ip):
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_reserved or addr.is_unspecified)


def _epoch(value):
    try:
        return datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except ValueError:
        return None


def _number(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _cv(values):
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean else 0.0


def beacon_alerts(events):
    groups = {}
    for event in events:
        data = event.get('data') if isinstance(event.get('data'), dict) else {}
        src, dst, port = _first(data, _SRC), _first(data, _DST), _first(data, _PORT)
        ts = _epoch(_first(data, _TIME) or event.get('timestamp'))
        if not (src and dst and port and ts is not None and event.get('row') is not None) or not _external(dst):
            continue
        groups.setdefault((str(src), str(dst), str(port)), []).append(
            (ts, event['row'], _number(_first(data, _BYTES)), _first(data, _HOST), _first(data, _TIME)))
    alerts = []
    for (src, dst, port), rows in groups.items():
        if len(rows) < MIN_CONNECTIONS:
            continue
        rows.sort()
        starts = [r[0] for r in rows]
        intervals = [b - a for a, b in zip(starts, starts[1:])]
        mean = statistics.fmean(intervals)
        sizes = [r[2] for r in rows if r[2] is not None]
        jitter, size_cv = _cv(intervals), (_cv(sizes) if len(sizes) == len(rows) else None)
        if mean < MIN_INTERVAL_S or jitter > MAX_JITTER or size_cv is None or size_cv > MAX_SIZE_CV:
            continue
        port_n = int(_number(port) or 0)
        alerts.append({
            'type': 'beaconing', 'severity': 'high',
            'technique': 'T1071.001' if port_n in WEB_PORTS else 'T1071',
            'title': f'Beaconing vers {dst}:{port} toutes les {mean:.0f} s',
            'description': (f'{len(rows)} connexions de {src} vers {dst}:{port} toutes les {mean:.1f} s '
                            f'(gigue {jitter:.1%}), volume quasi constant (variation {size_cv:.1%}).'),
            'src': src, 'dst': dst, 'dst_port': port_n, 'host': rows[0][3], 'row': rows[0][1],
            'timestamp': rows[0][4], 'interval_s': round(mean, 2), 'jitter': round(jitter, 4),
            'size_cv': round(size_cv, 4), 'connections': len(rows), 'rows': [r[1] for r in rows][:50],
        })
    alerts.sort(key=lambda a: a['row'])
    return alerts
