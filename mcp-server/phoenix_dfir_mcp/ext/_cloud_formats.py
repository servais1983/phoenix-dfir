"""Journaux cloud, identite et Kubernetes : detection du format et normalisation.

Formats reconnus d'apres le CONTENU (l'extension ne suffit pas : un export
CloudTrail est un .json, un journal d'audit Kubernetes un .log ou un .json
en JSON lines, un export Purview un .csv) :

    m365_ual        Microsoft 365 Unified Audit Log (CSV Purview avec colonne
                    AuditData, JSON / JSON lines)
    entra_signin    Entra ID, journaux de connexion (JSON du portail, Graph
                    {"value": [...]}, export Log Analytics, CSV du portail)
    entra_audit     Entra ID, journaux d'audit (JSON / CSV)
    aws_cloudtrail  AWS CloudTrail ({"Records": [...]}, .json.gz, JSON lines,
                    CSV de l'historique des evenements)
    gcp_audit       GCP Cloud Audit Logs (JSON lines ou tableau)
    k8s_audit       Kubernetes audit log (JSON lines)
    linux_auditd    Linux auditd (audit.log texte)

Chaque enregistrement devient un evenement normalise (horodatage UTC,
principal, IP source, user agent, operation, resultat, ressource cible,
compte / tenant / projet) portant une reference de preuve citable :
- 'line' : numero de ligne physique (JSON lines, audit.log) ;
- 'row'  : rang de l'enregistrement (ligne de donnees d'un CSV, comme
           parse_csv, ou position dans le tableau Records[] / value[] d'un
           document JSON, a partir de 1).
Les cles internes prefixees par '_' servent aux detections et ne sont
jamais renvoyees ni indexees.
"""

import csv
import datetime
import gzip
import io
import ipaddress
import json
import os
import re
from collections import Counter

from .. import toolkit
from ..evidence_db import normalize_ts

FORMATS = {
    'm365_ual': 'Microsoft 365 Unified Audit Log',
    'entra_signin': 'Entra ID - journaux de connexion',
    'entra_audit': "Entra ID - journaux d'audit",
    'aws_cloudtrail': 'AWS CloudTrail',
    'gcp_audit': 'GCP Cloud Audit Logs',
    'k8s_audit': 'Kubernetes audit log',
    'linux_auditd': 'Linux auditd (audit.log)',
}
CLOUD_FORMATS = tuple(k for k in FORMATS if k != 'linux_auditd')

DEFAULT_MAX_EVENTS = 50000
_SNIFF_BYTES = 256 * 1024
_SKIP_EXT = {'.evtx', '.pf', '.lnk', '.sqlite', '.db', '.raw', '.mem', '.vmem', '.dmp', '.lime',
             '.e01', '.ex01', '.dd', '.img', '.001', '.vmdk', '.vhd', '.vhdx', '.hve', '.dat',
             '.mft', '.pcap', '.pcapng', '.zip', '.7z', '.exe', '.dll', '.png', '.jpg', '.pdf'}

AUDITD_RE = re.compile(r'(?:^|\s)(?:node=\S+\s+)?type=[A-Z0-9_]+\s+msg=audit\(')


# ============================================================================
# Utilitaires
# ============================================================================

_ALT_TS_FORMATS = ('%m/%d/%Y %I:%M:%S %p', '%m/%d/%Y, %I:%M:%S %p', '%m/%d/%Y %H:%M:%S',
                   '%m/%d/%Y %H:%M', '%d/%m/%Y %H:%M:%S', '%Y/%m/%d %H:%M:%S')


def to_utc(value):
    """Horodatage quelconque -> 'YYYY-MM-DDTHH:MM:SSZ' (UTC) ou None."""
    if value in (None, ''):
        return None
    ts = normalize_ts(value)
    if ts:
        return ts
    text = str(value).strip()
    for fmt in _ALT_TS_FORMATS:
        try:
            return datetime.datetime.strptime(text, fmt).strftime('%Y-%m-%dT%H:%M:%SZ')
        except ValueError:
            continue
    return None


def parse_ts(ts):
    """'YYYY-MM-DDTHH:MM:SSZ' -> datetime naif (UTC), ou None."""
    try:
        return datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%SZ')
    except (TypeError, ValueError):
        return None


def clean_ip(value):
    """IP sans port ni crochets ('1.2.3.4:443' -> '1.2.3.4', '[::1]:80' -> '::1')."""
    text = str(value or '').strip()
    m = re.match(r'^\[([0-9a-fA-F:.]+)\](?::\d+)?$', text)
    if m:
        return m.group(1)
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$', text)
    return m.group(1) if m else text


def is_public_ip(value):
    try:
        return ipaddress.ip_address(clean_ip(value)).is_global
    except ValueError:
        return False


def as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def dig(obj, path, default=None):
    """Acces imbrique tolerant : dig(d, 'a.b.c')."""
    cur = obj
    for part in path.split('.'):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
    return default if cur is None else cur


def email_domain(value):
    text = str(value or '').strip().lower()
    if text.startswith('smtp:'):
        text = text[5:]
    return text.rsplit('@', 1)[1] if '@' in text else ''


def _lower_keys(row):
    return {str(k).strip().lower(): v for k, v in row.items() if k is not None}


def _maybe_json(value):
    if isinstance(value, str) and value.strip()[:1] in ('{', '['):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


# ============================================================================
# Detection du format
# ============================================================================

def _read_head(path, limit=_SNIFF_BYTES):
    """(octets, complet, gzip) : debut du fichier, decompresse s'il est gzip."""
    with open(path, 'rb') as f:
        magic = f.read(2)
        f.seek(0)
        if magic == b'\x1f\x8b':
            with gzip.GzipFile(fileobj=f) as gz:
                data = gz.read(limit + 1)
            compressed = True
        else:
            data = f.read(limit + 1)
            compressed = False
    return data[:limit], len(data) <= limit, compressed


def _unwrap(rec):
    """Export Azure Monitor / Log Analytics : {'category': ..., 'properties': {...}}."""
    if isinstance(rec, dict) and isinstance(rec.get('properties'), dict) and rec.get('category'):
        inner = dict(rec['properties'])
        inner.setdefault('_category', rec.get('category'))
        if rec.get('time') and not inner.get('createdDateTime') and not inner.get('activityDateTime'):
            key = 'activityDateTime' if 'audit' in str(rec.get('category')).lower() else 'createdDateTime'
            inner[key] = rec['time']
        return inner
    return rec


def classify_record(rec):
    """Format d'un enregistrement JSON, ou None."""
    if not isinstance(rec, dict):
        return None
    category = str(rec.get('category') or '').lower()
    if isinstance(rec.get('properties'), dict) and category:
        if 'signin' in category:
            return 'entra_signin'
        if category == 'auditlogs':
            return 'entra_audit'
    if 'eventSource' in rec and 'eventName' in rec and ('eventTime' in rec or 'userIdentity' in rec):
        return 'aws_cloudtrail'
    if isinstance(rec.get('protoPayload'), dict) or 'cloudaudit.googleapis.com' in str(rec.get('logName', '')):
        return 'gcp_audit'
    if str(rec.get('apiVersion', '')).startswith('audit.k8s.io') or (
            rec.get('kind') == 'Event' and 'verb' in rec and ('objectRef' in rec or 'requestURI' in rec)):
        return 'k8s_audit'
    if 'activityDisplayName' in rec or ('activityDateTime' in rec and 'initiatedBy' in rec):
        return 'entra_audit'
    if 'createdDateTime' in rec and ('userPrincipalName' in rec or 'ipAddress' in rec) and (
            'status' in rec or 'appDisplayName' in rec or 'clientAppUsed' in rec):
        return 'entra_signin'
    if 'AuditData' in rec:
        return 'm365_ual'
    if 'Operation' in rec and ('Workload' in rec or 'RecordType' in rec) and 'CreationTime' in rec:
        return 'm365_ual'
    return None


def _records_of(doc):
    """Enregistrements d'un document JSON complet."""
    if isinstance(doc, dict):
        for key in ('Records', 'value', 'records', 'items', 'entries'):
            if isinstance(doc.get(key), list):
                return doc[key]
        return [doc]
    return doc if isinstance(doc, list) else []


_JSON_HINTS = (
    ('aws_cloudtrail', (r'"eventSource"\s*:', r'"eventName"\s*:')),
    ('gcp_audit', (r'"protoPayload"\s*:',)),
    ('k8s_audit', (r'"apiVersion"\s*:\s*"audit\.k8s\.io',)),
    ('entra_audit', (r'"activityDisplayName"\s*:',)),
    ('entra_signin', (r'"createdDateTime"\s*:', r'"userPrincipalName"\s*:')),
    ('m365_ual', (r'"Operation"\s*:', r'"Workload"\s*:')),
    ('m365_ual', (r'"AuditData"\s*:',)),
)


def classify_header(columns):
    """Format d'un CSV d'apres ses en-tetes, ou None."""
    low = {str(c).strip().lower() for c in columns if c is not None}
    if 'auditdata' in low:
        return 'm365_ual'
    if 'cloudtrail event' in low or {'event name', 'event source'} <= low:
        return 'aws_cloudtrail'
    if ('activity' in low or 'activitydisplayname' in low) and (
            {'category', 'service', 'loggedbyservice'} & low):
        return 'entra_audit'
    if ({'date (utc)', 'createddatetime', 'date'} & low) and ({'ip address', 'ipaddress'} & low) and (
            {'sign-in error code', 'status', 'request id', 'client app', 'errorcode',
             'status.errorcode', 'clientappused'} & low):
        return 'entra_signin'
    return None


def _delimiter(header_line):
    """Separateur d'un CSV d'apres sa ligne d'en-tetes (virgule par defaut)."""
    counts = {d: header_line.count(d) for d in (',', ';', '\t')}
    best = max(counts, key=counts.get)
    return best if counts[best] else ','


def _majority(formats):
    found = Counter(f for f in formats if f)
    return found.most_common(1)[0][0] if found else None


def _detect_bytes(data, complete):
    """(format, conteneur, raison) depuis le debut d'un fichier."""
    if b'\x00' in data[:4096]:
        return None, None, 'binaire'
    text = data.decode('utf-8', errors='replace').lstrip('﻿')
    stripped = text.lstrip()
    if not stripped:
        return None, None, 'vide'
    lines = [ln for ln in stripped.splitlines()[:50] if ln.strip()]
    if lines and sum(1 for ln in lines if AUDITD_RE.search(ln)) * 2 >= len(lines):
        return 'linux_auditd', 'text', 'lignes type=... msg=audit(...)'
    if stripped[0] in '[{':
        if complete:
            try:
                doc = json.loads(stripped)
            except ValueError:
                doc = None
            if doc is not None:
                records = _records_of(doc)
                fmt = _majority(classify_record(r) for r in records[:50])
                if records == [doc] and len(lines) == 1:
                    return fmt, 'jsonl', 'JSON lines (un enregistrement)'
                return fmt, 'json', 'document JSON'
        sample = []
        for ln in lines[:20]:
            try:
                sample.append(json.loads(ln))
            except ValueError:
                break
        if sample and all(isinstance(s, dict) for s in sample) and (len(sample) > 1 or len(lines) == 1):
            fmt = _majority(classify_record(s) for s in sample)
            if fmt:
                return fmt, 'jsonl', 'JSON lines'
        head = stripped[:_SNIFF_BYTES]
        for fmt, patterns in _JSON_HINTS:
            if all(re.search(p, head) for p in patterns):
                return fmt, 'json', 'document JSON volumineux (cles caracteristiques)'
        return None, None, 'JSON non reconnu'
    first = stripped.splitlines()[0]
    if ',' in first or ';' in first or '\t' in first:
        header = next(csv.reader([first], delimiter=_delimiter(first)))
        fmt = classify_header(header)
        if fmt:
            return fmt, 'csv', 'en-tetes CSV'
    return None, None, 'format non reconnu'


_CACHE = {}


def detect(path):
    """Detecter le format d'un journal : {'format', 'label', 'container', 'compressed', 'reason'}.
    'format' vaut None si le fichier n'est pas un journal reconnu."""
    out = {'file': path, 'format': None, 'label': None, 'container': None, 'compressed': False}
    ext = os.path.splitext(path)[1].lower()
    if ext in _SKIP_EXT or not os.path.isfile(path):
        out['reason'] = 'type de fichier non concerne' if ext in _SKIP_EXT else 'fichier introuvable'
        return out
    try:
        st = os.stat(path)
        key = (os.path.realpath(path), st.st_size, st.st_mtime_ns)
    except OSError as e:
        out['reason'] = str(e)
        return out
    if key in _CACHE:
        return dict(_CACHE[key])
    try:
        data, complete, compressed = _read_head(path)
        fmt, container, reason = _detect_bytes(data, complete)
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        fmt, container, reason, compressed = None, None, f'lecture impossible : {e}', False
    out.update(format=fmt, label=FORMATS.get(fmt), container=container, compressed=compressed,
               reason=reason)
    if len(_CACHE) > 2048:
        _CACHE.clear()
    _CACHE[key] = dict(out)
    return out


# ============================================================================
# Lecture des enregistrements
# ============================================================================

def _open_text(path):
    with open(path, 'rb') as f:
        magic = f.read(2)
    if magic == b'\x1f\x8b':
        return io.TextIOWrapper(gzip.open(path, 'rb'), encoding='utf-8-sig', errors='replace')
    return open(path, 'r', encoding='utf-8-sig', errors='replace', newline='')


def _load_json_doc(path):
    limit = toolkit._max_json_bytes()
    with _open_text(path) as f:
        text = f.read(limit + 1)
    if len(text) > limit:
        raise ValueError(f'document JSON trop volumineux (> {limit} octets) : '
                         'le convertir en JSON lines pour une lecture en flux')
    return json.loads(text)


def iter_records(path, det, max_events=DEFAULT_MAX_EVENTS, stats=None):
    """(type_ref, numero, enregistrement brut, format) pour chaque enregistrement."""
    stats = stats if stats is not None else {}
    stats.setdefault('skipped', 0)
    container, fmt = det['container'], det['format']
    count = 0
    if container == 'json':
        for i, rec in enumerate(_records_of(_load_json_doc(path)), 1):
            if count >= max_events:
                stats['truncated'] = True
                return
            rec_fmt = classify_record(rec) or fmt
            if isinstance(rec, dict):
                count += 1
                yield 'row', i, _unwrap(rec), rec_fmt
            else:
                stats['skipped'] += 1
    elif container == 'jsonl':
        with _open_text(path) as f:
            for i, line in enumerate(f, 1):
                if not line.strip():
                    continue
                if count >= max_events:
                    stats['truncated'] = True
                    return
                try:
                    rec = json.loads(line)
                except ValueError:
                    stats['skipped'] += 1
                    continue
                if not isinstance(rec, dict):
                    stats['skipped'] += 1
                    continue
                count += 1
                yield 'line', i, _unwrap(rec), classify_record(rec) or fmt
    elif container == 'csv':
        with _open_text(path) as f:
            first = f.readline()
            f.seek(0)
            reader = csv.DictReader(f, delimiter=_delimiter(first))
            for i, row in enumerate(reader, 1):
                if count >= max_events:
                    stats['truncated'] = True
                    return
                count += 1
                yield 'row', i, _csv_record(row, fmt), fmt


def _csv_record(row, fmt):
    low = _lower_keys(row)
    if fmt == 'm365_ual':
        audit = _maybe_json(low.get('auditdata'))
        rec = dict(audit) if isinstance(audit, dict) else {}
        rec.setdefault('CreationTime', low.get('creationdate') or low.get('creationtime'))
        rec.setdefault('Operation', low.get('operation') or low.get('operations'))
        rec.setdefault('UserId', low.get('userid') or low.get('userids'))
        return rec
    if fmt == 'aws_cloudtrail':
        event = _maybe_json(low.get('cloudtrail event'))
        if isinstance(event, dict):
            return event
        return {'eventTime': low.get('event time'), 'eventName': low.get('event name'),
                'eventSource': low.get('event source'), 'awsRegion': low.get('aws region'),
                'sourceIPAddress': low.get('source ip address'), 'errorCode': low.get('error code'),
                'userIdentity': {'userName': low.get('user name'),
                                 'accessKeyId': low.get('aws access key')},
                'requestParameters': {'resources': low.get('resources')}}
    return {'_csv': low}


# ============================================================================
# Normalisation
# ============================================================================

def _event(ref_kind, ref_no, fmt, **fields):
    ev = {ref_kind: ref_no, '_ref': (ref_kind, ref_no), 'source': fmt}
    for key, value in fields.items():
        if value not in (None, '', [], {}):
            ev[key] = value
    ev.setdefault('severity', 'info')
    return ev


def _summary_text(ev):
    parts = [str(ev.get('operation') or '?')]
    if ev.get('user'):
        parts.append(f"par {ev['user']}")
    if ev.get('src_ip'):
        parts.append(f"depuis {ev['src_ip']}")
    if ev.get('target'):
        parts.append(f"-> {str(ev['target'])[:120]}")
    if ev.get('result'):
        parts.append(f"[{ev['result']}]")
    return ' '.join(parts)


# --- Entra ID : connexions ---------------------------------------------------

SPRAY_CODES = {50126, 50053, 50055, 50056, 50057, 50034, 50064}
MFA_FAIL_CODES = {500121, 50088}
_MFA_FAIL_WORDS = ('denied', 'did not respond', 'timed out', 'timeout', 'declined', 'fraud',
                   'refuse', 'expire')
_MFA_OK_WORDS = ('successfully completed', 'satisfied by claim', 'mfa completed', 'succeeded')


def _signin_flags(ev, mfa_text):
    """Indicateurs derives communs aux connexions Entra et UAL."""
    err = ev.get('error_code')
    text = (mfa_text or '').lower()
    success = ev.get('result') == 'success'
    ev['_signin'] = True
    ev['_mfa_fail'] = (not success) and (err in MFA_FAIL_CODES or any(w in text for w in _MFA_FAIL_WORDS))
    req = str(ev.get('auth_requirement') or '').lower()
    ev['_mfa_ok'] = success and ('multi' in req or any(w in text for w in _MFA_OK_WORDS))
    ev['_single_factor'] = success and 'single' in req
    ev['_pwd_fail'] = (not success) and (err in SPRAY_CODES or (
        err is None and ev.get('operation') == 'UserLoginFailed'))


def _norm_entra_signin(rec, ref_kind, ref_no):
    if '_csv' in rec:
        return _norm_entra_signin_csv(rec['_csv'], ref_kind, ref_no)
    status = rec.get('status') if isinstance(rec.get('status'), dict) else {}
    loc = rec.get('location') if isinstance(rec.get('location'), dict) else {}
    geo = loc.get('geoCoordinates') if isinstance(loc.get('geoCoordinates'), dict) else {}
    err = as_int(status.get('errorCode', rec.get('errorCode')))
    texts = []
    for d in rec.get('authenticationDetails') or []:
        if isinstance(d, dict):
            texts.append(f"{d.get('authenticationMethod', '')} {d.get('authenticationStepResultDetail', '')}"
                         f"{'' if d.get('succeeded', True) else ' failed'}")
    mfa = rec.get('mfaDetail') if isinstance(rec.get('mfaDetail'), dict) else {}
    if mfa:
        texts.append(f"{mfa.get('authMethod', '')} {mfa.get('authDetail', '')}")
    if status.get('additionalDetails'):
        texts.append(str(status['additionalDetails']))
    mfa_text = '; '.join(t.strip() for t in texts if t.strip())
    result = 'success' if err == 0 else ('interrupted' if err in (50074, 50076, 50140, 50158) else 'failure')
    ev = _event(
        ref_kind, ref_no, 'entra_signin',
        timestamp=to_utc(rec.get('createdDateTime')),
        account=rec.get('resourceTenantId') or rec.get('homeTenantId') or rec.get('tenantId'),
        user=rec.get('userPrincipalName') or rec.get('userDisplayName') or rec.get('userId'),
        src_ip=clean_ip(rec.get('ipAddress')),
        user_agent=rec.get('userAgent'),
        operation='SignIn',
        result=result,
        target=rec.get('resourceDisplayName') or rec.get('appDisplayName'),
        app=rec.get('appDisplayName'),
        client_app=rec.get('clientAppUsed'),
        error_code=err,
        failure_reason=status.get('failureReason'),
        auth_requirement=rec.get('authenticationRequirement'),
        mfa_detail=mfa_text,
        ca_status=rec.get('conditionalAccessStatus'),
        city=loc.get('city'),
        country=loc.get('countryOrRegion'),
        lat=geo.get('latitude'),
        lon=geo.get('longitude'),
        risk=rec.get('riskLevelDuringSignIn'),
        signin_type=rec.get('_category') or rec.get('signInEventTypes'),
    )
    ev['host'] = ev.get('account')
    _signin_flags(ev, mfa_text)
    return ev


def _norm_entra_signin_csv(low, ref_kind, ref_no):
    status = str(low.get('status') or low.get('status.errorcode') or '').strip()
    err = as_int(low.get('sign-in error code') or low.get('errorcode') or low.get('status.errorcode'))
    if err is None and status:
        err = 0 if status.lower() == 'success' else None
    location = str(low.get('location') or '')
    parts = [p.strip() for p in location.split(',') if p.strip()]
    country = low.get('country') or (parts[-1] if parts else None)
    req = str(low.get('authentication requirement') or low.get('authenticationrequirement') or '')
    if 'multi' in req.lower():
        req = 'multiFactorAuthentication'
    elif 'single' in req.lower():
        req = 'singleFactorAuthentication'
    mfa_text = ' '.join(str(low.get(k) or '') for k in (
        'multifactor authentication result', 'multifactor authentication auth method',
        'multifactor authentication auth detail', 'failure reason')).strip()
    if err == 0:
        result = 'success'
    elif err in (50074, 50076, 50140, 50158) or status.lower() == 'interrupted':
        result = 'interrupted'
    else:
        result = 'failure'
    ev = _event(
        ref_kind, ref_no, 'entra_signin',
        timestamp=to_utc(low.get('date (utc)') or low.get('createddatetime') or low.get('date')),
        account=low.get('resource tenant id') or low.get('home tenant id') or low.get('tenantid'),
        user=low.get('username') or low.get('userprincipalname') or low.get('user'),
        src_ip=clean_ip(low.get('ip address') or low.get('ipaddress')),
        user_agent=low.get('user agent') or low.get('useragent'),
        operation='SignIn',
        result=result,
        target=low.get('resource') or low.get('application'),
        app=low.get('application') or low.get('appdisplayname'),
        client_app=low.get('client app') or low.get('clientappused'),
        error_code=err,
        failure_reason=low.get('failure reason'),
        auth_requirement=req,
        mfa_detail=mfa_text,
        ca_status=low.get('conditional access'),
        city=parts[0] if len(parts) > 1 else None,
        country=country,
        lat=low.get('latitude'),
        lon=low.get('longitude'),
    )
    ev['host'] = ev.get('account')
    _signin_flags(ev, mfa_text)
    return ev


# --- Microsoft 365 UAL ---------------------------------------------------------

def _name_values(items, value_key='Value'):
    out = {}
    for item in items or []:
        if isinstance(item, dict) and item.get('Name') is not None:
            out[str(item['Name'])] = '' if item.get(value_key) is None else str(item.get(value_key))
    return out


def _norm_ual(rec, ref_kind, ref_no):
    audit = _maybe_json(rec.get('AuditData'))
    if isinstance(audit, dict):
        merged = dict(audit)
        for key, value in rec.items():
            merged.setdefault(key, value)
        rec = merged
    params = _name_values(rec.get('Parameters'))
    params.update(_name_values(rec.get('OperationProperties')))
    props = _name_values(rec.get('ModifiedProperties'), 'NewValue')
    ext = _name_values(rec.get('ExtendedProperties'))
    targets = [str(t.get('ID')) for t in rec.get('Target') or [] if isinstance(t, dict) and t.get('ID')]
    op = str(rec.get('Operation') or rec.get('Operations') or '')
    user = rec.get('UserId') or rec.get('UserIds') or rec.get('UserKey')
    ip = clean_ip(rec.get('ClientIP') or rec.get('ClientIPAddress') or rec.get('ActorIpAddress'))
    status = str(rec.get('ResultStatus') or '')
    is_signin = op in ('UserLoggedIn', 'UserLoginFailed')
    err = as_int(rec.get('ErrorNumber'))
    if is_signin:
        result = 'success' if op == 'UserLoggedIn' else 'failure'
        if op == 'UserLoggedIn' and err is None:
            err = 0
    elif status:
        result = 'failure' if status.lower() in ('failed', 'failure', 'false') else 'success'
    else:
        result = None
    target = (params.get('Identity') or params.get('Name') or rec.get('ObjectId')
              or (targets[0] if targets else None))
    ev = _event(
        ref_kind, ref_no, 'm365_ual',
        timestamp=to_utc(rec.get('CreationTime') or rec.get('CreationDate')),
        account=rec.get('OrganizationId') or rec.get('OrganizationName'),
        user=user,
        src_ip=ip,
        user_agent=ext.get('UserAgent') or rec.get('UserAgent') or rec.get('ClientInfoString'),
        operation=op,
        result=result,
        target=target,
        workload=rec.get('Workload'),
        record_type=rec.get('RecordType'),
        error_code=err if is_signin else None,
        failure_reason=rec.get('LogonError'),
        app=rec.get('ApplicationDisplayName') or rec.get('AppDisplayName'),
        params='; '.join(f'{k}={v}' for k, v in params.items())[:600],
    )
    ev['host'] = ev.get('account')
    ev['_params'] = params
    ev['_props'] = props
    ev['_targets'] = targets
    ev['_org'] = str(rec.get('OrganizationName') or '')
    if is_signin:
        req_type = ext.get('RequestType', '')
        ev['client_app'] = 'Browser' if 'login' in req_type.lower() else None
        _signin_flags(ev, f"{rec.get('LogonError') or ''} {ext.get('ResultStatusDetail', '')}")
    return ev


# --- Entra ID : audit ----------------------------------------------------------

def _norm_entra_audit(rec, ref_kind, ref_no):
    if '_csv' in rec:
        return _norm_entra_audit_csv(rec['_csv'], ref_kind, ref_no)
    init = rec.get('initiatedBy') if isinstance(rec.get('initiatedBy'), dict) else {}
    iu = init.get('user') if isinstance(init.get('user'), dict) else {}
    ia = init.get('app') if isinstance(init.get('app'), dict) else {}
    props, names, apps = {}, [], []
    for t in rec.get('targetResources') or []:
        if not isinstance(t, dict):
            continue
        name = t.get('displayName') or t.get('userPrincipalName') or t.get('id')
        if name:
            names.append(str(name))
            if str(t.get('type', '')).lower() in ('serviceprincipal', 'application'):
                apps.append(str(name))
        for mp in t.get('modifiedProperties') or []:
            if isinstance(mp, dict) and mp.get('displayName'):
                props[str(mp['displayName'])] = str(mp.get('newValue') or '')
    for d in rec.get('additionalDetails') or []:
        if isinstance(d, dict) and d.get('key'):
            props.setdefault(str(d['key']), str(d.get('value') or ''))
    result = str(rec.get('result') or '').lower() or None
    ev = _event(
        ref_kind, ref_no, 'entra_audit',
        timestamp=to_utc(rec.get('activityDateTime')),
        account=rec.get('tenantId'),
        user=iu.get('userPrincipalName') or ia.get('displayName') or ia.get('servicePrincipalName'),
        src_ip=clean_ip(iu.get('ipAddress') or ia.get('ipAddress')),
        user_agent=props.get('User-Agent'),
        operation=rec.get('activityDisplayName'),
        result='failure' if result in ('failure', 'failed') else ('success' if result else None),
        target=', '.join(names)[:300],
        category=rec.get('category'),
        service=rec.get('loggedByService'),
        app=apps[0] if apps else None,
    )
    ev['host'] = ev.get('account')
    ev['_props'] = props
    ev['_targets'] = names
    return ev


def _norm_entra_audit_csv(low, ref_kind, ref_no):
    props, names, apps = {}, [], []
    for n in range(1, 10):
        name = low.get(f'target{n}displayname') or low.get(f'target{n}userprincipalname')
        if not name:
            continue
        names.append(name)
        if str(low.get(f'target{n}type') or '').lower() in ('serviceprincipal', 'application'):
            apps.append(name)
        for m in range(1, 20):
            pname = low.get(f'target{n}modifiedproperty{m}name')
            if pname:
                props[pname] = str(low.get(f'target{n}modifiedproperty{m}newvalue') or '')
    result = str(low.get('result') or '').lower() or None
    ev = _event(
        ref_kind, ref_no, 'entra_audit',
        timestamp=to_utc(low.get('date (utc)') or low.get('activitydatetime') or low.get('date')),
        user=low.get('actoruserprincipalname') or low.get('actordisplayname'),
        src_ip=clean_ip(low.get('ipaddress') or low.get('ip address')),
        operation=low.get('activity') or low.get('activitydisplayname'),
        result='failure' if result in ('failure', 'failed') else ('success' if result else None),
        target=', '.join(names)[:300],
        category=low.get('category'),
        service=low.get('service') or low.get('loggedbyservice'),
        app=apps[0] if apps else None,
    )
    ev['_props'] = props
    ev['_targets'] = names
    return ev


# --- AWS CloudTrail --------------------------------------------------------------

_AWS_TARGET_KEYS = ('userName', 'roleName', 'groupName', 'policyArn', 'secretId', 'name', 'trailName',
                    'bucketName', 'keyId', 'functionName', 'dbInstanceIdentifier', 'detectorId',
                    'instanceId', 'logGroupName', 'roleArn', 'imageId')


def aws_principal(identity):
    ui = identity if isinstance(identity, dict) else {}
    itype = ui.get('type')
    arn = str(ui.get('arn') or '')
    if itype == 'Root':
        return 'root'
    if itype == 'AssumedRole' and 'assumed-role/' in arn:
        return arn.split('assumed-role/', 1)[1]
    if itype == 'AWSService':
        return ui.get('invokedBy') or 'aws-service'
    return ui.get('userName') or (arn.rsplit('/', 1)[-1] if arn else None) or ui.get('principalId')


def _norm_cloudtrail(rec, ref_kind, ref_no):
    ui = rec.get('userIdentity') if isinstance(rec.get('userIdentity'), dict) else {}
    req = rec.get('requestParameters') if isinstance(rec.get('requestParameters'), dict) else {}
    resp = rec.get('responseElements') if isinstance(rec.get('responseElements'), dict) else {}
    extra = rec.get('additionalEventData') if isinstance(rec.get('additionalEventData'), dict) else {}
    target = None
    for key in _AWS_TARGET_KEYS:
        if req.get(key):
            target = str(req[key])
            if key == 'bucketName' and req.get('key'):
                target += '/' + str(req['key'])
            break
    name = rec.get('eventName')
    failed = bool(rec.get('errorCode')) or (name == 'ConsoleLogin' and resp.get('ConsoleLogin') == 'Failure')
    ev = _event(
        ref_kind, ref_no, 'aws_cloudtrail',
        timestamp=to_utc(rec.get('eventTime')),
        account=rec.get('recipientAccountId') or ui.get('accountId'),
        user=aws_principal(ui),
        src_ip=clean_ip(rec.get('sourceIPAddress')),
        user_agent=rec.get('userAgent'),
        operation=name,
        result='failure' if failed else 'success',
        target=target,
        service=rec.get('eventSource'),
        region=rec.get('awsRegion'),
        identity_type=ui.get('type'),
        principal_arn=ui.get('arn'),
        access_key=ui.get('accessKeyId'),
        error_code=rec.get('errorCode'),
        mfa_used=extra.get('MFAUsed'),
        event_type=rec.get('eventType'),
        read_only=rec.get('readOnly'),
    )
    ev['host'] = ev.get('account')
    ev['_req'] = req
    ev['_resp'] = resp
    ev['_invoked_by'] = ui.get('invokedBy')
    ev['_caller_user'] = ui.get('userName')
    return ev


# --- GCP -----------------------------------------------------------------------------

def _norm_gcp(rec, ref_kind, ref_no):
    pp = rec.get('protoPayload') if isinstance(rec.get('protoPayload'), dict) else {}
    auth = pp.get('authenticationInfo') if isinstance(pp.get('authenticationInfo'), dict) else {}
    meta = pp.get('requestMetadata') if isinstance(pp.get('requestMetadata'), dict) else {}
    status = pp.get('status') if isinstance(pp.get('status'), dict) else {}
    labels = dig(rec, 'resource.labels', {}) or {}
    project = labels.get('project_id')
    if not project:
        m = re.match(r'^(?:projects|organizations|folders)/([^/]+)/', str(rec.get('logName') or ''))
        project = m.group(1) if m else None
    code = as_int(status.get('code')) or 0
    ev = _event(
        ref_kind, ref_no, 'gcp_audit',
        timestamp=to_utc(rec.get('timestamp') or rec.get('receiveTimestamp')),
        account=project,
        user=auth.get('principalEmail') or auth.get('principalSubject'),
        src_ip=clean_ip(meta.get('callerIp')),
        user_agent=meta.get('callerSuppliedUserAgent'),
        operation=pp.get('methodName'),
        result='failure' if code else 'success',
        target=pp.get('resourceName'),
        service=pp.get('serviceName'),
        status_code=code or None,
        status_message=status.get('message'),
        log_name=str(rec.get('logName') or '').rsplit('/', 1)[-1],
    )
    ev['host'] = ev.get('account')
    ev['_pp'] = pp
    return ev


# --- Kubernetes ------------------------------------------------------------------------

def _norm_k8s(rec, ref_kind, ref_no):
    user = rec.get('user') if isinstance(rec.get('user'), dict) else {}
    obj = rec.get('objectRef') if isinstance(rec.get('objectRef'), dict) else {}
    resp = rec.get('responseStatus') if isinstance(rec.get('responseStatus'), dict) else {}
    code = as_int(resp.get('code'))
    ips = rec.get('sourceIPs') or []
    resource = obj.get('resource')
    sub = obj.get('subresource')
    target = '/'.join(str(p) for p in (obj.get('namespace'), resource, obj.get('name')) if p)
    if sub:
        target += f'/{sub}'
    ev = _event(
        ref_kind, ref_no, 'k8s_audit',
        timestamp=to_utc(rec.get('requestReceivedTimestamp') or rec.get('stageTimestamp')),
        user=user.get('username'),
        src_ip=clean_ip(ips[0]) if ips else None,
        user_agent=rec.get('userAgent'),
        operation=rec.get('verb'),
        result=None if code is None else ('success' if code < 400 else 'failure'),
        target=target or rec.get('requestURI'),
        namespace=obj.get('namespace'),
        resource=resource,
        subresource=sub,
        status_code=code,
        stage=rec.get('stage'),
        audit_id=rec.get('auditID'),
        request_uri=str(rec.get('requestURI') or '')[:300],
        groups=', '.join(str(g) for g in user.get('groups') or [])[:300],
    )
    ev['_req'] = rec.get('requestObject') if isinstance(rec.get('requestObject'), dict) else {}
    ev['_groups'] = [str(g) for g in user.get('groups') or []]
    return ev


NORMALIZERS = {
    'm365_ual': _norm_ual,
    'entra_signin': _norm_entra_signin,
    'entra_audit': _norm_entra_audit,
    'aws_cloudtrail': _norm_cloudtrail,
    'gcp_audit': _norm_gcp,
    'k8s_audit': _norm_k8s,
}


def load_events(path, det=None, max_events=DEFAULT_MAX_EVENTS):
    """(evenements normalises internes, statistiques) d'un journal cloud."""
    det = det or detect(path)
    stats = {'skipped': 0}
    events = []
    if det.get('format') not in NORMALIZERS:
        return events, stats
    for ref_kind, ref_no, rec, fmt in iter_records(path, det, max_events, stats):
        norm = NORMALIZERS.get(fmt) or NORMALIZERS[det['format']]
        try:
            ev = norm(rec, ref_kind, ref_no)
        except (AttributeError, TypeError, ValueError):
            stats['skipped'] += 1
            continue
        ev['event'] = _summary_text(ev)
        events.append(ev)
    return events, stats


def public_view(ev):
    """Evenement sans les cles internes ('_...'), pret a etre renvoye et indexe."""
    return {k: v for k, v in ev.items() if not k.startswith('_')}


def summarize(events):
    def top(key, n):
        return [{'value': v, 'count': c} for v, c in
                Counter(str(e[key]) for e in events if e.get(key)).most_common(n)]
    stamps = sorted(e['timestamp'] for e in events if e.get('timestamp'))
    return {
        'time_span': {'first': stamps[0], 'last': stamps[-1]} if stamps else None,
        'failures': sum(1 for e in events if e.get('result') == 'failure'),
        'accounts': top('account', 10),
        'top_operations': top('operation', 30),
        'top_users': top('user', 20),
        'top_source_ips': top('src_ip', 20),
        'top_user_agents': top('user_agent', 10),
    }
