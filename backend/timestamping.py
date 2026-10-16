#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RFC 3161 trusted timestamping (Time-Stamp Protocol), pure standard library.

Phoenix builds the TimeStampReq DER itself (minimal ASN.1 DER encoder), posts
it to the Time Stamping Authority configured in PHOENIX_TSA_URL and stores the
TimeStampResp (.tsr) next to the timestamped object (Merkle checkpoint or
report). Timestamping is disabled when PHOENIX_TSA_URL is unset.

    TimeStampReq ::= SEQUENCE {
        version        INTEGER { v1(1) },
        messageImprint MessageImprint,      -- SHA-256 of the data
        nonce          INTEGER OPTIONAL,    -- 64-bit random
        certReq        BOOLEAN DEFAULT FALSE }  -- TRUE: TSA cert in token
    MessageImprint ::= SEQUENCE {
        hashAlgorithm  AlgorithmIdentifier, -- id-sha256 (2.16.840.1.101.3.4.2.1), NULL
        hashedMessage  OCTET STRING }

Verification performed by Phoenix on every response (verify_response):
PKIStatus granted (0 or 1), the token is a CMS SignedData whose encapsulated
content is a TSTInfo, and the TSTInfo messageImprint (algorithm + digest) and
nonce equal the ones that were requested.

LIMIT: the CMS signature and the TSA certificate chain are NOT verified by
Phoenix (no X.509 / CMS stack in the standard library). The .tsr token is
standard: verify it offline with
    openssl ts -verify -data <file> -in <file>.tsr -CAfile tsa-ca.pem
(instructions are included in the custody bundle).

Environment:
    PHOENIX_TSA_URL       TSA endpoint (http/https). Unset: disabled.
    PHOENIX_TSA_TIMEOUT   HTTP timeout in seconds (default 10).
"""

import datetime
import hashlib
import os
import secrets
import urllib.parse
import urllib.request

OID_SHA256 = '2.16.840.1.101.3.4.2.1'
OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
OID_TST_INFO = '1.2.840.113549.1.9.16.1.4'

MAX_RESPONSE_BYTES = 1024 * 1024


class DERError(ValueError):
    """Malformed DER input."""


# ============================================================================
# Minimal DER encoder
# ============================================================================

def _len(n):
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(body)]) + body


def tlv(tag, content):
    return bytes([tag]) + _len(len(content)) + content


def der_integer(value):
    if value == 0:
        body = b'\x00'
    else:
        length = (value.bit_length() + 8) // 8
        body = value.to_bytes(length, 'big', signed=True)
        # DER: minimal encoding (strip redundant leading 0x00 / 0xff)
        while len(body) > 1 and ((body[0] == 0 and body[1] < 0x80)
                                 or (body[0] == 0xff and body[1] >= 0x80)):
            body = body[1:]
    return tlv(0x02, body)


def der_boolean(value):
    return tlv(0x01, b'\xff' if value else b'\x00')


def der_null():
    return b'\x05\x00'


def der_octet_string(data):
    return tlv(0x04, data)


def der_oid(dotted):
    parts = [int(p) for p in dotted.split('.')]
    if len(parts) < 2:
        raise ValueError('OID needs at least two arcs')
    out = bytearray([40 * parts[0] + parts[1]])
    for arc in parts[2:]:
        chunk = [arc & 0x7f]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7f))
            arc >>= 7
        out.extend(reversed(chunk))
    return tlv(0x06, bytes(out))


def der_sequence(*items):
    return tlv(0x30, b''.join(items))


def message_imprint(digest):
    if len(digest) != 32:
        raise ValueError('SHA-256 digest must be 32 bytes')
    return der_sequence(der_sequence(der_oid(OID_SHA256), der_null()), der_octet_string(digest))


def build_request(digest, nonce=None, cert_req=True):
    """DER TimeStampReq for a SHA-256 digest (bytes)."""
    items = [der_integer(1), message_imprint(digest)]
    if nonce is not None:
        items.append(der_integer(nonce))
    if cert_req:
        items.append(der_boolean(True))
    return der_sequence(*items)


# ============================================================================
# Minimal DER decoder
# ============================================================================

def read_tlv(data, offset=0):
    """Decode one TLV at offset. Returns (tag, value_bytes, next_offset)."""
    if offset + 2 > len(data):
        raise DERError('truncated TLV header')
    tag = data[offset]
    if tag & 0x1f == 0x1f:
        raise DERError('high tag numbers not supported')
    first = data[offset + 1]
    pos = offset + 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7f
        if count == 0 or count > 4:
            raise DERError('unsupported length encoding')
        if pos + count > len(data):
            raise DERError('truncated length')
        length = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    end = pos + length
    if end > len(data):
        raise DERError('value exceeds buffer')
    return tag, data[pos:end], end


def children(value):
    """List of (tag, value) of the TLVs packed inside a constructed value."""
    out, pos = [], 0
    while pos < len(value):
        tag, val, pos = read_tlv(value, pos)
        out.append((tag, val))
    return out


def decode_integer(value):
    if not value:
        raise DERError('empty INTEGER')
    return int.from_bytes(value, 'big', signed=True)


def decode_oid(value):
    if not value:
        raise DERError('empty OID')
    first = value[0]
    arcs = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    acc = 0
    for byte in value[1:]:
        acc = (acc << 7) | (byte & 0x7f)
        if not byte & 0x80:
            arcs.append(acc)
            acc = 0
    return '.'.join(str(a) for a in arcs)


def _expect(item, tag, what):
    if item[0] != tag:
        raise DERError(f'{what}: expected tag 0x{tag:02x}, got 0x{item[0]:02x}')
    return item[1]


def parse_request(der):
    """Decode a TimeStampReq (used by tests and by the bundle verifier)."""
    tag, body, end = read_tlv(der)
    if tag != 0x30 or end != len(der):
        raise DERError('TimeStampReq must be one SEQUENCE')
    items = children(body)
    version = decode_integer(_expect(items[0], 0x02, 'version'))
    alg, digest = _parse_imprint(_expect(items[1], 0x30, 'messageImprint'))
    nonce, cert_req = None, False
    for t, v in items[2:]:
        if t == 0x02:
            nonce = decode_integer(v)
        elif t == 0x01:
            cert_req = v != b'\x00'
    return {'version': version, 'hash_algorithm': alg, 'digest': digest.hex(),
            'nonce': nonce, 'cert_req': cert_req}


def _parse_imprint(value):
    items = children(value)
    alg_items = children(_expect(items[0], 0x30, 'hashAlgorithm'))
    alg = decode_oid(_expect(alg_items[0], 0x06, 'algorithm'))
    digest = _expect(items[1], 0x04, 'hashedMessage')
    return alg, digest


def _parse_generalized_time(value):
    text = value.decode('ascii', errors='replace')
    raw = text.rstrip('Z')
    main, _, frac = raw.partition('.')
    try:
        dt = datetime.datetime.strptime(main, '%Y%m%d%H%M%S')
    except ValueError as e:
        raise DERError(f'invalid GeneralizedTime {text!r}') from e
    if frac:
        dt = dt.replace(microsecond=int((frac + '000000')[:6]))
    return dt.replace(tzinfo=datetime.timezone.utc).isoformat()


def parse_tst_info(der):
    tag, body, _ = read_tlv(der)
    if tag != 0x30:
        raise DERError('TSTInfo must be a SEQUENCE')
    items = children(body)
    info = {
        'version': decode_integer(_expect(items[0], 0x02, 'version')),
        'policy': decode_oid(_expect(items[1], 0x06, 'policy')),
    }
    alg, digest = _parse_imprint(_expect(items[2], 0x30, 'messageImprint'))
    info['hash_algorithm'] = alg
    info['digest'] = digest.hex()
    info['serial_number'] = decode_integer(_expect(items[3], 0x02, 'serialNumber'))
    info['gen_time'] = _parse_generalized_time(_expect(items[4], 0x18, 'genTime'))
    info['nonce'] = None
    for t, v in items[5:]:
        if t == 0x02:  # nonce (accuracy is a SEQUENCE, ordering a BOOLEAN)
            info['nonce'] = decode_integer(v)
    return info


def parse_response(der):
    """Decode a TimeStampResp. Returns status, token DER and TSTInfo fields."""
    tag, body, _ = read_tlv(der)
    if tag != 0x30:
        raise DERError('TimeStampResp must be a SEQUENCE')
    items = children(body)
    status_items = children(_expect(items[0], 0x30, 'PKIStatusInfo'))
    status = decode_integer(_expect(status_items[0], 0x02, 'status'))
    result = {'status': status, 'granted': status in (0, 1), 'token': None, 'tst_info': None}
    if len(items) < 2:
        return result
    # Re-encode the token TLV exactly as received (ContentInfo)
    token = tlv(0x30, _expect(items[1], 0x30, 'timeStampToken'))
    result['token'] = token
    ci = children(items[1][1])
    if decode_oid(_expect(ci[0], 0x06, 'contentType')) != OID_SIGNED_DATA:
        raise DERError('timeStampToken is not CMS SignedData')
    signed = children(_expect(ci[1], 0xa0, 'content'))
    sd = children(_expect(signed[0], 0x30, 'SignedData'))
    encap = children(_expect(sd[2], 0x30, 'encapContentInfo'))
    if decode_oid(_expect(encap[0], 0x06, 'eContentType')) != OID_TST_INFO:
        raise DERError('encapsulated content is not TSTInfo')
    econtent = children(_expect(encap[1], 0xa0, 'eContent'))
    tst_der = _expect(econtent[0], 0x04, 'eContent OCTET STRING')
    result['tst_info'] = parse_tst_info(tst_der)
    return result


def verify_response(der, digest, nonce=None):
    """Check a TimeStampResp against the request. Returns (ok, info|reason)."""
    try:
        resp = parse_response(der)
    except (DERError, IndexError) as e:
        return False, f'malformed response: {e}'
    if not resp['granted']:
        return False, f"TSA refused the request (PKIStatus {resp['status']})"
    info = resp['tst_info']
    if not info:
        return False, 'no timeStampToken in response'
    if info['hash_algorithm'] != OID_SHA256:
        return False, f"unexpected hash algorithm {info['hash_algorithm']}"
    if info['digest'] != digest.hex():
        return False, 'messageImprint does not match the timestamped data'
    if nonce is not None and info['nonce'] != nonce:
        return False, 'nonce mismatch (possible replay)'
    return True, info


# ============================================================================
# TSA client
# ============================================================================

def tsa_url():
    return os.environ.get('PHOENIX_TSA_URL', '').strip()


def is_enabled():
    return bool(tsa_url())


def _timeout():
    try:
        return max(1.0, float(os.environ.get('PHOENIX_TSA_TIMEOUT', '10')))
    except ValueError:
        return 10.0


def _http_post(url, body, timeout):
    """POST the DER request (isolated so tests can mock the network)."""
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ('http', 'https'):
        raise ValueError('PHOENIX_TSA_URL must use http or https')
    req = urllib.request.Request(url, data=body, method='POST', headers={
        'Content-Type': 'application/timestamp-query',
        'Accept': 'application/timestamp-reply',
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - scheme checked above
        return resp.read(MAX_RESPONSE_BYTES + 1)


def status():
    url = tsa_url()
    host = urllib.parse.urlparse(url).hostname if url else None
    return {'enabled': bool(url), 'tsa_host': host,
            'signature_chain_verified': False}


def timestamp_digest(digest, out_path=None):
    """Timestamp a SHA-256 digest. Writes the .tsr to out_path when granted.

    Returns a dict: status ('disabled' | 'granted' | 'error'), gen_time,
    serial_number, policy, nonce, tsr_path, error.
    """
    if not is_enabled():
        return {'status': 'disabled'}
    nonce = secrets.randbits(63) | 1
    request_der = build_request(digest, nonce=nonce, cert_req=True)
    try:
        response = _http_post(tsa_url(), request_der, _timeout())
    except Exception as e:  # network / HTTP error: never breaks the caller
        return {'status': 'error', 'error': f'TSA unreachable: {e}'[:300]}
    if len(response) > MAX_RESPONSE_BYTES:
        return {'status': 'error', 'error': 'TSA response too large'}
    ok, info = verify_response(response, digest, nonce)
    if not ok:
        return {'status': 'error', 'error': info}
    result = {
        'status': 'granted',
        'gen_time': info['gen_time'],
        'serial_number': str(info['serial_number']),
        'policy': info['policy'],
        'nonce': str(nonce),
        'digest': digest.hex(),
        'tsa_host': urllib.parse.urlparse(tsa_url()).hostname,
        'tsr_path': None,
    }
    if out_path:
        with open(out_path, 'wb') as f:
            f.write(response)
        result['tsr_path'] = out_path
    return result


def timestamp_file(path, out_path=None):
    """Timestamp a file: SHA-256 of its content, .tsr written next to it."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return timestamp_digest(h.digest(), out_path or path + '.tsr')
