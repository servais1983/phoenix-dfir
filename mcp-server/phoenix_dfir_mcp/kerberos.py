"""Kerberos correlation on Windows Security events (no LLM).

A service ticket request (4769) is normally preceded by a TGT request (4768)
of the same account. When the log holds TGT requests but none for the account
that asks for service tickets, the TGT was not issued by this domain
controller: a forged ticket (Golden Ticket, T1558.001). Such RC4 requests are
not Kerberoasting (T1558.003), so per-event Kerberoasting alerts on them are
reclassified. The verdict needs the log to cover a TGT lifetime before the
request, or the ticket to be RC4 while every TGT of the log is AES; otherwise
a low, inconclusive alert without technique says the TGT may predate the log.
"""

import datetime

TGT, TGS = 4768, 4769
KERBEROASTING = 'T1558.003'
TGT_LIFETIME_S = 10 * 3600  # Windows default: a TGT obtained before the log may still be valid
RC4 = ('0x17', '0x18')


def _account(event):
    data = event.get('data') or {}
    return str(data.get('TargetUserName') or '').split('@', 1)[0].strip().lower()


def _sorted(events):
    return sorted(events, key=lambda e: (str(e.get('timestamp') or ''), str(e.get('record_id') or '')))


def tickets_without_tgt(events):
    """Record ids of the 4769 events whose account never got a TGT before them."""
    if not any(e.get('event_id') == TGT for e in events):
        return {}
    with_tgt, out = set(), {}
    for event in _sorted(events):
        account = _account(event)
        if not account:
            continue
        if event.get('event_id') == TGT:
            with_tgt.add(account)
        elif event.get('event_id') == TGS and account not in with_tgt and event.get('record_id') is not None:
            out[event['record_id']] = event
    return out


def _epoch(event):
    try:
        return datetime.datetime.fromisoformat(str(event.get('timestamp') or '').replace('Z', '+00:00')).timestamp()
    except ValueError:
        return None


def _encryption(event):
    return str((event.get('data') or {}).get('TicketEncryptionType') or '').lower()


def _conclusive(event, events):
    """A missing TGT means a forged ticket only when the log covers the TGT lifetime before
    the request, or when the ticket is RC4 while every TGT of the log is AES."""
    times = [t for t in (_epoch(e) for e in events) if t is not None]
    start, at = (min(times) if times else None), _epoch(event)
    if start is not None and at is not None and at - start >= TGT_LIFETIME_S:
        return True
    tgt_encryptions = {_encryption(e) for e in events if e.get('event_id') == TGT} - {''}
    return _encryption(event) in RC4 and bool(tgt_encryptions) and not (tgt_encryptions & set(RC4))


def forged_ticket_alerts(events):
    alerts = []
    for record_id, event in tickets_without_tgt(events).items():
        data = event.get('data') or {}
        account = _account(event)
        if _conclusive(event, events):
            verdict = {'rule_title': 'Ticket de service sans TGT (ticket Kerberos forge, Golden Ticket possible)',
                       'description': f"4769 de {account} sans aucune demande de TGT (4768) de ce compte "
                                      'dans le journal',
                       'level': 'high', 'tactic': 'credential_access', 'technique': 'T1558.001',
                       'conclusive': True}
        else:
            verdict = {'rule_title': 'Ticket de service sans TGT dans le journal (non concluant)',
                       'description': f"4769 de {account} sans 4768 dans le journal, qui couvre moins que la "
                                      'duree de vie d un TGT et sans chiffrement RC4 anormal : le TGT peut '
                                      'preceder le journal',
                       'level': 'low', 'conclusive': False}
        alerts.append({
            'rule_id': 'phoenix-correlation-tgs-without-tgt', **verdict,
            'engine': 'phoenix-correlation', 'user': account,
            'service_name': data.get('ServiceName'), 'ip': data.get('IpAddress'),
            'event_id': TGS, 'record_id': record_id, 'timestamp': event.get('timestamp'),
            **({'row': event['row']} if event.get('row') is not None else {}),
        })
    return alerts


def _is_kerberoasting(alert):
    techniques = [alert.get('technique')] + list(alert.get('techniques') or [])
    return any(str(t or '').upper() == KERBEROASTING for t in techniques)


def correlate(alerts, events):
    """(alerts without the Kerberoasting ones on forged tickets, forged ticket alerts, reclassified count)."""
    found = forged_ticket_alerts(events)
    forged = {a['record_id'] for a in found if a['conclusive']}
    kept = [a for a in alerts if not (a.get('record_id') in forged and _is_kerberoasting(a))]
    return kept, found, len(alerts) - len(kept)
