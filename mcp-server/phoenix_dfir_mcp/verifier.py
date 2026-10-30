"""Deterministic verifier: a finding is kept only if the evidence backs it.

A finding is ``verified`` when:

1. it cites at least one reference (``record_id``, ``row``, ``line``, ``pid``,
   ``inode``) that a tool actually produced for that artifact (the case
   evidence index), and
2. every entity it names (IP addresses, domains, hashes, e-mail addresses,
   URLs) appears in the events those references point to.

Otherwise it is ``unverified``, with the reason. No LLM is involved: the same
case gives the same verdicts. A ``refuted`` verdict from the independent LLM
verification is kept (it can only remove a finding, never add one).

The report check works the same way: every factual sentence of a report (one
that states an IoC, a technique, a timestamp or an evidence reference) must
cite a verified finding as ``[F<id>]``.
"""

import re

from . import _paths, evidence_db, memory

_paths.ensure_backend_importable()
import parsers  # noqa: E402

VERIFIED, UNVERIFIED, REFUTED = 'verified', 'unverified', 'refuted'
REF_KINDS = ('record_id', 'row', 'line', 'pid', 'inode')
_IPV4 = re.compile(r'(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\.?\d)')
_FILE_SUFFIX = re.compile(r'\.(?:log|evtx|json|csv|txt|xml|pcap|pcapng|img|dd|raw|mem|plist|db|sqlite|yml|yaml|'
                          r'md|ps1|bat|sh|exe|dll|lnk|pf|e01|vmdk|jsonl|gz|zip)$', re.I)
CITATION = re.compile(r'\[F(\d+)\]')
_TECHNIQUE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
_TIMESTAMP = re.compile(r'\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2})?|\b\d{2}:\d{2}:\d{2}\b')
_REF_TOKEN = re.compile(r'\b(?:record_id|row|line|pid|inode)\s*[=:#]\s*\d', re.I)


# Evidence reference written in a report: kind=value@artifact (not an e-mail address)
_REF_WRITTEN = re.compile(r'\b(?:record_id|row|line|pid|inode)=[^\s,;)\]]+', re.I)


def entities(text):
    """Entities a finding asserts: IPv4 (public and private), domains, hashes, e-mails, URLs."""
    text = _REF_WRITTEN.sub(' ', str(text or ''))
    found = {('ip', ip) for ip in _IPV4.findall(text)}
    for ioc in parsers.extract_iocs(text):
        kind, value = ioc.get('type', ''), str(ioc.get('value', ''))
        if not value or (kind == 'domain' and _FILE_SUFFIX.search(value)):
            continue
        if kind == 'ip':
            continue  # already covered, with private addresses
        found.add((kind.split('_')[0], value))
    return sorted(found)


def _referenced_events(case_dir, ref):
    """Text of the indexed events a reference points to ([] when not indexed)."""
    if not evidence_db.exists(case_dir):
        return []
    artifact = str(ref.get('artifact') or '')
    base = artifact.replace('\\', '/').rstrip('/').rsplit('/', 1)[-1]
    conn = evidence_db._connect(case_dir)
    try:
        rows = conn.execute(
            'SELECT e.text, e.host, e.user, e.process FROM events e JOIN event_refs r ON r.event_id = e.id '
            'WHERE r.kind=? AND r.value=? AND (r.artifact=? OR r.artifact=? OR r.artifact LIKE ?)',
            (ref.get('kind'), str(ref.get('value')), evidence_db._rel(case_dir, artifact), base,
             f'%/{base}')).fetchall()
    finally:
        conn.close()
    return [' '.join(str(x) for x in row if x) for row in rows]


MAX_REPLAY_BYTES = 32 * 1024 * 1024


def _replay_shield(case_dir, detector):
    """Re-run the anti-injection shield on the artifact the detection came from."""
    import os
    from . import pathpolicy, shield, toolkit
    path = detector.get('artifact') or ''
    if not os.path.isabs(path):
        path = os.path.join(case_dir, path)
    if not os.path.isfile(path) or not pathpolicy.within(path, case_dir):
        return None
    with open(path, 'rb') as f:
        raw = f.read(MAX_REPLAY_BYTES)
    texts = [raw.decode('utf-8', 'ignore'), raw.decode('utf-16-le', 'ignore')]
    hits = [h for t in texts for h in shield.scan_text(t)[1]]
    if not hits and detector.get('tool') in toolkit.TOOLS:
        # Binary formats (EVTX...): replay the tool that produced the output
        result = toolkit.TOOLS[detector['tool']]['func'](file_path=path)
        hits = shield.sanitize(result)[1] if isinstance(result, (dict, list)) else []
    return len(hits)


def verify_finding(case_dir, finding):
    """Deterministic verdict for one finding (dict with status, reason and details)."""
    detector = finding.get('detector') or {}
    if detector.get('name') == 'shield':
        try:
            hits = _replay_shield(case_dir, detector)
        except Exception as e:  # replay failure: not verified, never a crash
            hits = None
            reason = f'shield replay failed: {type(e).__name__}'
        else:
            reason = 'artifact not found in the case' if hits is None else f'shield replay: {hits} hit(s)'
        status = VERIFIED if hits else UNVERIFIED
        return {'status': status, 'reason': reason, 'entities': [], 'missing': [], 'refs_found': 0}
    refs = [r for r in finding.get('evidence_refs') or [] if isinstance(r, dict) and r.get('kind') in REF_KINDS]
    claimed = entities(f"{finding.get('title', '')} {finding.get('evidence', '')}")
    if not refs:
        return {'status': UNVERIFIED, 'reason': 'no evidence reference', 'entities': claimed, 'missing': claimed,
                'refs_found': 0}
    found_refs, texts = 0, []
    for ref in refs:
        events = _referenced_events(case_dir, ref)
        if events or evidence_db.has_ref(case_dir, ref.get('artifact', ''), ref.get('kind'), ref.get('value')):
            found_refs += 1
            texts.extend(events)
    if not found_refs:
        return {'status': UNVERIFIED, 'reason': 'references absent from the tool outputs of the case',
                'entities': claimed, 'missing': claimed, 'refs_found': 0}
    haystack = ' '.join(texts).lower()
    missing = [list(e) for e in claimed if e[1].lower() not in haystack]
    if missing:
        names = ', '.join(v for _k, v in missing)
        return {'status': UNVERIFIED, 'reason': f'cited entities not in the referenced events: {names}',
                'entities': claimed, 'missing': missing, 'refs_found': found_refs}
    return {'status': VERIFIED, 'reason': f'{found_refs} reference(s) found, {len(claimed)} entit(y/ies) matched',
            'entities': claimed, 'missing': [], 'refs_found': found_refs}


def verify_case(case_dir):
    """Verify every finding of the case and store the verdicts. Returns a summary."""
    state = memory.load_state(case_dir)
    counts = {VERIFIED: 0, UNVERIFIED: 0, REFUTED: 0}
    for finding in state['findings']:
        det = verify_finding(case_dir, finding)
        finding['deterministic'] = {'status': det['status'], 'reason': det['reason'][:300],
                                    'missing': det['missing'][:10], 'refs_found': det['refs_found']}
        if finding.get('verification') == REFUTED:
            final = REFUTED  # the independent verification may only remove a finding
        else:
            final = det['status']
        if final != finding.get('verification'):
            note = finding.get('verification_note') or ''
            finding['verification_note'] = (f"[deterministic] {det['reason']}" + (f' | {note}' if note else ''))[:600]
        finding['verification'] = final
        counts[final] += 1
    memory.save_state(case_dir, state)
    return {'findings': len(state['findings']), **counts,
            'verified_ids': [f['id'] for f in state['findings'] if f['verification'] == VERIFIED]}


def verified_ids(case_dir):
    return {f['id'] for f in memory.get_state(case_dir)['findings'] if f.get('verification') == VERIFIED}


# Lines Phoenix writes itself into a report (save_report header, annex head):
# metadata, not claims of the investigator
GENERATED_LINES = ('> Report generated by Phoenix DFIR', '> Verification deterministe')


def _sentences(markdown):
    """Report sentences, outside code blocks, headings and the annex."""
    in_code = False
    for raw in markdown.splitlines():
        line = raw.strip()
        if line.startswith('```'):
            in_code = not in_code
            continue
        if in_code or not line or line.startswith('#') or set(line) <= set('|-: '):
            continue
        if line.startswith(GENERATED_LINES):
            continue
        for part in re.split(r'(?<=[.!?])\s+(?=[A-Z0-9\[])', line):
            if part.strip():
                yield part.strip()


def is_factual(sentence):
    """Does the sentence state something checkable (IoC, technique, timestamp, reference)?"""
    plain = CITATION.sub('', sentence)
    return bool(entities(plain) or _TECHNIQUE.search(plain) or _TIMESTAMP.search(plain)
                or _REF_TOKEN.search(plain))


def _finding_support(case_dir, findings, fid, cache):
    """Lower-cased text of the events a finding references, plus its own text."""
    if fid not in cache:
        finding = findings.get(fid) or {}
        texts = [str(finding.get('title', '')), str(finding.get('evidence', ''))]
        for ref in finding.get('evidence_refs') or []:
            if isinstance(ref, dict) and ref.get('kind') in REF_KINDS:
                texts.extend(_referenced_events(case_dir, ref))
        cache[fid] = ' '.join(texts).lower()
    return cache[fid]


def check_citations(markdown, verified, case_dir=None):
    """Coverage of factual sentences by citations of verified findings.

    With ``case_dir``, a citation links a sentence only when the entities it
    states (IP, domain, hash...) appear in the events referenced by the cited
    findings: citing [F2] does not prove an address F2 never observed."""
    factual, linked, bad = 0, 0, []
    findings = {f['id']: f for f in memory.get_state(case_dir)['findings']} if case_dir else {}
    support = {}
    for sentence in _sentences(markdown):
        if not is_factual(sentence):
            continue
        factual += 1
        cited = {int(x) for x in CITATION.findall(sentence)}
        reason = None
        if not cited:
            reason = 'no [F<id>] citation'
        elif not cited <= set(verified):
            reason = 'cites a non verified finding'
        elif case_dir:
            text = ' '.join(_finding_support(case_dir, findings, fid, support) for fid in sorted(cited))
            missing = [v for _k, v in entities(CITATION.sub('', sentence)) if v.lower() not in text]
            if missing:
                reason = f"entities not in the cited findings' events: {', '.join(missing[:5])}"
        if reason is None:
            linked += 1
        elif len(bad) < 20:
            bad.append({'sentence': sentence[:200], 'cited': sorted(cited), 'reason': reason})
    return {'factual_sentences': factual, 'linked': linked,
            'coverage': 1.0 if factual == 0 else round(linked / factual, 4), 'unlinked': bad}
