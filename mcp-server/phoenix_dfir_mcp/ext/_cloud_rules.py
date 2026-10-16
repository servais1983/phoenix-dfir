"""Detections deterministes sur les journaux cloud, identite et Kubernetes.

Chaque detection produit un constat (severite, technique MITRE ATT&CK,
description) accompagne des references EXACTES ('row' / 'line') des
evenements qui le fondent : l'enqueteur peut les citer telles quelles dans
record_finding. Les seuils privilegient la precision : l'administration
courante (connexions MFA, regles de classement, lecture de ressources,
controleurs Kubernetes) ne doit pas declencher de constat.
"""

import json
import re
from collections import defaultdict
from urllib.parse import unquote

from . import _cloud_geo as geo
from ._cloud_formats import email_domain, is_public_ip, parse_ts

SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
MAX_REFS = 30

MITRE_NAMES = {
    'T1078.001': 'Valid Accounts: Default Accounts',
    'T1078.004': 'Valid Accounts: Cloud Accounts',
    'T1110.001': 'Brute Force: Password Guessing',
    'T1110.003': 'Brute Force: Password Spraying',
    'T1621': 'Multi-Factor Authentication Request Generation',
    'T1528': 'Steal Application Access Token',
    'T1098.001': 'Account Manipulation: Additional Cloud Credentials',
    'T1098.002': 'Account Manipulation: Additional Email Delegate Permissions',
    'T1098.003': 'Account Manipulation: Additional Cloud Roles',
    'T1098.006': 'Account Manipulation: Additional Container Cluster Roles',
    'T1114.003': 'Email Collection: Email Forwarding Rule',
    'T1564.008': 'Hide Artifacts: Email Hiding Rules',
    'T1562.008': 'Impair Defenses: Disable or Modify Cloud Logs',
    'T1136.003': 'Create Account: Cloud Account',
    'T1555.006': 'Credentials from Password Stores: Cloud Secrets Management Stores',
    'T1535': 'Unused/Unsupported Cloud Regions',
    'T1530': 'Data from Cloud Storage',
    'T1609': 'Container Administration Command',
    'T1611': 'Escape to Host',
    'T1552.007': 'Unsecured Credentials: Container API',
}


class Hunt:
    """Accumulateur de constats pour un artefact."""

    def __init__(self, artifact):
        self.artifact = artifact
        self.findings = []
        self.notes = []
        self._seen = set()

    def add(self, rule, title, severity, mitre, events, description='', **extra):
        events = sorted({id(e): e for e in events}.values(),
                        key=lambda e: (e.get('timestamp') or '', e['_ref'][1]))
        if not events:
            return None
        refs = [{'artifact': self.artifact, 'kind': e['_ref'][0], 'value': e['_ref'][1]}
                for e in events[:MAX_REFS]]
        signature = (rule, tuple((r['kind'], r['value']) for r in refs))
        if signature in self._seen:
            return None  # meme regle sur les memes evenements : un seul constat
        self._seen.add(signature)
        techniques = [t.strip() for t in mitre.split(',') if t.strip()]
        finding = {
            'rule': rule, 'title': title, 'severity': severity, 'mitre': mitre,
            'mitre_name': ' / '.join(MITRE_NAMES.get(t, t) for t in techniques),
            'description': description,
            'first_seen': events[0].get('timestamp'), 'last_seen': events[-1].get('timestamp'),
            'users': sorted({str(e['user']) for e in events if e.get('user')})[:10],
            'src_ips': sorted({str(e['src_ip']) for e in events if e.get('src_ip')})[:10],
            'event_count': len(events),
            'refs': refs,
            '_events': events[:MAX_REFS],
        }
        finding.update({k: v for k, v in extra.items() if v not in (None, '', [])})
        self.findings.append(finding)
        return finding

    def result(self):
        self.findings.sort(key=lambda f: (SEVERITY_RANK.get(f['severity'], 9), f['first_seen'] or ''))
        alerts = []
        for i, f in enumerate(self.findings, 1):
            f['id'] = f'F{i}'
            for e in f.pop('_events'):
                kind, value = e['_ref']
                alerts.append({kind: value, 'timestamp': e.get('timestamp'), 'severity': f['severity'],
                               'rule': f['rule'], 'finding': f['id'], 'mitre': f['mitre'],
                               'title': f['title'], 'user': e.get('user'), 'src_ip': e.get('src_ip'),
                               'operation': e.get('operation'), 'target': e.get('target'),
                               'host': e.get('host'), 'event': e.get('event')})
        return self.findings, alerts


def _dt(ev):
    return parse_ts(ev.get('timestamp'))


def _by_time(events):
    return sorted((e for e in events if _dt(e)), key=lambda e: (e['timestamp'], e['_ref'][1]))


def _within(a, b, seconds):
    da, db = _dt(a), _dt(b)
    return da is not None and db is not None and 0 <= (db - da).total_seconds() <= seconds


def _norm_op(op):
    return re.sub(r'\s+', ' ', str(op or '').strip().rstrip('.').lower())


def internal_domains(events):
    """Domaines de l'organisation, deduits des comptes vus dans le journal."""
    domains = set()
    for e in events:
        d = email_domain(e.get('user'))
        if d:
            domains.add(d)
        org = str(e.get('_org') or '').lower()
        if '.' in org and ' ' not in org:
            domains.add(org)
    return domains


def is_external(address, domains):
    dom = email_domain(address)
    if not dom:
        return False
    return not any(dom == d or dom.endswith('.' + d) for d in domains)


# ============================================================================
# Identite : connexions (Entra ID, UAL)
# ============================================================================

LEGACY_CLIENTS = {'exchange activesync', 'imap4', 'pop3', 'authenticated smtp', 'other clients',
                  'mapi over http', 'offline address book', 'outlook anywhere (rpc over http)',
                  'exchange web services', 'autodiscover', 'exchange online powershell',
                  'reporting web services', 'imap', 'pop', 'smtp'}


def rule_password_spray(events, hunt, ctx):
    fails = [e for e in _by_time(events) if e.get('_pwd_fail') and e.get('src_ip')]
    successes = [e for e in _by_time(events) if e.get('_signin') and e.get('result') == 'success']
    by_ip = defaultdict(list)
    for e in fails:
        by_ip[e['src_ip']].append(e)
    for ip, evs in by_ip.items():
        users = {str(e.get('user')).lower() for e in evs}
        window = [e for e in evs if _within(evs[0], e, 3600)]
        if len({str(e.get('user')).lower() for e in window}) >= 5:
            followed = [s for s in successes if s.get('src_ip') == ip
                        and str(s.get('user')).lower() in users and _within(evs[0], s, 86400)]
            hunt.add('password_spray', f'Pulverisation de mots de passe depuis {ip} '
                     f'({len(users)} comptes)', 'high', 'T1110.003', evs,
                     f'{len(evs)} echecs d\'authentification sur {len(users)} comptes distincts depuis '
                     f'{ip} en moins d\'une heure.', src_ip=ip)
            ctx.setdefault('spray_ips', set()).add(ip)
            if followed:
                hunt.add('spray_success', f'Connexion reussie depuis l\'IP de pulverisation {ip}',
                         'critical', 'T1078.004', followed + evs[-3:],
                         'Un compte vise par la pulverisation se connecte avec succes depuis la '
                         'meme IP : identifiants probablement compromis.', src_ip=ip)
            continue
        per_user = defaultdict(list)
        for e in evs:
            per_user[str(e.get('user')).lower()].append(e)
        for user, uevs in per_user.items():
            burst = [e for e in uevs if _within(uevs[0], e, 3600)]
            if len(burst) >= 10:
                hunt.add('brute_force', f'Force brute sur {user} depuis {ip}', 'medium', 'T1110.001',
                         burst, f'{len(burst)} echecs de mot de passe en moins d\'une heure.')


def rule_mfa_fatigue(events, hunt, ctx):
    per_user = defaultdict(list)
    for e in _by_time(events):
        if e.get('_signin') and e.get('user'):
            per_user[str(e['user']).lower()].append(e)
    for user, evs in per_user.items():
        fails = [e for e in evs if e.get('_mfa_fail')]
        used = set()
        for i, first in enumerate(fails):
            if id(first) in used:
                continue
            burst = [f for f in fails[i:] if _within(first, f, 3600)]
            if len(burst) < 3:
                continue
            used.update(id(f) for f in burst)
            last = burst[-1]
            success = next((e for e in evs if e.get('result') == 'success' and _within(last, e, 3600)
                            and e is not last), None)
            ips = sorted({f.get('src_ip') for f in burst if f.get('src_ip')})
            if success:
                hunt.add('mfa_fatigue', f'Fatigue MFA : {len(burst)} refus/expirations puis connexion '
                         f'reussie de {user}', 'critical' if success.get('src_ip') in ips else 'high',
                         'T1621', burst + [success],
                         'Demandes MFA repetees refusees ou expirees, suivies d\'une validation : '
                         'l\'utilisateur a probablement cede au bombardement de notifications.',
                         success_ip=success.get('src_ip'))
            elif len(burst) >= 5:
                hunt.add('mfa_fatigue', f'Bombardement MFA sur {user} ({len(burst)} refus)', 'medium',
                         'T1621', burst, 'Demandes MFA repetees sans validation observee.')


def rule_single_factor(events, hunt, ctx):
    per_user = defaultdict(list)
    for e in _by_time(events):
        if e.get('_signin') and e.get('user') and e.get('result') == 'success':
            per_user[str(e['user']).lower()].append(e)
    for user, evs in per_user.items():
        mfa_ips = {e.get('src_ip') for e in evs if e.get('_mfa_ok')}
        if not mfa_ips:
            continue  # MFA jamais observee : pas d'attente etablie
        odd = [e for e in evs if e.get('_single_factor') and e.get('src_ip') not in mfa_ips]
        if odd:
            hunt.add('single_factor_signin', f'Connexion simple facteur de {user} depuis une IP '
                     'jamais validee par MFA', 'medium', 'T1078.004', odd,
                     'Le compte utilise habituellement la MFA ; ces connexions reussies n\'ont satisfait '
                     'qu\'un facteur depuis des IP inconnues (jeton rejoue, exclusion d\'acces '
                     'conditionnel, protocole sans MFA).')


def rule_legacy_auth(events, hunt, ctx):
    hits = defaultdict(list)
    for e in events:
        if not e.get('_signin') or e.get('result') != 'success':
            continue
        client = str(e.get('client_app') or '').lower()
        ua = str(e.get('user_agent') or '')
        if client in LEGACY_CLIENTS or 'bav2ropc' in ua.lower():
            hits[(str(e.get('user')).lower(), 'bav2ropc' in ua.lower())].append(e)
    for (user, ropc), evs in hits.items():
        hunt.add('legacy_auth', f'Authentification heritee reussie pour {user}'
                 + (' (ROPC BAV2ROPC)' if ropc else ''), 'high' if ropc else 'medium', 'T1078.004', evs,
                 'Protocole d\'authentification herite (IMAP/POP/SMTP/ROPC...) qui contourne la MFA.')


def rule_impossible_travel(events, hunt, ctx, max_kmh=900):
    per_user = defaultdict(list)
    no_geo = set()
    for e in _by_time(events):
        if not (e.get('_signin') and e.get('result') == 'success' and e.get('user')):
            continue
        pos = geo.position(e.get('lat'), e.get('lon'), e.get('country'))
        if pos is None:
            no_geo.add(str(e['user']).lower())
            continue
        per_user[str(e['user']).lower()].append((e, pos))
    for user, items in per_user.items():
        for (a, pa), (b, pb) in zip(items, items[1:]):
            if a.get('src_ip') == b.get('src_ip'):
                continue
            precise = pa[2] == 'coords' and pb[2] == 'coords'
            dist = geo.distance_km(pa, pb)
            if dist < (300 if precise else 800):
                continue
            hours = max((_dt(b) - _dt(a)).total_seconds() / 3600.0, 1 / 60.0)
            speed = dist / hours
            if speed > max_kmh:
                where = lambda e: ', '.join(str(x) for x in (e.get('city'), e.get('country')) if x)  # noqa: E731
                hunt.add('impossible_travel', f'Voyage impossible pour {user} : {where(a)} -> {where(b)} '
                         f'({int(dist)} km en {hours * 60:.0f} min)', 'high', 'T1078.004', [a, b],
                         f'Vitesse implicite {int(speed)} km/h (> {max_kmh} km/h), position '
                         f"{'des coordonnees du journal' if precise else 'approximee au pays'}.",
                         distance_km=int(dist), speed_kmh=int(speed))
    if no_geo:
        hunt.notes.append(f'no geo : voyage impossible non evaluable pour {len(no_geo)} compte(s) '
                          '(journal sans champ de localisation ; aucune geolocalisation reseau)')


# ============================================================================
# Identite : audit (consentements OAuth, principaux de service, Exchange)
# ============================================================================

HIGH_RISK_SCOPES = {
    'mail.read', 'mail.readwrite', 'mail.send', 'mail.readbasic', 'mailboxsettings.readwrite',
    'files.read.all', 'files.readwrite.all', 'sites.read.all', 'sites.readwrite.all',
    'full_access_as_user', 'ews.accessasuser.all', 'directory.readwrite.all',
    'application.readwrite.all', 'approleassignment.readwrite.all',
    'rolemanagement.readwrite.directory', 'user.readwrite.all', 'contacts.read', 'notes.read.all',
    'chat.read', 'imap.accessasuser.all', 'pop.accessasuser.all', 'smtp.send',
}
_CONSENT_OPS = ('consent to application', 'add delegated permission grant',
                'add app role assignment to service principal')
_SP_CREATE_OPS = ('add service principal', 'add application')
_SP_CRED_RE = re.compile(r'(add service principal credentials|certificates and secrets management|'
                         r'update application.{0,5}certificates)')


def _app_name(ev):
    props = ev.get('_props') or {}
    for key in ('ServicePrincipal.DisplayName', 'DisplayName', 'AppDisplayName'):
        if props.get(key):
            return props[key].strip('"[] ')
    if ev.get('app'):
        return str(ev['app'])
    for t in ev.get('_targets') or []:
        if not re.fullmatch(r'[0-9a-fA-F-]{36}', t) and not t.startswith('ServicePrincipal_'):
            return t
    return str(ev.get('target') or '?')


def _scopes(ev):
    blob = ' '.join(f'{k} {v}' for k, v in (ev.get('_props') or {}).items())
    found = set()
    for m in re.finditer(r'Scope:\s*([^,\]]+)', blob):
        found.update(s.strip().lower() for s in m.group(1).split() if s.strip())
    for key in ('AppRole.Value', 'DelegatedPermissionGrant.Scope'):
        value = (ev.get('_props') or {}).get(key)
        if value:
            found.update(s.strip('"[] ').lower() for s in re.split(r'[\s,]+', value) if s.strip('"[] '))
    return found


def rule_oauth_consent(events, hunt, ctx):
    for e in events:
        if _norm_op(e.get('operation')) not in _CONSENT_OPS or e.get('result') == 'failure':
            continue
        scopes = _scopes(e)
        risky = sorted(s for s in scopes if s in HIGH_RISK_SCOPES)
        if not risky:
            continue
        props = e.get('_props') or {}
        admin = 'true' in str(props.get('ConsentContext.IsAdminConsent', '')).lower()
        app = _app_name(e)
        ctx.setdefault('consented_apps', set()).add(app.lower())
        hunt.add('oauth_consent', f'Consentement OAuth a risque accorde a l\'application "{app}"',
                 'critical' if admin or len(risky) >= 3 else 'high', 'T1528', [e],
                 f"Permissions a haut risque : {', '.join(risky)}"
                 + (" (offline_access : acces persistant)" if 'offline_access' in scopes else '')
                 + ('; consentement administrateur (tout le tenant)' if admin else '') + '.',
                 application=app, permissions=sorted(scopes))


def rule_sp_credentials(events, hunt, ctx):
    created = [e for e in _by_time(events) if _norm_op(e.get('operation')) in _SP_CREATE_OPS]
    for e in _by_time(events):
        if not _SP_CRED_RE.search(_norm_op(e.get('operation'))) or e.get('result') == 'failure':
            continue
        app = _app_name(e).lower()
        origin = [c for c in created if _app_name(c).lower() == app and _within(c, e, 86400)]
        consented = app in ctx.get('consented_apps', set())
        if origin or consented:
            hunt.add('sp_credentials', f'Identifiants ajoutes au principal de service "{_app_name(e)}" '
                     'peu apres sa creation', 'high', 'T1098.001', origin + [e],
                     'Nouveau principal de service (ou application consentie) dote d\'un secret ou '
                     'certificat : persistance applicative independante des mots de passe.')
        else:
            hunt.add('sp_credentials', f'Identifiants ajoutes au principal de service "{_app_name(e)}"',
                     'low', 'T1098.001', [e], 'Rotation de secret possible : verifier l\'auteur.')


_HIDE_FOLDERS = ('rss', 'conversation history', 'archive', 'junk', 'deleted items', 'notes',
                 'sync issues', 'outbox')
_BEC_WORDS = ('invoice', 'facture', 'payment', 'paiement', 'wire', 'virement', 'iban', 'bank',
              'banque', 'urgent', 'transfer')


def _recipients(text):
    return sorted(set(re.findall(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+', text or '')))


def rule_inbox_rules(events, hunt, ctx):
    domains = ctx['domains']
    for e in events:
        op = _norm_op(e.get('operation'))
        if op not in ('new-inboxrule', 'set-inboxrule', 'updateinboxrules') or e.get('result') == 'failure':
            continue
        params = {k.lower(): v for k, v in (e.get('_params') or {}).items()}
        blob = ' '.join(f'{k}={v}' for k, v in params.items()).lower()
        owner = str(e.get('user') or '')
        fwd_text = ' '.join(v for k, v in params.items()
                            if k in ('forwardto', 'forwardasattachmentto', 'redirectto'))
        if op == 'updateinboxrules' and re.search(r'forward|redirect', blob):
            fwd_text += ' ' + blob
        recipients = [r for r in _recipients(fwd_text) if r.lower() != owner.lower()]
        external = [r for r in recipients if is_external(r, domains)]
        delete = (params.get('deletemessage', '').lower() == 'true'
                  or params.get('softdeletemessage', '').lower() == 'true'
                  or 'deletemessage' in blob and op == 'updateinboxrules')
        folder = params.get('movetofolder', '').lower()
        if op == 'updateinboxrules':
            m = re.search(r'movetofolder[^,;]*?(rss[^,;"]*|conversation history|archive|junk[^,;"]*)', blob)
            folder = m.group(1) if m else folder
        hidden = delete or any(h in folder for h in _HIDE_FOLDERS)
        keywords = [w for w in _BEC_WORDS if w in blob]
        name = params.get('name', '')
        odd_name = bool(name) and len(re.sub(r'[\W_]', '', name)) <= 1
        if recipients:
            hunt.add('inbox_rule_forward', f'Regle de boite aux lettres de {owner} transferant vers '
                     f"{', '.join(external or recipients)}",
                     'critical' if external and (hidden or keywords) else ('high' if external else 'medium'),
                     'T1114.003' + (', T1564.008' if hidden else ''), [e],
                     ('Transfert vers un domaine EXTERNE. ' if external else 'Transfert interne. ')
                     + (f"Mots-cles financiers : {', '.join(keywords)}. " if keywords else '')
                     + ('Les messages sont ensuite masques ou supprimes.' if hidden else ''),
                     recipients=recipients, rule_name=name)
        elif hidden and (keywords or odd_name or 'rss' in folder or delete):
            hunt.add('inbox_rule_hide', f'Regle de masquage dans la boite de {owner} '
                     f"({'suppression' if delete else folder})", 'high' if keywords or odd_name else 'medium',
                     'T1564.008', [e],
                     'Regle qui supprime ou deplace les messages vers un dossier peu consulte '
                     + (f"(mots-cles : {', '.join(keywords)})" if keywords else '')
                     + (f' ; nom de regle suspect "{name}"' if odd_name else '') + '.',
                     rule_name=name)


def rule_mailbox_forwarding(events, hunt, ctx):
    domains = ctx['domains']
    for e in events:
        op = _norm_op(e.get('operation'))
        params = {k.lower(): v for k, v in (e.get('_params') or {}).items()}
        if e.get('result') == 'failure':
            continue
        if op == 'set-mailbox':
            dest = params.get('forwardingsmtpaddress') or params.get('forwardingaddress')
            if not dest:
                continue
            external = is_external(dest, domains)
            hunt.add('mailbox_forwarding', f"Transfert SMTP de la boite {params.get('identity', e.get('target'))} "
                     f'vers {dest}', 'high' if external else 'low', 'T1114.003', [e],
                     'Transfert automatique de toute la messagerie'
                     + (' vers un domaine externe.' if external else ' (destination interne).'),
                     recipients=[dest])
        elif op in ('new-transportrule', 'set-transportrule'):
            dest = ' '.join(params.get(k, '') for k in ('redirectmessageto', 'blindcopyto', 'addtorecipients',
                                                       'copyto'))
            external = [r for r in _recipients(dest) if is_external(r, domains)]
            if external:
                hunt.add('transport_rule_forward', f"Regle de transport copiant le courrier vers "
                         f"{', '.join(external)}", 'high', 'T1114.003', [e],
                         'Regle de flux de messagerie (tenant entier) vers un destinataire externe.',
                         recipients=external)
        elif op == 'add-mailboxpermission' and 'fullaccess' in params.get('accessrights', '').lower():
            hunt.add('mailbox_delegation', f"Acces complet a la boite {params.get('identity')} accorde a "
                     f"{params.get('user')}", 'low', 'T1098.002', [e],
                     'Delegation FullAccess : legitime en administration, a corroborer.')


# ============================================================================
# AWS CloudTrail
# ============================================================================

_AWS_LOG_TAMPER = {'StopLogging': 'critical', 'DeleteTrail': 'critical', 'UpdateTrail': 'medium',
                   'PutEventSelectors': 'medium', 'DeleteFlowLogs': 'high', 'DeleteDetector': 'high',
                   'UpdateDetector': 'medium', 'DisassociateFromMasterAccount': 'high',
                   'StopConfigurationRecorder': 'high', 'DeleteConfigurationRecorder': 'high',
                   'DeleteLogGroup': 'medium', 'DisableSecurityHub': 'high'}
_AWS_RECON = {'GetCallerIdentity', 'ListBuckets', 'ListUsers', 'ListAccessKeys', 'ListRoles',
              'GetAccountAuthorizationDetails', 'ListSecrets', 'ListAttachedUserPolicies',
              'GetAccountSummary', 'ListPolicies', 'DescribeTrails'}


def _ok(e):
    return e.get('result') == 'success'


def rule_aws_logging(events, hunt, ctx):
    for e in events:
        sev = _AWS_LOG_TAMPER.get(e.get('operation'))
        if not sev:
            continue
        if not _ok(e):
            hunt.add('aws_logging_tamper_attempt', f"Tentative {e['operation']} refusee ({e.get('error_code')})",
                     'medium', 'T1562.008', [e], 'Tentative d\'alteration de la journalisation.')
            continue
        hunt.add('aws_logging_tamper', f"{e['operation']} sur {e.get('target') or '?'} par {e.get('user')}",
                 sev, 'T1562.008', [e], 'Desactivation ou modification de la journalisation / '
                 'detection AWS (CloudTrail, GuardDuty, Config, VPC Flow Logs).')


def rule_aws_credentials(events, hunt, ctx):
    for e in events:
        op = e.get('operation')
        if not _ok(e):
            continue
        req = e.get('_req') or {}
        if op in ('CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile'):
            target = req.get('userName')
            caller = e.get('_caller_user')
            if target and target != caller:
                hunt.add('aws_credential_other_user', f'{op} pour l\'utilisateur {target} par {e.get("user")}',
                         'medium', 'T1098.001', [e],
                         'Creation d\'identifiants pour un AUTRE utilisateur IAM : persistance classique '
                         'apres compromission (a corroborer avec l\'activite de l\'appelant).',
                         target_user=target)
        elif op == 'CreateUser':
            hunt.add('aws_create_user', f"Creation de l'utilisateur IAM {req.get('userName')}", 'low',
                     'T1136.003', [e], 'Nouveau compte IAM.')


def rule_aws_admin_policy(events, hunt, ctx):
    for e in events:
        op = e.get('operation')
        if not _ok(e):
            continue
        req = e.get('_req') or {}
        arn = str(req.get('policyArn') or '')
        if op in ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy') and re.search(
                r'/(AdministratorAccess|IAMFullAccess|PowerUserAccess)$', arn):
            who = req.get('userName') or req.get('roleName') or req.get('groupName')
            hunt.add('aws_admin_policy', f"{arn.rsplit('/', 1)[-1]} attachee a {who}", 'high', 'T1098.003',
                     [e], 'Elevation de privileges par attachement d\'une politique administrateur.')
        elif op in ('PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy'):
            doc = unquote(str(req.get('policyDocument') or '')).replace(' ', '')
            if re.search(r'"Action":(\["?\*"?\]|"\*")', doc) and re.search(r'"Resource":(\["?\*"?\]|"\*")', doc):
                hunt.add('aws_admin_policy', f"Politique en ligne Action:* / Resource:* ({op})", 'high',
                         'T1098.003', [e], 'Politique inline equivalente a AdministratorAccess.')


def rule_aws_console(events, hunt, ctx):
    root = [e for e in events if e.get('identity_type') == 'Root' and not e.get('_invoked_by')
            and e.get('event_type') != 'AwsServiceEvent']
    if root:
        hunt.add('aws_root_usage', f'Utilisation du compte root ({len(root)} appels)', 'high', 'T1078.004',
                 root, 'Le compte root ne devrait servir qu\'a de rares operations de gestion.')
    for e in events:
        if (e.get('operation') == 'ConsoleLogin' and _ok(e) and e.get('mfa_used') == 'No'
                and e.get('identity_type') == 'IAMUser'):
            hunt.add('aws_console_no_mfa', f"Connexion console sans MFA de {e.get('user')} depuis "
                     f"{e.get('src_ip')}", 'medium', 'T1078.004', [e],
                     'Connexion a la console AWS par mot de passe seul.')


def rule_aws_secrets(events, hunt, ctx):
    per = defaultdict(list)
    for e in _by_time(events):
        if e.get('operation') in ('GetSecretValue', 'GetParameter', 'GetParameters') and _ok(e):
            if e['operation'] != 'GetSecretValue' and not (e.get('_req') or {}).get('withDecryption'):
                continue
            per[e.get('user')].append(e)
    for user, evs in per.items():
        for i, first in enumerate(evs):
            burst = [x for x in evs[i:] if _within(first, x, 600)]
            if len({x.get('target') for x in burst}) >= 5:
                hunt.add('aws_secrets_burst', f'Rafale de lecture de secrets par {user} '
                         f"({len({x.get('target') for x in burst})} secrets en 10 min)", 'high',
                         'T1555.006', burst, 'Lecture en masse de Secrets Manager / SSM : collecte '
                         'd\'identifiants.')
                break


def rule_aws_region(events, hunt, ctx):
    regional = [e for e in events if e.get('region') and e.get('region') != 'us-east-1'
                or e.get('region') == 'us-east-1' and e.get('service') not in (
                    'iam.amazonaws.com', 'sts.amazonaws.com', 'signin.amazonaws.com',
                    'cloudfront.amazonaws.com', 'route53.amazonaws.com', 'organizations.amazonaws.com')]
    if len(regional) < 20:
        return
    counts = defaultdict(list)
    for e in regional:
        counts[e['region']].append(e)
    total = len(regional)
    for region, evs in counts.items():
        writes = [e for e in evs if not re.match(r'(Describe|List|Get|Head|Lookup)', str(e.get('operation')))]
        if len(evs) / total < 0.05 and writes and len(counts) > 1:
            hunt.add('aws_unusual_region', f'Activite d\'ecriture dans une region inhabituelle : {region}',
                     'medium', 'T1535', writes,
                     f'{len(evs)} appels sur {total} ({100 * len(evs) / total:.1f} %) dans {region}, '
                     'dont des creations / modifications.')


def rule_aws_s3(events, hunt, ctx):
    per = defaultdict(list)
    for e in _by_time(events):
        if not _ok(e):
            continue
        op = e.get('operation')
        req = e.get('_req') or {}
        if op == 'GetObject' and e.get('identity_type') not in ('AWSService',) and not e.get('_invoked_by'):
            per[(e.get('user'), e.get('src_ip'))].append(e)
        elif op == 'PutBucketPolicy':
            doc = json.dumps(req.get('bucketPolicy') or req.get('policy') or '').replace(' ', '').replace('\\', '')
            if re.search(r'"Principal":("\*"|\{"AWS":"\*"\})', doc):
                hunt.add('aws_s3_public', f"Bucket {req.get('bucketName')} rendu public (politique)", 'high',
                         'T1530', [e], 'Politique de bucket accordant l\'acces a tout principal.')
        elif op == 'PutBucketAcl' and 'AllUsers' in json.dumps(req):
            hunt.add('aws_s3_public', f"Bucket {req.get('bucketName')} rendu public (ACL)", 'high', 'T1530',
                     [e], 'ACL accordant l\'acces a AllUsers.')
        elif op == 'DeleteBucketPublicAccessBlock' or op == 'DeletePublicAccessBlock':
            hunt.add('aws_s3_public', f"Blocage d'acces public supprime ({req.get('bucketName')})", 'medium',
                     'T1530', [e], 'Suppression de la protection contre l\'exposition publique.')
    for (user, ip), evs in per.items():
        for i, first in enumerate(evs):
            burst = [x for x in evs[i:] if _within(first, x, 600)]
            if len(burst) >= 20:
                buckets = sorted({str(x.get('target', '')).split('/')[0] for x in burst})
                hunt.add('aws_s3_exfil', f'Telechargement massif S3 par {user} depuis {ip} '
                         f'({len(evs)} objets)', 'high', 'T1530', evs,
                         f"{len(burst)} GetObject en 10 min sur {', '.join(buckets)}.", buckets=buckets)
                break


def _ua_family(ua):
    return re.split(r'[/ ]', str(ua or '').strip(), maxsplit=1)[0].lower()


def rule_aws_key_new_ip(events, hunt, ctx):
    per_key = defaultdict(list)
    for e in _by_time(events):
        key = str(e.get('access_key') or '')
        if key.startswith('AKIA'):
            per_key[key].append(e)
    for key, evs in per_key.items():
        seen_ips, seen_ua, new = set(), set(), defaultdict(list)
        for i, e in enumerate(evs):
            ip = e.get('src_ip')
            if i >= 3 and ip not in seen_ips and is_public_ip(ip) and ip not in new:
                new[ip] = []
            if ip in new:
                new[ip].append(e)
            elif ip:
                seen_ips.add(ip)
                seen_ua.add(_ua_family(e.get('user_agent')))
        for ip, ip_evs in new.items():
            recon = [x for x in ip_evs if x.get('operation') in _AWS_RECON]
            other_ua = any(_ua_family(x.get('user_agent')) not in seen_ua for x in ip_evs)
            if recon and other_ua:
                ctx.setdefault('compromised_principals', set()).add(ip_evs[0].get('user'))
                hunt.add('aws_key_new_ip', f'Cle {key} utilisee depuis une nouvelle IP {ip}', 'high',
                         'T1078.004', ip_evs,
                         f"Cle d'acces longue duree utilisee depuis {ip} jamais vue pour cette cle, avec un "
                         f"autre client ({ip_evs[0].get('user_agent')}) et de la reconnaissance "
                         f"({', '.join(sorted({x['operation'] for x in recon}))}).",
                         access_key=key, src_ip=ip)


def escalate_correlated(hunt, ctx):
    """Un constat AWS moyen dont l'auteur est deja signale comme compromis devient haut."""
    bad = ctx.get('compromised_principals') or set()
    for f in hunt.findings:
        if f['rule'] in ('aws_credential_other_user', 'aws_create_user') and set(f['users']) & bad:
            f['severity'] = 'high'
            f['description'] += ' Auteur deja signale (cle utilisee depuis une IP inconnue).'


# ============================================================================
# GCP
# ============================================================================

_GCP_PRIV_ROLES = {'roles/owner': 'critical', 'roles/editor': 'high', 'roles/iam.securityadmin': 'high',
                   'roles/resourcemanager.projectiamadmin': 'high',
                   'roles/resourcemanager.organizationadmin': 'critical',
                   'roles/iam.serviceaccounttokencreator': 'high', 'roles/iam.serviceaccountkeyadmin': 'high',
                   'roles/iam.serviceaccountadmin': 'high'}


def _gcp_domains(events):
    domains = set()
    for e in events:
        d = email_domain(e.get('user'))
        if d and not d.endswith('gserviceaccount.com'):
            domains.add(d)
        if e.get('account'):
            domains.add(f"{e['account']}.iam.gserviceaccount.com".lower())
    return domains


def rule_gcp(events, hunt, ctx):
    domains = _gcp_domains(events)
    for e in events:
        if not _ok(e):
            continue
        method = str(e.get('operation') or '')
        pp = e.get('_pp') or {}
        if method.endswith('SetIamPolicy'):
            deltas = dig_list(pp, 'serviceData.policyDelta.bindingDeltas') or dig_list(
                pp, 'metadata.datasetChange.bindingDeltas')
            if not deltas:
                deltas = [{'action': 'ADD', 'role': b.get('role'), 'member': m}
                          for b in dig_list(pp, 'request.policy.bindings') for m in b.get('members') or []]
            for d in deltas:
                if str(d.get('action', '')).upper() != 'ADD':
                    continue
                role = str(d.get('role') or '').lower()
                member = str(d.get('member') or '')
                public = member in ('allUsers', 'allAuthenticatedUsers')
                addr = member.split(':', 1)[-1]
                external = public or (email_domain(addr) and is_external(addr, domains)) or (
                    member.startswith('domain:') and not any(addr == x for x in domains))
                if external and (role in _GCP_PRIV_ROLES or public):
                    hunt.add('gcp_iam_external', f'Role {role} accorde a {member} (externe) sur '
                             f"{e.get('target')}", _GCP_PRIV_ROLES.get(role, 'high'), 'T1098.003', [e],
                             'Liaison IAM privilegiee vers un principal hors de l\'organisation.',
                             member=member, role=role)
        elif method.endswith('CreateServiceAccountKey'):
            hunt.add('gcp_sa_key', f"Cle de compte de service creee par {e.get('user')} "
                     f"({str(e.get('target')).rsplit('/', 1)[-1]})", 'high', 'T1098.001', [e],
                     'Cle longue duree exportable : persistance hors console.')
        elif re.search(r'(DeleteSink|UpdateSink|DeleteLog$|CreateExclusion|UpdateExclusion|'
                       r'UpdateBucket|DeleteBucket)', method) and 'logging' in str(e.get('service')):
            hunt.add('gcp_logging_tamper', f"{method.rsplit('.', 1)[-1]} par {e.get('user')}", 'high',
                     'T1562.008', [e], 'Modification ou suppression de la journalisation GCP.')


def dig_list(obj, path):
    cur = obj
    for part in path.split('.'):
        if not isinstance(cur, dict):
            return []
        cur = cur.get(part)
    return [x for x in cur if isinstance(x, dict)] if isinstance(cur, list) else []


# ============================================================================
# Kubernetes
# ============================================================================

_SYSTEM_PREFIXES = ('system:kube-', 'system:node:', 'system:serviceaccount:kube-system:',
                    'system:apiserver', 'system:volume-scheduler')
_HEALTH_URIS = ('/healthz', '/livez', '/readyz', '/version', '/openapi', '/.well-known', '/metrics')
_SENSITIVE_HOSTPATHS = ('/', '/etc', '/root', '/proc', '/var/run/docker.sock', '/run/containerd',
                        '/var/lib/kubelet', '/var/run', '/host', '/dev', '/sys')
_WORKLOADS = {'pods', 'deployments', 'daemonsets', 'statefulsets', 'replicasets', 'jobs', 'cronjobs'}


def _k8s_dedup(events):
    """Un evenement par auditID (etape la plus avancee)."""
    latest = {}
    order = []
    for e in events:
        key = e.get('audit_id') or id(e)
        if key not in latest:
            order.append(key)
        if key not in latest or e.get('stage') in ('ResponseComplete', 'Panic'):
            latest[key] = e
    return [latest[k] for k in order if latest[k].get('stage') in (None, 'ResponseComplete', 'Panic')]


def _allowed(e):
    return e.get('status_code') is None or e['status_code'] < 400


def _pod_spec(obj):
    if not isinstance(obj, dict):
        return {}
    spec = obj.get('spec') or {}
    for path in ('template', 'jobTemplate'):
        if isinstance(spec.get(path), dict):
            inner = spec[path].get('spec') or {}
            return _pod_spec({'spec': inner}) if 'template' in inner or 'jobTemplate' in inner else inner
    return spec if isinstance(spec, dict) else {}


def rule_k8s(events, hunt, ctx):
    events = _k8s_dedup(events)
    secrets_by_user = defaultdict(list)
    for e in events:
        user = str(e.get('user') or '')
        groups = e.get('_groups') or []
        res, sub, verb = e.get('resource'), e.get('subresource'), e.get('operation')
        system = user.startswith(_SYSTEM_PREFIXES)
        sa = user.startswith('system:serviceaccount:')
        anon = user == 'system:anonymous' or 'system:unauthenticated' in groups
        if anon and _allowed(e) and not str(e.get('request_uri', '')).startswith(_HEALTH_URIS):
            hunt.add('k8s_anonymous', f"Acces anonyme autorise : {verb} {e.get('target')}", 'high',
                     'T1078.001', [e], 'Requete non authentifiee acceptee par l\'API server '
                     '(liaison RBAC vers system:anonymous / system:unauthenticated).')
        if res == 'pods' and sub in ('exec', 'attach') and verb in ('create', 'get') and _allowed(e):
            hunt.add('k8s_exec', f"{sub} dans le pod {e.get('target')} par {user}",
                     'high' if sa or anon or e.get('namespace') == 'kube-system' else 'medium', 'T1609', [e],
                     'Commande interactive dans un conteneur'
                     + (' depuis un compte de service.' if sa else '.'))
        if res in _WORKLOADS and not sub and verb in ('create', 'update', 'patch') and _allowed(e) \
                and not (system and e.get('namespace') == 'kube-system'):
            spec = _pod_spec(e.get('_req'))
            reasons, critical = [], False
            for c in (spec.get('containers') or []) + (spec.get('initContainers') or []):
                sc = c.get('securityContext') or {} if isinstance(c, dict) else {}
                if sc.get('privileged'):
                    reasons.append(f"conteneur {c.get('name')} privilegie")
                caps = [str(x).upper() for x in (sc.get('capabilities') or {}).get('add') or []]
                if {'SYS_ADMIN', 'ALL', 'SYS_PTRACE', 'SYS_MODULE'} & set(caps):
                    reasons.append(f"capacites {','.join(caps)}")
            for flag in ('hostPID', 'hostNetwork', 'hostIPC'):
                if spec.get(flag):
                    reasons.append(flag)
                    critical = critical or flag == 'hostPID'
            for v in spec.get('volumes') or []:
                hp = (v.get('hostPath') or {}).get('path') if isinstance(v, dict) else None
                if hp:
                    reasons.append(f'hostPath {hp}')
                    critical = critical or (hp.rstrip('/') or '/') in _SENSITIVE_HOSTPATHS
            if reasons:
                hunt.add('k8s_privileged_workload', f"{res} {e.get('target')} cree avec "
                         f"{', '.join(reasons[:4])} par {user}", 'critical' if critical else 'high', 'T1611',
                         [e], 'Charge de travail permettant de s\'evader vers le noeud (privilegie, '
                         'espaces de noms de l\'hote, montage hostPath).', reasons=reasons)
        if res == 'secrets' and verb in ('list', 'watch', 'get') and not system:
            secrets_by_user[user].append(e)
        if res in ('clusterrolebindings', 'rolebindings') and verb in ('create', 'update', 'patch') \
                and _allowed(e):
            req = e.get('_req') or {}
            role = str((req.get('roleRef') or {}).get('name') or '')
            if role == 'cluster-admin' and not system:
                subjects = [f"{s.get('kind')}:{s.get('namespace', '')}/{s.get('name')}"
                            if s.get('namespace') else f"{s.get('kind')}:{s.get('name')}"
                            for s in req.get('subjects') or [] if isinstance(s, dict)]
                risky = sa or any(s.startswith('ServiceAccount') or 'system:anonymous' in s
                                  or 'unauthenticated' in s for s in subjects)
                hunt.add('k8s_cluster_admin_binding', f"Liaison cluster-admin {e.get('target')} vers "
                         f"{', '.join(subjects) or '?'} par {user}", 'critical' if risky else 'high',
                         'T1098.006', [e], 'Octroi du role cluster-admin : controle total du cluster.',
                         subjects=subjects)
    for user, evs in secrets_by_user.items():
        sa_ns = user.split(':')[2] if user.startswith('system:serviceaccount:') else None
        suspicious = [e for e in evs if (e.get('operation') in ('list', 'watch') and not e.get('namespace'))
                      or (sa_ns and e.get('namespace') and e.get('namespace') != sa_ns)]
        namespaces = {e.get('namespace') for e in evs if e.get('namespace')}
        if len(namespaces) >= 3:
            suspicious = evs
        if not suspicious:
            continue
        allowed = [e for e in suspicious if _allowed(e)]
        hunt.add('k8s_secrets_enum', f'Enumeration de secrets par {user}'
                 + (' (cluster entier)' if any(not e.get('namespace') for e in suspicious) else ''),
                 ('high' if sa_ns else 'medium') if allowed else 'medium', 'T1552.007', suspicious,
                 'Lecture de secrets hors de l\'espace de noms du compte ou a l\'echelle du cluster'
                 + ('' if allowed else ' (requetes refusees : tentative)') + '.')


# ============================================================================
# Point d'entree
# ============================================================================

RULES = {
    'm365_ual': (rule_password_spray, rule_mfa_fatigue, rule_single_factor, rule_legacy_auth,
                 rule_impossible_travel, rule_oauth_consent, rule_sp_credentials, rule_inbox_rules,
                 rule_mailbox_forwarding),
    'entra_signin': (rule_password_spray, rule_mfa_fatigue, rule_single_factor, rule_legacy_auth,
                     rule_impossible_travel),
    'entra_audit': (rule_oauth_consent, rule_sp_credentials),
    'aws_cloudtrail': (rule_aws_key_new_ip, rule_aws_logging, rule_aws_credentials, rule_aws_admin_policy,
                       rule_aws_console, rule_aws_secrets, rule_aws_region, rule_aws_s3),
    'gcp_audit': (rule_gcp,),
    'k8s_audit': (rule_k8s,),
}


def run(events, fmt, artifact):
    """Executer les detections applicables : (constats, alertes, notes, regles executees)."""
    hunt = Hunt(artifact)
    ctx = {'domains': internal_domains(events)}
    rules = RULES.get(fmt, ())
    for rule in rules:
        rule(events, hunt, ctx)
    if fmt == 'aws_cloudtrail':
        escalate_correlated(hunt, ctx)
    findings, alerts = hunt.result()
    return findings, alerts, hunt.notes, [r.__name__[5:] for r in rules]
