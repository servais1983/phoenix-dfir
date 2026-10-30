#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""/api/autonomous/* on top of the durable job queue: persistence across a
restart, listing and cancel access control, cooperative cancellation, quota."""

import io
import os
import tempfile
import time
import unittest
from unittest import mock


os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['PHOENIX_DEBUG'] = 'false'
os.environ.pop('REDIS_URL', None)

from tests.auth_helpers import add_member, bootstrap_admin, create_user  # noqa: E402


def _h(token):
    return {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}


class JobQueueApiTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import database
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')
        database.close_db()
        database.DB_PATH = cls.db_path
        database.init_db()

        from app import app
        app.config['TESTING'] = True
        cls.app = app
        cls.client = app.test_client()
        cls.admin = bootstrap_admin(cls.client, 'jq_admin', 'Admin-JobQ-Strong-2026!')['token']
        cls.alice_login = create_user(cls.client, cls.admin, 'jq_alice', 'Alice-JobQ-Strong-2026!')
        cls.alice = cls.alice_login['token']
        cls.alice_id = cls.alice_login['user']['id']
        cls.bob = create_user(cls.client, cls.admin, 'jq_bob', 'Bob-JobQ-Strong-2026!x')['token']
        cls.carol = create_user(cls.client, cls.admin, 'jq_carol', 'Carol-JobQ-Strong-2026!')['token']
        cls.victor = create_user(cls.client, cls.admin, 'jq_victor', 'Victor-JobQ-Strong-2026!',
                                 role='viewer')['token']

    @classmethod
    def tearDownClass(cls):
        import database
        database.close_db()
        os.close(cls.db_fd)
        os.unlink(cls.db_path)

    def setUp(self):
        import autonomous
        self.inv = self._inv(self.alice, 'Cas file durable')
        self._upload(self.alice, self.inv)
        add_member(self.client, self.alice, self.inv, 'jq_victor')   # viewer member
        add_member(self.client, self.alice, self.inv, 'jq_carol')    # analyst member
        self.patches = [mock.patch.object(autonomous, 'copilot_configured', return_value=True),
                        mock.patch.object(autonomous, '_wake_workers')]
        for p in self.patches:
            p.start()

    def tearDown(self):
        import autonomous
        import jobqueue
        for p in self.patches:
            p.stop()
        q = jobqueue.get_queue()
        for job in q.list(statuses=jobqueue.ACTIVE_STATUSES, limit=500):
            q.request_cancel(job['id'])
            if job['status'] == jobqueue.RUNNING:
                q.mark_cancelled(job['id'], job['worker'])
        autonomous.autonomous_jobs.clear()

    def _inv(self, token, name):
        resp = self.client.post('/api/investigations', json={'name': name}, headers=_h(token))
        self.assertEqual(resp.status_code, 201, resp.get_json())
        return resp.get_json()['id']

    def _upload(self, token, inv_id):
        data = {'file': (io.BytesIO(b'Failed password from 203.0.113.9\n'), 'auth.log'),
                'investigation_id': inv_id}
        resp = self.client.post('/api/upload', data=data, content_type='multipart/form-data',
                                headers={'Authorization': f'Bearer {token}'})
        self.assertEqual(resp.status_code, 200, resp.get_json())

    def _start(self, token=None, inv=None):
        resp = self.client.post('/api/autonomous/investigate',
                                json={'investigation_id': inv or self.inv, 'question': 'qui ?'},
                                headers=_h(token or self.alice))
        self.assertEqual(resp.status_code, 200, resp.get_json())
        return resp.get_json()['job_id']

    # ------------------------------------------------------------------

    def test_job_persiste_en_file_et_forme_historique(self):
        import jobqueue
        job_id = self._start()
        stored = jobqueue.get_queue().get(job_id)
        self.assertEqual(stored['status'], jobqueue.QUEUED)
        self.assertEqual(stored['owner_id'], self.alice_id)
        self.assertEqual(stored['investigation_id'], self.inv)
        self.assertEqual(stored['payload']['question'], 'qui ?')
        data = self.client.get(f'/api/autonomous/jobs/{job_id}', headers=_h(self.alice)).get_json()
        for key in ('job_id', 'investigation_id', 'status', 'messages', 'started_at'):
            self.assertIn(key, data)
        self.assertEqual(data['status'], 'queued')
        self.assertEqual(data['state'], 'queued')

    def test_job_termine_consultable_apres_redemarrage(self):
        import autonomous
        import jobqueue
        job_id = self._start()

        def fake_investigate(case_dir, question=None, on_step=None, on_tool=None, **kwargs):
            on_step('Analyse de auth.log')
            on_tool(1, 'parse_log_file', {'file_path': os.path.join(case_dir, 'auth.log')},
                    {'total': 1})
            report = os.path.join(case_dir, 'rapport_phoenix_test.md')
            with open(report, 'w', encoding='utf-8') as f:
                f.write('# Rapport\n\nBrute force depuis 203.0.113.7.\n')
            return {'summary': 'Brute force SSH.', 'report_path': report, 'steps': 2,
                    'tool_calls': [{'tool': 'parse_log_file'}]}

        with mock.patch('phoenix_dfir_mcp.investigator.investigate', side_effect=fake_investigate):
            self.assertEqual(jobqueue.get_queue().run_once('test-worker'), (job_id, jobqueue.DONE))

        # Simulated restart: the in-memory registry is gone
        autonomous.autonomous_jobs.clear()
        resp = self.client.get(f'/api/autonomous/jobs/{job_id}', headers=_h(self.alice))
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'completed')
        self.assertEqual(data['state'], 'done')
        self.assertTrue(data['report_id'].startswith('rapport_autonome_'))
        self.assertIn('203.0.113.7', data['report_content'])
        self.assertTrue(any('auth.log' in m for m in data['messages']))
        self.assertEqual(data['progress']['tools_executed'], 1)
        self.assertIn('finished_at', data)
        # The graph route reads the same registry and still finds the job
        self.assertIsNotNone(autonomous.autonomous_jobs.get(job_id))
        report_path = os.path.join(autonomous.REPORTS_DIR, data['report_id'])
        if os.path.exists(report_path):
            os.unlink(report_path)
        # Access control still applies to persisted jobs
        self.assertEqual(self.client.get(f'/api/autonomous/jobs/{job_id}',
                                         headers=_h(self.bob)).status_code, 404)

    def test_echec_persiste_comme_error(self):
        import autonomous
        import jobqueue
        job_id = self._start()
        with mock.patch('phoenix_dfir_mcp.investigator.investigate',
                        side_effect=RuntimeError('quota LLM depasse')):
            self.assertEqual(jobqueue.get_queue().run_once('w'), (job_id, jobqueue.FAILED))
        autonomous.autonomous_jobs.clear()
        data = self.client.get(f'/api/autonomous/jobs/{job_id}', headers=_h(self.alice)).get_json()
        self.assertEqual(data['status'], 'error')
        self.assertIn('quota LLM', data['error'])

    def test_liste_controle_d_acces(self):
        job_id = self._start()
        bob_inv = self._inv(self.bob, 'Cas de Bob')
        self._upload(self.bob, bob_inv)
        bob_job = self._start(self.bob, bob_inv)

        def ids(token, query=''):
            resp = self.client.get(f'/api/autonomous/jobs{query}', headers=_h(token))
            return resp.status_code, {j['job_id'] for j in (resp.get_json() or {}).get('items', [])}

        q = f'?investigation_id={self.inv}'
        self.assertEqual(ids(self.alice, q), (200, {job_id}))
        self.assertEqual(ids(self.victor, q), (200, {job_id}))       # viewer member reads
        self.assertEqual(ids(self.admin, q), (200, {job_id}))
        self.assertEqual(ids(self.bob, q)[0], 404)                   # not a member
        status, bob_ids = ids(self.bob)
        self.assertEqual(status, 200)
        self.assertIn(bob_job, bob_ids)
        self.assertNotIn(job_id, bob_ids)
        _, admin_ids = ids(self.admin)
        self.assertTrue({job_id, bob_job} <= admin_ids)
        _, alice_queued = ids(self.alice, '?status=queued')
        self.assertIn(job_id, alice_queued)
        self.assertEqual(self.client.get('/api/autonomous/jobs?status=bogus',
                                         headers=_h(self.alice)).status_code, 400)
        # Listing never ships report bodies
        items = self.client.get(f'/api/autonomous/jobs{q}', headers=_h(self.alice)).get_json()['items']
        self.assertNotIn('report_content', items[0])

    def test_annulation_controle_d_acces_job_en_file(self):
        job_id = self._start()
        url = f'/api/autonomous/jobs/{job_id}/cancel'
        self.assertEqual(self.client.post(url, headers=_h(self.bob)).status_code, 404)
        self.assertEqual(self.client.post(url, headers=_h(self.victor)).status_code, 403)
        resp = self.client.post(url, headers=_h(self.alice))
        self.assertEqual(resp.status_code, 200, resp.get_json())
        self.assertEqual(resp.get_json()['status'], 'cancelled')
        self.assertEqual(self.client.post(url, headers=_h(self.alice)).status_code, 409)
        data = self.client.get(f'/api/autonomous/jobs/{job_id}', headers=_h(self.alice)).get_json()
        self.assertEqual(data['status'], 'cancelled')
        self.assertEqual(self.client.post('/api/autonomous/jobs/nope/cancel',
                                          headers=_h(self.admin)).status_code, 404)

    def test_annulation_par_analyst_membre_et_admin(self):
        import jobqueue
        job_a = self._start()
        resp = self.client.post(f'/api/autonomous/jobs/{job_a}/cancel', headers=_h(self.carol))
        self.assertEqual(resp.status_code, 200)
        job_b = self._start()
        jobqueue.get_queue().claim('w-running')
        resp = self.client.post(f'/api/autonomous/jobs/{job_b}/cancel', headers=_h(self.admin))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()['status'], 'running')      # cooperative: flag set
        self.assertTrue(jobqueue.get_queue().is_cancel_requested(job_b))

    def test_annulation_cooperative_entre_etapes_de_l_enqueteur(self):
        import autonomous
        import jobqueue
        job_id = self._start()
        calls = []

        def fake_investigate(case_dir, question=None, on_step=None, on_tool=None, **kwargs):
            for i in range(50):
                calls.append(i)
                if i == 2:
                    jobqueue.get_queue().request_cancel(job_id)
                on_tool(i, 'parse_log_file', {}, {'total': i})   # checkpoint after each tool
                on_step(f'etape {i}')
            return {'summary': 'should not finish', 'report_path': None, 'steps': 50,
                    'tool_calls': []}

        with mock.patch('phoenix_dfir_mcp.investigator.investigate', side_effect=fake_investigate):
            self.assertEqual(jobqueue.get_queue().run_once('w'), (job_id, jobqueue.CANCELLED))
        self.assertEqual(calls, [0, 1, 2])
        data = self.client.get(f'/api/autonomous/jobs/{job_id}', headers=_h(self.alice)).get_json()
        self.assertEqual(data['status'], 'cancelled')
        self.assertNotIn('report_id', data)
        self.assertEqual(dict.get(autonomous.autonomous_jobs, job_id)['status'], 'cancelled')

    def test_quota_compte_les_jobs_en_file(self):
        with mock.patch.dict(os.environ, {'PHOENIX_MAX_JOBS_PER_USER': '1'}):
            self._start()
            resp = self.client.post('/api/autonomous/investigate',
                                    json={'investigation_id': self.inv}, headers=_h(self.alice))
            self.assertEqual(resp.status_code, 429)
            # Another user is not affected by alice's quota
            self.assertEqual(self.client.post('/api/autonomous/investigate',
                                              json={'investigation_id': self.inv},
                                              headers=_h(self.carol)).status_code, 200)
            status = self.client.get('/api/autonomous/status', headers=_h(self.alice)).get_json()
            self.assertEqual(status['my_jobs_running'], 1)
            self.assertGreaterEqual(status['jobs_queued'], 2)

    def test_reprise_apres_redemarrage_relance_le_job(self):
        import autonomous
        import jobqueue
        job_id = self._start()
        q = jobqueue.get_queue()
        q.claim('dead-process')
        conn = q._connect()
        conn.execute('UPDATE jobs SET heartbeat=? WHERE id=?', (time.time() - 3600, job_id))
        conn.close()
        autonomous.autonomous_jobs.clear()
        requeued, _failed = q.recover_stale()
        self.assertIn(job_id, requeued)

        def fake_investigate(case_dir, **kwargs):
            return {'summary': 'ok', 'report_path': None, 'steps': 1, 'tool_calls': []}

        with mock.patch('phoenix_dfir_mcp.investigator.investigate', side_effect=fake_investigate):
            self.assertEqual(q.run_once('new-process'), (job_id, jobqueue.DONE))
        data = self.client.get(f'/api/autonomous/jobs/{job_id}', headers=_h(self.alice)).get_json()
        self.assertEqual(data['status'], 'completed')
        self.assertEqual(data['attempts'], 2)
        self.assertTrue(any('Reprise' in m for m in data['messages']))
        report = data.get('report_id')
        if report and os.path.exists(os.path.join(autonomous.REPORTS_DIR, report)):
            os.unlink(os.path.join(autonomous.REPORTS_DIR, report))


if __name__ == '__main__':
    unittest.main(verbosity=2)
