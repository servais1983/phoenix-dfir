#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Attack graph API: access control, v1 contract validation, caps and the
'graph_updated' live update."""

import json
import os
import shutil
import tempfile
import unittest
from unittest import mock


os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['PHOENIX_DEBUG'] = 'false'

SAMPLE = {
    'version': 1,
    'generated_at': '2026-03-01T10:00:00Z',
    'nodes': [
        {'id': 'user:jdoe', 'type': 'user', 'label': 'jdoe', 'first_seen': '2026-03-01T08:00:00Z',
         'last_seen': None, 'malicious': False, 'technique_ids': [], 'finding_ids': []},
        {'id': 'host:SRV-01', 'type': 'host', 'label': 'SRV-01', 'first_seen': '2026-03-01T08:05:00Z',
         'last_seen': '2026-03-01T09:00:00Z', 'malicious': True,
         'technique_ids': ['T1059.001', 'bogus', 't1003'], 'finding_ids': [1, '2', -3, True]},
        {'id': 'ip:203.0.113.9', 'type': 'ip', 'label': '203.0.113.9', 'malicious': True},
    ],
    'edges': [
        {'id': 'e1', 'source': 'user:jdoe', 'target': 'host:SRV-01', 'type': 'authenticated_to',
         'first_seen': '2026-03-01T08:05:00Z', 'last_seen': None,
         'refs': [{'artifact': 'Security.evtx', 'kind': 'record_id', 'value': '4624'}],
         'technique_ids': ['T1078'], 'finding_ids': [1]},
        {'id': 'e2', 'source': 'host:SRV-01', 'target': 'ip:203.0.113.9', 'type': 'Connected To!',
         'first_seen': 'not-a-date'},
        {'id': 'e3', 'source': 'host:SRV-01', 'target': 'ghost', 'type': 'x'},
    ],
    'patient_zero': {'node': 'host:SRV-01', 'timestamp': '2026-03-01T08:05:00Z',
                     'path': ['user:jdoe', 'host:SRV-01', 'ghost']},
    'blast_radius': {'seed': 'host:SRV-01', 'nodes': ['host:SRV-01', 'ip:203.0.113.9', 'nope']},
}


class AttackGraphSanitizeTest(unittest.TestCase):

    def test_contract_sanitized(self):
        import attack_graph
        g = attack_graph.sanitize(SAMPLE)
        self.assertEqual(g['version'], 1)
        self.assertEqual([n['id'] for n in g['nodes']], ['user:jdoe', 'host:SRV-01', 'ip:203.0.113.9'])
        srv = g['nodes'][1]
        self.assertEqual(srv['technique_ids'], ['T1059.001', 'T1003'])
        self.assertEqual(srv['finding_ids'], [1, 2])
        self.assertTrue(srv['malicious'])
        self.assertEqual([e['id'] for e in g['edges']], ['e1', 'e2'])  # dangling edge dropped
        self.assertEqual(g['edges'][1]['type'], 'related_to')
        self.assertIsNone(g['edges'][1]['first_seen'])
        self.assertEqual(g['edges'][0]['refs'][0]['value'], '4624')
        self.assertEqual(g['patient_zero']['path'], ['user:jdoe', 'host:SRV-01'])
        self.assertEqual(g['blast_radius']['nodes'], ['host:SRV-01', 'ip:203.0.113.9'])
        self.assertEqual(g['truncated'], {'nodes': False, 'edges': False})

    def test_caps_and_garbage(self):
        import attack_graph
        nodes = [{'id': f'n{i}', 'type': 'weird', 'label': 'x\x00y' * 200} for i in range(2100)]
        edges = [{'source': 'n0', 'target': f'n{i % 50}'} for i in range(5100)]
        g = attack_graph.sanitize({'version': 1, 'nodes': nodes + ['junk', {'id': 'n1'}], 'edges': edges})
        self.assertEqual(len(g['nodes']), attack_graph.MAX_NODES)
        self.assertEqual(len(g['edges']), attack_graph.MAX_EDGES)
        self.assertTrue(g['truncated']['nodes'])
        self.assertTrue(g['truncated']['edges'])
        self.assertEqual(g['nodes'][0]['type'], 'other')
        self.assertLessEqual(len(g['nodes'][0]['label']), 256)
        self.assertNotIn('\x00', g['nodes'][0]['label'])
        self.assertEqual(len({e['id'] for e in g['edges']}), len(g['edges']))

    def test_bad_version_rejected(self):
        import attack_graph
        with self.assertRaises(attack_graph.GraphError):
            attack_graph.sanitize({'version': 2, 'nodes': []})
        with self.assertRaises(attack_graph.GraphError):
            attack_graph.sanitize(['not', 'an', 'object'])


class AttackGraphApiTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')
        cls.uploads = tempfile.mkdtemp(prefix='phoenix_graph_')
        import database
        database.DB_PATH = cls.db_path
        database.init_db()
        from app import app
        app.config['TESTING'] = True
        cls._old_upload = app.config['UPLOAD_FOLDER']
        app.config['UPLOAD_FOLDER'] = cls.uploads
        cls.app = app
        cls.client = app.test_client()
        from tests.auth_helpers import add_member, bootstrap_admin, create_user
        cls.admin = bootstrap_admin(cls.client, 'graph_admin', 'Graph-Admin-2026!')['token']
        cls.analyst = create_user(cls.client, cls.admin, 'graph_analyst', 'Graph-Analyst-2026!')['token']
        cls.viewer = create_user(cls.client, cls.admin, 'graph_viewer', 'Graph-Viewer-2026!',
                                 role='viewer')['token']
        cls.outsider = create_user(cls.client, cls.admin, 'graph_out', 'Graph-Outsider-2026!')['token']
        resp = cls.client.post('/api/investigations', json={'name': 'Graph case'},
                               headers={'Authorization': f'Bearer {cls.analyst}'})
        cls.inv = resp.get_json()['id']
        add_member(cls.client, cls.analyst, cls.inv, 'graph_viewer')

    @classmethod
    def tearDownClass(cls):
        cls.app.config['UPLOAD_FOLDER'] = cls._old_upload
        shutil.rmtree(cls.uploads, ignore_errors=True)
        os.close(cls.db_fd)
        os.unlink(cls.db_path)

    def _h(self, token):
        return {'Authorization': f'Bearer {token}'}

    def _write_graph(self, data):
        case_dir = os.path.join(self.uploads, 'cases', self.inv)
        os.makedirs(case_dir, exist_ok=True)
        with open(os.path.join(case_dir, 'entity_graph.json'), 'w', encoding='utf-8') as f:
            f.write(data if isinstance(data, str) else json.dumps(data))
        return case_dir

    def _remove_graph(self):
        shutil.rmtree(os.path.join(self.uploads, 'cases', self.inv), ignore_errors=True)

    def test_not_built_is_404_with_message(self):
        self._remove_graph()
        resp = self.client.get(f'/api/investigations/{self.inv}/graph', headers=self._h(self.analyst))
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.get_json()['code'], 'graph_not_built')

    def test_member_viewer_and_admin_read(self):
        self._write_graph(SAMPLE)
        for token in (self.analyst, self.viewer, self.admin):
            resp = self.client.get(f'/api/investigations/{self.inv}/graph', headers=self._h(token))
            self.assertEqual(resp.status_code, 200)
            body = resp.get_json()
            self.assertEqual(body['investigation_id'], self.inv)
            self.assertEqual(len(body['nodes']), 3)
            self.assertEqual(body['patient_zero']['node'], 'host:SRV-01')

    def test_non_member_gets_404(self):
        self._write_graph(SAMPLE)
        resp = self.client.get(f'/api/investigations/{self.inv}/graph', headers=self._h(self.outsider))
        self.assertEqual(resp.status_code, 404)
        self.assertNotIn('nodes', resp.get_json())
        resp = self.client.get('/api/investigations/../../etc/graph', headers=self._h(self.admin))
        self.assertEqual(resp.status_code, 404)

    def test_invalid_json_is_422(self):
        self._write_graph('{not json')
        resp = self.client.get(f'/api/investigations/{self.inv}/graph', headers=self._h(self.analyst))
        self.assertEqual(resp.status_code, 422)

    def test_job_graph_access(self):
        import autonomous
        self._write_graph(SAMPLE)
        autonomous.autonomous_jobs['job-graph-1'] = {
            'job_id': 'job-graph-1', 'investigation_id': self.inv, 'status': 'running', 'messages': []}
        try:
            ok = self.client.get('/api/autonomous/jobs/job-graph-1/graph', headers=self._h(self.viewer))
            self.assertEqual(ok.status_code, 200)
            self.assertEqual(ok.get_json()['job_id'], 'job-graph-1')
            denied = self.client.get('/api/autonomous/jobs/job-graph-1/graph', headers=self._h(self.outsider))
            self.assertEqual(denied.status_code, 404)
            missing = self.client.get('/api/autonomous/jobs/nope/graph', headers=self._h(self.admin))
            self.assertEqual(missing.status_code, 404)
        finally:
            autonomous.autonomous_jobs.pop('job-graph-1', None)

    def test_graph_updated_emitted_on_mtime_change(self):
        import autonomous
        from routes import graph as graph_routes
        case_dir = self._write_graph(SAMPLE)
        autonomous.autonomous_jobs['job-graph-2'] = {
            'job_id': 'job-graph-2', 'investigation_id': self.inv, 'status': 'running', 'messages': []}
        graph_routes._last_mtimes.pop(self.inv, None)
        try:
            with mock.patch.object(graph_routes, 'emit_secure') as emit:
                events = graph_routes.check_graph_updates(self.app)
                self.assertEqual(len(events), 1)
                emit.assert_called_once()
                self.assertEqual(emit.call_args[0][0], 'graph_updated')
                self.assertEqual(emit.call_args[1]['investigation_id'], self.inv)
                # Unchanged file: no new event
                self.assertEqual(graph_routes.check_graph_updates(self.app), [])
                path = os.path.join(case_dir, 'entity_graph.json')
                st = os.stat(path)
                os.utime(path, (st.st_atime, st.st_mtime + 10))
                self.assertEqual(len(graph_routes.check_graph_updates(self.app)), 1)
        finally:
            autonomous.autonomous_jobs.pop('job-graph-2', None)


if __name__ == '__main__':
    unittest.main()
