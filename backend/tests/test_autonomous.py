#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de l'enqueteur autonome cote plateforme : routes API, runner de job
et watcher du dossier de depot."""

import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

os.environ['PHOENIX_SECRET_KEY'] = 'test-secret-key-for-testing-only'
os.environ['PHOENIX_DEBUG'] = 'false'


class AutonomousTestCase(unittest.TestCase):
    """Tests des routes /api/autonomous et du pipeline autonome."""

    @classmethod
    def setUpClass(cls):
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')

        import database
        database.DB_PATH = cls.db_path
        database.init_db()

        from app import app
        app.config['TESTING'] = True
        cls.app = app
        cls.client = app.test_client()

        from tests.auth_helpers import bootstrap_admin
        cls.token = bootstrap_admin(cls.client, 'auto_tester', 'Phx-Auto-Test-2026!',
                                    'Auto Tester')['token']

    @classmethod
    def tearDownClass(cls):
        os.close(cls.db_fd)
        os.unlink(cls.db_path)

    def _headers(self):
        return {'Authorization': f'Bearer {self.token}', 'Content-Type': 'application/json'}

    def _create_investigation(self, name='Cas autonome'):
        resp = self.client.post('/api/investigations', json={'name': name}, headers=self._headers())
        return resp.get_json()['id']

    def _attach_artifact(self, investigation_id, content=b'Failed password from 203.0.113.7\n'):
        import database
        fd, path = tempfile.mkstemp(suffix='.log')
        with os.fdopen(fd, 'wb') as f:
            f.write(content)
        with self.app.app_context():
            db = database.get_db()
            db.execute(
                "INSERT INTO artifacts (investigation_id, filename, original_filename, file_path, file_size, file_type) VALUES (?, ?, ?, ?, ?, ?)",
                (investigation_id, os.path.basename(path), 'auth.log', path, len(content), '.log'),
            )
            db.commit()
        return path

    # ------------------------------------------------------------------
    # Route status
    # ------------------------------------------------------------------

    def test_status_endpoint(self):
        resp = self.client.get('/api/autonomous/status', headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn('copilot_configured', data)
        self.assertIn('inbox_dir', data)
        self.assertIn('model', data)

    def test_status_requiert_auth(self):
        resp = self.client.get('/api/autonomous/status')
        self.assertEqual(resp.status_code, 401)

    # ------------------------------------------------------------------
    # Route investigate : validations
    # ------------------------------------------------------------------

    def test_investigate_sans_jeton_github(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('GITHUB_TOKEN', None)
            os.environ.pop('PHOENIX_GITHUB_TOKEN', None)
            inv_id = self._create_investigation()
            resp = self.client.post('/api/autonomous/investigate',
                                    json={'investigation_id': inv_id}, headers=self._headers())
        self.assertEqual(resp.status_code, 400)
        self.assertIn('GITHUB_TOKEN', resp.get_json()['error'])

    def test_investigate_enquete_inconnue(self):
        with mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'github_pat_test'}):
            resp = self.client.post('/api/autonomous/investigate',
                                    json={'investigation_id': 'inexistante'}, headers=self._headers())
        self.assertEqual(resp.status_code, 404)

    def test_investigate_sans_artefact(self):
        inv_id = self._create_investigation('Cas vide')
        with mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'github_pat_test'}):
            resp = self.client.post('/api/autonomous/investigate',
                                    json={'investigation_id': inv_id}, headers=self._headers())
        self.assertEqual(resp.status_code, 400)
        self.assertIn('artefact', resp.get_json()['error'].lower())

    def test_investigate_demarre_un_job(self):
        import autonomous
        inv_id = self._create_investigation('Cas avec artefact')
        self._attach_artifact(inv_id)
        with mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'github_pat_test'}), \
                mock.patch.object(autonomous, '_wake_workers') as submit:
            resp = self.client.post('/api/autonomous/investigate',
                                    json={'investigation_id': inv_id}, headers=self._headers())
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['status'], 'started')
        self.assertTrue(submit.called)
        # Le job est persiste en file durable, suivi et consultable
        job_resp = self.client.get(f"/api/autonomous/jobs/{data['job_id']}", headers=self._headers())
        self.assertEqual(job_resp.status_code, 200)
        self.assertIn(job_resp.get_json()['status'], ('queued', 'running'))
        autonomous.cancel_job(data['job_id'])

    def test_job_inconnu(self):
        resp = self.client.get('/api/autonomous/jobs/xyz', headers=self._headers())
        self.assertEqual(resp.status_code, 404)

    # ------------------------------------------------------------------
    # Runner complet (investigator GitHub Copilot simule)
    # ------------------------------------------------------------------

    def test_run_job_complet(self):
        import autonomous
        import database

        inv_id = self._create_investigation('Cas runner')
        self._attach_artifact(inv_id)

        def fake_investigate(case_dir, question=None, on_step=None, **kwargs):
            # Les artefacts doivent avoir ete copies dans le dossier du cas
            assert any(f == 'auth.log' for f in os.listdir(case_dir))
            if on_step:
                on_step('Analyse de auth.log')
            report = os.path.join(case_dir, 'rapport_phoenix_test.md')
            with open(report, 'w', encoding='utf-8') as f:
                f.write('# Rapport\n\nBrute force depuis 203.0.113.7 (evil-c2.xyz).\n')
            return {'summary': 'Brute force SSH confirmee.', 'report_path': report,
                    'steps': 3, 'tool_calls': [{'tool': 'parse_log_file'}]}

        with mock.patch('phoenix_dfir_mcp.investigator.investigate', side_effect=fake_investigate):
            job_id = 'job-test-runner'
            autonomous.autonomous_jobs[job_id] = {'job_id': job_id, 'status': 'running', 'messages': []}
            autonomous._run_job(self.app, job_id, inv_id, None, None, 'tester')

        job = autonomous.autonomous_jobs[job_id]
        self.assertEqual(job['status'], 'completed')
        self.assertIn('Brute force', job['summary'])
        self.assertTrue(job['report_id'].startswith('rapport_autonome_'))
        self.assertIn('203.0.113.7', job['report_content'])

        # Rapport ecrit dans backend/reports/
        report_path = os.path.join(autonomous.REPORTS_DIR, job['report_id'])
        self.assertTrue(os.path.exists(report_path))
        os.unlink(report_path)

        # IoCs du rapport inseres en base + evenement timeline
        with self.app.app_context():
            db = database.get_db()
            iocs = db.execute("SELECT type, value FROM iocs WHERE investigation_id=?", (inv_id,)).fetchall()
            values = {row['value'] for row in iocs}
            self.assertIn('203.0.113.7', values)
            events = db.execute("SELECT event FROM timeline_events WHERE investigation_id=?", (inv_id,)).fetchall()
            self.assertTrue(any('autonome' in row['event'] for row in events))

    def test_run_job_erreur_investigator(self):
        import autonomous
        inv_id = self._create_investigation('Cas en erreur')
        self._attach_artifact(inv_id)
        with mock.patch('phoenix_dfir_mcp.investigator.investigate',
                        side_effect=RuntimeError('quota depasse')):
            job_id = 'job-test-erreur'
            autonomous.autonomous_jobs[job_id] = {'job_id': job_id, 'status': 'running', 'messages': []}
            autonomous._run_job(self.app, job_id, inv_id, None, None, 'tester')
        job = autonomous.autonomous_jobs[job_id]
        self.assertEqual(job['status'], 'error')
        self.assertIn('quota', job['error'])


    def test_run_job_racines_propres_au_job(self):
        """Le coffre n'est jamais ajoute globalement : seules les evidences du coffre
        referencees par CE cas sont autorisees, et uniquement pendant le job."""
        import autonomous
        import database
        from phoenix_dfir_mcp import pathpolicy
        vault = tempfile.mkdtemp(prefix='phoenix_vault_test_')
        mine = os.path.join(vault, 'mine.log')
        other = os.path.join(vault, 'other_case.log')
        for path in (mine, other):
            with open(path, 'w') as f:
                f.write('Failed password from 203.0.113.7\n')
        inv_id = self._create_investigation('Cas coffre')
        with self.app.app_context():
            db = database.get_db()
            db.execute("INSERT INTO artifacts (investigation_id, filename, original_filename, file_path, "
                       "file_size, file_type) VALUES (?, ?, ?, ?, ?, ?)",
                       (inv_id, 'mine.log', 'mine.log', mine, 33, '.log'))
            db.commit()
        seen = {}

        def fake_investigate(case_dir, **kwargs):
            seen['case'] = pathpolicy.current_case()
            seen['mine'] = pathpolicy.is_allowed(os.path.join(case_dir, 'mine.log'))
            seen['other'] = pathpolicy.is_allowed(other)
            seen['vault'] = pathpolicy.is_allowed(vault)
            return {'summary': 'ok', 'report_path': None, 'steps': 1, 'tool_calls': []}

        pathpolicy.reset()
        with mock.patch.dict(os.environ, {'PHOENIX_EVIDENCE_VAULT': vault}), \
                mock.patch('phoenix_dfir_mcp.investigator.investigate', side_effect=fake_investigate):
            job_id = 'job-test-coffre'
            autonomous.autonomous_jobs[job_id] = {'job_id': job_id, 'status': 'running', 'messages': []}
            autonomous._run_job(self.app, job_id, inv_id, None, None, 'tester')
        self.assertEqual(autonomous.autonomous_jobs[job_id]['status'], 'completed')
        self.assertTrue(seen['case'].endswith(inv_id))
        self.assertTrue(seen['mine'])
        self.assertFalse(seen['other'])   # evidence d'un autre cas dans le coffre
        self.assertFalse(seen['vault'])
        # Apres le job : aucun perimetre residuel, aucune racine globale ajoutee
        self.assertIsNone(pathpolicy.current_job())
        self.assertEqual(pathpolicy.active_roots(), set())
        report = autonomous.autonomous_jobs[job_id].get('report_id')
        if report and os.path.exists(os.path.join(autonomous.REPORTS_DIR, report)):
            os.unlink(os.path.join(autonomous.REPORTS_DIR, report))

    def test_registre_des_jobs_borne(self):
        import datetime
        import autonomous
        saved = dict(autonomous.autonomous_jobs)
        try:
            autonomous.autonomous_jobs.clear()
            now = datetime.datetime(2026, 10, 15, 12, 0, 0)
            autonomous.autonomous_jobs['running'] = {'status': 'running',
                                                     'started_at': '2020-01-01T00:00:00'}
            autonomous.autonomous_jobs['old'] = {'status': 'completed',
                                                 'finished_at': '2026-10-13T12:00:00'}
            for i in range(5):
                autonomous.autonomous_jobs[f'f{i}'] = {
                    'status': 'completed', 'finished_at': f'2026-10-15T11:0{i}:00'}
            evicted = autonomous.prune_jobs(now=now, max_finished=3, ttl_seconds=24 * 3600)
            self.assertEqual(evicted, 3)
            self.assertEqual(set(autonomous.autonomous_jobs), {'running', 'f2', 'f3', 'f4'})
        finally:
            autonomous.autonomous_jobs.clear()
            autonomous.autonomous_jobs.update(saved)


class WatcherTestCase(unittest.TestCase):
    """Tests du dossier de depot surveille."""

    @classmethod
    def setUpClass(cls):
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix='.db')
        import database
        database.DB_PATH = cls.db_path
        database.init_db()
        from app import app
        app.config['TESTING'] = True
        cls.app = app

    @classmethod
    def tearDownClass(cls):
        os.close(cls.db_fd)
        os.unlink(cls.db_path)

    def setUp(self):
        self.inbox = tempfile.mkdtemp(prefix='phoenix_inbox_test_')
        self.env = mock.patch.dict(os.environ, {'PHOENIX_EVIDENCE_DIR': self.inbox})
        self.env.start()
        os.environ.pop('GITHUB_TOKEN', None)
        os.environ.pop('PHOENIX_GITHUB_TOKEN', None)

    def tearDown(self):
        self.env.stop()

    def test_scan_ignore_lisezmoi_et_fichiers_partiels(self):
        import watcher
        open(os.path.join(self.inbox, 'LISEZMOI.txt'), 'w').close()
        open(os.path.join(self.inbox, 'transfert.part'), 'w').close()
        open(os.path.join(self.inbox, 'evidence.log'), 'w').close()
        entries = watcher._scan_entries()
        self.assertEqual([os.path.basename(p) for p, _ in entries], ['evidence.log'])

    def test_liens_symboliques_refuses(self):
        """Un lien symbolique depose (fichier ou dossier) n'est jamais suivi."""
        import watcher
        secret_dir = tempfile.mkdtemp(prefix='phoenix_secret_')
        secret = os.path.join(secret_dir, 'shadow')
        with open(secret, 'w') as f:
            f.write('root:$6$secret')
        os.symlink(secret, os.path.join(self.inbox, 'shadow.log'))
        os.symlink(secret_dir, os.path.join(self.inbox, 'dossier_lien'))
        case = os.path.join(self.inbox, 'cas')
        os.makedirs(case)
        with open(os.path.join(case, 'auth.log'), 'w') as f:
            f.write('Failed password from 198.51.100.9\n')
        os.symlink(secret, os.path.join(case, 'shadow.txt'))
        os.symlink(secret_dir, os.path.join(case, 'sous_lien'))

        entries = watcher._scan_entries()
        self.assertEqual([(os.path.basename(p), d) for p, d in entries], [('cas', True)])
        files = list(watcher._iter_files(case, True))
        self.assertEqual([os.path.basename(p) for p in files], ['auth.log'])
        # Les liens sont retires de l'inbox, leurs cibles intactes
        self.assertFalse(os.path.lexists(os.path.join(self.inbox, 'shadow.log')))
        self.assertFalse(os.path.lexists(os.path.join(case, 'shadow.txt')))
        self.assertTrue(os.path.exists(secret))
        # _create_case refuse aussi un lien passe directement
        os.symlink(secret, os.path.join(self.inbox, 'direct.log'))
        with mock.patch('autonomous.copilot_configured', return_value=False):
            watcher._create_case(self.app, 'Lien direct', [os.path.join(self.inbox, 'direct.log')])
        self.assertFalse(os.path.lexists(os.path.join(self.inbox, 'direct.log')))
        self.assertTrue(os.path.exists(secret))

    def test_depot_fichiers_cree_une_enquete(self):
        import database
        import watcher
        with open(os.path.join(self.inbox, 'auth.log'), 'w') as f:
            f.write('Failed password from 198.51.100.9\n')

        entries = watcher._scan_entries()
        watcher._process_entries(self.app, entries)

        # Fichier deplace hors de l'inbox
        self.assertFalse(os.path.exists(os.path.join(self.inbox, 'auth.log')))
        with self.app.app_context():
            db = database.get_db()
            inv = db.execute(
                "SELECT * FROM investigations WHERE description LIKE '%dossier de depot%' ORDER BY created_at DESC"
            ).fetchone()
            self.assertIsNotNone(inv)
            arts = db.execute("SELECT * FROM artifacts WHERE investigation_id=?", (inv['id'],)).fetchall()
            self.assertEqual(len(arts), 1)
            self.assertEqual(arts[0]['original_filename'], 'auth.log')
            self.assertTrue(os.path.exists(arts[0]['file_path']))
            self.assertEqual(len(arts[0]['file_hash_sha256']), 64)

    def test_depot_dossier_devient_un_cas_nomme(self):
        import database
        import watcher
        case_folder = os.path.join(self.inbox, 'incident-serveur-web')
        os.makedirs(case_folder)
        with open(os.path.join(case_folder, 'access.log'), 'w') as f:
            f.write('GET /shell.php 200\n')

        watcher._process_entries(self.app, watcher._scan_entries())

        self.assertFalse(os.path.exists(case_folder))
        with self.app.app_context():
            db = database.get_db()
            inv = db.execute("SELECT * FROM investigations WHERE name='incident-serveur-web'").fetchone()
            self.assertIsNotNone(inv)

    def test_depot_lance_l_enqueteur_si_copilot_configure(self):
        import autonomous
        import watcher
        with open(os.path.join(self.inbox, 'security.csv'), 'w') as f:
            f.write('a,b\n1,2\n')
        with mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'github_pat_test'}), \
                mock.patch.object(autonomous, 'start_job') as start_job:
            watcher._process_entries(self.app, watcher._scan_entries())
        self.assertTrue(start_job.called)

    def test_start_watcher_desactive_par_env(self):
        import watcher
        with mock.patch.dict(os.environ, {'PHOENIX_INBOX_ENABLED': 'false'}):
            self.assertIsNone(watcher.start_watcher(self.app))


if __name__ == '__main__':
    unittest.main()
