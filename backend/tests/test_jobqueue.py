#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Durable job queue (jobqueue.py): atomic claims, recovery, cancellation, quota."""

import os
import tempfile
import threading
import time

import pytest


import jobqueue  # noqa: E402
from jobqueue import JobQueue  # noqa: E402


@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    yield path
    for suffix in ('', '-wal', '-shm'):
        try:
            os.unlink(path + suffix)
        except OSError:
            pass


def _queue(path, **kw):
    kw.setdefault('per_user_limit', 100)
    kw.setdefault('heartbeat_interval', 1)
    kw.setdefault('stale_after', 30)
    kw.setdefault('max_attempts', 2)
    return JobQueue(path, **kw)


def _set(path, job_id, **fields):
    import sqlite3
    conn = sqlite3.connect(path)
    sets = ', '.join(f'{k}=?' for k in fields)
    conn.execute(f'UPDATE jobs SET {sets} WHERE id=?', (*fields.values(), job_id))  # nosec - test helper
    conn.commit()
    conn.close()


def _wait(predicate, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_enqueue_get_and_json_fields(db_path):
    q = _queue(db_path)
    job_id = q.enqueue('demo', {'a': 1}, owner_id=7, owner_name='alice', investigation_id='inv-1')
    job = q.get(job_id)
    assert job['status'] == jobqueue.QUEUED
    assert job['payload'] == {'a': 1}
    assert job['owner_id'] == 7 and job['investigation_id'] == 'inv-1'
    assert job['attempts'] == 0 and job['cancel_requested'] is False
    assert q.get('missing') is None


def test_claim_atomique_avec_claimers_concurrents(db_path):
    q = _queue(db_path)
    ids = {q.enqueue('demo', {'n': i}) for i in range(60)}
    claimed = []
    lock = threading.Lock()
    barrier = threading.Barrier(8)

    def claimer(name):
        own = _queue(db_path)  # separate instance = separate connections
        barrier.wait()
        while True:
            job = own.claim(name)
            if job is None:
                return
            with lock:
                claimed.append(job['id'])

    threads = [threading.Thread(target=claimer, args=(f'w{i}',)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert len(claimed) == len(ids)
    assert set(claimed) == ids                     # every job claimed exactly once
    assert all(q.get(j)['status'] == jobqueue.RUNNING for j in ids)
    assert all(q.get(j)['attempts'] == 1 for j in ids)


def test_pool_de_workers_execute_chaque_job_une_fois(db_path):
    q = _queue(db_path, workers=4, poll_interval=0.05)
    runs = []
    lock = threading.Lock()

    def handler(job, ctx):
        with lock:
            runs.append(job['id'])
        time.sleep(0.01)
        return {'n': job['payload']['n'] * 2}

    q.register('demo', handler)
    ids = [q.enqueue('demo', {'n': i}) for i in range(20)]
    q.start()
    try:
        assert _wait(lambda: all(q.get(j)['status'] == jobqueue.DONE for j in ids))
    finally:
        q.stop()
    assert sorted(runs) == sorted(ids)
    assert q.get(ids[3])['result'] == {'n': 6}
    assert q.get(ids[3])['finished_at'] >= q.get(ids[3])['started_at']


def test_priorite_puis_fifo(db_path):
    q = _queue(db_path)
    low = q.enqueue('demo', priority=0)
    high = q.enqueue('demo', priority=5)
    low2 = q.enqueue('demo', priority=0)
    assert [q.claim()['id'] for _ in range(3)] == [high, low, low2]


def test_reprise_heartbeat_perime_requeue_une_fois_puis_echec(db_path):
    q = _queue(db_path, stale_after=30, max_attempts=2)
    job_id = q.enqueue('demo')
    fresh = q.enqueue('demo')
    assert q.claim('old-process')['id'] == job_id
    assert q.claim('old-process')['id'] == fresh
    # The process died: heartbeat far in the past for job_id only
    _set(db_path, job_id, heartbeat=time.time() - 3600)

    restarted = _queue(db_path, stale_after=30, max_attempts=2)
    requeued, failed = restarted.recover_stale()
    assert requeued == [job_id] and failed == []
    assert restarted.get(job_id)['status'] == jobqueue.QUEUED
    assert restarted.get(fresh)['status'] == jobqueue.RUNNING      # fresh heartbeat untouched

    second = restarted.claim('new-process')
    assert second['id'] == job_id and second['attempts'] == 2
    _set(db_path, job_id, heartbeat=time.time() - 3600)
    requeued, failed = _queue(db_path, stale_after=30, max_attempts=2).recover_stale()
    assert requeued == [] and failed == [job_id]
    job = q.get(job_id)
    assert job['status'] == jobqueue.FAILED and 'worker lost' in job['error']


def test_ancien_worker_ne_peut_pas_ecraser_un_job_repris(db_path):
    q = _queue(db_path)
    job_id = q.enqueue('demo')
    q.claim('old')
    _set(db_path, job_id, heartbeat=time.time() - 3600)
    q.recover_stale()
    q.claim('new')
    assert q.complete(job_id, 'old', {'stale': True}) is False   # lost its claim
    assert q.complete(job_id, 'new', {'ok': True}) is True
    assert q.get(job_id)['result'] == {'ok': True}


def test_start_reprend_et_execute_les_jobs_orphelins(db_path):
    q = _queue(db_path)
    job_id = q.enqueue('demo', {'x': 1})
    q.claim('crashed')
    _set(db_path, job_id, heartbeat=time.time() - 3600)
    restarted = _queue(db_path, workers=1, poll_interval=0.05)
    restarted.register('demo', lambda job, ctx: {'resumed': job['attempts']})
    restarted.start()
    try:
        assert _wait(lambda: restarted.get(job_id)['status'] == jobqueue.DONE)
    finally:
        restarted.stop()
    assert restarted.get(job_id)['result'] == {'resumed': 2}


def test_heartbeat_maintient_un_job_long_en_vie(db_path):
    q = _queue(db_path, workers=1, heartbeat_interval=1, stale_after=1, poll_interval=0.05)
    release = threading.Event()
    q.register('slow', lambda job, ctx: release.wait(5) and {'ok': True})
    job_id = q.enqueue('slow')
    q.start()
    try:
        assert _wait(lambda: q.get(job_id)['status'] == jobqueue.RUNNING)
        first = q.get(job_id)['heartbeat']
        time.sleep(2.3)
        # Heartbeats advanced and the reaper did not re-queue the live job
        job = q.get(job_id)
        assert job['status'] == jobqueue.RUNNING and job['heartbeat'] > first
        assert job['attempts'] == 1
        release.set()
        assert _wait(lambda: q.get(job_id)['status'] == jobqueue.DONE)
    finally:
        release.set()
        q.stop()


def test_annulation_job_en_file(db_path):
    q = _queue(db_path)
    job_id = q.enqueue('demo')
    assert q.request_cancel(job_id) == jobqueue.CANCELLED
    assert q.get(job_id)['status'] == jobqueue.CANCELLED
    assert q.claim() is None                     # never runs
    assert q.request_cancel('missing') is None


def test_annulation_cooperative_job_en_cours(db_path):
    q = _queue(db_path, workers=1, poll_interval=0.05)
    started = threading.Event()
    phases = []

    def handler(job, ctx):
        for phase in range(500):
            started.set()
            ctx.check_cancel()                   # checkpoint between phases
            phases.append(phase)
            time.sleep(0.01)
        return {'finished': True}

    q.register('long', handler)
    job_id = q.enqueue('long')
    q.start()
    try:
        assert started.wait(5)
        assert q.request_cancel(job_id) == jobqueue.RUNNING
        assert q.is_cancel_requested(job_id)
        assert _wait(lambda: q.get(job_id)['status'] == jobqueue.CANCELLED)
    finally:
        q.stop()
    assert len(phases) < 500
    assert q.get(job_id)['result'] is None


def test_job_cancelled_traverse_except_exception():
    """The investigator swallows Exception from callbacks: cancellation must not be."""
    def swallowing():
        try:
            raise jobqueue.JobCancelled('x')
        except Exception:  # noqa: BLE001 - this is what the engine does
            return 'swallowed'
    with pytest.raises(jobqueue.JobCancelled):
        swallowing()


def test_echec_handler_et_type_inconnu(db_path):
    q = _queue(db_path)

    def boom(job, ctx):
        raise RuntimeError('volatility a plante')

    q.register('boom', boom)
    failing = q.enqueue('boom')
    unknown = q.enqueue('nope')
    assert q.run_once('w') == (failing, jobqueue.FAILED)
    assert 'volatility' in q.get(failing)['error']
    assert q.run_once('w') == (unknown, jobqueue.FAILED)
    assert 'no handler' in q.get(unknown)['error']
    assert q.run_once('w') is None


def test_quota_par_utilisateur_au_claim(db_path):
    q = _queue(db_path, per_user_limit=1)
    a1 = q.enqueue('demo', owner_id=1)
    a2 = q.enqueue('demo', owner_id=1)
    b1 = q.enqueue('demo', owner_id=2)
    system = q.enqueue('demo')                   # inbox watcher job: no owner, no quota
    assert q.claim('w')['id'] == a1
    assert q.claim('w')['id'] == b1              # a2 skipped: user 1 at its limit
    assert q.claim('w')['id'] == system
    assert q.claim('w') is None
    assert q.count_active(owner_id=1) == 2
    assert q.active_ids(1) == {a1, a2}
    q.complete(a1, 'w', {})
    assert q.claim('w')['id'] == a2


def test_quota_par_defaut_lu_dans_l_environnement(db_path, monkeypatch):
    monkeypatch.setenv('PHOENIX_MAX_JOBS_PER_USER', '3')
    assert JobQueue(db_path).per_user_limit == 3
    monkeypatch.setenv('PHOENIX_MAX_JOBS_PER_USER', 'abc')
    assert JobQueue(db_path).per_user_limit == 2


def test_liste_filtree_par_enquete_et_proprietaire(db_path):
    q = _queue(db_path)
    mine = q.enqueue('demo', owner_id=1, investigation_id='inv-a')
    shared = q.enqueue('demo', owner_id=2, investigation_id='inv-b')
    other = q.enqueue('demo', owner_id=3, investigation_id='inv-c')
    assert [j['id'] for j in q.list(investigation_id='inv-b')] == [shared]
    visible = {j['id'] for j in q.list(owner_id=1, investigation_ids=['inv-b'])}
    assert visible == {mine, shared}
    assert {j['id'] for j in q.list(owner_id=9, investigation_ids=[])} == set()
    assert {j['id'] for j in q.list()} == {mine, shared, other}
    q.request_cancel(other)
    assert [j['id'] for j in q.list(statuses=(jobqueue.CANCELLED,))] == [other]


def test_evenements_emis_vers_la_salle_de_l_enquete(db_path):
    events = []
    q = _queue(db_path, emitter=lambda event, data, inv, owner: events.append((event, data, inv, owner)))
    job_id = q.enqueue('demo', owner_id=4, investigation_id='inv-z')
    q.update_progress(job_id, {'message': 'phase 1'})
    q.request_cancel(job_id)
    kinds = [(e[0], e[1]['status']) for e in events]
    assert ('job_status', 'queued') in kinds
    assert ('job_progress', 'queued') in kinds
    assert ('job_status', 'cancelled') in kinds
    assert all(e[2] == 'inv-z' and e[3] == 4 for e in events)
    assert events[1][1]['progress'] == {'message': 'phase 1'}


def test_schema_cree_par_init_db():
    import sqlite3
    import database
    fd, path = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    saved = database.DB_PATH
    try:
        database.close_db()
        database.DB_PATH = path
        database.init_db()
        cols = {r[1] for r in sqlite3.connect(path).execute('PRAGMA table_info(jobs)')}
        assert {'id', 'kind', 'payload', 'status', 'owner_id', 'investigation_id', 'priority',
                'attempts', 'progress', 'result', 'error', 'created_at', 'started_at',
                'finished_at', 'heartbeat', 'cancel_requested'} <= cols
    finally:
        database.close_db()
        database.DB_PATH = saved
        os.unlink(path)
