#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phoenix DFIR - Durable job queue for heavy work (SQLite backed).

Heavy jobs (autonomous investigations running Volatility, Hayabusa, disk
images, PCAP parsing) are persisted in the `jobs` table of the main SQLite
database and executed by a small, bounded pool of worker threads that is
separate from the threads serving HTTP and WebSocket requests, so a long
investigation can never starve the web server.

Why SQLite and not Redis, even when REDIS_URL is configured:
- Phoenix runs as a single node (one gunicorn worker, Socket.IO needs sticky
  sessions), so a distributed broker brings no throughput benefit;
- SQLite with WAL is durable on disk and already holds the investigations the
  jobs belong to: job state, audit trail and evidence live in one place and
  survive a restart together (Redis is configured as an LRU cache here and may
  evict keys);
- no new dependency or service to operate. Redis stays an optional cache.

Lifecycle: queued -> running -> done | failed | cancelled.
- Claiming is atomic (BEGIN IMMEDIATE): two workers never run the same job.
- Running jobs heartbeat; a job whose heartbeat is stale (worker crashed or
  process restarted) is re-queued while attempts < max_attempts, then failed.
- Cancellation is cooperative: request_cancel() sets a flag the handler
  checks between phases (JobContext.check_cancel raises JobCancelled).
- Per-user concurrency: a worker never starts a job whose owner already has
  `per_user_limit` jobs running (PHOENIX_MAX_JOBS_PER_USER).

Environment:
- PHOENIX_JOB_WORKERS          worker threads (default 2)
- PHOENIX_JOB_HEARTBEAT        heartbeat interval in seconds (default 10)
- PHOENIX_JOB_STALE_SECONDS    heartbeat age that marks a job orphaned (default 120)
- PHOENIX_JOB_MAX_ATTEMPTS     runs allowed before a stale job fails (default 2)
- PHOENIX_MAX_JOBS_PER_USER    concurrent jobs per user (default 2)
"""

import datetime
import json
import logging
import os
import sqlite3
import threading
import time
import uuid

logger = logging.getLogger('phoenix.jobqueue')

QUEUED, RUNNING, DONE, FAILED, CANCELLED = 'queued', 'running', 'done', 'failed', 'cancelled'
ACTIVE_STATUSES = (QUEUED, RUNNING)
TERMINAL_STATUSES = (DONE, FAILED, CANCELLED)

SCHEMA_SQL = """
    CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        payload TEXT NOT NULL DEFAULT '{}',
        status TEXT NOT NULL DEFAULT 'queued'
            CHECK(status IN ('queued', 'running', 'done', 'failed', 'cancelled')),
        owner_id INTEGER,
        owner_name TEXT,
        investigation_id TEXT,
        priority INTEGER NOT NULL DEFAULT 0,
        attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 2,
        cancel_requested INTEGER NOT NULL DEFAULT 0,
        progress TEXT,
        result TEXT,
        error TEXT,
        worker TEXT,
        created_at REAL NOT NULL,
        started_at REAL,
        finished_at REAL,
        heartbeat REAL
    );
    CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, priority, created_at);
    CREATE INDEX IF NOT EXISTS idx_jobs_investigation ON jobs(investigation_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_jobs_owner ON jobs(owner_id, status);
"""

_JSON_FIELDS = ('payload', 'progress', 'result')


def _env_int(name, default, minimum=1):
    try:
        return max(minimum, int(os.environ.get(name, str(default)) or default))
    except ValueError:
        return default


def max_jobs_per_user():
    """Concurrent jobs allowed per user (PHOENIX_MAX_JOBS_PER_USER, default 2)."""
    return _env_int('PHOENIX_MAX_JOBS_PER_USER', 2)


def ensure_schema(db):
    """Create the jobs table on an existing sqlite3 connection (idempotent)."""
    db.executescript(SCHEMA_SQL)


def iso(ts):
    """Epoch seconds -> local ISO 8601 string (format used by the legacy API)."""
    if ts is None:
        return None
    return datetime.datetime.fromtimestamp(ts).isoformat()


class JobCancelled(BaseException):
    """Raised inside a handler when its job was cancelled.

    Derives from BaseException on purpose: tool callbacks in the investigator
    swallow `Exception` so a failing callback never aborts an investigation,
    but a cancellation must unwind the whole run.
    """


class JobContext:
    """Handle given to a job handler: progress reporting and cancellation."""

    def __init__(self, queue, job):
        self.queue = queue
        self.job = job
        self.job_id = job['id']
        self._cancelled = False

    def cancelled(self):
        if not self._cancelled:
            self._cancelled = self.queue.is_cancel_requested(self.job_id)
        return self._cancelled

    def check_cancel(self):
        """Cooperative cancellation point: raise JobCancelled if requested."""
        if self.cancelled():
            raise JobCancelled(self.job_id)

    def progress(self, data):
        self.queue.update_progress(self.job_id, data)


class JobQueue:
    """SQLite backed job queue with a bounded pool of worker threads."""

    def __init__(self, db_path, workers=None, heartbeat_interval=None, stale_after=None,
                 max_attempts=None, per_user_limit=None, emitter=None, poll_interval=1.0):
        self.db_path = db_path
        self.workers = workers if workers is not None else _env_int('PHOENIX_JOB_WORKERS', 2)
        self.heartbeat_interval = (heartbeat_interval if heartbeat_interval is not None
                                   else _env_int('PHOENIX_JOB_HEARTBEAT', 10))
        self.stale_after = (stale_after if stale_after is not None
                            else _env_int('PHOENIX_JOB_STALE_SECONDS', 120))
        self.max_attempts = (max_attempts if max_attempts is not None
                             else _env_int('PHOENIX_JOB_MAX_ATTEMPTS', 2))
        self._per_user_limit = per_user_limit
        self.emitter = emitter
        self.poll_interval = poll_interval
        self.handlers = {}
        self._threads = []
        self._stop = threading.Event()
        self._wake = threading.Condition()
        self._running_here = {}          # job_id -> worker name (this process)
        self._running_lock = threading.Lock()
        self._schema_ready = False

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        if not self._schema_ready:
            ensure_schema(conn)
            self._schema_ready = True
        return conn

    @property
    def per_user_limit(self):
        return self._per_user_limit if self._per_user_limit is not None else max_jobs_per_user()

    @staticmethod
    def _row(row):
        if row is None:
            return None
        job = dict(row)
        for key in _JSON_FIELDS:
            raw = job.get(key)
            if raw:
                try:
                    job[key] = json.loads(raw)
                except (TypeError, ValueError):
                    job[key] = None
            else:
                job[key] = {} if key == 'payload' else None
        job['cancel_requested'] = bool(job.get('cancel_requested'))
        return job

    def _emit(self, event, job):
        if not self.emitter or not job:
            return
        try:
            self.emitter(event, {
                'job_id': job['id'], 'kind': job['kind'], 'status': job['status'],
                'investigation_id': job.get('investigation_id'),
                'progress': job.get('progress'), 'attempts': job.get('attempts'),
                'cancel_requested': job.get('cancel_requested'),
            }, job.get('investigation_id'), job.get('owner_id'))
        except Exception:  # pragma: no cover - never break the queue on a broadcast
            logger.debug('job event broadcast failed', exc_info=True)

    # ------------------------------------------------------------------
    # Producer API
    # ------------------------------------------------------------------

    def enqueue(self, kind, payload=None, owner_id=None, owner_name=None, investigation_id=None,
                priority=0, job_id=None):
        job_id = job_id or str(uuid.uuid4())
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO jobs (id, kind, payload, status, owner_id, owner_name, investigation_id, "
                "priority, max_attempts, created_at) VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?)",
                (job_id, kind, json.dumps(payload or {}, default=str), owner_id, owner_name,
                 investigation_id, int(priority), self.max_attempts, time.time()))
        finally:
            conn.close()
        self.wake()
        self._emit('job_status', self.get(job_id))
        return job_id

    def get(self, job_id):
        conn = self._connect()
        try:
            return self._row(conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())
        finally:
            conn.close()

    def list(self, investigation_id=None, owner_id=None, investigation_ids=None, statuses=None,
             kind=None, limit=50):
        """List jobs, newest first.

        `investigation_ids` restricts to those investigations OR to jobs owned
        by `owner_id` (access control for non admins); None means no restriction.
        """
        clauses, params = [], []
        if investigation_id:
            clauses.append("investigation_id=?")
            params.append(str(investigation_id))
        if kind:
            clauses.append("kind=?")
            params.append(kind)
        if statuses:
            clauses.append(f"status IN ({','.join('?' * len(statuses))})")
            params.extend(statuses)
        if investigation_ids is not None:
            scope = []
            if investigation_ids:
                scope.append(f"investigation_id IN ({','.join('?' * len(investigation_ids))})")
                params.extend(str(i) for i in investigation_ids)
            if owner_id is not None:
                scope.append("owner_id=?")
                params.append(owner_id)
            clauses.append('(' + (' OR '.join(scope) or '0') + ')')
        elif owner_id is not None:
            clauses.append("owner_id=?")
            params.append(owner_id)
        where = ' AND '.join(clauses) or '1=1'
        params.append(max(1, min(int(limit), 500)))
        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM jobs WHERE {where} ORDER BY created_at DESC LIMIT ?",  # nosec B608 - fixed fragments, values bound
                params).fetchall()
        finally:
            conn.close()
        return [self._row(r) for r in rows]

    def count_active(self, owner_id=None, statuses=ACTIVE_STATUSES):
        conn = self._connect()
        try:
            marks = ','.join('?' * len(statuses))
            if owner_id is None:
                sql = f"SELECT COUNT(*) FROM jobs WHERE status IN ({marks})"  # nosec B608 - placeholders only
                return conn.execute(sql, tuple(statuses)).fetchone()[0]
            sql = f"SELECT COUNT(*) FROM jobs WHERE owner_id=? AND status IN ({marks})"  # nosec B608 - placeholders only
            return conn.execute(sql, (owner_id, *statuses)).fetchone()[0]
        finally:
            conn.close()

    def active_ids(self, owner_id):
        conn = self._connect()
        try:
            return {r[0] for r in conn.execute(
                "SELECT id FROM jobs WHERE owner_id=? AND status IN ('queued', 'running')",
                (owner_id,)).fetchall()}
        finally:
            conn.close()

    def request_cancel(self, job_id):
        """Cancel a job. Returns its status afterwards, or None if unknown.

        A queued job is cancelled at once; a running job gets its cancel flag
        set and stops at the handler's next cancellation point.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT status FROM jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                conn.execute("ROLLBACK")
                return None
            status = row['status']
            if status == QUEUED:
                conn.execute("UPDATE jobs SET status='cancelled', cancel_requested=1, finished_at=?, "
                             "error='cancelled before start' WHERE id=?", (time.time(), job_id))
                status = CANCELLED
            elif status == RUNNING:
                conn.execute("UPDATE jobs SET cancel_requested=1 WHERE id=?", (job_id,))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        self._emit('job_status', self.get(job_id))
        return status

    def is_cancel_requested(self, job_id):
        conn = self._connect()
        try:
            row = conn.execute("SELECT cancel_requested, status FROM jobs WHERE id=?",
                               (job_id,)).fetchone()
        finally:
            conn.close()
        return bool(row) and (bool(row['cancel_requested']) or row['status'] == CANCELLED)

    def update_progress(self, job_id, progress, emit=True):
        """Persist progress (JSON) and refresh the heartbeat of a running job."""
        conn = self._connect()
        try:
            conn.execute("UPDATE jobs SET progress=?, heartbeat=CASE WHEN status='running' "
                         "THEN ? ELSE heartbeat END WHERE id=?",
                         (json.dumps(progress, default=str), time.time(), job_id))
        finally:
            conn.close()
        if emit:
            self._emit('job_progress', self.get(job_id))

    # ------------------------------------------------------------------
    # Worker side
    # ------------------------------------------------------------------

    def claim(self, worker='worker'):
        """Atomically take the next runnable job, or return None.

        BEGIN IMMEDIATE takes the SQLite write lock before reading, so the
        select-then-update pair cannot interleave with another claimer.
        Jobs of an owner already at the per-user limit are skipped.
        """
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT id FROM jobs j WHERE status='queued' AND (owner_id IS NULL OR "
                "(SELECT COUNT(*) FROM jobs r WHERE r.status='running' AND r.owner_id=j.owner_id) < ?) "
                "ORDER BY priority DESC, created_at ASC, rowid ASC LIMIT 1",
                (self.per_user_limit,)).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return None
            now = time.time()
            conn.execute(
                "UPDATE jobs SET status='running', attempts=attempts+1, worker=?, started_at=?, "
                "heartbeat=?, error=NULL WHERE id=? AND status='queued'",
                (worker, now, now, row['id']))
            job = self._row(conn.execute("SELECT * FROM jobs WHERE id=?", (row['id'],)).fetchone())
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        self._emit('job_status', job)
        return job

    def heartbeat(self, job_id, worker=None):
        conn = self._connect()
        try:
            if worker:
                conn.execute("UPDATE jobs SET heartbeat=? WHERE id=? AND status='running' AND worker=?",
                             (time.time(), job_id, worker))
            else:
                conn.execute("UPDATE jobs SET heartbeat=? WHERE id=? AND status='running'",
                             (time.time(), job_id))
        finally:
            conn.close()

    def _finish(self, job_id, worker, status, result=None, error=None):
        """Terminal transition, only if this worker still owns the run (a run
        recovered by the reaper and re-queued must not be overwritten)."""
        conn = self._connect()
        try:
            cur = conn.execute(
                "UPDATE jobs SET status=?, result=?, error=?, finished_at=?, heartbeat=? "
                "WHERE id=? AND status='running' AND worker=?",
                (status, json.dumps(result, default=str) if result is not None else None,
                 error, time.time(), time.time(), job_id, worker))
            changed = cur.rowcount > 0
        finally:
            conn.close()
        if changed:
            self._emit('job_status', self.get(job_id))
        return changed

    def complete(self, job_id, worker, result=None):
        return self._finish(job_id, worker, DONE, result=result)

    def fail(self, job_id, worker, error):
        return self._finish(job_id, worker, FAILED, error=str(error)[:4000])

    def mark_cancelled(self, job_id, worker, result=None):
        return self._finish(job_id, worker, CANCELLED, result=result, error='cancelled')

    def recover_stale(self, now=None):
        """Re-queue (or fail) running jobs whose heartbeat is stale.

        Returns (requeued_ids, failed_ids). A job is re-queued while it has
        attempts left, otherwise it fails; a stale job whose cancel was
        requested is cancelled instead.
        """
        now = now if now is not None else time.time()
        cutoff = now - self.stale_after
        requeued, failed = [], []
        with self._running_lock:
            local = set(self._running_here)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT id, attempts, max_attempts, cancel_requested FROM jobs "
                "WHERE status='running' AND COALESCE(heartbeat, started_at, 0) < ?",
                (cutoff,)).fetchall()
            for row in rows:
                if row['id'] in local:
                    continue  # still executing in this process (handler blocked on a long tool)
                if row['cancel_requested']:
                    conn.execute("UPDATE jobs SET status='cancelled', finished_at=?, worker=NULL, "
                                 "error='cancelled (worker lost)' WHERE id=?", (now, row['id']))
                    failed.append(row['id'])
                elif row['attempts'] < row['max_attempts']:
                    conn.execute("UPDATE jobs SET status='queued', worker=NULL, heartbeat=NULL, "
                                 "error='re-queued after a lost worker' WHERE id=?", (row['id'],))
                    requeued.append(row['id'])
                else:
                    conn.execute("UPDATE jobs SET status='failed', finished_at=?, worker=NULL, "
                                 "error=? WHERE id=?",
                                 (now, f"worker lost {row['attempts']} time(s): giving up", row['id']))
                    failed.append(row['id'])
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        for job_id in requeued + failed:
            self._emit('job_status', self.get(job_id))
        if requeued or failed:
            logger.warning('job recovery: %d re-queued, %d failed', len(requeued), len(failed))
            self.wake()
        return requeued, failed

    def register(self, kind, handler):
        """handler(job: dict, ctx: JobContext) -> result dict (JSON serialisable)."""
        self.handlers[kind] = handler

    def run_job(self, job, worker):
        """Execute one claimed job with its handler and record the outcome."""
        job_id = job['id']
        handler = self.handlers.get(job['kind'])
        if handler is None:
            self.fail(job_id, worker, f"no handler for job kind {job['kind']!r}")
            return FAILED
        ctx = JobContext(self, job)
        with self._running_lock:
            self._running_here[job_id] = worker
        try:
            ctx.check_cancel()
            result = handler(job, ctx)
            # A handler that returns normally finished its work: a cancel that
            # arrived after its last checkpoint does not discard the result.
            self.complete(job_id, worker, result=result)
            return DONE
        except JobCancelled:
            self.mark_cancelled(job_id, worker)
            return CANCELLED
        except Exception as exc:
            # Expected outcome for a job (bad evidence, LLM down): no traceback
            # unless debugging; the error is stored on the job.
            logger.warning('job %s failed: %s', job_id, exc,
                           exc_info=logger.isEnabledFor(logging.DEBUG))
            self.fail(job_id, worker, exc)
            return FAILED
        finally:
            with self._running_lock:
                self._running_here.pop(job_id, None)

    def run_once(self, worker='inline'):
        """Claim and run a single job synchronously (tests, maintenance)."""
        job = self.claim(worker)
        if job is None:
            return None
        return job['id'], self.run_job(job, worker)

    def wake(self):
        with self._wake:
            self._wake.notify_all()

    def _worker_loop(self, name):
        while not self._stop.is_set():
            try:
                job = self.claim(name)
            except sqlite3.Error:
                logger.exception('job claim failed')
                job = None
            if job is None:
                with self._wake:
                    self._wake.wait(self.poll_interval)
                continue
            self.run_job(job, name)

    def _maintenance_loop(self):
        while not self._stop.wait(self.heartbeat_interval):
            with self._running_lock:
                running = list(self._running_here.items())
            for job_id, worker in running:
                try:
                    self.heartbeat(job_id, worker)
                except sqlite3.Error:
                    logger.debug('heartbeat failed', exc_info=True)
            try:
                self.recover_stale()
            except sqlite3.Error:
                logger.debug('recovery failed', exc_info=True)

    @property
    def started(self):
        return any(t.is_alive() for t in self._threads)

    def start(self):
        """Recover orphaned jobs, then start the worker and heartbeat threads."""
        if self.started:
            return self
        self._stop.clear()
        self.recover_stale()
        prefix = f'phoenix-job-{os.getpid()}'
        for index in range(self.workers):
            t = threading.Thread(target=self._worker_loop, args=(f'{prefix}-{index}',),
                                 name=f'{prefix}-{index}', daemon=True)
            t.start()
            self._threads.append(t)
        t = threading.Thread(target=self._maintenance_loop, name=f'{prefix}-heartbeat', daemon=True)
        t.start()
        self._threads.append(t)
        logger.info('job queue started: %d worker(s), db=%s', self.workers, self.db_path)
        return self

    def stop(self, timeout=5):
        self._stop.set()
        self.wake()
        for t in self._threads:
            t.join(timeout)
        self._threads = []


_queue = None
_queue_lock = threading.Lock()


def _default_emitter(event, data, investigation_id, owner_id):
    from extensions import emit_secure
    emit_secure(event, data, investigation_id=investigation_id, user_id=owner_id)


def get_queue():
    """Process-wide queue bound to the current database.DB_PATH."""
    global _queue
    import database
    with _queue_lock:
        if _queue is None or _queue.db_path != database.DB_PATH:
            if _queue is not None:
                _queue.stop(timeout=1)
            _queue = JobQueue(database.DB_PATH, emitter=_default_emitter)
        return _queue
