#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de l'analytique colonnaire (ext/analytics.py) : garde SQL, lecture
seule de l'index des preuves, stacking / longue traine, comportement avec et
sans DuckDB."""

import hashlib
import os

import pytest


from phoenix_dfir_mcp import evidence_db, pathpolicy, phases, toolkit  # noqa: E402
from phoenix_dfir_mcp.ext import analytics  # noqa: E402

HAS_DUCKDB = analytics._duckdb() is not None

needs_duckdb = pytest.mark.skipif(not HAS_DUCKDB, reason='duckdb non installe')


@pytest.fixture(autouse=True)
def _isolation():
    pathpolicy.reset()
    toolkit.reset_evidence_index()
    toolkit.set_active_case(None)
    yield
    pathpolicy.reset()
    toolkit.set_active_case(None)


def _proc(n, ts, host, process, parent, ua=None, dst=None, port=None, user='alice'):
    row = {'row': n, 'timestamp': ts, 'host': host, 'process': process, 'ParentImage': parent,
           'user': user}
    if ua:
        row['user_agent'] = ua
    if dst:
        row['DestinationIp'] = dst
        row['DestinationPort'] = port
    return row


@pytest.fixture
def case(tmp_path):
    d = tmp_path / 'case'
    d.mkdir()
    art = d / 'sysmon.csv'
    art.write_text('x\n')
    rows = []
    n = 0
    for i in range(5):
        n += 1
        rows.append(_proc(n, f'2026-10-10T08:0{i}:00Z', 'WS01', 'C:\\Windows\\System32\\svchost.exe',
                          'C:\\Windows\\System32\\services.exe', ua='Mozilla/5.0 (Windows NT 10.0)',
                          dst='10.0.0.5', port=443))
    for i in range(3):
        n += 1
        rows.append(_proc(n, f'2026-10-10T09:0{i}:00Z', 'WS02', 'C:\\Windows\\System32\\svchost.exe',
                          'C:\\Windows\\System32\\services.exe', dst='10.0.0.5', port=443))
    n += 1
    rows.append(_proc(n, '2026-10-10T10:00:00Z', 'WS01', 'C:\\Users\\bob\\AppData\\evil.exe',
                      'C:\\Program Files\\Office\\WINWORD.EXE', ua='curl/8.1', dst='185.220.101.44',
                      port=8443, user='bob'))
    n += 1
    rows.append(_proc(n, '2026-10-11T23:00:00Z', 'WS02', 'C:\\Windows\\System32\\rundll32.exe',
                      'C:\\Windows\\explorer.exe', dst='198.51.100.9', port=53))
    evidence_db.record_run(str(d), 'parse_csv', str(art), {'rows': rows})
    return str(d)


def _db_digest(case):
    with open(evidence_db.db_path(case), 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


# ============================================================================
# Garde SQL
# ============================================================================

@pytest.mark.parametrize('sql', [
    'UPDATE events SET host = 1',
    'DELETE FROM events',
    "INSERT INTO events (tool) VALUES ('x')",
    'DROP TABLE events',
    "ATTACH DATABASE '/tmp/x.db' AS x",
    'PRAGMA writable_schema = 1',
    'VACUUM',
    'SELECT 1; DELETE FROM events',
    "SELECT 'a'; DELETE FROM events",
    'SELECT 1;; ',
    'select 1; dRoP table events',
    'SELECT 1 -- ; DELETE FROM events',
    'SELECT 1 /* */ ; DELETE FROM events',
    'SELECT 1 /*',
    "SELECT ';' ; ATTACH 'x' AS y",
    "SELECT 'non ferme",
    'SELECT "non ferme',
    'SELECT `host` FROM events',
    'WITH a AS (SELECT 1) DELETE FROM events',
    'WITH a AS (SELECT 1) INSERT INTO events SELECT * FROM events',
    'SELECT * INTO copie FROM events',
    "SELECT load_extension('/tmp/evil.so')",
    "SELECT * FROM read_csv('/etc/passwd')",
    "SELECT * FROM read_csv_auto ('/etc/passwd')",
    "SELECT * FROM parquet_scan('/x.parquet')",
    "SELECT * FROM sqlite_scan('/x.db', 't')",
    "SELECT * FROM '/etc/passwd'",
    "SELECT * FROM events JOIN '/x.csv' USING (id)",
    "SELECT * FROM query('DELETE FROM events')",
    'SELECT 1\x00',
    '',
    '   ',
    'EXPLAIN SELECT 1',
    "COPY events TO '/tmp/x.csv'",
    'SET enable_external_access = true',
    'SELECT ' + 'x,' * 3000 + '1',
])
def test_garde_sql_refuse(sql):
    with pytest.raises(analytics.SQLRejected):
        analytics.check_sql(sql)


@pytest.mark.parametrize('sql,expected', [
    ('SELECT 1', 'SELECT 1'),
    ('  select host from events ;  ', 'select host from events'),
    ("SELECT 'DELETE; DROP -- /*' AS texte", "SELECT 'DELETE; DROP -- /*' AS texte"),
    ('SELECT "update" FROM (SELECT 1 AS "update")', 'SELECT "update" FROM (SELECT 1 AS "update")'),
    ("SELECT replace(text, 'a', 'b') FROM events", "SELECT replace(text, 'a', 'b') FROM events"),
    ('WITH a AS (SELECT 1 AS x) SELECT x FROM a', 'WITH a AS (SELECT 1 AS x) SELECT x FROM a'),
    ("SELECT 'it''s' AS s", "SELECT 'it''s' AS s"),
])
def test_garde_sql_accepte(sql, expected):
    assert analytics.check_sql(sql) == expected


# ============================================================================
# Moteur SQLite (lecture seule stricte)
# ============================================================================

def test_sqlite_requete_et_index_inchange(case, monkeypatch):
    before = _db_digest(case)
    r = analytics.run_query(case, 'SELECT host, COUNT(*) AS n FROM events GROUP BY host ORDER BY host',
                            engine='sqlite')
    assert r['engine'] == 'sqlite' and r['rows'] == [{'host': 'WS01', 'n': 6}, {'host': 'WS02', 'n': 4}]
    r = analytics.run_query(case, 'SELECT id FROM events ORDER BY id', limit=3, engine='sqlite')
    assert r['returned'] == 3 and r['truncated']
    assert _db_digest(case) == before


def test_sqlite_autorisateur_bloque_ce_que_la_garde_laisse_passer(case):
    before = _db_digest(case)
    # Fonction table de PRAGMA : pas un mot cle PRAGMA, mais refusee par l'autorisateur
    r = analytics._run_sqlite(case, "SELECT * FROM pragma_table_info('events')", 10, 5)
    assert 'error' in r
    # Meme en contournant la garde, aucune ecriture n'est possible (mode=ro + query_only)
    r = analytics._run_sqlite(case, 'DELETE FROM events', 10, 5)
    assert 'error' in r
    r = analytics._run_sqlite(case, "ATTACH DATABASE ':memory:' AS x", 10, 5)
    assert 'error' in r
    assert _db_digest(case) == before
    assert analytics.run_query(case, 'SELECT COUNT(*) AS n FROM events', engine='sqlite')['rows'] == [{'n': 10}]


def test_sqlite_delai_maximal(case):
    sql = 'WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT MAX(x) FROM c'
    r = analytics.run_query(case, sql, timeout=0.3, engine='sqlite')
    assert r['error'].startswith('Delai depasse')


def test_sans_index_de_preuves(tmp_path):
    assert 'Aucun index' in analytics.run_query(str(tmp_path), 'SELECT 1', engine='sqlite')['error']
    assert 'Aucun index' in analytics.stack(str(tmp_path), 'process')['error']
    assert not os.path.exists(evidence_db.db_path(str(tmp_path)))  # jamais cree en lecture


def test_outil_refuse_une_ecriture(case):
    r = toolkit.run_tool('analytics_query', {'case_dir': case, 'sql': 'DELETE FROM events'})
    assert r['rejected'] and r['error'].startswith('Requete refusee')


# ============================================================================
# Sans DuckDB
# ============================================================================

def test_sans_duckdb_repli_sqlite_et_export_indisponible(case, monkeypatch):
    monkeypatch.setattr(analytics, '_duckdb', lambda: None)
    r = toolkit.run_tool('analytics_query', {'case_dir': case, 'sql': 'SELECT COUNT(*) AS n FROM events'})
    assert r['engine'] == 'sqlite' and r['rows'] == [{'n': 10}]
    assert 'DuckDB non installe' in analytics.run_query(case, 'SELECT 1', engine='duckdb')['error']
    exp = toolkit.run_tool('analytics_export_parquet', {'case_dir': case})
    assert exp['duckdb'] is False and 'DuckDB' in exp['error']
    assert not os.path.exists(os.path.join(case, analytics.ANALYTICS_DIR))
    s = toolkit.run_tool('analytics_stack', {'case_dir': case, 'field': 'process'})
    assert s['least_frequent'][0]['value'] == 'evil.exe'


def test_import_duckdb_absent(monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == 'duckdb':
            raise ImportError('absent')
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, '__import__', fake)
    assert analytics._duckdb() is None


# ============================================================================
# DuckDB (si installe)
# ============================================================================

@needs_duckdb
def test_duckdb_memes_resultats_que_sqlite(case):
    sql = ('SELECT host, COUNT(*) AS n, MIN(ts) AS first FROM events GROUP BY host ORDER BY host')
    a = analytics.run_query(case, sql, engine='duckdb')
    b = analytics.run_query(case, sql, engine='sqlite')
    assert a['engine'] == 'duckdb' and a['rows'] == b['rows'] and a['events_loaded'] == 10
    assert analytics.run_query(case, 'SELECT "user" FROM events WHERE "user" = \'bob\'',
                               engine='duckdb')['rows'] == [{'user': 'bob'}]


@needs_duckdb
def test_duckdb_acces_externe_coupe(case, tmp_path):
    secret = tmp_path / 'secret.csv'
    secret.write_text('a\nconfidentiel\n')
    # Garde contournee volontairement : la configuration verrouillee bloque quand meme
    import duckdb
    r = analytics._run_duckdb(duckdb, case, f"SELECT * FROM read_csv('{secret}')", 10, 5)
    assert 'error' in r and 'confidentiel' not in str(r)
    r = analytics._run_duckdb(duckdb, case, 'SET enable_external_access = true', 10, 5)
    assert 'error' in r


@needs_duckdb
def test_export_parquet(case):
    r = toolkit.run_tool('analytics_export_parquet', {'case_dir': case})
    path = os.path.join(case, 'analytics', 'events.parquet')
    assert r['path'] == os.path.join('analytics', 'events.parquet') and os.path.isfile(path)
    assert r['rows'] == 10 and r['size_bytes'] > 0
    import duckdb
    con = duckdb.connect()
    assert con.execute('SELECT COUNT(*) FROM read_parquet(?)', [path]).fetchone()[0] == 10
    # Le dossier analytics n'est pas une preuve du cas
    names = [a['name'] for a in toolkit.run_tool('list_artifacts', {'case_dir': case})['artifacts']]
    assert 'events.parquet' not in names and 'sysmon.csv' in names
    assert all('analytics' not in p for p in toolkit.case_artifacts(case))


# ============================================================================
# Stacking / longue traine
# ============================================================================

def test_stack_processus_longue_traine(case):
    r = analytics.stack(case, 'process')
    assert r['events_scanned'] == 10 and r['distinct_values'] == 3
    least = r['least_frequent']
    assert [(g['value'], g['count']) for g in least] == [('evil.exe', 1), ('rundll32.exe', 1),
                                                         ('svchost.exe', 8)]
    assert least[0]['hosts'] == ['WS01'] and least[0]['first_seen'] == '2026-10-10T10:00:00Z'
    assert least[0]['refs'] == [{'artifact': 'sysmon.csv', 'kind': 'row', 'value': '9'}]
    assert r['most_frequent'][0] == least[-1]


def test_stack_parent_enfant_user_agent_destination(case):
    pc = analytics.stack(case, 'parent_child')
    assert pc['least_frequent'][0]['value'] == 'winword.exe > evil.exe'
    assert pc['least_frequent'][-1] == dict(pc['least_frequent'][-1], value='services.exe > svchost.exe',
                                            count=8)
    ua = analytics.stack(case, 'user_agent')
    assert [(g['value'], g['count']) for g in ua['least_frequent']] == [
        ('curl/8.1', 1), ('Mozilla/5.0 (Windows NT 10.0)', 5)]
    dest = analytics.stack(case, 'destination', limit=2)
    assert [g['value'] for g in dest['least_frequent']] == ['185.220.101.44:8443', '198.51.100.9:53']
    assert dest['distinct_values'] == 3


def test_stack_fenetre_et_par_hote(case):
    r = analytics.stack(case, 'process', start='2026-10-10T00:00:00Z', end='2026-10-10T23:59:59Z',
                        per_host=True)
    assert r['events_scanned'] == 9  # rundll32 du 11/10 hors fenetre
    assert 'rundll32.exe' not in [g['value'] for g in r['least_frequent']]
    hosts = {h['host']: h for h in r['by_host']}
    assert [(g['value'], g['count']) for g in hosts['WS01']['least_frequent']] == [
        ('evil.exe', 1), ('svchost.exe', 5)]
    assert [(g['value'], g['count']) for g in hosts['WS02']['least_frequent']] == [('svchost.exe', 3)]
    only = analytics.stack(case, 'user', host='WS02')
    assert [(g['value'], g['count']) for g in only['least_frequent']] == [('alice', 4)]


def test_stack_champ_inconnu(case):
    assert 'Champ inconnu' in analytics.stack(case, 'password')['error']


def test_parse_text_cles_valeurs_avec_espaces():
    fields = analytics.parse_text('Image=C:\\Program Files\\a b.exe user_agent=Mozilla/5.0 (X11) row=3')
    assert fields == {'image': 'C:\\Program Files\\a b.exe', 'user_agent': 'Mozilla/5.0 (X11)', 'row': '3'}


def test_outils_declares_en_phases_et_lecture_seule():
    assert {'analytics_query', 'analytics_stack'} <= set(toolkit.READONLY_TOOLS)
    assert 'analytics_export_parquet' not in toolkit.READONLY_TOOLS
    corr = next(p for p in phases.PHASES if p.key == 'correlation')
    assert {'analytics_query', 'analytics_stack'} <= set(corr.tools)
    assert 'analytics_export_parquet' not in corr.tools
