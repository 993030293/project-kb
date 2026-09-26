"""Immutable per-domain native statistics with generation-owned visibility."""
from contextlib import contextmanager
import math
import os
import re
import sqlite3
import uuid

from ..textutil import slugify
from . import lexical, store
from .records import published_generation

REVISION = 'w5-tiered-occurrence-v2'
TOKEN_VERSION = 'unicode61-original-frequency-nul-soh-v1'
OFFSET_VERSION = 'native-first-match-nul-soh-codepoints-v1'
MAX_NUL_BYTES = lexical.MAX_DOCUMENT_CHARS * 4
MAX_WORK = 100000
MARKER = '\x01KB_NATIVE_MATCH\x02'
FIELDS = {'revision', 'ranking_snapshot_id', 'generation_id', 'query', 'project_id', 'include_history', 'last'}
STOPWORDS = set('a an and are as for from in is it of on or project the to with'.split())
STOPWORDS.update(('\u8fd9\u91cc', '\u8fd9\u4e2a', '\u9879\u76ee'))
LINEAGE = '''WITH RECURSIVE lineage(id,seq,parent_id) AS (
 SELECT id,seq,parent_id FROM main.generations WHERE id=:generation AND state='published'
 UNION SELECT g.id,g.seq,g.parent_id FROM main.generations g JOIN lineage l ON g.id=l.parent_id
 WHERE g.state='published') '''
DOC_COLUMNS = 'source_id,body_id,priority,id_class,namespace,legacy_order,target_type,target_id'
REGISTRY = (
    '''CREATE TABLE main.rank_domains(owner TEXT PRIMARY KEY,kind INTEGER NOT NULL,
       origin_generation TEXT NOT NULL REFERENCES generations(id),revision TEXT NOT NULL,
       token_version TEXT NOT NULL,document_count INTEGER NOT NULL)''',
    '''CREATE TABLE main.rank_snapshots(generation_id TEXT PRIMARY KEY REFERENCES generations(id),
       snapshot_id TEXT NOT NULL UNIQUE,revision TEXT NOT NULL,token_version TEXT NOT NULL,
       offset_version TEXT NOT NULL,table_prefix TEXT NOT NULL UNIQUE,
       summary_owner TEXT NOT NULL REFERENCES rank_domains(owner),
       evidence_owner TEXT NOT NULL REFERENCES rank_domains(owner),expansion_count INTEGER NOT NULL)''',
    '''CREATE TABLE main.rank_revocations(owner TEXT PRIMARY KEY REFERENCES rank_domains(owner),
       reason TEXT NOT NULL,created_at TEXT NOT NULL)''',
)


def match_expression(query):
    """Retain the frozen legacy parser; invalid MATCH is not a LIKE fallback."""
    lexical._text(query, 'query', 256)
    query = query.strip()
    terms = [term for term in re.findall(r'[\w\u4e00-\u9fff.-]+', query)
             if len(term) > 1 and term.lower() not in STOPWORDS]
    return ' OR '.join('"' + term + '"' for term in terms[:12]) or query


def metadata(conn):
    values = dict(conn.execute("SELECT key,value FROM main.meta WHERE key IN ('rank_revision','rank_token_version','rank_offset_version')"))
    if values != {'rank_revision': REVISION, 'rank_token_version': TOKEN_VERSION, 'rank_offset_version': OFFSET_VERSION}:
        raise lexical.LexicalError('backend_unavailable', 'Explicit compatible tiered index installation is required')
    if conn.execute("SELECT 1 FROM main.meta WHERE key='lexical_revision'").fetchone():
        raise lexical.LexicalError('backend_unavailable', 'Mixed native and lexical index backends are not supported')
    return {'backend_revision': REVISION, 'token_version': TOKEN_VERSION, 'offset_version': OFFSET_VERSION}


def _nul_text(text):
    if type(text) is not str or len(text.encode('utf-8')) > MAX_NUL_BYTES:
        raise ValueError('Invalid or oversized NUL text')
    return text.replace('\0', '\x01')


def configure_connection(conn):
    conn.create_function('rank_nul_text', 1, _nul_text, deterministic=True)


def _prefix(value, domain=False):
    pattern = r'rank_d[0-9a-f]{32}' if domain else r'rank_g[1-9][0-9]*'
    if type(value) is not str or not re.fullmatch(pattern, value):
        raise lexical.LexicalError('index_corrupt', 'Invalid generated index object identity')
    return value


def _source_query(kind):
    if kind == 0:
        return LINEAGE + '''SELECT cast(s.id AS TEXT) source_id,NULL body_id,0 priority,0 id_class,
            '' namespace,-s.id legacy_order,s.target_type,s.target_id
            FROM main.summaries s JOIN lineage l ON l.seq=s.created_generation'''
    return LINEAGE + '''SELECT e.id source_id,e.body_id,
        CASE WHEN e.kind='priority' THEN 0 ELSE 1 END priority,
        CASE WHEN f.source_snapshot_id IS NOT NULL AND json_type(e.legacy_json,'$.id')='integer' THEN 0 ELSE 1 END id_class,
        CASE WHEN f.source_snapshot_id IS NOT NULL AND json_type(e.legacy_json,'$.id')='integer'
             THEN f.source_snapshot_id ELSE '' END namespace,
        CASE WHEN f.source_snapshot_id IS NOT NULL AND json_type(e.legacy_json,'$.id')='integer'
             THEN json_extract(e.legacy_json,'$.id') ELSE 0 END legacy_order,
        NULL target_type,NULL target_id
        FROM main.evidence_occurrences e CROSS JOIN main.file_versions v ON v.id=e.file_version_id
        CROSS JOIN main.files f ON f.id=v.file_id
        WHERE EXISTS(SELECT 1 FROM main.file_memberships m JOIN lineage l ON l.seq=m.valid_from
                     WHERE m.file_version_id=e.file_version_id AND m.tombstone=0)'''


def _same_sources(conn, owner, kind, generation_id):
    docs = _prefix(owner, True) + '_docs'
    expected, actual = _source_query(kind), f'SELECT {DOC_COLUMNS} FROM main.{docs}'
    params = {'generation': generation_id}
    # Compare full bindings in both directions, not counts or body hashes.
    return (conn.execute(f'SELECT 1 FROM (SELECT * FROM ({expected}) EXCEPT {actual}) LIMIT 1', params).fetchone() is None
            and conn.execute(f'SELECT 1 FROM ({actual} EXCEPT SELECT * FROM ({expected})) LIMIT 1', params).fetchone() is None)


def _same_sources_for_integrity(conn, owner, kind, generation_id):
    docs = _prefix(owner, True) + '_docs'
    expected, actual = _source_query(kind), f'SELECT {DOC_COLUMNS} FROM main.{docs}'
    params = {'generation': generation_id}
    return _same_relation(conn, expected, actual, params)


@contextmanager
def _building(*prefixes, registry=False, validating=()):
    if getattr(store._ownership, 'rank_scope_active', False):
        raise ValueError('Nested native index ownership is not allowed')
    store._ownership.rank_scope_active = True
    store._ownership.rank_build_prefixes = set(prefixes)
    store._ownership.rank_registry_install = registry
    store._ownership.rank_validation_fts = set(validating)
    try:
        yield
    finally:
        store._ownership.rank_scope_active = False
        store._ownership.rank_build_prefixes = set()
        store._ownership.rank_registry_install = False
        store._ownership.rank_validation_fts = set()


def _seal(conn, table, *, append=False):
    for action in (('UPDATE', 'DELETE') if append else ('INSERT', 'UPDATE', 'DELETE')):
        conn.execute(f'''CREATE TRIGGER main.{table}_{action.lower()} BEFORE {action} ON main.{table}
          BEGIN SELECT RAISE(ABORT,'immutable published rank object'); END''')


def _install_registry(conn):
    # Source-only migrations do not inherit the old lexical lookup index.
    conn.execute('CREATE INDEX IF NOT EXISTS main.membership_version ON file_memberships(file_version_id,valid_from)')
    table = conn.execute("SELECT tbl_name FROM main.sqlite_master WHERE name='membership_version'").fetchone()
    if (table is None or table[0] != 'file_memberships'
            or [row[2] for row in conn.execute("PRAGMA main.index_info('membership_version')")] != ['file_version_id', 'valid_from']):
        raise lexical.LexicalError('backend_unavailable', 'An incompatible membership lookup index requires explicit repair')
    if conn.execute("SELECT 1 FROM main.sqlite_master WHERE name='rank_domains'").fetchone():
        metadata(conn)
        return
    if conn.execute("SELECT 1 FROM main.meta WHERE key='lexical_revision' OR key LIKE 'rank_%'").fetchone():
        raise lexical.LexicalError('backend_unavailable', 'Install on a new source-only store, not over an existing index backend')
    with _building(registry=True):
        for sql in REGISTRY:
            conn.execute(sql)
        for table in ('rank_domains', 'rank_snapshots', 'rank_revocations'):
            _seal(conn, table, append=True)
        for key, value in (('rank_revision', REVISION), ('rank_token_version', TOKEN_VERSION), ('rank_offset_version', OFFSET_VERSION)):
            conn.execute('INSERT INTO main.meta VALUES(?,?)', (key, value))
        for action in ('UPDATE', 'DELETE'):
            conn.execute(f'''CREATE TRIGGER main.rank_meta_{action.lower()} BEFORE {action} ON main.meta
              WHEN OLD.key IN ('rank_revision','rank_token_version','rank_offset_version')
              BEGIN SELECT RAISE(ABORT,'immutable rank metadata'); END''')
        conn.execute('''CREATE TRIGGER main.rank_meta_replace BEFORE INSERT ON main.meta
          WHEN NEW.key IN ('rank_revision','rank_token_version','rank_offset_version')
               AND EXISTS(SELECT 1 FROM main.meta WHERE key=NEW.key)
          BEGIN SELECT RAISE(ABORT,'immutable rank metadata'); END''')


def _limit_database(conn):
    value = os.environ.get('PROJECT_KB_RANK_MAX_BYTES', '')
    if not value.isdecimal() or not 1024**2 <= int(value) <= 16 * 1024**3:
        raise lexical.LexicalError('build_budget_required', 'An explicit admitted native DB byte ceiling is required')
    page = conn.execute('PRAGMA main.page_size').fetchone()[0]
    pages = int(value) // page
    if conn.execute('PRAGMA main.page_count').fetchone()[0] > pages:
        raise lexical.LexicalError('build_budget_exceeded', 'The source database already exceeds its admitted ceiling')
    conn.execute(f'PRAGMA main.max_page_count={pages}')


def _content_expression(column):
    # SQL gates oversized transfers before invoking the exceptional Python UDF.
    return (f'CASE WHEN instr({column},char(0))=0 THEN {column} '
            f'WHEN length(cast({column} AS BLOB))<={MAX_NUL_BYTES} THEN rank_nul_text({column}) END')


def _build_domain(conn, kind, generation_id, check):
    owner = 'rank_d' + uuid.uuid4().hex
    docs, view, fts = owner + '_docs', owner + '_content', owner + '_fts'
    with _building(owner):
        conn.execute(f'''CREATE TABLE main.{docs}(doc_key INTEGER PRIMARY KEY,source_id TEXT NOT NULL UNIQUE,
          body_id INTEGER,priority INTEGER NOT NULL,id_class INTEGER NOT NULL,namespace TEXT NOT NULL,
          legacy_order INTEGER NOT NULL,target_type TEXT,target_id TEXT)''')
        conn.execute(f'INSERT INTO main.{docs}({DOC_COLUMNS}) SELECT * FROM ({_source_query(kind)}) ORDER BY source_id',
                     {'generation': generation_id})
        check()
        if kind == 0:
            source = f'FROM main.{docs} d JOIN main.summaries s ON s.id=cast(d.source_id AS INTEGER)'
            content = _content_expression('s.content')
        else:
            source = f'FROM main.{docs} d JOIN main.text_bodies b ON b.id=d.body_id'
            content = _content_expression('b.content')
            invalid = conn.execute(f'''SELECT 1 FROM main.{docs} d WHERE d.id_class=0 AND
                (d.legacy_order<1 OR NOT EXISTS(SELECT 1 FROM main.legacy_refs lr
                 WHERE lr.snapshot_id=d.namespace AND lr.reference=cast(d.legacy_order AS TEXT)
                 AND lr.evidence_id=d.source_id AND lr.status='resolved_snapshot')) LIMIT 1''').fetchone()
            if invalid:
                raise lexical.LexicalError('index_corrupt', 'Legacy source order lacks its canonical reference binding')
        conn.execute(f'CREATE VIEW main.{view} AS SELECT d.doc_key,{content} content {source}')
        count = conn.execute(f'SELECT count(*) FROM main.{docs}').fetchone()[0]
        visible = conn.execute(f'SELECT count(*),count(DISTINCT doc_key) FROM main.{view}').fetchone()
        if tuple(visible) != (count, count):
            raise lexical.LexicalError('index_corrupt', 'Native content view is not one-to-one with source documents')
        if conn.execute(f'SELECT 1 FROM main.{view} WHERE content IS NULL LIMIT 1').fetchone():
            raise lexical.LexicalError('document_budget_exceeded', 'NUL-containing source exceeds the explicit transfer ceiling')
        conn.execute(f"CREATE VIRTUAL TABLE main.{fts} USING fts5(content,content='{view}',content_rowid='doc_key',"
                     "tokenize='unicode61',detail=full,columnsize=1)")
        conn.execute(f'INSERT INTO main.{fts}(rowid,content) SELECT doc_key,content FROM main.{view}')
        conn.execute(f"INSERT INTO main.{fts}({fts},rank) VALUES('integrity-check',1)")
        check()
        _seal(conn, docs)
        conn.execute('INSERT INTO main.rank_domains VALUES(?,?,?,?,?,?)',
                     (owner, kind, generation_id, REVISION, TOKEN_VERSION, count))
        store._ownership.rank_commit_prefixes.add(owner)
    return owner, False


def _domain(conn, kind, generation_id, check):
    candidates = conn.execute('SELECT owner FROM main.rank_domains WHERE kind=? ORDER BY rowid DESC', (kind,))
    for row in candidates:
        check()
        owner = row[0]
        if conn.execute('SELECT 1 FROM main.rank_revocations WHERE owner=?', (owner,)).fetchone():
            continue
        if _same_sources(conn, owner, kind, generation_id):
            fts = _prefix(owner, True) + '_fts'
            with _building(validating=(fts,)):
                conn.execute(f"INSERT INTO main.{fts}({fts},rank) VALUES('integrity-check',1)")
            return owner, True
    return _build_domain(conn, kind, generation_id, check)


def _mapping_queries(kind, owner):
    docs = _prefix(owner, True) + '_docs'
    if kind == 0:
        visible = LINEAGE + f'''SELECT 0,d.doc_key,s.record_type!='legacy_unknown' AND NOT EXISTS(
            SELECT 1 FROM main.summaries n JOIN lineage l ON l.seq=n.created_generation
            WHERE n.supersedes_id=s.id)
            FROM main.{docs} d JOIN main.summaries s ON s.id=cast(d.source_id AS INTEGER)'''
        links = f'''FROM main.{docs} d JOIN main.summary_evidence se
            ON se.summary_id=cast(d.source_id AS INTEGER) AND se.status='resolved_snapshot'
            JOIN main.evidence_occurrences e ON e.id=se.evidence_id'''
        provenance = 'e.id'
    else:
        visible = f'SELECT 1,doc_key,1 FROM main.{docs}'
        links = f'FROM main.evidence_occurrences e CROSS JOIN main.{docs} d ON e.id=d.source_id'
        provenance = "''"
    join = 'JOIN' if kind == 0 else 'CROSS JOIN'
    expansion = LINEAGE + f'''SELECT DISTINCT {kind},d.doc_key,m.id,{provenance},f.project_id,
        NOT EXISTS(SELECT 1 FROM lineage ended WHERE ended.seq=m.valid_to)
        {links} {join} main.file_memberships m ON m.file_version_id=e.file_version_id
        {join} lineage born ON born.seq=m.valid_from {join} main.files f ON f.id=m.file_id
        WHERE m.tombstone=0'''
    return visible, expansion


def install_snapshot(conn, generation_id, check):
    """Publish domains and visibility in the caller-owned transaction, without commit."""
    if not conn.in_transaction or not getattr(store._ownership, 'held', False):
        raise ValueError('Native installation requires the controlled outer transaction')
    _limit_database(conn)
    _install_registry(conn)
    generation = published_generation(conn, generation_id)
    if conn.execute('SELECT 1 FROM main.rank_snapshots WHERE generation_id=?', (generation['id'],)).fetchone():
        raise lexical.LexicalError('snapshot_already_published', 'Published ranking snapshots cannot be replaced')
    owners = [_domain(conn, kind, generation['id'], check) for kind in (0, 1)]
    prefix = 'rank_g' + str(generation['seq'])
    visible, expansion = prefix + '_visible', prefix + '_expansions'
    params = {'generation': generation['id']}
    with _building(prefix):
        conn.execute(f'''CREATE TABLE main.{visible}(domain INTEGER NOT NULL,doc_key INTEGER NOT NULL,
                     current INTEGER NOT NULL,PRIMARY KEY(domain,doc_key))''')
        conn.execute(f'''CREATE TABLE main.{expansion}(domain INTEGER NOT NULL,doc_key INTEGER NOT NULL,
                     membership INTEGER NOT NULL,provenance TEXT NOT NULL,project TEXT NOT NULL,
                     current INTEGER NOT NULL,PRIMARY KEY(domain,doc_key,membership,provenance))''')
        for kind, (owner, _) in enumerate(owners):
            visibility_query, expansion_query = _mapping_queries(kind, owner)
            conn.execute(f'INSERT INTO main.{visible} SELECT * FROM ({visibility_query})', params)
            conn.execute(f'INSERT INTO main.{expansion} SELECT * FROM ({expansion_query})', params)
            check()
        total = conn.execute(f'SELECT count(*) FROM main.{expansion}').fetchone()[0]
        _seal(conn, visible)
        _seal(conn, expansion)
        identity = uuid.uuid4().hex + uuid.uuid4().hex
        conn.execute('INSERT INTO main.rank_snapshots VALUES(?,?,?,?,?,?,?,?,?)',
                     (generation['id'], identity, REVISION, TOKEN_VERSION, OFFSET_VERSION, prefix,
                      owners[0][0], owners[1][0], total))
    return {'status': 'ready', 'generation_id': generation['id'], 'ranking_snapshot_id': identity,
            'ranking_revision': REVISION, 'summary_domain_reused': owners[0][1], 'evidence_domain_reused': owners[1][1],
            'external_content_integrity': 'ok', 'expansion_rows': total}


def install_indexes(operation_id, generation_id=None):
    def handler(conn):
        with store.query_budget(conn) as check:
            return install_snapshot(conn, published_generation(conn, generation_id)['id'], check)
    return store.execute_operation('rank_install', operation_id, {'revision': REVISION, 'generation_id': generation_id}, handler)


def refresh_snapshots(conn, check):
    metadata(conn)
    ids = [row[0] for row in conn.execute('''SELECT g.id FROM main.generations g WHERE g.state='published'
          AND NOT EXISTS(SELECT 1 FROM main.rank_snapshots r WHERE r.generation_id=g.id) ORDER BY g.seq''')]
    for generation_id in ids:
        check()
        install_snapshot(conn, generation_id, check)
    snapshot(conn, published_generation(conn)['id'])


def _same_relation(conn, expected, actual, params):
    sql = f'''WITH
        rank_expected AS MATERIALIZED ({expected}),
        rank_actual AS MATERIALIZED ({actual})
        SELECT EXISTS(SELECT * FROM rank_expected EXCEPT SELECT * FROM rank_actual)
            OR EXISTS(SELECT * FROM rank_actual EXCEPT SELECT * FROM rank_expected)'''
    return conn.execute(sql, params).fetchone()[0] == 0


def _validate_domain(conn, domain, verified_source=None):
    owner = _prefix(domain['owner'], True)
    count = conn.execute(f'SELECT count(*) FROM main.{owner}_docs').fetchone()[0]
    # Reuse only the immediately preceding identical predicate in the owned transaction.
    source_checked = verified_source == (owner, domain['kind'], domain['origin_generation'])
    if source_checked and (not conn.in_transaction or not getattr(store._ownership, 'held', False)):
        raise ValueError('Verified source reuse requires the controlled write transaction')
    if count != domain['document_count'] or (not source_checked and not
            _same_sources_for_integrity(conn, owner, domain['kind'], domain['origin_generation'])):
        raise lexical.LexicalError('index_corrupt', 'Native source bindings differ from the retained source lineage')
    fts = owner + '_fts'
    with _building(validating=(fts,)):
        conn.execute(f"INSERT INTO main.{fts}({fts},rank) VALUES('integrity-check',1)")


def check_indexes(operation_id):
    """Explicit writer-only validation; confirmed defects revoke dependent domains."""
    def handler(conn):
        metadata(conn)
        bad = {}
        checked = set()
        snapshots = list(conn.execute('SELECT * FROM main.rank_snapshots ORDER BY rowid'))
        with store.query_budget(conn) as check:
            for snap in snapshots:
                owners = (snap['summary_owner'], snap['evidence_owner'])
                try:
                    check()
                    snapshot(conn, snap['generation_id'])
                    for kind, owner in enumerate(owners):
                        if not _same_sources_for_integrity(conn, owner, kind, snap['generation_id']):
                            raise lexical.LexicalError('index_corrupt', 'Native domain does not cover this snapshot source lineage')
                        if owner not in checked:
                            domain = conn.execute('SELECT * FROM main.rank_domains WHERE owner=?', (owner,)).fetchone()
                            _validate_domain(conn, domain, verified_source=(owner, kind, snap['generation_id']))
                            checked.add(owner)
                        for suffix, expected in zip(('visible', 'expansions'), _mapping_queries(kind, owner)):
                            actual = f"SELECT * FROM main.{_prefix(snap['table_prefix'])}_{suffix} WHERE domain={kind}"
                            if not _same_relation(conn, expected, actual, {'generation': snap['generation_id']}):
                                raise lexical.LexicalError('index_corrupt', 'Frozen visibility differs from the source lineage')
                    count = conn.execute(f"SELECT count(*) FROM main.{snap['table_prefix']}_expansions").fetchone()[0]
                    if count != snap['expansion_count']:
                        raise lexical.LexicalError('index_corrupt', 'Frozen expansion count differs from its registry')
                except (lexical.LexicalError, sqlite3.DatabaseError) as exc:
                    corruption = (isinstance(exc, lexical.LexicalError) and exc.code == 'index_corrupt')
                    corruption = corruption or (getattr(exc, 'sqlite_errorcode', 0) & 255) in (sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB)
                    corruption = corruption or str(exc).startswith(('no such table:', 'no such view:'))
                    if not corruption:
                        raise
                    for owner in owners:
                        bad[owner] = 'explicit_integrity_failure'
            with _building():
                for owner, reason in bad.items():
                    conn.execute('INSERT OR IGNORE INTO main.rank_revocations VALUES(?,?,?)', (owner, reason, store.now()))
        return {'status': 'index_corrupt' if bad else 'ok', 'domains_checked': len(checked),
                'snapshots_checked': len(snapshots), 'revoked_domains': sorted(bad),
                'external_content_integrity': 'failed' if bad else 'ok', **metadata(conn)}
    return store.execute_operation('rank_check', operation_id, {'revision': REVISION}, handler)


def index_stats(conn):
    with store.query_budget(conn):
        result = {'status': 'ok', **metadata(conn), 'domain_count': 0, 'document_rows': 0,
                  'snapshot_count': conn.execute('SELECT count(*) FROM main.rank_snapshots').fetchone()[0],
                  'revoked_domain_count': conn.execute('SELECT count(*) FROM main.rank_revocations').fetchone()[0],
                  'source_text_copies': 0, 'offset_cache_bytes': 0, 'fts_data_blob_bytes': 0,
                  'integrity': 'not_checked_by_read', 'acceptance': 'not_evaluated'}
        for domain in conn.execute('SELECT * FROM main.rank_domains'):
            owner = _prefix(domain['owner'], True)
            result['domain_count'] += 1
            result['document_rows'] += conn.execute(f'SELECT count(*) FROM main.{owner}_docs').fetchone()[0]
            result['fts_data_blob_bytes'] += conn.execute(f'SELECT coalesce(sum(length(block)),0) FROM main.{owner}_fts_data').fetchone()[0]
        result['allocated_bytes'] = None
        if any(row[0] == 'dbstat' for row in conn.execute('PRAGMA module_list')):
            result['allocated_bytes'] = conn.execute("SELECT coalesce(sum(pgsize),0) FROM dbstat WHERE name GLOB 'rank_*' OR name GLOB 'sqlite_autoindex_rank_*'").fetchone()[0]
        result['byte_sums_are_allocated_size'] = False
        if result['revoked_domain_count']:
            result['status'] = 'index_corrupt'
        return result


def snapshot(conn, generation_id):
    metadata(conn)
    row = conn.execute('SELECT * FROM main.rank_snapshots WHERE generation_id=?', (generation_id,)).fetchone()
    if row is None:
        raise lexical.LexicalError('ranking_snapshot_unavailable', 'No retained native ranking snapshot for this generation')
    if (row['revision'] != REVISION or row['token_version'] != TOKEN_VERSION or row['offset_version'] != OFFSET_VERSION
            or not re.fullmatch('[0-9a-f]{64}', row['snapshot_id'])):
        raise lexical.LexicalError('backend_unavailable', 'Incompatible native snapshot metadata')
    prefix = _prefix(row['table_prefix'])
    names = {prefix + '_visible': 'table', prefix + '_expansions': 'table'}
    for kind in ('summary', 'evidence'):
        owner = _prefix(row[kind + '_owner'], True)
        domain = conn.execute('SELECT * FROM main.rank_domains WHERE owner=?', (owner,)).fetchone()
        if domain is None or domain['kind'] != (0 if kind == 'summary' else 1) or domain['revision'] != REVISION or domain['token_version'] != TOKEN_VERSION:
            raise lexical.LexicalError('index_corrupt', 'Missing or incompatible native domain')
        if conn.execute('SELECT 1 FROM main.rank_revocations WHERE owner=?', (owner,)).fetchone():
            raise lexical.LexicalError('index_corrupt', 'The native domain has been explicitly revoked')
        names.update({owner + '_docs': 'table', owner + '_content': 'view', owner + '_fts': 'table',
                      **{owner + '_fts' + suffix: 'table' for suffix in ('_data', '_idx', '_docsize', '_config')}})
    placeholders = ','.join('?' for _ in names)
    observed = dict(conn.execute(f'SELECT name,type FROM main.sqlite_master WHERE name IN ({placeholders})', list(names)))
    if observed != names:
        raise lexical.LexicalError('index_corrupt', 'A published native index relation is missing')
    return row


def decode_key(raw):
    if type(raw) is not list or len(raw) != 9:
        raise ValueError('Invalid native cursor key')
    for i in (0, 2, 3, 5, 7):
        if type(raw[i]) is not int or not -(2**63) < raw[i] < 2**63:
            raise ValueError('Invalid native cursor integer')
    if raw[0] not in (0, 1) or raw[2] not in (0, 1) or raw[3] not in (0, 1) or raw[7] < 0:
        raise ValueError('Invalid native cursor enum')
    for i in (1, 4, 6, 8):
        if type(raw[i]) is not str or len(raw[i]) > 256 or any(ord(c) == 0 or 0xD800 <= ord(c) <= 0xDFFF for c in raw[i]):
            raise ValueError('Invalid native cursor string')
    try:
        score = float.fromhex(raw[1])
    except (ValueError, OverflowError) as exc:
        raise ValueError('Invalid native cursor score') from exc
    if not math.isfinite(score) or score > 0 or score.hex() != raw[1]:
        raise ValueError('Invalid native cursor score')
    return raw[0], score, *raw[2:]


def encode_key(key):
    return [key[0], key[1].hex(), *key[2:]]


def binding(snap, query, project_id, include_history):
    return {'revision': REVISION, 'ranking_snapshot_id': snap['snapshot_id'], 'generation_id': snap['generation_id'],
            'query': query, 'project_id': project_id, 'include_history': include_history}


def _first_match(conn, owner, doc_key, expression):
    fts, view = owner + '_fts', owner + '_content'
    for attempt in range(16):
        marker = MARKER + str(attempt)
        collision = conn.execute(f'SELECT instr(content,?) FROM main.{view} WHERE doc_key=?', (marker, doc_key)).fetchone()
        if collision is None or collision[0] is None:
            raise lexical.LexicalError('index_corrupt', 'Missing or oversized snippet source')
        if collision[0] == 0:
            break
    else:
        raise lexical.LexicalError('document_budget_exceeded', 'Unable to reserve a noncolliding snippet marker')
    position = conn.execute(f'''SELECT instr(highlight({fts},0,?,''),?)-1 FROM main.{fts}
              WHERE rowid=? AND {fts} MATCH ?''', (marker, marker, doc_key, expression)).fetchone()
    if position is None or position[0] < 0:
        raise lexical.LexicalError('index_corrupt', 'Native match position is unavailable')
    return {'native_first_match': (position[0], position[0] + 1)}


def search_page(conn, query, *, project_id=None, generation_id=None, include_history=False, after=None, limit=10):
    expression = match_expression(query)
    lexical._text(project_id, 'project_id', optional=True)
    lexical._text(generation_id, 'generation_id', optional=True)
    if type(include_history) is not bool or type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError('Invalid native history or page limit')
    if after is not None:
        if type(after) is not dict or set(after) != FIELDS:
            raise ValueError('Invalid native cursor fields')
        if generation_id is None:
            generation_id = after['generation_id']
    with store.query_budget(conn) as check:
        if not conn.in_transaction or conn.row_factory is not sqlite3.Row or conn.execute('PRAGMA query_only').fetchone()[0] != 1:
            raise ValueError('Native search requires a short query_only transaction')
        configure_connection(conn)
        store.check_schema(conn)
        generation = published_generation(conn, generation_id)
        snap = snapshot(conn, generation['id'])
        bound = binding(snap, query, project_id, include_history)
        if after is not None and any(type(after[k]) is not type(v) or after[k] != v for k, v in bound.items()):
            raise ValueError('Native cursor binding mismatch')
        last = decode_key(after['last']) if after is not None else None
        result = {'status': 'no_match', 'rows': [], 'next_key': None, 'generation_id': generation['id'],
                  'include_history': include_history, **metadata(conn), 'ranking_snapshot_id': snap['snapshot_id'],
                  'claim_boundary': 'unconfirmed_lexical_candidates', 'truncated': False}
        work = {'expanded_rows_examined': 0, 'payload_rows_read': 0, 'internal_engine_postings_work': 'not_measured'}
        result['work'] = work
        if not expression:
            return result
        selected = []
        prefix = snap['table_prefix']
        try:
            for kind, name in ((0, 'summary'), (1, 'evidence')):
                if last is not None and kind < last[0]:
                    continue
                owner = snap[name + '_owner']
                fts, docs = owner + '_fts', owner + '_docs'
                sql = f'''SELECT d.*,bm25({fts}) score,coalesce(x.membership,0) membership,
                      coalesce(x.provenance,'') provenance FROM main.{fts}
                    JOIN main.{docs} d ON d.doc_key={fts}.rowid
                    JOIN main.{prefix}_visible v ON v.domain={kind} AND v.doc_key=d.doc_key
                    LEFT JOIN main.{prefix}_expansions x ON x.domain={kind} AND x.doc_key=d.doc_key
                      AND (:history OR x.current=1) AND (:project IS NULL OR x.project=:project)
                    WHERE {fts} MATCH :expression AND (:history OR v.current=1)
                      AND ({kind}=1 OR :project IS NULL OR (d.target_type='project' AND d.target_id=:target))
                      AND ({kind}=0 OR x.membership IS NOT NULL)
                    ORDER BY score,d.priority,d.id_class,d.namespace,d.legacy_order,d.source_id,membership,provenance'''
                cursor = conn.execute(sql, {'history': include_history, 'project': project_id or None,
                      'target': slugify(project_id) if project_id else None, 'expression': expression})
                try:
                    for row in cursor:
                        check()
                        work['expanded_rows_examined'] += 1
                        if work['expanded_rows_examined'] > MAX_WORK:
                            raise lexical.LexicalError('budget_exceeded', 'Native expanded-row work budget exceeded')
                        score = row['score']
                        if type(score) is not float or not math.isfinite(score) or score > 0:
                            raise lexical.LexicalError('index_corrupt', 'Invalid native BM25 score')
                        key = (kind, score, row['priority'], row['id_class'], row['namespace'], row['legacy_order'],
                               row['source_id'], row['membership'], row['provenance'])
                        if last is None or key > last:
                            selected.append((key, owner, row['doc_key']))
                            if len(selected) == limit + 1:
                                break
                finally:
                    cursor.close()
                if len(selected) == limit + 1:
                    break
        except sqlite3.OperationalError as exc:
            if str(exc).startswith(('fts5: syntax error', 'unterminated string', 'unknown special query:')):
                raise lexical.LexicalError('invalid_query', 'The legacy parser produced invalid FTS syntax') from exc
            raise
        snippets = {}
        for key, owner, doc_key in selected[:limit]:
            check()
            old_key = (key[1], 1 if key[0] == 0 else 0, key[6], key[7], key[8])
            def loader(c, kind, identity, owner=owner, doc_key=doc_key):
                return _first_match(c, owner, doc_key, expression)
            row = lexical._result_row(conn, old_key, generation['id'], {'native_first_match': 1}, snippets,
                                      native_match='summary' if key[0] == 0 else 'body', span_loader=loader)
            row['result_key'] = encode_key(key)
            row['ranking_snapshot_id'] = snap['snapshot_id']
            result['rows'].append(row)
            work['payload_rows_read'] += 1
        result['status'] = 'ok' if result['rows'] else 'no_match'
        result['unavailable_candidates'] = sum(r['status'] in {'asset_unavailable', 'asset_corrupt'} for r in result['rows'])
        if len(selected) > limit:
            result['truncated'] = True
            result['next_key'] = {**bound, 'last': result['rows'][-1]['result_key']}
        return result
