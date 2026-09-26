from __future__ import annotations

from contextlib import contextmanager
from collections import Counter
from datetime import datetime, timezone
import json
import msvcrt
import os
import sqlite3
import sys
import threading
import time
from typing import Callable
import uuid

from ..config import DB_PATH, KB_ROOT
from ..runtime import kb_path, require_sandbox_writes, trace_event


SCHEMA_VERSION = "3"
STORAGE_REVISION = "w2-reviewed-r2"
_ownership = threading.local()
DDL = """
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE generations(
  id TEXT PRIMARY KEY, seq INTEGER NOT NULL UNIQUE,
  parent_id TEXT REFERENCES generations(id), state TEXT NOT NULL,
  label TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE projects(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, legacy_json TEXT NOT NULL,
  provenance_review TEXT NOT NULL DEFAULT 'unreviewed');
CREATE TABLE project_roots(
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
  host TEXT NOT NULL, path TEXT NOT NULL, state TEXT NOT NULL,
  observed_at TEXT NOT NULL, decision_source TEXT NOT NULL,
  UNIQUE(project_id,host,path));
CREATE TABLE files(
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
  source_snapshot_id TEXT, legacy_id INTEGER,
  UNIQUE(source_snapshot_id,legacy_id));
CREATE TABLE file_versions(
  id TEXT PRIMARY KEY, file_id TEXT NOT NULL REFERENCES files(id),
  legacy_json TEXT NOT NULL, parser_version TEXT NOT NULL,
  snapshot_state TEXT NOT NULL, asset_path TEXT,
  source_identity_json TEXT, created_at TEXT NOT NULL);
CREATE INDEX version_file ON file_versions(file_id,id);
CREATE TABLE file_memberships(
  id INTEGER PRIMARY KEY, file_id TEXT NOT NULL REFERENCES files(id),
  file_version_id TEXT NOT NULL REFERENCES file_versions(id),
  rel_path TEXT NOT NULL, valid_from INTEGER NOT NULL,
  valid_to INTEGER, tombstone INTEGER NOT NULL DEFAULT 0,
  CHECK(valid_to IS NULL OR valid_to > valid_from));
CREATE UNIQUE INDEX file_one_open_membership ON file_memberships(file_id) WHERE valid_to IS NULL;
CREATE INDEX membership_generation ON file_memberships(valid_from,valid_to,file_id);
CREATE INDEX membership_path ON file_memberships(rel_path,valid_from,valid_to);
CREATE INDEX membership_file ON file_memberships(file_id,valid_from);
CREATE TABLE text_bodies(
  id INTEGER PRIMARY KEY, parser_version TEXT NOT NULL,
  content TEXT NOT NULL COLLATE BINARY, char_length INTEGER NOT NULL,
  text_prefix TEXT NOT NULL COLLATE BINARY);
CREATE INDEX body_candidates ON text_bodies(parser_version,char_length,text_prefix);
CREATE TABLE evidence_occurrences(
  id TEXT PRIMARY KEY, file_version_id TEXT NOT NULL REFERENCES file_versions(id),
  body_id INTEGER NOT NULL REFERENCES text_bodies(id), kind TEXT NOT NULL,
  line_start INTEGER NOT NULL, line_end INTEGER NOT NULL,
  char_start INTEGER, char_end INTEGER, ordinal INTEGER NOT NULL,
  summary TEXT, legacy_json TEXT NOT NULL,
  UNIQUE(file_version_id,ordinal));
CREATE INDEX occurrence_body ON evidence_occurrences(body_id,file_version_id);
CREATE INDEX occurrence_file ON evidence_occurrences(file_version_id,id);
CREATE TABLE legacy_refs(
  snapshot_id TEXT NOT NULL, reference TEXT NOT NULL,
  evidence_id TEXT REFERENCES evidence_occurrences(id), status TEXT NOT NULL,
  PRIMARY KEY(snapshot_id,reference));
CREATE TABLE summaries(
  id INTEGER PRIMARY KEY AUTOINCREMENT, target_type TEXT NOT NULL,
  target_id TEXT NOT NULL, summary_type TEXT NOT NULL, content TEXT NOT NULL,
  evidence_ids TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  summary_family TEXT, supersedes_id INTEGER REFERENCES summaries(id),
  record_type TEXT NOT NULL DEFAULT 'legacy_unknown',
  content_status TEXT NOT NULL DEFAULT 'unconfirmed',
  applicability TEXT NOT NULL DEFAULT 'legacy_unclassified',
  provenance_review TEXT NOT NULL DEFAULT 'unreviewed',
  created_generation INTEGER NOT NULL);
CREATE INDEX summary_target ON summaries(target_type,target_id,id);
CREATE TABLE summary_evidence(
  summary_id INTEGER NOT NULL REFERENCES summaries(id), ordinal INTEGER NOT NULL,
  original_reference_json TEXT NOT NULL, reference_kind TEXT NOT NULL,
  evidence_id TEXT REFERENCES evidence_occurrences(id), status TEXT NOT NULL,
  PRIMARY KEY(summary_id,ordinal));
CREATE TABLE relations(
  id INTEGER PRIMARY KEY, source_type TEXT NOT NULL, source_id TEXT NOT NULL,
  target_type TEXT NOT NULL, target_id TEXT NOT NULL,
  relation_type TEXT NOT NULL, legacy_json TEXT NOT NULL,
  provenance_review TEXT NOT NULL DEFAULT 'unreviewed');
CREATE INDEX relation_source ON relations(source_id,source_type,relation_type);
CREATE INDEX relation_target ON relations(target_id,target_type,relation_type);
CREATE TABLE concepts(id TEXT PRIMARY KEY,name TEXT NOT NULL,legacy_json TEXT NOT NULL);
CREATE TABLE legacy_auxiliary(table_name TEXT NOT NULL,ordinal INTEGER NOT NULL,legacy_json TEXT NOT NULL,
  PRIMARY KEY(table_name,ordinal));
CREATE TABLE write_jobs(
  operation_id TEXT PRIMARY KEY, kind TEXT NOT NULL, request_json TEXT NOT NULL,
  result_json TEXT NOT NULL, committed_at TEXT NOT NULL);
CREATE TABLE write_journal(
  sequence INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL UNIQUE REFERENCES write_jobs(operation_id),
  kind TEXT NOT NULL, request_json TEXT NOT NULL, result_json TEXT NOT NULL, committed_at TEXT NOT NULL);
CREATE TABLE migration_progress(
  job_id TEXT NOT NULL, stage TEXT NOT NULL, cursor_value TEXT NOT NULL,
  completed INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(job_id,stage));
CREATE TABLE scan_jobs(
  operation_id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id),
  state TEXT NOT NULL, manifest_json TEXT NOT NULL, error_json TEXT,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
"""

for _table in ("files", "file_versions", "text_bodies", "evidence_occurrences", "legacy_refs",
               "summaries", "summary_evidence", "legacy_auxiliary", "write_jobs", "write_journal"):
    for _action in ("UPDATE", "DELETE"):
        DDL += (f"CREATE TRIGGER immutable_{_table}_{_action.lower()} BEFORE {_action} ON {_table} "
                "BEGIN SELECT RAISE(ABORT,'immutable record'); END;\n")
DDL += """
CREATE TRIGGER generation_identity BEFORE UPDATE ON generations
WHEN NEW.id IS NOT OLD.id OR NEW.seq IS NOT OLD.seq OR NEW.parent_id IS NOT OLD.parent_id
 OR NEW.label IS NOT OLD.label OR NEW.created_at IS NOT OLD.created_at
 OR OLD.state != 'building' OR NEW.state NOT IN ('published','aborted')
BEGIN SELECT RAISE(ABORT,'immutable generation'); END;
CREATE TRIGGER generation_delete BEFORE DELETE ON generations
BEGIN SELECT RAISE(ABORT,'immutable generation'); END;
CREATE TRIGGER membership_file_insert BEFORE INSERT ON file_memberships
WHEN NOT EXISTS(SELECT 1 FROM file_versions v WHERE v.id=NEW.file_version_id AND v.file_id=NEW.file_id)
BEGIN SELECT RAISE(ABORT,'version belongs to another file'); END;
CREATE TRIGGER membership_close_only BEFORE UPDATE ON file_memberships
WHEN NEW.id IS NOT OLD.id OR NEW.file_id IS NOT OLD.file_id
 OR NEW.file_version_id IS NOT OLD.file_version_id OR NEW.rel_path IS NOT OLD.rel_path
 OR NEW.valid_from IS NOT OLD.valid_from OR NEW.tombstone IS NOT OLD.tombstone
 OR OLD.valid_to IS NOT NULL OR NEW.valid_to IS NULL
BEGIN SELECT RAISE(ABORT,'membership can only close once'); END;
CREATE TRIGGER membership_delete BEFORE DELETE ON file_memberships
BEGIN SELECT RAISE(ABORT,'immutable membership'); END;
"""


class StorageError(RuntimeError):
    code = "storage_error"


class WriterBusy(StorageError):
    code = "writer_busy"


class OperationConflict(StorageError):
    code = "operation_id_conflict"


class SchemaMismatch(StorageError):
    code = "schema_mismatch"


class NotPublished(StorageError):
    code = "generation_not_published"


class QueryDeadline(StorageError):
    code = 'query_deadline_exceeded'


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


@contextmanager
def writer_lock(timeout: float = 5.0):
    require_sandbox_writes()
    if getattr(_ownership, "held", False):
        raise StorageError("Nested writer ownership is not supported")
    root = kb_path(KB_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    path = kb_path(root / "writer.lock")
    stream = path.open("a+b")
    acquired = False
    try:
        if os.fstat(stream.fileno()).st_size == 0:
            stream.write(b"0")
            stream.flush()
        deadline = time.monotonic() + timeout
        while True:
            stream.seek(0)
            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                acquired = True
                _ownership.held = True
                _ownership.connections = []
                _ownership.rank_commit_prefixes = set()
                _ownership.rank_committing = False
                break
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise WriterBusy("The v2 writer is busy; retry with the same operation ID") from exc
                time.sleep(0.025)
        yield
    finally:
        if acquired:
            for conn in _ownership.connections:
                conn.close()
            _ownership.connections = []
            _ownership.held = False
            _ownership.rank_commit_prefixes = set()
            _ownership.rank_committing = False
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        stream.close()


def check_schema(conn) -> None:
    try:
        row = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.OperationalError as exc:
        raise SchemaMismatch("Schema metadata is missing; explicit initialization is required") from exc
    if row is None or row[0] != SCHEMA_VERSION:
        raise SchemaMismatch("This entrypoint accepts schema 3 only")
    revision = conn.execute("SELECT value FROM meta WHERE key='storage_revision'").fetchone()
    if revision is None or revision[0] != STORAGE_REVISION:
        raise SchemaMismatch("Storage revision differs; preserve this candidate and initialize a new one")


def authorize_policy(action, first, second, database, origin):
    creates = {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_TEMP_TABLE, sqlite3.SQLITE_CREATE_VIEW,
               sqlite3.SQLITE_CREATE_TEMP_VIEW, sqlite3.SQLITE_CREATE_VTABLE, sqlite3.SQLITE_CREATE_INDEX,
               sqlite3.SQLITE_CREATE_TEMP_INDEX, sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_CREATE_TEMP_TRIGGER}
    drops = {sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_DROP_VTABLE, sqlite3.SQLITE_DROP_VIEW,
             sqlite3.SQLITE_DROP_INDEX, sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_ALTER_TABLE,
             sqlite3.SQLITE_DROP_TEMP_TABLE, sqlite3.SQLITE_DROP_TEMP_VIEW, sqlite3.SQLITE_DROP_TEMP_TRIGGER}
    dml = {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}
    names = [name.casefold() for name in (first, second) if isinstance(name, str)]
    source_names = {'meta', 'generations', 'projects', 'files', 'file_versions', 'file_memberships',
                    'text_bodies', 'evidence_occurrences', 'legacy_refs', 'summaries', 'summary_evidence'}
    source_ddl = {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_TEMP_TABLE, sqlite3.SQLITE_CREATE_VIEW,
                  sqlite3.SQLITE_CREATE_TEMP_VIEW, sqlite3.SQLITE_CREATE_VTABLE, sqlite3.SQLITE_CREATE_TEMP_TRIGGER}
    if action in source_ddl | drops and any(name in source_names for name in names):
        return sqlite3.SQLITE_DENY
    if action in creates | drops | dml:
        prefixes = getattr(_ownership, 'rank_build_prefixes', set())
        registry = {'rank_domains', 'rank_snapshots', 'rank_revocations'}
        for name in (name for name in names if name.startswith('rank_')):
            allowed = database == 'main' and any(name.startswith(prefix + '_') for prefix in prefixes)
            if database == 'main' and name in registry and action == sqlite3.SQLITE_INSERT:
                allowed = getattr(_ownership, 'rank_scope_active', False)
            if database == 'main' and getattr(_ownership, 'rank_registry_install', False):
                allowed = allowed or ((name in registry or name.startswith('rank_meta_')
                                       or any(name.startswith(table + '_') for table in registry))
                                      and action in creates | {sqlite3.SQLITE_INSERT})
            if database == 'main' and action == sqlite3.SQLITE_INSERT:
                allowed = allowed or name in getattr(_ownership, 'rank_validation_fts', set())
            # SQLite may flush an earlier new FTS domain when later DDL changes the schema.
            if (database == 'main' and action in dml
                    and (getattr(_ownership, 'rank_committing', False)
                         or getattr(_ownership, 'rank_scope_active', False))):
                allowed = allowed or any(name in {prefix + '_fts' + suffix
                                       for suffix in ('_data', '_idx', '_docsize', '_config')}
                                       for prefix in getattr(_ownership, 'rank_commit_prefixes', set()))
            if not allowed:
                trace_event('rank_write_denied', action=action, first=first, second=second, database=database,
                            building=sorted(prefixes), pending=sorted(getattr(_ownership, 'rank_commit_prefixes', set())),
                            committing=getattr(_ownership, 'rank_committing', False))
                return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_PRAGMA and second is not None and first.lower() in {
        'recursive_triggers', 'foreign_keys', 'writable_schema', 'ignore_check_constraints',
        'journal_mode', 'synchronous',
    }:
        return sqlite3.SQLITE_DENY
    if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_DROP_TRIGGER):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def connect_write() -> sqlite3.Connection:
    require_sandbox_writes()
    if not getattr(_ownership, "held", False):
        raise StorageError("A v2 write connection requires current writer ownership")
    database = kb_path(DB_PATH)
    conn = sqlite3.connect(database.as_uri() + "?mode=rw", uri=True, timeout=5, cached_statements=0)
    _ownership.connections.append(conn)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA recursive_triggers=ON")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("PRAGMA cache_size=-16384")
    try:
        check_schema(conn)
        from . import ranked
        ranked.configure_connection(conn)
        if conn.execute("SELECT 1 FROM main.meta WHERE key='rank_revision'").fetchone():
            ranked._limit_database(conn)
    except BaseException:
        conn.close()
        raise
    trace_event("database_open", path=str(database), readonly=False, api_version=2)
    conn.set_authorizer(authorize_policy)
    return conn


@contextmanager
def query_budget(conn, timeout_seconds=60):
    if not 0 < timeout_seconds <= 60:
        raise ValueError('Query deadline must be positive and at most 60 seconds')
    limits = getattr(_ownership, 'read_deadlines', None)
    if limits is None:
        limits = _ownership.read_deadlines = {}
    previous = limits.get(conn)
    deadline = min(previous or float('inf'), time.monotonic() + timeout_seconds)
    limits[conn] = deadline
    conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)

    def check():
        if time.monotonic() >= deadline:
            raise QueryDeadline('Query exceeded its execution deadline')

    try:
        check()
        yield check
        check()
    except sqlite3.OperationalError as exc:
        if time.monotonic() >= deadline and 'interrupted' in str(exc):
            raise QueryDeadline('Query exceeded its SQLite execution deadline') from exc
        raise
    finally:
        if previous is None:
            limits.pop(conn, None)
            conn.set_progress_handler(None, 0)
        else:
            limits[conn] = previous
            conn.set_progress_handler(lambda: int(time.monotonic() >= previous), 1000)


@contextmanager
def read_transaction(require_published: bool = True, *, timeout_seconds: float = 60):
    if not 0 < timeout_seconds <= 60:
        raise ValueError('Read deadline must be positive and at most 60 seconds')
    database = kb_path(DB_PATH)
    conn = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    operations = Counter()
    deadline, connection_id = time.monotonic() + timeout_seconds, new_id()
    if not hasattr(_ownership, 'read_deadlines'):
        _ownership.read_deadlines = {}
    _ownership.read_deadlines[conn] = deadline
    try:
        conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA cache_size=-16384")
        from . import ranked
        ranked.configure_connection(conn)
        check_schema(conn)
        conn.execute("BEGIN")
        if require_published and not conn.execute("SELECT 1 FROM meta m JOIN generations g ON g.id=m.value WHERE m.key='published_generation' AND g.state='published'").fetchone():
            raise NotPublished("No generation has been published")
        trace_event("database_open", path=str(database), readonly=True, api_version=2, connection_id=connection_id)
        conn.set_trace_callback(lambda sql: operations.update([sql.lstrip().split(None, 1)[0].upper()]))
        yield conn
    except sqlite3.OperationalError as exc:
        if time.monotonic() >= deadline and 'interrupted' in str(exc):
            raise QueryDeadline('Read exceeded its SQLite execution deadline') from exc
        raise
    finally:
        primary_error = sys.exc_info()[1]
        _ownership.read_deadlines.pop(conn, None)
        conn.close()
        # Aggregate every observed operation type without per-row filesystem logging overhead.
        for operation, count in sorted(operations.items()):
            try:
                trace_event("read_sql", operation=operation, count=count, aggregation="connection",
                            api_version=2, connection_id=connection_id)
            except Exception as exc:
                if primary_error is None:
                    raise
                primary_error.add_note('Secondary read trace failure: ' + type(exc).__name__)


def initialize() -> dict:
    with writer_lock():
        database = kb_path(DB_PATH)
        database.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(database, timeout=5)
        try:
            if conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
                check_schema(conn)
                return {"status": "already_initialized", "schema_version": SCHEMA_VERSION}
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.executescript("BEGIN IMMEDIATE;\n" + DDL + "\nINSERT INTO meta VALUES('schema_version','3');"
                               f"\nINSERT INTO meta VALUES('storage_revision','{STORAGE_REVISION}');\nCOMMIT;")
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()
    return {"status": "initialized", "schema_version": SCHEMA_VERSION}


def execute_operation(kind: str, operation_id: str, request: dict, handler: Callable, timeout: float = 5.0):
    if not operation_id or len(operation_id) > 240:
        raise ValueError("A nonempty operation ID of at most 240 characters is required")
    request_json = canonical(request)
    with writer_lock(timeout):
        conn = connect_write()
        try:
            conn.execute("BEGIN IMMEDIATE")
            old = conn.execute("SELECT * FROM write_jobs WHERE operation_id=?", (operation_id,)).fetchone()
            if old:
                if old["kind"] != kind or old["request_json"] != request_json:
                    raise OperationConflict("The operation ID was already used for a different request")
                conn.rollback()
                return json.loads(old["result_json"])
            # Handlers own domain DML, while this wrapper alone owns transaction boundaries.
            conn.set_authorizer(lambda action, *args: sqlite3.SQLITE_DENY
                                if action in (sqlite3.SQLITE_TRANSACTION, sqlite3.SQLITE_SAVEPOINT)
                                else authorize_policy(action, *args))
            try:
                indexes = None
                native = None
                maintenance = kind in {'lexical_install', 'lexical_rebuild', 'lexical_maintain', 'lexical_check',
                                       'rank_install', 'rank_check'}
                has_native = (conn.execute("SELECT 1 FROM main.meta WHERE key LIKE 'rank_%'").fetchone()
                              or conn.execute("SELECT 1 FROM main.sqlite_master WHERE name='rank_domains'").fetchone())
                if has_native and kind.startswith('lexical_'):
                    from .lexical import LexicalError
                    raise LexicalError('backend_unavailable', 'Lexical maintenance cannot modify a native-ranked store')
                if not maintenance and has_native:
                    from . import ranked
                    native = ranked
                    native.metadata(conn)
                    from .records import published_generation
                    native.snapshot(conn, published_generation(conn)['id'])
                elif not maintenance and conn.execute("SELECT 1 FROM meta WHERE key='lexical_revision'").fetchone():
                    from . import lexical
                    indexes = lexical
                    status = indexes._backend(conn)
                    if status != 'ok':
                        raise indexes.LexicalError(status, 'Finish explicit index maintenance before domain writes')
                result = handler(conn)
                if native is not None:
                    with query_budget(conn, timeout_seconds=60) as check:
                        native.refresh_snapshots(conn, check)
                if indexes is not None:
                    # Derived indexes and domain records must become visible together.
                    with query_budget(conn, timeout_seconds=60) as check:
                        while True:
                            check()
                            synchronized = indexes.refresh_indexes(conn, max_documents=256)
                            if not synchronized['pending']:
                                break
            finally:
                conn.set_authorizer(authorize_policy)
            result_json, committed_at = canonical(result), now()
            conn.execute("INSERT INTO write_jobs VALUES(?,?,?,?,?)", (operation_id, kind, request_json, result_json, committed_at))
            conn.execute("INSERT INTO write_journal(operation_id,kind,request_json,result_json,committed_at) VALUES(?,?,?,?,?)",
                         (operation_id, kind, request_json, result_json, committed_at))
            try:
                # FTS5 may flush newly built segments during the wrapper-owned commit.
                _ownership.rank_committing = True
                conn.commit()
            finally:
                _ownership.rank_committing = False
            return result
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


def body_id(conn, content: str, parser_version: str) -> int:
    values = (parser_version, len(content), content[:64], content)
    row = conn.execute("SELECT id FROM text_bodies WHERE parser_version=? AND char_length=? AND text_prefix=? AND content=?", values).fetchone()
    if row:
        return row[0]
    cursor = conn.execute("INSERT INTO text_bodies(parser_version,char_length,text_prefix,content) VALUES(?,?,?,?)", values)
    return cursor.lastrowid
