from __future__ import annotations

from collections import Counter
from contextlib import contextmanager, nullcontext
import ctypes
from ctypes import wintypes
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import time

import psutil

from ..config import DB_PATH
from ..runtime import EXECUTION_ROOT, bounded_path, trace_event
from .store import body_id, canonical, execute_operation, initialize, new_id, now, read_transaction


PARSER = "legacy-extracted-unknown-version"
TABLES = ("projects", "files", "chunks", "summaries", "relations", "concepts")


class MigrationBudget:
    def __init__(self, seconds=1800):
        self.started = time.monotonic()
        self.seconds = seconds
        self.peak_rss = 0

    def check(self):
        rss = psutil.Process().memory_info().rss
        self.peak_rss = max(self.peak_rss, rss)
        if time.monotonic() - self.started > self.seconds:
            raise TimeoutError("Migration exceeded its bounded runtime")
        if rss > 2 * 1024**3 or psutil.virtual_memory().available < 8 * 1024**3:
            raise MemoryError("Migration memory reserve reached")
        if shutil.disk_usage(EXECUTION_ROOT).free < 10 * 1024**3:
            raise OSError("Migration disk reserve reached")


@contextmanager
def source_connection(path: Path):
    path = bounded_path(path, EXECUTION_ROOT)
    if path == DB_PATH:
        raise ValueError("The migration source and destination must differ")
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x80, None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    conn = None
    try:
        for suffix in ('-wal', '-journal'):
            sidecar = Path(str(path) + suffix)
            if sidecar.exists() and sidecar.stat().st_size:
                raise ValueError('Migration requires a standalone checkpointed snapshot')
        conn = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=5)
        yield from _source_transaction(conn, path)
    finally:
        if conn is not None:
            conn.close()
        kernel.CloseHandle(handle)


def _source_transaction(conn, path):
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA cache_size=-16384")
        conn.execute("BEGIN")
        version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if version is None or version[0] != "2":
            raise ValueError("Only an explicit schema-2 snapshot can be imported")
        trace_event("migration_source_open", path=str(path), readonly=True)
        yield conn
    finally:
        conn.close()


def source_counts(conn):
    return {table: conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] for table in TABLES}


def source_signature(path: Path):
    info = path.stat()
    with path.open("rb") as stream:
        header = stream.read(100).hex()
        stream.seek(0)
        identity = hashlib.file_digest(stream, "sha256").hexdigest()
    wal = Path(str(path) + "-wal")
    wal_info = wal.stat() if wal.exists() else None
    wal_signature = None
    if wal_info and wal_info.st_size:
        with wal.open("rb") as stream:
            wal_header = stream.read(32).hex()
        wal_signature = [wal_info.st_size, wal_info.st_mtime_ns, wal_header]
    # The database digest binds input identity only, never document content acceptance.
    return {"size": info.st_size, "mtime_ns": info.st_mtime_ns, "sqlite_header": header,
            "wal": wal_signature, "database_byte_identity_sha256": identity}


def start_migration(src, source: Path, snapshot_id: str):
    counts = source_counts(src)
    request = {"source": str(source), "snapshot_id": snapshot_id, "counts": counts, "signature": source_signature(source)}

    def write(conn):
        if conn.execute("SELECT 1 FROM projects LIMIT 1").fetchone() or conn.execute("SELECT 1 FROM generations LIMIT 1").fetchone():
            raise ValueError("A migration starts only in an empty candidate")
        generation = new_id()
        conn.execute("INSERT INTO generations VALUES(?,1,NULL,'building',?,?)", (generation, snapshot_id, now()))
        for key, value in (("source_snapshot_id", snapshot_id), ("source_path", str(source)), ("migration_state", "building")):
            conn.execute("INSERT INTO meta VALUES(?,?)", (key, value))
        schema = [dict(row) for row in src.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name")]
        conn.execute("INSERT INTO meta VALUES('legacy_schema_json',?)", (canonical(schema),))
        return {"generation": generation, "counts": counts}

    return execute_operation("migration_start", snapshot_id + ":start", request, write)


def import_projects(conn, rows, snapshot_id):
    for row in rows:
        legacy = dict(row)
        conn.execute("INSERT INTO projects(id,name,legacy_json) VALUES(?,?,?)", (row["id"], row["name"], canonical(legacy)))
        path = Path(row["path"])
        state = "available_at_observation" if path.is_dir() else "source_unavailable"
        conn.execute("INSERT INTO project_roots VALUES(?,?,?,?,?,?,?)",
                     (new_id(), row["id"], "local", row["path"], state, now(), "current_path_is_dir_probe"))


def import_files(conn, rows, snapshot_id):
    for row in rows:
        file_id, version_id = new_id(), new_id()
        conn.execute("INSERT INTO files VALUES(?,?,?,?)", (file_id, row["project_id"], snapshot_id, row["id"]))
        conn.execute("INSERT INTO file_versions VALUES(?,?,?,?,?,?,?,?)",
                     (version_id, file_id, canonical(dict(row)), PARSER,
                      "legacy_extracted_only" if row["indexed"] else "metadata_only", None, None, now()))
        conn.execute("INSERT INTO file_memberships(file_id,file_version_id,rel_path,valid_from) VALUES(?,?,?,1)",
                     (file_id, version_id, row["rel_path"]))


def import_chunks(conn, rows, snapshot_id):
    for row in rows:
        version = conn.execute("SELECT m.file_version_id FROM files f JOIN file_memberships m ON m.file_id=f.id WHERE f.source_snapshot_id=? AND f.legacy_id=? AND m.valid_from=1",
                               (snapshot_id, row["file_id"])).fetchone()
        if not version:
            raise ValueError("Chunk references an unimported file")
        occurrence = new_id()
        metadata = dict(row)
        content = metadata.pop("content")
        body = body_id(conn, content, PARSER)
        conn.execute("INSERT INTO evidence_occurrences VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                     (occurrence, version[0], body, row["kind"], row["line_start"], row["line_end"], None, None,
                      row["id"], row["summary"], canonical(metadata)))
        conn.execute("INSERT INTO legacy_refs VALUES(?,?,?,'resolved_snapshot')", (snapshot_id, str(row["id"]), occurrence))


def classify_reference(conn, value, snapshot_id):
    token = str(value)
    match = re.fullmatch(r"(?:chunk:)?([0-9]+)", token)
    if not match:
        return "path_or_label", None, "unclassified_legacy"
    found = conn.execute("SELECT evidence_id FROM legacy_refs WHERE snapshot_id=? AND reference=?", (snapshot_id, str(int(match[1])))).fetchone()
    evidence = found[0] if found else None
    status = "resolved_snapshot" if evidence else "unresolved_legacy"
    conn.execute("INSERT OR IGNORE INTO legacy_refs VALUES(?,?,?,?)", (snapshot_id, token, evidence, status))
    return "chunk_id", evidence, status


def import_summaries(conn, rows, snapshot_id):
    for row in rows:
        columns = ("id", "target_type", "target_id", "summary_type", "content", "evidence_ids", "created_at", "updated_at")
        conn.execute("INSERT INTO summaries(" + ",".join(columns) + ",created_generation) VALUES(?,?,?,?,?,?,?,?,1)", tuple(row[column] for column in columns))
        references = json.loads(row["evidence_ids"])
        if not isinstance(references, list):
            raise ValueError("Legacy summary evidence_ids must be a list")
        for ordinal, value in enumerate(references):
            kind, evidence, status = classify_reference(conn, value, snapshot_id)
            conn.execute("INSERT INTO summary_evidence VALUES(?,?,?,?,?,?)", (row["id"], ordinal, canonical(value), kind, evidence, status))


def import_relations(conn, rows, snapshot_id):
    for row in rows:
        conn.execute("INSERT INTO relations(id,source_type,source_id,target_type,target_id,relation_type,legacy_json) VALUES(?,?,?,?,?,?,?)",
                     (row["id"], row["source_type"], row["source_id"], row["target_type"], row["target_id"], row["relation_type"], canonical(dict(row))))


def import_concepts(conn, rows, snapshot_id):
    for row in rows:
        conn.execute("INSERT INTO concepts VALUES(?,?,?)", (row["id"], row["name"], canonical(dict(row))))


IMPORTERS = {"projects": import_projects, "files": import_files, "chunks": import_chunks,
             "summaries": import_summaries, "relations": import_relations, "concepts": import_concepts}


def migrate(source: Path, snapshot_id: str, batch_size: int = 256, max_batches: int | None = None):
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,120}", snapshot_id):
        raise ValueError("Invalid snapshot identifier")
    if not 1 <= batch_size <= 1024:
        raise ValueError("Batch size must be between 1 and 1024")
    source = bounded_path(source, EXECUTION_ROOT)
    initialize()
    budget, batches = MigrationBudget(), 0
    with source_connection(source) as src:
        signature = source_signature(source)
        binding = start_migration(src, source, snapshot_id)
        for table, importer in IMPORTERS.items():
            with read_transaction(False) as conn:
                old = conn.execute("SELECT cursor_value,completed FROM migration_progress WHERE job_id=? AND stage=?", (snapshot_id, table)).fetchone()
            if old and old[1]:
                continue
            cursor = json.loads(old[0]) if old else ("" if table in {"projects", "concepts"} else 0)
            while True:
                budget.check()
                deadline = time.monotonic() + 60
                src.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
                rows = src.execute(f"SELECT * FROM {table} WHERE id>? ORDER BY id LIMIT ?", (cursor, batch_size)).fetchall()
                next_cursor = rows[-1]["id"] if rows else cursor
                completed = not rows
                request = {"snapshot_id": snapshot_id, "table": table, "after": cursor, "through": next_cursor, "count": len(rows)}

                def write(conn):
                    importer(conn, rows, snapshot_id)
                    conn.execute("INSERT INTO migration_progress VALUES(?,?,?,?) ON CONFLICT(job_id,stage) DO UPDATE SET cursor_value=excluded.cursor_value,completed=excluded.completed",
                                 (snapshot_id, table, canonical(next_cursor), int(completed)))
                    return {"table": table, "cursor": next_cursor, "imported": len(rows), "completed": completed}

                result = execute_operation("migration_batch", f"{snapshot_id}:{table}:{cursor}", request, write)
                cursor = result["cursor"]
                batches += 1
                if batches % 50 == 0 or result["completed"]:
                    print(canonical({"event": "migration_progress", **result, "batches_this_run": batches}), flush=True)
                if max_batches is not None and batches >= max_batches:
                    return {"status": "paused", "batches": batches, "generation": binding["generation"]}
                if result["completed"]:
                    break
        auxiliary(src, snapshot_id)
        def publish(conn):
            checks = verify_migration(src, snapshot_id, budget, destination=conn)
            if source_signature(source) != signature:
                raise RuntimeError("The source snapshot changed during migration; candidate remains unpublished")
            changed = conn.execute("UPDATE generations SET state='published' WHERE id=? AND state='building'", (binding["generation"],))
            if changed.rowcount != 1:
                raise RuntimeError('Publication requires exactly one building generation')
            conn.execute("INSERT INTO meta VALUES('published_generation',?)", (binding["generation"],))
            conn.execute("UPDATE meta SET value='complete' WHERE key='migration_state'")
            return {"status": "migrated", "generation": binding["generation"], "checks": checks}

        result = execute_operation("migration_publish", snapshot_id + ":publish",
                                   {"generation": binding["generation"], "source_identity": signature}, publish)
        return {**result, "seconds": time.monotonic() - budget.started, "observed_peak_rss_bytes": budget.peak_rss}


def auxiliary(src, snapshot_id):
    tables = [name for name in ("meta", "run_log", "sqlite_sequence", "sqlite_stat1")
              if src.execute("SELECT 1 FROM sqlite_master WHERE name=?", (name,)).fetchone()]

    def write(conn):
        for table in tables:
            for ordinal, row in enumerate(src.execute(f"SELECT * FROM {table} ORDER BY rowid")):
                conn.execute("INSERT INTO legacy_auxiliary VALUES(?,?,?)", (table, ordinal, canonical(dict(row))))
        return {"tables": tables}

    return execute_operation("migration_auxiliary", snapshot_id + ":auxiliary", {"snapshot_id": snapshot_id, "tables": tables}, write)


def verify_migration(src, snapshot_id, budget=None, destination=None):
    budget = budget or MigrationBudget()
    counts = source_counts(src)
    compared = Counter()
    with (nullcontext(destination) if destination is not None else read_transaction(False)) as dst:
        for table in TABLES:
            deadline = time.monotonic() + 60
            src.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
            cursor = src.execute(f"SELECT * FROM {table} ORDER BY id")
            while rows := cursor.fetchmany(256):
                budget.check()
                deadline = time.monotonic() + 60
                for row in rows:
                    expected = dict(row)
                    if table == "files":
                        result = dst.execute("SELECT v.legacy_json,f.project_id,v.file_id,f.id,m.rel_path,m.valid_to,m.tombstone,v.parser_version,v.snapshot_state,v.asset_path,v.source_identity_json FROM files f JOIN file_memberships m ON m.file_id=f.id AND m.valid_from=1 JOIN file_versions v ON v.id=m.file_version_id WHERE f.source_snapshot_id=? AND f.legacy_id=?",
                                             (snapshot_id, row["id"])).fetchone()
                        want = (row['project_id'], result[3] if result else None, result[3] if result else None,
                                row['rel_path'], None, 0, PARSER,
                                'legacy_extracted_only' if row['indexed'] else 'metadata_only', None, None)
                        if result is None or tuple(result)[1:] != want:
                            raise AssertionError(f"File provenance mismatch: {row['id']}")
                    elif table == "chunks":
                        result = dst.execute("""SELECT e.legacy_json,b.content,f.legacy_id,f.project_id,m.rel_path,
                            e.kind,e.line_start,e.line_end,e.char_start,e.char_end,e.ordinal,e.summary,
                            v.parser_version,b.parser_version,b.char_length,b.text_prefix,l.status,f.source_snapshot_id
                            FROM legacy_refs l JOIN evidence_occurrences e ON e.id=l.evidence_id
                            JOIN text_bodies b ON b.id=e.body_id JOIN file_versions v ON v.id=e.file_version_id
                            JOIN files f ON f.id=v.file_id JOIN file_memberships m ON m.file_version_id=v.id
                            AND m.file_id=f.id AND m.valid_from=1 WHERE l.snapshot_id=? AND l.reference=?""",
                                             (snapshot_id, str(row["id"]))).fetchone()
                        content = expected.pop('content')
                        if result is None or result[1] != content:
                            raise AssertionError(f"Chunk content mismatch: {row['id']}")
                        want = (row['file_id'], row['project_id'], row['rel_path'], row['kind'], row['line_start'],
                                row['line_end'], None, None, row['id'], row['summary'], PARSER, PARSER,
                                len(content), content[:64], 'resolved_snapshot', snapshot_id)
                        if tuple(result)[2:] != want:
                            raise AssertionError(f"Chunk provenance mismatch: {row['id']}")
                    elif table == "summaries":
                        result = dst.execute("SELECT id,target_type,target_id,summary_type,content,evidence_ids,created_at,updated_at FROM summaries WHERE id=?", (row["id"],)).fetchone()
                        if result is None or dict(result) != expected:
                            raise AssertionError(f"Summary mismatch: {row['id']}")
                        verify_summary_references(src, dst, row, snapshot_id)
                        governance = dst.execute('SELECT summary_family,supersedes_id,record_type,content_status,applicability,provenance_review,created_generation FROM summaries WHERE id=?', (row['id'],)).fetchone()
                        if tuple(governance) != (None, None, 'legacy_unknown', 'unconfirmed', 'legacy_unclassified', 'unreviewed', 1):
                            raise AssertionError(f"Summary governance mismatch: {row['id']}")
                        compared[table] += 1
                        continue
                    else:
                        actual = dst.execute(f"SELECT * FROM {table} WHERE id=?", (row["id"],)).fetchone()
                        result = (actual['legacy_json'],) if actual else None
                        if actual is not None:
                            for key in set(actual.keys()) & set(expected) - {'legacy_json'}:
                                if actual[key] != expected[key]:
                                    raise AssertionError(f"Typed field mismatch: {table}/{row['id']}/{key}")
                            if 'provenance_review' in actual.keys() and actual['provenance_review'] != 'unreviewed':
                                raise AssertionError('Legacy governance was promoted')
                        if table == 'projects':
                            root = dst.execute('SELECT host,path,state,decision_source FROM project_roots WHERE project_id=?', (row['id'],)).fetchall()
                            if len(root) != 1 or tuple(root[0])[:2] != ('local', row['path']):
                                raise AssertionError(f"Project root mismatch: {row['id']}")
                    if result is None or json.loads(result[0]) != expected:
                        raise AssertionError(f"Legacy field mismatch: {table}/{row['id']}")
                    compared[table] += 1
                if compared[table] % 16384 == 0:
                    print(canonical({"event": "migration_validation", "table": table, "compared": compared[table]}), flush=True)
            target = "evidence_occurrences" if table == "chunks" else table
            if dst.execute(f"SELECT count(*) FROM {target}").fetchone()[0] != counts[table]:
                raise AssertionError(f"Cardinality mismatch: {table}")
        if dst.execute("PRAGMA foreign_key_check").fetchall():
            raise AssertionError("Foreign key validation failed")
        for table, expected_count in [('file_versions', counts['files']), ('file_memberships', counts['files']), ('project_roots', counts['projects'])]:
            if dst.execute(f'SELECT count(*) FROM {table}').fetchone()[0] != expected_count:
                raise AssertionError(f'Cardinality mismatch: {table}')
        verify_auxiliary(src, dst)
        verify_legacy_aliases(src, dst, snapshot_id)
        reference_states = dict(dst.execute("SELECT status,count(*) FROM summary_evidence GROUP BY status"))
        bodies = dst.execute("SELECT count(*) FROM text_bodies").fetchone()[0]
        orphan = dst.execute("SELECT 1 FROM text_bodies b WHERE NOT EXISTS(SELECT 1 FROM evidence_occurrences e WHERE e.body_id=b.id) LIMIT 1").fetchone()
        if orphan:
            raise AssertionError("Unreferenced text body found")
    return {"all_legacy_fields_equal": True, "compared": dict(compared), "text_bodies": bodies,
            "summary_reference_states": reference_states, "foreign_key_errors": 0}


def expected_reference(src, dst, snapshot_id, value):
    token = str(value)
    match = re.fullmatch(r'(?:chunk:)?([0-9]+)', token)
    if not match:
        return 'path_or_label', None, 'unclassified_legacy'
    chunk_id = int(match[1])
    exists = src.execute('SELECT 1 FROM chunks WHERE id=?', (chunk_id,)).fetchone()
    if not exists:
        return 'chunk_id', None, 'unresolved_legacy'
    found = dst.execute('SELECT evidence_id,status FROM legacy_refs WHERE snapshot_id=? AND reference=?',
                        (snapshot_id, str(chunk_id))).fetchone()
    if not found or not found[0] or found[1] != 'resolved_snapshot':
        raise AssertionError('A known source reference is not resolved')
    return 'chunk_id', found[0], 'resolved_snapshot'


def verify_summary_references(src, dst, row, snapshot_id):
    references = json.loads(row['evidence_ids'])
    actual = dst.execute('SELECT ordinal,original_reference_json,reference_kind,evidence_id,status FROM summary_evidence WHERE summary_id=? ORDER BY ordinal', (row['id'],)).fetchall()
    expected = [(ordinal, canonical(value), *expected_reference(src, dst, snapshot_id, value))
                for ordinal, value in enumerate(references)]
    if [tuple(item) for item in actual] != expected:
        raise AssertionError(f"Summary reference mismatch: {row['id']}")


def verify_legacy_aliases(src, dst, snapshot_id):
    extras = {}
    for row in src.execute('SELECT evidence_ids FROM summaries ORDER BY id'):
        for value in json.loads(row[0]):
            kind, evidence, status = expected_reference(src, dst, snapshot_id, value)
            if kind == 'chunk_id':
                token = str(value)
                actual = dst.execute('SELECT evidence_id,status FROM legacy_refs WHERE snapshot_id=? AND reference=?', (snapshot_id, token)).fetchone()
                if actual is None or tuple(actual) != (evidence, status):
                    raise AssertionError('Legacy alias mismatch')
                match = re.fullmatch(r'(?:chunk:)?([0-9]+)', token)
                if token != str(int(match[1])) or status != 'resolved_snapshot':
                    extras[token] = True
    expected_count = src.execute('SELECT count(*) FROM chunks').fetchone()[0] + len(extras)
    if dst.execute('SELECT count(*) FROM legacy_refs').fetchone()[0] != expected_count:
        raise AssertionError('Extra or missing legacy aliases')


def verify_auxiliary(src, dst):
    total = 0
    for table in ('meta', 'run_log', 'sqlite_sequence', 'sqlite_stat1'):
        if not src.execute('SELECT 1 FROM sqlite_master WHERE name=?', (table,)).fetchone():
            continue
        count = 0
        for ordinal, row in enumerate(src.execute(f'SELECT * FROM {table} ORDER BY rowid')):
            actual = dst.execute('SELECT legacy_json FROM legacy_auxiliary WHERE table_name=? AND ordinal=?', (table, ordinal)).fetchone()
            if actual is None or json.loads(actual[0]) != dict(row):
                raise AssertionError(f'Auxiliary field mismatch: {table}/{ordinal}')
            count += 1
        total += count
    if dst.execute('SELECT count(*) FROM legacy_auxiliary').fetchone()[0] != total:
        raise AssertionError('Auxiliary cardinality mismatch')
    schema = [dict(row) for row in src.execute('SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name')]
    actual = dst.execute("SELECT value FROM meta WHERE key='legacy_schema_json'").fetchone()
    if actual is None or json.loads(actual[0]) != schema:
        raise AssertionError('Legacy schema mismatch')
