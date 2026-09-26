from __future__ import annotations

import sqlite3
from pathlib import Path

from .config import DB_PATH
from .runtime import kb_path, require_sandbox_writes, trace_event, trace_path


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  path TEXT NOT NULL UNIQUE,
  is_git INTEGER NOT NULL,
  git_head TEXT,
  readme_path TEXT,
  agents_path TEXT,
  file_count INTEGER NOT NULL DEFAULT 0,
  indexed_file_count INTEGER NOT NULL DEFAULT 0,
  chunk_count INTEGER NOT NULL DEFAULT 0,
  technologies TEXT NOT NULL DEFAULT '[]',
  domains TEXT NOT NULL DEFAULT '[]',
  domain_evidence TEXT NOT NULL DEFAULT '{}',
  readme_candidates TEXT NOT NULL DEFAULT '[]',
  entrypoints TEXT NOT NULL DEFAULT '[]',
  configs TEXT NOT NULL DEFAULT '[]',
  project_card_path TEXT,
  source_mtime_max REAL NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  rel_path TEXT NOT NULL,
  abs_path TEXT NOT NULL,
  size INTEGER NOT NULL,
  mtime REAL NOT NULL,
  sha256 TEXT,
  language TEXT,
  kind TEXT NOT NULL,
  indexed INTEGER NOT NULL,
  skipped_reason TEXT,
  UNIQUE(project_id, rel_path)
);

CREATE TABLE IF NOT EXISTS chunks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
  rel_path TEXT NOT NULL,
  kind TEXT NOT NULL,
  line_start INTEGER NOT NULL,
  line_end INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  content TEXT NOT NULL,
  summary TEXT,
  updated_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
  content,
  project_id UNINDEXED,
  chunk_id UNINDEXED,
  rel_path UNINDEXED,
  tokenize='unicode61'
);

CREATE TABLE IF NOT EXISTS concepts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  description TEXT,
  project_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS relations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  relation_type TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  evidence TEXT,
  weight REAL NOT NULL DEFAULT 1.0,
  status TEXT NOT NULL DEFAULT 'confirmed',
  updated_at TEXT NOT NULL,
  UNIQUE(source_type, source_id, relation_type, target_type, target_id)
);

CREATE TABLE IF NOT EXISTS summaries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  summary_type TEXT NOT NULL,
  content TEXT NOT NULL,
  evidence_ids TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS summaries_fts USING fts5(
  content,
  target_type UNINDEXED,
  target_id UNINDEXED,
  summary_type UNINDEXED,
  summary_id UNINDEXED,
  tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS summaries_ai AFTER INSERT ON summaries BEGIN
  INSERT INTO summaries_fts(rowid, content, target_type, target_id, summary_type, summary_id)
  VALUES (new.id, new.content, new.target_type, new.target_id, new.summary_type, new.id);
END;

CREATE TRIGGER IF NOT EXISTS summaries_ad AFTER DELETE ON summaries BEGIN
  DELETE FROM summaries_fts WHERE rowid = old.id;
END;

CREATE TRIGGER IF NOT EXISTS summaries_au AFTER UPDATE ON summaries BEGIN
  DELETE FROM summaries_fts WHERE rowid = old.id;
  INSERT INTO summaries_fts(rowid, content, target_type, target_id, summary_type, summary_id)
  VALUES (new.id, new.content, new.target_type, new.target_id, new.summary_type, new.id);
END;

CREATE TABLE IF NOT EXISTS run_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  command TEXT NOT NULL,
  scope TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  status TEXT NOT NULL,
  message TEXT
);

CREATE INDEX IF NOT EXISTS idx_files_project ON files(project_id);
CREATE INDEX IF NOT EXISTS idx_chunks_project ON chunks(project_id);
CREATE INDEX IF NOT EXISTS idx_chunks_file ON chunks(file_id);
CREATE INDEX IF NOT EXISTS idx_rel_source ON relations(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_rel_target ON relations(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_summaries_target ON summaries(target_type, target_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_summaries_type ON summaries(summary_type, id DESC);
"""


def check_legacy_schema(conn: sqlite3.Connection, *, allow_empty: bool = False) -> None:
    if allow_empty and not conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone():
        return
    try:
        version = conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.OperationalError as exc:
        raise RuntimeError("Unsupported schema version; explicit compatible initialization is required") from exc
    if version is None or version[0] != "2":
        raise RuntimeError("Unsupported schema version; run an explicit compatible migration")


def connect(db_path: Path = DB_PATH, *, bootstrap: bool = False) -> sqlite3.Connection:
    require_sandbox_writes()
    db_path = kb_path(db_path)
    if bootstrap:
        db_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "rwc" if bootstrap else "rw"
    conn = sqlite3.connect(db_path.as_uri() + "?mode=" + mode, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        check_legacy_schema(conn, allow_empty=bootstrap)
        conn.execute("PRAGMA foreign_keys=ON")
        trace_event("database_open", path=str(db_path), readonly=False)
        return conn
    except BaseException:
        conn.close()
        raise


def read_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    db_path = kb_path(db_path)
    trace_path()
    conn = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA foreign_keys=ON")
        check_legacy_schema(conn)
        trace_event("database_open", path=str(db_path), readonly=True)
        conn.set_trace_callback(
            lambda sql: trace_event("read_sql", operation=sql.lstrip().split(None, 1)[0].upper())
        )
        return conn
    except BaseException:
        conn.close()
        raise


def init_db(conn: sqlite3.Connection) -> None:
    require_sandbox_writes()
    database = conn.execute("PRAGMA database_list").fetchone()[2]
    kb_path(Path(database))
    check_legacy_schema(conn, allow_empty=True)
    conn.executescript(SCHEMA)
    ensure_column(conn, "projects", "domain_evidence", "TEXT NOT NULL DEFAULT '{}'")
    ensure_column(conn, "projects", "readme_candidates", "TEXT NOT NULL DEFAULT '[]'")
    conn.execute(
        """
        INSERT INTO summaries_fts(rowid, content, target_type, target_id, summary_type, summary_id)
        SELECT s.id, s.content, s.target_type, s.target_id, s.summary_type, s.id
        FROM summaries s
        WHERE NOT EXISTS (
          SELECT 1 FROM summaries_fts sf WHERE sf.rowid = s.id
        )
        """
    )
    conn.execute(
        "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '2')"
    )
    conn.commit()


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
