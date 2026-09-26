"""Explicit, budgeted v2 read surfaces and controlled feature initialization."""

from __future__ import annotations

import base64
import codecs
from contextlib import contextmanager
import hashlib
import hmac
import json
import re
import secrets
import time


WIRE_LIMIT = 65536
PAYLOAD_LIMIT = 30720
READ_SECONDS = 60.0
FEATURE_REVISION = "w5-api-1"
FEATURE_KEY = "api.feature_revision"
CURSOR_KEY = "api.cursor_hmac_key"
RETENTION_PREFIX = "api.cursor_expired:"
RELATED_SCOPE_REVISION = "published-lineage-v1"
SUCCESS = {"ok", "no_match", "saved", "registered", "refreshed", "initialized", "already_initialized",
           "api_initialized", "cursor_retention_marked"}
SUMMARY_COLUMNS = ("id", "target_type", "target_id", "summary_type", "evidence_ids", "created_at", "updated_at",
                   "summary_family", "supersedes_id", "record_type", "content_status", "applicability",
                   "provenance_review", "created_generation")


class ApiError(RuntimeError):
    def __init__(self, code, message, **details):
        super().__init__(message)
        self.code = code
        self.details = details


def encode(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def encoded_size(value) -> int:
    return len(encode(value).encode("utf-8"))


def finalize(value: dict) -> dict:
    value = {"api_version": 2, **value}
    value.setdefault("errorcode", None if value.get("status") in SUCCESS else value.get("status", "backend_unavailable"))
    if encoded_size(value) > PAYLOAD_LIMIT:
        raise ApiError("budget_too_small", "Required metadata and response framing exceed the logical payload budget")
    return value


def _text_budget(value: dict, field: str, offset: int, total: int) -> dict:
    text = value[field]

    def candidate(size):
        end = offset + size
        return {**value, field: text[:size], "next_offset": end if end < total else None,
                "truncated": end < total, "budget_truncated": size < len(text)}

    # A terminal response can be smaller than its continuation-only framing.
    try:
        return finalize(candidate(len(text)))
    except ApiError as exc:
        if exc.code != "budget_too_small":
            raise
    # Do not drop metadata to make room for the content window.
    finalize(candidate(0))
    low, high = 0, len(text)
    while low < high:
        mid = (low + high + 1) // 2
        if encoded_size({"api_version": 2, "errorcode": None, **candidate(mid)}) <= PAYLOAD_LIMIT:
            low = mid
        else:
            high = mid - 1
    if text and low == 0:
        raise ApiError("budget_too_small", "Metadata leaves no room for a nonempty Unicode window")
    return finalize(candidate(low))


def _check(deadline):
    if time.monotonic() >= deadline:
        raise ApiError("deadline_exceeded", "The read work deadline was exceeded")


@contextmanager
def _read():
    from . import store

    deadline = time.monotonic() + READ_SECONDS
    try:
        with store.read_transaction(require_published=False, timeout_seconds=READ_SECONDS) as conn:
            _check(deadline)
            key = _feature(conn)
            yield conn, key, deadline
            _check(deadline)
    except store.StorageError as exc:
        if exc.code == "query_deadline_exceeded":
            raise ApiError("deadline_exceeded", "The SQLite read was interrupted at its work deadline") from exc
        raise


def _feature(conn) -> bytes:
    values = dict(conn.execute("SELECT key,value FROM meta WHERE key IN (?,?)", (FEATURE_KEY, CURSOR_KEY)))
    key = values.get(CURSOR_KEY, "")
    if values.get(FEATURE_KEY) != FEATURE_REVISION or not re.fullmatch(r"[0-9a-f]{64}", key):
        raise ApiError("backend_unavailable", "Explicit init-api is required for this API feature revision")
    return bytes.fromhex(key)


def initialize(operation_id: str) -> dict:
    from .store import execute_operation

    def write(conn):
        existing = dict(conn.execute("SELECT key,value FROM meta WHERE key IN (?,?)", (FEATURE_KEY, CURSOR_KEY)))
        if existing:
            _feature(conn)
        else:
            conn.executemany("INSERT INTO meta VALUES(?,?)", [(FEATURE_KEY, FEATURE_REVISION), (CURSOR_KEY, secrets.token_hex(32))])
        return {"status": "api_initialized", "feature_revision": FEATURE_REVISION, "operation_id": operation_id}

    return finalize(execute_operation("api_initialize", operation_id, {"feature_revision": FEATURE_REVISION}, write))


def expire_cursors(operation_id: str, generation_id: str) -> dict:
    from .records import published_generation
    from .store import execute_operation

    def write(conn):
        _feature(conn)
        published_generation(conn, generation_id)
        conn.execute("INSERT INTO meta VALUES(?,'expired') ON CONFLICT(key) DO NOTHING", (RETENTION_PREFIX + generation_id,))
        return {"status": "cursor_retention_marked", "generation": generation_id, "operation_id": operation_id}

    return finalize(execute_operation("api_expire_cursors", operation_id, {"generation_id": generation_id}, write))


def _generation(conn, generation_id=None, cursor=False):
    from .records import published_generation
    from .store import NotPublished

    try:
        generation = published_generation(conn, generation_id)
    except NotPublished as exc:
        if cursor:
            raise ApiError("invalid_cursor", "Cursor generation is unknown or was never published") from exc
        raise
    if cursor:
        _retained(conn, generation["id"])
    return generation


def _retained(conn, generation_id):
    marker = conn.execute("SELECT value FROM meta WHERE key=?", (RETENTION_PREFIX + generation_id,)).fetchone()
    if marker:
        if marker[0] != "expired":
            raise ApiError("backend_unavailable", "Invalid cursor retention marker")
        raise ApiError("cursor_expired", "This generation's API cursor retention has expired")


def _binding(key, endpoint, request):
    return hmac.new(key, encode({"endpoint": endpoint, "request": request}).encode("utf-8"), hashlib.sha256).hexdigest()


def _b64(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("Invalid base64url")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if _b64(decoded) != value:
        raise ValueError("Noncanonical base64url")
    return decoded


def _cursor(key, binding, generation, last, ceiling):
    data = encode({"v": 1, "binding": binding, "generation": generation, "last": last, "ceiling": ceiling}).encode("utf-8")
    return _b64(data) + "." + _b64(hmac.new(key, data, hashlib.sha256).digest())


def _page_scope(conn, key, endpoint, request, cursor, table):
    binding = _binding(key, endpoint, request)
    if cursor is None:
        generation = _generation(conn, request.get("generation_id"))
        _retained(conn, generation["id"])
        ceiling = conn.execute(f"SELECT coalesce(max(id),0) FROM {table}").fetchone()[0]
        return generation, binding, 0, ceiling
    try:
        if not isinstance(cursor, str) or len(cursor) > 4096:
            raise ValueError("Invalid cursor length")
        token, signature = cursor.split(".")
        data = _unb64(token)
        if not hmac.compare_digest(_unb64(signature), hmac.new(key, data, hashlib.sha256).digest()):
            raise ValueError("Invalid cursor signature")
        value = json.loads(data)
        if (set(value) != {"v", "binding", "generation", "last", "ceiling"} or value["v"] != 1
                or type(value["v"]) is not int or value["binding"] != binding
                or not isinstance(value["generation"], str) or not value["generation"]
                or type(value["last"]) is not int or type(value["ceiling"]) is not int
                or not 0 < value["last"] <= value["ceiling"] or encode(value).encode("utf-8") != data):
            raise ValueError("Invalid cursor fields or request binding")
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise ApiError("invalid_cursor", "Cursor is malformed, tampered with, or bound to another request") from exc
    generation = _generation(conn, value["generation"], cursor=True)
    return generation, binding, value["last"], value["ceiling"]


def _window(conn, table, rowid, offset, length, deadline, total_chars=None, prefix_only=False, column="content"):
    if type(offset) is not int or type(length) is not int or offset < 0 or not 1 <= length <= 8192:
        raise ValueError("Use a nonnegative character offset and length from 1 through 8192")
    count, pieces = 0, []
    decoder = codecs.getincrementaldecoder("utf-8")("strict")
    # blobopen reads TEXT storage bytes without SQLite TEXT length/substr NUL semantics.
    with conn.blobopen(table, column, rowid, readonly=True) as blob:
        while True:
            _check(deadline)
            raw = blob.read(4096)
            chunk = decoder.decode(raw, final=not raw)
            begin, end = max(0, offset - count), min(len(chunk), offset + length - count)
            if end > begin:
                pieces.append(chunk[begin:end])
            count += len(chunk)
            if not raw or ((prefix_only or total_chars is not None) and count >= offset + length):
                break
    total = total_chars if total_chars is not None else count
    if offset > total:
        raise ValueError("Offset exceeds the serialized field length")
    return "".join(pieces), total


def _metadata(conn, table, columns, where, parameters):
    size_sql = "+".join(f"coalesce(length(CAST({column} AS BLOB)),0)" for column in columns)
    size = conn.execute(f"SELECT {size_sql} FROM {table} WHERE {where}", parameters).fetchone()
    if size is None:
        raise ApiError("not_found", "The requested record does not exist")
    if size[0] > PAYLOAD_LIMIT:
        raise ApiError("budget_too_small", "Required record metadata exceeds the logical payload budget")
    return dict(conn.execute(f"SELECT {','.join(columns)} FROM {table} WHERE {where}", parameters).fetchone())


def _validate_page(limit, sort, detail, allowed_details=("snippet", "metadata")):
    if type(limit) is not int or not 1 <= limit <= 50 or sort != "id_asc" or detail not in allowed_details:
        raise ValueError("Use limit 1 through 50, id_asc sort, and a supported detail level")


def _pack_page(rows, base, key, binding, generation, ceiling, limit, load):
    items = []
    last = None
    for index, row in enumerate(rows[:limit]):
        item = load(row)
        has_more = index + 1 < len(rows)
        token = _cursor(key, binding, generation, row[0], ceiling) if has_more else None
        candidate = {**base, "items": [*items, item], "next_cursor": token, "truncated": has_more}
        if encoded_size({"api_version": 2, "errorcode": None, **candidate}) > PAYLOAD_LIMIT:
            if not items:
                raise ApiError("budget_too_small", "One result and its continuation metadata exceed the response budget")
            return finalize({**base, "items": items, "next_cursor": _cursor(key, binding, generation, last, ceiling), "truncated": True})
        items.append(item)
        last = row[0]
    more = len(rows) > limit
    return finalize({**base, "items": items, "next_cursor": _cursor(key, binding, generation, last, ceiling) if more else None,
                     "truncated": more})


def stats():
    from .records import storage_stats

    with _read() as (conn, _, deadline):
        _generation(conn)
    value = storage_stats()
    _check(deadline)
    return finalize(value)


def evidence(evidence_id, offset=0, length=4096, generation_id=None, include_history=True):
    from .records import evidence_record

    with _read() as (conn, _, deadline):
        generation = _generation(conn, generation_id)
    value = evidence_record(evidence_id, offset=offset, length=length, generation_id=generation["id"], include_history=include_history)
    _check(deadline)
    if value.get("status") != "ok":
        return finalize(value)
    return _text_budget(value, "text", offset, value["total_chars"])


def resolve_legacy(snapshot_id, reference):
    from .records import resolve_legacy as resolve

    with _read() as (conn, _, deadline):
        _generation(conn)
    value = resolve(snapshot_id, reference)
    _check(deadline)
    return finalize(value)


def summary(summary_id, offset=0, length=4096, generation_id=None):
    from .records import LINEAGE

    if type(summary_id) is not int or summary_id < 1:
        raise ValueError("A positive summary ID is required")
    with _read() as (conn, _, deadline):
        generation = _generation(conn, generation_id)
        visible = conn.execute(LINEAGE + "SELECT s.id FROM summaries s JOIN lineage l ON l.seq=s.created_generation WHERE s.id=?",
                               (generation["id"], summary_id)).fetchone()
        if visible is None:
            return finalize({"status": "not_found", "summary_id": summary_id, "generation": generation["id"]})
        value = _metadata(conn, "summaries", SUMMARY_COLUMNS, "id=?", (summary_id,))
        text, total = _window(conn, "summaries", summary_id, offset, length, deadline)
        value.update(status="ok", summary_id=summary_id, generation=generation["id"], offset=offset, text=text, total_chars=total)
        return _text_budget(value, "text", offset, total)


def file_version(file_version_id, generation_id=None, include_history=True, detail="metadata",
                 field="source_identity_json", offset=0, length=4096):
    from .records import LINEAGE, source_availability

    if detail not in {"metadata", "raw"} or field not in {"source_identity_json", "legacy_json"}:
        raise ValueError("Use metadata or raw detail and an explicit supported JSON field")
    if type(include_history) is not bool or type(offset) is not int or offset < 0 or type(length) is not int or not 1 <= length <= 8192:
        raise ValueError("Use a boolean history flag, nonnegative offset and length 1 through 8192")
    with _read() as (conn, _, deadline):
        generation = _generation(conn, generation_id)
        sql = LINEAGE + """SELECT m.id FROM file_memberships m JOIN lineage born ON born.seq=m.valid_from
                            WHERE m.file_version_id=? AND m.tombstone=0"""
        if not include_history:
            sql += " AND NOT EXISTS(SELECT 1 FROM lineage ended WHERE ended.seq=m.valid_to)"
        member = conn.execute(sql + " ORDER BY m.valid_from DESC LIMIT 1", (generation["id"], file_version_id)).fetchone()
        if member is None:
            return finalize({"status": "not_found", "file_version_id": file_version_id,
                             "generation": generation["id"], "reason": "not_visible_in_published_scope"})
        metadata = _metadata(conn, "file_versions", ("id", "file_id", "parser_version", "snapshot_state", "asset_path", "created_at"),
                             "id=?", (file_version_id,))
        membership = _metadata(conn, "file_memberships", ("id", "rel_path", "valid_from", "valid_to", "tombstone"), "id=?", (member[0],))
        if membership['valid_to'] is not None and not conn.execute(
                LINEAGE + 'SELECT 1 FROM lineage WHERE seq=?', (generation['id'], membership['valid_to'])).fetchone():
            membership['valid_to'] = None
        project = conn.execute("SELECT project_id FROM files WHERE id=?", (metadata["file_id"],)).fetchone()[0]
        descriptors = conn.execute("""SELECT rowid,source_identity_json IS NULL,legacy_json IS NULL,
          length(CAST(source_identity_json AS BLOB)),length(CAST(legacy_json AS BLOB)) FROM file_versions WHERE id=?""", (file_version_id,)).fetchone()
        fields = {name: {"is_null": bool(descriptors[index + 1]), "serialized_bytes": descriptors[index + 3]}
                  for index, name in enumerate(("source_identity_json", "legacy_json"))}
        value = {"status": "ok", "file_version_id": file_version_id, "generation": generation["id"],
                 "include_history": include_history, "detail": detail, "metadata": metadata, "membership": membership,
                 "project_id": project, "source_availability": source_availability(conn, project),
                 "json_fields": fields, "content_scope": "stored_metadata_only",
                 "offset_basis": "serialized_metadata_unicode_codepoints"}
        if detail == "metadata":
            return finalize(value)
        if fields[field]["is_null"]:
            if offset:
                raise ValueError("A null metadata field has no nonzero character offset")
            text, total = "", 0
        else:
            text, total = _window(conn, "file_versions", descriptors[0], offset, length, deadline, column=field)
        value.update(field=field, offset=offset, text=text, total_chars=total, metadata_is_null=fields[field]["is_null"])
        return _text_budget(value, "text", offset, total)


def summaries(target_type, target_id, summary_type=None, summary_family=None, include_history=True,
              detail="snippet", sort="id_asc", limit=10, cursor=None, generation_id=None):
    from .records import LINEAGE

    _validate_page(limit, sort, detail)
    if type(include_history) is not bool:
        raise ValueError("include_history must be boolean")
    request = dict(target_type=target_type, target_id=target_id, summary_type=summary_type, summary_family=summary_family,
                   include_history=include_history, detail=detail, sort=sort, limit=limit, generation_id=generation_id)
    with _read() as (conn, key, deadline):
        generation, binding, after, ceiling = _page_scope(conn, key, "summaries", request, cursor, "summaries")
        sql = LINEAGE + "SELECT s.id FROM summaries s JOIN lineage l ON l.seq=s.created_generation WHERE s.target_type=? AND s.target_id=? AND s.id>? AND s.id<=?"
        parameters = [generation["id"], target_type, target_id, after, ceiling]
        for name, value in (("summary_type", summary_type), ("summary_family", summary_family)):
            if value is not None:
                sql += f" AND s.{name}=?"
                parameters.append(value)
        if not include_history:
            sql += " AND NOT EXISTS(SELECT 1 FROM summaries newer JOIN lineage nl ON nl.seq=newer.created_generation WHERE newer.supersedes_id=s.id)"
        rows = conn.execute(sql + " ORDER BY s.id LIMIT ?", (*parameters, limit + 1)).fetchall()

        def load(row):
            _check(deadline)
            columns = tuple(name for name in SUMMARY_COLUMNS if name != "evidence_ids")
            item = _metadata(conn, "summaries", columns, "id=?", (row[0],))
            item["summary_id"] = item["id"]
            if detail == "snippet":
                text, _ = _window(conn, "summaries", row[0], 0, 257, deadline, prefix_only=True)
                item.update(snippet=text[:256], snippet_truncated=len(text) > 256)
            return item

        return _pack_page(rows, {"status": "ok", "generation": generation["id"], "detail": detail,
                                "include_history": include_history, "sort": sort},
                          key, binding, generation["id"], ceiling, limit, load)


def project(project_id, detail="overview", summary_family=None, generation_id=None, offset=0, length=4096):
    from .records import LINEAGE

    if detail not in {"overview", "metadata", "raw"}:
        raise ValueError("Use overview, metadata or raw detail")
    if type(offset) is not int or offset < 0 or type(length) is not int or not 1 <= length <= 8192:
        raise ValueError("Use a nonnegative offset and length 1 through 8192")
    with _read() as (conn, _, deadline):
        generation = _generation(conn, generation_id)
        if not conn.execute("SELECT 1 FROM projects WHERE id=?", (project_id,)).fetchone():
            return finalize({"status": "not_found", "project_id": project_id, "generation": generation["id"]})
        columns = ("id", "name", "provenance_review")
        data = _metadata(conn, "projects", columns, "id=?", (project_id,))
        facts = {"status": "unknown", "reason": "explicit_reviewed_current_family_required", "summary_ids": []}
        if summary_family:
            candidates = conn.execute(LINEAGE + """SELECT s.id FROM summaries s JOIN lineage l ON l.seq=s.created_generation
                WHERE s.target_type='project' AND s.target_id=? AND s.summary_family=?
                  AND s.applicability='current' AND s.content_status='confirmed' AND s.provenance_review='reviewed'
                  AND NOT EXISTS(SELECT 1 FROM summaries newer JOIN lineage nl ON nl.seq=newer.created_generation WHERE newer.supersedes_id=s.id)
                ORDER BY s.id LIMIT 2""", (generation["id"], project_id, summary_family)).fetchall()
            if len(candidates) == 1:
                facts = {"status": "confirmed", "summary_family": summary_family, "summary_ids": [candidates[0][0]]}
            elif len(candidates) > 1:
                facts["reason"] = "ambiguous_reviewed_current_family"
        _check(deadline)
        value = {"status": "ok", "generation": generation["id"], "detail": detail,
                 "registry_scope": "unversioned_registered_metadata", "project": data, "current_facts": facts}
        if detail == "overview":
            return finalize(value)
        descriptor = conn.execute("SELECT rowid,legacy_json IS NULL,length(CAST(legacy_json AS BLOB)) FROM projects WHERE id=?",
                                  (project_id,)).fetchone()
        value.update(json_fields={"legacy_json": {"is_null": bool(descriptor[1]), "serialized_bytes": descriptor[2]}},
                     content_scope="stored_metadata_only", offset_basis="serialized_metadata_unicode_codepoints")
        if detail == "metadata":
            return finalize(value)
        if descriptor[1]:
            if offset:
                raise ValueError("A null metadata field has no nonzero character offset")
            text, total = "", 0
        else:
            text, total = _window(conn, "projects", descriptor[0], offset, length, deadline, column="legacy_json")
        value.update(field="legacy_json", offset=offset, text=text, total_chars=total, metadata_is_null=bool(descriptor[1]))
        return _text_budget(value, "text", offset, total)


def related(item_id, item_type="project", direction="both", relation_types=None, detail="metadata", sort="id_asc",
            limit=10, cursor=None, generation_id=None):
    from .records import LINEAGE

    _validate_page(limit, sort, detail, ("metadata",))
    if direction not in {"in", "out", "both"}:
        raise ValueError("Use in, out, or both direction")
    if relation_types is not None and (not isinstance(relation_types, list) or not all(type(item) is str for item in relation_types)):
        raise ValueError("relation_types must be a string list")
    request = dict(item_id=item_id, item_type=item_type, direction=direction, relation_types=relation_types,
                   detail=detail, sort=sort, limit=limit, generation_id=generation_id, scope_revision=RELATED_SCOPE_REVISION)
    with _read() as (conn, key, deadline):
        generation, binding, after, ceiling = _page_scope(conn, key, "related", request, cursor, "relations")
        conditions, parameters = [], [after, ceiling]
        if direction in {"out", "both"}:
            conditions.append("(source_type=? AND source_id=?)")
            parameters.extend((item_type, item_id))
        if direction in {"in", "both"}:
            conditions.append("(target_type=? AND target_id=?)")
            parameters.extend((item_type, item_id))
        sql = "SELECT id FROM relations WHERE id>? AND id<=? AND (" + " OR ".join(conditions) + ")"
        if relation_types is not None:
            sql += " AND relation_type IN (" + ",".join("?" for _ in relation_types) + ")"
            parameters.extend(relation_types)
        # Preserve legacy JSON; validate the reserved top-level marker without coercion.
        scoped = LINEAGE + ", candidates AS (" + sql + """), marker_values AS (
          SELECT r.id,
            CASE WHEN json_valid(r.legacy_json) THEN
              (SELECT count(*) FROM json_each(r.legacy_json) j WHERE j.key='_kb_v2_created_generation')
              ELSE -1 END AS marker_count,
            CASE WHEN json_valid(r.legacy_json) THEN json_type(r.legacy_json,'$._kb_v2_created_generation') END AS marker_type,
            CASE WHEN json_valid(r.legacy_json) THEN json_extract(r.legacy_json,'$._kb_v2_created_generation') END AS marker_value
          FROM relations r JOIN candidates c ON c.id=r.id
        ), scoped AS (
          SELECT id,CASE WHEN marker_count=0 THEN 1
            WHEN marker_count=1 AND marker_type='integer' AND typeof(marker_value)='integer' AND marker_value>0
            THEN marker_value END AS created_generation FROM marker_values
        ) SELECT id,created_generation FROM scoped
          WHERE created_generation IS NULL OR created_generation IN (SELECT seq FROM lineage)
          ORDER BY id LIMIT ?"""
        rows = conn.execute(scoped, (generation["id"], *parameters, limit + 1)).fetchall()
        for row in rows:
            if row[1] is None:
                raise ApiError("invalid_relation_generation", f"Relation {row[0]} has malformed creation-generation metadata")

        def load(row):
            _check(deadline)
            item = _metadata(conn, "relations", ("id", "source_type", "source_id", "target_type", "target_id",
                                                 "relation_type", "legacy_json", "provenance_review"), "id=?", (row[0],))
            legacy = json.loads(item["legacy_json"])
            status = legacy.get("status") if isinstance(legacy, dict) else None
            item["effective_status"] = "confirmed" if status == "confirmed" and item["provenance_review"] == "reviewed" else "candidate" if status == "candidate" else "unconfirmed"
            item["created_generation"] = row[1]
            return item

        return _pack_page(rows, {"status": "ok", "generation": generation["id"], "detail": detail, "sort": sort,
                                "relation_scope": "published_lineage_with_storage_high_watermark",
                                "scope_revision": RELATED_SCOPE_REVISION, "legacy_generation_fallback": 1,
                                "snapshot_max_relation_id": ceiling},
                          key, binding, generation["id"], ceiling, limit, load)


def _search_cursor(key, binding, backend, generation, request, last, snapshot_id):
    after = {"revision": backend["backend_revision"], "generation_id": generation, "query": request["query"],
             "project_id": request["project_id"], "include_history": request["include_history"], "last": list(last),
             "ranking_snapshot_id": snapshot_id}
    value = {"v": 3, "binding": binding, "backend": backend, "generation": generation, "after": after}
    raw = encode(value).encode("utf-8")
    cursor = _b64(raw) + "." + _b64(hmac.new(key, raw, hashlib.sha256).digest())
    if len(cursor) > 4096:
        raise ApiError("budget_too_small", "Search continuation metadata exceeds the cursor input budget")
    return cursor


def _search_scope(conn, key, binding, backend, request, cursor):
    if cursor is None:
        generation = _generation(conn, request["generation_id"])
        _retained(conn, generation["id"])
        return generation, None
    try:
        if type(cursor) is not str or len(cursor) > 4096:
            raise ValueError("Invalid search cursor size")
        token, signature = cursor.split(".")
        raw = _unb64(token)
        if not hmac.compare_digest(_unb64(signature), hmac.new(key, raw, hashlib.sha256).digest()):
            raise ValueError("Invalid search cursor signature")
        value = json.loads(raw)
        if (type(value) is not dict or set(value) != {"v", "binding", "backend", "generation", "after"}
                or type(value["v"]) is not int or value["v"] != 3 or value["binding"] != binding
                or value["backend"] != backend or type(value["generation"]) is not str or not value["generation"]
                or encode(value).encode("utf-8") != raw):
            raise ValueError("Search cursor binding mismatch")
        after = value["after"]
        from . import ranked
        if (type(after) is not dict or set(after) != ranked.FIELDS
                or after["revision"] != backend["backend_revision"] or after["generation_id"] != value["generation"]
                or after["query"] != request["query"] or type(after["include_history"]) is not bool
                or after["include_history"] != request["include_history"]
                or type(after["project_id"]) is not type(request["project_id"]) or after["project_id"] != request["project_id"]):
            raise ValueError("Search cursor after binding mismatch")
        ranked.decode_key(after['last'])
        if ranked.snapshot(conn, after['generation_id'])['snapshot_id'] != after['ranking_snapshot_id']:
            raise ValueError('Cursor statistics snapshot mismatch')
    except (ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise ApiError("invalid_cursor", "Search cursor is malformed or belongs to another request or backend") from exc
    return _generation(conn, value["generation"], cursor=True), after


def search(query, project_id=None, generation_id=None, include_history=False, detail="snippet", sort="relevance",
           limit=10, cursor=None):
    if type(limit) is not int or not 1 <= limit <= 50 or sort != "relevance" or detail not in {"snippet", "metadata"}:
        raise ValueError("Use limit 1 through 50, relevance sort, and snippet or metadata detail")
    with _read() as (conn, key, deadline):
        from . import lexical, ranked
        backend = ranked.metadata(conn)
        request = dict(query=query, project_id=project_id, generation_id=generation_id, include_history=include_history,
                       detail=detail, sort=sort, limit=limit, **backend)
        binding = _binding(key, "search", request)
        generation, after = _search_scope(conn, key, binding, backend, request, cursor)
        try:
            result = lexical.search_page(conn, query, project_id=project_id, generation_id=generation["id"],
                                         include_history=include_history, after=after, limit=limit)
        except ValueError as exc:
            if cursor is not None:
                raise ApiError("invalid_cursor", "The lexical backend rejected the cursor ordering key") from exc
            raise
        _check(deadline)
        base = {name: value for name, value in result.items() if name not in {"rows", "next_key", "truncated", "unavailable_candidates"}}
        base.update(detail=detail, sort=sort, query=query, project_id=project_id, generation=generation["id"],
                    offset_version=backend["offset_version"])
        if result["status"] not in {"ok", "no_match"}:
            return finalize({**base, "rows": [], "next_cursor": None, "truncated": False, "unavailable_candidates": 0})
        items = []
        last_key = None

        def page(rows, more, last):
            return {**base, "rows": rows, "next_cursor": _search_cursor(key, binding, backend, generation["id"], request, last,
                                                                      result['ranking_snapshot_id']) if more else None,
                    "truncated": more, "unavailable_candidates": sum(item["status"] in {"asset_unavailable", "asset_corrupt"} for item in rows)}

        for index, original in enumerate(result["rows"]):
            _check(deadline)
            item = dict(original)
            if detail == "metadata":
                for field in ("snippet", "snippet_start", "snippet_end", "snippet_total_chars", "snippet_truncated", "snippet_offset_basis"):
                    item.pop(field, None)
            more = index + 1 < len(result["rows"]) or result["next_key"] is not None
            candidate = page([*items, item], more, item["result_key"])
            if encoded_size({"api_version": 2, "errorcode": None, **candidate}) > PAYLOAD_LIMIT:
                if items:
                    return finalize(page(items, True, last_key))
                text = item.get("snippet")
                if not isinstance(text, str) or not text:
                    raise ApiError("budget_too_small", "One search result and its continuation metadata exceed the payload budget")

                def clipped(size):
                    row = {**item, "snippet": text[:size], "snippet_end": item["snippet_start"] + size,
                           "snippet_truncated": item["snippet_truncated"] or size < len(text), "snippet_budget_truncated": size < len(text)}
                    return page([row], more, row["result_key"])

                finalize(clipped(0))
                low, high = 0, len(text)
                while low < high:
                    middle = (low + high + 1) // 2
                    if encoded_size({"api_version": 2, "errorcode": None, **clipped(middle)}) <= PAYLOAD_LIMIT:
                        low = middle
                    else:
                        high = middle - 1
                if low == 0:
                    raise ApiError("budget_too_small", "Search metadata leaves no room for a nonempty Unicode snippet")
                return finalize(clipped(low))
            items.append(item)
            last_key = item["result_key"]
        return finalize(page(items, result["next_key"] is not None, last_key))


def _write(function, operation_id, **arguments):
    result = function(operation_id=operation_id, **arguments)
    try:
        return finalize(result)
    except ApiError as exc:
        if exc.code == "budget_too_small":
            exc.details.update(operation_id=operation_id, write_committed=True)
        raise


def save_summary(operation_id, **arguments):
    from .records import append_summary

    return _write(append_summary, operation_id, **arguments)


def register_root(operation_id, project_id, root, name=None):
    from .incremental import register_root as register

    return _write(register, operation_id, project_id=project_id, root=root, name=name)


def refresh(operation_id, project_id, root, mode="full", receipt_allowlist=None):
    from .incremental import refresh as refresh_root

    return _write(refresh_root, operation_id, project_id=project_id, root=root, mode=mode, receipt_allowlist=receipt_allowlist)
