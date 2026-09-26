"""Production-compatible public API backed by the versioned evidence store."""
from contextlib import contextmanager
import json
from pathlib import Path
import re
import time
import uuid

from .config import DB_PATH, PROJECTS_DIR, RESUME_DIR
from .runtime import kb_path, restored_asset_path, require_sandbox_writes, source_path
from .textutil import compact_line, load_json, slugify, utc_now
from .v2 import api, incremental, ranked, records, store


@contextmanager
def reading():
    with store.read_transaction() as conn:
        yield conn, records.published_generation(conn)


def project_row_to_dict(row):
    value = dict(row)
    legacy = json.loads(value.pop("legacy_json", "{}"))
    out = {**legacy, **value}
    for key in ("technologies", "domains", "entrypoints", "configs", "readme_candidates"):
        if not isinstance(out.get(key), list):
            out[key] = load_json(out.get(key), [])
    if not isinstance(out.get("domain_evidence"), dict):
        out["domain_evidence"] = load_json(out.get("domain_evidence"), {})
    return out


def summary_row_to_dict(row):
    out = dict(row)
    out["evidence_ids"] = load_json(out.get("evidence_ids"), [])
    return out


def list_projects():
    with reading() as (conn, generation):
        return [project_row_to_dict(row) for row in conn.execute("SELECT * FROM projects ORDER BY name")]


def relation_search(conn, item_id, depth=2, relation_types=None):
    if type(depth) is not int or not 1 <= depth <= 4:
        raise ValueError("Relation depth must be from 1 through 4")
    frontier, seen, results = {item_id}, {item_id}, []
    for level in range(depth):
        next_frontier = set()
        for source in sorted(frontier):
            sql, parameters = "SELECT * FROM relations WHERE source_id=?", [source]
            if relation_types:
                sql += " AND relation_type IN (" + ",".join("?" for _ in relation_types) + ")"
                parameters.extend(relation_types)
            sql += " ORDER BY coalesce(json_extract(legacy_json,'$.weight'),0) DESC,relation_type,target_id LIMIT 80"
            for row in conn.execute(sql, parameters):
                item = dict(row)
                legacy = json.loads(item.pop("legacy_json"))
                item = {**legacy, **item, "depth": level + 1}
                results.append(item)
                if item["target_id"] not in seen:
                    seen.add(item["target_id"])
                    if item["target_type"] == "project":
                        next_frontier.add(item["target_id"])
        frontier = next_frontier
        if not frontier:
            break
    return results


def related(item_id, depth=2, relation_types=None):
    with reading() as (conn, generation):
        return {"status": "ok", "api_version": 2, "item_id": item_id, "generation": generation["id"],
                "relations": relation_search(conn, slugify(item_id), depth, relation_types)}


def _map_hit(conn, original):
    item = dict(original)
    if item["kind"] == "summary":
        row = conn.execute("SELECT evidence_ids,created_at,updated_at FROM summaries WHERE id=?", (item["summary_id"],)).fetchone()
        item.update(dict(row))
        item["evidence_ids"] = json.loads(item["evidence_ids"])
        item.update(result_type="summary", project_name=item["target_id"],
                    rel_path=f"kb://summary/{item['target_type']}/{item['target_id']}?summary_type={item['summary_type']}&summary_id={item['summary_id']}",
                    line_start=1, line_end=1, summary=item.get("snippet"))
    else:
        row = conn.execute("SELECT legacy_json,summary FROM evidence_occurrences WHERE id=?", (item["evidence_id"],)).fetchone()
        legacy = json.loads(row["legacy_json"])
        name = conn.execute("SELECT name FROM projects WHERE id=?", (item["project_id"],)).fetchone()
        item.update(result_type="evidence_chunk", chunk_id=legacy.get("id", item["evidence_id"]),
                    project_name=name[0] if name else item["project_id"], summary=row["summary"])
    return item


def search(query, mode="hybrid", filters=None, top_k=20):
    if type(top_k) is not int or not 1 <= top_k <= 100:
        raise ValueError("top_k must be from 1 through 100")
    if not isinstance(query, str) or len(query) > 256:
        raise ValueError("Search query must be a string of at most 256 characters")
    if mode == "vector":
        return {"status": "unavailable", "errorcode": "vector_not_installed", "results": [],
                "message": "Vector search is not installed. Use fts, hybrid, or graph."}
    if mode == "graph":
        result = related(query, 2)
        result["results"] = result.pop("relations")
        result["mode"] = mode
        return result
    if mode not in {"hybrid", "fts"}:
        raise ValueError("Unknown search mode")
    if not query.strip():
        return {"status": "ok", "api_version": 2, "mode": mode, "query": query, "results": [],
                "summary_results": [], "evidence_results": [], "related": []}
    project_id = slugify(filters["project_id"]) if filters and filters.get("project_id") else None
    rows, cursor, generation, seen = [], None, None, set()
    deadline = time.monotonic() + 60
    while len(rows) < top_k:
        # Legacy summaries remain searchable without asserting that they are current facts.
        page = api.search(query, project_id=project_id, limit=min(top_k, 50), cursor=cursor, include_history=True)
        if time.monotonic() > deadline:
            return {"status": "error", "errorcode": "budget_exceeded", "results": [],
                    "message": "Compatibility search exceeded the 60-second read budget"}
        if page["status"] not in {"ok", "no_match"}:
            return {**page, "results": []}
        generation = page["generation"]
        for item in page["rows"]:
            if item["kind"] == "summary":
                if item["summary_is_superseded"]:
                    continue
                identity = ("summary", item["summary_id"])
            else:
                if item["membership_is_history"]:
                    continue
                identity = ("evidence", item["evidence_id"], item["membership_id"])
            if identity not in seen:
                seen.add(identity)
                rows.append(item)
        cursor = page["next_cursor"]
        if cursor is None:
            break
    with store.read_transaction() as conn:
        results = [_map_hit(conn, item) for item in rows[:top_k]]
        links, visited = [], set()
        if mode == "hybrid":
            for item in results[:8]:
                pid = item.get("project_id")
                if pid and pid not in visited:
                    visited.add(pid)
                    links.extend(relation_search(conn, pid, depth=1)[:8])
    return {"status": "ok", "api_version": 2, "mode": mode, "query": query, "generation": generation,
            "backend_revision": ranked.REVISION, "results": results,
            "summary_results": [item for item in results if item["result_type"] == "summary"],
            "evidence_results": [item for item in results if item["result_type"] == "evidence_chunk"],
            "result_partition_scope": "returned_results", "related": links[:top_k],
            "truncated": bool(cursor) or len(rows) > top_k,
            "pagination_endpoint": "kb2_search", "pagination_include_history": True,
            "visibility_scope": "current_file_memberships_and_nonsuperseded_including_legacy_unknown_summaries",
            "claim_boundary": "unconfirmed_evidence_candidates"}


def get_summary(target_type, target_id, summary_type=None, latest_only=True):
    target_id = slugify(target_id)
    with reading() as (conn, generation):
        sql = records.LINEAGE + "SELECT s.* FROM summaries s JOIN lineage l ON l.seq=s.created_generation WHERE s.target_type=? AND s.target_id=?"
        parameters = [generation["id"], target_type, target_id]
        if summary_type:
            sql += " AND s.summary_type=?"
            parameters.append(summary_type)
        sql += " ORDER BY s.id DESC" + (" LIMIT 1" if latest_only else "")
        rows = [summary_row_to_dict(row) for row in conn.execute(sql, parameters)]
        return {"status": "ok" if rows else "not_found", "api_version": 2, "generation": generation["id"],
                "target_type": target_type, "target_id": target_id, "summary_type": summary_type, "summaries": rows}


def get_project(project_id, detail="full"):
    if detail not in {"full", "resume", "technical", "evidence"}:
        raise ValueError("Unsupported project detail")
    with reading() as (conn, generation):
        row = conn.execute("SELECT * FROM projects WHERE id=? OR name=?", (slugify(project_id), project_id)).fetchone()
        if row is None:
            return {"status": "not_found", "project_id": project_id}
        project = project_row_to_dict(row)
        pid = project["id"]
        card, card_state = "", "not_recorded"
        if project.get("project_card_path"):
            try:
                card = restored_asset_path(Path(project["project_card_path"])).read_text(encoding="utf-8")
                card_state = "historical_card"
            except FileNotFoundError:
                card_state = "asset_unavailable"
        result = {"status": "ok", "api_version": 2, "generation": generation["id"], "project": project,
                  "project_card": card, "project_card_state": card_state,
                  "source_availability": records.source_availability(conn, pid)}
        result["summaries"] = [summary_row_to_dict(r) for r in conn.execute(records.LINEAGE +
            "SELECT s.* FROM summaries s JOIN lineage l ON l.seq=s.created_generation WHERE s.target_type='project' AND s.target_id=? ORDER BY s.id DESC LIMIT 20",
            (generation["id"], pid))]
        active = records.LINEAGE + """SELECT m.rel_path,v.*,f.project_id FROM files f
          JOIN file_versions v ON v.file_id=f.id JOIN file_memberships m ON m.file_version_id=v.id
          JOIN lineage born ON born.seq=m.valid_from WHERE f.project_id=? AND m.tombstone=0
          AND NOT EXISTS(SELECT 1 FROM lineage ended WHERE ended.seq=m.valid_to)"""
        if detail in {"full", "technical", "evidence"}:
            files = []
            for item in conn.execute(active + " ORDER BY m.rel_path LIMIT 500", (generation["id"], pid)):
                legacy = json.loads(item["legacy_json"])
                identity = json.loads(item["source_identity_json"] or "{}")
                files.append({"rel_path": item["rel_path"], "file_version_id": item["id"], "file_id": item["file_id"],
                              "size": legacy.get("size", identity.get("raw_bytes")), "sha256": legacy.get("sha256"),
                              "language": legacy.get("language"), "kind": legacy.get("kind", "extracted_text"),
                              "indexed": legacy.get("indexed", int(item["snapshot_state"] == "verified_snapshot")),
                              "skipped_reason": legacy.get("skipped_reason", identity.get("not_indexed_reason"))})
            result["files"] = files
            result["files_limit"] = 500
        if detail in {"full", "evidence"}:
            sql = records.LINEAGE + """SELECT e.id,e.legacy_json,e.line_start,e.line_end,e.summary,m.rel_path
                FROM files f JOIN file_versions v ON v.file_id=f.id
                JOIN evidence_occurrences e ON e.file_version_id=v.id JOIN file_memberships m ON m.file_version_id=v.id
                JOIN lineage born ON born.seq=m.valid_from WHERE f.project_id=? AND m.tombstone=0
                AND NOT EXISTS(SELECT 1 FROM lineage ended WHERE ended.seq=m.valid_to)
                ORDER BY e.kind='priority' DESC,m.rel_path,e.line_start,e.id LIMIT 80"""
            result["top_chunks"] = [{"chunk_id": json.loads(r["legacy_json"]).get("id", r["id"]), "evidence_id": r["id"],
                                     "rel_path": r["rel_path"], "line_start": r["line_start"],
                                     "line_end": r["line_end"], "summary": r["summary"]}
                                    for r in conn.execute(sql, (generation["id"], pid))]
        if detail in {"full", "resume", "technical"}:
            result["relations"] = relation_search(conn, pid, depth=2)[:100]
        result["metadata_scope"] = "legacy_project_metadata_with_current_file_and_evidence_views"
        return result


def save_summary(target_type, target_id, summary_type, content, evidence_ids=None, operation_id=None):
    references = evidence_ids or []
    stable = []
    with reading() as (conn, generation):
        source = conn.execute("SELECT value FROM meta WHERE key='source_snapshot_id'").fetchone()
        for reference in references:
            if conn.execute("SELECT 1 FROM evidence_occurrences WHERE id=?", (reference,)).fetchone():
                stable.append(reference)
                continue
            token = str(reference)
            if re.fullmatch(r"(?:chunk:)?[0-9]+", token) and source:
                token = str(int(token.removeprefix("chunk:")))
                row = conn.execute("SELECT evidence_id FROM legacy_refs WHERE snapshot_id=? AND reference=?", (source[0], token)).fetchone()
                if row and row[0]:
                    stable.append(row[0])
                    continue
            raise ValueError("Unresolved evidence reference; use a published stable ID or a resolvable legacy chunk ID")
    result = api.save_summary(operation_id or "summary:" + uuid.uuid4().hex, target_type=target_type,
                              target_id=slugify(target_id), summary_type=summary_type, content=content,
                              evidence_ids=stable, record_type="note")
    if result.get("status") != "saved":
        return result
    return {**result, "status": "ok", "write_status": result["status"]}


def stats():
    with reading() as (conn, generation):
        counts = {table: conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()[0]
                  for table in ("projects", "files", "file_versions", "evidence_occurrences", "text_bodies", "summaries", "relations", "concepts")}
        indexed = conn.execute("""SELECT count(*) FROM file_memberships m JOIN file_versions v ON v.id=m.file_version_id
            WHERE m.valid_to IS NULL AND m.tombstone=0 AND (v.snapshot_state IN ('verified_snapshot','legacy_extracted_only'))""").fetchone()[0]
        active_files = conn.execute("SELECT count(*) FROM file_memberships WHERE valid_to IS NULL AND tombstone=0").fetchone()[0]
        return {"status": "ok", "api_version": 2, "schema_version": 3, "backend_revision": ranked.REVISION,
                "generation": generation["id"], **counts, "chunks": counts["evidence_occurrences"],
                "active_files": active_files, "indexed_files": indexed, "indexed_summaries": counts["summaries"],
                "git_projects": conn.execute("SELECT count(*) FROM projects WHERE json_extract(legacy_json,'$.is_git')=1").fetchone()[0],
                "count_scope": "all_stored_history_except_active_files_and_indexed_files",
                "db_path": str(DB_PATH), "projects_dir": str(PROJECTS_DIR),
                "d1_enabled": False, "vector_enabled": False}


def answer(question, require_evidence=True, top_k=12):
    result = search(question, mode="hybrid", top_k=top_k)
    if result["status"] != "ok":
        return result
    evidence = result["results"]
    return {"status": "needs_evidence" if require_evidence and not evidence else "ok", "question": question,
            "answer": "Evidence package for Codex synthesis; matching records are candidates, not verified conclusions.",
            "evidence": evidence, "related": result.get("related", []), "generation": result.get("generation")}


def score_project_for_target(project, target_terms):
    text = " ".join([project["name"], *project.get("technologies", []), *project.get("domains", []), project.get("readme_path") or ""]).lower()
    return sum(1.0 for term in target_terms if term and term in text)


def resume_pack(target_role, language="zh", style="impact", require_evidence=True):
    terms = set(re.findall(r"[\w\u4e00-\u9fff.+#-]+", target_role.lower()))
    projects = sorted(list_projects(), key=lambda p: score_project_for_target(p, terms), reverse=True)
    selected = []
    for project in projects[:10]:
        saved = get_summary("project", project["id"], latest_only=False)["summaries"][:3]
        query = (target_role + " " + project["name"])
        if len(query) > 256:
            raise ValueError("Resume retrieval query exceeds the 256-character search limit")
        evidence = search(query, mode="fts", filters={"project_id": project["id"]}, top_k=6)
        if evidence["status"] != "ok":
            return evidence
        if require_evidence and not evidence["results"] and not saved:
            continue
        selected.append({"project_id": project["id"], "name": project["name"], "technologies": project["technologies"],
                         "domains": project["domains"], "card": project.get("project_card_path"), "summaries": saved,
                         "evidence": evidence["results"], "draft_rule": "Use evidence only; do not invent claims."})
    require_sandbox_writes()
    path = kb_path(RESUME_DIR / ("resume-pack-" + slugify(target_role)[:100] + "-" + uuid.uuid4().hex + ".md"))
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Resume Evidence Pack", "", "Target: " + target_role, "", "Generated: " + utc_now(), ""]
    for item in selected:
        lines.extend(["## " + item["name"], "", "Project: " + item["project_id"], ""])
        lines.extend("- " + str(ev["rel_path"]) + ": " + compact_line(ev.get("snippet") or "", 240) for ev in item["evidence"])
    with path.open("x", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")
    return {"status": "ok", "target_role": target_role, "language": language, "style": style, "path": str(path), "projects": selected}


def audit_claims(text):
    claims = [c.strip() for c in re.split(r"(?:[。！？!?]+|(?<!\d)\.(?!\d)|\n+)", text) if c.strip()]
    projects, audited = list_projects(), []
    for claim in claims:
        filters = next(({"project_id": p["id"]} for p in projects if p["id"].lower() in claim.lower() or p["name"].lower() in claim.lower()), None)
        if len(claim) > 256:
            audited.append({"claim": claim, "status": "needs_narrower_query", "evidence": []})
            continue
        result = search(claim, "fts", filters, 5)
        if result["status"] != "ok":
            audited.append({"claim": claim, "status": "query_failed", "error": result, "evidence": []})
            continue
        hits = result["results"]
        audited.append({"claim": claim, "status": "supported_candidate" if hits else "needs_evidence", "evidence": hits})
    return {"status": "ok", "claims": audited}


def refresh(scope="changed", project_id=None, operation_id=None):
    if scope not in {"all", "changed", "project"} or (scope == "project" and not project_id):
        raise ValueError("Use all, changed, or project with a project_id")
    require_sandbox_writes()
    operation_id = operation_id or "refresh:" + uuid.uuid4().hex
    if len(operation_id) > 120:
        raise ValueError("Refresh operation_id must not exceed 120 characters")
    with reading() as (conn, generation):
        roots = [dict(row) for row in conn.execute("SELECT * FROM project_roots ORDER BY observed_at DESC,id DESC")]
    selected = {}
    for root in roots:
        if project_id and root["project_id"] != slugify(project_id):
            continue
        selected.setdefault(root["project_id"], root)
    from .scanner import discover_projects, project_id_for_path
    registered = []
    for path in discover_projects():
        pid = project_id_for_path(path)
        if pid in selected or (project_id and pid != slugify(project_id)):
            continue
        source_path(path)
        result = api.register_root(operation_id + ":register:" + uuid.uuid5(uuid.NAMESPACE_URL, pid).hex,
                                   pid, str(path), name=path.name)
        registered.append(result)
        selected[pid] = {"project_id": pid, "path": str(path)}
    if project_id and not selected:
        return {"status": "not_found", "project_id": project_id}
    completed, unavailable, failed = [], [], []
    for pid, root in sorted(selected.items()):
        path = Path(root["path"])
        if not path.is_dir():
            unavailable.append({"project_id": pid, "root": str(path), "status": "source_unavailable", "history_preserved": True})
            continue
        try:
            source_path(path)
            result = incremental.refresh(operation_id + ":" + uuid.uuid5(uuid.NAMESPACE_URL, pid).hex, pid, str(path), mode="full")
            completed.append(result)
        except (ValueError, store.StorageError, OSError) as exc:
            failed.append({"project_id": pid, "status": "error", "errorcode": getattr(exc, "code", type(exc).__name__), "message": str(exc)})
            break
    return {"status": "error" if failed else ("partial" if unavailable else "ok"), "operation_id": operation_id,
            "scope": scope, "indexed_projects": completed, "unavailable_projects": unavailable, "failed_projects": failed,
            "registered_projects": registered,
            "unattempted_projects": len(selected) - len(completed) - len(unavailable) - len(failed),
            "refresh_mode": "file_level_full_content_check", "history_preserved": True, "db_path": str(DB_PATH)}


def verify(scope="all", project_id=None, strict=False, resume_target=None):
    with reading() as (conn, generation):
        integrity = [row[0] for row in conn.execute("PRAGMA integrity_check")]
        foreign_keys = [tuple(row) for row in conn.execute("PRAGMA foreign_key_check")]
        missing = conn.execute("SELECT count(*) FROM evidence_occurrences e LEFT JOIN text_bodies b ON b.id=e.body_id WHERE b.id IS NULL").fetchone()[0]
        snapshot = ranked.snapshot(conn, generation["id"])
        passed = integrity == ["ok"] and not foreign_keys and missing == 0
        return {"status": "ok" if passed else "failed", "api_version": 2, "verification_scope": "read_only_storage_integrity",
                "requested_scope": scope, "requested_project_id": project_id, "strict": strict,
                "generation": generation["id"], "integrity": integrity, "foreign_key_errors": foreign_keys,
                "missing_occurrence_bodies": missing, "ranking_snapshot_id": snapshot["snapshot_id"],
                "source_freshness_verified": False, "semantic_claims_verified": False,
                "resume_target": resume_target}
