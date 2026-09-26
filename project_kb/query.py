from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path

from .config import DB_PATH, PROJECTS_DIR, RESUME_DIR
from .schema import connect, read_connection
from .runtime import kb_path, restored_asset_path
from .textutil import compact_line, load_json, safe_json, slugify, utc_now

STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "for",
    "from",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "project",
    "the",
    "to",
    "with",
    "这里",
    "这个",
    "项目",
}


def db() -> sqlite3.Connection:
    return read_connection(DB_PATH)


def project_row_to_dict(row: sqlite3.Row) -> dict:
    out = dict(row)
    for key in ("technologies", "domains", "entrypoints", "configs", "readme_candidates"):
        out[key] = load_json(out.get(key), [])
    out["domain_evidence"] = load_json(out.get("domain_evidence"), {})
    return out


def summary_row_to_dict(row: sqlite3.Row) -> dict:
    out = dict(row)
    out["evidence_ids"] = load_json(out.get("evidence_ids"), [])
    return out


def list_projects() -> list[dict]:
    conn = db()
    try:
        return [project_row_to_dict(row) for row in conn.execute("SELECT * FROM projects ORDER BY name")]
    finally:
        conn.close()


def fts_search(conn: sqlite3.Connection, query: str, top_k: int = 20, filters: dict | None = None) -> list[dict]:
    query = query.strip()
    if not query:
        return []
    filters = filters or {}
    project_filter = filters.get("project_id")
    raw_terms = re.findall(r"[\w\u4e00-\u9fff.-]+", query)
    terms = [t for t in raw_terms if len(t) > 1 and t.lower() not in STOPWORDS]
    match = " OR ".join(f'"{term}"' for term in terms[:12]) or query
    sql = """
        SELECT c.id AS chunk_id, c.project_id, p.name AS project_name, c.rel_path, c.line_start, c.line_end,
               c.summary, snippet(chunks_fts, 0, '[', ']', ' ... ', 24) AS snippet
        FROM chunks_fts
        JOIN chunks c ON c.id = chunks_fts.rowid
        JOIN projects p ON p.id = c.project_id
        WHERE chunks_fts MATCH ?
    """
    params: list[object] = [match]
    if project_filter:
        sql += " AND c.project_id = ?"
        params.append(project_filter)
    sql += " ORDER BY bm25(chunks_fts), CASE WHEN c.kind='priority' THEN 0 ELSE 1 END LIMIT ?"
    params.append(top_k)
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        like_terms = terms[:6] or [query]
        clauses = " OR ".join("c.content LIKE ?" for _ in like_terms)
        sql = f"""
            SELECT c.id AS chunk_id, c.project_id, p.name AS project_name, c.rel_path, c.line_start, c.line_end,
                   c.summary, substr(c.content, 1, 700) AS snippet
            FROM chunks c
            JOIN projects p ON p.id = c.project_id
            WHERE ({clauses})
        """
        params = [f"%{term}%" for term in like_terms]
        if project_filter:
            sql += " AND c.project_id = ?"
            params.append(project_filter)
        sql += " LIMIT ?"
        params.append(top_k)
        rows = conn.execute(sql, params).fetchall()
    results = [dict(row) for row in rows]
    for result in results:
        result["result_type"] = "evidence_chunk"
    return results


def summary_fts_search(conn: sqlite3.Connection, query: str, top_k: int = 20, filters: dict | None = None) -> list[dict]:
    query = query.strip()
    if not query:
        return []
    filters = filters or {}
    project_filter = filters.get("project_id")
    raw_terms = re.findall(r"[\w\u4e00-\u9fff.-]+", query)
    terms = [t for t in raw_terms if len(t) > 1 and t.lower() not in STOPWORDS]
    match = " OR ".join(f'"{term}"' for term in terms[:12]) or query
    sql = """
        SELECT s.id AS summary_id, s.target_type, s.target_id, s.summary_type,
               s.evidence_ids, s.created_at, s.updated_at,
               snippet(summaries_fts, 0, '[', ']', ' ... ', 36) AS snippet
        FROM summaries_fts
        JOIN summaries s ON s.id = summaries_fts.rowid
        WHERE summaries_fts MATCH ?
    """
    params: list[object] = [match]
    if project_filter:
        sql += " AND s.target_type = 'project' AND s.target_id = ?"
        params.append(slugify(project_filter))
    sql += " ORDER BY bm25(summaries_fts), s.id DESC LIMIT ?"
    params.append(top_k)
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        like_terms = terms[:6] or [query]
        clauses = " OR ".join("s.content LIKE ?" for _ in like_terms)
        sql = f"""
            SELECT s.id AS summary_id, s.target_type, s.target_id, s.summary_type,
                   s.evidence_ids, s.created_at, s.updated_at,
                   substr(s.content, 1, 1000) AS snippet
            FROM summaries s
            WHERE ({clauses})
        """
        params = [f"%{term}%" for term in like_terms]
        if project_filter:
            sql += " AND s.target_type = 'project' AND s.target_id = ?"
            params.append(slugify(project_filter))
        sql += " ORDER BY s.id DESC LIMIT ?"
        params.append(top_k)
        rows = conn.execute(sql, params).fetchall()
    results = []
    for row in rows:
        item = summary_row_to_dict(row)
        item.update(
            {
                "result_type": "summary",
                "project_id": item["target_id"] if item["target_type"] == "project" else None,
                "project_name": item["target_id"],
                "rel_path": (
                    f"kb://summary/{item['target_type']}/{item['target_id']}"
                    f"?summary_type={item['summary_type']}&summary_id={item['summary_id']}"
                ),
                "line_start": 1,
                "line_end": 1,
                "summary": item.get("snippet"),
            }
        )
        results.append(item)
    return results


def relation_search(conn: sqlite3.Connection, item_id: str, depth: int = 2, relation_types: list[str] | None = None) -> list[dict]:
    seen = {item_id}
    frontier = {item_id}
    results: list[dict] = []
    relation_types = relation_types or []
    for level in range(max(1, depth)):
        if not frontier:
            break
        next_frontier = set()
        for source in sorted(frontier):
            sql = "SELECT * FROM relations WHERE source_id=?"
            params: list[object] = [source]
            if relation_types:
                placeholders = ",".join("?" for _ in relation_types)
                sql += f" AND relation_type IN ({placeholders})"
                params.extend(relation_types)
            sql += " ORDER BY weight DESC, relation_type, target_id LIMIT 80"
            for row in conn.execute(sql, params):
                item = dict(row)
                item["depth"] = level + 1
                results.append(item)
                target = item["target_id"]
                if target not in seen:
                    seen.add(target)
                    if item["target_type"] == "project":
                        next_frontier.add(target)
        frontier = next_frontier
    return results


def search(query: str, mode: str = "hybrid", filters: dict | None = None, top_k: int = 20) -> dict:
    conn = db()
    try:
        mode = mode.lower()
        if mode == "vector":
            return {
                "status": "unavailable",
                "message": "Vector search is intentionally disabled in the Codex-in-the-loop build. Use fts, graph, or hybrid.",
                "results": [],
            }
        if mode == "graph":
            return {"status": "ok", "mode": mode, "results": relation_search(conn, slugify(query), 2)}
        summary_hits = summary_fts_search(conn, query, top_k=top_k, filters=filters)
        evidence_hits = fts_search(conn, query, top_k=top_k, filters=filters)
        results = (summary_hits + evidence_hits)[:top_k]
        related: list[dict] = []
        if mode == "hybrid":
            project_ids = []
            for row in results[:8]:
                project_id = row.get("project_id")
                if project_id and project_id not in project_ids:
                    project_ids.append(project_id)
            for pid in project_ids:
                related.extend(relation_search(conn, pid, depth=1)[:8])
        return {
            "status": "ok",
            "mode": mode,
            "query": query,
            "results": results,
            "summary_results": summary_hits,
            "evidence_results": evidence_hits,
            "related": related[:top_k],
        }
    finally:
        conn.close()


def get_project(project_id: str, detail: str = "full") -> dict:
    pid = slugify(project_id)
    conn = db()
    try:
        row = conn.execute("SELECT * FROM projects WHERE id=? OR name=?", (pid, project_id)).fetchone()
        if not row:
            return {"status": "not_found", "project_id": project_id}
        project = project_row_to_dict(row)
        card = ""
        if project.get("project_card_path"):
            card_path = restored_asset_path(Path(project["project_card_path"]))
            if card_path.exists():
                card = card_path.read_text(encoding="utf-8")
        result: dict = {"status": "ok", "project": project, "project_card": card}
        result["summaries"] = [
            summary_row_to_dict(r)
            for r in conn.execute(
                """
                SELECT * FROM summaries
                WHERE target_type='project' AND target_id=?
                ORDER BY id DESC
                LIMIT 20
                """,
                (project["id"],),
            )
        ]
        if detail in {"full", "technical", "evidence"}:
            result["files"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT rel_path, size, sha256, language, kind, indexed, skipped_reason FROM files WHERE project_id=? ORDER BY rel_path LIMIT 500",
                    (project["id"],),
                )
            ]
        if detail in {"full", "evidence"}:
            result["top_chunks"] = [
                dict(r)
                for r in conn.execute(
                    "SELECT id AS chunk_id, rel_path, line_start, line_end, summary FROM chunks WHERE project_id=? ORDER BY kind='priority' DESC, rel_path, line_start LIMIT 80",
                    (project["id"],),
                )
            ]
        if detail in {"full", "resume", "technical"}:
            result["relations"] = relation_search(conn, project["id"], depth=2)[:100]
        return result
    finally:
        conn.close()


def get_summary(
    target_type: str,
    target_id: str,
    summary_type: str | None = None,
    latest_only: bool = True,
) -> dict:
    conn = db()
    try:
        sql = "SELECT * FROM summaries WHERE target_type=? AND target_id=?"
        params: list[object] = [target_type, slugify(target_id)]
        if summary_type:
            sql += " AND summary_type=?"
            params.append(summary_type)
        sql += " ORDER BY id DESC"
        if latest_only:
            sql += " LIMIT 1"
        rows = [summary_row_to_dict(row) for row in conn.execute(sql, params)]
        if not rows:
            return {
                "status": "not_found",
                "target_type": target_type,
                "target_id": slugify(target_id),
                "summary_type": summary_type,
            }
        return {
            "status": "ok",
            "target_type": target_type,
            "target_id": slugify(target_id),
            "summary_type": summary_type,
            "summaries": rows,
        }
    finally:
        conn.close()


def related(item_id: str, depth: int = 2, relation_types: list[str] | None = None) -> dict:
    conn = db()
    try:
        return {"status": "ok", "item_id": item_id, "relations": relation_search(conn, slugify(item_id), depth, relation_types)}
    finally:
        conn.close()


def answer(question: str, require_evidence: bool = True, top_k: int = 12) -> dict:
    hits = search(question, mode="hybrid", top_k=top_k)
    evidence = hits.get("results", [])
    if require_evidence and not evidence:
        return {
            "status": "needs_evidence",
            "question": question,
            "answer": "没有找到足够证据。请先刷新知识库或扩大查询范围。",
            "evidence": [],
        }
    return {
        "status": "ok",
        "question": question,
        "answer": "以下为证据包。请由 Codex 基于这些片段生成最终回答，不能添加无证据结论。",
        "evidence": evidence,
        "related": hits.get("related", []),
    }


def score_project_for_target(project: dict, target_terms: set[str]) -> float:
    text = " ".join(
        [
            project["name"],
            " ".join(project.get("technologies", [])),
            " ".join(project.get("domains", [])),
            project.get("readme_path") or "",
        ]
    ).lower()
    return sum(1.0 for term in target_terms if term and term in text)


def resume_pack(target_role: str, language: str = "zh", style: str = "impact", require_evidence: bool = True) -> dict:
    conn = db()
    try:
        terms = set(re.findall(r"[\w\u4e00-\u9fff.+#-]+", target_role.lower()))
        projects = [project_row_to_dict(row) for row in conn.execute("SELECT * FROM projects ORDER BY name")]
        ranked = sorted(projects, key=lambda p: score_project_for_target(p, terms), reverse=True)
        selected = []
        for project in ranked[:10]:
            summaries = [
                summary_row_to_dict(row)
                for row in conn.execute(
                    """
                    SELECT * FROM summaries
                    WHERE target_type='project' AND target_id=?
                    ORDER BY
                      CASE
                        WHEN summary_type LIKE '%application%' THEN 0
                        WHEN summary_type LIKE '%graduate%' THEN 1
                        ELSE 2
                      END,
                      id DESC
                    LIMIT 3
                    """,
                    (project["id"],),
                )
            ]
            evidence = fts_search(
                conn,
                target_role + " " + project["name"],
                top_k=6,
                filters={"project_id": project["id"]},
            )
            if require_evidence and not evidence and not summaries:
                continue
            selected.append(
                {
                    "project_id": project["id"],
                    "name": project["name"],
                    "technologies": project["technologies"],
                    "domains": project["domains"],
                    "card": project.get("project_card_path"),
                    "summaries": summaries,
                    "evidence": evidence,
                    "draft_rule": "Codex must rewrite bullets from evidence only; metrics require explicit evidence.",
                }
            )
        now = utc_now()
        kb_path(RESUME_DIR).mkdir(parents=True, exist_ok=True)
        out_path = RESUME_DIR / f"resume-pack-{slugify(target_role)}-{now.replace(':', '-')}.md"
        lines = [
            f"# Resume Evidence Pack: {target_role}",
            "",
            f"- language: {language}",
            f"- style: {style}",
            f"- generated_at: {now}",
            "",
            "## Usage",
            "Use this as evidence only. Final bullets must not invent metrics or claims absent from snippets.",
            "",
        ]
        for item in selected:
            lines.extend(
                [
                    f"## {item['name']} (`{item['project_id']}`)",
                    "",
                    f"- technologies: {', '.join(item['technologies']) or 'unconfirmed'}",
                    f"- domains: {', '.join(item['domains']) or 'unconfirmed'}",
                    f"- project card: `{item['card']}`",
                    "",
                    "### Evidence",
                ]
            )
            for ev in item["evidence"]:
                lines.append(
                    f"- `{ev['rel_path']}:{ev['line_start']}` {compact_line(ev.get('snippet') or ev.get('summary') or '', 240)}"
                )
            if item["summaries"]:
                lines.extend(["", "### Saved summaries"])
                for saved in item["summaries"]:
                    lines.append(
                        f"- `{saved['summary_type']}` (summary_id={saved['id']}): "
                        f"{compact_line(saved['content'], 320)}"
                    )
            lines.append("")
        kb_path(out_path).write_text("\n".join(lines), encoding="utf-8")
        return {"status": "ok", "target_role": target_role, "path": str(out_path), "projects": selected}
    finally:
        conn.close()


def audit_claims(text: str) -> dict:
    claims = [
        c.strip()
        for c in re.split(r"(?:[。！？!?]+|(?<!\d)\.(?!\d)|\n+)", text)
        if c.strip()
    ]
    conn = db()
    projects = [project_row_to_dict(row) for row in conn.execute("SELECT id, name, path, is_git, git_head, readme_path, agents_path, file_count, indexed_file_count, chunk_count, technologies, domains, entrypoints, configs, project_card_path, source_mtime_max, updated_at FROM projects")]
    conn.close()
    audited = []
    for claim in claims:
        filters = None
        claim_l = claim.lower()
        for project in projects:
            if project["id"].lower() in claim_l or project["name"].lower() in claim_l:
                filters = {"project_id": project["id"]}
                break
        hits = search(claim, mode="fts", filters=filters, top_k=5).get("results", [])
        audited.append(
            {
                "claim": claim,
                "status": "supported_candidate" if hits else "needs_evidence",
                "evidence": hits[:5],
            }
        )
    return {"status": "ok", "claims": audited}


def save_summary(target_type: str, target_id: str, summary_type: str, content: str, evidence_ids: list[str] | None = None) -> dict:
    conn = connect(DB_PATH)
    now = utc_now()
    evidence_ids = evidence_ids or []
    try:
        conn.execute(
            """
            INSERT INTO summaries(target_type, target_id, summary_type, content, evidence_ids, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (target_type, slugify(target_id), summary_type, content, safe_json(evidence_ids), now, now),
        )
        conn.commit()
        return {"status": "ok", "summary_id": conn.execute("SELECT last_insert_rowid()").fetchone()[0]}
    finally:
        conn.close()


def stats() -> dict:
    conn = db()
    try:
        return {
            "status": "ok",
            "projects": conn.execute("SELECT COUNT(*) FROM projects").fetchone()[0],
            "git_projects": conn.execute("SELECT COUNT(*) FROM projects WHERE is_git=1").fetchone()[0],
            "files": conn.execute("SELECT COUNT(*) FROM files").fetchone()[0],
            "indexed_files": conn.execute("SELECT COUNT(*) FROM files WHERE indexed=1").fetchone()[0],
            "chunks": conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0],
            "relations": conn.execute("SELECT COUNT(*) FROM relations").fetchone()[0],
            "concepts": conn.execute("SELECT COUNT(*) FROM concepts").fetchone()[0],
            "summaries": conn.execute("SELECT COUNT(*) FROM summaries").fetchone()[0],
            "indexed_summaries": conn.execute("SELECT COUNT(*) FROM summaries_fts").fetchone()[0],
            "db_path": str(DB_PATH),
            "projects_dir": str(PROJECTS_DIR),
        }
    finally:
        conn.close()


from .runtime import PROFILE  # noqa: E402

if PROFILE == "production" or os.environ.get("PROJECT_KB_PUBLIC_V2") == "1":
    from .service import (answer, audit_claims, get_project, get_summary, list_projects,  # noqa: F401
                          related, resume_pack, save_summary, search, stats)  # noqa: F401

    def _public_boundary(function):
        from functools import wraps

        @wraps(function)
        def call(*args, **kwargs):
            try:
                return function(*args, **kwargs)
            except Exception as exc:
                from scripts.kb_v2 import failure
                return failure(exc, writing=function.__name__ in {"save_summary", "resume_pack"})
        return call

    for _name in ("answer", "audit_claims", "get_project", "get_summary", "list_projects",
                  "related", "resume_pack", "save_summary", "search", "stats"):
        globals()[_name] = _public_boundary(globals()[_name])
