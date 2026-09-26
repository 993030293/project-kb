"""Compact local evidence retrieval."""

import json
import time

from .query import search


REVISION = "compact-local-v1"
FIELDS = (
    "kind", "result_type", "evidence_id", "summary_id", "project_id", "project_name",
    "target_type", "target_id", "summary_type", "summary_family", "record_type",
    "rel_path", "line_start", "line_end", "file_id", "file_version_id", "membership_id",
    "status", "content_status", "stored_content_status", "applicability", "source_state",
    "provenance_state", "provenance_review", "provenance_evidence_id", "evidence_ids",
    "snapshot_state", "membership_is_history", "summary_is_superseded",
    "snippet", "snippet_start", "snippet_end", "snippet_total_chars", "snippet_truncated",
    "snippet_offset_basis",
)
WIRE_LIMIT = 30720


def _finish(value, started):
    value["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 2)
    value["payload_truncated"] = False
    def size():
        return len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
    while size() > WIRE_LIMIT and value["results"]:
        value["results"].pop()
        value["payload_truncated"] = value["truncated"] = True
    if value["payload_truncated"] and not value["results"]:
        value.update(status="error", errorcode="retrieval_metadata_exceeds_budget")
    return value


def retrieve(query, project_id=None, top_k=10):
    started = time.perf_counter()
    if not isinstance(query, str) or not query.strip() or len(query) > 256:
        raise ValueError("Use a nonempty query of at most 256 characters")
    if type(top_k) is not int or not 1 <= top_k <= 20:
        raise ValueError("top_k must be from 1 through 20")
    if project_id is not None and (not isinstance(project_id, str) or not project_id.strip() or len(project_id) > 256):
        raise ValueError("project_id must be a nonempty string of at most 256 characters")
    filters = {"project_id": project_id} if project_id else None
    base = search(query, mode="fts", filters=filters, top_k=top_k)
    if base.get("status") != "ok":
        return base
    rows = base["results"]
    result = {
        "status": "ok" if rows else "no_match", "api_version": 2, "retrieval_revision": REVISION,
        "query": query, "project_id": project_id, "generation": base.get("generation"),
        "backend_revision": base.get("backend_revision"),
        "results": [{k: row[k] for k in FIELDS if k in row} for row in rows],
        "truncated": base.get("truncated", False),
        "claim_boundary": "unconfirmed_evidence_candidates",
        "visibility_scope": base.get("visibility_scope"),
        "pagination_endpoint": "kb2_search",
        "pagination_include_history": True,
    }
    return _finish(result, started)
