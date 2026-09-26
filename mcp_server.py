from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from project_kb.query import (  # noqa: E402
    answer,
    audit_claims,
    get_project,
    get_summary,
    related,
    resume_pack,
    save_summary,
    search,
    stats,
)
from project_kb.scanner import refresh  # noqa: E402
from project_kb.verifier import verify  # noqa: E402

mcp = FastMCP("project-kb")


def as_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


@mcp.tool()
def kb_refresh(scope: str = "changed", project_id: str | None = None) -> str:
    """Refresh the local project knowledge base. scope: all, changed, or project."""
    return as_text(refresh(scope=scope, project_id=project_id))


@mcp.tool()
def kb_search(query: str, mode: str = "hybrid", top_k: int = 20, project_id: str | None = None) -> str:
    """Search project evidence with fts, graph, hybrid, or vector mode."""
    filters = {"project_id": project_id} if project_id else None
    return as_text(search(query=query, mode=mode, filters=filters, top_k=top_k))


@mcp.tool()
def kb_retrieve(query: str, project_id: str | None = None, top_k: int = 10) -> str:
    """Prefer for compact local evidence discovery; use kb_search for graph relations."""
    from project_kb.retrieval import retrieve

    return json.dumps(retrieve(query, project_id, top_k), ensure_ascii=False, separators=(",", ":"))


@mcp.tool()
def kb_project(project_id: str, detail: str = "full") -> str:
    """Return a project card, metadata, files, evidence, and relations."""
    return as_text(get_project(project_id=project_id, detail=detail))


@mcp.tool()
def kb_related(item_id: str, depth: int = 2, relation_types: list[str] | None = None) -> str:
    """Return graph relations for a project or concept id."""
    return as_text(related(item_id=item_id, depth=depth, relation_types=relation_types))


@mcp.tool()
def kb_answer(question: str, require_evidence: bool = True) -> str:
    """Return an evidence pack for Codex to answer a question without inventing details."""
    return as_text(answer(question=question, require_evidence=require_evidence))


@mcp.tool()
def kb_resume_pack(target_role: str, language: str = "zh", style: str = "impact", require_evidence: bool = True) -> str:
    """Build an evidence-backed project pack for a resume target role."""
    return as_text(resume_pack(target_role=target_role, language=language, style=style, require_evidence=require_evidence))


@mcp.tool()
def kb_audit_claims(text: str) -> str:
    """Check whether claims have matching evidence in the local project KB."""
    return as_text(audit_claims(text=text))


@mcp.tool()
def kb_save_summary(target_type: str, target_id: str, summary_type: str, content: str, evidence_ids: list[str] | None = None,
                    operation_id: str | None = None) -> str:
    """Save a Codex-generated, evidence-backed summary into the KB."""
    if operation_id:
        return as_text(save_summary(target_type, target_id, summary_type, content, evidence_ids, operation_id=operation_id))
    return as_text(save_summary(target_type, target_id, summary_type, content, evidence_ids))


@mcp.tool()
def kb_summary(
    target_type: str,
    target_id: str,
    summary_type: str | None = None,
    latest_only: bool = True,
) -> str:
    """Read saved summaries directly by target and optional summary type."""
    return as_text(get_summary(target_type, target_id, summary_type, latest_only))


@mcp.tool()
def kb_stats() -> str:
    """Return KB statistics."""
    return as_text(stats())


@mcp.tool()
def kb_verify(scope: str = "all", project_id: str | None = None, strict: bool = False, resume_target: str | None = None) -> str:
    """Run project-kb correctness and completeness verification reports."""
    return as_text(verify(scope=scope, project_id=project_id, strict=strict, resume_target=resume_target))


@mcp.resource("kb://project/{project_id}")
def project_resource(project_id: str) -> str:
    return as_text(get_project(project_id, "full"))


@mcp.resource("kb://graph/{item_id}")
def graph_resource(item_id: str) -> str:
    return as_text(related(item_id, 2))


@mcp.resource("kb://summary/{target_type}/{target_id}")
def summary_resource(target_type: str, target_id: str) -> str:
    return as_text(get_summary(target_type, target_id, latest_only=True))


from scripts.kb_v2 import dispatch  # noqa: E402


@mcp.tool()
def kb2_search(query: str, project_id: str | None = None, generation_id: str | None = None,
               include_history: bool = False, detail: str = "snippet", sort: str = "relevance",
               limit: int = 10, cursor: str | None = None) -> str:
    """Search versioned evidence with bounded, generation-bound pagination."""
    return as_text(dispatch("search", locals()))


@mcp.tool()
def kb2_evidence(evidence_id: str, offset: int = 0, length: int = 4096,
                 generation_id: str | None = None, include_history: bool = True) -> str:
    """Read an exact text window of a stable evidence occurrence."""
    return as_text(dispatch("evidence", locals()))


@mcp.tool()
def kb2_summary(summary_id: int, offset: int = 0, length: int = 4096,
                generation_id: str | None = None) -> str:
    """Read a summary by stable ID with Unicode character offsets."""
    return as_text(dispatch("summary", locals()))


@mcp.tool()
def kb2_summaries(target_type: str, target_id: str, summary_type: str | None = None,
                  summary_family: str | None = None, include_history: bool = True,
                  detail: str = "snippet", sort: str = "id_asc", limit: int = 10,
                  cursor: str | None = None, generation_id: str | None = None) -> str:
    """List summary metadata using generation-bound continuation cursors."""
    return as_text(dispatch("summaries", locals()))


@mcp.tool()
def kb2_file_version(file_version_id: str, generation_id: str | None = None,
                     include_history: bool = True, detail: str = "metadata",
                     field: str = "source_identity_json", offset: int = 0, length: int = 4096) -> str:
    """Read immutable file-version metadata, including historical versions."""
    return as_text(dispatch("file-version", locals()))


@mcp.tool()
def kb2_resolve_legacy(snapshot_id: str, reference: str) -> str:
    """Resolve a snapshot-scoped legacy chunk reference to a stable evidence ID."""
    return as_text(dispatch("resolve-legacy", locals()))


@mcp.tool()
def kb2_save_summary(operation_id: str, target_type: str, target_id: str, summary_type: str,
                     content: str, evidence_ids: list[str] | None = None, record_type: str = "note",
                     summary_family: str | None = None, supersedes_id: int | None = None) -> str:
    """Append a summary with an explicit idempotency key and stable evidence IDs."""
    return as_text(dispatch("save-summary", locals()))


@mcp.tool()
def kb2_refresh(operation_id: str, project_id: str, root: str, mode: str = "full",
                 receipt_allowlist: list[str] | None = None) -> str:
    """Refresh one registered source while retaining old versions and evidence."""
    return as_text(dispatch("refresh", locals()))


@mcp.tool()
def kb2_register_root(operation_id: str, project_id: str, root: str, name: str | None = None) -> str:
    """Register an explicitly selected root within configured source boundaries."""
    return as_text(dispatch("register-root", locals()))


if __name__ == "__main__":
    mcp.run()
