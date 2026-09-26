from __future__ import annotations

import json
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .config import AUDITS_DIR
from .schema import read_connection
from .runtime import kb_path, source_path
from .scanner import (
    choose_readme_path,
    extract_notebook_text,
    iter_files,
    readme_priority,
    should_ignore_dir,
)
from .textutil import decode_text, detect_binary, load_json, slugify, utc_now


SAFE_SENSITIVE_CODE_TERMS = (
    "tokenizer",
    "tokenize",
    "tokens",
    "token_usage",
    "api-keys.ts",
    "github-tokens.ts",
    "apikeys",
    "keymap",
    "keyboard",
    "public_key",
)

TRUE_SECRET_NAMES = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".npmrc",
    ".pypirc",
    "auth.json",
    "credentials.json",
    "credential.json",
    "secrets.json",
    "secret.json",
    "token.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

SECRET_EXTENSIONS = {".pem", ".key", ".p12", ".pfx"}


@dataclass
class Finding:
    severity: str
    project_id: str
    category: str
    path: str
    message: str
    recommendation: str


def row_to_project(row: sqlite3.Row) -> dict:
    item = dict(row)
    for key in ("technologies", "domains", "entrypoints", "configs", "readme_candidates"):
        item[key] = load_json(item.get(key), [])
    item["domain_evidence"] = load_json(item.get("domain_evidence"), {})
    return item


def emit_jsonl(path: Path, rows: Iterable[dict]) -> None:
    kb_path(path).write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def iter_source_files(root: Path) -> list[str]:
    rels: list[str] = []
    if not root.exists():
        return rels
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not should_ignore_dir(d)]
        base = Path(dirpath)
        for filename in files:
            rels.append((base / filename).relative_to(root).as_posix())
    return sorted(rels, key=str.lower)


def git_ls_files(root: Path) -> tuple[list[str], str | None]:
    if not (root / ".git").exists():
        return [], None
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files"],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except Exception as exc:
        return [], f"{exc.__class__.__name__}: {exc}"
    if result.returncode != 0:
        return [], result.stderr.strip() or f"git ls-files failed with code {result.returncode}"
    return [line.strip().replace("\\", "/") for line in result.stdout.splitlines() if line.strip()], None


def classify_sensitive_path(rel_path: str) -> str:
    lower = rel_path.lower()
    name = Path(lower).name
    if name in TRUE_SECRET_NAMES or Path(lower).suffix in SECRET_EXTENSIONS:
        return "true_sensitive"
    if any(term in lower for term in SAFE_SENSITIVE_CODE_TERMS):
        return "safe_code_term"
    if re.search(r"(^|[/_.-])(secret|secrets|credential|credentials|private[_-]?key|api[_-]?key|access[_-]?token|refresh[_-]?token)([/_.-]|$)", lower):
        return "review_sensitive_term"
    return "not_sensitive"


def high_value_file(rel_path: str) -> bool:
    lower = rel_path.lower()
    name = Path(lower).name
    if name.startswith("readme") or name == "agents.md":
        return True
    if name in {
        "pyproject.toml",
        "package.json",
        "requirements.txt",
        "environment.yml",
        "setup.py",
        "dockerfile",
        "docker-compose.yml",
        "makefile",
        "tsconfig.json",
    }:
        return True
    return lower.startswith(("docs/", "doc/", "tests/", "test/", "submission/")) or any(
        token in lower for token in ("report", "result", "metric", "benchmark", "eval")
    )


def read_source_text(path: Path) -> tuple[str | None, str | None]:
    path = source_path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, f"read_failed:{exc.__class__.__name__}"
    if detect_binary(data):
        return None, "binary_detected"
    text = decode_text(data)
    if path.suffix.lower() == ".ipynb":
        text = extract_notebook_text(text)
    return text, None


def sample_chunks(conn: sqlite3.Connection, project_id: str, limit: int) -> list[sqlite3.Row]:
    rows = conn.execute(
        """
        SELECT id, rel_path, line_start, line_end, sha256, content, kind
        FROM chunks
        WHERE project_id=?
        ORDER BY CASE WHEN kind='priority' THEN 0 ELSE 1 END, id
        LIMIT ?
        """,
        (project_id, limit),
    ).fetchall()
    return rows


def verify_chunk_source(project_root: Path, chunk: sqlite3.Row) -> tuple[bool, str]:
    source = project_root / chunk["rel_path"]
    text, error = read_source_text(source)
    if error:
        return False, error
    if text is None:
        return False, "source_text_unavailable"
    lines = text.splitlines()
    start = int(chunk["line_start"])
    end = int(chunk["line_end"])
    if start < 1 or end < start or end > len(lines):
        return False, f"line_range_invalid:{start}-{end}:source_lines={len(lines)}"
    reconstructed = "\n".join(lines[start - 1 : end]).strip()
    if reconstructed != chunk["content"]:
        return False, "content_mismatch_for_recorded_line_range"
    return True, "ok"


def verify_project(conn: sqlite3.Connection, project: dict, strict: bool, findings: list[Finding]) -> dict:
    project_id = project["id"]
    root = source_path(Path(project["path"]))
    file_rows = [dict(row) for row in conn.execute("SELECT * FROM files WHERE project_id=?", (project_id,))]
    indexed_paths = {row["rel_path"] for row in file_rows if row["indexed"]}
    recorded_paths = {row["rel_path"] for row in file_rows}
    actual_paths = [candidate.rel_path for candidate in iter_files(root)]
    git_paths, git_error = git_ls_files(root)
    readme_candidates = sorted([p for p in actual_paths if Path(p).name.lower().startswith("readme")], key=readme_priority)
    best_readme = choose_readme_path(readme_candidates)
    selected_readme = project.get("readme_path")

    audit = {
        "project_id": project_id,
        "name": project["name"],
        "path": project["path"],
        "is_git": bool(project["is_git"]),
        "git_ls_files_ok": git_error is None if project["is_git"] else None,
        "git_file_count": len(git_paths),
        "actual_file_count": len(actual_paths),
        "kb_file_count": len(file_rows),
        "indexed_file_count": len(indexed_paths),
        "chunk_count": int(project["chunk_count"]),
        "selected_readme": selected_readme,
        "best_readme": best_readme,
        "readme_candidates": readme_candidates[:20],
        "domain_count": len(project.get("domains", [])),
        "domain_evidence_count": sum(len(v) for v in project.get("domain_evidence", {}).values()),
        "entrypoint_count": len(project.get("entrypoints", [])),
        "config_count": len(project.get("configs", [])),
        "relation_count": conn.execute("SELECT COUNT(*) FROM relations WHERE source_id=?", (project_id,)).fetchone()[0],
        "confirmed_relation_count": conn.execute("SELECT COUNT(*) FROM relations WHERE source_id=? AND status='confirmed'", (project_id,)).fetchone()[0],
        "candidate_relation_count": conn.execute("SELECT COUNT(*) FROM relations WHERE source_id=? AND status='candidate'", (project_id,)).fetchone()[0],
        "chunk_verification": {"checked": 0, "failed": 0, "failures": []},
        "sensitive_indexed": {"true_sensitive": [], "review_sensitive_term": [], "safe_code_term": []},
        "coverage": {},
        "status": "ok",
    }

    if project["is_git"] and git_error:
        findings.append(Finding("P1", project_id, "git", "", git_error, "Check git availability and repository health."))
    if not root.exists():
        findings.append(Finding("P0", project_id, "source", str(root), "Project path does not exist.", "Refresh or remove this project from KB."))
    if best_readme and selected_readme != best_readme:
        findings.append(
            Finding(
                "P1",
                project_id,
                "readme_selection",
                selected_readme or "",
                f"Selected README is not the best candidate. Expected {best_readme}.",
                "Refresh after README priority fix or inspect whether a submodule README is intended.",
            )
        )
    if not selected_readme and readme_candidates:
        findings.append(Finding("P1", project_id, "readme_selection", "", "README candidates exist but none is selected.", "Refresh this project."))
    if not readme_candidates and int(project["chunk_count"]) > 0:
        findings.append(Finding("P2", project_id, "readme_selection", "", "No README candidate found.", "Add project documentation or mark project as metadata-only."))

    high_value_missing = sorted(p for p in actual_paths if high_value_file(p) and p not in recorded_paths)
    if high_value_missing:
        findings.append(
            Finding(
                "P1",
                project_id,
                "coverage",
                high_value_missing[0],
                f"{len(high_value_missing)} high-value source files are absent from KB file table.",
                "Review ignore rules and refresh if these files should be indexed.",
            )
        )

    audit["coverage"] = {
        "has_readme": bool(readme_candidates),
        "has_agents": any(Path(p).name.lower() == "agents.md" for p in actual_paths),
        "has_config": any(high_value_file(p) and Path(p).name.lower() not in {"readme.md", "agents.md"} for p in actual_paths),
        "has_tests": any(p.lower().startswith(("tests/", "test/")) or "/tests/" in p.lower() for p in actual_paths),
        "has_docs": any(p.lower().startswith(("docs/", "doc/", "documentation/")) for p in actual_paths),
        "has_results": any(any(token in p.lower() for token in ("report", "result", "metric", "benchmark", "eval", "submission")) for p in actual_paths),
        "high_value_missing_count": len(high_value_missing),
    }

    for row in file_rows:
        if not row["indexed"]:
            continue
        cls = classify_sensitive_path(row["rel_path"])
        if cls in audit["sensitive_indexed"]:
            audit["sensitive_indexed"][cls].append(row["rel_path"])
    for rel in audit["sensitive_indexed"]["true_sensitive"]:
        findings.append(Finding("P0", project_id, "sensitive_indexed", rel, "A true sensitive-looking file was indexed.", "Remove from index and tighten skip rules."))
    for rel in audit["sensitive_indexed"]["review_sensitive_term"][:5]:
        findings.append(Finding("P2", project_id, "sensitive_review", rel, "Path contains sensitive terms but may be ordinary code.", "Review once; classify as safe_code_term if appropriate."))

    if int(project["chunk_count"]) == 0 and project["name"].lower() not in {"figs", "outputs", "__pycache__", "genimage_data", "genimage_archives"}:
        findings.append(Finding("P1", project_id, "coverage", "", "No chunks were indexed for a non-metadata project.", "Inspect ignore rules and source files."))

    sample_limit = max(20, int(project["chunk_count"])) if strict and int(project["chunk_count"]) <= 200 else min(20, int(project["chunk_count"]))
    for chunk in sample_chunks(conn, project_id, sample_limit):
        ok, message = verify_chunk_source(root, chunk)
        audit["chunk_verification"]["checked"] += 1
        if not ok:
            audit["chunk_verification"]["failed"] += 1
            failure = {"chunk_id": chunk["id"], "rel_path": chunk["rel_path"], "reason": message}
            audit["chunk_verification"]["failures"].append(failure)
            findings.append(
                Finding(
                    "P0",
                    project_id,
                    "chunk_verification",
                    chunk["rel_path"],
                    f"Chunk {chunk['id']} failed source verification: {message}",
                    "Refresh the project; if it persists, inspect text decoding and line chunking.",
                )
            )

    card_path = Path(project.get("project_card_path") or "")
    if not card_path.exists():
        findings.append(Finding("P1", project_id, "project_card", str(card_path), "Project card is missing.", "Refresh this project."))
    else:
        card_text = card_path.read_text(encoding="utf-8", errors="replace")
        required_markers = ("项目身份", "已确认信息", "证据来源", "未确认")
        missing_markers = [marker for marker in required_markers if marker not in card_text]
        if missing_markers:
            findings.append(
                Finding(
                    "P2",
                    project_id,
                    "project_card",
                    str(card_path),
                    "Project card is missing expected sections: " + ", ".join(missing_markers),
                    "Regenerate project card with the current template.",
                )
            )
        if selected_readme and selected_readme not in card_text:
            findings.append(Finding("P2", project_id, "project_card", str(card_path), "Selected README is not mentioned in project card.", "Regenerate project card."))

    if audit["relation_count"] == 0 and int(project["chunk_count"]) > 0:
        findings.append(Finding("P2", project_id, "relations", "", "Project has indexed content but no outgoing relations.", "Inspect technology/domain detection."))
    if conn.execute("SELECT COUNT(*) FROM relations WHERE source_id=? AND relation_type='same_domain' AND status='confirmed'", (project_id,)).fetchone()[0]:
        findings.append(Finding("P1", project_id, "relations", "", "same_domain relation is confirmed; it should be candidate by default.", "Rebuild relations with current confidence rules."))
    if project.get("domains") and not project.get("domain_evidence"):
        findings.append(Finding("P1", project_id, "domain_evidence", "", "Domains exist without evidence terms.", "Refresh after domain evidence extraction."))

    severities = {finding.severity for finding in findings if finding.project_id == project_id}
    if "P0" in severities:
        audit["status"] = "failed"
    elif "P1" in severities:
        audit["status"] = "warning"
    return audit


def audit_resume_target(conn: sqlite3.Connection, resume_target: str, findings: list[Finding]) -> dict:
    terms = [term for term in re.findall(r"[\w\u4e00-\u9fff.+#-]+", resume_target) if len(term) > 1]
    if not terms:
        return {"target": resume_target, "checked": 0, "supported": 0, "message": "No searchable terms."}
    match = " OR ".join(f'"{term}"' for term in terms[:10])
    try:
        rows = conn.execute(
            """
            SELECT c.project_id, p.name AS project_name, c.rel_path, c.line_start, c.summary
            FROM chunks_fts
            JOIN chunks c ON c.id=chunks_fts.rowid
            JOIN projects p ON p.id=c.project_id
            WHERE chunks_fts MATCH ?
            ORDER BY bm25(chunks_fts)
            LIMIT 30
            """,
            (match,),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        return {"target": resume_target, "checked": 0, "supported": 0, "message": f"Search failed: {exc}"}
    if not rows:
        findings.append(Finding("P1", "_resume", "resume_target", resume_target, "No evidence found for resume target.", "Broaden target wording or refresh KB."))
    return {
        "target": resume_target,
        "checked": len(rows),
        "supported": len(rows),
        "top_projects": sorted({row["project_id"] for row in rows})[:10],
        "top_evidence": [dict(row) for row in rows[:10]],
    }


def write_reports(audit_dir: Path, audits: list[dict], findings: list[Finding], resume_audit: dict | None) -> None:
    audit_dir.mkdir(parents=True, exist_ok=True)
    emit_jsonl(audit_dir / "project_audit.jsonl", audits)

    severity_order = {"P0": 0, "P1": 1, "P2": 2}
    sorted_findings = sorted(findings, key=lambda f: (severity_order.get(f.severity, 9), f.project_id, f.category, f.path))
    finding_lines = ["# Findings", ""]
    if not sorted_findings:
        finding_lines.append("No findings.")
    for finding in sorted_findings:
        finding_lines.extend(
            [
                f"## {finding.severity} {finding.project_id} - {finding.category}",
                "",
                f"- Path: `{finding.path}`",
                f"- Issue: {finding.message}",
                f"- Recommendation: {finding.recommendation}",
                "",
            ]
        )
    (audit_dir / "findings.md").write_text("\n".join(finding_lines), encoding="utf-8")

    p0 = sum(1 for f in findings if f.severity == "P0")
    p1 = sum(1 for f in findings if f.severity == "P1")
    p2 = sum(1 for f in findings if f.severity == "P2")
    status = "failed" if p0 else "warning" if p1 else "ok"
    summary = [
        "# project-kb Audit Summary",
        "",
        f"- Status: {status}",
        f"- Projects audited: {len(audits)}",
        f"- P0 findings: {p0}",
        f"- P1 findings: {p1}",
        f"- P2 findings: {p2}",
        f"- Generated at: {utc_now()}",
        "",
        "## Coverage",
        "",
        f"- Projects with README candidates: {sum(1 for a in audits if a['coverage']['has_readme'])}",
        f"- Projects with tests: {sum(1 for a in audits if a['coverage']['has_tests'])}",
        f"- Projects with docs: {sum(1 for a in audits if a['coverage']['has_docs'])}",
        f"- Projects with result/report evidence: {sum(1 for a in audits if a['coverage']['has_results'])}",
        f"- Chunk verification failures: {sum(a['chunk_verification']['failed'] for a in audits)}",
        "",
    ]
    if resume_audit:
        summary.extend(
            [
                "## Resume Target Audit",
                "",
                f"- Target: {resume_audit['target']}",
                f"- Evidence rows checked: {resume_audit['checked']}",
                f"- Top projects: {', '.join(resume_audit.get('top_projects', [])) or 'none'}",
                "",
            ]
        )
        (audit_dir / "resume_audit.json").write_text(json.dumps(resume_audit, ensure_ascii=False, indent=2), encoding="utf-8")
    summary.extend(["## Report Files", "", "- `project_audit.jsonl`", "- `findings.md`"])
    (audit_dir / "audit_summary.md").write_text("\n".join(summary), encoding="utf-8")


def make_audit_dir(scope: str, project_id: str | None, resume_target: str | None) -> Path:
    timestamp = utc_now().replace(":", "-")
    label = slugify(project_id or scope or "all")
    if resume_target:
        label = f"{label}-resume-{slugify(resume_target)}"
    candidate = AUDITS_DIR / f"{timestamp}-{label}"
    suffix = 1
    while candidate.exists():
        suffix += 1
        candidate = AUDITS_DIR / f"{timestamp}-{label}-{suffix}"
    return kb_path(candidate)


def verify(scope: str = "all", project_id: str | None = None, strict: bool = False, resume_target: str | None = None) -> dict:
    from .runtime import PROFILE

    if PROFILE == "production" or os.environ.get("PROJECT_KB_PUBLIC_V2") == "1":
        from .service import verify as versioned_verify
        return versioned_verify(scope=scope, project_id=project_id, strict=strict, resume_target=resume_target)
    conn = read_connection()
    effective_scope = "project" if project_id else scope
    audit_dir = make_audit_dir(effective_scope, project_id, resume_target)
    findings: list[Finding] = []
    try:
        sql = "SELECT * FROM projects"
        params: list[object] = []
        if project_id:
            sql += " WHERE id=? OR name=?"
            params.extend([project_id, project_id])
        sql += " ORDER BY name"
        projects = [row_to_project(row) for row in conn.execute(sql, params)]
        audits = [verify_project(conn, project, strict, findings) for project in projects]
        resume_audit = audit_resume_target(conn, resume_target, findings) if resume_target else None
        write_reports(audit_dir, audits, findings, resume_audit)
        p0 = sum(1 for f in findings if f.severity == "P0")
        p1 = sum(1 for f in findings if f.severity == "P1")
        p2 = sum(1 for f in findings if f.severity == "P2")
        return {
            "status": "failed" if p0 else "warning" if p1 else "ok",
            "scope": effective_scope,
            "project_id": project_id,
            "strict": strict,
            "audit_dir": str(audit_dir),
            "projects_audited": len(audits),
            "findings": {"P0": p0, "P1": p1, "P2": p2},
            "reports": {
                "summary": str(audit_dir / "audit_summary.md"),
                "project_audit": str(audit_dir / "project_audit.jsonl"),
                "findings": str(audit_dir / "findings.md"),
            },
        }
    finally:
        conn.close()
