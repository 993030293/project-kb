from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from project_kb.query import (  # noqa: E402
    answer,
    audit_claims,
    get_project,
    get_summary,
    list_projects,
    related,
    resume_pack,
    save_summary,
    search,
    stats,
)
from project_kb.scanner import refresh  # noqa: E402
from project_kb.verifier import verify  # noqa: E402


def emit(value: object) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(json.dumps(value, ensure_ascii=False, indent=2))
    if isinstance(value, dict) and value.get("status") in {"error", "failed", "partial", "unavailable", "not_found"}:
        raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="kb", description="Local project knowledge base")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("refresh")
    p.add_argument("--scope", choices=["all", "changed", "project"], default="changed")
    p.add_argument("--project-id")

    p = sub.add_parser("search")
    p.add_argument("query")
    p.add_argument("--mode", choices=["hybrid", "fts", "graph", "vector"], default="hybrid")
    p.add_argument("--top-k", type=int, default=20)
    p.add_argument("--project-id")

    p = sub.add_parser("retrieve")
    p.add_argument("query")
    p.add_argument("--project-id")
    p.add_argument("--top-k", type=int, default=10)

    p = sub.add_parser("project")
    p.add_argument("project_id")
    p.add_argument("--detail", choices=["full", "resume", "technical", "evidence"], default="full")

    p = sub.add_parser("related")
    p.add_argument("item_id")
    p.add_argument("--depth", type=int, default=2)
    p.add_argument("--relation-type", action="append", default=[])

    p = sub.add_parser("answer")
    p.add_argument("question")
    p.add_argument("--no-require-evidence", action="store_true")

    p = sub.add_parser("resume")
    p.add_argument("--target", required=True)
    p.add_argument("--language", choices=["zh", "en"], default="zh")
    p.add_argument("--style", choices=["concise", "impact"], default="impact")
    p.add_argument("--with-evidence", action="store_true")

    p = sub.add_parser("audit")
    p.add_argument("text")

    p = sub.add_parser("save-summary")
    p.add_argument("--target-type", required=True)
    p.add_argument("--target-id", required=True)
    p.add_argument("--summary-type", required=True)
    p.add_argument("--content", required=True)
    p.add_argument("--evidence-id", action="append", default=[])
    p.add_argument("--operation-id")

    p = sub.add_parser("summary")
    p.add_argument("--target-type", required=True)
    p.add_argument("--target-id", required=True)
    p.add_argument("--summary-type")
    p.add_argument("--all", action="store_true")

    p = sub.add_parser("verify")
    p.add_argument("--scope", choices=["all", "project"], default="all")
    p.add_argument("--project-id")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--resume-target")

    sub.add_parser("stats")
    sub.add_parser("list-projects")

    args = parser.parse_args(argv)
    if args.cmd == "refresh":
        emit(refresh(args.scope, args.project_id))
    elif args.cmd == "search":
        filters = {"project_id": args.project_id} if args.project_id else None
        emit(search(args.query, args.mode, filters, args.top_k))
    elif args.cmd == "retrieve":
        from project_kb.retrieval import retrieve
        emit(retrieve(args.query, args.project_id, args.top_k))
    elif args.cmd == "project":
        emit(get_project(args.project_id, args.detail))
    elif args.cmd == "related":
        emit(related(args.item_id, args.depth, args.relation_type))
    elif args.cmd == "answer":
        emit(answer(args.question, not args.no_require_evidence))
    elif args.cmd == "resume":
        emit(resume_pack(args.target, args.language, args.style, args.with_evidence))
    elif args.cmd == "audit":
        emit(audit_claims(args.text))
    elif args.cmd == "save-summary":
        if args.operation_id:
            emit(save_summary(args.target_type, args.target_id, args.summary_type, args.content, args.evidence_id,
                              operation_id=args.operation_id))
        else:
            emit(save_summary(args.target_type, args.target_id, args.summary_type, args.content, args.evidence_id))
    elif args.cmd == "summary":
        emit(get_summary(args.target_type, args.target_id, args.summary_type, not args.all))
    elif args.cmd == "verify":
        emit(verify(args.scope, args.project_id, args.strict, args.resume_target))
    elif args.cmd == "stats":
        emit(stats())
    elif args.cmd == "list-projects":
        emit(list_projects())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
