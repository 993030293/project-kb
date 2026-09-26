from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE))
MAX_JSON_BYTES = 1_048_576
SUCCESS = {"ok", "no_match", "saved", "initialized", "already_initialized", "api_initialized", "ready", "registered", "refreshed"}
WRITES = {"init", "init-api", "rank-install", "save-summary", "register-root", "refresh"}


class EntryError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class Request(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")


class EvidenceRequest(Request):
    evidence_id: str = Field(min_length=1)
    offset: int = Field(default=0, ge=0)
    length: int = Field(default=4096, ge=1, le=8192)
    generation_id: str | None = None
    include_history: bool = True


class ResolveRequest(Request):
    snapshot_id: str = Field(min_length=1)
    reference: str = Field(min_length=1)


class SummaryRequest(Request):
    operation_id: str = Field(min_length=1, max_length=240)
    target_type: str
    target_id: str
    summary_type: str
    content: str
    evidence_ids: list[str] | None = None
    record_type: str = "note"
    summary_family: str | None = None
    supersedes_id: int | None = None


class InitializeApiRequest(Request):
    operation_id: str = Field(min_length=1, max_length=240)


class RankInstallRequest(InitializeApiRequest):
    generation_id: str | None = Field(default=None, min_length=1, max_length=240)


class RegisterRequest(InitializeApiRequest):
    project_id: str = Field(min_length=1)
    root: str = Field(min_length=1)
    name: str | None = None


class RefreshRequest(Request):
    operation_id: str = Field(min_length=1, max_length=180)
    project_id: str = Field(min_length=1)
    root: str = Field(min_length=1)
    mode: Literal["full", "metadata-fast"] = "full"
    receipt_allowlist: list[str] | None = None


class ReadSummaryRequest(Request):
    summary_id: int = Field(ge=1)
    offset: int = Field(default=0, ge=0)
    length: int = Field(default=4096, ge=1, le=8192)
    generation_id: str | None = None


class FileVersionRequest(Request):
    file_version_id: str = Field(min_length=1)
    generation_id: str | None = None
    include_history: bool = True
    detail: Literal["metadata", "raw"] = "metadata"
    field: Literal["source_identity_json", "legacy_json"] = "source_identity_json"
    offset: int = Field(default=0, ge=0)
    length: int = Field(default=4096, ge=1, le=8192)


class SummariesRequest(Request):
    target_type: str = Field(min_length=1)
    target_id: str = Field(min_length=1)
    summary_type: str | None = None
    summary_family: str | None = None
    include_history: bool = True
    detail: Literal["snippet", "metadata"] = "snippet"
    sort: Literal["id_asc"] = "id_asc"
    limit: int = Field(default=10, ge=1, le=50)
    cursor: str | None = Field(default=None, max_length=4096)
    generation_id: str | None = None


class ProjectRequest(Request):
    project_id: str = Field(min_length=1)
    detail: Literal["overview", "metadata", "raw"] = "overview"
    summary_family: str | None = None
    generation_id: str | None = None
    offset: int = Field(default=0, ge=0)
    length: int = Field(default=4096, ge=1, le=8192)


class RelatedRequest(Request):
    item_id: str = Field(min_length=1)
    item_type: str = "project"
    direction: Literal["in", "out", "both"] = "both"
    relation_types: list[str] | None = None
    detail: Literal["metadata"] = "metadata"
    sort: Literal["id_asc"] = "id_asc"
    limit: int = Field(default=10, ge=1, le=50)
    cursor: str | None = Field(default=None, max_length=4096)
    generation_id: str | None = None


class SearchRequest(Request):
    query: str = Field(min_length=1, max_length=256)
    project_id: str | None = Field(default=None, min_length=1, max_length=240)
    generation_id: str | None = Field(default=None, min_length=1, max_length=240)
    include_history: bool = False
    detail: Literal["snippet", "metadata"] = "snippet"
    sort: Literal["relevance"] = "relevance"
    limit: int = Field(default=10, ge=1, le=50)
    cursor: str | None = Field(default=None, max_length=4096)


REQUESTS = {"stats": Request, "evidence": EvidenceRequest,
            "resolve-legacy": ResolveRequest, "save-summary": SummaryRequest,
            "init": Request, "init-api": InitializeApiRequest, "rank-install": RankInstallRequest,
            "register-root": RegisterRequest,
            "refresh": RefreshRequest, "summary": ReadSummaryRequest, "summaries": SummariesRequest,
            "project": ProjectRequest, "related": RelatedRequest, "file-version": FileVersionRequest, "search": SearchRequest}


def as_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def failure(exc: Exception, writing: bool = False) -> dict:
    code = getattr(exc, "code", None)
    if not isinstance(code, str):
        if isinstance(exc, ValidationError):
            code = "invalid_arguments"
        elif isinstance(exc, PermissionError):
            code = ("writes_disabled" if writing and os.environ.get("PROJECT_KB_ENABLE_SANDBOX_WRITES") != "1"
                    else "permission_denied")
        elif isinstance(exc, FileNotFoundError):
            code = "file_not_found"
        elif isinstance(exc, sqlite3.OperationalError):
            code = "database_unavailable"
        elif isinstance(exc, sqlite3.DatabaseError):
            code = "database_error"
        elif isinstance(exc, (ValueError, TypeError)):
            code = "invalid_arguments"
        elif isinstance(exc, RuntimeError):
            code = "configuration_error"
        elif isinstance(exc, OSError):
            code = "io_error"
        else:
            code = "internal_error"
    # Validation messages can contain full user input; never echo that content.
    message = "Arguments do not match the v2 request schema" if isinstance(exc, ValidationError) else str(exc)
    if code == "query_deadline_exceeded":
        code = "deadline_exceeded"
    result = {"status": "error", "api_version": 2, "errorcode": code,
              "message": message[:512], "retryable": code == "writer_busy"}
    details = getattr(exc, "details", {})
    if details.get("write_committed") is True:
        result.update(write_committed=True, operation_id=str(details.get("operation_id", ""))[:240])
    return result


def dispatch(command: str, arguments: dict) -> dict:
    try:
        if command not in REQUESTS:
            raise EntryError("unknown_command", "Unknown v2 command")
        request = REQUESTS[command].model_validate(arguments).model_dump()
        # Import only after validation, inside the error boundary. Never initialize on reads.
        from project_kb.v2 import api, store
        if command in WRITES:
            from project_kb.runtime import require_sandbox_writes

            require_sandbox_writes()

        handlers = {"stats": api.stats, "evidence": api.evidence,
                    "resolve-legacy": api.resolve_legacy, "save-summary": api.save_summary,
                    "init": store.initialize, "init-api": api.initialize,
                    "register-root": api.register_root,
                    "refresh": api.refresh, "summary": api.summary, "summaries": api.summaries,
                    "project": api.project, "related": api.related, "file-version": api.file_version, "search": api.search}
        if command == "rank-install":
            from project_kb.v2 import ranked

            handler = ranked.install_indexes
        else:
            handler = handlers[command]
        result = dict(handler(**request))
        result.setdefault("api_version", 2)
        result["errorcode"] = None if result.get("status") in SUCCESS else result.get("status", "storage_error")
        return api.finalize(result)
    except Exception as exc:
        return failure(exc, writing=command in WRITES)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise EntryError("invalid_json", "Duplicate JSON object keys are not allowed")
        value[key] = item
    return value


def _reject_constant(value):
    raise EntryError("invalid_json", "Non-finite JSON numbers are not allowed")


def read_json_file(path: Path):
    from project_kb.runtime import SANDBOX_BASE, bounded_path

    path = bounded_path(path, SANDBOX_BASE)
    if not stat.S_ISREG(path.stat().st_mode):
        raise EntryError("invalid_payload", "A regular UTF-8 JSON file is required")
    with path.open("rb") as stream:
        data = stream.read(MAX_JSON_BYTES + 1)
    if len(data) > MAX_JSON_BYTES:
        raise EntryError("payload_too_large", "JSON input exceeds the 1048576-byte entrypoint limit")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EntryError("invalid_json", "Input must be strict UTF-8 JSON without a BOM") from exc


class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise EntryError("invalid_arguments", message)


def parser() -> argparse.ArgumentParser:
    root = JsonArgumentParser(description="Explicit isolated schema-3 candidate entrypoint")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("stats")
    commands.add_parser("init")
    initialize_api = commands.add_parser("init-api")
    initialize_api.add_argument("--operation-id", required=True)
    rank_install = commands.add_parser("rank-install")
    rank_install.add_argument("--operation-id", required=True)
    rank_install.add_argument("--generation-id")
    for name in ("register-root", "refresh"):
        write = commands.add_parser(name)
        write.add_argument("--operation-id", required=True)
        write.add_argument("--project-id", required=True)
        write.add_argument("--root", required=True)
        if name == "register-root":
            write.add_argument("--name")
        else:
            write.add_argument("--mode", choices=("full", "metadata-fast"), default="full")
            write.add_argument("--receipt-allowlist", nargs="*")
    summary = commands.add_parser("summary")
    summary.add_argument("summary_id", type=int)
    summary.add_argument("--offset", type=int, default=0)
    summary.add_argument("--length", type=int, default=4096)
    summary.add_argument("--generation-id")
    summaries = commands.add_parser("summaries")
    summaries.add_argument("target_type")
    summaries.add_argument("target_id")
    summaries.add_argument("--summary-type")
    summaries.add_argument("--summary-family")
    summaries.add_argument("--include-history", action=argparse.BooleanOptionalAction, default=True)
    summaries.add_argument("--detail", choices=("snippet", "metadata"), default="snippet")
    project = commands.add_parser("project")
    project.add_argument("project_id")
    project.add_argument("--summary-family")
    project.add_argument("--detail", choices=("overview", "metadata", "raw"), default="overview")
    project.add_argument("--generation-id")
    project.add_argument("--offset", type=int, default=0)
    project.add_argument("--length", type=int, default=4096)
    search = commands.add_parser("search")
    search.add_argument("query")
    search.add_argument("--project-id")
    search.add_argument("--generation-id")
    search.add_argument("--include-history", action=argparse.BooleanOptionalAction, default=False)
    search.add_argument("--detail", choices=("snippet", "metadata"), default="snippet")
    search.add_argument("--sort", choices=("relevance",), default="relevance")
    search.add_argument("--limit", type=int, default=10)
    search.add_argument("--cursor")
    related = commands.add_parser("related")
    related.add_argument("item_id")
    related.add_argument("--item-type", default="project")
    related.add_argument("--direction", choices=("in", "out", "both"), default="both")
    related.add_argument("--relation-types", nargs="*")
    related.add_argument("--detail", choices=("metadata",), default="metadata")
    for listing in (summaries, related):
        listing.add_argument("--sort", choices=("id_asc",), default="id_asc")
        listing.add_argument("--limit", type=int, default=10)
        listing.add_argument("--cursor")
        listing.add_argument("--generation-id")
    evidence = commands.add_parser("evidence")
    evidence.add_argument("evidence_id")
    evidence.add_argument("--offset", type=int, default=0)
    evidence.add_argument("--length", type=int, default=4096)
    evidence.add_argument("--generation-id")
    evidence.add_argument("--include-history", action=argparse.BooleanOptionalAction, default=True)
    version = commands.add_parser("file-version")
    version.add_argument("file_version_id")
    version.add_argument("--generation-id")
    version.add_argument("--include-history", action=argparse.BooleanOptionalAction, default=True)
    version.add_argument("--detail", choices=("metadata", "raw"), default="metadata")
    version.add_argument("--field", choices=("source_identity_json", "legacy_json"), default="source_identity_json")
    version.add_argument("--offset", type=int, default=0)
    version.add_argument("--length", type=int, default=4096)
    resolve = commands.add_parser("resolve-legacy")
    resolve.add_argument("snapshot_id")
    resolve.add_argument("reference")
    save = commands.add_parser("save-summary")
    save.add_argument("--operation-id", required=True)
    save.add_argument("--payload", required=True, type=Path)
    return root


def main() -> int:
    try:
        arguments = vars(parser().parse_args())
        command = arguments.pop("command")
        if command == "save-summary":
            payload = read_json_file(arguments.pop("payload"))
            if not isinstance(payload, dict) or "operation_id" in payload:
                raise EntryError("invalid_payload", "Payload must be an object without operation_id; use --operation-id")
            arguments.update(payload)
        result = dispatch(command, arguments)
    except Exception as exc:
        result = failure(exc)
    print(as_json(result))
    return 0 if result["errorcode"] is None else 2 if result["errorcode"] == "invalid_arguments" else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    raise SystemExit(main())
