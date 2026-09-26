from __future__ import annotations

import json
import os
import stat
from functools import lru_cache
from pathlib import Path


EXECUTION_ROOT = Path(__file__).resolve().parents[2]
CODE_ROOT = Path(__file__).resolve().parents[1]
_install_root = Path(os.environ.get("PROJECT_KB_INSTALL_ROOT", Path.home() / "project-kb"))
if not _install_root.is_absolute():
    raise ValueError("PROJECT_KB_INSTALL_ROOT must be absolute")
LIVE_KB_ROOT = _install_root.resolve()
PROFILE = os.environ.get("PROJECT_KB_PROFILE", "production" if CODE_ROOT == LIVE_KB_ROOT else "sandbox")
if PROFILE not in {"sandbox", "production"}:
    raise ValueError("Unknown knowledge-base runtime profile")
if PROFILE == "production" and CODE_ROOT != LIVE_KB_ROOT:
    raise ValueError("Only the installed production code can use the production profile")


@lru_cache(maxsize=1)
def local_settings() -> dict:
    if PROFILE != "production":
        return {}
    path = LIVE_KB_ROOT / "settings.local.json"
    reject_reparse(path)
    if not path.exists():
        return {}
    if path.stat().st_size > 16384:
        raise ValueError("Local settings exceed the 16 KiB limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) - {"source_root", "root_overrides", "ignored_top_level"}:
        raise ValueError("Invalid local settings keys")
    return value


def deployment():
    marker = LIVE_KB_ROOT / "deployment.json"
    value = json.loads(marker.read_text(encoding="utf-8"))
    if value.get("schema_version") != 3 or value.get("database") != "indexes/kb-v3.sqlite":
        raise ValueError("Unrecognized production database route")
    if value.get("state") not in {"active", "maintenance"}:
        raise PermissionError("Knowledge-base deployment is not active")
    return value


def reject_reparse(path: Path) -> None:
    for part in (path, *path.parents):
        if not part.exists() and not part.is_symlink():
            continue
        info = part.lstat()
        if info.st_mode & stat.S_IFLNK == stat.S_IFLNK or (
            getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise ValueError(f"Reparse paths are not allowed: {part}")


def bounded_path(path: Path, root: Path) -> Path:
    if not path.is_absolute():
        raise ValueError(f"An absolute path is required: {path}")
    reject_reparse(path)
    resolved = path.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes its sandbox boundary: {resolved}")
    if PROFILE != "production" and (resolved == LIVE_KB_ROOT or resolved.is_relative_to(LIVE_KB_ROOT)):
        raise ValueError("The live knowledge base is not a sandbox")
    return resolved


def required_path(name: str, root: Path) -> Path:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be explicitly set for the isolated candidate")
    return bounded_path(Path(value), root)


if PROFILE == "production":
    deployment()
    SANDBOX_BASE = KB_ROOT = LIVE_KB_ROOT
    _source_root = Path(os.environ.get("PROJECT_KB_SOURCE_ROOT",
                                    local_settings().get("source_root", LIVE_KB_ROOT.parent / "git")))
    if not _source_root.is_absolute():
        raise ValueError("PROJECT_KB_SOURCE_ROOT must be absolute")
    SOURCE_ROOT = _source_root.resolve()
    os.environ.setdefault("PROJECT_KB_RANK_MAX_BYTES", str(16 * 1024**3))
else:
    SANDBOX_BASE = required_path("PROJECT_KB_SANDBOX_BASE", EXECUTION_ROOT)
    KB_ROOT = required_path("PROJECT_KB_ROOT", SANDBOX_BASE)
    SOURCE_ROOT = required_path("PROJECT_KB_SOURCE_ROOT", SANDBOX_BASE)
if KB_ROOT == SOURCE_ROOT or KB_ROOT.is_relative_to(SOURCE_ROOT) or SOURCE_ROOT.is_relative_to(KB_ROOT):
    raise ValueError("The source root and KB root must be disjoint")


def kb_path(path: Path) -> Path:
    return bounded_path(path, KB_ROOT)


def restored_asset_path(path: Path) -> Path:
    origin = os.environ.get("PROJECT_KB_RESTORE_ORIGIN_VAULT")
    if not origin:
        return kb_path(path)
    origin_path = Path(origin)
    if not origin_path.is_absolute() or ".." in origin_path.parts:
        raise ValueError("The restore origin must be an absolute normalized vault path")
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Invalid recorded asset path")
    # The old path is only a lexical identity; never open or resolve its files.
    if path.is_relative_to(origin_path):
        mapped = kb_path(KB_ROOT / "vault" / path.relative_to(origin_path))
        trace_event("restored_asset_read", path=str(mapped), origin=str(path))
        return mapped
    return kb_path(path)


def source_path(path: Path) -> Path:
    if PROFILE == "production":
        for root in (SOURCE_ROOT, *root_overrides().values()):
            if path.is_absolute() and path.is_relative_to(root):
                return bounded_path(path, root)
        raise ValueError("Source is outside the configured production project roots")
    return bounded_path(path, SOURCE_ROOT)


def require_sandbox_writes() -> None:
    if PROFILE == "production":
        if deployment()["state"] != "active":
            raise PermissionError("Knowledge-base writes are paused for maintenance")
        kb_path(KB_ROOT)
        return
    if os.environ.get("PROJECT_KB_ENABLE_SANDBOX_WRITES") != "1":
        raise PermissionError("Sandbox writes are disabled; enable them explicitly for fixture operations")
    kb_path(KB_ROOT)
    trace_path()


def trace_path() -> Path | None:
    value = os.environ.get("PROJECT_KB_TRACE_PATH")
    if not value:
        return None
    diagnostics = kb_path(KB_ROOT / "diagnostics")
    destination = bounded_path(Path(value), diagnostics)
    if destination == diagnostics:
        raise ValueError("A trace file must be inside KB_ROOT/diagnostics")
    if destination.exists():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("A trace destination must be a private regular diagnostic file")
    return destination


def trace_event(event: str, **fields: object) -> None:
    destination = trace_path()
    if destination is None:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8") as stream:
        if os.fstat(stream.fileno()).st_nlink != 1:
            raise ValueError("A trace destination must not share a file with another path")
        stream.write(json.dumps({"event": event, **fields}, ensure_ascii=True) + "\n")


@lru_cache(maxsize=1)
def root_overrides() -> dict[str, Path]:
    configured = os.environ.get("PROJECT_KB_ROOT_OVERRIDES")
    value = json.loads(configured) if configured is not None else local_settings().get("root_overrides", {})
    if not isinstance(value, dict):
        raise ValueError("PROJECT_KB_ROOT_OVERRIDES must be a JSON object")
    roots = {}
    for key, raw_path in value.items():
        if not isinstance(key, str) or not key or not isinstance(raw_path, str):
            raise ValueError("Project overrides require nonempty string IDs and paths")
        path = Path(raw_path)
        if not path.is_absolute() or ".." in path.parts:
            raise ValueError("Project override paths must be absolute and normalized")
        if PROFILE == "production":
            reject_reparse(path)
            resolved = path.resolve()
            if resolved == KB_ROOT or resolved.is_relative_to(KB_ROOT):
                raise ValueError("Project source cannot be inside the knowledge base")
            roots[key] = resolved
        else:
            roots[key] = bounded_path(path, SOURCE_ROOT)
    return roots


# Reject an unsafe diagnostic sink before importing any database entrypoint.
trace_path()
