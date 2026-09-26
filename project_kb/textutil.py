from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable

from .config import SENSITIVE_NAMES, SENSITIVE_SUBSTRINGS


SLUG_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def slugify(value: str) -> str:
    value = value.strip().replace("\\", "/").split("/")[-1]
    value = SLUG_RE.sub("-", value)
    value = value.strip(".-_").lower()
    return value or "item"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def safe_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def load_json(value: str | None, default: object) -> object:
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def is_sensitive_path(path: Path) -> bool:
    lowered_parts = [p.lower() for p in path.parts]
    name = path.name.lower()
    if name in SENSITIVE_NAMES:
        return True
    if name.endswith((".pem", ".key", ".p12", ".pfx", ".crt")):
        return True
    return any(token in part for part in lowered_parts for token in SENSITIVE_SUBSTRINGS)


def detect_binary(data: bytes) -> bool:
    if b"\x00" in data[:4096]:
        return True
    if not data:
        return False
    sample = data[:4096]
    weird = sum(1 for b in sample if b < 9 or (13 < b < 32))
    return weird / max(1, len(sample)) > 0.25


def decode_text(data: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def markdown_table(rows: Iterable[tuple[str, str]]) -> str:
    out = ["| 字段 | 值 |", "| --- | --- |"]
    for key, value in rows:
        out.append(f"| {key} | {value.replace('|', '/')} |")
    return "\n".join(out)


def compact_line(text: str, limit: int = 180) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"
