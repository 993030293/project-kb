from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from .config import (
    CHUNK_MAX_CHARS,
    CHUNK_MAX_LINES,
    CONCEPTS_DIR,
    EVIDENCE_DIR,
    IGNORED_DIR_NAMES,
    KB_ROOT,
    LOW_VALUE_FILENAMES,
    MAX_INDEX_FILE_BYTES,
    METADATA_ONLY_TOP_LEVEL_NAMES,
    METADATA_ONLY_TOP_LEVEL_SUFFIXES,
    PRIORITY_FILENAMES,
    PROJECT_IGNORED_TOP_LEVEL,
    PROJECT_ROOT_OVERRIDES,
    PROJECTS_DIR,
    SAFE_TEXT_EXTENSIONS,
    SOURCE_ROOT,
)
from .schema import connect, init_db
from .runtime import kb_path, require_sandbox_writes, source_path
from .textutil import (
    compact_line,
    decode_text,
    detect_binary,
    is_sensitive_path,
    load_json,
    safe_json,
    sha256_bytes,
    sha256_text,
    slugify,
    utc_now,
)


TECH_BY_FILE = {
    "pyproject.toml": "Python",
    "requirements.txt": "Python",
    "setup.py": "Python",
    "package.json": "Node.js",
    "tsconfig.json": "TypeScript",
    "vite.config.ts": "Vite",
    "vite.config.js": "Vite",
    "next.config.js": "Next.js",
    "next.config.mjs": "Next.js",
    "dockerfile": "Docker",
    "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose",
}

TECH_BY_EXT = {
    ".py": "Python",
    ".ipynb": "Jupyter",
    ".js": "JavaScript",
    ".jsx": "React",
    ".ts": "TypeScript",
    ".tsx": "React",
    ".rs": "Rust",
    ".go": "Go",
    ".java": "Java",
    ".cpp": "C++",
    ".c": "C",
    ".cs": "C#",
    ".r": "R",
    ".tex": "LaTeX",
    ".html": "HTML",
    ".css": "CSS",
    ".vue": "Vue",
}

DOMAIN_KEYWORDS = {
    "AI Agent": ("agent", "agents", "multi-agent", "tool use", "mcp", "autonomous"),
    "RAG": ("rag", "retrieval", "vector", "embedding", "citation"),
    "Paper Generation": ("paper", "latex", "manuscript", "scientist", "hypothesis"),
    "AIGC Detection": ("aigc", "detector", "deepfake", "generated image", "genimage"),
    "Computer Vision": ("image", "vision", "cnn", "clip", "opencv"),
    "Finance": ("finance", "quant", "portfolio", "validation", "trading"),
    "Browser Automation": ("browser", "playwright", "selenium", "chrome"),
    "MCP": ("mcp", "model context protocol"),
    "Frontend": ("react", "vue", "vite", "next.js", "tailwind"),
    "Data Pipeline": ("pipeline", "etl", "dataset", "csv", "parquet"),
}

ENTRYPOINT_NAMES = {
    "main.py",
    "app.py",
    "server.py",
    "run.py",
    "cli.py",
    "index.js",
    "index.ts",
    "src/main.py",
    "src/app.py",
    "src/index.ts",
    "src/index.js",
}


@dataclass
class FileCandidate:
    path: Path
    rel_path: str
    kind: str
    indexed: bool
    skipped_reason: str | None = None


def normalized_path(path: Path) -> str:
    return os.path.normcase(os.path.abspath(path))


def project_id_for_path(path: Path) -> str:
    normalized = normalized_path(path)
    for project_id, project_root in PROJECT_ROOT_OVERRIDES.items():
        if normalized == normalized_path(project_root):
            return project_id
    return slugify(path.name)


def discover_projects(source_root: Path = SOURCE_ROOT) -> list[Path]:
    source_root = source_path(source_root)
    projects = [p for p in source_root.iterdir() if p.is_dir()] if source_root.exists() else []
    override_ids = set(PROJECT_ROOT_OVERRIDES)
    projects = [p for p in projects if project_id_for_path(p) not in override_ids]
    projects.extend(path for path in PROJECT_ROOT_OVERRIDES.values() if path.exists())
    return sorted((source_path(p) for p in projects), key=lambda p: project_id_for_path(p).lower())


def git_head(path: Path) -> str | None:
    if not (path / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return None
    if result.returncode == 0:
        return result.stdout.strip() or None
    return None


def classify_file(path: Path, project_root: Path) -> FileCandidate:
    path = source_path(path)
    project_root = source_path(project_root)
    rel = path.relative_to(project_root).as_posix()
    name_lower = path.name.lower()
    if is_sensitive_path(path):
        return FileCandidate(path, rel, "sensitive", False, "sensitive_path")
    if name_lower in LOW_VALUE_FILENAMES:
        return FileCandidate(path, rel, "low_value", False, "low_value_lock_or_cache")
    try:
        size = path.stat().st_size
    except OSError:
        return FileCandidate(path, rel, "unknown", False, "stat_failed")
    if size > MAX_INDEX_FILE_BYTES:
        return FileCandidate(path, rel, "large", False, f"larger_than_{MAX_INDEX_FILE_BYTES}_bytes")
    base_no_ext = path.stem.lower()
    if name_lower in PRIORITY_FILENAMES or base_no_ext in PRIORITY_FILENAMES:
        return FileCandidate(path, rel, "priority", True)
    if path.suffix.lower() in SAFE_TEXT_EXTENSIONS:
        return FileCandidate(path, rel, "source", True)
    return FileCandidate(path, rel, "unsupported", False, "unsupported_extension")


def iter_files(project_root: Path, project_id: str | None = None) -> list[FileCandidate]:
    project_root = source_path(project_root)
    candidates: list[FileCandidate] = []
    root_name = project_root.name.lower()
    project_id = project_id or project_id_for_path(project_root)
    ignored_top_level = PROJECT_IGNORED_TOP_LEVEL.get(project_id, set())
    metadata_only = root_name in METADATA_ONLY_TOP_LEVEL_NAMES or root_name.endswith(METADATA_ONLY_TOP_LEVEL_SUFFIXES)
    for root, dirs, files in os.walk(project_root):
        if metadata_only and Path(root) != project_root:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if not should_ignore_dir(d)]
        for dirname in dirs:
            source_path(Path(root) / dirname)
        if Path(root) == project_root and ignored_top_level:
            dirs[:] = [d for d in dirs if d.lower() not in ignored_top_level]
        root_path = Path(root)
        for filename in files:
            candidates.append(classify_file(root_path / filename, project_root))
    return sorted(candidates, key=lambda c: (not c.indexed, c.rel_path.lower()))


def should_ignore_dir(dirname: str) -> bool:
    lowered = dirname.lower()
    if lowered in IGNORED_DIR_NAMES:
        return True
    if lowered.startswith(".venv") or lowered.startswith("venv"):
        return True
    if lowered.startswith(".mamba") or lowered.startswith(".conda"):
        return True
    if lowered.endswith(".egg-info") or lowered.endswith(".dist-info"):
        return True
    return False


def read_text_candidate(path: Path) -> tuple[str | None, str | None, str | None]:
    path = source_path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, None, f"read_failed:{exc.__class__.__name__}"
    digest = sha256_bytes(data)
    if detect_binary(data):
        return None, digest, "binary_detected"
    return decode_text(data), digest, None


def extract_notebook_text(text: str) -> str:
    try:
        obj = json.loads(text)
    except Exception:
        return text
    cells = obj.get("cells")
    if not isinstance(cells, list):
        return text
    out: list[str] = []
    for idx, cell in enumerate(cells, start=1):
        ctype = cell.get("cell_type", "cell")
        src = cell.get("source", "")
        if isinstance(src, list):
            src = "".join(src)
        if isinstance(src, str) and src.strip():
            out.append(f"# notebook cell {idx} ({ctype})\n{src.strip()}")
    return "\n\n".join(out) or text


def chunk_text(text: str) -> list[tuple[int, int, str]]:
    lines = text.splitlines()
    chunks: list[tuple[int, int, str]] = []
    current: list[str] = []
    start = 1
    chars = 0
    for idx, line in enumerate(lines, start=1):
        if current and (len(current) >= CHUNK_MAX_LINES or chars + len(line) > CHUNK_MAX_CHARS):
            chunks.append((start, idx - 1, "\n".join(current).strip()))
            current = []
            start = idx
            chars = 0
        current.append(line)
        chars += len(line) + 1
    if current:
        chunks.append((start, len(lines), "\n".join(current).strip()))
    return [(s, e, c) for s, e, c in chunks if c]


def detect_technologies(file_rows: list[dict], texts_by_rel: dict[str, str]) -> list[str]:
    tech = set()
    ext_counter = Counter()
    for row in file_rows:
        rel = row["rel_path"]
        name = Path(rel).name.lower()
        suffix = Path(rel).suffix.lower()
        if name in TECH_BY_FILE:
            tech.add(TECH_BY_FILE[name])
        if suffix in TECH_BY_EXT:
            tech.add(TECH_BY_EXT[suffix])
            ext_counter[suffix] += 1
    package_json = texts_by_rel.get("package.json")
    if package_json:
        try:
            pkg = json.loads(package_json)
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            for dep in deps:
                dep_l = dep.lower()
                if dep_l == "react":
                    tech.add("React")
                elif dep_l == "vue":
                    tech.add("Vue")
                elif dep_l in {"next", "next.js"}:
                    tech.add("Next.js")
                elif dep_l == "vite":
                    tech.add("Vite")
                elif dep_l == "typescript":
                    tech.add("TypeScript")
                elif "playwright" in dep_l:
                    tech.add("Playwright")
        except Exception:
            pass
    req_text = "\n".join(texts_by_rel.get(p, "") for p in ("requirements.txt", "pyproject.toml"))
    req_l = req_text.lower()
    for marker, name in {
        "torch": "PyTorch",
        "tensorflow": "TensorFlow",
        "sklearn": "scikit-learn",
        "scikit-learn": "scikit-learn",
        "pandas": "Pandas",
        "numpy": "NumPy",
        "playwright": "Playwright",
        "fastapi": "FastAPI",
        "flask": "Flask",
        "streamlit": "Streamlit",
        "mcp": "MCP",
    }.items():
        if marker in req_l:
            tech.add(name)
    return sorted(tech)


def detect_domain_evidence(texts_by_rel: dict[str, str]) -> dict[str, list[str]]:
    evidence: dict[str, list[str]] = {}
    for domain, markers in DOMAIN_KEYWORDS.items():
        hits: list[str] = []
        for rel_path, text in sorted(texts_by_rel.items(), key=lambda item: readme_priority(item[0])):
            haystack = text[:50000].lower()
            for marker in markers:
                if marker in haystack:
                    hits.append(f"{marker} @ {rel_path}")
                    break
            if len(hits) >= 8:
                break
        if hits:
            evidence[domain] = hits
    return evidence


def detect_domains(texts_by_rel: dict[str, str]) -> list[str]:
    return sorted(detect_domain_evidence(texts_by_rel).keys())


def readme_priority(rel_path: str) -> tuple[int, int, str]:
    rel = rel_path.replace("\\", "/")
    name = Path(rel).name.lower()
    depth = rel.count("/")
    if not name.startswith("readme"):
        return (999, depth, rel.lower())
    if depth == 0:
        if name in {"readme", "readme.md", "readme.txt", "readme.rst"}:
            return (-1, depth, rel.lower())
        return (0, depth, rel.lower())
    if rel.lower().startswith(("docs/", "doc/", "documentation/")):
        return (10, depth, rel.lower())
    return (50, depth, rel.lower())


def choose_readme_path(readme_candidates: list[str]) -> str | None:
    if not readme_candidates:
        return None
    return sorted(readme_candidates, key=readme_priority)[0]


def detect_entrypoints(file_rows: list[dict], texts_by_rel: dict[str, str]) -> list[str]:
    entrypoints = []
    rels = {row["rel_path"] for row in file_rows}
    lowered = {rel.lower(): rel for rel in rels}
    for name in ENTRYPOINT_NAMES:
        if name.lower() in lowered:
            entrypoints.append(lowered[name.lower()])
    package_json = texts_by_rel.get("package.json")
    if package_json:
        try:
            pkg = json.loads(package_json)
            scripts = pkg.get("scripts", {})
            if isinstance(scripts, dict):
                for key in ("start", "dev", "build", "test"):
                    if key in scripts:
                        entrypoints.append(f"package.json scripts.{key}: {scripts[key]}")
        except Exception:
            pass
    return sorted(dict.fromkeys(entrypoints))


def detect_configs(file_rows: list[dict]) -> list[str]:
    configs = []
    for row in file_rows:
        name = Path(row["rel_path"]).name.lower()
        if name in TECH_BY_FILE or name in PRIORITY_FILENAMES:
            configs.append(row["rel_path"])
    return sorted(dict.fromkeys(configs))


def first_readme_title(text: str | None) -> str | None:
    if not text:
        return None
    for line in text.splitlines()[:80]:
        if line.lstrip().startswith("#"):
            title = line.lstrip("#").strip()
            if title:
                return title
    for line in text.splitlines()[:20]:
        if line.strip():
            return compact_line(line, 120)
    return None


def clear_project(conn: sqlite3.Connection, project_id: str) -> None:
    chunk_ids = [row["id"] for row in conn.execute("SELECT id FROM chunks WHERE project_id=?", (project_id,))]
    for chunk_id in chunk_ids:
        conn.execute("DELETE FROM chunks_fts WHERE rowid=?", (chunk_id,))
    conn.execute("DELETE FROM relations WHERE source_id=? OR target_id=?", (project_id, project_id))
    conn.execute("DELETE FROM projects WHERE id=?", (project_id,))
    project_dir = PROJECTS_DIR / project_id
    evidence_dir = EVIDENCE_DIR / project_id
    if project_dir.exists():
        shutil.rmtree(project_dir)
    if evidence_dir.exists():
        shutil.rmtree(evidence_dir)


def write_evidence_file(project_id: str, rel_path: str, digest: str, text: str) -> str:
    evidence_dir = EVIDENCE_DIR / project_id
    evidence_dir.mkdir(parents=True, exist_ok=True)
    safe_name = slugify(rel_path.replace("/", "__"))
    target = evidence_dir / f"{safe_name}.md"
    body = [
        "---",
        f"project_id: {project_id}",
        f"source_rel_path: {rel_path}",
        f"sha256: {digest}",
        "---",
        "",
        "```text",
        text.strip(),
        "```",
        "",
    ]
    target.write_text("\n".join(body), encoding="utf-8")
    return str(target)


def generate_project_card(project: dict, evidence_notes: list[str]) -> str:
    tech = ", ".join(project["technologies"]) or "未从文件证据确认"
    domains = ", ".join(project["domains"]) or "未从文件证据确认"
    readme_candidates = "\n".join(f"- `{item}`" for item in project.get("readme_candidates", [])[:20]) or "- 未发现"
    domain_evidence_items: list[str] = []
    for domain, hits in sorted(project.get("domain_evidence", {}).items()):
        domain_evidence_items.append(f"- {domain}: " + "; ".join(f"`{hit}`" for hit in hits[:5]))
    domain_evidence = "\n".join(domain_evidence_items) or "- 未发现领域证据"
    entrypoints = "\n".join(f"- `{item}`" for item in project["entrypoints"]) or "- 未确认"
    configs = "\n".join(f"- `{item}`" for item in project["configs"]) or "- 未确认"
    evidence = "\n".join(f"- {item}" for item in evidence_notes[:40]) or "- 未索引到文本证据"
    unconfirmed = []
    if not project.get("readme_path"):
        unconfirmed.append("未发现 README，项目目标需要人工或后续证据确认。")
    if not project["entrypoints"]:
        unconfirmed.append("未确认运行入口。")
    if not project["domains"]:
        unconfirmed.append("未确认项目领域标签。")
    unconfirmed_text = "\n".join(f"- {item}" for item in unconfirmed) or "- 暂无"
    return f"""---
project_id: {project['id']}
source_path: {project['path']}
updated_at: {project['updated_at']}
---

# {project['name']}

## 项目身份

- 项目 ID：`{project['id']}`
- 本地路径：`{project['path']}`
- Git 仓库：`{'是' if project['is_git'] else '否'}`
- Git HEAD：`{project.get('git_head') or '未确认'}`
- README：`{project.get('readme_path') or '未发现'}`
- README 候选：
{readme_candidates}
- AGENTS.md：`{project.get('agents_path') or '未发现'}`

## 已确认信息

- README 标题/首段：{project.get('readme_title') or '未确认'}
- 技术栈：{tech}
- 候选领域标签：{domains}
- 已扫描文件数：{project['file_count']}
- 已索引文本文件数：{project['indexed_file_count']}
- 文本 chunk 数：{project['chunk_count']}

## 入口与配置

## 候选领域证据

{domain_evidence}

### 可能入口
{entrypoints}

### 配置/依赖文件
{configs}

## 证据来源

{evidence}

## 未确认或需人工复核

{unconfirmed_text}

## 简历使用规则

- 只能基于上方证据和 `kb_search` 返回的原始片段撰写项目描述。
- 若要写“提升、优化、准确率、收益”等量化成果，必须先找到实验日志、README 指标、论文结果或代码注释作为证据。
- 无证据内容应标记为“待确认”，不能直接写入正式简历。
"""


def index_project(conn: sqlite3.Connection, project_path: Path) -> dict:
    project_id = project_id_for_path(project_path)
    clear_project(conn, project_id)
    now = utc_now()
    candidates = iter_files(project_path)
    file_rows: list[dict] = []
    texts_by_rel: dict[str, str] = {}
    evidence_notes: list[str] = []
    chunk_count = 0
    indexed_file_count = 0
    source_mtime_max = 0.0

    agents_path = None
    readme_candidates: list[str] = []

    for candidate in candidates:
        try:
            stat = candidate.path.stat()
        except OSError:
            continue
        source_mtime_max = max(source_mtime_max, stat.st_mtime)
        text = None
        digest = None
        skipped = candidate.skipped_reason
        indexed = int(candidate.indexed)
        if candidate.indexed:
            text, digest, read_error = read_text_candidate(candidate.path)
            if read_error:
                indexed = 0
                skipped = read_error
            elif text is not None:
                if candidate.path.suffix.lower() == ".ipynb":
                    text = extract_notebook_text(text)
                texts_by_rel[candidate.rel_path] = text
                indexed_file_count += 1
        file_rows.append(
            {
                "rel_path": candidate.rel_path,
                "abs_path": str(candidate.path),
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "sha256": digest,
                "language": candidate.path.suffix.lower().lstrip("."),
                "kind": candidate.kind,
                "indexed": indexed,
                "skipped_reason": skipped,
            }
        )
        name = candidate.path.name.lower()
        if name.startswith("readme"):
            readme_candidates.append(candidate.rel_path)
        if name == "agents.md":
            agents_path = candidate.rel_path

    technologies = detect_technologies(file_rows, texts_by_rel)
    readme_path = choose_readme_path(readme_candidates)
    domain_evidence = detect_domain_evidence(texts_by_rel)
    domains = sorted(domain_evidence.keys())
    entrypoints = detect_entrypoints(file_rows, texts_by_rel)
    configs = detect_configs(file_rows)
    readme_title = first_readme_title(texts_by_rel.get(readme_path) if readme_path else None)

    project_row = {
        "id": project_id,
        "name": project_id if project_id in PROJECT_ROOT_OVERRIDES else project_path.name,
        "path": str(project_path),
        "is_git": int((project_path / ".git").exists()),
        "git_head": git_head(project_path),
        "readme_path": readme_path,
        "agents_path": agents_path,
        "file_count": len(file_rows),
        "indexed_file_count": indexed_file_count,
        "chunk_count": 0,
        "technologies": technologies,
        "domains": domains,
        "domain_evidence": domain_evidence,
        "readme_candidates": sorted(readme_candidates, key=readme_priority),
        "entrypoints": entrypoints,
        "configs": configs,
        "project_card_path": None,
        "source_mtime_max": source_mtime_max,
        "updated_at": now,
        "readme_title": readme_title,
    }

    conn.execute(
        """
        INSERT INTO projects(
          id, name, path, is_git, git_head, readme_path, agents_path,
          file_count, indexed_file_count, chunk_count, technologies, domains, domain_evidence, readme_candidates,
          entrypoints, configs, project_card_path, source_mtime_max, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            project_id,
            project_row["name"],
            str(project_path),
            project_row["is_git"],
            project_row["git_head"],
            readme_path,
            agents_path,
            len(file_rows),
            indexed_file_count,
            0,
            safe_json(technologies),
            safe_json(domains),
            safe_json(domain_evidence),
            safe_json(project_row["readme_candidates"]),
            safe_json(entrypoints),
            safe_json(configs),
            None,
            source_mtime_max,
            now,
        ),
    )

    for row in file_rows:
        cur = conn.execute(
            """
            INSERT INTO files(project_id, rel_path, abs_path, size, mtime, sha256, language, kind, indexed, skipped_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                project_id,
                row["rel_path"],
                row["abs_path"],
                row["size"],
                row["mtime"],
                row["sha256"],
                row["language"],
                row["kind"],
                row["indexed"],
                row["skipped_reason"],
            ),
        )
        file_id = cur.lastrowid
        if row["indexed"] and row["rel_path"] in texts_by_rel:
            text = texts_by_rel[row["rel_path"]]
            if row["kind"] == "priority":
                evidence_path = write_evidence_file(project_id, row["rel_path"], row["sha256"] or "", text)
                evidence_notes.append(f"`{row['rel_path']}` -> `{evidence_path}`")
            for line_start, line_end, content in chunk_text(text):
                digest = sha256_text(content)
                cur2 = conn.execute(
                    """
                    INSERT INTO chunks(project_id, file_id, rel_path, kind, line_start, line_end, sha256, content, summary, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        project_id,
                        file_id,
                        row["rel_path"],
                        row["kind"],
                        line_start,
                        line_end,
                        digest,
                        content,
                        compact_line(content, 220),
                        now,
                    ),
                )
                chunk_id = cur2.lastrowid
                conn.execute(
                    "INSERT INTO chunks_fts(rowid, content, project_id, chunk_id, rel_path) VALUES (?, ?, ?, ?, ?)",
                    (chunk_id, content, project_id, chunk_id, row["rel_path"]),
                )
                chunk_count += 1

    project_row["chunk_count"] = chunk_count
    project_dir = PROJECTS_DIR / project_id
    project_dir.mkdir(parents=True, exist_ok=True)
    card_path = project_dir / "project_card.md"
    card_path.write_text(generate_project_card(project_row, evidence_notes), encoding="utf-8")
    conn.execute(
        "UPDATE projects SET chunk_count=?, project_card_path=? WHERE id=?",
        (chunk_count, str(card_path), project_id),
    )
    conn.commit()
    return {"project_id": project_id, "name": project_row["name"], "chunks": chunk_count, "card": str(card_path)}


def relation_evidence(common: set[str]) -> str:
    return ", ".join(sorted(common))


def rebuild_relations(conn: sqlite3.Connection) -> dict:
    now = utc_now()
    conn.execute("DELETE FROM relations")
    conn.execute("DELETE FROM concepts")
    projects = [dict(row) for row in conn.execute("SELECT * FROM projects ORDER BY id")]
    concept_projects: dict[tuple[str, str], set[str]] = defaultdict(set)

    for project in projects:
        project_id = project["id"]
        techs = set(load_json(project["technologies"], []))
        domains = set(load_json(project["domains"], []))
        domain_evidence = load_json(project.get("domain_evidence"), {})
        for tech in techs:
            cid = "tech-" + slugify(tech)
            concept_projects[(cid, "technology")].add(project_id)
            conn.execute(
                """
                INSERT OR REPLACE INTO relations(source_type, source_id, relation_type, target_type, target_id, evidence, weight, status, updated_at)
                VALUES('project', ?, 'uses_technology', 'concept', ?, ?, 1.0, 'confirmed', ?)
                """,
                (project_id, cid, tech, now),
            )
        for domain in domains:
            cid = "domain-" + slugify(domain)
            concept_projects[(cid, "domain")].add(project_id)
            evidence = "; ".join((domain_evidence.get(domain) or [])[:6]) or domain
            conn.execute(
                """
                INSERT OR REPLACE INTO relations(source_type, source_id, relation_type, target_type, target_id, evidence, weight, status, updated_at)
                VALUES('project', ?, 'has_domain', 'concept', ?, ?, 0.6, 'candidate', ?)
                """,
                (project_id, cid, evidence, now),
            )

    for i, a in enumerate(projects):
        for b in projects[i + 1 :]:
            a_tech = set(load_json(a["technologies"], []))
            b_tech = set(load_json(b["technologies"], []))
            a_domain = set(load_json(a["domains"], []))
            b_domain = set(load_json(b["domains"], []))
            common_tech = a_tech & b_tech
            common_domain = a_domain & b_domain
            edges: list[tuple[str, set[str], float, str]] = []
            if common_tech:
                edges.append(("shares_technology", common_tech, min(1.0, len(common_tech) / 4), "confirmed"))
            if common_domain:
                edges.append(("same_domain", common_domain, min(0.8, len(common_domain) / 4), "candidate"))
            if not edges:
                a_words = set(re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}", (a["name"] + " " + (a["readme_path"] or "")).lower()))
                b_words = set(re.findall(r"[a-zA-Z][a-zA-Z0-9_-]{2,}", (b["name"] + " " + (b["readme_path"] or "")).lower()))
                common_words = a_words & b_words
                if len(common_words) >= 2:
                    edges.append(("candidate_name_overlap", common_words, 0.25, "candidate"))
            for relation_type, common, weight, status in edges:
                ev = relation_evidence(common)
                for source, target in ((a["id"], b["id"]), (b["id"], a["id"])):
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO relations(source_type, source_id, relation_type, target_type, target_id, evidence, weight, status, updated_at)
                        VALUES('project', ?, ?, 'project', ?, ?, ?, ?, ?)
                        """,
                        (source, relation_type, target, ev, weight, status, now),
                    )

    for (cid, ctype), pids in concept_projects.items():
        name = cid.split("-", 1)[1].replace("-", " ")
        conn.execute(
            "INSERT OR REPLACE INTO concepts(id, name, type, description, project_count, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (cid, name, ctype, f"Auto-detected {ctype} concept from project evidence.", len(pids), now),
        )
        concept_path = CONCEPTS_DIR / f"{cid}.md"
        CONCEPTS_DIR.mkdir(parents=True, exist_ok=True)
        concept_path.write_text(
            "\n".join(
                [
                    "---",
                    f"concept_id: {cid}",
                    f"type: {ctype}",
                    f"updated_at: {now}",
                    "---",
                    "",
                    f"# {name}",
                    "",
                    "## Related Projects",
                    *[f"- `{pid}`" for pid in sorted(pids)],
                    "",
                ]
            ),
            encoding="utf-8",
        )
    conn.commit()
    return {"projects": len(projects), "relations": conn.execute("SELECT COUNT(*) FROM relations").fetchone()[0]}


def refresh(scope: str = "changed", project_id: str | None = None) -> dict:
    from .runtime import PROFILE

    if PROFILE == "production" or os.environ.get("PROJECT_KB_PUBLIC_V2") == "1":
        from .service import refresh as versioned_refresh
        return versioned_refresh(scope=scope, project_id=project_id)
    require_sandbox_writes()
    kb_path(KB_ROOT).mkdir(parents=True, exist_ok=True)
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    CONCEPTS_DIR.mkdir(parents=True, exist_ok=True)
    conn = connect(bootstrap=True)
    init_db(conn)
    started = utc_now()
    conn.execute(
        "UPDATE run_log SET finished_at=?, status='stale', message='superseded by a later refresh' WHERE command='refresh' AND status='running'",
        (started,),
    )
    conn.execute(
        "INSERT INTO run_log(command, scope, started_at, status, message) VALUES('refresh', ?, ?, 'running', '')",
        (scope, started),
    )
    run_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    try:
        projects = discover_projects()
        if project_id:
            projects = [p for p in projects if project_id_for_path(p) == project_id or p.name == project_id]
        elif scope == "changed":
            existing = {row["id"]: row for row in conn.execute("SELECT id, source_mtime_max FROM projects")}
            filtered = []
            for p in projects:
                pid = project_id_for_path(p)
                max_mtime = 0.0
                for candidate in iter_files(p):
                    try:
                        max_mtime = max(max_mtime, candidate.path.stat().st_mtime)
                    except OSError:
                        pass
                if pid not in existing or max_mtime > float(existing[pid]["source_mtime_max"] or 0):
                    filtered.append(p)
            projects = filtered
        elif scope != "all":
            raise ValueError("scope must be all, changed, or project")

        indexed = [index_project(conn, p) for p in projects]
        rel = rebuild_relations(conn)
        finished = utc_now()
        message = safe_json({"indexed": len(indexed), "relations": rel})
        conn.execute(
            "UPDATE run_log SET finished_at=?, status='ok', message=? WHERE id=?",
            (finished, message, run_id),
        )
        conn.commit()
        return {
            "status": "ok",
            "scope": scope,
            "indexed_projects": indexed,
            "relation_stats": rel,
            "db_path": str(conn.execute("PRAGMA database_list").fetchone()[2]),
        }
    except Exception as exc:
        conn.execute(
            "UPDATE run_log SET finished_at=?, status='error', message=? WHERE id=?",
            (utc_now(), f"{exc.__class__.__name__}: {exc}", run_id),
        )
        conn.commit()
        raise
    finally:
        conn.close()
