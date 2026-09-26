from __future__ import annotations

import json
import os

from .runtime import KB_ROOT, SOURCE_ROOT, PROFILE, local_settings, root_overrides  # noqa: F401

PROJECT_ROOT_OVERRIDES = root_overrides()


def ignored_top_level() -> dict[str, set[str]]:
    configured = os.environ.get("PROJECT_KB_IGNORED_TOP_LEVEL")
    value = json.loads(configured) if configured is not None else local_settings().get("ignored_top_level", {})
    if not isinstance(value, dict):
        raise ValueError("PROJECT_KB_IGNORED_TOP_LEVEL must be a JSON object")
    result = {}
    for project_id, names in value.items():
        if (not isinstance(project_id, str) or not project_id or not isinstance(names, list)
                or any(not isinstance(name, str) or not name or "/" in name or "\\" in name for name in names)):
            raise ValueError("Ignored top-level paths require project IDs and directory names")
        result[project_id] = set(names)
    return result


PROJECT_IGNORED_TOP_LEVEL = ignored_top_level()

INDEX_DIR = KB_ROOT / "indexes"
DB_PATH = INDEX_DIR / ("kb-v3.sqlite" if PROFILE == "production" else "kb.sqlite")
VAULT_DIR = KB_ROOT / "vault"
PROJECTS_DIR = VAULT_DIR / "projects"
EVIDENCE_DIR = VAULT_DIR / "evidence"
CONCEPTS_DIR = VAULT_DIR / "concepts"
RESUME_DIR = VAULT_DIR / "resume"
AUDITS_DIR = VAULT_DIR / "audits"
LOG_DIR = KB_ROOT / "logs"

SAFE_TEXT_EXTENSIONS = {
    ".md",
    ".mdx",
    ".txt",
    ".rst",
    ".py",
    ".ipynb",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".json",
    ".jsonl",
    ".toml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".csv",
    ".tsv",
    ".sql",
    ".sh",
    ".ps1",
    ".bat",
    ".cmd",
    ".html",
    ".css",
    ".scss",
    ".vue",
    ".svelte",
    ".java",
    ".go",
    ".rs",
    ".cpp",
    ".c",
    ".h",
    ".hpp",
    ".cs",
    ".r",
    ".m",
    ".tex",
}

PRIORITY_FILENAMES = {
    "readme",
    "agents",
    "architecture",
    "repository_architecture",
    "repository_structure",
    "repository_map",
    "design_notes",
    "project_summary",
    "application_project_summary",
    "data_card",
    "model_card",
    "path_migration",
    "deep_model_research_plan",
    "deepscientist_integration",
    "official_deepscientist_extension_plan",
    "pyproject.toml",
    "package.json",
    "requirements.txt",
    "environment.yml",
    "conda.yml",
    "setup.py",
    "setup.cfg",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "makefile",
    "justfile",
    "vite.config.ts",
    "vite.config.js",
    "next.config.js",
    "next.config.mjs",
    "tsconfig.json",
}

IGNORED_DIR_NAMES = {
    ".git",
    "node_modules",
    ".venv",
    ".venv-1",
    ".mamba",
    ".conda",
    "venv",
    "env",
    "envs",
    "conda-meta",
    "pkgs",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
    ".next",
    ".nuxt",
    "dist",
    "build",
    "target",
    "coverage",
    ".idea",
    ".ipynb_checkpoints",
    "outputs",
    "output",
    "logs",
    "log",
    "data",
    "dataset",
    "datasets",
    "archive",
    "archives",
    "checkpoints",
    "models",
    "weights",
    "runs",
    "wandb",
    "mlruns",
    "tmp",
    "temp",
    "downloads",
    "download",
    "site-packages",
}

METADATA_ONLY_TOP_LEVEL_NAMES = {
    ".claude",
    ".vscode",
    "__pycache__",
    "outputs",
    "figs",
    "playwright",
    "_tmp_wkreader_asar",
}

METADATA_ONLY_TOP_LEVEL_SUFFIXES = (
    "_data",
    "_archives",
    "_archive",
    "-data",
    "-archives",
)

LOW_VALUE_FILENAMES = {
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "uv.lock",
    "pipfile.lock",
}

SENSITIVE_NAMES = {
    ".env",
    ".env.local",
    ".env.development",
    ".env.production",
    ".npmrc",
    ".pypirc",
    "auth.json",
    "credentials.json",
    "credential.json",
    "token.json",
    "secrets.json",
    "secret.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
}

SENSITIVE_SUBSTRINGS = (
    "secret",
    "secrets",
    "credential",
    "credentials",
    "private_key",
    "apikey",
    "api_key",
    "access_token",
    "refresh_token",
)

MAX_INDEX_FILE_BYTES = 700_000
CHUNK_MAX_CHARS = 10_000
CHUNK_MAX_LINES = 180
