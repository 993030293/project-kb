"""Project root rules use synthetic directories instead of machine-specific data."""

from pathlib import Path

import pytest

from project_kb import scanner
from project_kb.config import ignored_top_level


@pytest.fixture
def migrated_root(tmp_path, monkeypatch):
    source = tmp_path / "sources"
    original = source / "stable-id"
    migrated = tmp_path / "migrated"
    original.mkdir(parents=True)
    migrated.mkdir()
    for name in ("normal.md", "cache/duplicate.md", "worktrees/duplicate.md"):
        file = migrated / name
        file.parent.mkdir(exist_ok=True)
        file.write_text(name, encoding="utf-8")
    monkeypatch.setattr(scanner, "PROJECT_ROOT_OVERRIDES", {"stable-id": migrated})
    monkeypatch.setattr(scanner, "PROJECT_IGNORED_TOP_LEVEL", {"stable-id": {"cache", "worktrees"}})
    monkeypatch.setattr(scanner, "source_path", lambda path: Path(path).resolve())
    return source, migrated


def test_migrated_project_keeps_stable_id(migrated_root):
    _, migrated = migrated_root
    assert scanner.project_id_for_path(migrated) == "stable-id"


def test_discovery_uses_authoritative_migrated_root(migrated_root):
    source, migrated = migrated_root
    assert scanner.discover_projects(source) == [migrated]


def test_project_specific_duplicate_roots_are_excluded(migrated_root):
    _, migrated = migrated_root
    rel_paths = [candidate.rel_path.lower() for candidate in scanner.iter_files(migrated, "stable-id")]
    assert rel_paths == ["normal.md"]


def test_invalid_ignored_directory_configuration(monkeypatch):
    monkeypatch.setenv("PROJECT_KB_IGNORED_TOP_LEVEL", '{"project": ["../outside"]}')
    with pytest.raises(ValueError, match="Ignored top-level"):
        ignored_top_level()
