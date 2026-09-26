"""Publication rules reject data paths and likely credentials."""

import subprocess

from scripts import check_public_tree as public


def test_only_source_and_docs_are_publishable():
    assert public.allowed("project_kb/v2/store.py")
    assert public.allowed("docs/CODE_REVIEW.md")
    assert not public.allowed("vault/evidence/private.md")
    assert not public.allowed("indexes/kb-v3.sqlite")
    assert not public.allowed("settings.local.json")
    assert not public.allowed("scripts/debug.env")


def test_sensitive_signatures_are_detected_without_echoing_values():
    assert public.RULES["api_token"].search("sk-" + "a" * 40)
    assert public.RULES["private_key"].search("-----BEGIN " + "PRIVATE KEY-----")
    assert public.RULES["personal_windows_path"].search("C:\\Users\\someone\\document.txt")
    assert public.RULES["aws_access_key"].search("AKIA" + "A" * 16)
    assert public.RULES["google_api_key"].search("AIza" + "a" * 35)
    assert public.RULES["slack_token"].search("xoxb-" + "a" * 20)
    assert public.RULES["assigned_secret"].search('SERVICE_API_KEY: "' + "a" * 20 + '"')


def test_staged_content_is_checked_even_when_worktree_is_clean(tmp_path, monkeypatch):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    note = tmp_path / "docs" / "note.md"
    note.parent.mkdir()
    note.write_text("password='" + "x" * 24 + "'\n", encoding="utf-8")
    subprocess.run(["git", "add", "docs/note.md"], cwd=tmp_path, check=True)
    note.write_text("public note\n", encoding="utf-8")
    monkeypatch.setattr(public, "ROOT", tmp_path)
    assert ("docs/note.md:index:1", "assigned_secret") in public.check()
