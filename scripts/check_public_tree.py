"""Fail closed on unexpected Git files and likely private content."""

from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ROOT_FILES = {".gitignore", "README.md", "LICENSE.md", "requirements.txt", "requirements-dev.txt", "mcp_server.py"}
RULES = {
    "personal_windows_path": re.compile(r"(?i)[A-Z]:[/\\]Users[/\\][^/\\\s]+"),
    "personal_unix_path": re.compile(r"/" + r"home/[^/\s]+"),
    "tailscale_address": re.compile(r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\b(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]{20,}"),
    "api_token": re.compile(r"\bsk-[A-Za-z0-9_-]{32,}"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}"),
    "assigned_secret": re.compile(
        r"(?i)\b(?:[a-z0-9_]+_)?(?:password|api[_-]?key|access[_-]?token|client[_-]?secret)"
        r"\s*[:=]\s*['\"][^'\"]{16,}['\"]"
    ),
}


def allowed(relative: str) -> bool:
    if relative in ROOT_FILES:
        return True
    parts = relative.split("/")
    if len(parts) < 2:
        return False
    if parts[0] in {"project_kb", "scripts", "tests"}:
        return relative.endswith(".py")
    return parts[0] == "docs" and relative.endswith(".md")


def git_candidates() -> list[str]:
    return sorted(set(git_paths("--cached")) | set(git_paths("--others", "--exclude-standard")))


def git_paths(*flags: str) -> list[str]:
    result = subprocess.run(["git", "ls-files", *flags, "-z"], cwd=ROOT, capture_output=True, check=True)
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def staged_bytes(relative: str) -> bytes:
    result = subprocess.run(["git", "show", ":" + relative], cwd=ROOT, capture_output=True, check=True)
    return result.stdout


def inspect_bytes(relative: str, data: bytes, issues: list[tuple[str, str]], label: str) -> None:
    if len(data) > 512 * 1024 or b"\0" in data:
        issues.append((relative + label, "binary_or_oversized"))
        return
    try:
        content = data.decode("utf-8")
    except UnicodeError:
        issues.append((relative + label, "not_utf8"))
        return
    for line_number, line in enumerate(content.splitlines(), 1):
        for name, pattern in RULES.items():
            if pattern.search(line):
                issues.append((f"{relative}{label}:{line_number}", name))


def check() -> list[tuple[str, str]]:
    issues = []
    staged = set(git_paths("--cached"))
    candidates = sorted(staged | set(git_paths("--others", "--exclude-standard")))
    if not candidates:
        issues.append(("repository", "no_files_selected"))
    for relative in candidates:
        path = ROOT / relative
        if not allowed(relative):
            issues.append((relative, "unexpected_file"))
            continue
        if not path.is_file() or any(part.is_symlink() for part in (path, *path.parents) if part != ROOT):
            issues.append((relative, "missing_or_linked_file"))
            continue
        inspect_bytes(relative, path.read_bytes(), issues, ":worktree")
        if relative in staged:
            inspect_bytes(relative, staged_bytes(relative), issues, ":index")
    return issues


def main() -> int:
    try:
        issues = check()
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        print("Publication check could not inspect Git files: " + type(exc).__name__, file=sys.stderr)
        return 2
    if issues:
        for path, reason in issues:
            print(f"{path}: {reason}", file=sys.stderr)
        return 1
    print(f"Public tree check passed: {len(git_candidates())} candidate files; no high-confidence leaks detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
