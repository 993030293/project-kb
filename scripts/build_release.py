"""Create a code-only source archive after publication checks pass."""

import sys
from zipfile import ZipFile, ZIP_DEFLATED

from check_public_tree import ROOT, check, git_candidates, git_paths, staged_bytes


sys.path.insert(0, str(ROOT))
from project_kb import __version__ as VERSION  # noqa: E402


OUTPUT = ROOT / ".local" / "dist" / f"project-kb-{VERSION}-source.zip"


def main() -> int:
    issues = check()
    if issues:
        for path, reason in issues:
            print(f"{path}: {reason}", file=sys.stderr)
        return 1
    files = git_candidates()
    staged = set(git_paths("--cached"))
    for relative in files:
        if relative in staged and staged_bytes(relative) != (ROOT / relative).read_bytes():
            print(f"{relative}: staged_and_worktree_content_differ", file=sys.stderr)
            return 1
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(OUTPUT, "x", compression=ZIP_DEFLATED) as archive:
        for relative in files:
            archive.write(ROOT / relative, arcname=f"project-kb-{VERSION}/{relative}")
    with ZipFile(OUTPUT) as archive:
        bad = archive.testzip()
        if bad or len(archive.namelist()) != len(files):
            print("Archive verification failed", file=sys.stderr)
            return 1
    print(f"Created {OUTPUT} with {len(files)} source files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
