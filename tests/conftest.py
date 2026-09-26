"""Keep local tests isolated when run directly from a fresh checkout."""

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("PROJECT_KB_PROFILE", "sandbox")
os.environ.setdefault("PROJECT_KB_SANDBOX_BASE", str(ROOT))
os.environ.setdefault("PROJECT_KB_ROOT", str(ROOT / ".local" / "kb"))
os.environ.setdefault("PROJECT_KB_SOURCE_ROOT", str(ROOT / ".local" / "sources"))
os.environ.setdefault("PROJECT_KB_PUBLIC_V2", "1")
