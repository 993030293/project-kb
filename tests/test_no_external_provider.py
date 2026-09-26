"""The public runtime must not grow an outbound model-provider integration."""

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FILES = (*sorted((ROOT / "project_kb").rglob("*.py")), ROOT / "mcp_server.py",
                 ROOT / "scripts" / "kb.py", ROOT / "scripts" / "kb_v2.py")
PROVIDER_MODULES = ("httpx", "requests", "aiohttp", "openai", "anthropic", "urllib.request")
PROVIDER_MARKERS = ("DEEPSEEK_API_KEY", "PROJECT_KB_API_", "api.deepseek.com", "expand_query")


def test_no_external_provider_imports_or_configuration():
    for path in RUNTIME_FILES:
        source = path.read_text(encoding="utf-8")
        assert not any(marker in source for marker in PROVIDER_MARKERS), path
        tree = ast.parse(source, filename=str(path))
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module)
        assert not any(module == banned or module.startswith(banned + ".")
                       for module in modules for banned in PROVIDER_MODULES), path
