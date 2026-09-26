# project-kb 1.0.1

A local, evidence-first project knowledge base with a Windows MCP server and CLI.
It stores source snapshots and summaries in SQLite, retains provenance, and exposes
bounded local search and exact readback. This public distribution has no external
model API integration.

This source release contains **code only**. Runtime databases, vault content, local settings,
credentials, logs, and source projects belong outside Git history. The production
schema-3 deployment is Windows-specific. This release was tested on Python 3.11.
Read the [1.0.1 audit and release notes](docs/RELEASE_1.0.1.md) before deploying it.

## Try It With An Isolated Sample

Run these commands from a PowerShell session in this checkout. They create only
ignored `.local` data. Use a disposable sample project inside `.local\sources`.
The ranking byte ceiling is an explicit local storage limit, not a usage target.

```powershell
py -3.11 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
& .\.venv\Scripts\python.exe -m pytest -q tests
$repo = (Get-Location).Path
$env:PROJECT_KB_PROFILE = 'sandbox'
$env:PROJECT_KB_SANDBOX_BASE = $repo
$env:PROJECT_KB_ROOT = Join-Path $repo '.local\kb'
$env:PROJECT_KB_SOURCE_ROOT = Join-Path $repo '.local\sources'
$env:PROJECT_KB_PUBLIC_V2 = '1'
$env:PROJECT_KB_ENABLE_SANDBOX_WRITES = '1'
$env:PROJECT_KB_RANK_MAX_BYTES = '67108864'
New-Item -ItemType Directory -Path "$env:PROJECT_KB_ROOT\indexes", "$env:PROJECT_KB_SOURCE_ROOT\sample" -Force | Out-Null
Set-Content -LiteralPath "$env:PROJECT_KB_SOURCE_ROOT\sample\README.md" -Value 'A sample calibration checklist.'
& .\.venv\Scripts\python.exe scripts\kb_v2.py init
& .\.venv\Scripts\python.exe scripts\kb_v2.py init-api --operation-id sample-init-api
& .\.venv\Scripts\python.exe scripts\kb_v2.py register-root --operation-id sample-register --project-id sample --root "$env:PROJECT_KB_SOURCE_ROOT\sample"
& .\.venv\Scripts\python.exe scripts\kb_v2.py rank-install --operation-id sample-rank
& .\.venv\Scripts\python.exe scripts\kb_v2.py refresh --operation-id sample-refresh --project-id sample --root "$env:PROJECT_KB_SOURCE_ROOT\sample"
& .\.venv\Scripts\python.exe scripts\kb_v2.py search calibration --project-id sample
```

Operation IDs are idempotency keys. Reuse one only for an identical retry.
Keep `PROJECT_KB_ENABLE_SANDBOX_WRITES` unset for read-only sessions. The sample
does not turn a new checkout into an existing production deployment.

Start the MCP server from the same configured environment with
`& .\.venv\Scripts\python.exe -B -X utf8 -u .\mcp_server.py`.
The server exposes compact `kb_retrieve` and exact `kb2_*` interfaces; source
summaries remain evidence candidates until independently checked.

## Existing Production Store

An existing schema-3 installation has a `deployment.json` marker and an active
`indexes/kb-v3.sqlite`. By default, production code expects that installation at
`$HOME\project-kb` and source repositories at `$HOME\git`. Set
`PROJECT_KB_INSTALL_ROOT` and `PROJECT_KB_SOURCE_ROOT` before starting the server
when those paths differ. Keep the production data and code together at the
configured installation root. See [local settings](docs/LOCAL_SETTINGS.md).

Search remains local. No query or indexed evidence is sent to an external model
service by this code. The local MCP interface and versioned `kb2_*` commands
remain available.

## Before GitHub

Run `python scripts\check_public_tree.py` and inspect `git status --short`.
The check examines both Git's staged bytes and current worktree files. It
reports possible leaks by path and line number without printing matched text.
It cannot prove that every project document is licensed for publication.
After review, run `python scripts\build_release.py` to create the source ZIP
under the ignored `.local\dist` directory. The build refuses mismatched staged
and worktree bytes; it does not commit or push the repository.

## License

This is source-available software, **not an open-source license**. Individuals
and organizations may download, install, and run the unmodified code for their
own internal purposes, including commercial internal use. Modification,
redistribution, and public hosting require separate written permission. Read
the complete [LICENSE.md](LICENSE.md) before use. GitHub's platform terms still
allow viewing and forking a public repository.

The release does not upload anything automatically. Review and test details
are in [RELEASE_1.0.1.md](docs/RELEASE_1.0.1.md). See
[SECURITY.md](docs/SECURITY.md) for the SSH, MCP and data boundaries.
