# project-kb

## 中文介绍

隔一段时间再回到项目，常常记得结论，却找不到当时依据的文件。project-kb
把选定项目的文本材料和保存的摘要组织在本地 SQLite 中，让 Codex
或命令行先找到线索，再回到原文核对。

- **整理与更新项目材料：** 登记源码目录，收集受支持的文本文件，并按项目刷新索引。版本记录保留文件变化的历史。
- **查找线索：** 全文搜索支持项目筛选；混合检索还会带出已保存的项目关系。版本化搜索可继续翻页和查看历史记录。
- **回读证据：** 检索结果带有来源路径、位置和证据 ID；`kb2_evidence` 可以按字符偏移读取对应的原文片段。
- **保存与核对：** 可以保存关联证据的摘要，获取供 Codex 整理的证据包，检查一段陈述是否有匹配材料，并运行存储与引用检查。匹配材料是候选依据，不能代替事实核验。
- **接入现有工作流：** 提供 MCP 工具和 CLI，可用于项目回顾、跨项目查找及整理项目经历的证据材料。

公开版在本机运行，不向外部模型服务发送检索内容，也不包含外部模型 API
接入。数据库、项目原文和本地设置由使用者保存在自己的机器上。

## English overview

When you return to an old project, finding the file behind a past conclusion
can take longer than finding the conclusion itself. project-kb keeps selected
project text and saved summaries in a local SQLite store, so Codex or a CLI
can find a lead and open the source again.

- **Collect and refresh:** Register a source directory, index supported text files, and refresh a project as its files change. Version records preserve earlier states.
- **Search across projects:** Use full-text search with a project filter, browse stored relations alongside matches, and page through versioned search results or history.
- **Read the source:** Results carry paths, locations, and evidence IDs. `kb2_evidence` reads an exact text window by character offset.
- **Keep useful context:** Save summaries with evidence references, prepare evidence packs for Codex, find candidate support for a claim, and check storage and reference integrity. A matching record still needs human verification.
- **Work where you already work:** Use the MCP server or CLI for project handoffs, cross-project lookup, and evidence gathering for a resume or portfolio.

The public edition runs locally and has no external model API integration.
Search text and indexed evidence are not sent to a model provider by this code.
Your database, source projects, and local settings stay outside the repository.

## Quick start / 快速开始

This repository contains code only. On Windows with Python 3.11, run the
PowerShell commands below in a checkout. They create a sample under ignored
`.local` paths and leave an existing store untouched.
本仓库只包含代码。以下命令会建立独立样例；确认运行正常后，再连接自己的项目。
Read the [1.0.1 release notes](docs/RELEASE_1.0.1.md) before deploying it.

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

The ranking byte ceiling is an explicit local storage limit, not a usage target.
Operation IDs are idempotency keys. Reuse one only for an identical retry.
Keep `PROJECT_KB_ENABLE_SANDBOX_WRITES` unset for read-only sessions. The sample
does not turn a new checkout into an existing production deployment.

Start the MCP server from the same configured environment with
`& .\.venv\Scripts\python.exe -B -X utf8 -u .\mcp_server.py`.
The server exposes compact `kb_retrieve` and exact `kb2_*` interfaces; source
summaries remain evidence candidates until independently checked.

## Existing store / 现有知识库

An existing schema-3 installation has a `deployment.json` marker and an active
`indexes/kb-v3.sqlite`. By default, production code expects that installation at
`$HOME\project-kb` and source repositories at `$HOME\git`. Set
`PROJECT_KB_INSTALL_ROOT` and `PROJECT_KB_SOURCE_ROOT` before starting the server
when those paths differ. Keep the production data and code together at the
configured installation root. See [local settings](docs/LOCAL_SETTINGS.md).

本节仅用于连接已经存在的 schema-3 知识库；新安装请从上面的独立样例开始。

## Build a source archive / 打包源码

Run `python scripts\check_public_tree.py` and inspect `git status --short`.
The check examines both Git's staged bytes and current worktree files. It
reports possible leaks by path and line number without printing matched text.
It cannot prove that every project document is licensed for publication.
After review, run `python scripts\build_release.py` to create the source ZIP
under the ignored `.local\dist` directory. The build refuses mismatched staged
and worktree bytes; it does not commit or push the repository.

## License

这是源码可用许可，不是开源许可。允许个人和企业内部运行未修改版本；修改、再发布或对外托管需要另行获得书面许可。

This is source-available software, **not an open-source license**. Individuals
and organizations may download, install, and run the unmodified code for their
own internal purposes, including commercial internal use. Modification,
redistribution, and public hosting require separate written permission. Read
the complete [LICENSE.md](LICENSE.md) before use. GitHub's platform terms still
allow viewing and forking a public repository.

Review and test details are in [RELEASE_1.0.1.md](docs/RELEASE_1.0.1.md). See
[SECURITY.md](docs/SECURITY.md) for the SSH, MCP and data boundaries.
