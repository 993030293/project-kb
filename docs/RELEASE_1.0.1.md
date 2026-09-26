# project-kb 1.0.1 public source release

## Scope

This release contains a local Windows-oriented MCP server, CLI, and tests.
It supports SQLite-backed source snapshots, provenance-aware retrieval, and
versioned `kb2_*` operations. The public tree does not contain the production
database, vault, source projects, logs, local settings, or credentials.

The public variant excludes external model-provider integration, including
query expansion, provider configuration, and provider credentials. `kb_retrieve`
uses local FTS retrieval. The local MCP and `kb2_*` interfaces remain.

## Deployment boundary

Use an isolated sandbox and the commands in the README for initial validation.
An existing schema-3 production store has separate identity and data; this
source package does not migrate or overwrite it. Write tools run with the
permissions of the operating-system account that starts the MCP process.
Do not expose MCP over an unauthenticated network bridge.

## Publication checks

The source tree is checked by `scripts/check_public_tree.py` against a narrow
Git file allowlist and common secret/path patterns. The checker does not prove
that every line is safe to publish or that third-party code and data rights are
cleared. Before publication, inspect the complete staged diff and run the
tests and isolated CLI/MCP smoke paths. A source ZIP can be built with
`scripts/build_release.py`; `.local/dist` remains outside Git.

On 2026-09-27, the 40-file public candidate passed the publication checker,
20 included pytest tests, Ruff, `pip check`, and `pip-audit -r requirements.txt`
with no known vulnerabilities reported. The source ZIP was extracted into an
isolated directory; its 20 included tests passed. A fresh sandbox completed
`init`, `init-api`, `register-root`, `rank-install`, `refresh`, and search with
one sample evidence hit. MCP listed 21 tools and passed retrieval plus exact
`kb2_evidence` readback. These are engineering checks, not a guarantee that
unseen deployments or dependencies are free of defects.

## License

The custom [source-available license](../LICENSE.md) allows unmodified
individual and organization-internal use, including commercial internal use.
It does not allow modification, external redistribution, or external hosted
service without written permission. It is not an OSI open-source license.
GitHub's public-repository terms still permit platform viewing and forking.
