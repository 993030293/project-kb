# Local settings

Production installations may use `settings.local.json` at the installed knowledge
base root. Keep it out of Git. This file is read when a production process starts.
Environment variables take precedence over the corresponding local value.

```json
{
  "source_root": "C:\\workspaces",
  "root_overrides": {
    "existing-project-id": "D:\\migrated-project"
  },
  "ignored_top_level": {
    "existing-project-id": ["cache", "worktrees"]
  }
}
```

`source_root` is the normal source boundary. Explicit `root_overrides` retain
project identity when an individual source moved outside that boundary. Paths
must be absolute; reparse points are rejected for source access. A missing
source is retained as historical database data, without claiming a fresh scan.

The equivalent environment settings are `PROJECT_KB_SOURCE_ROOT`,
`PROJECT_KB_ROOT_OVERRIDES` (JSON object), and `PROJECT_KB_IGNORED_TOP_LEVEL`
(JSON object of directory-name lists). `PROJECT_KB_INSTALL_ROOT` selects an
existing schema-3 production installation. Restart MCP after changing settings.
