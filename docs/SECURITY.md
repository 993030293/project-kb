# Security and data scope

This server uses MCP over stdio. The operating-system account that starts it
controls access to source roots, the SQLite store, and write tools. A connection
over SSH runs with the permissions of the authenticated account. Give this
server only to trusted clients and accounts; the MCP tool list itself is not an
authorization boundary between read and write tools.

The code-only repository excludes personal `vault/`, `indexes/`, `settings.local.json`,
`.local/`, credentials, and logs. Keep the actual database and snapshots outside
Git. Run `python scripts/check_public_tree.py` before staging and again before pushing files;
also inspect `git status --short` and the Git diff. The checker catches common
accidental leaks but does not classify arbitrary personal or licensed text.

This public code contains no outbound model request path or external API
credentials. It does not upload search text or indexed evidence to a provider.
The publication checker still detects likely keys accidentally added to Git;
those detection rules do not make network requests.

The production runtime validates source and data paths and rejects reparse
points for filesystem access. Runtime settings should remain writable only by
the owner of the service account. Do not expose the stdio process through an
unauthenticated network bridge.
