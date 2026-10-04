# Backup catalog and recovery workflow

Backup catalogs local recovery archives created by the `toolframe-backup`
operator CLI. Its Dashboard and read-only MCP tool inspect archives without
copying a running application's files. The source application must be cleanly
stopped while the CLI captures its public maintenance inventory.

Install the plugin package in the application's environment and configure a
fixed, absolute local backup directory through the application's plugin
configuration:

```toml
[plugins.backup.config]
destination = "/srv/toolframe-backups"
retention_keep = 10
```

The destination must belong to the operator, have mode `0700`, and have no
symlink components. Archive files must belong to the operator and have no group
or other permissions; the CLI creates them with mode `0600`. The plugin permits
a missing destination so the stopped CLI can create it. It never accepts paths
or arbitrary filesystem actions from Dashboard, MCP, or RPC clients. Only local
filesystem destinations are supported; S3 and other external destinations are
unimplemented.

To capture an application, stop it using its ordinary shutdown flow, then run:

```sh
toolframe-backup create --home /srv/toolframe-app --directory /srv/toolframe-backups
toolframe-backup list --directory /srv/toolframe-backups
```

The operator installation needs the `operator` extra for creation. Verification,
listing, and restoration work without a running host. Restart the source
application to inspect the catalog. Read the package README for the complete
creation and restoration support limits.

The destination directory is the catalog's source of truth. No catalog file is
written into the source application by the offline CLI, and the runtime plugin
does not require a storage, Jobs, or Audit provider. Each scan fully verifies
the own-format files named `backup-<32 lowercase hexadecimal characters>.zip`
before showing them. The `last_verified_at` timestamp reports that scan's
verification, rather than a cached assertion. When the host supplies its
application identity, catalog results and individual verification are restricted
to that application. Invalid candidates are reported by ID and error code and
preserved. Unknown filenames are ignored and preserved.

Scans are bounded to 1,000 archive candidates, 10,000 directory entries, and a
4 GiB total archive scan budget. Each archive also has the library's file-count,
compressed-size, payload-size, and decompression limits. The read interface shows
at most 100 verified backups, newest first, with a default limit of 50. Split
larger catalogs into separate operator-managed directories before scanning.

The public `backup.catalog` service is version 1:

| Method | Scope | Behavior |
| --- | --- | --- |
| `list_backups(limit=50)` | `backup.read` | Scan and list at most 100 verified archives; read-only MCP uses this method. |
| `verify_backup(backup_id)` | `system.plugins.manage` | Recheck one validated ID in the configured destination. |
| `retention_preview(max_delete=100)` | `system.plugins.manage` | Preview deletion of at most 100 oldest verified archives beyond the configured keep count. |
| `apply_retention(plan_token)` | `system.plugins.manage` | Reverify and apply the unchanged, unexpired preview once. |

`backup.read` is a business scope. Verification and retention require the
existing **Manage plugins** operator permission, `system.plugins.manage`; an
all-business grant does not permit these actions. The Dashboard requires
`backup.read` and hides management controls without `system.plugins.manage`.
All service methods require scoped calls and are
excluded from anonymous public API routes. MCP exposes only listing.

Retention is explicit, never automatic. `retention_keep` defaults to 10 and is
bounded to 1–1,000. A preview requires the host-issued application identity,
keeps the newest matching verified archives, and selects the oldest excess
archives up to `max_delete` (1–100). Unknown entries, rejected candidates, and
archives for other applications remain untouched. Preview tokens live in
process memory for ten minutes and can be used once; restarting the plugin
invalidates them. Catalog changes invalidate a preview. Confirmation moves
selected files into a protected temporary directory and verifies them again
before deleting them. If a destination change prevents safe recovery, preserved
files may remain under `.backup-retention-*` for operator recovery; these entries
are never adopted by the catalog or automatically deleted.

Archives are **unencrypted** and can contain credentials and retained key
payloads. Protect the destination and archive permissions. Public catalog
summaries contain identity, composition revision, counts, timestamps, and
checksums, never payload contents or dependency credential URLs. SHA-256 checks
detect corruption; an archive is not signed or authenticated. Restoration
preserves the original application identity for recovery, so do not concurrently
run a restored clone with the same external identity.
