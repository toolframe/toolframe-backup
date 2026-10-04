# Toolframe Backup

Toolframe Backup creates recovery archives of cleanly stopped Toolframe applications
and provides a Dashboard and read-only MCP catalog for a configured local backup
directory. Its standalone CLI can verify or restore archives even when the source
application cannot start. The ordinary plugin never snapshots a running application.

## Quick start

Use Python 3.14 or newer and matching Toolframe SDK/Core wheels. Archive creation
requires a Core release providing `toolframe_core.maintenance.stopped_application`.
Restoring recorded environments also requires its public `application_lock` helper.
Install the operator extra from your Toolframe wheel set:

```sh
uv venv --python 3.14
uv pip install --find-links ./wheelhouse 'toolframe-backup[operator]==0.1.0'
# Stop the application's host and workers cleanly before creating the archive.
.venv/bin/toolframe-backup create --home ./app --directory ./backups
.venv/bin/toolframe-backup list --directory ./backups
.venv/bin/toolframe-backup verify ./backups/backup-<id>.zip
.venv/bin/toolframe-backup restore ./backups/backup-<id>.zip --destination ./recovered-app
# Optional local-only reconstruction (requires every exact-hash dependency locally):
.venv/bin/toolframe-backup restore ./backups/backup-<id>.zip --destination ./offline-recovered-app --offline --wheelhouse ./wheelhouse
```

The CLI prints nonsecret JSON summaries; errors use exit code 2 and interruption
uses 130. New backup directories and restored directories have mode 0700. Archive
files and restored payload files have mode 0600; uv sets reconstructed environment
file modes. Existing backup directories must already have
mode 0700. Restore requires a new destination with an existing parent directory;
it never replaces an existing home, including an empty directory.
Restore paths may contain spaces, but cannot contain quotes, backslashes or control
characters because exact lock reconstruction expands paths in the original TOML.

To install the catalog in an existing application, declare the plugin and its
required destination together in `app/toolframe.toml`. The example wheel path is
relative to the application home; replace the destination with your operator-owned
absolute backup path:

```toml
[plugins.backup]
source = "wheel:../wheelhouse/toolframe_backup-0.1.0-py3-none-any.whl"
enabled = true

[plugins.backup.config]
destination = "/srv/toolframe-backups"
retention_keep = 10
```

```sh
toolframe-core --home ./app plan
toolframe-core --home ./app apply --plan-id <plan-id-from-the-plan-output>
```

An installed Dashboard or MCP provider consumes the plugin's ordinary resources.
Grant `backup.read` to catalog readers. Verification and retention actions require
the built-in `system.plugins.manage` (Manage plugins) operator permission.
See the [catalog guide](src/toolframe_backup/docs/usage.md) for its service methods,
verification records and explicit retention workflow.

## Support limits

- Version 1 supports local in-home files and local SQLite stores accepted by Core's
  stopped maintenance inventory. Live or uncertain workers, pending recovery,
  external SQL and external attachments are rejected by Core. S3 and other remote
  archive destinations are not implemented.
- Archives are **unencrypted** and contain private keys, configuration and database
  contents in their payloads. Store them in an operator-controlled local directory.
  The public manifest contains identity, hashes, store ownership, retained-key
  requirements and dependency prerequisites, without credential URLs or key bytes.
- SHA-256 checks detect corruption. They are not signatures and do not authenticate
  an archive against an attacker who can replace both payload and manifest.
- Offline means the source host is stopped and the CLI needs no running application.
  Restore reconstructs omitted backend/UI environments with uv from protected original
  exact pylocks before reporting `ready: true`. It uses the final absolute directory
  under Core's public application lock so console-script shebangs remain valid. Missing
  dependency wheels require exact-hash wheels from a supplied wheelhouse or network;
  an air-gapped restart is not guaranteed. uv performs locked dependency acquisition;
  the CLI has no independent downloader. `--offline` forbids network acquisition and
  `--wheelhouse` supplies local candidate wheels. Recovery requires the original Python
  implementation, OS and machine architecture. A recorded two-component Python
  version requires the same major/minor; a recorded three-component version requires
  the exact patch too. The complete operator interpreter is checked against
  Requires-Python, environment markers and wheel tags before publication. Reconstruction
  requires compatible exact-hash wheels and supports at most 100 distinct environments;
  source builds are disabled. Subprocess output is suppressed to protect credentials.
  A failed reconstruction removes only the new destination created by that restore.
- A recovered clone retains the application ID and composition. Do not concurrently
  run it with another copy using the same external identity. External state is outside
  the supported recovery scope.
- Atomic restoration is supported on macOS and Linux. Default limits are 10,000
  files, 512 MiB per payload file, 2 GiB total payload, 4 MiB manifest, 3 GiB archive,
  16 MiB protected environment payload and a maximum decompression ratio of 200.
  ZIP central-directory size/count are checked before indexing. The catalog scans at
  most 1,000 archives.

See the [archive architecture](docs/architecture.md) and
[offline recovery decision](docs/adr/0001-stopped-recovery-and-directory-catalog.md).

## Development

Place the immutable matching Toolframe wheel set, including SDK, Core and their
prerequisites, in `build/wheelhouse/` before syncing. The Core wheel must provide the public
maintenance helpers used above. This library omits a committed `uv.lock` and
sibling source pins; development resolves dependencies from supplied or published
wheels.

```sh
uv sync --no-sources --find-links ./build/wheelhouse --extra operator --extra ui --group dev
uv run --no-sync pytest
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .
uv build
```

Package tests cover archive boundaries with mocked Core inventories and guards, and
include real offline uv reconstruction of local environments in temporary homes.
Verify stopped-state eligibility, the actual Core lock and restored application,
Dashboard and client flows separately through an installed application. Package tests
do not establish remote-store or air-gap support.

Licensed under [Apache-2.0](LICENSE).
