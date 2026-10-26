# Development and verification

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

The compatibility workflow tests the same wheel with the minimum and newest
supported SDK. Its separate operator checks exercise Core 0.7.0 and the newest
supported Core through the public CLI: a running application refuses backup,
while a cleanly stopped application can be backed up, verified, restored and
restarted. These checks also run before package publication.
