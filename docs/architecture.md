# Recovery archive contract

The runtime catalog imports only the SDK and Backup's archive library. Creation
lazily imports Core's public `stopped_application` helper. Verification needs no
Core import. Restoration lazily imports the public `application_lock` helper when
recorded environments exist; an archive without environments needs no Core import
for restoration. These operator operations need no running host.

Core owns application layout, artifact ownership and stopped-state eligibility.
`stopped_application(home)` holds the real HostLock for the complete source read.
Backup creates all temporary output outside the source home. Captured files are copied
without writing to the source; SQLite backup runs against these protected local copies.
Core's HostLock updates the documented volatile `.toolframe/host.lock` PID while held;
this lock and filesystem access-time metadata are excluded from durable byte-preservation
checks. Backup writes no source catalog, configuration, key, artifact or store data.
An archive is published under a fresh `backup-<32-hex-id>.zip` name only after every
payload has passed verification. Failure and interruption remove staging output.

Version 1 ZIP archives contain `manifest.json`, exactly the declared regular files
under `payload/`, and a protected `recovery/environment-locks.json` when the inventory
contains recorded environments. The manifest records application identity/composition, the original
inventory file hashes, the snapshot payload hashes, SQLite store identities, retained
key requirements, exact environment-lock hashes and dependency-wheel prerequisites.
Only documented public inventory fields are copied to metadata. Sensitive configuration,
original locks and key contents remain in payload files. Raw pylock text is excluded
from public inventory and manifest metadata; the protected recovery payload is bound by
its own size/hash and each original lock hash. A SQLite snapshot's checksum
can differ from the original database's byte checksum while retaining its logical data.

Verification rejects unsafe paths, duplicate or conflicting paths, links and special
members, encrypted ZIP members, unsupported compression, undeclared/missing entries,
size/checksum disagreement, oversized archives and excessive decompression ratios.
It checks every payload without extraction. Restoration repeats checksum checks while
extracting from the same opened archive, stages a protected tree next to the destination,
and publishes it with the platform's atomic no-replace rename. It holds Core's public
`application_lock` across publication and reconstructs recorded environments at the
final absolute path using uv, exact original locks and hash verification. The original
raw lock remains unchanged in the protected archive; reconstruction expands its
`${TOOLFRAME_HOME}` token for the final location. Direct wheel `archive.path` records
confined to the recovered home are supported alongside index wheel records.
Python implementation, OS and machine architecture must match. A recorded version
with only major/minor requires those components to match; when it includes a patch,
all three components must match.
The complete operator interpreter must satisfy Requires-Python, environment markers
and compatible wheel tags before publication. uv is constrained to hash-verified
binary installation, including when the original lock contains source alternatives.
No `.ready` marker is written before successful synchronization. Failure rolls the
new home back out of its public
name while the lock remains held, then removes staging output. Existing homes are never
merged or overwritten. Both checksums and the archive's own digest are corruption
metadata, not authenticity evidence.

The configured local directory is the catalog's source of truth. Scanning recognizes
only Backup's filename convention and verifies archives before admitting them. The
catalog can be regenerated after restart without writing a source-side offline catalog.
Retention is an explicit operator action: preview a bounded deletion set, then apply
the current preview after rechecking archive identity/content. Unknown or invalid files
are preserved. No running service accepts an arbitrary filesystem path from a client.
