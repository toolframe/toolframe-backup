# ADR 0001: Stopped recovery and a directory catalog

Status: accepted

## Context

A useful recovery archive must bind configuration, captured artifacts, journal locks,
business data and retained private keys to one application composition. Copying a live
host's home can mix generations and transactions. A recovery tool must also work when
the application's plugin runtime cannot start.

## Decision

Creation is a standalone operator command using Core's public stopped maintenance
context. Core owns layout and eligibility, while Backup owns archives, bounded
verification, restoration into a new home and local retention. Ordinary plugin
resources expose a directory catalog and guide operators through the stopped workflow.
The configured directory provides catalog truth; previews and verification observations
can be rebuilt without coupling recovery to a SQL provider, Jobs or Audit.

Version 1 accepts only local files and SQLite stores inside the application home.
Archives retain the application identity and exact dependency prerequisites; omitted
runtime environments are reconstructed at the final path under Core's public lock,
using protected original exact pylocks before recovery is declared ready. Rehydration can require a network
or a prepared wheelhouse. Archive encryption and signatures are deferred, so operator
filesystem permissions protect confidentiality and hashes detect corruption only.

## Consequences

The runtime cannot offer a live-backup button. Operators must stop the host cleanly
before capture, and external storage needs a future explicit consistency contract.
Recovery remains available without a functioning source application. A restored clone
must not concurrently reuse the same external identity. Directory scanning costs full
verification work and is bounded; unknown files remain untouched by retention.
