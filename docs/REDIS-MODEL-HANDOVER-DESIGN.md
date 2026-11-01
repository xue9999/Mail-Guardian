# Redis model handover: design constraints

> Historical design note. Statements such as “not deployed” describe the original design stage. For current maintenance, start with [the operations runbook](maintainers/OPERATIONS.md) and [release process](maintainers/RELEASING.md). Private audit paths are deliberately omitted.

Status: design only. The synthetic `tools/redis_restore_rehearsal.py` proves
an isolated RDB-to-AOF conversion for known test data. It is not an importer,
and this document does not authorize or perform a mailbox cutover.

## Why a guarded import is needed

Guardian's Redis is configured with AOF enabled. A standalone `dump.rdb`
placed into an AOF-enabled Redis data directory is not a safe restore: Redis
can start without loading that file. A verified restore must load the RDB in a
new empty volume with AOF disabled, enable AOF, wait for successful persistence,
stop cleanly, then start the same volume with the normal production settings.
The real target's content must be compared after this restart.

The installed Compose project uses a project-scoped Redis volume. Docker does
not provide an atomic volume rename. An importer must never overwrite or
delete an existing volume, assume that a same-named volume is empty, or use
`docker compose down -v` against the installed project. The current helper
accepts no model import operation, and its root process deliberately avoids
traversing worker-owned state. A production importer must preserve those
boundaries instead of accepting an arbitrary caller-supplied path as root.

## Consistency and trust

1. Fence the old owner, stop its scheduler and prevent GUI/manual runs; hold
   the application's actual instance lock across the complete database,
   archive, configuration and fresh model snapshot. Recheck pending work.
2. Validate the fresh Redis RDB's format, CRC and SHA-256. A previously cached
   model or equal high-water revision numbers alone do not prove equivalence.
   Protect the expected digest and freshness/identity receipt independently
   from the transferred payload. Preserve a verified encrypted off-host copy.
3. Deliver the RDB to administrator-controlled private staging using a bounded,
   no-symlink, regular-file interface and authenticated receipt. Do not pass
   model data or credentials through argv, environment variables, or logs.
   Verify available disk, memory, image digest, Redis version and host time.
4. Create a unique labeled candidate volume. Verify it is new, empty and owned
   by this import; run isolated, network-disabled Redis containers with the
   pinned image. Keep the original production volume untouched. Load the
   verified RDB with AOF disabled, enable AOF, verify rewrite and fsync health,
   stop cleanly, restart with the exact intended production Redis configuration,
   and repeat health checks.
5. Compare the complete logical state and expiry behavior against a separate
   isolated reference loaded from the same RDB, as described below. Persist
   a sanitized receipt of success, without keys, values or message content.
6. Before publication, create and sync a root-owned journal recording old and
   candidate volume identities and operation state. The worker and every
   maintenance path that can start the stack must enforce a pending-migration
   marker. Publish the candidate with an explicitly validated, root-owned
   Compose volume binding; sync the binding and journal before clearing the
   marker. An interruption must leave the old volume and candidate intact and
   keep the worker blocked until the journal has been reconciled.
7. Preserve the original volume until recovery is verified. Before server-side
   mailbox/model mutations it may support rollback; afterwards rollback must
   carry the newest server database, model and archives back to a compatible
   owner. Starting a stale Mac snapshot would lose intervening state.

## Complete comparison and expiry

The comparator must be binary-safe and bounded, operate only on isolated
instances with no writers, scan all configured databases, deduplicate SCAN
results and detect missing or extra keys in both directions. Canonicalize each
supported value by type, including binary strings, ordered lists, unordered
sets and hashes, and sorted-set members and scores. Avoid emitting key names or
values. Streams and their consumer-group/pending metadata, module values,
functions or other state that cannot be represented completely must fail
closed until explicitly supported. Treat unsupported Redis versions and schema
changes as failures, not empty or successfully compared data.

Compare key expiration using absolute millisecond timestamps, and compare
Redis 7.4 hash-field expiration independently. Expiry continues during the
handover, so a key or field may disappear while scanning. The verifier must
record the comparison window, detect a deadline crossing that prevents a
stable comparison, and fail/retry instead of silently treating an unexplained
missing value as an expired one. Both servers must use a synchronized clock.
`DUMP` is an opaque serialization that omits key expiration, and the Redis
`DEBUG DIGEST` implementation does not capture all expiry and stream-group
metadata; neither is a complete semantic comparison.

At a read-only inspection on 30 October 2026, the live Mac model had roughly
21,267 keys, mostly hashes, and roughly 17,540 keys with expiry; the shortest
sampled remaining TTL was about 7.4 minutes. These are point-in-time counts,
not a fresh model snapshot or proof that a later cutover will see the same
data. Short expiries make an explicit comparison-window policy necessary.

## Acceptance tests before real use

- Synthetic RDB conversion and normal-configuration restart on an isolated
  native target, followed by a comparison of all data and expiration metadata.
- Binary keys and values, multiple databases, different internal encodings,
  hash-field expiries, wrong values/deadlines, absent and extra keys, and a
  deadline crossing during comparison. Reject unsupported types/metadata.
- Corrupt, wrong-origin, stale, truncated and oversized input; absent/invalid
  receipt; nonempty or mislabeled candidate volume; clock and storage failures.
- Interrupt each stage before and after publication; reboot with a pending
  journal; verify that all worker/helper starts remain blocked and recovery
  preserves both volumes. Confirm the old owner cannot resume concurrently.
- Restore the complete encrypted backup into a separately isolated target,
  validate SQLite, archive decryption and the real model, then perform fresh
  server authorization and a controlled dry run before any live protect run.

References: [Redis 7.4.9 debug digest implementation](https://raw.githubusercontent.com/redis/redis/7.4.9/src/debug.c),
[Redis DUMP](https://redis.io/docs/latest/commands/dump/),
[Redis hash-field expiration](https://redis.io/docs/latest/commands/hpexpiretime/).
