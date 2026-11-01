# Candidate snapshot capture: unresolved requirements

> Historical design note. Statements such as “not deployed” describe the original design stage. For current maintenance, start with [the operations runbook](maintainers/OPERATIONS.md) and [release process](maintainers/RELEASING.md). Private audit paths are deliberately omitted.

There is no production capture orchestrator yet. The existing SQLite snapshot,
archive relocation, authorization revocation, encrypted bundle and Redis
rehearsal are separate primitives. A synthetic round-trip test is not evidence
that a real cross-component checkpoint is coherent or recoverable.

The continuation adds `SnapshotDatabaseBounded`, strict offline inspection,
clone-only preparation of abandoned superseded cursors, `ExportRedisFresh` and
a serialized local receipt catalog. The packaged `guardian-recovery` command
inspects/prepares database-only copies; it does not implement this operational
capture boundary. Actual-copy tests preserve original bytes and logical history.

Before implementing an operational capture, establish these conditions:

1. **Prove and hold the owner boundary.** Quiesce and fence the Mac launchd,
   GUI, old and alternate executables, stack operations and existing mailbox
   sessions, and retain the relevant locks until capture finishes. The Linux
   migration fence is cooperative and does not fence the Mac or old binaries.
   Redis/Rspamd and external clients need their own write isolation. A caller's
   `Check()` callback is an assertion, not proof that any of these conditions
   hold. See `MAC-OLD-OWNER-FENCE.md` and `deploy/linux/MIGRATION_FENCE.md`.
2. **Capture a fresh model, not a cached backup.** The existing `BackupRedis`
   path can reuse a checkpoint for up to 12 hours. Force a fresh export, verify
   that the exporting process completed successfully, bound output and runtime,
   and validate the captured RDB independently. Its CRC and header do not prove
   full RDB structure, freshness, model contents or revision continuity. Compare
   a restored model and its absolute key and hash-field expiries as described in
   `REDIS-MODEL-HANDOVER-DESIGN.md`.
3. **Enforce resource limits throughout capture.** Bound archive counts and
   bytes, Redis export bytes, SQLite output and row counts, temporary disk use,
   and elapsed time, including blocked dependencies. Use
   `SnapshotDatabaseBounded` for a pinned read view and an enforced main-image
   page limit; the legacy `SnapshotDatabase` wrapper has no practical small
   image limit. Journal/WAL/temporary overhead is outside that image bound, and
   raw backup steps are not hard-interruptible by context. Enforce total staging
   use and hard deadlines independently. Reserve free space on the
   actual staging filesystem. On this VPS, `/tmp` was too small for the recovery
   reserve; a private disk-backed `/var/tmp` fixture passed.
4. **Validate the complete source state.** Recheck unresolved move, restore,
   learning, ambiguous and error states, pending model-checkpoint markers,
   schema compatibility and other operation-specific invariants after fencing.
   Preserve the actual mailbox and folder identity. Copy every referenced
   archive through a safe no-symlink path, decrypt it with the original archive
   identity and verify its recorded raw hash. Ensure referenced files cannot
   change during capture; an unchanged size or timestamp alone is insufficient.
5. **Make interrupted stages unmistakable.** Capture into a new private,
   exclusively owned staging area with a durable incomplete marker before
   sensitive intermediate data is created. Publish a completion record only
   after all checks and filesystem syncs succeed. A crash can leave a partial
   stage containing a database with inherited authorization; no reader may
   consume it as a completed or importable capture. Recovery must safely inspect
   and clean only the stage it owns, without following symlinks or overwriting
   an existing backup. Before an imported database can run, revoke inherited
   deployment and dry-run authorization and reset the protect window using a
   trusted current clock; a stale caller-supplied timestamp is not sufficient.
6. **Produce and exercise a complete independent backup.** Include the
   configuration, current SQLite journal, verified archives, original archive
   identity, model, compatible software and metadata. Securely provision and
   independently recover keys; authenticate the backup receipt, enforce
   durable freshness/watermark policy, and perform an isolated full restore.
   The current bundle and signed receipt are primitives only, and an unsigned
   manifest or caller-supplied digest does not establish provenance or recency.

The implementation must fail closed if any prerequisite is unavailable. Tests
must cover interruption, cancellation, output bounds, symlink/path substitution,
stale or corrupt export, missing original key, archive mismatch, unresolved
operations, destination collision, source changes, and concurrent ownership.
Only after isolated recovery and current-state rollback are demonstrated should
the workflow be considered for a controlled real-mailbox handover.
