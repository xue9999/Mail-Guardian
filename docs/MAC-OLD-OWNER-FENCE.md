# Mac old-owner fence for a Guardian server handover

> Historical design note. Statements such as “not deployed” describe the original design stage. For current maintenance, start with [the operations runbook](maintainers/OPERATIONS.md) and [release process](maintainers/RELEASING.md). Private audit paths are deliberately omitted.

Status: design only. No Mac scheduler, app, credential, mailbox or state was
changed for this document. The installed Mac version and older executable
copies do not implement a durable cross-host ownership protocol. A local file
lock or a disabled LaunchAgent alone is not a sufficient fence.

## Observed entry points and limits

At the 30 October 2026 inspection, the scheduler was the user LaunchAgent
`pl.o2.mail-guardian`, and the separate `pl.o2.mail-guardian-ui` LaunchAgent
started the GUI. Their definitions reside in `~/Library/LaunchAgents/`. The
service runner and live data reside in `~/Library/Application Support/O2 Mail
Guardian/`; the GUI invokes `~/.local/bin/o2-mail-guardian/guardian`. The
same executable directory contained additional older executable copies. These
observations must be refreshed immediately before handover.

The installed or historical code can take paths outside `guardian.lock`:
the GUI snapshot opens the database, service installation can re-enable
launchd, service-run starts the stack and updates health before the mailbox
lock, and Mac stack up/down is not covered by that lock. Redis, Rspamd and
Unbound can continue running after the LaunchAgents stop. Redis expiry and
other clients can change model state independently. Neither disabling one
LaunchAgent nor blocking one executable path addresses every path.

## Required ownership boundary

Before the server may mutate the mailbox, establish and test an independent
boundary that prevents the old Mac owner from authenticating or issuing IMAP
mutations, including already-open sessions. A separately revocable provider
credential per owner is a candidate **only if** the provider actually supports
it and revocation and session termination have been verified. A password
shared by both hosts does not provide independent revocation. Do not assume
that replacing or removing one Keychain item, renaming one executable, or
changing a user-owned directory's permissions blocks older copies or cached
secrets. An OS-enforced network boundary is another possible design, but its
coverage, persistence, effects on other mail clients, and recovery need
separate design and testing; none is currently implemented.

The owner has confirmed that the current Mac Guardian uses a separate o2 app
password. The preferred handover therefore uses a newly issued VPS app password
and revocation of only the old Guardian app credential, after the recovery and
server prerequisites pass. o2 documents separate per-program/device credentials,
but the actual effect on already-authenticated sessions still needs a harmless
read-only qualification. Keep the Mac credential active while it remains owner;
do not reuse it on the VPS or rotate the unrelated archive encryption identity.
[Provider documentation](https://pomoc.o2.pl/wpkonto/hasla-do-aplikacji-zewnetrznej)

This boundary must remain effective across Mac wake, login and reboot, and
across manual and GUI launches. A local user or administrator can deliberately
reverse local controls; the operational threat model must state what is
prevented and who can remove the fence. If independent ownership cannot be
established, do not perform the modifying server cutover.

## Proposed reversible sequence

This is an acceptance plan, not an executable command sequence. It requires a
tested coordinator and a recovery mechanism before touching the active owner.

1. Record versions, hashes, current configuration and identities, LaunchAgent
   definitions and disabled/loaded states, running processes, Docker project
   resources and current model/database health. Preserve the original archive
   identity and credentials securely; never print them or pass them in argv.
   Confirm a tested off-host recovery copy and a concrete rollback operator.
2. Persistently disable both Guardian LaunchAgents in the correct user domain,
   close the GUI and apply the tested local controls that prevent ordinary
   reinstallation or manual invocation during the handover. These controls are
   provisional until the independent mailbox fence is in place. Wait for any
   already-running scan to complete before unloading its job: terminating a run
   mid-MOVE may create an unresolved operation. Confirm disabled state and
   absence after a login/reboot test. Merely retaining the plist is not evidence
   that the agent will remain disabled; conversely removing it loses recovery
   configuration unless a verified copy exists.
3. Enumerate relevant processes, child processes, open database/WAL files and
   established IMAP sessions. If any cannot be accounted for, stop. Recheck
   database reconciliation and pending work after quiescence.
4. Establish the chosen external mailbox fence and confirm it prevents a new
   old-owner authenticated session; account for existing sessions explicitly.
   Coordinate the ordering with separately provisioned server credentials so
   this step does not accidentally lock out both owners. No credential should
   be revoked until its recovery, session behavior and impact on the user's
   other mail clients are understood. Recheck quiescence after applying the
   boundary; stop if an old-owner session or pending operation is detected.
5. Establish an exclusive capture boundary for SQLite, archive files and
   Redis. Stop or isolate Rspamd and every possible Redis writer, account for
   expiry, hold the appropriate locks, and take a fresh validated Redis RDB and
   a SQLite online snapshot with all committed WAL data. Verify every referenced
   encrypted archive using its original identity and recorded message hash.
   A run lock alone is not sufficient proof of this boundary.
6. Seal and independently restore the complete checkpoint, verify it, and
   transfer it to a clean server staging area. No server mutation until model
   continuity, immutable source provenance, fresh authorization, failure
   recovery, and publication have all been tested. Record an ownership receipt
   that identifies the checkpoint and the intended owner, without secrets.
7. Keep the Mac externally fenced through the server dry-run and acceptance.
   If no server mutation has happened, recovery may use the final Mac snapshot
   after the server has been fenced and de-authorized. Once server operations
   change mail or model, never restart the stale Mac checkpoint: first stop and
   fence the server, transfer and validate the latest compatible server state,
   and only then restore the Mac's access and scheduler. Recovery itself must
   be rehearsed using isolated data.

## Engineering still needed

- A coordinator that can prove quiescence across all relevant Mac entry points,
  not only the ordinary run lock, and a durable, externally enforced mailbox
  owner boundary with tested credential/session semantics.
- Snapshot orchestration that captures the SQLite WAL, referenced archives and
  Redis model as one consistent state while preventing or detecting writers.
- A tested reversible state machine with durable checkpoints, interruption
  recovery, current-state rollback, identity binding and negative tests for
  old binaries, manual launches, wake/reboot and worker overlap.
- An isolated full restore and a server publication path with durable fencing;
  the source-only Linux cooperative fence does not govern the installed older
  Mac binaries or freeze the Mac containers.
