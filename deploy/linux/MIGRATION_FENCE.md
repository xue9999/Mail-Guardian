# Migration fence: development contract

The new source code provides a local fencing primitive for future migration and
recovery. It is not a migration command or an authorization to move a mailbox.
It is not present in older installed releases. Updating a live installation to
this contract requires a separately reviewed transition that stops and fences
every old worker and helper before the new release is used.

`/etc/mail-guardian/<instance>/migration.lock` is a root-owned regular file,
mode 0640, group `mg-<instance>`, under the root-owned instance directory. The
directory and lock inode must never be replaced or unlinked during operation.
All supported Linux runtime commands hold a nonblocking shared flock for their
whole command, including operations that appear read-only but can open SQLite.
The maintenance helper independently holds a shared flock throughout dispatch,
before acquiring its separate maintenance lock. Both fail closed if the lock is
missing or unsafe, if the exclusive flock is held, or if the persistent
`migration-pending` marker exists (including a dangling symlink).

An administrator performing a future migration must stop and disable scheduling,
fence the Mac and any old binaries, then obtain and retain the exclusive flock
on that exact inode before publishing the root-owned marker. Keep the exclusive
lock across every publication and recovery operation; atomically write and
fsync the marker and its directory before changes. The instance directory and
lock must not be swapped: replace only individually validated files or pointers.
Remove the marker only after reconciliation has verified a complete consistent
state, then fsync the containing directory before releasing the exclusive lock.
No worker-callable helper operation can clear the marker.

The installer also takes a root-only global provisioning lock under `/run` so
that two fresh installs cannot both proceed before an instance fence exists.
Its `--check` may create this otherwise empty runtime lock file. The first
installer creates the instance inode once; subsequent provisioning takes the
exclusive fence and validates its identity and permissions. An older installed
instance lacking this file is rejected rather than upgraded in place by the
initial installer. Interruption, crash recovery, model-volume publication and
an administrator-only reconciliation tool remain to be implemented and tested.
An administrator with unrestricted root can bypass these controls. The fence
does not prevent a worker on another host or a binary predating the fence from
accessing the mailbox; those owners require separate fencing.
In particular, the current Mac API, service installation, heartbeat and stack
operations do not all take its mailbox run lock; holding that lock alone does
not establish a quiescent Mac snapshot. Redis and Rspamd containers do not hold
the fence themselves; migration must separately quiesce or isolate external
clients and account for Redis expiry and persistence before claiming a
consistent model checkpoint.
