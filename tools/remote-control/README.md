# VPS-1 status and experimental remote-control protocol

## Installed status shortcut

On 31 October 2026, `Guardian-VPS.command` in the VPS-1 project became the
ordinary Mac status shortcut. It invokes `status.py`, which reads the current
server over the existing pinned administrative SSH connection. It verifies the
VPS deployment binding, actual completed mailbox run and heartbeat, active
timer, policy, unresolved operations, model-recovery flags and latest completed
encrypted-backup receipt. An inactive successful oneshot between scheduled
passes is normal. A connection or validation failure reports disconnected and
never starts the retired Mac worker.

This status shortcut does not start, pause, update or restore Guardian, and it
does not integrate the Mac GUI. Its SSH access uses the existing administrative
identity; the proposed separate restricted status account below has not been
provisioned. The backup receipt displayed by status is completion metadata,
not a fresh checksum calculation or independent restore proof.

## Experimental dispatcher protocol

The separate source-only dispatcher prototype reports the systemd service and timer state for the
single installed Linux instance. It does **not** configure a mailbox, report
mailbox health or last successful run, start or pause scheduling, recover mail,
integrate with the Mac GUI, or fall back to the Mac worker. It is not installed
by the Linux package and has not been accepted as a production remote-control
path.

The client requires an explicit host, SSH user, private key, pinned known-hosts
file, instance and expected server identifier. SSH runs with its user and system
configuration disabled, no agent, forwards or TTY, and strict host-key checking.
The command sent to SSH is fixed; a bounded JSON request carries the instance
and a random nonce. Requests and responses have deadlines and size limits.
The client checks the protocol, nonce, instance and expected server identifier;
connection or validation failure is reported as disconnected and never starts
a local worker. Unit state alone cannot establish whether filtering works.

The server identifier is SHA-256 of the domain-separated machine ID and
instance. It is an identification check, not an authentication credential:
machine IDs can be copied. Authentication depends on an independently
verified SSH host key. Enroll both the pinned host key and expected server ID
using an already authenticated administrative channel before use; never accept
either from the same unauthenticated status response.

Before deployment, create a separate least-privilege SSH account and key, with
only a root-owned authorized-keys file and a forced, root-owned fixed dispatcher
using OpenSSH `restrict`. Disable other authentication and forwarding for that
account; do not reuse the normal `ubuntu` administrative key as evidence of
limited access. Ensure the dispatcher and all its parent directories are owned
by root and not writable by the account. Verify real SSH host-key rejection,
forced-command enforcement, process deadlines and systemd access on a disposable
target. This repository does not yet implement or test that provisioning.

Run the isolated protocol and bounded-I/O tests with:

```sh
cd tools/remote-control
python3 -m unittest -v test_remote.py
```
