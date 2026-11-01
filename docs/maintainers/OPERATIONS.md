# Operations and recovery

Identify the active mailbox owner before touching a deployment. The reference
profile is one Linux `pilot` instance with the old Mac worker retired. Substitute
an explicitly provisioned instance only where the helper supports it; the
reference update coordinators are intentionally fixed to `pilot`.

## First five minutes of a handoff

1. Read this guide, [maintenance](../../ops/vps-maintenance/README.md), and the
   deployment's private access/key-custody record. GitHub contains no host address,
   app password, decryption key or authoritative live-health record.
2. Establish a fresh authenticated SSH session using the operator's verified
   host-key configuration. Do not disable host-key checking.
3. Read state before restarting anything. A failed observer may be reporting a
   real failed mail pass rather than being broken itself.
4. Identify any pending update journal, migration marker and active owner/locks.
   Do not delete an old marker or start a second worker to “unstick” mail.
5. If service impact is required, capture current coherent state and use the
   owning recovery/update mechanism. Verify an actual run afterwards.

## Paths and identities

| Purpose | Reference path or identity |
| --- | --- |
| Current immutable application release | `/opt/mail-guardian/current` symlink |
| Release generations | `/opt/mail-guardian/releases/` |
| Instance config and credentials | `/etc/mail-guardian/pilot/` |
| SQLite, encrypted message archives and heartbeat | `/var/lib/mail-guardian/pilot/` |
| Encrypted application backups | `/var/backups/mail-guardian/pilot/` |
| Mail user | `mg-pilot`, without Docker-group access |
| Root runtime dispatcher | `/usr/local/libexec/mail-guardian-maintenance` |
| Backup/observer helpers | `/usr/local/libexec/mail-guardian-backup`, `mail-guardian-observe` |
| Maintenance source installation | `/opt/vps-maintenance/security-maintenance/` |
| Private approved application source | `/var/lib/mail-guardian-application-update/sources/` |

Credentials are root-provisioned and delivered through systemd `LoadCredential`.
Never print the configuration/credential directories as a diagnostic shortcut.
Use the [hidden-input provisioning tools](../../tools/provisioning/README.md).

## Read health safely

From a configured control Mac, `python3 -I tools/remote-control/status.py` uses
pinned SSH and reads server state; failure never starts a local worker. See
[remote status](../../tools/remote-control/README.md). On the server:

```sh
systemctl --failed
systemctl list-timers --all mail-guardian@pilot.timer \
  mail-guardian-backup@pilot.timer mail-guardian-observe@pilot.timer
systemctl show mail-guardian@pilot.service -p Result -p ExecMainExitTimestamp
sudo journalctl -u mail-guardian@pilot.service -n 50 --no-pager
sudo docker ps --format 'table {{.Names}}\t{{.Status}}'
```

Read logs privately and redact before sharing. Confirm the actual latest SQLite
run agrees with `service-health.json`, has zero errors and no pending/blocked
operations, reconciliation cursors or model recovery requirement. A service exit
code on its own is insufficient. Do not use a direct SQLite write to change
health, authorization, checkpoint flags or message locations.

The reference profile polls mail every five minutes. The fresh package's default
timer is fifteen minutes; the operator override is in
`ops/vps-maintenance/security-maintenance/mail-guardian-pilot.timer.conf`.
Mac local scheduling is separate. Keep a one-week watch after interval changes
for login refusals, unexpected EOF or evidence of throttling. A missing MOVE UID
mapping is a different error class and does not by itself prove throttling.

## Monitoring and delivery

`deploy/linux/observe.py` runs as the mail user, verifies database/heartbeat and
identity, and sends a status signal using a root-owned systemd credential. Its
ping URL grants access and must never enter Git, process arguments or logs.
Provision it with the hidden-input helper and use the optional units separately
from initial worker installation.

Reference settings are a five-minute external period, ten-minute grace and a
five-minute observer offset two minutes after the worker boundary. Host/observer
silence can therefore be detected after roughly fifteen minutes. A stopped
worker with a still-running observer is detected within roughly twenty-six
minutes because accepted worker success expires. These are detection bounds;
network and owner-notification delivery add separate uncertainty.

Use a destination independent of the monitored mailbox. Keep an email to that
mailbox only as an additional channel. Test Down and recovery notifications on
the actual owner's device. An HTTP success in a journal is not proof the owner
received the alert. Record false alerts separately from genuine failed runs.
The original email drill does not establish independent phone delivery or
fourteen-day continuity.

## Mail safety and common incidents

| Symptom | Inspect | Safe response |
| --- | --- | --- |
| Missing destination UID after MOVE | Last run, pending record and reconciliation events | Let exact-content reconciliation settle it; never repeat MOVE manually just because the reply was incomplete. |
| Observer says unhealthy | Actual latest run, identity and unresolved/model state | Fix the underlying condition; do not force a success ping. |
| Timer enabled, no fresh mail run | Worker journal, locks, pending update, credential delivery | Determine the owner/blocker before restarting. |
| Rspamd/Redis healthy, Guardian failing | Scanner authentication, persistence, model checkpoint, IMAP errors | Container health alone cannot clear the failure. |
| Update fenced the worker | Owning durable journal and actual package/release state | Use forward recovery after inspection; keep the fence while state is ambiguous. |
| Restore/worker uses stale Mac data | Ownership and latest compatible VPS generation | Stop the stale path; recover current VPS state deliberately. |

Provider Spam may have its own short retention period. Quarantine and review
must be dedicated folders, not aliases for provider Spam. Inspect the provider's
sorting configuration and every folder the worker must watch. Do not infer
coverage from a folder name or from the number of “observed” database records.

A weekly skim of quarantine/review is useful initially. Move a confirmed false
positive to `AI-Naucz-wazne` for explicit correction and return-to-inbox handling.
A direct move to Inbox does not supply that training signal. Preserve
rescue authentication; a sender's display name or contact entry is not a bypass.

## Backup and recovery

The reference daily backup runs at 03:07 UTC with small jitter, before daily
maintenance. It captures a coherent database, archives, configuration,
credentials, release/approved source and a fresh Redis model. Update activation
also captures current state while scheduling and scanner writes are fenced;
a daily backup alone is not enough for a later service-impacting update.

Keep the backup decryption identity off the server, with independent recoverable
custody. Encrypted files and their `.age.sha256` receipts can be pulled to the
control Mac with `python3 -I tools/backup/fetch_latest.py`; see
[the pull contract](../../tools/backup/README.md). A sleeping/offline Mac cannot
prove timely off-server custody and may skip intermediate generations.

For a restore, use [the exact backup format and tools](../../deploy/linux/BACKUP.md):

1. Fence the current worker and establish exclusive ownership. Stopping a timer
   does not stop an in-flight service or revoke a provider credential.
2. Select the newest compatible VPS generation with the matching release,
   configuration, archive identities and trained model. Never use the stale
   pre-migration Mac as an automatic fallback.
3. Decrypt into a new private isolated target. Check database integrity and
   readiness, archive hashes, release/source manifests and model recovery.
4. Follow the configuration mapping, destination binding and authorization
   procedure. A restored database does not carry permission to operate a
   different host/mailbox. Run the required fresh dry run before real work.
5. Verify authenticated external SSH, scanner authentication, DNS, Redis
   persistence, model consistency and a real successful Guardian run. Only then
   resume the normal timer and verify monitoring/notifications.

A checksum proves transfer identity, not successful decryption, restored model
behavior or whole-host recovery. Application bundles are not Ubuntu/SSH host
images. Retain a separately verified access/console recovery route.

## Leave an actionable handoff

Record UTC and local timestamps, commit/tag and exact immutable release,
installed/running versions, mailbox owner, timers, last real run, pending work,
recovery generation and off-server verification. Include the concrete blocker
and next action for any newer version line. Keep private evidence outside Git.
Separate detection, candidate qualification, activation, reboot/restore proof,
notification receipt and sustained observation; none substitutes for the others.
