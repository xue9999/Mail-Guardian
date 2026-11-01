# Guardian VPS maintenance

This directory publishes the reference server's maintenance implementation and
its synthetic tests. It is an operations profile for a single `pilot` instance,
not a general-purpose installer. Copying this directory or checking out the
repository does not enable services. Root updaters can stop/restart Guardian or
reboot the host: read this guide and inspect the target before executing them.

The application/runtime lives elsewhere in this repository. The overview is
[architecture](../../docs/maintainers/ARCHITECTURE.md); health, monitoring,
backup and restore are in [operations](../../docs/maintainers/OPERATIONS.md).
[Releasing](../../docs/maintainers/RELEASING.md) separates source publication,
dependency maintenance and reviewed application-code promotion.

## Approved reference policy

Check daily and automatically install compatible stable patches within approved
Docker, container, Guardian module and compiler major/minor lines. Include
ordinary bug fixes, not only security updates. Detect newer major/minor lines
and record them for manual compatibility review; compatible patches continue
independently. Ubuntu package/kernel updates within the installed distribution,
including new kernel ABIs, remain automatic; a distribution upgrade is manual.
A blocked newer line needs a concrete reason and next action.

Before an update can interrupt/migrate Guardian, capture a coherent current
recovery point including the trained model. After impact verify SSH, supporting
services and an actual Guardian run. Keep the old Mac worker retired and
permanent deletion disabled. Recover with the newest compatible VPS state.
Other operators should record any different approved policy explicitly.

## Entrypoints and daily schedule

All times below are **UTC**, with small timer jitter. The daily encrypted
application backup at 03:07 UTC precedes maintenance throughout the year.
A Warsaw-local fixed time would change its UTC relationship at DST transitions.

| Owner | Time | Source | Durable state |
| --- | --- | --- | --- |
| Ubuntu packages/kernel and activation | 04:30 | `security-maintenance/simple-updates/ubuntu/updater.py` | `/var/lib/vps-ubuntu-update/pending.json` |
| Docker Engine/CLI/containerd/Buildx/Compose | 05:00 | `security-maintenance/simple-updates/docker/updater.py` | `/var/lib/vps-docker-simple-update/pending.json` |
| Redis/Rspamd/Unbound image pins | 05:30 | `security-maintenance/simple-updates/guardian_images.py` | `/var/lib/mail-guardian-admin/auto-image-update/transaction.json` |
| Guardian dependencies/compiler and app-source discovery | 06:00 | `security-maintenance/simple-updates/application/updater.py` | `/var/lib/mail-guardian-application-update/pending.json` |
| Ubuntu release discovery, no distribution install | 06:45 | `security-maintenance/simple-updates/ubuntu/release_check.py` | Service journal |
| Docker/image and Rspamd/Unbound advisory review | 06:50 | `security-maintenance/vps_security_review.py` | Service journal, findings separate from installation |

Unit files are alongside the corresponding implementation. Their ordinary
services and recovery services have different purposes. A skipped shared-lock
attempt can exit successfully: inspect its journal rather than counting it as a
completed discovery/upgrade. Persistent catch-up and staggered times do not
eliminate the need for the shared lock. Repeated contention requires review.

## Dependency map: what must be installed together

The deployed root-controlled tree is `/opt/vps-maintenance/`; its child
`security-maintenance` must keep the relative layout published here.

- The current Docker updater imports `auto-updates/docker/engine.py`, which
  imports `docker_auto_update.py` and `transaction_journal.py`. These are shared
  production primitives. The old command-line coordinator in that directory
  remains experimental; it is not the scheduled entrypoint.
- Ubuntu imports the current Docker updater and shared worker-evidence reader.
- Images use `image_discovery.py` and `fenced_backup.py` from `simple-updates`.
- Application maintenance uses `builder.py`, `source_snapshot.py` and the current
  image engine for coherent capture, switch and forward recovery.
- Advisory helpers in `auto-updates/guardian` are read-only checkers. The former
  image/VM/lab deployment coordinators are not published or installed by this
  profile; do not infer that every old `auto-updates` CLI is production approved.
- Runtime backup and maintenance dispatchers are built from `deploy/linux` at
  repository root, outside this tree. Their private configuration is provisioned
  separately and must match the active manifested release.

Do not remove an imported “legacy” library just because its parent directory is
named `auto-updates`. Keep the shared semantics and its tests when extracting a
smaller library. `make check-maintenance` runs each suite independently to avoid
Python module-name collisions.

## Transaction and recovery contract

Mutating coordinators hold `/run/mail-guardian-auto-update.lock` and defer to a
foreign pending transaction. Before impact they stop/mask scheduling as required,
wait for active worker/backup processes and retries, acquire real Guardian and
maintenance fences, preserve current coherent state and journal intent durably.
Scanner writes are quiesced for model/database capture. Package plans and
candidate artifacts are verified, not inferred from a version string.

Postflight checks actual supporting-service identities/health, Redis persistence,
authenticated scanner operation, SSH and a real Guardian pass. Some package
paths also require a new SQLite run/heartbeat fingerprint, read as `mg-pilot`.
An inactive oneshot InvocationID is not persistent worker evidence. A loopback
SSH banner check still needs a fresh external authenticated login after impact.

Recovery units run after failure/boot and later maintenance attempts inspect
pending work. They validate actual package/application and marker ownership.
Ambiguity stays fenced. Never delete a lock file held by another process, clear
a marker for age, downgrade the trained model, or restore pre-migration Mac data.
Permanent deletion remains disabled.

## Inspect before acting

Read-only status:

```sh
systemctl list-timers --all vps-ubuntu-update.timer vps-docker-update.timer \
  guardian-image-update.timer guardian-application-update.timer
systemctl --failed
sudo journalctl -u vps-ubuntu-update.service -u vps-docker-update.service \
  -u guardian-image-update.service -u guardian-application-update.service -n 100
```

`--check` for Ubuntu/Docker can refresh metadata and report candidates without
installation. The application's `--check` performs source discovery and is not a
build/activation test. `--qualify-only` can build in the isolated native sandbox
without installing a changed candidate. Inspect each command's help/source and
owning subguide: similar flags do not imply identical behavior.

Manual new-line review uses the explicit `--allow-new-lines` paths documented
in the [Ubuntu](security-maintenance/simple-updates/ubuntu/README.md),
[Docker](security-maintenance/simple-updates/docker/README.md), and
[application](security-maintenance/simple-updates/application/README.md) guides.
For images, inspect unrestricted discovery before manually allowing new lines.
Never add a manual-review flag to a scheduled service.

## Installation and changes to this profile

Installation is a deliberate administrator operation, not `pip install` or a
repository hook. Stage a reviewed source tree root-owned, preserve its relative
paths and exact hashes, and verify all imported modules. Install/check the
recovery units and required needrestart/APT coordination before enabling the
ordinary timers. The `worker_evidence.py` reader and its ancestors must be
traversable by `mg-pilot`; private updater state remains root-only.

The reference profile disables legacy unattended APT **installation** while
retaining signed metadata refresh, because the Guardian-aware owner coordinates
backups/restarts/reboots. Enabling stock unattended installation concurrently
would bypass that fence. A future stock-tools replacement must preserve the
contract above, including approved version lines and current model recovery.

Additional libexec mappings for advisory review are:

| Installed helper | Source in `security-maintenance/` |
| --- | --- |
| `vps-security-review` | `vps_security_review.py` |
| `vps-docker-security-check` | `docker_security_check.py` |
| `vps-guardian-image-candidates` | `auto-updates/guardian/image_candidates.py` |
| `vps-rspamd-advisory-check` | `auto-updates/guardian/rspamd_advisory_check.py` |
| `vps-unbound-advisory-check` | `auto-updates/guardian/unbound_advisory_check.py` |

Root helpers must be installed with root-controlled ancestors; do not make them
writable to the mail user to solve a permission failure. Keep backups/decryption
keys and production state outside this source tree. There is no public/private
repo synchronization daemon: publication alone does not change installed code.
