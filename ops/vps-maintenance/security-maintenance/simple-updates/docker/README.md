# Docker package maintenance

Use the [shared maintenance/recovery contract](../README.md),
[update policy](../../../README.md) and
[current deployment](../../../../../docs/maintainers/OPERATIONS.md).
[Evidence and archived detail](../../../../../docs/README.md) distinguish observed
no-update/rehearsal behavior from an actual package-version upgrade.

## Package and recovery contract

The updater covers Engine, CLI, containerd, Buildx and Compose from Docker's
stable signed APT repository. Scheduled updates select patches within each
installed upstream major/minor line, including Debian packaging revisions.
Newer major/minor lines are reported for manual review; available same-line
patches continue independently. A dependency plan cannot cross a Docker
component version line automatically.
Dependency-origin and repository-suite checks use the actually qualified Ubuntu
codename. Held targets, unsupported source formats, untrusted dependencies or
removal plans require inspection.

It downloads targets, persistently masks Guardian scheduling, verifies a fresh
coherent encrypted backup and unchanged worker fingerprint, then holds the
migration fence and journals intent. APT owns its frontend lock and installs the
complete pinned plan with `--no-remove`; a full inventory check catches a changed
dependency plan or unexpected action between simulation and execution.

Postflight verifies container identities/health, Redis persistence, authenticated
Rspamd, SSH and an actual Guardian pass before restoring timers. `OnFailure`,
boot recovery and later daily runs handle pending work. Before mutation,
recovery needs unchanged old versions/fence/health. After mutation, it requires
the complete pinned inventory, clean `dpkg --audit`, prior container identity
and its own marker before forward recovery. Incomplete/ambiguous state stays
fenced; package downgrade and old-model restore are not attempted.

Docker/containerd changes can interrupt other projects; their application health
is outside this updater's checks. The local SSH check still needs external
login verification after impact. Ubuntu owns required host reboot activation.

## Installation and triage

The root-controlled `/opt/vps-maintenance` tree must include this updater,
`worker_evidence.py` and its `security-maintenance/auto-updates/docker` support
modules. Keep the [shared reader/activation prerequisites](../ubuntu/README.md)
and boot recovery installed before enabling the timer.

```sh
journalctl -u vps-docker-update.service -u vps-docker-update-recover.service -n 100
sudo dpkg --audit
sudo docker version
sudo docker compose version
sudo docker ps -a --filter label=com.docker.compose.project=mail-guardian-pilot
```

Inspect pending ownership and active locks/processes before invoking
`sudo systemctl start vps-docker-update-recover.service`. Recovery validates the
actual state; an old journal is not permission to delete it.

Local fixture/mocked tests, from the project root:

```sh
python3 -m unittest discover -s ops/vps-maintenance/security-maintenance/simple-updates/docker -v
```


For a manually reviewed new component line, first inspect the signed candidate
and simulated dependency plan with `updater.py --check --allow-new-lines`.
After reviewing all affected component lines, run `updater.py --allow-new-lines`
through the same root-controlled path. This preserves backup, fencing, postflight
and forward recovery. The scheduled service never supplies this flag.
