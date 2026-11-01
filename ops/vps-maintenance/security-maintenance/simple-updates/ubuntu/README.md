# Ubuntu package and release maintenance

Follow the [shared maintenance/recovery contract](../README.md) and
[update policy](../../../README.md). Installed versions, qualification
limits and current release blockers belong in the
[deployment record](../../../../../docs/maintainers/OPERATIONS.md);
[evidence and archived detail](../../../../../docs/README.md) retain the rehearsals.

## Package and activation contract

The updater accepts signed Ubuntu stable release, `-updates` and `-security`
pockets, including new package lines and kernel ABI dependencies. Docker packages
have their own owner. It rejects held targets, removals and unknown/non-stable
dependency origins, pins the complete simulated APT plan, then checks the full
installed inventory. An unexpected package/dependency action stays fenced.

Before mutation, it stops and masks scheduling, waits for active worker/backup
activity and retries to settle, verifies a fresh coherent encrypted backup and
unchanged run/heartbeat fingerprint, then holds Guardian's migration fence. Worker evidence
is read entirely as `mg-pilot`; inactive systemd InvocationIDs are insufficient.

Automatic needrestart hooks are suspended during package-manager work. The
root-controlled `/etc/needrestart/conf.d/99-vps-guardian-updates.conf` excludes
maintenance owners and Guardian units from incidental restart. Controlled
`needrestart -r a` runs while fenced. Missing/modified exclusions, incomplete
activation, `/run/reboot-required` or a different target kernel select the
journalled reboot fallback. A no-update check does not reboot just because
needrestart is absent. Kernel links are checked root-owned paths resolving
inside `/boot` (`/boot/vmlinuz`, with `/vmlinuz` fallback).

Recovery requires clean dpkg state and the complete expected inventory under the
APT frontend lock. A requested reboot needs a changed boot ID and the expected
running kernel. Marker ownership, persistence, scanner authentication, SSH and a
fresh successful Guardian pass must verify before scheduling resumes. There is
no package downgrade or old-model restoration; uncertainty remains fenced.

## Prerequisites and commands

- Install root-controlled helpers under `/opt/vps-maintenance`, enable boot
  recovery before ordinary updater jobs, and retain cross-updater pending guards.
- The shared `docker/worker_evidence.py` reader must be mode 0644 with ancestors
  traversable by `mg-pilot`; private updater state stays 0700.
- Disable legacy unattended **installation**, keeping metadata refresh, so it
  cannot bypass the coherent backup/fence. The shared flock cannot govern it.

```sh
sudo python3 -I /opt/vps-maintenance/security-maintenance/simple-updates/ubuntu/updater.py --check
sudo systemctl start vps-ubuntu-update-recover.service
```

`--check` refreshes APT metadata and reports candidates/activation without package
installation, recovery, fencing or reboot. Start recovery only after inspecting
the owning journal and actual state. `--rehearse` is a deliberate real reboot:
it refuses package candidates, takes a fresh backup/fence and exercises ordinary
boot recovery. It is not an ordinary status check.

## Distribution releases

The separate release-check timer compares final stable publication with the
ordinary official upgrade offering. `Prompt=normal` permits stable non-LTS
upgrades; publication alone does not establish an available in-place path.
The package updater never runs `do-release-upgrade` or forces a development
upgrade. Qualify the offered supported path and current Guardian state before
that separate migration. The deployment record holds any concrete blocker.

Local tests from the project root (fixtures do not prove a real APT upgrade):

```sh
python3 -m unittest discover -s ops/vps-maintenance/security-maintenance/simple-updates/ubuntu -v
```
