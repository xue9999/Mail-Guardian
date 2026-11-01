# VPS-1 software maintenance

Use the [update policy](../../README.md) for the standing rule,
[current deployment](../../../../docs/maintainers/OPERATIONS.md) for installed
versions and acceptance, and [documentation/evidence index](../../../../docs/README.md)
for validation records and archived guides. Detection, qualification and an
installed running result are separate evidence.

| Coverage | Daily owner | Durable transaction / detail |
| --- | --- | --- |
| Ubuntu packages and supported kernel | `vps-ubuntu-update.timer` | `/var/lib/vps-ubuntu-update/pending.json`; [Ubuntu guide](ubuntu/README.md) |
| Stable Ubuntu distribution releases | `vps-ubuntu-release-check.timer` | Detection only, output in the service journal; publication and an offered upgrade are separate |
| Docker Engine/CLI, containerd, Buildx, Compose | `vps-docker-update.timer` | `/var/lib/vps-docker-simple-update/pending.json`; [Docker guide](docker/README.md) |
| Qualified Redis/Rspamd/Unbound publisher image pins, including changed digests | `guardian-image-update.timer` | `/var/lib/mail-guardian-admin/auto-image-update/transaction.json` |
| Guardian compiler/dependencies; app-source discovery | `guardian-application-update.timer` | `/var/lib/mail-guardian-application-update/pending.json`; [application guide](application/README.md) |

The jobs run daily on the VPS independently of the Mac and Codex. Automatic
Docker/image/module/compiler changes stay in the approved major/minor lines.
Newer lines are reported for manual review, while compatible patches proceed.
Ubuntu packages/kernel ABIs within the installed distribution remain automatic.
The daily UTC schedule is Ubuntu 04:30, Docker 05:00, images 05:30, application
06:00, OS-release discovery 06:45 and advisory review 06:50, with small jitter.
In Warsaw this is one hour later in winter and two hours later in summer; the
03:07 UTC backup remains before maintenance throughout the year. New Guardian application code requires a
reviewed Linux-compatible source generation; dependency maintenance continues
from its approved private baseline.

## Shared safeguards and recovery

All mutating jobs share `/run/mail-guardian-auto-update.lock` and defer to another
owner's pending transaction. Before service impact they preserve a coherent
current recovery point, including the trained model, and fence scheduling with
persistent timer masks/disablement, real Guardian locks and an owned marker.
Postflight checks supporting services, Redis persistence, SSH and an actual
Guardian pass. Ubuntu/Docker additionally prove a fresh SQLite run and matching
heartbeat, read as `mg-pilot`. An inactive oneshot is normal between passes; its
collected InvocationID is not persistent worker proof.

Recovery goes forward with the newest compatible VPS state. Ambiguous state
stays fenced. Inspect the owning journal, marker ownership, package/application
state and active processes/locks before intervening; never remove a marker or
journal merely because it is old. Permanent deletion stays disabled and the Mac
worker stays retired. After a reboot, also verify a fresh remote SSH session:
a local SSH banner check is not an external authenticated-login test.

Legacy unattended APT installation is disabled; signed metadata refresh remains
enabled. The Guardian-aware coordinator owns installation and required reboot
activation. Unmanaged APT clients are outside the shared flock. Backup checksums
are not independent restore proof; accepted restore evidence is in the deployment
record. Independent Guardian health monitoring uses the separately installed
`mail-guardian-observe@pilot.timer`; see the operating guide for acceptance and
notification-channel limits. The Mac's
encrypted-backup pull is separate and depends on that Mac being available.

## Operator checks

On the VPS:

```sh
systemctl list-timers --all vps-ubuntu-update.timer vps-ubuntu-release-check.timer \
  vps-docker-update.timer guardian-image-update.timer guardian-application-update.timer
systemctl --failed
journalctl -u 'vps-*-update*.service' -u vps-ubuntu-release-check.service \
  -u 'guardian-*-update*.service' -n 100
```

Use the owning subguide for prerequisite, inspection and recovery commands.
[Guardian-VPS.command](../../../../tools/remote-control/status.py) provides ordinary status from
this Mac without falling back to the retired local worker.


For manually reviewed image version lines, inspect unrestricted discovery with
`image_discovery.py --compose /etc/mail-guardian/pilot/deploy/compose.yaml`.
After reviewing every proposed line, `guardian_images.py --allow-new-lines`
uses the same image qualification, current-model check, coherent backup and
postflight as scheduled patches. Never put this flag in a timer/service.
Digest pins remain in Compose; a moving minor tag is not the recovery identity.
