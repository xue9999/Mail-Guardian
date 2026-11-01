# Linux deployment: Ubuntu 24.04, 26.04 and 26.10 amd64

The source package accepts one private Ubuntu 24.04, 26.04 or 26.10 amd64 host,
with systemd, Docker Engine and Compose already installed. Initial provisioning
runs offline: it does not purchase hosting, install system packages, import a
live mailbox or enable the timer. The runtime accepts protect and active
policies with permanent deletion disabled. Active mailbox work requires the
normal protection-history, filter-quality and destination dry-run checks.
Host prerequisites and deployment acceptance are separate: scheduling,
network exposure, model continuity, recovery and an actual mailbox run must
also be verified on the selected target.

The reference deployment uses Ubuntu 26.04. The worker is the sole mailbox
owner; the retired Mac is a control panel. Read the repository's
[operations runbook](../../docs/maintainers/OPERATIONS.md),
[release process](../../docs/maintainers/RELEASING.md), and
[maintenance implementation](../../ops/vps-maintenance/README.md) before
changing an existing installation. These public procedures contain no production
credentials, mailbox database, model, host address or private audit bundle.
Preparation steps below describe a new target. Do not replay initial provisioning
on an active server or restart a stale previous worker.

Ubuntu 26.10 source prerequisites were qualified on 31 October 2026 in a
disposable, booted amd64 QEMU VM: kernel 7.3.0-9, systemd 261, Python 3.14.8,
Docker 29.9.2, containerd 2.4.2 and Compose 5.6.1. The candidate host checker
passed all mandatory checks, including x86-64-v3 support; its approximately
3 GB VM RAM produced an advisory. All 33 host/Linux boundary tests passed.
The installed Guardian 0.6.1 binary passed its SQLite self-test directly and
inside an unprivileged systemd service with synthetic `LoadCredential` delivery;
a restricted Docker container smoke test also passed. This qualifies host
prerequisites and basic runtime. No production credentials, mailbox or trained
model were imported, and no in-place Ubuntu release upgrade was tested.

The 26.10 allowlist and CPU check are source changes; they do not retroactively
change previously built or installed releases. Before a future release upgrade,
confirm that the qualified host tools are included in the release actually used.
At qualification, Ubuntu's [ordinary upgrade feed](https://changelogs.ubuntu.com/meta-release)
still did not offer 26.10, despite its [stable release](https://releases.ubuntu.com/26.10/).
Continue official release discovery and complete the current-model/recovery and
upgrade checks when that supported path opens; do not force a development upgrade.
The running VPS remains on Ubuntu 26.04.

The 30 October continuation adds a packaged `guardian-recovery` database-only
inspection tool and an optional external-health observer. Both are described
below. The observer is not installed/enabled by the installer, and neither tool
completes a mailbox handover. Final server operation must preserve the user's
current active filtering policy with permanent deletion off. The explicit
same-mailbox policy adoption described below preserves validated factual history;
it does not inherit permission to run on a new server.

### Preserve an existing filtering policy during handover

Map the source with `migration.LinuxConfig`: it preserves the existing policy,
thresholds, folders and identities while disabling permanent deletion. New
offline configurations default to protect; `server init-config --mode active`
only selects the configuration value and cannot establish activation history.

After stopping the old worker and verifying the complete imported database,
archives and model, use `relocate-snapshot --preserve-policy-history` during
offline preparation. It clears the copied deployment and dry-run authorization
while preserving factual protection/activation timestamps and quality history.
Publish the prepared state while the timer is disabled, then **before any normal
target `status`, `doctor` or `run` command**, run as the administrator:

```sh
sudo /opt/mail-guardian/current/guardian \
  --config /etc/mail-guardian/pilot/config.toml \
  server adopt-policy --instance pilot --preserve-policy
```

Adoption takes the exclusive migration lock and instance lock, requires exact
mailbox/folder identities, a successful latest actual filtering run, reconciled
state and no model-recovery marker, and checks the same active-quality gate as a
real run. It binds the current host and clears inherited dry-run permission
atomically while leaving history intact. A new successful server dry run is
mandatory. A repeat adoption or a database already bound by a runtime command is
rejected. Ordinary first use without explicit adoption still resets activation
permission conservatively; do not reconstruct erased timestamps by hand.

This offline action never reads credentials, connects to IMAP, starts containers
or changes the timer. Model/archive continuity and exclusive mailbox ownership
must be verified by the one-time deployment procedure. Subsequent real runs keep
all normal quality, model-high-water and checkpoint checks.

## Prerequisites researched on 30 October 2026

The original preparation below targets a new, otherwise unused Ubuntu 26.04
host. Current source also accepts 24.04 and the separately qualified 26.10 target
described above. Record the delivered host, OS, CPU, Docker, Compose, sudo and
systemd versions during qualification. Source allowlists and configured CI jobs
do not establish native-host or deployment acceptance; no 26.10 CI runner or
production release upgrade is claimed here.

| Area | Requirement and reason |
| --- | --- |
| Image | Ubuntu 26.04 LTS, distribution only, amd64. Canonical's 26.04 amd64 cloud images default to x86-64-v3; verify the guest's exposed CPU capabilities, not just `uname -m`. Keep the packaged Go binary's existing baseline amd64 target. |
| Capacity | Start with 2 vCores, 4 GB RAM and 40 GB disk. Measure the current database, encrypted archives, model and checkpoint sizes before transfer. The maintenance helper's 2 GiB free-space floor is a stop threshold, not a working capacity budget. |
| Privileges | A working administrative SSH account with sudo, plus a recovery-console path. Ubuntu's normal initial account is `ubuntu`; use the account in OVH's delivery information. Direct root SSH login is unnecessary. |
| Host software | Python 3, systemd >=249, sudo/visudo, passwd tools, util-linux, bash and ordinary coreutils. Ubuntu 26.04 supplies Python 3.14, systemd 259 and sudo-rs by default. Test that default sudo provider rather than replacing it to hide a failure. |
| Containers | Rootful Docker Engine >=28, without user namespace remapping, and a Compose plugin supporting `docker compose ... up --wait`. The fixed socket is `/var/run/docker.sock`; rootless Docker, remapped Docker, Podman and alternate sockets are outside this package's contract. |
| Storage layout | Use the ordinary root filesystem for `/var/lib/docker`, `/var/lib/containerd` and `/var/lib/mail-guardian`. Fresh Docker 29 installations store image data under containerd as well as Docker. The runtime helper currently checks Docker and Guardian filesystems; a custom split containerd filesystem requires additional runtime qualification. |
| Clock | Working time synchronization. New 26.04 installations use chrony/NTS; do not require systemd-timesyncd specifically. Correct time is needed for TLS, DNSSEC and scheduled runs. |

Sources: [Ubuntu changes for LTS users](https://documentation.ubuntu.com/release-notes/26.04/summary-for-lts-users/),
[Ubuntu system changes](https://documentation.ubuntu.com/release-notes/26.04/changes-since-previous-interim/),
[sudo-rs differences](https://ubuntu.com/server/docs/reference/other-tools/sudo-rs/),
[Docker on Ubuntu](https://docs.docker.com/engine/install/ubuntu/),
[Docker image storage](https://docs.docker.com/engine/storage/containerd/),
[OVH first connection](https://support.us.ovhcloud.com/hc/en-us/articles/360009253639-Getting-started-with-a-VPS).

### Prepare the fresh Ubuntu 26.04 host

Review the OS and disk layout first. Apply Ubuntu security updates and complete
any required reboot before qualification. Preserve any pre-existing workload;
the preparation below is for a fresh Guardian-only server. These commands have
not been run against a real VPS in the local preparation session.

```sh
cat /etc/os-release
uname -m
sudo apt update
sudo apt install --no-install-recommends ca-certificates curl python3 sudo-rs \
  systemd passwd util-linux iproute2 dnsutils openssl
```

The host does not need a Go compiler, pip, a Python virtual environment, or
host-installed Redis/Rspamd/Unbound: the package contains a static Go binary
and the supporting services use pinned container images.

Use Docker's signed apt repository. Inspect conflicting `docker.io`, old
Compose, Podman/containerd/runc packages and any existing container state
before resolving a conflict. Do not blindly remove packages or Docker data.
For the verified fresh image, the upstream repository setup is:

```sh
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo docker --host unix:///var/run/docker.sock version
sudo docker --host unix:///var/run/docker.sock compose version
```

Record installed package versions; do not use Docker's convenience script for
this deployment. Keep Docker's default iptables backend and AppArmor enabled.
Engine >=28 is required because older versions have a documented localhost
port-publication exposure issue. The worker must not join the Docker group.
[Upstream installation](https://docs.docker.com/engine/install/ubuntu/),
[port publishing](https://docs.docker.com/engine/network/port-publishing/),
[firewall behavior](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

After verifying the downloaded archive's external SHA-256 and extracting it,
run from the extracted release directory:

```sh
sha256sum -c SHA256SUMS
sudo python3 ./check_host.py
sudo python3 ./check_host.py --json
```

The host checker is read-only: it does not install packages, start containers,
alter firewall/sysctl settings, read credentials, contact a mailbox or enable
Guardian. It checks the local prerequisites and reports unavailable checks as
failures. A pass is local host readiness only; it does not authorize mail access
or establish network, persistence, scheduling or recovery acceptance.
CPU and RAM sizing is advisory in this report: review any capacity warning
against the selected 2-vCore/4-GB plan before proceeding. Unsynchronized or
unverifiable system time fails the check. A containerd filesystem outside
both runtime-monitored Docker/Guardian filesystems also fails.

### Network and filtering prerequisites

| Direction | Required connectivity |
| --- | --- |
| Inbound | Administrative SSH, normally TCP 22, restricted to the intended administrative access path. Guardian needs no inbound SMTP, public web server, domain or MX change. |
| Outbound | The configured IMAP TLS endpoint, normally TCP 993; recursive DNS to authoritative servers over UDP **and** TCP 53; HTTPS 443 for repositories, images, maps and the selected backup destination; HTTP 80 where the selected Ubuntu mirrors/maps use it. |
| Time | Permit the selected time service: ordinarily NTP UDP 123 and, for chrony/NTS, key exchange TCP 4460. Verify synchronization on the actual image. |
| Internal | Rspamd must bind on host loopback only, `127.0.0.1:11333` and `:11334`. Redis 6379 and Unbound 53 stay private to Compose. Verify external IPv4 and IPv6 exposure independently. |

Docker-published ports can bypass UFW rules. OVH's Edge Network Firewall is
IPv4-only and does not replace a host firewall. If configuring a final deny,
preserve SSH, established TCP, appropriate ICMP and returning DNS traffic;
OVH specifically documents allowing UDP responses with **source** port 53.
This does not mean opening a public DNS server. Test from the actual VPS and
from a separate external system, without changing firewall policy blindly.
[OVH Edge Network Firewall](https://support.us.ovhcloud.com/hc/en-us/articles/115001729044-Enabling-and-configuring-the-Edge-Network-Firewall).

Before provisioning mailbox credentials, verify certificate-valid IMAP TLS
connectivity without authentication. The packaged Unbound must resolve directly,
without a public DNS forwarder. Check DNSSEC and the actual reputation lookups
used by Rspamd from the assigned VPS IP. `dnssec.works` and `/ping` demonstrate
limited health only: use a disposable scan, appropriate readiness checks,
a known-listed DNSBL test and a negative/NXDOMAIN test. Treat blocked/rate-limit
responses as lookup failures, not spam listings. Spamhaus fair-use rules can
require an identifiable resolver or an appropriate DQS arrangement on shared
hosting infrastructure; do not assume that Unbound alone guarantees access.
[Rspamd DNS and production checks](https://docs.rspamd.com/getting-started/installation/),
[Spamhaus error responses](https://www.spamhaus.org/faqs/dnsbl-usage/),
[Spamhaus fair use](https://www.spamhaus.org/blocklists/dnsbl-fair-use-policy/).

### Memory, persistence and real-host acceptance

The existing Compose ceilings total 1.5 GiB RAM and 1.75 CPUs across Rspamd,
Redis and Unbound. They leave host headroom, but do not prove peak capacity.
Redis has a 256 MiB container limit and 128 MiB `maxmemory`; persistence forks,
fragmentation and rewrite buffers need a measured peak-memory check with the
transferred model. Upstream recommends `vm.overcommit_memory=1` and disabled
Transparent Huge Pages. Inspect these settings and qualify any host tuning
before enabling the worker; the installer and host checker do not change them.
[Redis administration](https://redis.io/docs/latest/operate/oss_and_stack/management/admin/).

Require successful model export/checksums, Redis AOF/RDB health, actual
administrative kernel diagnostics, storage margins, restart continuity and a
complete off-machine restore exercise. A normal test container cannot prove
host `dmesg` access, Docker networking, credential delivery, systemd execution
or reboot recovery. Native amd64 CI is configured on both Ubuntu 24.04 and
26.04; a configured job is not a completed CI run.

The current package permits only one instance per host. Restore rehearsals
therefore need an independently isolated target. Complete state transfer,
fencing of the Mac worker, fresh server authorization and the controlled live
pilot before enabling the timer. Preserve the original archive identity and
use the latest server state for rollback; an old Mac snapshot is not a safe
post-cutover recovery source.

### Database-only recovery inspection

The package includes a separate `guardian-recovery` binary. It requires explicit
configuration and private standalone snapshot paths, never reads Keychain or
credentials, and does not contact IMAP/Redis or start a worker. For an existing
private snapshot:

```sh
./guardian-recovery inspect-snapshot \
  --config /var/tmp/guardian-recovery-staging/config.toml \
  --database /var/tmp/guardian-recovery-staging/guardian.db
```

An explicit `--source /path/to/guardian.db` first creates a new standalone
SQLite-only copy at `--database`; the destination must not exist and its parent
must be private. The optional source can be a live read-only SQLite view,
including committed WAL data. The default main-image limit is 64 MiB, adjustable
from 1 to 256 MiB. SQLite page bounds apply while copying; temporary/journal disk
overhead is separate and raw backup steps have cooperative cancellation. Use an
external process deadline and storage quota when hard limits are required.

The inspector reads bounded bytes through no-symlink descriptors, checks the
current supported schema and identities in a read-only in-memory connection,
rejects unresolved operations/model markers, and returns counts and the digest
of the exact inspected bytes without account names or archive paths. A completed
diagnostic copy remains available when inspection rejects its state.

Historical superseded messages can retain abandoned reconciliation cursors.
The strict inspector rejects these for adoption. A separate explicit command
prepares a new private clone while preserving its original:

```sh
./guardian-recovery prepare-snapshot \
  --config /var/tmp/guardian-recovery-staging/config.toml \
  --source /var/tmp/guardian-recovery-staging/original.db \
  --database /var/tmp/guardian-recovery-staging/prepared.db
```

This accepts only an already standalone private source. It validates all
schema/identity/state checks, permits cursor removal only when every cursor
belongs to a same-account message with exact status `superseded`, and deletes
only those cursors in a separate in-memory clone. The new output must not exist.
The receipt binds source/result hashes and removed count. Messages, events,
runs and settings remain intact; imported authorization is not revoked here.
Older completed run-status/error-counter inconsistencies are preserved and
reported. The latest actual filtering outcome is selected separately, so a
later dry run cannot mask it. A coherent failed generation remains inspectable
offline; successful inspection is not a live-health or cutover decision.

**Database readiness is not recovery readiness.** This tool does not decrypt
archives, validate a fresh Redis model, prove cross-component coherence, fence
old mailbox sessions, establish independent provenance, or authorize activation.
The force-fresh exporter, bounded snapshot, inspector and durable receipt catalog
remain building blocks for the operational capture/recovery coordinator.

### Optional independent health observation

The source package carries `observe.py`, `mail-guardian-observe@.service` and its
five-minute timer. They are preparation only: the initial installer does not
install or enable them. Before deployment, review the root-owned observer path,
root-owned version-2 configuration, current deployment binding, credential
provisioning and an actual alert-delivery drill. The intended fixed script path
is `/usr/local/libexec/mail-guardian-observe`.

The observer uses a root-owned `healthchecks-url` credential source delivered by
systemd; the UUID URL must never be put in argv, environment variables or logs.
It sends empty HTTPS status signals to `hc-ping.com`, with bounded IO, no proxy
or redirects. It checks a fresh successful actual run, matching heartbeat,
deployment/mailbox/folder identity, unresolved operations and model markers.
Bounded in-flight deferral emits no success. The separate unprivileged observer
has no sudo access; its narrowly writable state path permits ordinary SQLite
WAL/SHM bookkeeping while SQL access stays read-only/query-only.

Successful worker state expires after twenty minutes, even if the observer keeps
running. With the five-minute observer timer, a stopped worker produces a failure
signal within about 26 minutes; a missing host/observer ping expires externally
after fifteen minutes. These are detection settings, not proof of delivery.
Use an external five-minute period and ten-minute grace initially, with an alert
destination outside the monitored mailbox. The observer is not a backup monitor:
an independent verified off-host generation needs its own check. The operator's
external account and secrets are still required; no external ping is enabled by
including these files in a release.

An optional local hidden-input helper is documented in the source checkout at
`tools/provisioning/README.md`; it is not installed by this server package. Its default
invocation only displays the fixed plan. Use credential provisioning at the
reviewed deployment stage, after account setup and release preparation; keep
the current empty pilot unconfigured until then. The helper does not deploy or
activate monitoring and refuses an existing credential.

## Initial Guardian provisioning

The `guardian` worker runs as `mg-<instance>` without Docker group membership.
Only `/usr/local/libexec/mail-guardian-maintenance` has narrowly scoped sudo
authorization. It accepts an instance and one fixed operation, validates the
administrator-owned deployment tree, and uses the fixed Docker Unix socket.
Kernel storage errors or unavailable diagnostics, insufficient space, unhealthy
Redis persistence and failed model exports fail the run. Exported RDB bytes are
validated and published by the worker. Root never writes through worker state.

The service uses `LoadCredential` for `imap-password`, `rspamd-password` and
`archive-identity`. Source files belong to root, mode 0600, in
`/etc/mail-guardian/<instance>/credentials`, whose mode is 0700. Provision them
through a secure administrative channel; do not put secrets in shell arguments,
environment variables, chat, logs or the package. Keep the original archive
identity separately recoverable. It is required to decrypt existing archives.

The installer verifies the included SHA-256 manifest, target OS, systemd,
Compose and sudo configuration. Generate a new configuration with:

```sh
sudo ./guardian server init-config --instance pilot --email owner@example.invalid \
  --server-spam Spam --output /root/pilot-config.toml
sudo ./install.sh --instance pilot --config /root/pilot-config.toml --check
sudo ./install.sh --instance pilot --config /root/pilot-config.toml
```

The installer's `--check` does not provision the instance, but may create a
root-only global provisioning lock under `/run` so concurrent initial installs
cannot race. It never starts Guardian or its timer.

Verify delivery and scheduling against the upstream definitions:
[`LoadCredential`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
and [`Persistent` calendar timers](https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html).
Docker administration stays behind the fixed helper because access to the
daemon socket controls the host's containers; see
[Docker daemon access](https://docs.docker.com/engine/security/protect-access/).

`init-config` creates configuration only. It does not authorize mailbox access.
Existing configuration, worker state and credentials are preserved. A different
installed release is rejected; this initial installer is not an update or
rollback implementation. Repeating provisioning requires the worker and timer
to be stopped and the timer disabled. Instance names have at most 29 characters to fit the system user.
The initial package rejects a second instance because Rspamd currently uses
fixed loopback ports 11333 and 11334. Linux Compose uses separate project-scoped
resources and does not reuse the Mac's resource names.

Scheduling remains off. The timer uses `OnCalendar=*-*-* 00/2:00:00` and
`Persistent=true`; missed events are eligible once the enabled timer starts.
systemd coalesces events while this oneshot is active, and Guardian's instance
lock also prevents concurrent manual workers. The service intentionally permits
the fixed sudo helper; `NoNewPrivileges` and capability restrictions that break
the helper would make required storage verification unavailable.

Before enabling any run, complete disposable tests, provision the credentials,
verify host identity and external IPv4/IPv6 exposure, perform an isolated
backup/restore exercise, fence the Mac worker and transfer a consistent current
database/model/archive checkpoint. Require fresh dry-run authorization on the
server. Protect mode can move mail and process training corrections. Keep
permanent deletion disabled, and authorize the controlled live pilot before
enabling the timer. Do not restart a stale Mac checkpoint after server changes.

The helper's `up` operation creates a controller hash through stdin inside the
pinned Rspamd container. Changed or missing administrator runtime recreates
containers while preserving volumes. It never accepts worker-supplied Compose
paths, mounts, executables, unit definitions or environment settings. Helper
failures return a generic diagnostic to the worker; administrative investigation
must avoid exposing message contents or credentials.

The pinned Rspamd image runs as UID/GID 11333. Its generated controller hash
file is root-owned with group 11333 and mode 0640, inside root-only runtime
directories under `/var/lib/mail-guardian-admin/<instance>`. The parent and
instance directories are root-owned 0700. This generated bind-file must persist
across reboots because Docker can restart containers before Guardian runs.
A missing file under `/run` could be recreated as a directory by Docker and
prevent Rspamd startup. Maintenance locks remain ephemeral under `/run`.
Docker bind-mounts the controller file directly read-only; the controller
password itself and its fingerprint remain root-only. The helper checks that
Docker does not use rootless or user-namespace remapping before creating or
reusing the file, and regenerates an old root-only file with the correct mode.
