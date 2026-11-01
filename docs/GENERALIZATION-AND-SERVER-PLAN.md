> **1 November 2026 source update:** the Mail Guardian 0.7.0 source now exposes
> custom IMAP setup in the desktop, CLI and Linux configuration command.
> See [the current provider contract](PROVIDERS.md). Provider certification and
> production promotion remain separate; the design below retains its history.

# Mail Guardian generalization and server hosting plan

> Historical design note. Statements such as “not deployed” describe the original design stage. For current maintenance, start with [the operations runbook](maintainers/OPERATIONS.md) and [release process](maintainers/RELEASING.md). Private audit paths are deliberately omitted.

Prepared on 20 October 2026 against the current working tree, including the
existing 0.5.3 changes. Updated on 30 October 2026 with the Linux worker and
initial deployment candidate described below. Real-server operation and
broader provider compatibility remain unqualified.

The goal is one filtering engine that works with several mail providers and
can run either locally on macOS or continuously on a private Linux server.
Develop provider support and server operation in parallel after a short shared
foundation. Keep the Mac application as the first control panel, with a secure
remote connection when filtering runs on the server.

## Implementation progress — 30 October 2026

The selected new deployment target is **OVHcloud VPS-1 2027, Ubuntu 26.04
amd64, 2 vCores / 4 GB RAM / 40 GB NVMe**. The installer now accepts 24.04
and 26.04 explicitly, while rejecting other releases, derivatives and
architectures. Native amd64 CI is configured on both Ubuntu releases,
including matching disposable installer fixtures with each release's default
sudo implementation. The prerequisite research and read-only `check_host.py`
are in [`deploy/linux/README.md`](../deploy/linux/README.md).

The 26.04 prerequisites include the cloud image's x86-64-v3 CPU baseline,
sudo-rs/Python 3.14, Docker >=28, cgroup v2, containerd storage and real
DNSBL access from the assigned VPS address. These are checks to complete on
the delivered server, not proof of its CPU, kernel, network or recovery
acceptance. The earlier 24.04-only evidence below is retained as historical
evidence and does not qualify 26.04.

Local 26.04 preparation checks passed: all 14 tested Go packages in a native
arm64 Ubuntu 26.04 container; 13 deployment boundary tests and 15 host-check
tests under Python 3.14.4; real systemd 259 unit parsing; and an emulated
amd64 installer fixture using sudo-rs 0.2.13. The minimal fixture's sudoers
permissions were normalized to 0440 before installation. Local amd64 GNU tar
hit an independently reproduced missing `openat2` emulator syscall, so that
fixture used Python extraction. Native arm64 GNU tar extracted the final
portable archive and its full internal manifest verified. These results do
not establish native amd64, x86-64-v3, booted services or recovery acceptance.
The full Mac checks passed, and the final packaging check confirms that an
ambient `GOAMD64=v4` cannot change the packaged baseline `GOAMD64=v1` binary.
The separate native amd64 GitHub jobs have not been dispatched in this work.

The B1 worker/package increment is implemented. Build the candidate with
`make package-linux`; the administrative procedure is in
[`deploy/linux/README.md`](../deploy/linux/README.md). The current candidate
shares version 0.6.1 with the working source; it is a development pilot, not
a new released Mac version. No existing installation or real mailbox was
changed, and no hosting was purchased or provisioned during this work.

| Area | Implemented | Acceptance still required |
| --- | --- | --- |
| Linux worker | Explicit administrator-owned instance configuration and fixed state paths; no fallback to a Mac installation. Linux help and command dispatch exclude unsupported Mac setup/API/mode/purge operations. The pilot enforces protect mode and permanent deletion off. | Controlled mailbox run on the target host; broader controls after cutover/recovery work. |
| Privilege boundary | Worker runs as `mg-<instance>`, with no Docker or administrator groups. A fixed sudo dispatcher accepts only an instance and seven named operations. It ignores caller environment, verifies administrator ownership, uses the fixed Docker socket, and never opens worker state as root. Responses, exports and durations are bounded. | Real host/kernel/Docker diagnostics and checks from the systemd service namespace. |
| Persistence | Host kernel storage errors, missing diagnostics, low/read-only storage and unhealthy Redis AOF/RDB fail closed. Every modifying Linux run/restoration records a durable required checkpoint, verifies model revision continuity and a CRC64/SHA-256 snapshot before and after work, and clears the marker only after success. | Real model export/restart continuity and failure injection against disposable server data. |
| Lifecycle | Offline Ubuntu 24.04/26.04 amd64 package, root-owned versioned binary, isolated Compose project, idempotent initial installer, three systemd credentials, two-hour persistent timer. Installer refuses an active/enabled schedule, a second instance, changed configuration, or an unreviewed software update. It leaves scheduling off. | Native target host and boot/missed-run/service-stop acceptance; software update/rollback implementation. |
| Ownership and authorization | Service readiness, heartbeat and mailbox operations share the instance lock. Manual stack changes use that same lock. A new machine/deployment revokes copied dry-run and activation permission while preserving quality/model history. | Fencing the Mac and transferring one current, consistent state; this is not an import/migration implementation. |
| Secrets | Root-owned credential sources feed systemd `LoadCredential`; existing read-only secret reader serves the worker. Controller hashing uses the pinned Rspamd implementation with the password only on stdin. | Secure provisioning/rotation on the actual server and recovery of the original archive key. |
| CI | Ubuntu native race tests, deployment/package tests, systemd definition verification and Linux artifact upload configured. Mac checks also validate Linux packaging. | The changed GitHub Actions job has not run in this local session. |

Current local evidence includes passing Go race tests and vet on macOS,
34 Swift tests and the Mac installer/release checks, all 14 tested Go packages
executed on native Linux arm64 in a disposable Ubuntu 24.04 container,
11 Python maintenance/package boundary checks and systemd unit validation.
The amd64 installer also passed inside an emulated disposable Ubuntu container:
real user/filesystem/sudoers provisioning with stub Docker/systemctl, repeat
installation preserving state/configuration/credentials, rejection of changed
configurations, second instances, active/enabled timers and supplementary
worker groups. Actual sudo authorization permits a named maintenance operation
and rejects arbitrary commands. These are fixture results, not live Docker or
systemd service acceptance.
Linux amd64 packaging passes. All 14 amd64 test packages also pass under CPU
emulation with `GODEBUG=asyncpreemptoff=1 GOGC=off`. Default emulation produced
inconsistent runtime failures in the full engine suite; the workaround does
not qualify the amd64 target. The arm64 test execution does not qualify an
arm64 release either. A real amd64 host or the
native Ubuntu amd64 CI run remains necessary. Unit parsing and container
tests do not demonstrate a booted systemd schedule or a live mailbox run.

Next complete SSH management, a consistent export/import and independent
encrypted backup/restore exercise, then the controlled VPS pilot and cutover
sequence below. Server access has not been supplied. Continue disposable
development without purchasing hosting; use the actual selected host for
native amd64, network, scheduled-run, reboot and recovery acceptance.

The foundation section below records the earlier 20 October state and its
historical validation; current Linux progress is described above.

## Implementation progress — 20 October 2026

The first increment adds configuration and credential contracts while preserving
the current Mac installation layout. It has not been installed over the active
application or connected to a real mailbox during this work.

| Area | Implemented in source | Remaining work |
| --- | --- | --- |
| Baseline | Saved the complete tracked and non-ignored source tree, including all existing uncommitted 0.5.3 fixes, with a SHA-256 manifest and Git patch outside the checkout. Existing Go tests passed before changes. | Preserve the currently installed package and real service as the cutover baseline; recheck the actual version and health at cutover. |
| Configuration | Version 2 has instance/account IDs, provider, separate login username and explicit authentication method. Version 1 loads as the existing o2 account without rewriting the file; a later save persists version 2. Legacy paths, folders and Keychain services remain intact. | Finish the provider-aware Mac wizard and the explicit migration/export operation. |
| Mailbox safety | SQLite binds its journal to the instance, account and connection fingerprint. A changed endpoint, provider, login or identity cannot reuse existing state. Folder changes revoke the dry-run proof and restart observation while preserving runs, corrections and model high-water marks. Pending operations block folder rebinding. Status checks do not rebind a running worker. | Deployment ownership/fencing and a reviewed import of an existing instance onto another host. |
| IMAP | Shared o2/custom profile resolution and an explicit password-authentication boundary. The setup API accepts optional provider/endpoint/login fields while retaining protocol 1 requests. Omitted fields preserve an existing custom connection. Verified TLS and native MOVE requirements remain. | Disposable Dovecot acceptance, provider-aware CLI prompts and Mac UI, then a second real provider. Custom IMAP is an implementation candidate, not a qualified provider claim. |
| Secrets | Shared reader/store interfaces cover mailbox, controller and archive secrets. macOS keeps Keychain; Linux runtime reads explicit private credential files named `imap-password`, `rspamd-password` and `archive-identity` from `CREDENTIALS_DIRECTORY`. Reads are bounded and reject symlinks/insecure permissions. Missing or invalid archive keys are not silently replaced. | Administrator provisioning, secure onboarding writes, credential rotation and independently recoverable archive-key delivery. The Linux reader deliberately rejects writes. |
| Linux | Explicit isolated `/etc/mail-guardian/<instance>` and `/var/lib/mail-guardian/<instance>` path contract; Ubuntu 24.04 CI job added for Go tests and a Linux build. | Platform/lifecycle services, systemd deployment, persistence helpers, backup/restore and SSH management. The new CI job needs a remote run. The default local Docker socket was unavailable during development. |

New installations created through the future provisioning workflow can use
`config.NewInstance` to generate random stable IDs. Existing setup entry points
retain deterministic legacy migration identities; they cannot redirect the
same state to another provider. Changing `version` or editing IDs is not an
account migration procedure.

The Linux credential reader and path contract do not make the worker ready for
unattended Linux operation. Colima checks, launchd scheduling, stack maintenance
and Mac notifications still need platform implementations. Keep server
scheduling and mailbox migration out of this increment.

Configuration v2 must not be opened with an older Guardian release. Older
binaries do not enforce the new fingerprints. Software rollback must restore a
compatible configuration and carry the newest journal/model as specified below;
do not copy only a previous executable over this candidate.

Validation for this increment: all Go tests with the race detector and `go vet`
passed; the full Mac `make check` passed using a temporary Swift scratch path,
including 34 Swift tests, mock onboarding, installer rollback, Compose checks,
release packaging and isolated prebuilt-install tests. The first Swift attempt
in the synced workspace failed because of Finder/File Provider signing metadata;
the scratch-directory run resolved it. The vulnerability check reported no
affected code or imported packages; the previously documented unused OpenPGP
module finding remains. Linux amd64 cross-compilation is separate from Linux
execution and deployment acceptance.

The next increment should finish the platform operation boundary (readiness,
storage checkpoint and scheduling), implement Linux lifecycle/provisioning,
and add disposable Dovecot tests alongside provider-aware setup controls. No
hosting purchase or real-mailbox cutover is needed for that work.

## Product scope

Use **Mail Guardian** as a working product name. Keep o2 as a provider profile
and preserve existing installations, credentials, folder mappings, model state
and recovery records during the transition.

The first release should protect one mailbox per isolated instance. A person
can eventually operate several instances on one sufficiently sized server,
each with separate state and learning. A combined account dashboard follows
the first successful deployment. A service where unrelated people sign up
would require a separate scope for user accounts, tenant isolation, onboarding,
abuse controls and provider authorization.

The server runs the filter while the Mac is off. Mail remains at the existing
mail provider, where the user continues reading it and making corrections
through the training folders. No mail-domain migration or MX change is needed.

Server operation changes the privacy boundary: message bodies are processed
in memory on the rented server and its administrator can access runtime
credentials. Encrypted archives and backups protect stored copies, but do not
hide mail from a compromised running server. Continue to avoid external LLM
processing, public fuzzy uploads and opening links or attachments. Explain the
local and server choices accurately in onboarding and privacy documentation.

Until server details or a different product scope are supplied, use a private
Linux VPS with one owner as the planning assumption. Existing server access,
operating system and capacity should be checked before ordering anything.

## Findings in the current application

| Finding | Current evidence | Consequence |
| --- | --- | --- |
| The engine already separates mail and scanning implementations. | `internal/engine/engine.go:29–55` | Reuse the engine rather than rewriting filtering. |
| Configuration explicitly restricts IMAP to o2, and GUI setup independently hardcodes the endpoint. | `internal/config/config.go:176–177`; `cmd/guardian/api.go:331` | Generalization must change both validation and onboarding. |
| IMAP transport supports an arbitrary TLS endpoint, but authenticates with LOGIN and uses the email as username. | `internal/imapmail/client.go:65–103` | Separate login name from email; add an authentication boundary. |
| All three runtime secrets require macOS Keychain. Archive loading takes its concrete store type. | `internal/keychain/keychain.go:20–32`; `internal/archive/archive.go:25–57`; `cmd/guardian/main.go:1909–1927` | Linux needs mailbox, controller and archive-key support together. |
| Compose runs Rspamd, Redis and Unbound. Guardian itself remains a host process. | `deploy/compose.yaml` | Copying Compose to a server does not deploy the complete application. |
| Startup and post-run checks require Colima, and the scheduler uses launchd. | `internal/stack/stack.go:35–65`; `internal/stack/storage_health.go:22–33`; `cmd/guardian/main.go:935–949`; `internal/service/launchd.go` | Provide Linux lifecycle, storage and backup implementations. |
| The GUI API is JSON over a local subprocess. | `cmd/guardian/api.go:68–172`; `macos/Sources/O2MailGuardianApp/O2MailGuardianApp.swift:222–319` | A remote connection must be developed; there is no existing HTTP application to publish. |
| Messages have an account field, but runs, settings and learning are shared by the instance. | `internal/store/store.go:229–292`; `internal/rspamd/client.go:214–225`; `deploy/rspamd/local.d/classifier-bayes.conf` | Adding a loop over accounts would mix safety and learning state. |
| Archive references use absolute paths, and the process lock is local to a host. | `internal/archive/archive.go:122–129`; `internal/store/store.go:248`; `internal/runlock/runlock.go:15–30` | Migration must rebase paths and explicitly transfer ownership of scanning. |
| Automated release checks currently target macOS. | `.github/workflows/check.yml`; `scripts/package-release.sh` | Add Linux execution, integration and release checks. |

A static Linux amd64 cross-build passed during planning:

```text
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -o <temporary directory>/guardian-linux-amd64 ./cmd/guardian
```

The output was identified as a statically linked x86-64 Linux ELF executable.
This proves compilation only. Linux execution, scheduling, credentials and
recovery still need acceptance testing. Planning did not run the mail engine
or change the active installation or mailbox.

## Shared foundation

Implement these contracts together so the two tracks do not create competing
configuration formats or duplicate business logic.

| Contract | Implementation requirement |
| --- | --- |
| Account and provider configuration | Introduce a versioned schema containing an immutable instance/account ID, provider ID, IMAP endpoint, login username, email, authentication method and folder roles. Bind operational authorization to that identity and a fingerprint of the relevant configuration. Changing host with the same email must not reuse another mailbox's UID history. |
| Secret access | Extract the existing command-level secret interface into a reusable package. Cover password or token, Rspamd controller secret and age archive identity. Keep Keychain on macOS and add a Linux implementation. |
| Platform operations | Separate paths, scheduling, stack readiness, storage checks, model snapshot and notifications from filtering. Preserve fail-closed behavior when required checks cannot run. |
| Application operations | Expose setup, probe, run, status, schedule and recovery through shared application services. Keep local JSON compatibility or negotiate an explicit protocol version when the setup schema changes. |
| Migration | Load existing v1 configuration as the o2 profile. Preserve old data paths, Keychain identifiers, LaunchAgent labels and Docker volume names until an explicit migration changes them. A display-name change must not create an empty installation. |

Provider, endpoint, login or folder changes must invalidate prior dry-run
authorization and require the appropriate observation period. Preserve the
previous quality history; a cosmetic rename or routine restart must not erase
unfavourable observations. A new mailbox identity gets fresh state rather than
silently redirecting existing pending operations.

## Track A Provider support

### A1 Secure generic IMAP

Add a small provider-profile layer with display name, endpoint defaults,
supported authentication methods, folder hints, setup help and an optional
webmail link. Begin with the existing o2 profile and a custom IMAP profile.
Use a disposable Dovecot environment for repeatable protocol tests, then
qualify one independently operated real provider before claiming broader
compatibility.

Support verified implicit TLS and password or app-password login first. Keep
native IMAP MOVE or IMAP4rev2 as a requirement for moving mail. Unsupported
capabilities should produce a clear explanation and permit read-only
diagnosis. Do not weaken TLS, emulate destructive moves, or lower classification
thresholds to make an incompatible server pass.

Probe the actual folder list and special-use attributes. Let users confirm
spam and training folders, including custom namespaces and delimiters. Keep
existing Polish folder names on upgraded installations; introducing neutral
names for new installations must not create a second set for existing users.
Some providers may have no spam folder or prohibit creating folders; report
that limitation rather than silently assigning a different folder role.

### A2 Provider aware setup and presentation

Use the same profile resolution for CLI, API probe, API commit and runtime.
Extend the Mac wizard for provider, login name and custom endpoint. Replace
o2-specific messages and webmail links throughout setup, corrections, recovery
and documentation. Keep advanced connection settings out of the ordinary
journey when a validated profile supplies them.

### A3 Authentication and provider semantics

Treat Gmail and Microsoft support as explicit adapters with their own
acceptance gates. Google documents OAuth IMAP access using the full mail
scope and verification requirements for public applications; app passwords
are conditional on account settings. Gmail also exposes label and global
message-identity extensions. Microsoft documents application registration,
token acquisition and SASL XOAUTH2 for IMAP. These are engineering and provider
approval dependencies, not additional host presets.
Sources: [Google OAuth IMAP](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol),
[Google app passwords](https://support.google.com/accounts/answer/185833?hl=en),
[Gmail IMAP extensions](https://developers.google.com/workspace/gmail/imap/imap-extensions),
[Microsoft OAuth IMAP](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth/).

Research the selected second provider's current requirements before choosing
it as a supported profile. Test login renewal, folder changes, moves,
duplicates, spam rescue and restoration with disposable mail. Any shared
public service must account for provider consent and verification timelines.

## Track B Server operation

### B1 Linux runtime and deployment package

Use a native Guardian executable under systemd and keep Rspamd, Redis and
Unbound in Compose on the same VPS. This preserves the existing restriction
that scanning and learning connect through host loopback. The mail worker
should run as a dedicated unprivileged user.

Separate administrator-owned container startup, model export and maintenance
from the mail worker. Do not grant the worker or remote-management process
general Docker access. Preserve the current post-run persistence checks by
using a narrow fixed-operation helper with a bounded result, or a maintenance
unit that waits under the same instance lock. A failed required checkpoint
must remain visible as failure, and block subsequent unattended mutations;
moving the check to another process must not make the run appear healthy.
Privileged helpers must use fixed administrator-owned configuration and reject
worker-supplied Compose paths, executable paths, mounts or unit definitions.

Use deterministic service paths such as `/etc/mail-guardian/<instance>` for
configuration and `/var/lib/mail-guardian/<instance>` for state. Deliver secrets
through systemd credentials backed by restricted files or encrypted host
credentials. Keep them out of process arguments, ordinary environment
variables, the repository and diagnostic receipts. Maintain a separately
recoverable archive key: host-bound credential encryption alone is insufficient
for replacement-server recovery. systemd documents `LoadCredential` and
`LoadCredentialEncrypted` for credential delivery.
Source: [systemd execution and credentials](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

Ship a two-hour systemd timer, prevent overlapping manual and scheduled runs,
and handle reboot and missed runs predictably. Readiness must include actual
Rspamd checks, Redis persistence and model continuity, disk capacity and
writability. Replace Colima-specific kernel checks with Linux host checks;
do not simply remove storage protection. A restricted worker's inability to
read kernel logs needs a supported administrator-side diagnostic path.

Ubuntu 26.04 LTS on the selected OVH VPS is the next amd64 qualification target;
24.04 remains accepted. Verify the actual CPU instruction set, Docker, sudo
and systemd versions during provisioning. Add arm64
only after image manifests and the real execution tests pass on that platform.

### B2 Hosting choice and cost

The current selection is OVHcloud VPS-1 2027 with plain Ubuntu 26.04 amd64.
The comparison below records earlier research; it is not a current order quote
or an instruction to buy a different provider. Check the selected account's
currency, billing country, taxes, term and included options before payment.

Start sizing at two shared vCPUs, 4 GB RAM and 40 GB SSD for one mailbox.
This is an engineering starting point, not a measured minimum. Before
provisioning, measure current archive/model/database size and growth, then
test peak memory, scan duration and free-space margins on the pilot.

| Option | Published starting configuration and price | Assessment |
| --- | --- | --- |
| Hetzner Cloud CX23 in Germany or Finland | 2 vCPU, 4 GB RAM, 40 GB NVMe; EUR 5.49/month excluding VAT and IPv4 in the current price table | Preferred low-cost candidate if available. Low-cost capacity is limited; check the actual order quote before selecting a fallback. |
| DigitalOcean Basic Droplet | 2 vCPU, 4 GiB RAM, 80 GiB SSD; USD 24/month before extras | Straightforward alternative, with a materially higher published base price. |
| Managed application platform | Requires durable worker storage and separate handling of the supporting services | Defer for this deployment. For example, Render's default filesystem is ephemeral and persistent disks require eligible paid services. The current stack fits a single VPS more directly. |

Sources: [Hetzner specifications and availability](https://www.hetzner.com/cloud/cost-optimized/),
[Hetzner price table](https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/),
[DigitalOcean prices](https://www.digitalocean.com/pricing/droplets),
[Render persistence](https://render.com/docs/disks).

The order quote must include VAT, public address, provider backups and an
independent encrypted backup destination. Hetzner lists automatic server
backups at 20% of the server price. Its seven rotating server backups exclude
attached Volumes, so they supplement application backups. Confirm the full
recurring amount before purchase; the base price is not the total budget.
Sources: [Hetzner billing](https://docs.hetzner.com/cloud/billing/faq/),
[Hetzner backup coverage](https://docs.hetzner.com/cloud/servers/backups-snapshots/overview/).

The assistant owns provisioning, configuration and validation. The user needs
to supply existing access or complete hosting registration/payment, and later
authorize mailbox access through a secure setup flow. Do not request secrets
in chat. No new service should be purchased merely to finish the local
development and disposable test environment.

### B3 Network and management

Keep Rspamd bound to loopback and Redis/Unbound private. Verify public exposure
for IPv4 and IPv6 from outside the host. Docker documents that published ports
can bypass normal ufw rules, so firewall configuration alone is insufficient
evidence. Check provider firewall rules and actual bindings too.
Source: [Docker firewall behavior](https://docs.docker.com/engine/network/packet-filtering-firewalls/).

The filter needs outbound IMAPS, DNS and controlled update/backup connectivity.
It does not send mail using SMTP. Hetzner's documented default blocks on
outbound ports 25 and 465 therefore do not block the intended IMAP workflow;
connectivity on the selected account's IMAP port still needs a pilot check.
Source: [Hetzner server FAQ](https://docs.hetzner.com/cloud/servers/faq/).

Test DNSSEC, DKIM and reputation queries from the selected server IP. Keep
Unbound recursive DNS and inspect blocked/rate-limited DNSBL responses rather
than assuming a container health check proves useful filtering. Rspamd warns
that major DNS blocklists reject public-resolver queries, and Spamhaus applies
conditions to public-mirror use. Determine a permitted configuration for the
chosen deployment and any later shared service before relying on those checks.
Sources: [Rspamd DNS guidance](https://docs.rspamd.com/getting-started/installation/),
[Spamhaus usage](https://www.spamhaus.org/faqs/dnsbl-usage/).

For the first management interface, add an SSH transport behind the existing
Mac GUI bridge. The user selects local or server operation, connects once,
and can view status, run a check, pause scheduling and recover mail. Commands
and responses must identify the server and instance so local status cannot be
mistaken for remote health.

Use host-key verification, bounded requests/responses and a fixed command
dispatcher. Never interpolate arbitrary remote shell text. Separate the
mailbox worker's operations from administrator maintenance and scope the
management key accordingly. Remote setup must support safe credential writes;
read-only systemd credentials alone do not implement an onboarding store.
Negotiate protocol compatibility and clearly show disconnected or stale state.
A failed remote connection must not fall back to running the local mail worker.

A private browser interface can follow if access from phones or other
computers is required. It would need a new HTTP transport, authentication,
session/CSRF protection and an appropriate private access route. It must use
the same application operations rather than implement another mail engine.

### B4 Installation and routine upkeep

Deliver these operations as tested software, run by the assistant during
initial deployment and exposed through clear controls where practical:

| Operation | Required behavior |
| --- | --- |
| Install | Check host identity/OS/capacity, create private paths and users, install verified versioned binaries and pinned container images, provision secrets, validate readiness, and finish with scheduling off until setup acceptance. Rerunning must preserve state. |
| Status | Show selected host/account, latest completed real run, current pending work, next schedule, backup age, model continuity and disk status. Keep historical errors separate. |
| Update | Pause the instance, produce a consistent checkpoint, stage the new release, run checks, switch atomically and resume only after success. Record schema compatibility before allowing software rollback. |
| Backup | Preserve a consistent SQLite snapshot, encrypted archives, Redis model and continuity metadata, configuration, image/binary versions and a manifest. Encrypt off-machine storage and verify transfer. |
| Restore | Restore to an isolated instance with mailbox mutation disabled; verify DB integrity, hashes, archive decryption and matching model state before permitting use. |
| Rollback | Stop the current owner, preserve its newest journal/model, and return them to a compatible previous release or host. Reject unsafe schema downgrades. |

Use a short deployment receipt with version, schema, instance identity,
container digests, state locations, test outcomes and backup identity. Exclude
mail contents and credentials.

Monitor missed runs, pending operations, authentication errors, backup age,
capacity/writability and model regressions. As initial configurable targets,
flag no successful run for more than four hours and no verified off-machine
backup for more than 24 hours. Establish a notification channel with the user
before sending external alerts. A process and its containers being alive must
not be presented as proof that mail filtering succeeded.

## Parallel delivery sequence

| Stage | Track A | Track B | Integration evidence |
| --- | --- | --- | --- |
| 0 Baseline | Inventory o2 assumptions and preserve current behavior. | Inventory runtime/state and define a recovery manifest. | A reproducible source/package baseline that includes the current uncommitted fixes; no reset or accidental omission of them. |
| 1 Shared contracts | Provider/account schema and authentication boundary. | Secret/platform/lifecycle boundaries and Linux paths. | Existing Mac setup and safety tests pass; v1 migration preserves the installed o2 account. |
| 2 Concurrent implementation | Custom IMAPS, shared setup resolution, folder mapping and provider-aware UI. | Linux runtime, systemd units, provisioning, persistence helpers and Linux CI/package. | Generic fixtures run on Linux; o2 compatibility remains intact on Mac. Neither lane waits for Gmail OAuth or a public web UI. |
| 3 Usable pilot | Validate a second provider and supply its setup help. | Add Mac remote transport, update/backup/restore controls and deploy a disposable pilot. | The Mac controls the intended remote instance, including after a host restart; secrets remain absent from logs and diagnostics. |
| 4 Recovery and cutover | Validate provider behavior and retain protection gates. | Rehearse migration, interruption, current-state rollback and off-machine recovery. | One real scheduled run, reboot recovery, restored archive/model and a demonstrated rollback path. |
| 5 Expansion | OAuth, Gmail semantics, Microsoft support and a combined account interface. | Additional architectures or a private browser interface as needed. | Each addition has its own provider/platform evidence. Shared public hosting needs a separate design. |

The first useful combined delivery is o2 plus custom secure IMAP, with the
same backend running on macOS or Linux, remote status/control, and verified
backup/restore. It does not require completing every provider adapter first.

## Mailbox migration and acceptance

1. Preserve the existing working tree and build the exact candidate release.
   Qualify it with disposable data before touching the real service. Record
   the active installed version and current health at cutover time; historical
   verification does not establish the current mailbox state.
2. Prepare the server with scheduling and mailbox writes disabled. Verify
   networking, credentials, model persistence and a complete recovery exercise.
3. Pause the Mac scheduler and confirm no scan is still running. Disable its
   automatic restart and manual worker path for this transferred instance; a
   local flock cannot stop a second host. Give the server a separately
   revocable app credential if the provider supports it. The Mac GUI becomes
   a remote controller after transfer. Never run two modifying owners.
4. With the instance quiescent, create the final consistent SQLite snapshot
   and model checkpoint. Include encrypted archives, their original age key,
   continuity metadata, configuration/folder mappings and a version manifest.
   Do not copy only the main SQLite file while WAL writes may be active.
5. Transfer through an encrypted channel. Import paths under the chosen server
   root, or migrate them to validated relative archive references. Verify every
   referenced archive against its recorded raw hash by decryption, plus DB
   integrity, account identity and model revisions. Never generate a new age
   key as a substitute for the old archive key.
6. Run a true dry-run on the server. Protect mode can move server-spam mail
   and process explicit training corrections, so it is not a read-only test.
   Require fresh operational authorization for this deployment even when the
   imported mailbox history is otherwise compatible.
7. Keep automatic INBOX sorting and permanent deletion off for initial server
   acceptance. Run a controlled live protect-mode pass, then verify item-level
   errors, expected destination hashes, zero unresolved moves/restores, current
   heartbeat and preserved learning state. Do not erase prior observation
   history or enable active mode merely because deployment succeeded.
8. Enable only the server schedule. Require a successful automatic run and a
   reboot followed by another successful scheduled run, with remote status,
   backup freshness and a current recovery receipt. The Mac remains fenced.

Before the first server mutation, rollback can use the final Mac checkpoint.
After the server has moved or learned mail, rollback must carry the server's
newest consistent journal, archives and model back to a compatible release or
host. Simply restarting the stale Mac installation would lose subsequent
decisions and is not a valid rollback.

## Required tests and completion evidence

Reuse the existing engine, IMAP, archive, installer and safety tests. Add tests
where the new boundaries introduce meaningful risk:

- Configuration v1 migration, stable identity, independent login name,
  legacy secrets and non-destructive rebranding.
- Endpoint/folder changes and missing or unreadable keys; no inherited
  activation or silent replacement of an archive key.
- Valid TLS and rejected certificate/auth cases; capability and special-use
  folder discovery; namespaces, duplicates and UIDVALIDITY changes.
- Missing COPYUID and interrupted MOVE reconciliation, malformed MIME,
  idempotent training, restore and preserved active-mode gates.
- Two isolated instances with different folders, state, credentials,
  controller ports, Docker resources, model and schedule identities.
- Genuine Linux execution and integration tests, service overlap prevention,
  reboot/missed-run behavior and absence of macOS/Colima dependencies.
- Interrupted install/update/migration; corrupt or stale backups; full disk,
  Redis persistence failure, unavailable storage diagnostics and expired auth.
- Off-machine restore including original-key archive decryption, compatible
  DB/model state and safe software/host rollback.
- Remote host-key handling, target-instance identity, bounded command transport,
  no arbitrary shell execution and no secrets in logs/arguments/receipts.

Completion requires the Mac regression checks and Linux checks to pass, a
second real provider to pass disposable-mail acceptance, and the chosen real
server to pass live-run, scheduled-run, reboot and restore checks. Report
fixture, compiler and real-service evidence separately. An early Linux build
or a healthy set of containers is insufficient to call the hosted app ready.
