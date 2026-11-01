# Documentation map

Start here when taking over Guardian. Current user and maintainer documentation
is in English. Commands in the server guides
can affect real mail: run tests in an isolated checkout and identify the current
mailbox owner before operating a deployment.

| Task | Canonical document |
| --- | --- |
| Build, test, change code, open a PR | [Contributor guide](../CONTRIBUTING.md) |
| Understand components, trust boundaries and durable states | [Architecture](maintainers/ARCHITECTURE.md) |
| Inspect health, diagnose failures, back up or restore | [Operations](maintainers/OPERATIONS.md) |
| Maintain Ubuntu, Docker, images and the application | [Maintenance source and policy](../ops/vps-maintenance/README.md) |
| Prepare a release or promote reviewed server source | [Releasing](maintainers/RELEASING.md) |
| Provision a fresh Linux host | [Linux installation](../deploy/linux/README.md) |
| Capture/restore encrypted bundles | [Backup format and procedure](../deploy/linux/BACKUP.md) |
| Transfer ownership safely | [Migration fence](../deploy/linux/MIGRATION_FENCE.md) |
| Report a vulnerability and avoid disclosing secrets | [Security](../SECURITY.md) |
| Understand release history | [Changelog](../CHANGELOG.md) |

## User guides

[Installation](INSTALLATION.md), [GUI and first steps](DESKTOP-GUIDE.md),
[daily operation](USER-GUIDE.md), [privacy](ARCHITECTURE-AND-PRIVACY.md),
[safety and recovery](SECURITY-AND-RECOVERY.md), and
[troubleshooting](TROUBLESHOOTING.md).

[Provider support and upgrade compatibility](PROVIDERS.md) documents the IMAP
contract, fresh defaults and preserved legacy identifiers.

## Source and deployment status

Version 0.7.0 adds English interfaces/documentation and explicit custom IMAP setup;
see [the provider contract](PROVIDERS.md). The preceding 0.6.1 public source includes macOS fixes after the last public 0.5.1 release,
a Linux worker, model/database handover tools, backup/recovery, monitoring,
configuration/provider boundaries and the missing-COPYUID hardening.
The reference server's reviewed application release on 1 November 2026 is
`0.6.1-auto-5d14558167ec2f54`. Its actual postflight run succeeded with zero
errors and no unresolved operations. That dated observation is not a current
health guarantee and is not fourteen-day acceptance.

| Capability | Scope and limits |
| --- | --- |
| Linux mailbox worker | Reference installation on Ubuntu 26.04; one active owner; permanent deletion disabled. |
| macOS application | Native UI, local worker for new Mac installations, mock-backed tests and installer/rollback checks. The migrated owner's Mac worker remains retired. |
| Remote control | SSH status bridge and backup pull tools. It is not a complete remote GUI replacement or automatic failover. |
| Ubuntu 24.04/26.04 CI | Native runner and disposable installation checks configured; use the actual workflow result for each publication. |
| Ubuntu 26.10 | Host/basic runtime qualification described in the Linux guide; no production distribution migration claim. |
| Custom IMAP/provider abstraction | Explicit password authentication and configuration binding; no Gmail/Microsoft OAuth implementation claim. |
| External observer | Checks actual successful work, not merely a running process. The owner must provision an independent destination and test delivery. |
| Automatic maintenance | Daily approved-line patches; new major/minor lines require manual review; no source auto-deployment from GitHub. |

The stock Linux worker timer is fifteen minutes. The reference operations
profile installs a five-minute override. The Mac's local schedule is separate.
Do not infer one deployment's schedule from a different platform's default.

## Historical designs

[Engineering history](../ANALYSIS_LOG.md) summarizes durable lessons.
[Original server plan](GENERALIZATION-AND-SERVER-PLAN.md),
[capture design](CAPTURE-ORCHESTRATION-DESIGN.md),
[Redis handover design](REDIS-MODEL-HANDOVER-DESIGN.md),
[old-owner fence design](MAC-OLD-OWNER-FENCE.md), and
[initial pilot note](VPS1-PILOT-2026-10-30.md) retain historical context.
Their original “not deployed” statements are not current runbooks. Private
mailbox evidence, credentials, model files and operator audit archives are
intentionally absent from GitHub.
