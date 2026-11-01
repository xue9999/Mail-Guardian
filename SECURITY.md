# Security and mail-safety policy

Guardian reads private mail and can move it. Treat a release/deployment failure
as a data-integrity problem as well as a service outage. The newest published
source is the maintenance baseline; historical tags are reproducibility points,
not promises of backported fixes.

## Report privately

Use GitHub's **Security → Report a vulnerability** if private reporting is
enabled for this repository. Otherwise contact the repository owner through an
established private channel. Do not put a password, healthcheck ping URL,
private key, raw message, database, encrypted backup plus decryption material,
or unredacted logs in a public issue. A public issue may describe a redacted
reproducer using synthetic mail when disclosure is appropriate.

Include the commit/tag, platform, relevant configuration *shape* with values
redacted, expected/observed behavior and a synthetic reproducer. Keep exploit
artifacts private until the owner has reviewed them. Do not use the owner's
mailbox or VPS to demonstrate a bug without explicit authorization.

## Boundaries that must remain intact

- Exactly one active mailbox worker; failover requires a deliberate ownership
  transfer using current state. An old Mac snapshot is not a recovery source.
- Fresh installations start in protect mode. Active filtering depends on
  persisted quality/history and fresh configuration authorization.
- Permanent deletion is disabled in the reference server and Linux contract.
  Do not weaken its distinct quality/retention safeguards elsewhere.
- Archive-before-move, exact-content reconciliation, UIDVALIDITY binding and
  durable intent protect against uncertain provider replies.
- Rescue-to-inbox retains authentication requirements. Contacts or sender names
  alone are not a trusted-sender bypass.
- Root-owned credential delivery and bounded maintenance dispatch; the mail user
  must not receive Docker-group membership, the Docker socket or general sudo.
- Rspamd binds to loopback; Redis and Unbound remain private to Compose. Verify
  Docker exposure independently of UFW, including IPv6 where available.
- Untrusted build/scan containers receive no live credentials, mail/model mounts,
  SSH keys or Docker socket. Downloads and offline tests are separate phases.

## Vulnerability checks and supply chain

`make vuln` runs the pinned `govulncheck` version and rejects compiled imports
of legacy OpenPGP. A module-only advisory in unused legacy packages is distinct
from an imported/reachable finding; explain the exception rather than asserting
there are no vulnerabilities. Scan results depend on the database and build
configuration and are not a full security audit.

Container references use version plus digest. Updating a pin is allowed after
qualification; a pin is an identity, not a reason to stop patch discovery.
Actions are pinned to reviewed commits. Review new version lines deliberately.
Checksums establish artifact identity and corruption detection; a checksum
served beside a file does not independently authenticate its publisher.

See [architecture](docs/maintainers/ARCHITECTURE.md),
[operations](docs/maintainers/OPERATIONS.md), and
[releasing](docs/maintainers/RELEASING.md) for the owning procedures.
