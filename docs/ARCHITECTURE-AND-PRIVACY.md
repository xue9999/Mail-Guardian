# Architecture and privacy

Mail Guardian is a mailbox client and local classifier coordinator. It is not
a mail server or delivery gateway. The Go backend connects to the configured
IMAP server, obtains full messages safely, asks a local Rspamd instance for a
verdict and records actions in SQLite. The Swift application presents status,
setup, corrections and recovery on macOS. Linux runs the same mail engine under
systemd with a restricted administration boundary.

## Data flow

1. Verified TLS connects to your configured IMAP host. Credentials are read from
   the platform secret store after mailbox identity checks.
2. Guardian scans bounded folder pages. Rspamd analyzes delivered email using
   local rules and the Redis Bayes model. SMTP greylisting is disabled for this
   already-delivered-mail scan; real scan errors still matter.
3. Before a move, Guardian encrypts the full original locally with age and
   records a durable operation. Moves require native IMAP MOVE.
4. Confirmation uses UID, UIDVALIDITY and exact content/SHA-256. Ambiguity or
   interruption remains pending for reconciliation; it is not success.
5. User corrections recorded through training folders teach the local model
   where valid. Model continuity and persistence are checked and backed up.

See the [maintainer architecture](maintainers/ARCHITECTURE.md) for component
ownership, state transitions and the source files that enforce each contract.

## Network and privacy boundaries

Message bodies are submitted to the locally deployed Rspamd service, not an
external language-model API. Guardian does not follow message links, execute
attachments, open HTML in a browser or send email. A Linux-hosted installation
processes mail on that server, so the server and its administrators are part of
your trust boundary.

Rspamd/Unbound may perform DNS and reputation checks, including domain/IP-related
queries. Package managers and container tools contact their configured sources
for updates. Thus local classification does not mean the entire system is
network-isolated. Your email provider continues to hold and process your mail.

SQLite stores operational metadata and state. Full local message copies are
encrypted, but encryption does not hide data already available to an authorized
running worker. Protect the machine, account, Keychain/credential delivery and
backup recipient keys. Diagnostic exports are deliberately restricted; inspect
any artifact before sharing it.

## Limits

No spam filter guarantees zero mistakes. Observation, conservative thresholds,
review folders, explicit corrections and encrypted backups reduce the impact.
A successful synthetic test is not a provider certification, security audit or
proof of current production health. Unsupported OAuth and provider semantics are
listed in [provider support](PROVIDERS.md).

The repository contains no production mailbox credentials, messages, trained
models or operator audit archives. Dated deployment descriptions explain the
reference environment; source publication does not deploy or activate it.
