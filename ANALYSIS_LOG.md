# Engineering history

This public summary preserves implementation decisions, not private mailbox
observations or operator audit bundles. Current instructions are in the
[documentation index](docs/README.md). Historical notes are evidence of a past
design stage and must not be used as live deployment instructions.

## 0.6.1 publication — 1 November 2026

The public source now includes the later macOS filtering/scheduling repairs,
Linux worker, configuration binding, migration fence, model checkpoints,
encrypted recovery bundles, systemd credentials, observer, backup transport,
and coordinated server maintenance. See [CHANGELOG.md](CHANGELOG.md).

MOVE confirmation now retries read-only destination inspection after an OK
response without COPYUID, while retaining exact-content and UIDVALIDITY checks.
The previous memory-server test still emitted COPYUID despite withholding the
UIDPLUS capability; it was corrected to suppress the mapping on the wire.
Delayed visibility and unavailable ENVELOPE regressions failed before the fix
and pass afterwards. The native Linux full Go race suite, vet, scanner and
static builds passed before reference deployment. Publication CI separately
checks the complete public tree and its packages.

## Decisions maintainers must preserve

- A loaded timer or exit-zero helper is not proof of a successful mail pass.
  Match the actual SQLite run, heartbeat, deployment identity and pending state.
- Calendar scheduling can catch up after sleep; it cannot filter while a Mac is
  asleep. Reference server polling is five minutes; fresh package defaults and
  local Mac schedules are separate settings.
- Last confirmed explicit feedback controls the current class; historical ham
  feedback remains a veto against permanent deletion. Training-set replay is
  not independent filter qualification.
- Per-command deadlines bound IMAP work without expiring a healthy long-lived
  session. Cancellation must stop further message mutations.
- Database, archives and model must form a coherent recovery point. Do not
  restore an old model or resume stale Mac state after server-side changes.
- Provider Spam retention can delete mail independently of Guardian. Dedicated
  review/quarantine folders and an independently delivered outage alert matter.
- A provider's missing destination mapping is uncertainty, not permission to
  repeat MOVE or silently declare success.
- Native tests, container fixtures, a completed restore and live mailbox checks
  establish different things. Keep their scope explicit in every handoff.
