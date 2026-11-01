# Daily operation

Start with the dashboard's last successful run and next action. Guardian's job
is reversible cleanup with explicit user correction, supported by encrypted
backups and durable records. Keep permanent deletion off for ordinary use.

## Modes and decisions

- **Protect** leaves Inbox messages in place. Candidates from the provider spam
  folder may go to review. Explicit training corrections are still processed.
- **Active** quarantines confident Inbox spam and rescues qualified legitimate
  messages from spam. It requires an observation period of at least 14 days and
  evidence of decision quality. Uncertainty remains for manual review.
- **Dry-run** previews the selected policy without moves, learning or deletion.
  Complete a fresh successful dry-run after relevant configuration changes.
- **Purge** is separately authorized permanent deletion. It requires active
  mode, at least 30 full days of active history, 30-day quarantine, sufficient
  unique training evidence, UIDPLUS, a valid encrypted backup, exact identity/
  checksum, no legitimate-mail correction and a fresh complete spam scan.

Ordinary Bayes classification starts at 100 statistical examples per class.
Independent qualification uses separate training/tuning/held-out examples and
requires at least 40 spam and 30 legitimate test messages, at least 90% spam
recognition and zero false holds or false rescues. Without a qualified tuned
threshold, the conservative threshold is at least 12. Permanent deletion retains
its stricter threshold of at least 12 and minimum 200/200 training requirements.
See the architecture and code for the full gate definitions; counters alone do
not authorize a policy change.

Elapsed time does not erase false-positive history. Reevaluate filter quality
when instructed. Evaluation trains a separate model, preserves history and does
not itself activate cleanup. Never mislabel messages to pass a gate.

## Folders

| Purpose | Fresh-install name | Action |
| --- | --- | --- |
| Quarantine | `Guardian-Quarantine` | Reversible holding area for confident spam. |
| Review | `Guardian-Review` | Inspect uncertain/rescued candidates in your email client. |
| Spam correction | `Guardian-Train-Spam` | Move recognized unwanted mail here. |
| Legitimate correction | `Guardian-Train-Ham` | Move legitimate mail wrongly held here. |

Existing names remain unchanged. Use the app/configuration as the authority.
A successful correction is recorded against exact content and learned only when
valid. Invalid MIME can retain the explicit correction and move the original
without Bayes learning; it does not falsely increase progress. A later correction
supersedes the current class, while historical legitimate-mail evidence continues
to protect against automatic deletion.

Provider trusted-sender lists and spam rules remain separate. Guardian neither
synchronizes nor overrides those lists. A message can be moved again by another
client or server rule; investigate competing actors before changing Guardian.

## Command line

Run `guardian` without arguments for the menu, or use English commands:

```sh
guardian help
guardian setup                    # macOS account wizard
guardian status
guardian run --dry-run
guardian run
guardian doctor --deep
guardian repair
guardian mode status
guardian archive list --page 1 --limit 25
guardian archive show ID
guardian archive restore ID
guardian purge --dry-run
```

Only run live commands against the currently authorized mailbox owner.
On Linux use the explicit instance configuration and administrator procedures;
not all desktop commands are available there. Existing Polish command aliases
remain accepted. CLI output is English. Machine error codes and protocol version
remain stable.

## Schedule and health

The Mac checks at even local hours and catches up once after sleep/wake.
A sleeping Mac cannot provide continuous service. The stock Linux timer is
15 minutes; the reference deployment has a five-minute override. Use the
platform's actual installed schedule as the authority.

A check over four hours old needs attention in the desktop policy; over 48 hours
is critical. Pending operations are not a successful run. Repair and rerun using
the current coherent state. Do not repeat an IMAP MOVE manually or delete pending
records to make a status indicator green.

Local encrypted backups are retained at least 35 days and no less than the
quarantine period. A copied archive without its key and database is not complete
recovery. See [security and recovery](SECURITY-AND-RECOVERY.md) and the platform
runbooks before restoring or retiring a worker.
