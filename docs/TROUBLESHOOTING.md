# Troubleshooting

Start with the last actual successful run, its errors and pending operations.
Retain the current database, archive and trained model. Do not reset state or
repeat mailbox moves manually to hide a problem.

| Symptom | First action |
| --- | --- |
| Login rejected | Confirm provider, explicit host/port and login; check IMAP access and password/app-password policy. OAuth-only accounts are unsupported. |
| Connection fails | Check network, DNS, certificate and server availability. A connection failure is not proof the password is wrong. |
| Native MOVE unavailable | Leave automation off. Guardian refuses unsafe copy/delete fallbacks. |
| Wrong spam folder | Reopen setup, confirm the provider's real selectable folder and complete a fresh dry-run. |
| Important mail missing | Search Inbox/spam/quarantine/review, then use encrypted-backup recovery. |
| Spam stays in Inbox | In protect mode this is expected. Correct it through the spam-training folder. Check qualification before enabling active cleanup. |
| No recent success | Wake/check the Mac or inspect the Linux timer and journal. A healthy process is not a successful mail run. |
| Pending/ambiguous moves | Use Repair and another run; let exact-content reconciliation finish. Preserve backups. |
| Bayes rollback/reset | Keep purge off, preserve the newest good coherent model/state and follow recovery procedures. |
| Disk/Redis persistence failure | Stop service-impacting work, retain good backups and investigate storage. A responsive Redis process may still be unable to persist. |
| Missing archive key | Recover/unlock the original Keychain/credential secret. Do not generate a replacement over existing archives. |
| Identity mismatch | Check whether configuration belongs to another account/endpoint/host. Use a separate instance or reviewed migration. |
| Quality gate fails after 14 days | Read the specific blockers. Historical errors require reevaluation; waiting alone does not clear them. |

## macOS checks

Use **Check and repair** for the local stack and configuration. Use **Full check**
for account/folder checks. From the CLI, `guardian doctor --deep` diagnoses;
`guardian repair` performs supported repairs. These can connect to the real
mailbox, so run them only on its authorized owner.

Automatic mail checks, login-start of the UI and an open window are separate.
The Mac catches up a missed check once after waking. It cannot work while asleep.
The usual schedule is every two hours; Linux uses its own installed timer.

If installation fails, keep the log at
`~/Library/Logs/O2 Mail Guardian/instalacja.log` and any retained update backups.
The legacy path is intentional. Do not delete the current model or encrypted
archive to make installation succeed. See [installation](INSTALLATION.md).

## Linux checks

Follow [operations](maintainers/OPERATIONS.md) for the actual instance's unit,
configuration, credentials, journal, state and observer. Keep root-only
administration separate from the unprivileged worker. Do not start a local Mac
as fallback while the VPS still owns the mailbox.

Use [backup recovery](../deploy/linux/BACKUP.md) for a coherent restore and
[migration fencing](../deploy/linux/MIGRATION_FENCE.md) for ownership changes.
Before an update, preserve model/state; afterwards verify a real successful run.
A package manifest or running container does not establish mailbox health.

## Support evidence

Collect version, platform, last successful run, error code, pending-operation
counts, exact reproduction steps and the relevant non-secret logs. The desktop
Help page can create a restricted diagnostic archive. Review it before sharing.
Do not post passwords, archive keys, private messages, addresses or access-bearing
URLs. Use the [security policy](../SECURITY.md) for vulnerability reports.
