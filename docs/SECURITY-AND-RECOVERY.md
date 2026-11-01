# Security and recovery

Guardian's safety depends on exclusive mailbox ownership, verified encrypted
transport, durable state, a recoverable model and exact-message confirmation.
Keep permanent deletion disabled unless separately qualified and authorized.

## Secrets and storage

The Mac stores IMAP, Rspamd controller and age archive secrets in Keychain.
Linux reads private systemd-delivered credentials; the worker cannot administer
Docker directly. Do not put secrets into TOML, Git, command arguments or logs.
A missing/corrupt archive key is not replaced automatically when earlier data
exists. Unlock or recover the original key instead of generating a new one.

The product rename preserves old storage paths, identifiers and folder names;
see [compatibility](PROVIDERS.md#upgrade-compatibility). Configuration/account
fingerprints prevent a populated database being reused with a different mailbox.
Folder/policy changes invalidate relevant authorizations. Do not bypass a
fingerprint error by deleting state.

## Recover an individual message

1. Check Inbox, provider spam, quarantine and review in your email client.
   Search by date/sender/subject. A message may have been moved by another rule.
2. If it is still present, move legitimate mail to the configured ham-training
   folder. Let Guardian process the explicit correction.
3. If missing, open Recovery or `guardian archive list`. Reveal sanitized
   headers for one selected entry; the body is not rendered.
4. Confirm restoration to the configured review folder. Guardian decrypts and
   checks the full message and ownership, then checks for an existing copy.
5. Inspect it in your email client and correct its classification if needed.

Archive restore uses IMAP APPEND; it does not send SMTP mail. Interrupted or
ambiguous restores reconcile before retrying. A duplicate match, changed
UIDVALIDITY, missing key or checksum mismatch stops the operation. Keep the
archive and database, record the error and investigate. Do not repeatedly append
or move mail manually to work around an unresolved operation.

## Back up a whole installation

A coherent recovery point includes configuration, SQLite state, encrypted
message archive, corresponding archive key, Rspamd/Redis trained model and
metadata needed to verify them. Keep secrets encrypted with private permissions.
Do not copy only a live SQLite file while ignoring its WAL. Use the platform
backup/export tools and verify their output.

The model cannot be reconstructed from a message archive alone. A model rollback
or failed persistence check blocks work or returns to protect mode and disables
purge. Preserve the newest good model/database/archive set. Do not replace it
with stale pre-migration Mac state.

For Linux, use the [encrypted bundle procedure](../deploy/linux/BACKUP.md) and
[operations runbook](maintainers/OPERATIONS.md). Before a service-impacting update,
preserve a current coherent recovery point including the model; after the update,
verify SSH, supporting services and an actual successful Guardian run. An image
pull, healthy container or package check is insufficient evidence.

## Transfer or rebuild

Fence the old worker first and prove exclusive ownership. Capture current state,
verify/import it, adopt only validated policy history, complete a fresh dry-run,
then supervise a real run and backup. Enable timers last. Follow the
[migration fence](../deploy/linux/MIGRATION_FENCE.md). Restoring files does not
by itself authorize the worker to mutate mail.

If recovery cannot be confirmed, leave scheduling off and retain evidence. Do
not empty archives, reset protection history or enable deletion as a repair step.
Use [troubleshooting](TROUBLESHOOTING.md) and report vulnerabilities according to
[SECURITY.md](../SECURITY.md) without sharing credentials or message content.
