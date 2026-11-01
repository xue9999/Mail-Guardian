# Desktop guide and first steps

Mail Guardian provides a native macOS window and menu-bar controls. The desktop
interface manages its local backend; it is not a complete remote control panel
for a Linux worker. A migrated Mac must remain retired until a reviewed ownership
transfer says otherwise.

## Setup: account, folders, dry-run

1. Select Custom IMAP and provide host, implicit TLS port, login, email and
   secret. Select the o2 preset only for that provider. Review the account
   preparation notes and use an app password where supported.
2. Probe the connection. Guardian verifies TLS, authentication and safe MOVE,
   then offers selectable spam folders. Confirm the actual provider spam folder
   and review the four Guardian folder names. A named server folder is not
   automatically safe merely because it contains the word spam.
3. Save and run the required dry-run. No message is moved, deleted or used for
   training during that run. An error or cancellation does not unlock automation.
   After success, choose manual mode or checks every two hours on the Mac.

Existing configured instances prefill the connection and keep its binding.
Changing servers/accounts requires a separate instance or reviewed migration.
Saving a replacement secret pauses scheduling and invalidates the previous
configuration's dry-run authorization. A failed login does not replace a valid
saved password.

## Overview

The dashboard presents current health, the last attempt/success, automation,
your next action, recent results and observation progress. A completed process
is not necessarily a successful run: errors and unresolved moves remain visible.
Stale data is marked and should be refreshed before making protection changes.
The menu-bar icon distinguishes observation, active cleanup and unknown status.

Use **Check mail now** for a real run under the current policy. A preview/dry-run
shows proposed decisions without moves or learning. **Check and repair** checks
the local stack and configuration; review reported failures rather than
repeatedly forcing operations.

## Training and corrections

Open your usual email client and the review folder shown by Guardian. Move
recognized spam into the spam-training folder, and legitimate mail into the
ham-training folder. The app displays and copies the configured names, including
legacy names on upgrades. The o2 webmail shortcut appears only for that profile.

Use **Check mail and process corrections** to process them immediately, or wait
for the next scheduled run. This also checks other eligible mail under the
current mode. Leave uncertain messages for later; do not create labels merely
to satisfy qualification counters.

## Recovery

The backup list shows the first local-backup date, category and status. Filter
by dates/category, select an entry and reveal sanitized sender/subject/date
headers to identify it. Content, links and attachments remain closed. Changing
selection or filters clears the previous preview.

Restore requires confirmation and uses the configured review folder. Guardian
checks whether the message already exists and avoids creating a duplicate.
Restoration does not send email. If the key or checksum cannot be verified,
restoration stops; see [security and recovery](SECURITY-AND-RECOVERY.md).

## Settings and help

Automation, application login start and protection mode are separate settings.
Closing the window does not stop the scheduled worker. Turning off application
login start does not disable mailbox checks. On a Mac the normal interval is
two hours; Linux schedules are managed separately by an administrator.

Active cleanup requires completed observation and quality evidence. The
confirmation word is `ACTIVE`. Permanent deletion is a separate advanced
permission with confirmation `ENABLE`; keep it disabled unless deliberately
qualified and authorized. Older protocol clients' confirmation words remain
accepted for compatibility.

The Help page links symptoms to recovery, training, repair and a full check.
A diagnostic report excludes message content, addresses, subjects and secrets;
review the generated archive before sharing it. Cancellation may leave already
completed safe steps recorded. Refresh status and let reconciliation finish.

Keyboard navigation is available through the Go menu and Command-1 through
Command-5. Existing accessibility labels and hints are retained in English.
Formal VoiceOver/usability qualification remains a separate activity.
