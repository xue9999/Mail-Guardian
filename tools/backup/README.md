# Encrypted VPS backup copies on the Mac

Run `python3 -I tools/backup/fetch_latest.py` to copy the newest completed
encrypted generation from `vps-1` into the private local directory
`~/.codex/backups/o2-guardian/vps-1-daily/`. The command uses the existing pinned
SSH alias, requires noninteractive key/sudo access, and times out within five
minutes. It never downloads plaintext, configuration or application passwords.

Only remote root-owned regular `*.age` files with a matching completed
`*.age.sha256` receipt are eligible. The command verifies the streamed size and
SHA-256 before publishing new local files. It preserves existing files on a
conflict and refuses symlink destinations. Keep the backup decryption key in
separate recoverable custody and perform an isolated restore drill.

The optional explicit command below installs and starts an hourly user
LaunchAgent, also invoked when the user session loads. It refuses to overwrite
an existing job. No agent is installed merely by building or testing the source.

```sh
python3 -I tools/backup/fetch_latest.py --install-agent
```

The job label is `pl.o2.mail-guardian.backup-pull`. Its small diagnostic logs are
under `~/.codex/backups/o2-guardian/backup-pull-logs/`. Failure to reach the VPS
leaves the last verified local generation unchanged; a later invocation retries.
The job copies the latest generation on each invocation, so a Mac that is
unavailable for several days does not necessarily retain every daily generation.

To remove only the job, keeping all downloaded backup data:

```sh
launchctl bootout "gui/$(id -u)/pl.o2.mail-guardian.backup-pull"
rm ~/Library/LaunchAgents/pl.o2.mail-guardian.backup-pull.plist
```
