# Mail Guardian

Mail Guardian is a self-hosted email assistant for IMAP mailboxes. It detects
spam left in your Inbox, helps recover legitimate messages placed in spam, and
learns from corrections you make in your usual email client. Rspamd performs
classification on your Mac or Linux server. Guardian does not send email or
open message links or attachments.

Previously named **O2 Mail Guardian**, the project now exposes provider-neutral
IMAP setup. The o2 connection remains a preset. This is a capability boundary,
not a claim that every email provider has been qualified: see
[provider support](docs/PROVIDERS.md).

## Start here

- **New user:** [installation](docs/INSTALLATION.md), then the
  [desktop guide](docs/DESKTOP-GUIDE.md).
- **Daily use:** [user guide](docs/USER-GUIDE.md),
  [troubleshooting](docs/TROUBLESHOOTING.md), and
  [security and recovery](docs/SECURITY-AND-RECOVERY.md).
- **Linux operator:** [server installation](deploy/linux/README.md),
  [operations](docs/maintainers/OPERATIONS.md), and
  [backup/restore](deploy/linux/BACKUP.md).
- **Developer taking over:** [documentation map](docs/README.md),
  [contributing](CONTRIBUTING.md), [architecture](docs/maintainers/ARCHITECTURE.md),
  and [release procedure](docs/maintainers/RELEASING.md).

## What it does

Guardian connects using verified implicit TLS and password/app-password
credentials. You confirm the provider's spam folder. It creates four folders
for quarantine, review, spam training and legitimate-mail training. New
installations use `Guardian-Quarantine`, `Guardian-Review`, `Guardian-Train-Spam`
and `Guardian-Train-Ham`; existing installations keep their configured names.

| Mode | Behavior |
| --- | --- |
| Dry-run | Previews decisions; no moves, learning or deletion. |
| Protect (default) | Leaves Inbox messages in place; spam-folder candidates may be moved to review; processes explicit training corrections. |
| Active | After observation and quality qualification, moves confident Inbox spam into reversible quarantine and rescues qualified legitimate mail. |
| Permanent deletion | Off by default, separately authorized and subject to stricter age, training, checksum and classification gates. |

Before moving a message, Guardian encrypts a full local copy and records its
intent. Move confirmation checks exact content and IMAP identity. Uncertain
or interrupted operations remain pending for reconciliation. It does not use
unsafe copy/delete fallbacks when native IMAP MOVE is unavailable.

The initial observation period is at least 14 days. Active cleanup requires
quality evidence as well as elapsed time. Simply waiting does not clear a
historical false-positive block. Permanent deletion has additional requirements,
including at least 30 days in active mode and retraining/rescan checks; ordinary
cleanup works with deletion disabled.

## Platforms and installation

The native desktop application targets Apple Silicon Macs with macOS 13 or
newer and uses Keychain for secrets. The supporting stack uses Colima,
Docker/Compose, Rspamd, Redis and Unbound. Linux uses systemd, private credentials
and a restricted administrator helper. Follow the platform guide; do not start
a second worker on a mailbox already owned by another installation.

Download only deliberately published artifacts from
[Releases](https://github.com/xue9999/Mail-Guardian/releases). GitHub's automatic
source archives are source code, not a prebuilt application. Local macOS
packages are ad hoc signed; Developer ID signing and Apple notarization are not
provided. Read the installation guide before running a package.

For a source build (no mailbox access):

```sh
git clone https://github.com/xue9999/Mail-Guardian.git
cd Mail-Guardian
make build build-recovery
make test
```

The desktop wizard and `guardian setup` accept custom IMAP host, implicit TLS
port and login. Linux configuration is explicit:

```sh
./bin/guardian server init-config --instance personal \
  --email owner@example.com --provider custom --host imap.example.com \
  --port 993 --username owner@example.com --server-spam Junk \
  --output /private/path/new-config.toml
```

Replace all example values with your provider's documented settings. This
command only creates configuration; it does not start services or authorize
mailbox work. The destination must be new and private. Follow the complete
Linux procedure for credentials, dry-run and scheduling.

## Correcting decisions

Use the folder names shown in the app or configuration:

| Your assessment | Action in your email client |
| --- | --- |
| Legitimate message in spam, quarantine or review | Move it to the configured ham-training folder. |
| Spam in Inbox or review | Move it to the configured spam-training folder. |
| Uncertain | Leave it for review. |

On the next run, Guardian records the correction, trains when valid and moves
the message to its destination. A legitimate-mail correction protects the exact
content from automatic permanent deletion. A provider's trusted-sender list is
separate; Guardian does not synchronize it.

## Compatibility and scope

Renaming the product does not migrate your mailbox or storage. Legacy macOS
paths, bundle/launchd identifiers, Keychain services, Docker names and existing
folder names remain stable. Old Polish CLI aliases remain accepted. See the
[upgrade contract](docs/PROVIDERS.md#upgrade-compatibility) before changing
account settings. Never edit a populated instance to point at a different
server; create a separate instance or use a reviewed migration.

The public source includes reference VPS maintenance tools. A GitHub merge or
release does not deploy to that VPS. Daily automatic updates stay within
approved major/minor lines; new lines need manual compatibility review. The
reference Mac worker remains retired and permanent deletion remains disabled.
Dated operational observations in the runbooks are not current health claims.

Mail Guardian is independent software, not an official service of any email
provider. Source is available under the [MIT license](LICENSE). Report security
issues using the [security policy](SECURITY.md).
