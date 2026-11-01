# Email provider support and compatibility

Mail Guardian supports a protocol contract rather than a list of assumed
provider brands. Read your provider's current IMAP documentation before setup.
Do not infer support from the domain part of an email address.

## Connection contract

| Requirement | Implementation |
| --- | --- |
| Transport | IMAP over implicit TLS with certificate/hostname verification; normally port 993, configurable for custom servers. No plaintext or STARTTLS mode. |
| Authentication | Password or provider-issued app password, using IMAP LOGIN. The login may differ from the email address. |
| Safe moves | Native IMAP MOVE is required. No COPY plus broad EXPUNGE fallback. |
| Folder access | Read Inbox/spam and create/use quarantine, review and training folders. Confirm the actual spam folder during setup. |
| Identity | Stable account/instance IDs and mailbox fingerprint bind state to host, port, login, email, profile and authentication method. |
| Recovery | Full content, SHA-256, UID and UIDVALIDITY confirmation; uncertain results stop for reconciliation. |
| Permanent deletion | Disabled by default; UIDPLUS and all independent deletion gates are required if separately enabled. |

OAuth2/XOAUTH2, POP3, SMTP sending, Exchange APIs and provider-specific label
semantics are not implemented. A provider requiring OAuth cannot be used merely
by entering its IMAP hostname. App-password availability is an account/provider
policy; Guardian does not create one or bypass that policy. Gmail and Microsoft
accounts have not been certified by this change.

## Profiles

- **Custom IMAP** is the default in new desktop, CLI and Linux setup. Supply the
  host, implicit TLS port and login explicitly. The login defaults to the email
  address only when omitted. A missing custom host is rejected before login.
- **o2** is an optional preset for `poczta.o2.pl:993`. It retains compatibility
  with the original deployment. A different endpoint requires `custom`.
- Legacy configuration v1 and protocol-1 setup requests without profile fields
  retain their historical o2 meaning. Omitted fields in an existing custom
  installation retain its configured connection; they never redirect it to o2.

The reference live deployment has been observed with o2. Generic configuration,
separate login names, protocol behavior and identity rejection have synthetic
regression coverage. That coverage does not establish end-to-end qualification
with any other commercial provider.

## Fresh setup

The desktop wizard exposes the connection profile, hostname, port, login,
email address and secret. It probes the server before showing selectable spam
folders. It displays the actual Guardian folder names returned by the backend.
Confirming folders saves credentials only after successful authentication;
a successful dry-run remains mandatory before enabling scheduling.

`guardian setup` provides the same connection choices on macOS. For Linux:

```sh
guardian server init-config --instance personal --email owner@example.com \
  --provider custom --host imap.example.com --port 993 --username login-name \
  --server-spam Junk --output /private/path/new-config.toml
```

For the o2 preset, use `--provider o2` instead of `--provider custom --host ...`.
No services start during configuration creation. See the
[Linux installation guide](../deploy/linux/README.md) for credential ownership,
acceptance and timer activation.

## Upgrade compatibility

The displayed product is Mail Guardian; the canonical repository is
[Mail-Guardian](https://github.com/xue9999/Mail-Guardian). The following historical
identifiers intentionally remain stable:

- `~/Library/Application Support/O2 Mail Guardian`,
  `~/Applications/O2 Mail Guardian.app`, the existing log directory and
  `~/.config/o2-mail-guardian` (or its XDG override).
- Keychain service IDs, bundle/launchd IDs, executable/Swift target names,
  Docker project/volume identifiers and deterministic v1 identity seeds.
- Existing folder names, including `AI-Kwarantanna`, `AI-Do-sprawdzenia`,
  `AI-Naucz-spam` and `AI-Naucz-wazne` where configured.
- Existing Polish command aliases and legacy setup JSON field spellings.

Fresh explicitly profiled installations receive independent random identities
and English folder names. Loading an existing configuration never renames its
folders or rewrites its credentials. Legacy v1 loading preserves its deterministic
identity, allowing the same existing state to be adopted safely.

Reconfiguration preserves the existing account binding. Changing the host,
port, login or profile in a populated instance is rejected before saved secrets
can be sent elsewhere. Do not bypass this guard by deleting the database.
Use a separate isolated instance or a reviewed migration with a coherent backup,
model continuity and exclusive mailbox ownership.

## Qualifying another provider

Use a dedicated test mailbox, synthetic messages and a separate data directory.
Verify TLS, login, folder delimiter/names, MOVE capabilities, flags, exact-content
confirmation, missing-COPYUID behavior, ambiguous duplicates, interruption and
archive restore. Confirm spam-folder selection and a clean dry-run. Inspect
actual successful runs before enabling a schedule. Keep permanent deletion off.
Record provider/account restrictions, date and tested behavior without publishing
credentials or private messages. Test results for one provider/account do not
qualify another provider automatically.
