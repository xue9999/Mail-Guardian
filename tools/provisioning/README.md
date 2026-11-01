# Hidden Healthchecks credential provisioning

## Separate VPS o2 app password

Create an o2 application password named **Guardian VPS-1**, keeping the existing
Mac Guardian password active until the actual ownership handover. Then run the
following command yourself in a real Terminal from the Guardian checkout:

```sh
python3 tools/provisioning/imap.py --provision
```

The two prompts hide the password and must match. Do not put the password in
chat, shell arguments, environment variables or a repository file. The helper
sends it only on pinned SSH stdin and exclusively creates the root-owned
mode-0600 file `/etc/mail-guardian/pilot/credentials/imap-password`. It refuses
an existing file, redirected input and any fallback that would echo input.
Running without `--provision` previews the fixed destination without connecting.
It does not log in to o2, revoke the old password or start the VPS worker.

If delivery fails, inspect the destination's metadata through administrative
SSH before retrying: a connection failure can occur after private publication.
Never print the file contents or overwrite an uncertain credential.

## Optional Healthchecks URL

`healthchecks.py` prepares one optional monitoring credential on the existing
`vps-1` SSH target. It does not install or enable the observer, send a ping, read
mail, change other credentials or rotate an existing credential. The external
account and tested alert delivery are separate acceptance work.

Run these commands from the Guardian checkout root. Inspect the plan without
connecting:

```sh
python3 tools/provisioning/healthchecks.py
```

Once the external check exists and the reviewed release/provisioning stage is
ready, run this command **yourself in a real Terminal**. Account creation alone
is not an instruction to populate the current empty pilot prematurely:

```sh
python3 tools/provisioning/healthchecks.py --provision
```

Enter the canonical `https://hc-ping.com/<UUID>` URL at the hidden prompt. Do not
paste it into chat, a command argument, an environment variable or a file in the
repository. The helper refuses redirected input and getpass echo fallback. It
uses the existing `vps-1` key and known-hosts configuration, requires strict
host-key checking, disables agents/forwards/proxies/multiplexing, and sends the
URL only on encrypted SSH stdin to a fixed sudo Python command.

The remote command accepts no configurable path. It requires root-owned,
non-writable, non-symlink ancestors and a root-owned mode-0700 credential
directory, then creates exactly:

```text
/etc/mail-guardian/pilot/credentials/healthchecks-url
```

Publication is mode 0600, synced, atomic and refuses an existing object. It
does not create missing directories or overwrite an existing URL. An interrupted
or failed request can have an uncertain result, including a credential already
published before a final sync/connection failure. Inspect its metadata through
the authenticated administrator path before retrying; do not print the secret
or delete/reset uncertain files automatically. A crash between link publication
and temporary-name removal can leave a second link; the observer rejects such
an unsafe credential until an administrator reconciles it.

The helper suppresses dependency diagnostics and bounds SSH output/time. It
cannot make a compromised administrator or SSH configuration trustworthy, erase
immutable Python strings from memory, establish backup health, or prove that a
notification reaches the intended recipient. Its only successful result is a
new private credential file; monitoring remains inactive until its reviewed
service is installed and accepted separately.

Run synthetic tests without credentials, SSH, or an external service:

```sh
python3 -m unittest discover -s tools/provisioning -p 'test_*.py'
```
