# Guardian application and Go dependency maintenance

The [update policy](../../../README.md) and
[shared maintenance/recovery contract](../README.md) apply. Use the
[deployment record](../../../../../docs/maintainers/OPERATIONS.md) for installed
versions/acceptance and the [evidence index](../../../../../docs/README.md) for native
qualification, source/binary bindings, restore proof and archived detail.

## Trust and coverage

Dependency/compiler maintenance uses a private, approved immutable source
allowlist; it does not overwrite the Mac checkout or publish unfinished work.
The [owner repository](https://github.com/xue9999/Mail-Guardian) is monitored
for stable tags. New application code needs a reviewed Linux-compatible source
generation: an older Mac release or unreviewed working tree is not an automatic
server update.

The builder verifies official Go release metadata, the exact `library/golang`
image digest/amd64 platform and actual compiler version. Toolchain auto-switching
is disabled. Modules use `proxy.golang.org` and `sum.golang.org`, with explicit
stable patch plans in approved major/minor lines and publisher-retraction checks. Known exceptions remain
explicit: SQLite's exact upstream libc pairing; approved IMAP preview/tagless
pins where no compatible stable release exists; and new-major API migrations
requiring reviewed source. A module-level advisory affects unimported OpenPGP
packages and has no known fix. Scans are bounded by the Go database/build
configuration, not proof of zero vulnerabilities; inspect JSON findings rather
than trusting its exit code alone.

## Qualification and promotion

Containers run as UID 65534 with bounded CPU, memory, PIDs, output and lifetime.
They receive read-only approved source and private scratch, with no operational
credentials, mail/model volumes, SSH keys or Docker socket. Downloads/scanning
have a separate network phase; race tests, vet and Linux builds run offline.
Root-owned shared scratch ancestors are **01777**, with caller-private temporary
descendants and disk-backed `GOTMPDIR`/`TMPDIR`. Preserve this layout rather than
weakening the application's recovery-catalog ownership policy.

Only `go.mod`/`go.sum` may change. Root ingests fixed outputs through bounded
non-following checks on every ancestor and leaf, requiring bounded single-link
regular files and refusing extra source changes. The two binaries overlay a verified current release,
preserving live Compose, helper, configuration and image pins. Approved source
is embedded as `application-source/`, covered by the release manifest and
ordinary encrypted backup. A verified restored release can reconstruct a
missing private source generation.

The shared fence/backup/postflight governs activation. Source-pointer promotion
follows a successful actual Guardian pass; startup reconciles interrupted
publication. State is `/var/lib/mail-guardian-application-update/`:
`pending.json` owns a transaction, `baseline.json` points to immutable `sources/`,
and `last-failure/` keeps bounded private phase logs plus reason/next action after
scratch/cache cleanup. Recovery preserves current VPS data and stays fenced
when state is ambiguous.

## Operator commands

```sh
systemctl status guardian-application-update.timer guardian-application-update.service
journalctl -u guardian-application-update.service -u guardian-application-update-recover.service -n 100
sudo python3 -I /opt/vps-maintenance/security-maintenance/simple-updates/application/updater.py --check
```

`--check` inspects channel/source discovery and refuses pending transactions;
it does not build, activate or recover. `--qualify-only` forces the native sandbox
even when discovery is unchanged and never activates a changed candidate.
Normal daily jobs skip cold builds when dependency/compiler/scanner/database
inputs match the accepted fingerprint; new inputs require qualification. Extra
`go.sum` download checksums alone are not a module-version or binary upgrade;
compare the qualification's module/payload identities (see the evidence index).

For an explicitly reviewed dependency candidate in a root-controlled private
inbox, substitute its own paths and reviewed receipt digest:

```sh
sudo python3 -I /opt/vps-maintenance/security-maintenance/simple-updates/application/updater.py \
  --apply-qualified /root/REVIEWED-CANDIDATE \
  --qualification-sha256 EXPECTED_RECEIPT_SHA256
```

Do not replay an archived bootstrap digest as routine maintenance.
`--adopt-qualified` is limited to the matching already-installed binaries and
recoverable embedded source; it is not evidence of an unobserved mailbox pass.
New major/minor dependency/compiler lines need manual qualification and a
reviewed baseline; scheduled discovery retains compatible patches and records
held dependency versions. New app-code publication is a separate reviewed-source workflow.

Local tests (fixtures and an available-Go temp-directory probe):

```sh
python3 -m unittest discover -s ops/vps-maintenance/security-maintenance/simple-updates/application -v
```


Manual new-line review can run `updater.py --qualify-only --allow-new-lines`.
After reviewing the complete candidate and its qualification, the operator can
use `updater.py --allow-new-lines` or the qualified-inbox promotion workflow.
The daily service never supplies this flag. New-major import/API migrations
still require an approved application source revision.
