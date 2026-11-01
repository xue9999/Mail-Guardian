# Release and deployment procedure

A GitHub publication, a tested package and a live deployment are different
results. Publish source through the protected branch; promote a server release
only after explicit review and a current coherent recovery point.

## Public release

1. Fetch `origin` and inspect remote changes. Prepare an isolated branch/worktree
   so a developer's uncommitted work is not discarded or accidentally omitted.
   Include new implementation/tests deliberately; never use a blind `git add .`
   on a folder containing operator data.
2. Reconcile `VERSION`, changelog, GUI version metadata, documentation, dependency
   locks and the intended source generation. A reference server may be ahead of
   the last public tag. Compare manifests rather than copying its entire config.
3. Review the complete source diff and public paths. Include tests, package
   scripts, runtime helpers and every imported maintenance module. Exclude
   operator configurations, databases, trained models, archives, credentials,
   ping URLs, personal audit narratives and build caches/binaries.
4. Run `make check` on macOS, `make check-linux` on native Linux, `make check-docs`
   and the publication secret scan. Read skipped cases and the package fixture
   results; Linux installer stubs do not establish a real-host installation.
5. Open a PR with the problem/result, scope, safety implications, exact checks
   and material limits. Wait for the required macOS check and all other relevant
   checks. Do not bypass protection or claim a queued job passed.
6. Merge without overwriting another contributor's commits. Create an annotated
   `vVERSION` tag at the merged commit and a GitHub release with dated notes.
   A release tag must identify one reviewed source tree; do not move it later.
7. If attaching packages, build them from that tag, run their integrity checks,
   attach the corresponding `.sha256` files and state architecture/signing limits.
   Source-only publication is valid; do not attach a stale local installer or
   silently imply notarization/Developer ID signing.
8. Verify the remote branch, tag, release URL and CI result. Leave a handoff that
   identifies what was published and whether anything was actually deployed.

`make package` produces a macOS arm64 distribution. `make package-linux`
produces a static Linux amd64 candidate. Build outputs stay in ignored `dist/`.
Linux archives omit AppleDouble/xattrs, credentials and runtime state. The
package's `SHA256SUMS` and external checksum must agree. Read the release scripts
for accepted toolchains and local-signature checks before changing them.

The 0.6.1 publication retains its existing version number because it is the
first public publication of the later 0.6.1 source line, including the final
MOVE hardening. The reference server release identity
`0.6.1-auto-5d14558167ec2f54` additionally binds its immutable payload. A future
code release should increment `VERSION` and the owning GUI/package metadata
consistently rather than replacing the existing public tag.

## Mail Guardian 0.7 migration boundary

Version 0.7.0 is a new minor source line: English product/documentation and
explicit provider-neutral setup. The Go module is now
`github.com/xue9999/Mail-Guardian`. Existing 0.6.1 tags remain immutable.
Do not automatically promote this minor line to the reference VPS; manual
compatibility review, a coherent current recovery point and a supervised actual
run are required. The installed 0.6 patch coordinator remains on its approved
line until that review. See [provider compatibility](../PROVIDERS.md).

Preserve historical storage, credential, bundle/service/Docker identifiers and
v1 identity seeds while changing display strings. Fresh profiled installations
use random identities and English folder defaults; legacy loads keep their exact
configured names. Provider/host/login changes must not inherit state or send
saved secrets to a new endpoint. UI snapshots may expose connection and folder
metadata, never secrets or secret-store identifiers.

## Dependency exceptions that need deliberate review

- `github.com/emersion/go-imap/v2` is a preview API. A stable replacement or new
  major API requires a source migration and the protocol regression tests.
- The SASL module can use a publisher pseudo-version when there is no compatible
  stable tag. A pseudo-version is not blanket permission to track branch HEAD.
- `modernc.org/sqlite` and its required libc pairing must remain compatible.
  Do not independently bump libc because a scanner/updater suggests a new line.
- Unused legacy OpenPGP packages can have a module-level advisory without a
  known compatible fix. Imported/reachable findings must fail qualification;
  `scripts/reject-openpgp.py` prevents a later import from silently activating
  the exception.
- Go compiler patches require rebuilding the binary. Updating a compiler package
  on a machine does not patch a previously built static executable.

Record current fixes/blockers and next actions. Do not let these exceptions
silently exclude compatible same-line patches or new-line discovery.

## Existing Linux application: identity before activation

Use [maintenance](../../ops/vps-maintenance/README.md) for the installed owners.
A server release is immutable under `/opt/mail-guardian/releases`. Its manifest
covers runtime helpers, Compose pins, binaries and embedded `application-source`.
The private root-owned source channel records a file-hash allowlist, parent tree,
compiler, qualification configuration and applied binary hashes. This bounded
application-source snapshot is sufficient for its approved Go build/recovery;
it is not a complete public-repository checkout. The separate operations tree
and contributor-only root files may be absent. Clone the matching public tag
when running the full contributor/package/operations checks.

A published commit does not replace that channel automatically. Public source
may include documentation, packaging/host-checker improvements or Mac UI changes
beyond the exact deployed generation. Before a source promotion:

- Bind the candidate to a specific reviewed commit/file manifest and the current
  server source/binary identities. Review only deliberate changes; abort on drift.
- Export only that allowlist into a private staging directory. Never build a
  live mutable working tree as root with credentials/model mounts.
- Qualify on native Linux through the isolated builder, with current vulnerability
  data, approved compiler/image identities, full race tests/vet and static builds.
- Verify output hashes and the complete selected dependency graph. A few added
  `go.sum` download checksums can be harmless, but inspect them explicitly; they
  are not evidence of a dependency-version upgrade.
- Preserve the running release's Compose/helper/configuration and image pins.
  A locally packaged default stack must not overwrite the trained deployment.

## Source promotion versus dependency promotion

The normal application updater's CLI is **dependency/compiler maintenance**, not
a general code-deployment command. `--apply-qualified` accepts its particular
reviewed dependency-candidate format and requires unchanged application source
apart from the module files. Do not forge that receipt or relax its checks to
smuggle a code patch through it.

The installed application module exposes the building blocks used in the
reviewed 1 November source patch. This remains a deliberate administrator
procedure, not an unattended public-source channel:

| Step | Owning implementation | Required guard |
| --- | --- | --- |
| Validate/export source | `application/source_snapshot.py` | Explicit bounded file allowlist, exact hashes, no links, root-controlled generation |
| Build candidate | `application/builder.py` | Read-only source, no live secrets/state, bounded unprivileged containers, current scan, offline tests/builds |
| Register approved source | `application/updater.py:source_record` | Reviewed manifest, parent tree, exact compiler and candidate binary hashes |
| Stage release | `application/updater.py:make_release` | Current release integrity and no runtime/Compose drift; embedded recoverable source |
| Activate | `application/updater.py:activate` | Hold `/run/mail-guardian-auto-update.lock`, reject every foreign pending transaction/marker |
| Coherent capture and switch | `simple-updates/guardian_images.py:locked_update` | Stop scheduling, wait for active jobs, hold migration/maintenance locks, stop scanner writes, capture model/database/archives |
| Verify and publish baseline | `activate` and `promote_from_current` | Supporting-service/SSH checks, actual successful Guardian pass, timers restored, source pointer matches installed binaries |

An administrator using these functions must validate the independently reviewed
qualification receipt SHA-256, current baseline and binary hashes immediately
before staging, and retain a journal owned by the normal application recovery
service. The global lock spans staging/activation; no updater or worker fence is
removed merely for its age. Preserve the coherent-backup receipt privately.
A generic code-promotion CLI is a future improvement and would need its own
adversarial fixture tests before replacing this explicit review step.

After a failed activation, inspect the durable journal and actual state before
starting the owning `guardian-application-update-recover.service`. Recovery goes
forward with current compatible VPS state; it never restores stale Mac data or
downgrades the trained model. Keep an ambiguous deployment fenced and notify the
owner with a concrete blocker and next action.

## Postflight and handoff

Use a new authenticated external SSH connection after service impact. Verify
scanner authentication, DNS, Redis persistence/model state, actual SQLite run
and matching heartbeat, zero unresolved work, enabled intended timers and the
observer's status signal. HTTP delivery is not owner-notification receipt.
Capture a post-change encrypted generation and verify its off-server copy.
A new restore drill is required when the change affects the recovery format or
compatibility; checksum transfer alone is not restore proof.

Record commit/tag, immutable release, source and payload hashes, compiler/module
versions, backup generation, actual run ID/errors and all remaining limits.
Update the private deployment record; keep credentials, mailbox histories and
raw operational logs out of the public release. Retain release generations until
the operator's recovery/retention policy permits removal.
