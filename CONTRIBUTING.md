# Developing Guardian

Read [the architecture](docs/maintainers/ARCHITECTURE.md) before changing mail
moves, training, persistent state or recovery. Use a branch and a synthetic
fixture. Building or testing must not log in to a real mailbox or start the
operator's local/remote worker.

## Toolchains and prerequisites

- Go: follow `go.mod` and its `toolchain` directive. The reference build uses
  Go 1.27.3. Release scripts enforce the accepted compiler security floor.
- Python 3.11 or newer for TOML and deployment helpers; native Ubuntu 26.04
  uses Python 3.14. Python fixtures use only the standard library.
- macOS: Apple Silicon, full Xcode/Swift 6 for the native UI, and normal Apple
  signing tools for local packages. Runtime minimum is macOS 13; one modern
  test host does not establish compatibility with every older macOS release.
- Linux: an amd64 Ubuntu runner for native acceptance. Docker/Compose and a
  disposable host/container are needed for installation/runtime qualification,
  not for ordinary Go unit tests.

```sh
go version
python3 --version
make test                 # synthetic Go tests
make build build-recovery
```

Do not install Guardian on the developer's machine just to test a code change.
Do not run `guardian run`, provisioning helpers, migration/import tools or any
root updater against an operator's configuration as a substitute for tests.

## Required checks

| Change | Check |
| --- | --- |
| Go behavior/state machine | `go test -race ./...` and `go vet ./...` |
| Dependencies, compiler or release | `make vuln` and platform package checks |
| Linux worker, helpers or credentials | `make check-linux` on native Linux |
| macOS UI, backend API, installer or public release | `make check` on macOS |
| Server maintenance | `make check-maintenance`; native Linux fixtures/qualification for service impact |
| Documentation | `make check-docs` |

`make check` includes Go race/vet, the reachable-vulnerability check, explicit
OpenPGP import rejection, Swift tests, mock GUI flows, storage checks, installer
failure/rollback fixtures, Linux package checks, operational Python suites and
local documentation-link validation. `make check-linux` covers Go, the Linux
package and operational suites without needing Swift. Each maintenance suite
runs in a fresh Python process to avoid collisions between modules named
`engine` or `updater`.

For a synced-folder Swift signing problem, move only the build scratch directory:

```sh
export GUARDIAN_SWIFT_SCRATCH_DIR="$(mktemp -d /tmp/guardian-swift.XXXXXX)"
make check
```

The scratch directory must be private to this build. Its location does not
change Xcode selection globally or start any installed application. Shell
fixture tests use temporary destinations and a mock backend. Some Linux-only
system-call cases may skip on macOS; native Linux CI must cover them.

The maintenance fixtures never invoke production updaters. Journal tests need
non-world-writable ancestors, so one legacy suite creates disposable subfolders
under `~/.codex/backups/vps-1`; it removes its own temporary children. Use a
throwaway CI home when reviewing changes to those fixtures.

## Add meaningful regressions

Reproduce the failure on the previous implementation first. Exercise the
protocol/state boundary, not a helper that simply repeats the new algorithm.
Include failure or ambiguity cases when a false success could move/delete mail,
lose model state, expose credentials or hide a failed run.

Examples worth extending:

- `internal/imapmail/move_confirmation_test.go` removes COPYUID on the wire
  and checks delayed visibility, duplicates, UIDVALIDITY changes and cancellation.
- `internal/engine/hardening_test.go` and `reconcile_size_test.go` cover durable
  intent, complete-message confirmation and recovery without duplicate moves.
- `internal/store/*_test.go` cover authorization, deployment binding, feedback
  history and transaction semantics.
- `deploy/linux/test_*.py` cover ownership, package verification, credential
  delivery, backup and observer boundaries.
- `ops/vps-maintenance/security-maintenance/simple-updates/*/test_*.py` cover
  qualified patch selection, package plans, fencing, interruption and recovery.

An in-memory server may send COPYUID even when it does not advertise UIDPLUS.
The missing-mapping tests assert that the response was actually suppressed.
Never silently weaken production checks to make a fixture pass.

## Change and review process

1. Keep the change small enough to explain its trigger, new behavior and failure
   handling. Preserve unrelated working-tree changes.
2. Update the canonical guide and changelog when behavior, commands, defaults,
   state formats or recovery requirements change. Historical plans get a dated
   supersession note rather than being presented as current instructions.
3. Run the checks appropriate to the change. Record platform, compiler, exact
   command, result and limits. “Configured CI” is not “CI passed.”
4. Inspect `git diff --check`, untracked files and the publication secret scan.
   Synthetic keys/addresses must be unmistakable fixtures; never include an
   operator's real configuration, mailbox, model or access-bearing URL.
5. Open a PR. The protected `main` branch requires **macOS tests and installer**;
   all other applicable checks must also pass before release. Do not bypass
   protection or force-push shared history.
6. Use [the release process](docs/maintainers/RELEASING.md). Merging source does
   not authorize or perform a live deployment.

Dependabot proposes Go and Actions changes daily. The daily security workflow
checks known reachable vulnerabilities, publication secrets and documentation.
These are review signals, not automatic production installation. Maintain the
explicit dependency exceptions in the release guide; do not mechanically replace
preview APIs or SQLite's coupled libc version.
