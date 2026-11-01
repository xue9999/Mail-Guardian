# Mail Guardian changelog

## 0.7.0 — 2026-11-01

- Rename the displayed product to Mail Guardian and the canonical GitHub
  repository to `xue9999/Mail-Guardian`; use the canonical Go module path.
- Make current documentation, desktop UI, backend messages and primary command
  help English. Preserve compatibility links to old guide filenames and keep
  Polish command aliases accepted.
- Expose custom IMAP profile, hostname, implicit TLS port and separate login in
  desktop/interactive setup and Linux configuration creation. New setup defaults
  to custom; the o2 endpoint is an explicit preset. OAuth is not implemented.
- Give explicitly profiled fresh installations independent identities and English
  Guardian folders. Keep existing paths, Keychain/bundle/service/Docker IDs,
  configured folders, deterministic v1 identities and mailbox bindings intact.
- Add non-secret connection/folder metadata to the local API so desktop setup
  and correction/recovery instructions use actual configured names. Omitted
  fields preserve old protocol compatibility and existing custom connections.
- Accept English `ACTIVE`/`ENABLE` confirmations alongside legacy wire tokens.
  Filtering, observation, archive, MOVE confirmation and permanent-deletion
  policy remain governed by their existing safety gates.
- Make synthetic backup restart tests independent of host free-space state and
  produce oversized pipe input concurrently to avoid a macOS fixture deadlock.
  Production backup and remote-protocol guards are unchanged.
- Document the provider protocol requirements, unsupported authentication,
  qualification limits and upgrade contract. Publication does not deploy this
  new minor line to the reference VPS.

## 0.6.1 — 2026-11-01

### Linux, recovery and maintenance

- Publish the Linux worker, systemd units, private credentials, restricted
  administrator helper, configuration/deployment identity, migration, encrypted
  backup and Redis model comparison tools.
- New installation leaves scheduling off. Adopting existing policy requires
  validated history and a fresh dry-run; a copied database does not authorize
  another configuration or host.
- Optional observation checks actual work, heartbeat and unresolved operations;
  process/container health alone is insufficient.
- Publish daily Ubuntu, Docker, image and Guardian dependency/compiler update
  coordinators with tests. They preserve coherent recovery/model state, locks,
  journals and postflight checks. New major/minor lines require manual review.
- Confirm MOVE without COPYUID through at most three read-only attempts with
  250 ms/750 ms delays. Check exact content and UIDVALIDITY without redundant
  ENVELOPE requests; never repeat MOVE merely to obtain its mapping.
- Keep the descriptor open and verify payload when cleaning a failed update
  marker. Inode reuse or file replacement cannot authorize deleting another
  transaction's lock.
- Correct the fixture whose server still emitted COPYUID without advertising
  UIDPLUS; regressions now actually suppress the wire mapping.
- Add architecture, operations, maintenance, release and incident documentation;
  label old pilot designs historical. Add macOS/Linux CI, operational fixtures,
  documentation links and secret scanning. Daily dependency/security checks do
  not deploy source to production.

### Configuration and secrets

- Configuration v2 separates account, login and provider. Loading v1 preserves
  the existing o2 installation, folder names, paths and Keychain entries.
- Bind mailbox state to instance and connection. Changing server/login cannot
  reuse old UIDs or pending operations; folder changes require fresh dry-run and
  observation while preserving quality history.
- Share the secret-store interface between Keychain and private Linux credential
  reads. A read failure or corrupt archive key cannot silently replace the key.
- Keep old setup requests valid while accepting custom IMAP fields. This does
  not imply OAuth support or qualification of every IMAP provider.

### macOS and shared engine repairs

- Catch up one missed run after wake; schedule at even local hours and service
  load. Short wake periods no longer necessarily miss all checks.
- Align deep checks and dashboard warnings: no success or success older than
  four hours needs attention; over 48 hours is critical.
- Let the latest explicit correction determine the current class. A
  spam→ham→spam change learns again, while historical ham evidence still blocks
  permanent deletion of identical content.
- Continue processing explicit corrections after quality authorization is lost;
  automatic cleanup is checked after training-folder processing.
- Apply IMAP timeout to individual commands rather than an entire healthy long
  scan. A stuck command ends the run instead of cascading fetch failures.
- Retry transient model export once with a separate deadline per attempt; save
  only successful, checksum-verified exports.
- Give Redis persistence checks separate timeouts and one process-error retry;
  a successful status check does not consume the next fsync-check budget.

## 0.6.0

- Allow completed observation to use a current stored independent qualification.
  Train a separate fresh model on about 70% of examples, tune on 10%, and test on
  20%. Keep normalized matching subjects in the same partition.
- Require at least 40 spam and 30 ham held-out examples, 90% spam recognition,
  zero false holds and zero false rescues. Bind qualification to mailbox policy,
  rules and threshold; new confirmed move errors revoke it pending reevaluation.
- Start Bayes classification at 100 statistical examples per class. Independent
  qualification may tune quarantine threshold down to 6; otherwise retain the
  conservative minimum of 12 and earlier activation checks.
- Allow strong positive spam evidence for reversible quarantine despite an
  incomplete auxiliary DNS test. Whole-scan timeout, skip and soft reject still
  block. Rescue needs a complete scan; purge retains completeness, threshold
  at least 12, 200/200 minimum learning and its other independent gates.
- Add Settings reevaluation and `guardian qualify` without resetting history.
  Reports contain hashes/results, not message bodies or credentials.
- Require fixed Go 1.27.3 or 1.26.10 to address reachable certificate-validation
  advisory GO-2026-6809.

## Local patch — 2026-10-22: delivered-mail scanning

- Disable only GREYLIST_CHECK/GREYLIST_SAVE for delivered IMAP mail. Real timeout,
  DNS failures and other soft rejects still block automatic decisions.
- Reevaluate eligible retained Inbox messages after a day or confirmed learning
  in the current run. Do not repeat completed moves or explicit corrections.
- Preserve first verdict/action separately; rescans cannot retroactively improve
  historical activation criteria.
- Explain persistent historical blocks after observation. A healthy schedule
  does not imply cleanup readiness. Enable neither cleanup nor purge implicitly.

## 0.5.3

- Wait for the IMAP greeting before LOGIN to remove a connection race.
- Retain exact-content user corrections for malformed MIME: encrypt and move the
  original according to explicit training choice without sending malformed data
  for learning or increasing Bayes counters. Retry previously blocked corrections;
  automatic classification still rejects malformed messages.
- Update x/crypto to 0.58.0 for 16 older advisories. Document the unfixable unused
  OpenPGP advisory and reject importing that package.
- Block start, installer restart and successful run completion on Colima disk
  write errors even if Redis still serves memory. Use synchronous AOF; rewrite
  begins at 4 MiB.

## 0.5.2

- Distinguish connection/server failure during IMAP login from rejected passwords.
- Do not authorize scheduling after a dry-run with individual-message errors;
  return structured results plus failure rather than full success.
- Build with fixed Go 1.27.2 and reject older vulnerable compilers, including
  1.27.1/1.26.8, during packaging/source installation.
- Select full Xcode for build/test/preview/install when CLT is selected; preserve
  explicit DEVELOPER_DIR without changing system settings.
- Support an external Swift scratch directory for packaging, preview and install.

## 0.5.1

- Repair/check the stack from the UI with a restricted PATH through explicit
  Colima/Docker dependency paths.
- Keep two checksum-verified Redis model backups outside Colima. A regressed
  model cannot replace good backups; persistence/export failures remain visible.
- Confirm full message content for missing-COPYUID reconciliation. Size searches
  avoid unrelated unreadable messages; ambiguity/read failures cannot confirm.
- Preserve corrections when Rspamd skips learning (HTTP 204), without false
  counter increments or endless retry loops.
- Detect model loss using observed Rspamd counters; statistical duplicates do not
  trigger false alarms. Failed/pending runs do not become green or successful
  heartbeats. Accept old UI/new backend setup-field spellings.
- Add GitHub vulnerability, application, installer and isolated synthetic checks.

## 0.5.0

- Package prebuilt Go/native macOS programs for Apple Silicon; installation from
  the ZIP does not compile. Source checkout installation still builds.
- Validate payload completeness, version, architecture, SHA-256, self-checks and
  local signatures before replacement; serialize installers with a shared lock.
- Distinguish success, attention and failure. Retain rollback backups and report
  incomplete recovery rather than claiming success.
- Include source. Checksums detect corruption, not publisher authenticity.
  Use ad hoc signing without Developer ID/notarization; declare macOS 13 minimum
  without claiming validation on every older OS.

## 0.4.0

- Prioritize user actions before statistics, group health/schedule and observation
  progress, and distinguish empty-review states from stale data.
- Guide corrections in three steps with webmail access, immediate processing and
  temporary copy-folder feedback.
- Explain archive dates; add adjacent-entry navigation and local-day date/category
  filters before pagination. Clear preview/restoration when selection changes.
- Show five explicit current-period quality criteria without changing activation.
- Add Go-menu keyboard shortcuts and accessibility labels for folders/quality.
  Preserve activation confirmation on failure; prevent stale-state retries.
- Explain account preparation in three steps and lock inputs while probing.
- Distinguish observation, active and unknown menu-bar states. Verify package UI
  and version against source.
- Add empty-filter/page recovery actions, clear stale lists after read failures,
  and retry the failed page. Treat cancellation as incomplete, retain completed
  steps, mark status unconfirmed and allow refresh before retry.
- Remaining qualification: Developer ID/notarization, VoiceOver/keyboard audit
  and usability tests outside the project.

## 0.3.0

Initial local protection engine, native macOS UI, setup, training, encrypted
backups and message recovery.
