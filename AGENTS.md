# Guardian contributor instructions

Read `CONTRIBUTING.md` and `docs/README.md` first. Canonical architecture,
operations and release instructions are in `docs/maintainers/`; historical
plans are labeled and do not supersede the current runbooks.

- Use synthetic fixtures and isolated destinations. Tests/builds must not start
  a real worker, provision an operator account, or mutate a live mailbox.
- Preserve exclusive mailbox ownership, archive-before-move, exact-content/UID
  confirmation, configuration binding, trained-model continuity and permanent
  deletion safeguards. The reference VPS keeps deletion off and the Mac retired.
- A service-impacting update needs a coherent current model/database/archive
  recovery point and a real successful mail run afterwards. Source publication
  alone is not deployment authorization.
- Keep secrets/runtime state out of Git. Scan the full publication, including
  untracked source. The gitleaks allowlist is limited to SHA-256 values in one
  exact checksum fixture; do not blanket-ignore test files.
- Run the change-appropriate checks in CONTRIBUTING. Mail/state changes need
  meaningful regression coverage; Linux-only behavior needs native Linux checks.
- Keep user documentation Polish and maintainer documentation English. Update
  the owning runbook/changelog when commands, state contracts or recovery change.
- The current Docker coordinator imports libraries from `auto-updates/docker`.
  Consult `ops/vps-maintenance/README.md` before removing “legacy” files.
- Never force-push shared history or bypass protected-branch checks. Keep source
  detection, tested candidates, installed versions and observed runs distinct.
