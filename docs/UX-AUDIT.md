# Desktop experience audit and remaining qualification

This guide records the current interaction contract for maintainers. It does
not certify accessibility or usability on untested machines. See the
[desktop guide](DESKTOP-GUIDE.md) for user instructions.

- Setup has three stages: explicit provider/connection settings, folder
  confirmation and a successful safe dry-run. Busy state locks editing so a
  result cannot silently refer to different visible inputs.
- The dashboard prioritizes health and the user's next action before counts.
  Unknown/stale state cannot be presented as confirmed protection.
- The menu-bar icon distinguishes observation, active cleanup and unknown state.
  Window closure and UI login start are separate from worker scheduling.
- Corrections show actual configured folder names and provide copy controls.
  A provider-specific webmail shortcut appears only for the matching profile.
- Recovery lists date/category without rendering content. Selecting another
  item or changing filters invalidates prior revealed headers and confirmation.
  Empty pages, filters and errors have explicit recovery actions.
- Cancellation is informational, never success. Already completed safe steps
  may persist. State is refreshed before another protected policy action.
- Mode/deletion confirmation remains visible after failure so retry is possible;
  stale status must be refreshed and backend gates remain authoritative.
- Keyboard navigation and accessibility labels/hints are preserved in English.
  Run Swift tests and mock onboarding after UI/protocol changes.

Remaining work includes formal VoiceOver and keyboard audits, usability testing
with people outside the project, Developer ID signing/notarization and broader
OS/provider qualification. Automated tests cover defined interactions and wire
contracts; they do not replace those assessments.
