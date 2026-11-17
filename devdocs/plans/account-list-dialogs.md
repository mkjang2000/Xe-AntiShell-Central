# Purpose

Replace large inline account forms with a compact list and focused account
operations. Explain actual role permissions next to role labels.

# Design and Scope

- Keep a one-line current-account summary and an explicit password-change button.
- Administrators see username/role/creation/update/detail columns, name search,
  role filter, count and an add-account button. Audit history starts collapsed.
- Native dialogs handle creation, account details and own-password change.
  Details show identity/timestamps and focused role/reset/delete controls.
- Role help supports hover, focus, touch/click and Escape; the tooltip remains
  readable when the pointer moves onto it and stays within the viewport.
- Preserve existing APIs, roles, CSRF, optimistic versions, session revocation
  and final-administrator protection. No database or agent changes.
- Clear password fields on submit/close/pagehide/navigation. Preserve target and
  version snapshots; reject duplicate submits and ignore stale completions.
  Restore focus after close and prevent old native close events clearing a
  newly reopened dialog. Display validation errors inside the dialog.

# Validation

Use focused DOM tests for dialog state, errors and delayed completions, existing
backend authorization tests, and real Chromium checks for account operations,
focus/Escape/password clearing, tooltip interaction, responsive layout and both
color themes. Back up central state before the normal RPM rollout; preserve
account data, PKI, policies and other service processes.

# Verification Evidence

Isolated Chromium checks exercised account creation, name/role filters, details,
permission changes, password reset with a real login, deletion with session
revocation, validation retry and a real stale-version conflict/reload. Native
close/reopen and navigation tests confirmed secret-field cleanup. Seven axe
A/AA scans covered the list/dialogs, both themes and small viewport layouts with
no reported violations. Independent review covered dialog focus/state and
existing authorization boundaries. Production verification uses read-only flows.
