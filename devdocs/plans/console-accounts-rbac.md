# Purpose

Add durable console accounts and server-enforced admin/operator/viewer roles
while preserving the existing initial administrator and browser CSRF boundary.

# Design

- `panel-auth.json` remains the bootstrap credential file. On the first opening
  of private `panel-accounts.db`, import that credential as the administrator.
  An initialization marker prevents deleted bootstrap accounts being recreated.
- Store one validated Argon2 credential and independent session signing key per
  account. Resolve sessions against the current account on every request.
  Password/role changes rotate that key; deletion removes the session authority.
- Admin manages accounts and operations. Operator manages fleet groups,
  templates, deployment, enrollment, removal approval and certificate revocation.
  Viewer can read approved console endpoints and change their own password.
  Unknown endpoints fail closed for non-admin accounts.
- All mutations retain Origin and session-bound CSRF verification. Self password
  changes require the current password. Admin can reset another account.
- Transactional account mutations use optimistic versions, protect the last
  administrator, and record actor/target/operation without credential material.
- `GET /api/session` includes `username`, `role`, and `csrf_token`. Safe account
  identity is attached to the downstream request context; browser role controls
  complement server authorization.

# Scope and validation

Keep account storage/HTTP/UI in dedicated modules. The serving command supplies
the account database path. Existing `New` callers use an isolated in-memory
repository. Test bootstrap persistence, session invalidation, last-admin and
concurrency guards, role/API matrices, CSRF, password confidentiality, and UI
forms with temporary state and mocked requests. No live credentials or running
services are read or modified.
