# Central console review

## Implemented boundary

The console uses a separate administrator session, never the operator bearer
credential. Agent mTLS APIs and existing signed policy contracts stay unchanged.
Groups and templates are drafts until explicit preview and deployment. Desired
integrity settings are retained centrally and remain pending on managed-v1 agents.

## Review corrections

- Release read transactions and result rows before HTTP writes so slow browsers
  cannot retain the single SQLite connection and delay agent delivery.
- Preserve NULL heartbeat as absent for newly enrolled agents.
- Bind deployment display to the exact server template snapshot; a concurrent
  observe-to-enforce edit must never leave an old observe preview on screen.
- Bind assigned-policy caches and delayed replies to enrollment and revision.
- Persist version tombstones across group/template deletion and recreation so
  stale editors cannot overwrite a replacement with the same ID.
- Keep browser form POST origin valid with `Referrer-Policy: same-origin` while
  rejecting opaque and foreign mutation origins.
- Distinguish partial wire application with pending integrity, stale reports,
  device diagnostics and verified runtime evidence. Hide planned capability rows
  in a disclosure by default; primary explanations are Korean.
- Limit fleet display explicitly to 1,000 rows and expose truncation rather than
  silently implying complete fleet coverage.

## Validation

Go regressions exercise additive migration and immutable data preservation,
optimistic edits, atomic deployment rollback, concurrent/replayed/stale previews,
removal denial and enrollment binding, credential privacy, cursor boundaries,
network-write database release and authentication/CSRF/rate limits. JavaScript
tests exercise evidence presentation, policy conversion, both asynchronous races,
selection preservation, secret clearing and safe text rendering.

An isolated Chromium run exercised group/template creation, explicit two-agent
observe deployment with integrity pending, enrollment/removal issuance, credential
download/clearing, authentication rejection and every navigation view. Automated
WCAG A/AA checks reported no violations in the tested login, seven desktop views,
deployment preview, issued credential and agent detail. Layout checks at widths
375 and 720 found no document overflow. These automated checks do not establish
complete accessibility conformance.

The independent existing-agent/multiple-agent central integration also passed.
No live enforcement policy is created by installation or these tests.

## Remaining scope

One administrator account owns all console privileges. Multi-user roles,
long-term resource time series, central HA, and actual agent integrity execution
remain separate work. Native console TLS is supported; forwarded headers are not
trusted. A schema-v1 binary rollback needs the pre-upgrade database backup.
