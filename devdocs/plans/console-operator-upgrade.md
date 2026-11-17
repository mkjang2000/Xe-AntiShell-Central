# Purpose

Improve daily central-console use: account administration and enforced roles,
separate searchable evidence/error histories, shared agent branding, guided
capability conditions, and persistent accessible dark/light themes.

# Current Structure

The console embeds plain HTML/CSS/JS and authenticates a single Argon2id account.
The central SQLite store retains immutable agent records and the latest heartbeat.
Policy templates are versioned and deployment requires explicit preview/approval.

# Requirements and Design

- Administrator manages accounts; operator manages fleet policies/approvals;
  viewer reads monitoring data. All users may change their own password.
  Authorization must be enforced by the HTTP server. Password/role/deletion
  changes invalidate existing sessions. Preserve one usable administrator.
- Preserve existing administrator credentials, PKI, enrollments and policy data.
  Introduce durable account state with bounded password hashing and strict input
  validation. Do not expose hashes or secrets in API responses or audit records.
- Separate findings, collected process events, agent operational errors and audit
  work into clear workflows. Date ranges, agent and type/search filters operate
  over server-side data before pagination. Retain legacy history API behavior.
- Latest heartbeat errors have no historical store today. Record error state
  transitions and recovery prospectively without duplicating identical reports;
  never claim historical errors or uncollected executions can be reconstructed.
- Capability selection uses Korean labels/help, explicit safety explanations and
  preserves custom capability keys. No policy deployment occurs automatically.
- Use the same angular XE mark as the agent, with blue central accent. Default
  central to dark, offer light toggle on login and console, persist preference,
  and work when browser storage is unavailable. Avoid initial light flash.

# Change Scope

Console authentication and account modules, central history/error queries and
schema, focused browser modules, shared page wiring, themes, documentation and
security/integration tests. Shared agent wire protocol is unchanged.

# Failure Handling / Compatibility

Reject stale or unauthorized changes server-side, deny removal of the final
administrator, escape untrusted text via DOM text nodes, preserve CSRF/origin
validation and password-rate limits. Date ranges use explicit instants and the
browser displays its timezone. Schema migration is additive and transactional.

# Validation Plan

Compile/vet/race tests and existing installer/source checks; RBAC bypass and
session revocation tests; history category/date/cursor/search tests; error
transition deduplication; browser checks for login/themes, role-aware workflows,
capability round trips and accessibility in both themes. Before live rollout,
back up stopped central state and preserve service overrides. Do not restart the
agent or change any live policy as part of this console upgrade.

# Implementation and Validation

Implemented separate account store/auth/HTTP modules and account audits; role
checks deny unrecognized routes for non-admins. Account version tombstones prevent
stale editors from modifying deleted/recreated identities. The legacy seed is
imported only once and session signing keys rotate after account changes.

History views project individual findings/events from immutable delivery bundles.
Error transitions are atomic with heartbeat storage and deduplicated across
restart. Date/search filters and cursors bind to the selected view. Agent audit
types use the protocol action field. Policy condition checkboxes preserve custom
keys and ordering; deployment warnings use the actual agent gate predicate.

Full make verify passed, including source/privacy/installer checks, JavaScript
tests, Go vet, race tests and static build. Independent review covered API
authorization, CSRF, session invalidation, final-admin transactions and history
SQL. Actual Chromium tests exercised viewer denial, operator mutation, account
creation/role change/password change/deletion, old-session rejection, and audit
timestamps against an isolated service. Desktop dark/light and mobile views were
checked with axe A/AA rules; these automated checks do not certify every aspect
of accessibility. Host-specific deployment evidence stays in ignored notes.
