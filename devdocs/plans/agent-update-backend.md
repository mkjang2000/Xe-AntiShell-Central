# Purpose and Implementation

The central backend manages immutable agent RPM releases and explicit per-server
or group rollouts. Shared protocol v0.1.5 owns signed plans, install authorization,
separate inventory and durable reports. UI contracts are in
[agent-update-api.md](agent-update-api.md). No operational deployment belongs to
this implementation phase.

# Responsibilities

- `updates_blobs.go`, `updates_rpm.go`, `updates_catalog.go`: private streaming
  staging, SHA256 publication, fixed unprivileged RPM metadata query, catalog
  quota and safe deletion. RPM payloads are never extracted or executed centrally.
- `updates_inventory.go`, `updates_schema.go`: additive enrollment-bound inventory,
  revision heads and timeout/failure propagation. Legacy database version 2 and
  heartbeat bytes remain unchanged.
- `updates_preview.go`, `updates_rollouts.go`: exact signed review snapshot,
  idempotent creation, guarded cancellation and independent update revisions.
- `updates_dispatch.go`, `updates_agent.go`, `updates_reports.go`: mTLS offer,
  authorized artifact transfer, short install claim and strict report transitions.
- `updates_console.go`, `updates_reads.go`: current-account role checks, paged
  operator views and fixed safe diagnostics; no package-manager output is exposed.

# Release Boundary

Only admins upload/delete agent RPMs. Initial packages must be named xe-antishell,
RPM arch x86_64 and EL major 7–10 with a matching .el marker (including point
release suffixes). The native RPM query has fixed arguments, no shell, private
0600 service-owned input, minimal environment, ten-second context and 4096-byte
output cap. It does not install or run scriptlets. Agent-side inspection remains
independent. Upload authorizes privileged code deployment; a hash/signature binds
bytes and authorization rather than asserting publisher provenance.

Raw application/x-rpm uploads (octet-stream also accepted) have a 64 MiB bound and
one admission slot. Only that exact authenticated/CSRF-protected route bypasses
the ordinary 1 MiB JSON cap. Transfer deadlines are bounded to five minutes; four
artifact download slots bound concurrent transfer resources. Catalog limits are
32 active releases and 1 GiB active published bytes. Staging and in-flight transfers
can use additional bounded temporary space.

Bytes live under state/update-blobs/sha256/<digest>.rpm, with private directories
and regular 0600 files. Stream/hash/fsync before publication; atomically link
without replacement before DB commit. Exact uploads deduplicate, conflicting
NEVRA bytes fail, and failed publication removes the new unpublished blob. No
network upload/download keeps a DB transaction open. Active-job references block
deletion. Retained job snapshots do not depend on a deleted catalog row.

# Review and Dispatch

All console roles can read metadata. Admin/operator can preview/create/cancel;
only admin can upload/delete. The business handler also requires the wrapper's
current-account context. Browser APIs require same origin and CSRF.

Preview expands the full sorted original agent/group set inside one transaction,
binds enrollment, current package/inventory hash, independent revision head and
group version/generation/member hash. It reports every exclusion and only the
reviewed eligible subset becomes jobs. A five-minute separately domain-signed
preview expires or conflicts on changes. Actor-scoped request IDs make exact
creation retries idempotent. No healthy collector gate prevents recovery updates.
Updater inventory must be supported/enabled and known; missing inventory requires
manual bootstrap. A known inventory may be queued offline; the agent repeats
fresh inventory before polling and independently checks local package preconditions.

Jobs queue for seven days. GET marks an eligible job offered, stores its exact
signed 15-minute plan and consumes the rollout's concurrency slot (default one).
Retries reissue those stored bytes. Expired offers release heads, stop the failed
campaign and cancel unclaimed remaining targets. Per-enrollment update revisions
never share detection-policy revision state. Re-enrollment/revocation blocks old
inventory joins, plan delivery, download, claim and reports.

# Installation and Reports

After downloading and validating the exact artifact, the agent ACKs downloading
and ready reports before claim. Claim checks the still-current head/job and
issues a stored two-minute authorization bound to plan digest, revision and
enrollment. It atomically enters installing. Duplicate claims never extend the
lease. Cancellation and first campaign failure can stop only unclaimed jobs.

Normal reports have sequential durable sequence numbers and immutable canonical
retry bytes. Exact retries ACK; same-sequence changed bodies and backward progress
conflict. Success requires server installing state, an issued authorization and
exact target package plus the shared epoch-aware running version. Source times
are informational; receipt time drives server freshness.

An installing job without a result for ten minutes becomes failed/interrupted,
with an explicitly unknown physical outcome. It frees the head and pauses its
campaign; it does not assert the remote installer stopped. Late reports from the
same still-current enrollment/job/revision can append bounded next-sequence
history and observed package data only. They never change terminal state, current
head, a newer job or paused rollout. No raw RPM stderr, argv, credentials or
unbounded agent diagnostics are retained.

# Validation

Regression tests cover immutable catalog/deduplication, RPM ordering/metadata
bounds, active-reference deletion, signed plan/claim reissue, authorization-only
success, current/foreign certificate download, re-enrollment, group ABA and
package changes, mixed eligible/excluded targets, idempotent creation/reports,
late ready retries after claim, offered/installation timeouts, first-failure
stop and old late history beside a newer job. Separate console tests exercise
roles, authentication/CSRF before reading uploads and retained ordinary body caps.
End-to-end synthetic HTTP tests use browser authentication plus mTLS agent APIs.
Further parent integration adds the dedicated UI and agent/helper workflows, then
full race/vet/script/UI/static/RPM checks before any operational deployment.
