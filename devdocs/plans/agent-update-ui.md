# Purpose and contract

Provide a compact release catalog, server inventory and rollout history without
equating an update request with a completed installation. The dedicated
`/api/updates` DTOs are defined in the backend's `agent-update-api.md`; inventory
is separate from strict legacy heartbeats. JavaScript does not compare RPM
versions or infer platform compatibility.

# UI and roles

`updates.js` owns the updates view, safe DOM rendering and dialog lifecycle.
`updates-source.js` isolates public manifest validation and bounded raw/GitHub
transports. `updates.css` uses existing light/dark color tokens and
angular compact tables. App/index/access only register and route the feature.

All roles can read catalog, inventory and rollout results. Only administrators
can register/delete release bytes. Administrators and operators can preview,
deploy and cancel unclaimed jobs. Backend role enforcement and CSRF remain
mandatory. Permission help explains that RPM installation scriptlets can run
as root; catalog upload is therefore approval for operators to deploy that RPM.

Use one native dialog at a time for upload, release detail, target preparation
or rollout detail. Confirmation is inside the same dialog, without a nested
global confirmation. Closing/navigation invalidates its generation and clears
file controls; a previously queued native close event cannot dismiss a reopened
dialog. Late mutation responses cannot modify a newer form. Closing a dialog
does not cancel a rollout. Explicit cancellation only covers pre-claim jobs.

# Data and failure handling

Raw upload requires an RPM of at most 64 MiB and its signed public manifest JSON
of at most 16 KiB. Before creating an XHR, validate UTF-8/JSON, exact public
top-level/manifest/package keys, bounded metadata and basic signature format.
Reject private PEM/JSON, unknown or duplicate keys with a fixed message; never
log file contents or raw parser exceptions. Reserialize only the validated public
structure into the base64url `X-XEAS-Release-Manifest` header. This local shape
check does not claim cryptographic verification. Central verifies its built-in
publisher anchor and file binding; the agent independently verifies it again.
The central's per-target deployment approval signature remains separate.

Use same-origin XHR with the CSRF header and a five-minute timeout, with separate
transport progress and server validation states. Do not send filename or
operator-authored package metadata. An interrupted
request may already have registered a release, so instruct the user to inspect
the catalog instead of silently retrying.

An explicit GitHub action fetches the fixed `mkjang2000/Xe-AntiShell` catalog;
select a listed release and public manifest asset before an admin-only five-minute
JSON import. No arbitrary repository, download URL or trust-key setting exists.
Only publisher-verified catalog entries can be selected for deployment. Release
detail distinguishes central publisher verification from the future agent check;
public built-in key IDs are read-only. Source signature bytes are not previewed.

Server/group selection has a default concurrency of one and uses a signed
compatibility preview. Selection changes invalidate that preview; late results
are rejected. Exclusions and initial one-time manual update requirements remain
visible. Confirmation sends a stable random client request ID for retry safety.
Inventory uses server pagination rather than assuming `/api/state` contains the
entire fleet. The preparation dialog has its own inventory search/pager and
retains selected IDs across pages. Rollout detail polls only while visible and preserves terminal
states. Missing or delayed reports never imply success. Installation leases
cannot be remotely cancelled, and cancellation results distinguish ongoing
authorized installs from cancelled jobs.

The first failed/expired target or an installation whose result is unknown
stops subsequent unclaimed jobs. Show campaign pause reasons and distinguish
`failed/interrupted` from proof that an installation stopped or rolled back.
Late reports may update the observed RPM while preserving that terminal outcome;
they cannot turn the campaign into success or resume deployment.
Display post-restart collection check separately as verified, not applicable,
failed or unknown; a late collection fact cannot upgrade a terminal result.

# Validation

Test admin/operator/viewer controls and mutation boundaries, raw upload progress,
CSRF/size/timeout/error/duplicate handling, immutable preview scope, exclusion
labels, idempotency IDs, stale asynchronous responses, dialog close/reopen and
focus restoration, paged inventory/jobs, cancellation and outcome semantics.
Run all browser-script tests, source checks, Go/race verification and isolated
browser checks before the parent integrates and deploys. No live update is part
of UI implementation tests.
