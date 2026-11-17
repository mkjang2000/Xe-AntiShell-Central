# Purpose and contract

Provide a compact release catalog, server inventory and rollout history without
equating an update request with a completed installation. The dedicated
`/api/updates` DTOs are defined in the backend's `agent-update-api.md`; inventory
is separate from strict legacy heartbeats. JavaScript does not compare RPM
versions or infer platform compatibility.

# UI and roles

`updates.js` owns the updates view, safe DOM rendering, dedicated raw RPM upload
and dialog lifecycle. `updates.css` uses existing light/dark color tokens and
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

Raw upload is bounded at 64 MiB, uses same-origin XHR with the CSRF header and a
five-minute timeout, and has separate transport progress and server validation
states. Do not send filename or user-authored package metadata. An interrupted
request may already have registered a release, so instruct the user to inspect
the catalog instead of silently retrying.

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

# Validation

Test admin/operator/viewer controls and mutation boundaries, raw upload progress,
CSRF/size/timeout/error/duplicate handling, immutable preview scope, exclusion
labels, idempotency IDs, stale asynchronous responses, dialog close/reopen and
focus restoration, paged inventory/jobs, cancellation and outcome semantics.
Run all browser-script tests, source checks, Go/race verification and isolated
browser checks before the parent integrates and deploys. No live update is part
of UI implementation tests.
