# Console API contract

Implementation contract for the dedicated updates UI. Requests use JSON except
raw RPM upload. GET is available to all roles. Upload/delete require admin;
preview/create/cancel require admin or operator. All mutations require current
session, same origin and CSRF header.

`POST /api/updates/releases`: raw RPM bytes, `application/x-rpm` (also accepts
`application/octet-stream`), maximum 64 MiB. The required header
`X-XEAS-Release-Manifest` is canonical unpadded base64url of the UTF-8
`SignedReleaseManifest` JSON (decoded maximum 16 KiB). This public manifest,
signed independently by the publisher, is verified before reading RPM bytes.
Do not send private keys or an arbitrary filename/URL. The signed size, SHA256,
RPM header and RHEL major must all match the actual bytes.
201 means created, 200 means exact existing bytes. Response:

```json
{"release":{"id":"64-lowercase-hex","package":{"name":"xe-antishell","epoch":0,"version":"0.1.0","release":"24.el9","arch":"x86_64"},"os_family":"rhel","os_major":"9","sha256":"64-lowercase-hex","size":1234,"created_at":"RFC3339","uploaded_by":"admin","publisher":{"manifest":{},"key_id":"embedded-publisher-key-id","signature":"public-signature"},"publisher_verified":true},"duplicate":false}
```

`publisher.manifest` is the complete shared ReleaseManifest: schema_version,
artifact_name, package, os_family, os_major, sha256, size and published_at.
`publisher_verified` reflects the embedded trust anchors and exact catalog match.
An unverified historical catalog item cannot be previewed or dispatched.

`GET /api/updates/releases`: `{"items":[release],"max_bytes":67108864,"max_releases":32,"max_total_bytes":1073741824,"publisher_keys":["embedded-publisher-key-id"]}`.
Publisher IDs are public read-only facts. There is no runtime trust/key editing API.
`POST /api/updates/releases/{id}/delete`, body `{"confirm":true}`: 200
`{"deleted":true}`. Active-job references conflict (409). No arbitrary file paths.

`GET /api/updates/github/releases` reads only public
`mkjang2000/Xe-AntiShell` Releases, with a five-minute cache:

```json
{"repository":"mkjang2000/Xe-AntiShell","fetched_at":"RFC3339","items":[{"tag":"v0.1.0","name":"Release title","published_at":"RFC3339","prerelease":false,"manifest_assets":[{"name":"agent.rpm.manifest.json","size":1024}]}]}
```

`POST /api/updates/github/import`, admin only, accepts
`{"tag":"v0.1.0","manifest_asset":"agent.rpm.manifest.json"}`. It has a
five-minute deadline and returns the same `{release,duplicate}` result as manual
upload. The requested manifest must belong to that fixed-repository release and
name its same-release RPM asset. A valid publisher signature is required before
RPM fetch. This API accepts no URL, path, private key or command. GitHub errors
use fixed safe messages and never echo redirect URLs or response bodies.

`GET /api/updates/agents?limit=100&after=agent-id&search=text`: paged inventory,
`{"items":[{"agent_id":"a","enrollment_id":"e","hostname":"h","inventory":null,"received_at":null,"active_job_id":""}],"next":"","total":1}`.
Inventory when present is the shared UpdateInventory: protocol_version,
supported, enabled, reason_code, os_family, os_major, arch, installed_package,
running_version, observed_at. Do not infer compatibility or version ordering in JS.

`POST /api/updates/preview`:

```json
{"release_id":"digest","agent_ids":["a"],"group_ids":[],"concurrency":1}
```

Response `{"preview_token":"opaque","expires_at":"RFC3339","release":release,"targets":[target],"eligible_count":1,"excluded_count":0}`.
Each target: agent_id, enrollment_id, current_package (nullable RPM object),
current_package_hash, current_revision, eligible, exclude_reason (fixed code).
The exact original target/group snapshot and excluded set are bound. The confirm
creates jobs for the exact eligible subset only. Zero eligible targets cannot
create a rollout. Codes include unsupported, disabled, inventory_stale,
platform_mismatch, already_current, downgrade, busy, revoked and not_found.

`POST /api/updates/rollouts`:

```json
{"preview_token":"opaque","confirm":true,"client_request_id":"unique-client-id"}
```

200 response `{"rollout":rollout,"jobs":[job]}`. Exact same account/request-ID
retries return the original result; changed requests conflict (409).
`GET /api/updates/rollouts?limit=20&after=rollout-id`: `{"items":[rollout],"next":""}`.
`GET /api/updates/rollouts/{id}?limit=100&after=job-id`: `{"rollout":rollout,"jobs":[job],"next":""}`.

Rollout: id, release_id, created_by, created_at, expires_at, concurrency,
cancelled, paused, stop_reason (failed/expired/interrupted), counters (state -> count).
Job: id, rollout_id, agent_id, enrollment_id, revision, state, terminal,
current_package, target_package, observed_package (nullable), last_report_at
(nullable), error_code, expires_at, stopped_after_failure, late_report,
collection_check (empty/verified/not_applicable/failed).

States: queued, offered, downloading, ready, installing, succeeded, failed,
expired, cancelled. Installing includes a granted installation lease and cannot
be cancelled remotely. A report can confirm succeeded only after a claim with the exact target
installed package and epoch-aware running version. Missing reports remain visible rather than
being assumed successful. Success additionally requires post-restart collection
verification (verified), or an explicitly inapplicable baseline collector
(not_applicable). A failed collection check cannot confirm success.

`POST /api/updates/rollouts/{id}/cancel`, body `{"confirm":true}`:
`{"cancelled":N,"installing":N}`. Cancels only jobs without an install claim;
already-authorized installs continue. The rollout remains in history.

First failure/expiry pauses the campaign and cancels unclaimed remaining jobs with
error_code rollout_stopped and stopped_after_failure=true. An install claim with
no result for ten minutes becomes failed/interrupted (physical result unknown).
Late bounded reports append history/observed_package with late_report=true only;
terminal state, current heads and paused campaigns never resume.

Generic safe API errors are `{"error":"Korean message"}`. No package-manager
stdout/stderr, signed plan bytes or credentials appear in console responses.
