# Purpose

Expose opt-in global root execution and paired credential-change detection without
turning a new observation or finding into automatic process termination.

# Contract and scope

The shared protocol adds optional `detection.privilege_rules` and
`detection.root_exec_alerts` (`suspicious` default or `all`). False/omitted opt-in
omits both fields, preserving old signed policy bytes. `detection.enabled` is the
common engine gate; a privilege-only policy may omit web origins and shells.
A root exec is not proof of a newly created PID or malicious privilege gain.

The editor provides a checkbox and root-alert selector, target preview and
current-policy detail. Existing template, CSRF and role-enforced endpoints are
reused. No database migration or new operator permission is required.

# Compatibility and deployment gate

Before preview, again during confirmation, and during direct admin policy
assignment, opt-in requires a fresh authenticated heartbeat for the exact agent
and current enrollment (at most two minutes old, at most one minute in the
future), selected Tetragon collector, and `detection.privilege_rules` with
implementation `implemented`, runtime `available`/`active`, details contract `1`.
Old/missing/stale/incompatible reports are rejected; legacy opt-out policies do
not acquire this requirement. Exact idempotent assignment retries remain safe.

Actual `observation.credential_change` receipt is not a precondition for enabling
the feature: that would prevent activating a new sensor. It is separately shown
as runtime observation and must not be confused with static engine support.

# Evidence and presentation

Central ingest validates new typed credential events with the shared model,
stable Tetragon identity, matching TGID and no conflicting operation payload.
Invalid/missing before evidence cannot claim applied; explicit unknown evidence
remains valid. Other event families preserve their previous validation behavior.

A separate `privilege.js` presentation module labels six new detection-only rule
IDs and bounded credential fields. UID zero is preserved, absent snapshots or
capability sets remain unknown, and capability differences are computed only
when both sets are known. A present empty set is distinct from missing data.
Root privilege recovery, new authority, and permitted-to-effective activation
have distinct labels. Initial user namespace is not proof of container escape;
non-host/unknown user namespace does not imply host root authority.

New history types and current-policy detail are available without raw JSON
editing. Technical raw records remain available under existing access controls.
The capability editor distinguishes optional observations from recommended
response conditions and no longer claims file/network observation is absent.

# Validation

- Go tests cover new support contract, missing/stale/future/current enrollment,
  old agent/audit rejection, preview-confirm support drift, direct admin bypass,
  legacy omitted wire fields, and single/bundled typed evidence validation.
- JavaScript tests cover opt-in/root mode round trips, disabled-field omission,
  root-only validation, supported engine vs receipt, UID0/unknown/ns/capability
  distinctions, malformed presentation, rule labels and module wiring.
- Existing roles, policies, history, accounts and update suites are retained.

Production deployment, actual sensor attachment and same-task privilege change
proof are separate integration checks and must not be inferred from UI tests.

# Local verification result

Against the parent's protocol workspace, all three central Go packages passed
`go test -race -count=1 ./...`; vet and static build passed. All seven browser
test files (including new privilege and policy-control cases), installer/build
script checks and sixteen source-check tests passed. Source inspection checked
172 Git candidates with no issues, and diff checks passed. This is isolated
validation, not production deployment or actual kernel sensor proof.

The release dependency pin must move to the published shared protocol v0.3.0
before a normal GOWORK=off package build; the local workspace is not shipped.
