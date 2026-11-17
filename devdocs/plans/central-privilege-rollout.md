# Purpose

Deploy Central RPM release 13 before enabling the new privilege policy fields,
preserving enrollment, accounts, signed policies, delivery cursors and trust keys.
This is a reviewed procedure, not an automated production deployment record.

# Current structure and compatibility

The RPM owns the binary and base systemd unit. Runtime state remains under
`/var/lib/xe-antishell-central`; existing systemd overrides select deployment
addresses. The default unit uses the dedicated `xe-antishell-central` account.
The feature adds no database schema or credential initialization step.

`Store.LatestPolicy` in `internal/central/policies.go` decodes persisted signed
policies into the shared typed model before returning them. Release 12, pinned to
protocol v0.2.0, cannot retain the new optional privilege fields through that
round trip. Its response would retain the signature but omit the signed fields.
Consequently, a plain package downgrade is incompatible after opt-in policies
have been issued. The absence of a database migration does not remove this risk.

The shared protocol must first be published at v0.3.0. Pin its released version in
`go.mod`/`go.sum`, run `GOWORK=off make verify`, and build with
`GOWORK=off make rpm`. The build script deliberately disables workspaces inside
rpmbuild. A successful local workspace build alone is not release validation.

# Upgrade procedure

1. Record the reviewed source commit, RPM metadata, binary/package hashes and
   installed Central version. Preserve the installed release 12 RPM. Run
   `rpm -Uvh --test` on the new RPM before the maintenance window.
2. Record Central and adjacent service process IDs, configured listener addresses
   and protected-state digests without printing tokens, key bytes, raw heartbeat
   diagnostics, installation codes or agent event payloads.
3. Stop only `sentinel-central.service`. With the service stopped, create a
   root-owned backup directory with mode 0700. Preserve the complete state tree,
   SQLite databases plus any sidecars, release blobs, systemd overrides and old
   RPM. Preserve ownership and permissions. Never copy only a live SQLite file.
4. Record a digest of agent enrollment identities/current policy revisions and
   signed policy rows, plus console account identities/roles/credential digests.
   Upgrade only the Central RPM, reload systemd and start Central. Do not run init,
   init-panel or enrollment commands during an upgrade.
5. Check package version and service health, and match the running executable's
   digest to the installed binary. Verify the existing TLS listener using the
   deployed CA and certificate hostname. An unauthenticated agent API request
   should remain unauthorized. Verify console login and the authenticated admin
   agent list using credentials read privately inside the checker.
6. Compare served `model.js`, `privilege.js`, `policy.js`, `fleet.js`, `history.js`
   and `index.html` with the reviewed build. Check account access, unchanged trust
   material/overrides and expected enrollment/policy identities. Adjacent agent,
   collector, tunnel and other services must not be restarted by this operation.
7. Only after the new process passes checks, satisfy this service's own
   `needs-restart` marker if systemd's RPM triggers left one. Do not clear other
   units' pending markers. Retain the protected backup for recovery.

# Agent activation order

1. Deploy compatible Agent packages with privilege rules still disabled, while
   preserving the existing web detection and observation-only response settings.
2. Wait for a fresh heartbeat from each intended agent/current enrollment showing
   selected `tetragon-json` and `detection.privilege_rules` contract `1`, implemented
   and available/active. Actual credential sensor receipt is a separate check and
   is deliberately not an activation precondition.
3. Preview the exact targets and issue a policy with `privilege_rules: true`,
   `root_exec_alerts: suspicious`, and the existing overall detection gate enabled.
   Preserve existing web settings and `response.mode: observe`. New privilege
   findings remain detection-only even when other response policies differ.
4. Confirm each agent's higher active revision and error-free policy result.
   Verify actual sensor attachment/receipt, unknown fields, namespace scope,
   bounded event rate and centralized findings independently. A compatible engine
   heartbeat does not prove a same-task credential change has been observed.

# Failure handling and rollback

Before any opt-in policy is issued, release 12 can be restored from the retained
RPM with `rpm -Uvh --oldpackage --replacepkgs` while Central is stopped, retaining
the current state and overrides, then reloading/starting and repeating health
checks. Confirm no new fields have entered the latest policies before choosing
this path. Never restore a stale database merely to change the executable.

After opt-in policy issuance, prefer fixing or rolling back to a binary that still
understands protocol v0.3.0. If release 12 is required, use release 13 first to
issue **higher-revision** opt-out policies for every affected current enrollment;
both new fields must be absent, not merely set to false with a mode retained.
Confirm application on affected agents and remove opt-in settings from templates
that would otherwise be edited after downgrade. Retain the new policy and audit
history, then stop Central and downgrade the package while keeping the current
database. Verify delivered policy signatures with a compatible Agent before
considering the rollback complete. If policy delivery/application cannot be
verified, retain the compatible Central binary rather than downgrading blindly.

Restoring a pre-upgrade database snapshot after agents accepted higher revisions
can violate their monotonic policy minimum and roll back delivery acknowledgments,
enrollment state or accounts. It is disaster recovery requiring explicit
reconciliation, not an ordinary rollback. The stopped-state snapshot protects
data recovery but is not an automatically safe downgrade action.

Release 12 also lacks the new typed privilege presentation and validation. Even
after policy compatibility is restored, it does not provide the same history
semantics. Production rollback rehearsal remains a separate integration check.

# Verification boundary

Unit/UI/script tests validate the package and protocol handling in isolation.
Production listeners, authentication, live agent policy application, real kernel
sensor evidence and rollback are verified only when the corresponding operation
is actually performed. Do not infer them from compilation or fixture tests.
