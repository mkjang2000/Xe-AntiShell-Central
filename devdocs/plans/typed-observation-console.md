# Purpose

Display shared-protocol v0.1.2 execution, file and TCP observations without
overstating the source's evidence or changing central retention and policy state.

# Scope and Data Flow

Pin the published protocol module. Existing event-bundle storage and history
projections preserve optional typed fields. The browser model converts allowlisted
runtime/mode/evidence/outcome values into Korean labels; history displays selected
metadata with the existing raw record disclosure available separately.

The execution view includes process.exec_observation, file.write and network.connect
filters alongside legacy process.exec/exit. Findings explain inline invocation and
temporary scripts as requests rather than successful code execution. Risk scores
are rule contributions, not maliciousness probabilities. Detection-only findings
state their exclusion from automatic termination.

Each observation capability needs implemented state and its own fresh actual
receipt. Policy files, passive kernel support, another observation's proof or a
stale timestamp cannot promote it. File writes expose return semantics and partial
scope; TCP return zero means initiation rather than an established connection.
Unsafe integer returns remain explicitly imprecise instead of displaying rounded
values as exact. Unknown enum values remain unknown; code/argv extensions are not
rendered as typed facts.

# Compatibility and Failures

There is no schema migration, policy rewrite, account change, enrollment change,
new listener, agent service change or external collector control in this release.
Older events and agents keep their existing views. Unknown future typed fields
remain preserved in original records. Malformed display values do not assert
successful execution, writes or connections.

# Validation and Release

Run complete source/script/UI/vet/race/static verification with GOWORK off and
build VCS metadata disabled. Regression tests cover typed fields, unsafe numbers,
unknown values, privacy and independent freshness. Build RPM release 11 from the
reviewed temporary checkout, fast-forward the clean maintained repository and
publish that commit. Before replacing the central RPM, retain a private stopped-state
backup and compare PKI/account/enrollment/policy/override digests. Restore the
previous package on failed readiness and keep the backup for data recovery.
After upgrade, verify TLS authentication boundaries, served asset bytes, history,
accounts, browser errors and accessible desktop/mobile rendering. Keep agent,
Tetragon and tunnel services unchanged.
