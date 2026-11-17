# Purpose

Replace manual capability-key entry in the response policy editor with Korean
choices and accurate explanations, while preserving existing templates and the
managed-v1 policy contract.

# Contract and Scope

`response.required_capabilities` is a list of response prerequisites, not a
Tetragon tracing policy or a list of detection rules. The agent checks each
listed capability's implementation, active runtime state and verification time
for `would_block` and `enforce`. Observe mode continues detection without these
response gates. Enforce also always requires process execution, lineage and the
locally enabled termination actuator, independently of the configured list.

The editor offers execution observation, lineage, termination, Tetragon, audit
and observed process eBPF hooks. Platform/BTF/cgroup diagnostics do not report
active monitoring; file/network/credential-change collection and IMA/TPM
verification are not implemented response gates. Existing keys for these or
other custom features remain editable and are never silently removed.

# Design and Compatibility

- Keep the existing `requiredCapabilities` form value as the wire-key backing
  field and render choices into `requiredCapabilitiesEditor`.
- Preserve original key order on an unchanged load/save and keep unknown keys
  in a separate advanced editor. Apply no implicit changes on mode switches.
- An explicit recommended-conditions button adds the three standard response
  prerequisites without clearing other choices.
- Explain that Tetragon and audit are alternative authoritative sources and
  warn when both are required; preserve the operator's selection.
- Describe unsupported/diagnostic keys separately from selectable gates.
- Save the same settings schema, preview the server's saved template snapshot,
  and deploy only its preview token. Human labels never replace wire keys.
- Preview warnings match the current agent's capability predicate: implemented,
  active runtime state and a non-nil verification timestamp. Passive support
  states and the age of verification timestamps do not replace this predicate.
  Heartbeat freshness remains an independent informational warning. Enforce's
  implicit gates and its current Tetragon-source restriction are also explained
  without changing policy validation or deployment authorization.

# Validation

Use browser-script tests to exercise unchanged custom-key round trips, explicit
choice edits and recommended additions, mode help, incompatible-source warnings,
input validation and exact preview/deployment request payloads. Retain existing
console tests and check user-controlled content is inserted as text.
