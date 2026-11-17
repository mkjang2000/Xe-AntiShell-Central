# Purpose

Display actual collection accurately when a passive probe cannot discover a
configured collector outside PATH. Existing agents can report both passive
unsupported/error and live active evidence; the shared protocol deliberately
retains those independent fields.

# Design and Scope

For known implemented collectors and process observations, fresh runtime active
evidence drives the operation column. Preserve stale, planned, runtime-error,
integrity and termination guards. Keep passive result/time and actual proof/time
separate in the evidence column, with a Korean diagnostic mismatch explanation.
Process eBPF proof confirms process hooks only. Raw reports remain unchanged.
No API, database, policy, key, account or enrollment change is involved.

Freshness distinguishes the latest heartbeat snapshot from live observation.
Environment diagnostics keep their original probe time; an online heartbeat can
still report that snapshot without an arbitrary five-minute expiry. Inactive or
error collector states and the current local termination opt-in are also current
heartbeat data. Active process observations and process eBPF proof additionally
require a recent `verified_at`; missing or old proof cannot be promoted to green.
An offline/stale heartbeat never establishes current operational status.

# Validation

Regression tests cover unsupported/error passive results with actual collection,
stale/planned/error/unknown states, response constraints and rendered evidence.
All29 browser model/DOM tests and the full central `make verify` passed. Verify
the installed panel against a live read-only agent report after a stopped-state
backup and reversible RPM update. Existing remote agents need no reinstall for
this presentation correction.
