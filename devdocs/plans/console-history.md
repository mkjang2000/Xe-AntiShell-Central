# Purpose

Separate suspected detections, collected events, agent error transitions and
agent audit records. Apply time, agent, type and text filters before server-side
pagination, rather than searching only the displayed page.

# Existing Data

- `records` preserves immutable event, finding, event-bundle and agent-audit
  delivery payloads. Bundles contain one event and up to 64 findings.
- `agents.heartbeat_json` retained only the latest heartbeat. It cannot reconstruct
  an earlier sequence of agent errors.
- `audit` contains central administrator actions; it is independent of agent
  audit delivery records.

# Read APIs

`GET /api/history?view=detections|events|agent_audit` projects one finding, event
or agent audit per row without changing stored delivery records. Legacy `kind`
queries retain their original response and cursor contract.

`GET /api/errors` returns fixed diagnostic categories and transitions. `GET
/api/audit?view=audit` uses the same filter contract for central administrator
activity. Authenticated console GET access is required for all three APIs.

Filters are `agent_id`, exact `type`, `q`, RFC3339 `from` (inclusive), `until`
(exclusive), and `limit` (1–500; default 20). The browser translates local date
inputs into explicit UTC timestamps. Periods apply to central receipt/recording
time, and cards also display source event/finding time where available.

Opaque keyset cursors bind the complete filter set. Finding cursors additionally
retain the array position within a delivery bundle, so a multi-finding bundle
can cross pages without omissions. Filters and limits are validated; SQL values
are bound parameters. Database rows are closed before writing HTTP responses.

The event view describes events delivered to and retained by central; it does
not promise complete capture of every host execution. Search examines the full
matching retained range; large deployments should keep a suitable time range.

# Error State and Upgrade

Heartbeat update, current error signatures and historical transitions commit in
one SQLite transaction. Track agent, collector and policy errors separately.
Store `occurred`, `changed`, and `recovered` only when the error state changes;
repeated heartbeats do not create repeated identical history rows.

Historical rows retain fixed categories, not raw diagnostic text. A SHA256 of
the diagnostic detects changes and is stored only in current-state tracking.
The existing latest heartbeat remains unchanged for current agent diagnostics.
The browser explains categories and links to current agent detail.

On upgrade, capture any existing current error once as `baseline`, timestamped
when central reads it. This is explicitly a snapshot of an existing error, not
its original occurrence time. Initialization processes at most 100 heartbeats
per batch and does not rewrite existing identities, policies or delivery data.
Existing schema-version-2 databases receive additive tables/indexes; the agent
wire contract and signed policy schema stay unchanged.

# Browser Boundaries

Four visible tabs replace the mixed record selector. Each selects a distinct
projection/API, clears incompatible type/search filters, and resets pagination.
Time and agent filters remain available while comparing different histories.
Request generations prevent a delayed prior response from overwriting the
selected category. Filter changes clear previous rows before requests, including
failed requests, so another category's records cannot remain under a new title.
Render all record data with text nodes; raw records use escaped text details.

# Validation

- Bundle-item cursor paging, date boundaries, agent/type/full-range search,
  malformed filters and cursor/filter mismatches.
- Central audit filters and paging, heartbeat error occurrence/change/recovery,
  repeated heartbeat deduplication, authorization rollback, one-time upgrade
  baseline and preservation of the latest heartbeat.
- Browser tab/API separation, date conversion and query encoding, delayed
  response rejection, and removal of stale rows after failed category changes.
- Existing central and browser regression suites remain enabled.

## Existing-data compatibility

Real non-detection bundles commonly encode a nil findings slice as JSON null.
SQLite json_each emits a null-key row for this value, so projected detection
queries must require a nonempty array and object elements. Regression coverage
includes missing/null/empty/scalar and mixed arrays. A partial bundle index skips
normal non-detection records; an EXPLAIN test checks the actual page query uses it.
Creating this index reads existing records once during schema initialization.
Original delivery records and the agent protocol remain unchanged.
