# Purpose

Prevent selective history reads from scanning the entire JSON archive or occupying
the single connection used by agent delivery, heartbeats and policy writes.
Keep existing canonical filters, cursor ordering, page limits and immutable records.

# Current structure and failure

The release 13 event view projects event and event-bundle JSON through UNION ALL.
Optional OR conditions are applied outside the projection, with a parameterized
JSON path. The existing kind/time indexes do not index the requested event type;
a rare or absent type may parse the entire archive before filling a page. A single
Store connection also serializes this work with authentication-independent agent
writes. Browser requests abort after twenty seconds; queued writes can wait too.
Type names are not rejected by an enum, and RFC3339Nano date bounds are supported.

# Design

- Build fixed SQL branches per record kind. Push agent, time, literal JSON type,
  search and cursor constraints into each branch using bound values.
- Order and limit each branch before merging at most two pages of candidates.
  Preserve global `(time, agent, source kind, record ID, item)` ordering and
  per-finding bundle pagination. Search still examines the same projected JSON.
- Add partial expression indexes for event and bundled-event types, with global
  type/time and agent/type/time variants. Existing indexes serve untyped date
  queries and bundles that actually contain findings. No payload is rewritten.
- Open one separate read-only history connection after schema initialization:
  URI `mode=ro`, `query_only`, the same WAL database and a bounded pool. Keep all
  writes and transaction-local reads on the existing main connection.
- Bound history requests by a short deadline, including pool wait. Timeout returns
  the existing JSON error shape with a controlled message. Arbitrary substring
  search can still inspect many candidate payloads; it must not monopolize writes.

# Failure handling and compatibility

Reader initialization failure closes opened resources and fails startup. Closing
Store closes history readers before the writer/checkpoint. Startup creates only
additive indexes at schema version 2; old binaries tolerate the extra indexes.
No runtime trust, policy or enrollment setting changes. Preserve old cursor wire
fields and comparison semantics, inclusive from/exclusive until, limit 1–500,
and legacy history endpoints. Never open production through Store.Open for a
read-only investigation because it initializes schema and changes permissions.

# Deployment and rollback

First startup builds indexes by reading the archive once. Plan a stopped-service
backup, maintenance window, free disk for indexes and temporary SQLite sort space,
and additional I/O/CPU/startup latency proportional to retained records. Four
indexes repeat small type/identity/time keys, not complete payloads. A snapshot
of only a live SQLite main file is not a valid backup. Do not build or benchmark
indexes on production during analysis.

Rollback can retain the additive indexes and current DB; do not restore an old
snapshot and rewind policy revisions or delivery acknowledgments. The separate
privilege-policy downgrade requirements still apply. Package deployment and any
production index build are performed by the parent, not this implementation task.

# Validation

- Compare new output with legacy semantics across views, filters, equal-timestamp
  records, cross-kind cursors, multiple findings, zero results and page boundaries.
- Assert query plans use type/date/agent indexes, branch LIMIT precedes merging,
  and only candidate pages enter final sorting.
- Verify read-only enforcement, bounded pool/timeout, concurrent writer progress,
  transaction-local reads and clean close/reopen.
- Use actual archive EXPLAIN and bounded read-only latency probes; never print
  event payloads or agent identities. Benchmark new indexes only on isolated data.
- Run full GOWORK=off verification and build Central RPM14 after review.

# Final implementation details

`history_query.go` selects only bounded metadata, then `history_page.go` closes
that metadata read before primary-key payload lookups in the same read-only
transaction. These local prepared lookups intentionally trade a bounded number
of cheap SQLite index probes for avoiding large payloads in sort buffers and for
stopping payload reads at the response budget. They acquire no second pool
connection and cannot observe payload changes between selection and lookup.
Missing indexed evidence fails the request rather than being silently skipped.

The modernc driver interruption watcher covers the first SQLite step. Metadata
is therefore returned through a bounded JSON aggregate in one row, so a sparse
search for later results cannot continue in an unguarded Rows.Next call. Audit
and error metadata use the same approach. Prepared point reads resolve one unique
key. Both active SQL and waiting for the sole history connection obey the request
deadline; a shorter caller deadline wins. Deadline errors use JSON with status503
and Retry-After1, never request values or SQL diagnostics.

The eight-MiB budget includes conservative escaped metadata and HTML/Unicode JSON
escaping. A valid first record fits under the production budget and is always
returned to preserve progress under smaller test budgets. A row that crosses the
budget is not included and does not advance the cursor. Both source-kind ties and
finding-array item offsets remain part of the existing continuation contract.
Legacy nonpaginated admin methods retain their prior sort order and may return
fewer rows than the requested upper limit when the byte budget is reached.

Release14 adds indexes without changing database user_version2, records,
registrations, policies or keys. Reader initialization occurs only after schema
commit, uses mode=ro/query_only and one connection, and closes before the writer's
checkpoint. Writes, authentication and transaction-local state reads retain their
existing connection ownership. No fallback to the writer pool is permitted.

Rollback to13 can retain the new indexes and current database, but loses the read
isolation/deadline/query improvements. Rollback to versions predating privilege
policy support still requires the separate policy compatibility procedure.

# Verification status

Read-only production inspection found the old event query used only kind indexes,
scanned the projected history and required a temporary global sort on a large
archive. The same pinned modernc SQLite3.49 driver failed to finish a selective
query within a deliberately bounded250ms probe and was cancelled. No production
index, database content, service or trust setting was changed by this analysis.
Actual new-query latency on that archive remains a post-deployment check.

Isolated regressions compare the new output with the old query across filters,
page sizes, same-time source-kind ties and finding items. Additional tests cover
read-only enforcement, concurrent WAL writes/state transactions, additive index
recreation without evidence changes, reader close, controlled pool-wait errors,
active sparse-query cancellation/recovery, response escaping, first-row progress,
large event/audit pages, within-bundle continuation and unchanged admin ordering.

The completed GOWORK=off make verify suite passed: source privacy checked180
candidates with no findings; format, installer/RPM archive mocks, sixteen Python
checks, seven browser-script suites, vet, all three Go packages under race and the
static build passed. Central race coverage took about86seconds with the new large
page and compatibility cases. The active sparse-query regression confirmed
cancellation and subsequent reader reuse. No new-query runtime latency claim is
made before the parent deploys14 and measures the retained archive.
