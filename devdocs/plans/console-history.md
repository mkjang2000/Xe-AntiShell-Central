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

## 운영자 판정

탐지 이력 카드의 **운영자 판정과 근거**에서 당시 규칙, 정책 리비전과 근거 이벤트를 확인한다. 원본에 정책 리비전이 없는 기존 경보에는 ‘기록 없음’을 표시한다. 모든 콘솔 역할이 이력을 읽을 수 있고, 관리자와 운영자는 정상·의심·판정 보류 중 하나와 사유를 기록할 수 있다. 판정자와 UTC 시각은 센트럴의 인증 세션과 서버 시계에서 정한다.

에이전트·레코드 종류·레코드 ID·묶음 안의 순번(1부터 시작)으로 하나의 경보를 지정한다. 원래의 단독 finding과 event_bundle이 같은 레코드 ID를 써도 구분된다. 판정은 별도 SQLite 테이블에 추가하며 원본 탐지와 근거 이벤트에는 기존 보존 정책이 적용된다. 서버는 근거 조회 대상이 해당 경보에서 참조한 이벤트인지 확인한다. 20건씩 최신순으로 판정 이력을 조회한다.

변경 API는 마지막으로 확인한 판정 버전과 요청 ID를 받는다. 다른 운영자가 먼저 판정하면 다시 조회해야 하고, 같은 사용자의 동일 요청을 재시도하면 최초 결과를 받는다. 판정과 감사 이력은 같은 트랜잭션에 기록한다.
