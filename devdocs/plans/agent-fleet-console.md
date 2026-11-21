# Purpose

Make the agent list and agent detail usable at a glance. The list shows one
overall state, the assigned policy with its response mode, recent detection
volume, resource pressure and the agent version instead of revision numbers
and duplicated heartbeat columns. The detail moves out from under the list into its own route with
tabs, so problems surface first and raw diagnostics stay one click away. Agent
heartbeats and the signed managed-v1 policy contract are unchanged.

# Contract and Scope

- `GET /api/state` adds `desired_response_mode` to each agent with a signed
  desired policy: that policy's default response mode.
  `desired_service_response_modes` lists the distinct service-binding modes
  that differ from it, weakest first, and is omitted when there are none.
  Both come from the signed policy, so directly issued policies report them
  too; `desired_policy_id` keeps naming console templates only. SQLite
  extracts the fields, so a refresh does not decode whole policies.
- The values describe the desired revision. Whether the host applied it stays
  the heartbeat's policy status, shown next to it.
- Each agent also gets `detections_24h`, the number of detected events whose
  central receipt time is within 24 hours of `server_time` (zero included),
  and `last_detection_at` when there is one. A detected event is a standalone
  finding or an event bundle with at least one finding; a bundle counts once
  however many rules it matched, while the history view lists each finding.
  Receipt time is what the history period filter uses.
- `detections: {since, truncated}` gives the window start. The count reads
  only the indexes detection history already maintains and never payloads.
  One refresh scans at most 100,000 entries across the fleet (about 1 µs
  each); past that, `truncated` is set and every count is a lower bound. No schema or index change.
- No agent change: version, platform, collector counters and resources are
  already in the heartbeat, and detections are already delivered records.

# Design

- List columns: 에이전트 / 호스트 (with OS) · 상태 · 정책 · 대응 · 최근
  탐지 (24시간) · 자원 · 버전. 상태 is one label in precedence order: 등록 해지, 보고 없음, 수신 지연,
  수집 오류/점검 필요, 정책 확인 필요, then 정상, with the heartbeat age below.
  The same precedence feeds the overview's "우선 확인할 서버".
- 정책 · 대응 shows the template name (or the policy ID, or "콘솔 밖에서 발급한
  정책"), the policy state and the desired response mode. A template saved
  after deployment adds "재배포 필요". The detail adds a direct policy's ID
  once it has loaded the signed policy.
- 최근 탐지 shows the count with the time of the latest one; the count opens
  detection history filtered to that agent and the last 24 hours, with type
  and search cleared. Zero reads 없음, a missing count (older server) 미확인.
  A truncated scan adds 이상 to counts and shows zero as 확인 안 됨.
- 자원 shows CPU, memory and the root filesystem. Fresh values at or above
  80/90% disk and 90/95% memory are highlighted; values from an old sample are
  muted and labelled.
- Rows open the detail; the agent ID is also a link. Sort: 상태 우선 (attention
  first, revoked last), 이름순, 최근 탐지 많은 순, 디스크 사용률. The connection filter gains
  "확인 필요".
- The detail route is `#agents/<agent ID>`; `#agents` returns to the list and
  leaving the view clears the selection. An unknown ID shows a notice instead
  of an empty page. The tab resets to 개요 when another agent opens.
- Header: agent ID, hostname, OS and version, connection/collection/policy
  tags, the recent detection count as in the list, history and removal
  shortcuts.
- Tabs render only the selected panel:
  - 개요: a "확인 필요" list (attention state, reported errors, dropped or
    unparsed events, disk/memory pressure, capabilities in warning or error,
    redeploy needed), resource cards and one set of identity facts. Resource
    and capability items require a current heartbeat.
  - 정책: assigned policy and applied snapshot, the host boundary facts
    collapsed, and agent file integrity.
  - 서비스·포트: listening TCP services, loaded only when the tab opens.
  - 자원: filesystems with mounts of identical size, usage and inodes merged
    (non-zero usage only), network devices with loopback, veth, bridge and
    container interfaces collapsed by name, disk I/O and processes.
  - 기능 진단: capabilities in warning or error first; the rest, planned
    features and both raw reports are collapsed.

# Validation

Browser-script tests cover state precedence and attention, list cells
(policy name, response modes, detection counts including unknown and
truncated ones, resource highlighting and staleness), the detection history
shortcut's filters, sorting and the attention filter, filesystem merging, interface grouping, the issue
list's freshness gate, routing (open, return, unknown and malformed IDs) and
per-tab rendering. Existing capability presentation tests run on the 기능 진단
tab. Go tests cover the new state fields for console, direct and absent
policies, and mode ordering, and detection counts: window boundary, bundles
with several or no findings, standalone findings, plain events, agents
without detections and the truncated scan.
