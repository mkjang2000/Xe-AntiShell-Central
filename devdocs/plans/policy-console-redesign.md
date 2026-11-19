# Purpose

Make the security policy workspace usable for daily operation: shorten the
editor, remove raw JSON entry, connect saving to deployment, show the whole
fleet's policy state, and show what a deployment changes before it is
confirmed. The signed managed-v1 policy contract and template schema are
unchanged.

# Contract and Scope

- Templates keep the same `settings` schema. An unchanged load and save
  returns the same settings, including custom capability keys, an observe
  policy's saved action, unchanged rule-control expiries and file/TCP scopes,
  and the archived integrity draft.
- `GET /api/state` adds `desired_policy_id` and `policy_template_state` to
  each agent whose desired revision was issued by the console. The state
  compares the deployed settings with the template's latest saved settings:
  `current`, `changed` (saved after deployment) or `missing` (deleted).
- `POST /api/deploy/preview` adds `current_policies`: preview targets grouped
  by the policy behind their current revision. `console` groups carry the
  stored settings, `direct` groups name a policy issued outside the console and
  `none` groups have no central policy. At most 32 distinct settings are
  returned; further groups set `comparison_omitted`. The preview token, its
  signature and deployment authorization are unchanged.
- Template validation rejects with the protocol's reason appended, so the
  operator sees which field failed.

# Design

- Workspace tabs: 정책 편집 · 적용 현황 · 배포. One term, "정책", replaces
  "템플릿" in the console.
- Editor sections: 개요 (ID, name, description, live summary) · 탐지 · 대응 ·
  서비스별 설정 · 에이전트 설정 · 사용처. All sections remain in one form, so
  hidden values are saved. Tabs mark unsaved (amber) and invalid (red)
  sections. Validation errors carry a section; saving switches to it and shows
  the message beside the save button.
- The save bar is sticky at the bottom of the editor. `scroll-padding-bottom`
  keeps keyboard focus clear of it.
- Response mode is three cards. The wire action follows the mode (`terminate`
  outside observe); an observe policy keeps the action it was saved with.
  Mode changes never add capability conditions; when none are selected the
  editor points to the explicit recommended-conditions button. Thresholds and
  conditions are hidden, not cleared, in observe mode.
- Rule controls and file/TCP scopes use row editors. Rule IDs come from the
  server's `rule_ids`; expiries are entered in local time and stored as UTC.
  Scope rows parse `CIDR port,port` lines and check absolute clean paths,
  write directories inside protected roots, IPv4 host bits and port ranges
  before the request. The tri-state scope source (host YAML, central empty,
  central list) is a checkbox plus an explicit "all scopes off" warning.
- Header actions: 복제 (copy saved settings into a new unsaved policy),
  배포… (open the deployment tab with the saved policy selected; refused while
  unsaved) and 삭제. Viewers cannot use them.
- 적용 현황 lists every non-revoked agent with its policy, state category and
  template freshness. Summary chips filter by category; selected rows open
  deployment with those agents (and their shared policy) preselected. Applied
  snapshots load for one selected row. Host security boundary facts moved to
  the agent detail.
- 배포 is numbered steps with agent search, select-visible/clear and a target
  count. The preview adds a per-group comparison table (현재 → 변경 후) above the
  target table. Staged rollouts load when the tab opens.

# Validation

Browser-script tests cover section routing of validation errors, action
derivation, duplicate/deploy shortcuts and viewer gating, rule-control and
scope row round trips and rejections, comparison rows and grouping, and the
fleet table's filters and deployment hand-off. Go tests cover the new state
fields, preview grouping (none, console, direct) and the validation reason. A
handler test requires every asset referenced by `index.html` to be served.
