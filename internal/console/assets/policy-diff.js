"use strict";

// Field-level comparison between a host's current console settings and the
// settings a deployment would issue. Lists compare as sets of readable items.
(function (C) {
  const modes = {observe: "탐지 전용", would_block: "모의 대응", enforce: "자동 종료"};
  const uninstall = {allow: "제거 허용", approval_required: "중앙 승인 필요", deny: "일반 제거 금지"};
  const controlModes = {enabled: "규칙 사용", disabled: "끄기", suppress_until: "만료 시각까지 예외"};
  const onoff = value => value ? "사용" : "사용 안 함";
  const list = values => C.array(values).map(String);
  const control = c => [c.service, c.rule_id, controlModes[c.mode] || c.mode, c.reason, c.expires_at].filter(Boolean).join(" · ");
  const scope = s => [s.service, ...C.array(s.protected_dirs).map(d => `보호 ${d}`), ...C.array(s.allowed_write_dirs).map(d => `쓰기 허용 ${d}`),
    ...C.array(s.allowed_tcp_destinations).map(t => `TCP ${t.cidr}${C.array(t.ports).length ? ` ${t.ports.join(",")}` : ""}`)].join(" · ");
  const normalize = settings => {
    const s = C.object(settings);
    return {...s, detection: C.object(s.detection), response: C.object(s.response), monitoring: C.object(s.monitoring), integrity: C.object(s.integrity)};
  };
  const fields = [
    ["탐지 엔진", s => onoff(s.detection.enabled)],
    ["확장 실행 규칙", s => onoff(s.detection.extended_process_rules)],
    ["전역 root·권한 변경 탐지", s => s.detection.privilege_rules ? (s.detection.root_exec_alerts === "all" ? "사용 · 모든 root 실행 경보" : "사용 · 의심 문맥만 경보") : "사용 안 함"],
    ["웹 출처 범위", s => C.policyScopeLabel(s.service_scope)],
    ["웹 실행 파일", s => list(s.detection.web_executables), true],
    ["웹 서비스", s => list(s.detection.web_services), true],
    ["탐지 셸", s => list(s.detection.shells), true],
    ["탐지 예외", s => list(s.detection.allowed_pairs), true],
    ["서비스별 규칙", s => C.array(s.detection.service_rule_controls).map(control), true],
    ["파일·TCP 범위 출처", s => Object.hasOwn(s.detection, "service_observations") ? "중앙 정책" : "호스트 YAML"],
    ["서비스별 파일·TCP 범위", s => C.array(s.detection.service_observations).map(scope), true],
    ["대응 방식", s => modes[s.response.mode] || "미확인"],
    ["대응 동작", s => s.response.action === "terminate" ? "프로세스 종료" : "동작 없음"],
    ["최소 위험 점수", s => String(s.response.risk_threshold ?? "미지정")],
    ["최소 신뢰도", s => String(s.response.min_confidence ?? "미지정")],
    ["필요한 기능", s => list(s.response.required_capabilities), true],
    ["서비스 정책 연결", s => C.array(s.application_bindings).map(b => `${b.service} → ${b.policy_id} v${b.policy_version}`), true],
    ["자원 모니터링", s => onoff(s.monitoring.enabled)],
    ["수집 주기", s => `${s.monitoring.sample_interval_seconds}초`],
    ["프로세스 조회 수", s => `${s.monitoring.process_limit}개`],
    ["에이전트 제거", s => uninstall[s.uninstall_mode] || "미확인"],
    ["정책 유효 기간", s => `${s.validity_hours}시간`],
    ["에이전트 파일 무결성", s => onoff(s.integrity.package_files)],
    ["사이트 YAML SHA-256", s => s.integrity.config_sha256 || "미지정"]
  ];

  // Rows are {label, before, after}; list rows show only removed (−) and added (+) items.
  C.policyDiff = (before, after) => {
    const from = normalize(before), to = normalize(after), rows = [];
    for (const [label, read, isList] of fields) {
      const a = read(from), b = read(to);
      if (!isList) {
        if (a !== b) rows.push({label, before: a, after: b});
        continue;
      }
      const removed = a.filter(item => !b.includes(item)), added = b.filter(item => !a.includes(item)), same = b.length - added.length;
      if (!removed.length && !added.length) continue;
      rows.push({label: same ? `${label} (그대로 ${same}개)` : label,
        before: removed.length ? removed.map(item => `− ${item}`).join("\n") : "—",
        after: added.length ? added.map(item => `+ ${item}`).join("\n") : "—"});
    }
    return rows;
  };

  const hosts = ids => {
    const shown = ids.slice(0, 3).join(", ");
    return ids.length > 3 ? `${shown} 외 ${ids.length - 3}대` : shown;
  };
  // current is the preview's current_policies; template is the server snapshot.
  C.policyChanges = (current, template) => {
    const groups = C.array(current);
    if (!groups.length) return null;
    const container = C.el("section", "policy-changes");
    container.append(C.el("h4", "policy-subheading", "현재 정책 대비 변경 사항"));
    for (const group of groups) {
      const ids = C.array(group.agent_ids), box = C.el("div", "changes-group"), head = C.el("div", "changes-head");
      head.append(C.el("strong", "", hosts(ids)), C.tag(`${ids.length}대`, "neutral"));
      box.append(head);
      if (group.kind === "none") {
        box.append(C.el("p", "field-note", "현재 중앙 정책이 없습니다. 이 정책이 처음 지정됩니다."));
      } else if (group.kind === "direct") {
        box.append(C.el("p", "field-note", `콘솔 밖에서 발급된 정책${group.policy_id ? ` (${group.policy_id})` : ""}이 지정되어 있어 항목별로 비교할 수 없습니다. 전체 정책이 교체됩니다.`));
      } else if (!group.settings) {
        box.append(C.el("p", "field-note", `현재 정책 ${group.policy_id || ""}과 비교할 그룹이 많아 항목 비교를 생략했습니다.`));
      } else {
        if (group.policy_id && group.policy_id !== template.id) box.append(C.el("p", "notice warning", `현재 정책 '${group.policy_id}'을(를) '${template.id}'(으)로 교체합니다.`));
        const rows = C.policyDiff(group.settings, template.settings);
        if (!rows.length) box.append(C.el("p", "field-note", template.settings.service_scope === "all_listening"
          ? "저장된 설정은 같습니다. 이번 배포의 실제 범위는 대상별 웹 서비스에서 확인하세요."
          : "설정 변경이 없습니다. 같은 설정으로 정책 리비전과 유효 기간만 갱신합니다."));
        else {
          const wrap = C.el("div", "table-scroll");
          const table = C.table("현재 정책 대비 변경 사항", ["항목", "현재", "변경 후"], rows.map(row => [row.label, row.before, row.after]));
          table.classList?.add("diff-table");
          wrap.append(table); box.append(wrap);
        }
      }
      container.append(box);
    }
    return container;
  };
})(globalThis.XEC);
