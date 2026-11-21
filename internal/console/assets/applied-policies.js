"use strict";

(function (C) {
  const states = {
    applied: ["목표 리비전 적용 확인", "good"],
    previous: ["이전 리비전 적용 확인", "warning"],
    legacy_applied: ["리비전 적용 보고 · 해시 미보고", "neutral"],
    legacy_previous: ["이전 리비전 보고 · 해시 미보고", "warning"],
    unverified: ["적용본 미확인", "neutral"],
    stale: ["최신 적용 상태 미확인", "warning"],
    mismatch: ["보고된 정책 해시 불일치", "danger"],
    none: ["지정 정책 없음", "neutral"]
  };
  const id = name => C.id(name);
  let sequence = 0, cacheKey = "", expiresAt = 0;
  C.applicationStateTag = value => C.tag(...(Object.hasOwn(states, value) ? states[value] : states.unverified));

  function policySection(policy, title, open) {
    const section = C.el("details", "app-policy-snapshot"); section.open = open;
    section.append(C.el("summary", "", title+" · 리비전 "+policy.revision));
    const apps = C.array(policy.applications);
    const facts = C.facts([["호스트 기본 정책", policy.policy_id], ["호스트 기본 탐지·대응", C.appPolicyTag(policy)],
      ["연결된 서비스", apps.length+"개"], ["정책 만료", C.time(policy.expires_at)]]);
    section.append(facts);
    if (apps.length) {
      section.append(C.appProjectionTable(apps, title+"의 서비스별 정책"));
      for (const app of apps) {
        const details = C.el("details","technical"), d = C.object(app.detection), r = C.object(app.response);
        details.append(C.el("summary","", app.service+" · 규칙과 대응 조건"), C.facts([
          ["정책", app.policy_id+" · v"+app.policy_version], ["탐지 셸", C.array(d.shells).join(" · ") || "없음"],
          ["실행 예외", C.array(d.allowed_pairs).join(" · ") || "없음"],
          ["서비스별 규칙", C.array(d.service_rule_controls).map(c => [c.rule_id,c.mode,c.reason,c.expires_at].filter(Boolean).join(" · ")).join("\n") || "프로필 기본값"],
          ["파일·TCP 범위", C.serviceScopeSummary(d)], ["최소 위험 점수 / 신뢰도", r.risk_threshold+" / "+r.min_confidence],
          ["필수 기능", C.array(r.required_capabilities).join(" · ") || "미지정"]
        ]));
        section.append(details);
      }
    }
    section.append(C.raw(policy, title+" 전체 JSON"));
    return section;
  }
  C.agentApplicationPolicies = (agent, result) => {
    const container = C.el("section","app-policy-status");
    const report = C.object(result.application_status);
    let state = Object.hasOwn(states, report.state) ? report.state : "unverified";
    const applied = result.applied_policy, desired = result.policy;
    const hb = C.object(agent.heartbeat), status = C.object(hb.policy_status);
    const matchedHeartbeat = hb.agent_id === agent.agent_id && hb.enrollment_id === agent.enrollment_id;
    const current = matchedHeartbeat && C.connection(agent).key === "online" && !agent.revoked;
    const legacy = state === "legacy_applied" || state === "legacy_previous";
    let exact = state === "applied" || state === "previous" || legacy;
    if (legacy && C.array(applied?.applications).length) { state = "unverified"; exact = false; }
    if (exact && applied?.expires_at && Date.parse(applied.expires_at) <= C.now()) { state = "stale"; exact = false; }
    if (exact && !current) { state = "stale"; exact = false; }
    if (exact && (!applied || applied.agent_id !== agent.agent_id || applied.enrollment_id !== agent.enrollment_id ||
      applied.revision !== report.active_revision || !desired || report.desired_revision !== desired.revision ||
      ((state === "applied" || state === "legacy_applied") ? applied.revision !== desired.revision : applied.revision >= desired.revision))) {
      state = "unverified"; exact = false;
    }
    container.append(C.tag(...states[state]));
    container.append(C.facts([["중앙 목표 리비전", desired?.revision ?? "없음"], ["호스트 보고 리비전", report.active_revision ?? "미보고"],
      ["최근 하트비트", matchedHeartbeat ? C.time(hb.sent_at) : "미보고"], ["적용 보고 시각", matchedHeartbeat && status.applied_at ? C.time(status.applied_at) : "미보고"]]));
    if (desired) container.append(policySection(desired, "중앙 목표 정책", !exact));
    if (exact) container.append(policySection(applied, legacy ? "호스트가 보고한 리비전의 정책" : "호스트 적용 정책", true));
    if (state === "none") container.append(C.el("p","panel-note","이 등록에 발급한 중앙 정책이 없습니다."));
    else if (!exact) container.append(C.el("p","inline-note","현재 등록과 리비전, 정책 해시가 일치하는 최신 적용 보고를 기다립니다."));
    if (exact) container.append(C.el("p","panel-note","적용 보고는 호스트가 정책 묶음을 수락한 시점을 나타냅니다. 서비스별 센서 수신과 대응 결과는 에이전트 상세와 탐지 이력에서 확인하세요."));
    return container;
  };
  // Fleet table: one row per registered agent, categorised from the same
  // heartbeat evidence as the agent list. Details load for one selected row.
  let selected = "";
  const chosen = new Set();
  const writable = () => C.session?.permissions ? C.can("policies.deploy") : ["admin", "operator"].includes(C.session?.role);
  const categories = {applied: ["적용 완료", "good"], pending: ["적용 대기", "warning"], error: ["오류", "danger"], unknown: ["확인 필요", "neutral"], none: ["정책 없음", "neutral"], outdated: ["재배포 필요", "warning"]};
  C.assignmentCategory = agent => {
    const state = C.policyState(agent);
    if (!agent.desired_policy_revision) return "none";
    if (state.tone === "danger") return "error";
    if (state.applied) return "applied";
    if (state.label === "적용 대기") return "pending";
    return "unknown";
  };
  const templateNote = agent => {
    if (!agent.desired_policy_revision) return null;
    const template = C.state.templates.find(t => t.id === agent.desired_policy_id);
    const name = template ? `${template.name} · ${agent.desired_policy_id}` : agent.desired_policy_id || "콘솔 밖에서 발급한 정책";
    const tag = {current: ["현재 저장본", "good"], changed: ["저장본 변경됨 · 재배포 필요", "warning"], missing: ["원본 정책 삭제됨", "neutral"]}[agent.policy_template_state];
    const cell = C.el("div", "assignment-policy");
    cell.append(C.el("span", "", name));
    if (tag) cell.append(C.tag(...tag));
    return cell;
  };
  const filtered = () => {
    const query = id("assignmentSearch").value.trim().toLowerCase(), policy = id("assignmentPolicyFilter").value, state = id("assignmentStateFilter").value;
    return C.state.agents.filter(agent => !agent.revoked).filter(agent => {
      if (query && !`${agent.agent_id} ${agent.hostname || ""}`.toLowerCase().includes(query)) return false;
      if (policy === "-" ? agent.desired_policy_revision > 0 : policy && agent.desired_policy_id !== policy) return false;
      if (state === "outdated") return agent.policy_template_state === "changed";
      return !state || C.assignmentCategory(agent) === state;
    });
  };
  const renderSelection = () => {
    for (const agentID of [...chosen]) if (!C.state.agents.some(agent => agent.agent_id === agentID && !agent.revoked)) chosen.delete(agentID);
    C.text("assignmentSelection", chosen.size ? `${chosen.size}대 선택` : "배포할 에이전트를 표에서 선택할 수 있습니다.");
    id("assignmentDeploy").disabled = !chosen.size || !writable();
  };
  C.renderAssignments = () => {
    const active = C.state.agents.filter(agent => !agent.revoked), counts = {applied: 0, pending: 0, error: 0, unknown: 0, none: 0, outdated: 0};
    for (const agent of active) { counts[C.assignmentCategory(agent)]++; if (agent.policy_template_state === "changed") counts.outdated++; }
    const stateFilter = id("assignmentStateFilter").value;
    id("assignmentSummary").replaceChildren(...Object.entries(categories).filter(([key]) => counts[key] || key === "applied").map(([key, [label, tone]]) => {
      const chip = C.button("", () => { id("assignmentStateFilter").value = stateFilter === key ? "" : key; C.renderAssignments(); }, `summary-chip ${tone}`);
      chip.append(C.el("span", "", label), C.el("strong", "", String(counts[key])));
      chip.setAttribute("aria-pressed", String(stateFilter === key));
      return chip;
    }));
    const policies = [...new Set(active.map(agent => agent.desired_policy_id).filter(Boolean))].sort();
    C.options("assignmentPolicyFilter", [["-", "정책 없음"], ...policies.map(policy => [policy, C.state.templates.find(t => t.id === policy)?.name ? `${C.state.templates.find(t => t.id === policy).name} · ${policy}` : policy])], "전체 정책");
    const agents = filtered();
    C.text("assignmentCount", agents.length === active.length ? `${active.length}대` : `${agents.length} / ${active.length}대`);
    const rows = agents.map(agent => {
      const row = C.el("tr"), state = C.policyState(agent), category = C.assignmentCategory(agent), hb = C.object(agent.heartbeat);
      if (agent.agent_id === selected) row.className = "selected-row";
      const pick = C.el("input"); pick.type = "checkbox"; pick.checked = chosen.has(agent.agent_id); pick.setAttribute("aria-label", `${agent.agent_id} 선택`);
      pick.addEventListener("change", () => { if (pick.checked) chosen.add(agent.agent_id); else chosen.delete(agent.agent_id); renderSelection(); });
      const identity = C.el("td", "cell-primary", agent.agent_id); identity.append(C.el("span", "secondary", agent.hostname || "호스트명 보고 없음"));
      const policyCell = C.el("td"); policyCell.append(templateNote(agent) || C.el("span", "cell-muted", "중앙 정책 없음"));
      const stateCell = C.el("td"); stateCell.append(C.tag(category === "none" ? "정책 없음" : state.label, category === "none" ? "neutral" : state.tone));
      const revision = C.el("td", "cell-muted", `${state.active ?? "—"} / ${state.desired ?? "—"}`);
      const last = C.el("td", "cell-muted", C.age(hb.sent_at));
      const action = C.el("td"), open = C.button("상세", () => { selected = agent.agent_id; C.renderAssignments(); C.refreshAppliedPolicies(true); id("appliedPolicyPanel").scrollIntoView?.({block: "start"}); id("appliedPolicyTitle").focus?.({preventScroll: true}); }, "small");
      open.setAttribute("aria-label", `${agent.agent_id} 적용 상세`); action.append(open);
      const pickCell = C.el("td"); pickCell.append(pick);
      row.append(pickCell, identity, policyCell, stateCell, revision, last, action);
      return row;
    });
    if (!rows.length) { const row = C.el("tr"), cell = C.el("td", "empty-cell", active.length ? "조건에 맞는 에이전트가 없습니다." : "등록된 에이전트가 없습니다."); cell.colSpan = 7; row.append(cell); rows.push(row); }
    id("assignmentRows").replaceChildren(...rows);
    id("assignmentSelectAll").checked = agents.length > 0 && agents.every(agent => chosen.has(agent.agent_id));
    renderSelection();
  };
  C.refreshAppliedPolicies = async (force = false) => {
    const agent = C.state.agents.find(a => a.agent_id === selected);
    const out = id("appliedPolicyReport");
    id("appliedPolicyPanel").hidden = !agent;
    id("reloadAppliedPolicies").disabled = !agent;
    if (!agent) { sequence++; cacheKey = ""; out.replaceChildren(); return; }
    C.text("appliedPolicyTitle", `적용 상세 · ${agent.agent_id}${agent.hostname ? ` · ${agent.hostname}` : ""}`);
    const key = C.policyIdentity(agent);
    if (!force && key === cacheKey && !(expiresAt && expiresAt <= C.now())) return;
    expiresAt = 0;
    cacheKey = key;
    const token = ++sequence;
    out.replaceChildren(C.el("p","panel-note","정책과 적용 보고를 조회하고 있습니다."));
    try {
      const result = await C.request("/api/agents/"+encodeURIComponent(agent.agent_id)+"/policy");
      if (sequence !== token) return;
      if (!C.policyResponseMatches(agent, result)) throw new Error("대상 등록 또는 목표 리비전이 변경되었습니다. 목록을 갱신한 후 다시 조회하세요.");
      const expiry = Date.parse(result.applied_policy?.expires_at);
      if (expiry > C.now()) expiresAt = expiry;
      out.replaceChildren(C.agentApplicationPolicies(agent,result));
    } catch (error) {
      if (sequence === token) out.replaceChildren(C.el("p","notice warning",error.message || "정책 조회에 실패했습니다."));
    }
  };
  C.initAppliedPolicies = () => {
    for (const name of ["assignmentSearch", "assignmentPolicyFilter", "assignmentStateFilter"]) id(name).addEventListener(name === "assignmentSearch" ? "input" : "change", () => C.renderAssignments());
    id("assignmentSelectAll").addEventListener("change", () => {
      for (const agent of filtered()) if (id("assignmentSelectAll").checked) chosen.add(agent.agent_id); else chosen.delete(agent.agent_id);
      C.renderAssignments();
    });
    id("assignmentDeploy").addEventListener("click", () => {
      const agents = C.state.agents.filter(agent => chosen.has(agent.agent_id));
      const policies = new Set(agents.map(agent => agent.desired_policy_id || ""));
      const only = policies.size === 1 ? [...policies][0] : "";
      C.startDeployment?.({templateID: C.state.templates.some(t => t.id === only) ? only : "", agentIDs: [...chosen]});
    });
    id("reloadAppliedPolicies").addEventListener("click",() => C.refreshAppliedPolicies(true));
    id("openAgentDetail").addEventListener("click",() => { if (selected) C.selectAgent?.(selected); });
    C.onState(() => {
      if (C.policyPane() !== "Assignments") return;
      C.renderAssignments();
      if (C.view === "policies") C.refreshAppliedPolicies();
    });
  };
})(globalThis.XEC);
