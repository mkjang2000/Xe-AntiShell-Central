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
  C.refreshAppliedPolicies = async (force = false) => {
    const selected = id("appliedPolicyAgent").value;
    const agent = C.state.agents.find(a => a.agent_id === selected);
    const out = id("appliedPolicyReport");
    id("reloadAppliedPolicies").disabled = !agent;
    if (!agent) { sequence++; cacheKey = ""; out.replaceChildren(C.empty(C.state.agents.length ? "에이전트를 선택하면 목표 정책과 적용 보고를 확인할 수 있습니다." : "등록된 에이전트가 없습니다.")); return; }
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
    id("appliedPolicyAgent").addEventListener("change",() => C.refreshAppliedPolicies());
    id("reloadAppliedPolicies").addEventListener("click",() => C.refreshAppliedPolicies(true));
    C.onState(() => {
      C.options("appliedPolicyAgent", C.state.agents.map(a => [a.agent_id,a.hostname ? a.agent_id+" · "+a.hostname : a.agent_id]),"에이전트를 선택하세요");
      if (C.policyPane() === "Assignments" && C.view === "policies") C.refreshAppliedPolicies();
    });
  };
})(globalThis.XEC);
