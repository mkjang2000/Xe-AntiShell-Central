"use strict";

(function (C) {
  const revision = value => Number.isSafeInteger(value) && value >= 0 ? String(value) : "미보고";

  function localTermination(capabilities, sentAt) {
    const cap = C.object(capabilities["response.terminate"]);
    if (cap.provider !== "pidfd" || cap.implementation !== "implemented" || cap.state !== "supported") return "미확인";
    if (cap.runtime_state === "available") return "허용 안 함 · 호스트 보고";
    const verified = Date.parse(cap.verified_at);
    if (cap.runtime_state === "active" && verified > 0 && verified <= Date.parse(sentAt) + 60000) return "허용 · 호스트 보고";
    return "미확인";
  }

  function renderReport() {
    const target = C.id("hostBoundaryReport");
    const agent = C.state.agents.find(item => item.agent_id === C.id("hostBoundaryAgent").value);
    if (!agent) {
      target.replaceChildren(C.empty(C.state.agents.length ? "에이전트를 선택하면 최근 보고를 확인할 수 있습니다." : "조회할 등록 에이전트가 없습니다."));
      return;
    }
    const hb = C.object(agent.heartbeat);
    const bound = Boolean(agent.enrollment_id) && hb.agent_id === agent.agent_id && hb.enrollment_id === agent.enrollment_id;
    const current = bound && !agent.revoked && C.fresh(hb.sent_at);
    const report = C.object(C.object(hb.status).capability_report);
    const policy = C.object(hb.policy_status);
    const results = {local: "로컬 설정 사용", applied: "적용", rejected: "거절", stale: "유효기간 경과"};
    const status = current && Object.hasOwn(results, policy.result) ? results[policy.result] : "미확인";
    const facts = [
      ["중앙 등록", agent.revoked ? "등록 해지" : "등록 유지"],
      ["등록 ID", agent.enrollment_id],
      ["중앙 목표 정책 리비전", revision(agent.desired_policy_revision)],
      ["현재 등록의 하트비트", bound ? C.time(hb.sent_at) : "미보고"],
      ["하트비트 상태", current ? "최근 보고" : C.connection(agent).key === "stale" && bound ? "보고 지연" : "현재 상태 미확인"],
      ["에이전트 적용 리비전", current ? revision(policy.active_revision) : "미확인"],
      ["에이전트 정책 적용 결과", status],
      ["프로세스 종료 로컬 허용", current ? localTermination(C.object(report.capabilities), hb.sent_at) : "미확인"]
    ];
    target.replaceChildren(C.facts(facts));
  }

  C.id("hostBoundaryAgent").addEventListener("change", renderReport);
  C.onState(() => {
    C.options("hostBoundaryAgent", C.state.agents.map(agent => [agent.agent_id, agent.hostname ? `${agent.agent_id} · ${agent.hostname}` : agent.agent_id]), "에이전트를 선택하세요");
    renderReport();
  });
})(globalThis.XEC);
