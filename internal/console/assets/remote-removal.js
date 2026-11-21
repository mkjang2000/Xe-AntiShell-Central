((C) => {
  "use strict";
  const states = {
    queued: ["제거 대기", "warning"], claimed: ["에이전트 확인 중", "warning"],
    started: ["제거 시작", "warning"], succeeded: ["제거 완료 · 등록 해지", "good"],
    failed: ["제거 실패", "danger"], expired: ["요청 만료", "neutral"],
    cancelled: ["요청 취소", "neutral"], result_unknown: ["제거 결과 미확인", "warning"]
  };
  const failures = {
    local_gate: "호스트 설정, 정책 또는 로컬 제거 승인·감사 확인을 통과하지 못했습니다.",
    package_busy: "다른 패키지 작업이 진행 중이었습니다.",
    package_unavailable: "제거할 Xe-AntiShell RPM을 확인하지 못했습니다.",
    removal_failed: "RPM 패키지 제거에 실패했습니다.",
    verification_failed: "RPM 패키지 부재를 확인하지 못했습니다.",
    interrupted: "패키지 작업이 중단됐습니다.",
    authorization_changed: "요청자의 제거 권한이 변경되어 취소됐습니다.",
    site_changed: "에이전트 소속 사이트가 바뀌어 취소됐습니다."
  };
  const unavailable = {
    unsupported: "에이전트가 원격 제거를 지원하지 않습니다.",
    disabled: "호스트 설정에서 원격 제거가 허용되지 않았습니다.",
    stale: "최근 에이전트 보고가 있어야 요청할 수 있습니다.",
    policy_denied: "현재 지정된 보안 정책에서 제거를 금지합니다.",
    update_busy: "에이전트 업데이트가 진행 중입니다.",
    removal_busy: "처리 중인 제거 요청이 있습니다.",
    revoked: "등록이 해지된 에이전트입니다."
  };
  let cached = null;
  const targetKey = agent => JSON.stringify([agent.agent_id, agent.enrollment_id, Boolean(agent.revoked)]);
  const read = (agent, endpoint) => {
    const key = targetKey(agent);
    if (cached?.key === key && (cached.pending || Date.now() - cached.readAt < 5000)) return cached.pending || Promise.resolve(cached.data);
    const entry = {key, readAt: 0, pending: null, data: null};
    cached = entry;
    entry.pending = C.request(endpoint).then(data => {
      if (data.agent_id !== agent.agent_id || data.enrollment_id !== agent.enrollment_id) {
        throw new Error("에이전트 등록이 변경됐습니다. 목록을 새로고침하세요.");
      }
      entry.data = data;
      entry.readAt = Date.now();
      return entry.data;
    }).finally(() => { entry.pending = null; });
    return entry.pending;
  };
  const stillSelected = agent => C.selectedAgent === agent.agent_id &&
    C.state.agents.some(current => current.agent_id === agent.agent_id && targetKey(current) === targetKey(agent));

  const mayRemove = agent => C.session?.permissions ? C.can("agents.remove", agent.site_id) : C.session?.role === "admin";

  C.remoteRemovalPanel = agent => {
    if (!mayRemove(agent) || !agent.enrollment_id) return null;
    const endpoint = `/api/agents/${encodeURIComponent(agent.agent_id)}/remote-removal`;
    const section = C.el("section", "policy-subsection");
    const result = C.el("div", "");
    const refresh = () => {
      result.replaceChildren(C.el("p", "panel-note", "원격 제거 상태를 불러오는 중입니다."));
      return read(agent, endpoint).then(render, error => {
        const message = error?.message || "원격 제거 상태를 불러오지 못했습니다.";
        result.replaceChildren(C.el("p", "notice warning", message), refreshButton());
      });
    };
    const refreshButton = () => C.button("다시 조회", () => { cached = null; return refresh(); }, "small quiet");
    const change = (button, data, cancel) => C.run(button, async () => {
      if (!cancel && !await C.confirm({
        title: "에이전트 원격 제거",
        description: `'${agent.agent_id}'에서 Xe-AntiShell RPM을 제거합니다. 제거 확인 후 현재 등록이 해지됩니다. 기존 수집 기록은 보존됩니다.`,
        accept: "제거 요청", match: agent.agent_id
      })) return;
      if (!stillSelected(agent) || !mayRemove(agent)) {
        throw new Error("에이전트 등록이 변경됐습니다. 목록을 새로고침하세요.");
      }
      const body = { enrollment_id: data.enrollment_id };
      if (cancel) body.order_id = data.job.order_id;
      else body.confirmation = agent.agent_id;
      await C.request(cancel ? endpoint + "/cancel" : endpoint, {method: "POST", body});
      cached = null;
      await refresh();
    });
    const render = data => {
      const items = [];
      if (data.job) {
        const [label, tone] = Object.hasOwn(states, data.job.state) ? states[data.job.state] : ["상태 확인 필요", "warning"];
        const rows = [["진행 상태", C.tag(label, tone)], ["요청 시각", C.time(data.job.issued_at)]];
        if (data.job.state === "queued") rows.push(["요청 만료", C.time(data.job.expires_at)]);
        if (data.job.updated_at) rows.push(["최근 변경", C.time(data.job.updated_at)]);
        items.push(C.facts(rows));
        if (Object.hasOwn(failures, data.job.code)) items.push(C.el("p", "notice warning", failures[data.job.code]));
        if (data.job.state === "result_unknown") items.push(C.el("p", "notice warning", "제거 결과를 받지 못했습니다. 완료 여부를 확인하세요."));
      }
      if (!data.can_request && (!data.job || data.reason && data.reason !== "removal_busy" && !agent.revoked)) {
        items.push(C.el("p", "panel-note", Object.hasOwn(unavailable, data.reason) ? unavailable[data.reason] : "현재 등록은 원격 제거를 요청할 수 없습니다."));
      }
      const actions = C.el("div", "form-actions");
      if (data.can_request) {
        const request = C.button("원격 제거…", () => change(request, data, false), "small");
        actions.append(request);
      }
      if (!agent.revoked && ["queued", "claimed"].includes(data.job?.state)) {
        const cancel = C.button("대기 요청 취소", () => change(cancel, data, true), "small quiet");
        actions.append(cancel);
      }
      actions.append(refreshButton());
      result.replaceChildren(...items, actions);
    };
    section.append(C.el("h3", "", "원격 제거"), result);
    refresh();
    return section;
  };
})(globalThis.XEC);
