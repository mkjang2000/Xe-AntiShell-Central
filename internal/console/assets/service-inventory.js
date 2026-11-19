"use strict";

(function (C) {
  const id = C.id;
  const states = {
    complete: ["전체 수집", "good"], partial: ["일부 수집", "warning"], stale: ["이전 보고", "warning"],
    pending: ["수집 대기", "neutral"], unsupported: ["미지원", "neutral"], unavailable: ["수집 불가", "warning"],
    malformed: ["보고 형식 오류", "danger"]
  };
  const familyLabels = {ipv4: "IPv4", ipv6: "IPv6"};
  const bindingLabels = {wildcard: "모든 주소", interface: "특정 주소", loopback: "루프백"};
  const isOperator = () => ["admin", "operator"].includes(C.session?.role);
  const canPick = () => isOperator() && id("policyServiceScope").value !== "all_listening";
  const fresh = time => {
    const age = C.now() - Date.parse(time);
    return age >= -5000 && age <= 180000;
  };
  const freshState = state => state === "complete" || state === "partial";
  const read = (reply, agent) => {
    if (reply?.agent_id !== agent.agent_id || reply?.enrollment_id !== agent.enrollment_id) throw new Error("에이전트 등록이 변경되었습니다. 목록을 새로고침하세요.");
    const state = Object.hasOwn(states, reply.state) ? reply.state : "malformed";
    const listeners = C.array(reply.listeners).slice(0, 64).filter(row => Number.isInteger(row?.port) && row.port > 0 && row.port <= 65535 &&
      Object.hasOwn(familyLabels, row.family) && Object.hasOwn(bindingLabels, row.binding) && (!row.service || C.validPolicyService(row.service)));
    return {state, sampled_at: reply.sampled_at, received_at: reply.received_at, listeners};
  };
  const current = report => {
    if (report && freshState(report.state) && (!fresh(report.sampled_at) || !fresh(report.received_at))) return {...report, state: "stale"};
    return report;
  };
  const keyFor = agent => {
    const details = C.object(agent.heartbeat?.status?.capability_report?.capabilities?.["inventory.listening_services"]?.details);
    return JSON.stringify([agent.agent_id, agent.enrollment_id, details.contract, details.state, details.snapshot]);
  };
  const emptyText = state => ({
    complete: "이 보고에서 확인된 TCP 대기 포트가 없습니다.",
    partial: "일부만 수집되었으며 이 보고에서 표시할 포트가 없습니다.",
    stale: "표시할 이전 포트 목록이 없습니다.",
    pending: "에이전트의 서비스 인벤토리 보고를 기다리고 있습니다.",
    unsupported: "현재 에이전트에서 서비스 인벤토리를 보고하지 않습니다.",
    unavailable: "에이전트가 서비스 인벤토리를 수집할 수 없습니다.",
    malformed: "서비스 인벤토리 보고를 확인할 수 없습니다."
  }[state]);
  const rowKey = row => row.service?.toLowerCase() || "";
  const render = (view, add) => {
    if (view.loading) { view.body.replaceChildren(C.el("p", "panel-note", "에이전트의 대기 포트를 불러오는 중입니다.")); return; }
    if (view.error) { view.body.replaceChildren(C.el("p", "notice warning", view.error)); return; }
    const report = current(view.report);
    if (!report) { view.body.replaceChildren(C.el("p", "panel-note", "조회할 에이전트를 선택하세요.")); return; }
    const [label, tone] = states[report.state];
    const summary = C.el("div", "service-inventory-meta");
    summary.append(C.tag(label, tone));
    if (report.sampled_at) summary.append(C.el("span", "", `수집 ${C.time(report.sampled_at)}`));
    if (report.received_at) summary.append(C.el("span", "", `중앙 수신 ${C.time(report.received_at)}`));
    if (!report.listeners.length) { view.body.replaceChildren(summary, C.el("p", "panel-note", emptyText(report.state))); return; }
    const nodes = [summary];
    if (report.state === "partial") nodes.push(C.el("p", "panel-note", "일부 포트가 누락됐을 수 있습니다."));
    if (report.state === "stale") nodes.push(C.el("p", "panel-note", "이전 스냅샷입니다. 현재 목록은 다시 조회해 확인하세요."));
    const choose = add && freshState(report.state);
    const picked = choose ? new Set(C.lines(id("webServices").value).map(name => name.toLowerCase())) : null;
    const buttons = new Map(), wrap = C.el("div", "table-scroll service-inventory-table");
    wrap.tabIndex = 0; wrap.setAttribute("role", "region"); wrap.setAttribute("aria-label", "대기 중인 TCP 서비스 표");
    const rows = report.listeners.map(row => {
      const columns = [row.service || "소속 미확인", row.port, familyLabels[row.family], bindingLabels[row.binding]];
      if (choose) {
        if (!row.service) columns.push("—");
        else {
          const key = rowKey(row), button = C.button(picked.has(key) ? "추가됨" : "추가", () => {
            if (!canPick() || !freshState(current(view.report)?.state) || !add(row.service)) return;
            for (const matching of buttons.get(key)) { matching.textContent = "추가됨"; matching.disabled = true; }
          }, "mini-button");
          button.setAttribute("aria-label", `${row.service} 웹 서비스 목록에 추가`);
          button.disabled = picked.has(key);
          if (!buttons.has(key)) buttons.set(key, []);
          buttons.get(key).push(button); columns.push(button);
        }
      }
      return columns;
    });
    wrap.append(C.table("대기 중인 TCP 서비스", ["시스템 서비스", "TCP 포트", "주소 유형", "바인딩", ...(choose ? ["웹 서비스"] : [])], rows));
    nodes.push(wrap, C.el("p", "field-note", "바인딩은 서버의 대기 주소 범위입니다. 방화벽이나 외부에서의 연결 가능 여부는 따로 확인하세요."));
    if (choose) nodes.push(Object.assign(C.el("span", "sr-only"), {id: "policyInventoryActionStatus", role: "status"}));
    view.body.replaceChildren(...nodes);
  };
  const viewState = body => ({body, key: null, generation: 0, loading: false, report: null, error: ""});
  const load = async (view, agent, key, update, force = false) => {
    if (key === view.key && !force) { if (!view.loading) update(); return; }
    const generation = ++view.generation;
    Object.assign(view, {key, loading: !!agent, report: null, error: ""});
    update();
    if (!agent) return;
    try {
      const reply = await C.request(`/api/agents/${encodeURIComponent(agent.agent_id)}/service-inventory`);
      if (generation === view.generation) view.report = read(reply, agent);
    } catch (error) {
      if (generation === view.generation) view.error = error.message || "서비스 인벤토리를 불러오지 못했습니다.";
    } finally {
      if (generation === view.generation) { view.loading = false; update(); }
    }
  };

  let picker;
  const pickerAgent = () => C.state.agents.find(agent => !agent.revoked && agent.agent_id === id("policyInventoryAgent").value);
  const loadPicker = force => {
    if (!picker || !id("policyServiceInventory").open || !isOperator()) return;
    const agent = pickerAgent();
    return load(picker, agent, agent ? keyFor(agent) : "", renderPicker, force);
  };
  const renderPicker = () => {
    id("policyInventoryRefresh").disabled = !pickerAgent() || picker.loading || !isOperator();
    render(picker, canPick() ? picker.add : null);
    C.policyServices?.refreshNameHints?.();
  };
  C.policyInventory = {
    init(changed) {
      picker = viewState(id("policyInventoryResult"));
      picker.add = service => {
        const field = id("webServices"), names = C.lines(field.value);
        if (names.some(name => name.toLowerCase() === service.toLowerCase())) return false;
        field.value = [...names, service].join("\n");
        changed();
        C.policyServices?.refreshNameHints?.();
        C.text("policyInventoryActionStatus", `${service}를 웹 서비스 목록에 추가했습니다.`);
        return true;
      };
      id("policyServiceInventory").addEventListener("toggle", () => loadPicker());
      id("policyInventoryAgent").addEventListener("input", event => event.stopPropagation?.());
      id("policyInventoryAgent").addEventListener("change", () => loadPicker());
      id("policyInventoryRefresh").addEventListener("click", () => loadPicker(true));
      renderPicker();
    },
    syncAgents() {
      if (!picker) return;
      const agents = C.state.agents.filter(agent => !agent.revoked);
      const list = id("policyInventoryAgent"), previous = list.value;
      const optionKey = JSON.stringify(agents.map(agent => [agent.agent_id, agent.hostname]));
      if (picker.optionKey !== optionKey) {
        picker.optionKey = optionKey;
        const options = agents.map(agent => Object.assign(C.el("option", "", agent.hostname && agent.hostname !== agent.agent_id ? `${agent.agent_id} · ${agent.hostname}` : agent.agent_id), {value: agent.agent_id}));
        list.replaceChildren(Object.assign(C.el("option", "", "에이전트 선택"), {value: ""}), ...options);
        list.value = agents.some(agent => agent.agent_id === previous) ? previous : "";
      }
      loadPicker();
    },
    render() { if (picker) renderPicker(); },
    suggestedNames() {
      const agent = picker && pickerAgent();
      if (!agent || picker.key !== keyFor(agent)) return [];
      const report = current(picker?.report);
      return freshState(report?.state) ? report.listeners.map(row => row.service).filter(Boolean) : [];
    }
  };

  let fleet;
  C.agentServiceInventory = agent => {
    if (agent.revoked) return null;
    const registration = JSON.stringify([agent.agent_id, agent.enrollment_id]);
    if (!fleet || fleet.registration !== registration) {
      const section = C.el("section", "service-inventory-result");
      const head = C.el("div", "section-heading"), body = C.el("div");
      const view = viewState(body);
      const update = () => { refresh.disabled = view.loading; render(view); };
      const refresh = C.button("서비스 다시 조회", () => load(view, view.agent, keyFor(view.agent), update, true), "small quiet");
      body.setAttribute("aria-live", "polite");
      head.append(C.el("h3", "", "대기 중인 TCP 서비스"), refresh);
      section.append(head, body);
      fleet = {registration, section, view, update};
    }
    fleet.view.agent = agent;
    load(fleet.view, agent, keyFor(agent), fleet.update);
    return fleet.section;
  };

  C.serviceTargetPreview = (groups, targets) => {
    const invalid = () => new Error("대상별 웹 서비스 목록이 배포 대상과 일치하지 않습니다. 미리보기를 다시 생성하세요.");
    const ids = targets.map(target => target?.agent_id);
    const unmatched = new Set(ids);
    if (!ids.length || ids.some(value => typeof value !== "string" || !value) || unmatched.size !== ids.length ||
        !Array.isArray(groups) || !groups.length || groups.length > ids.length) throw invalid();
    const section = Object.assign(C.el("section", "policy-changes inventory-targets"), {id: "previewServiceTargets"});
    section.append(C.el("h4", "policy-subheading", "대상별 웹 서비스"));
    for (const group of groups) {
      const hosts = group?.agent_ids, services = group?.services;
      if (!Array.isArray(hosts) || !hosts.length || !hosts.every(host => unmatched.delete(host)) ||
          !Array.isArray(services) || !services.length || services.length > 64 || !services.every(C.validPolicyService) ||
          new Set(services.map(unit => unit.toLowerCase())).size !== services.length) throw invalid();
      const details = C.el("details", "changes-group");
      details.open = groups.length <= 4;
      const title = hosts.length === 1 ? hosts[0] : `${hosts[0]} 외 ${hosts.length - 1}대`;
      details.append(C.el("summary", "", `${title} · 서비스 ${services.length}개`));
      if (hosts.length > 1) details.append(C.el("p", "field-note", `에이전트 ${hosts.join(" · ")}`));
      details.append(C.el("p", "service-target-names", services.join(" · ")));
      section.append(details);
    }
    if (unmatched.size) throw invalid();
    return section;
  };
})(globalThis.XEC);
