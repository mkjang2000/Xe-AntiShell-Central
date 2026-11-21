"use strict";

(function (C) {
  const root = globalThis;
  const tabs = [["overview", "개요"], ["policy", "정책"], ["services", "서비스·포트"], ["resources", "자원"], ["capabilities", "기능 진단"]];
  const defaultOpen = () => new Set(["filesystems", "network"]);
  const fleet = {policy: null, policyKey: "", policyLoading: false, processPage: 0, open: defaultOpen(), tab: "overview", tabButtons: new Map()};
  const heartbeat = agent => C.object(agent.heartbeat);
  const status = agent => C.object(heartbeat(agent).status);
  const platform = agent => C.object(C.object(status(agent).capability_report).platform);
  const modes = {observe: "탐지 전용", would_block: "모의 대응", enforce: "자동 종료"};
  const toneRank = {danger: 0, warning: 1, neutral: 2, pending: 2, blue: 2, good: 3};
  const byTone = (a, b) => (toneRank[a.tone] ?? 2) - (toneRank[b.tone] ?? 2);
  const when = value => Date.parse(value) > 0 ? `${C.time(value)} (${C.age(value)})` : "보고 없음";
  const percentOf = (used, total) => Number.isFinite(used) && used >= 0 && Number.isFinite(total) && total > 0 ? used / total * 100 : null;
  // Disk and memory pressure: [warning, danger] percent of capacity.
  const limits = {disk: [80, 90], memory: [90, 95]};
  // Read-only images always report full; they are not capacity problems.
  const imageFilesystems = new Set(["squashfs", "iso9660", "udf"]);
  const virtualInterface = /^(lo$|veth|docker|br-|virbr|vboxnet|cni|flannel|cali|vxlan|tunl|kube-|podman|vnet|lxc|weave|genev)/;
  // Continuous streams whose stale evidence means collection may have stopped.
  // Sporadic observations (file, TCP, interpreter) can be quiet while healthy.
  const coreCapabilities = new Set(["collector.tetragon", "collector.audit", "observation.process_exec"]);

  C.usageTone = (kind, value) => !Number.isFinite(value) ? "" : value >= limits[kind][1] ? "danger" : value >= limits[kind][0] ? "warning" : "";

  // One overall state per agent in precedence order. attention marks agents
  // the overview lists first; reason is the short explanation shown there.
  C.agentStatus = agent => {
    const connection = C.connection(agent);
    if (connection.key === "revoked") return {key: "revoked", label: "등록 해지", tone: "neutral", reason: "", attention: false};
    if (connection.key === "unknown") return {key: "unknown", label: "보고 없음", tone: "neutral", reason: "등록 후 하트비트 보고 없음", attention: true};
    if (connection.key === "stale") return {key: "stale", label: "수신 지연", tone: "warning", reason: "하트비트 수신 지연", attention: true};
    const health = C.health(agent), policy = C.policyState(agent);
    if (["warning", "danger"].includes(health.tone)) return {key: "health", label: health.label, tone: health.tone, reason: health.label, attention: true};
    if (policy.desired > 0 && !policy.applied) return {key: "policy", label: "정책 확인 필요", tone: policy.tone === "danger" ? "danger" : "warning", reason: policy.label, attention: true};
    if (health.tone !== "good") return {key: "health", label: health.label, tone: "neutral", reason: "", attention: false};
    return {key: "ok", label: "정상", tone: "good", reason: "", attention: false};
  };

  C.osLabel = agent => {
    const p = platform(agent), pretty = typeof p.pretty_name === "string" ? p.pretty_name.replace(/\s*\([^)]*\)\s*$/, "").trim() : "";
    return pretty || [p.distribution, p.version_id].filter(value => typeof value === "string" && value).join(" ");
  };

  C.resourceSummary = agent => {
    const resources = C.object(heartbeat(agent).resources);
    if (!resources.sampled_at) return null;
    const cpu = C.object(resources.cpu), memory = C.object(resources.memory);
    const rootFS = C.array(resources.filesystems).map(C.object).find(item => item.mount === "/");
    return {
      fresh: C.fresh(resources.sampled_at) && C.connection(agent).key === "online", sampledAt: resources.sampled_at,
      cpu: Number.isFinite(cpu.usage_percent) && cpu.usage_percent >= 0 ? cpu.usage_percent : null,
      memory: percentOf(memory.used_bytes, memory.total_bytes),
      disk: rootFS ? percentOf(rootFS.used_bytes, rootFS.total_bytes) : null
    };
  };

  // The desired revision's policy as the list names it. Response modes come
  // from the console settings of that revision, not from the host report.
  C.policySummary = agent => {
    if (!agent.desired_policy_revision) return null;
    const template = C.state.templates.find(item => item.id === agent.desired_policy_id);
    const services = C.array(agent.desired_service_response_modes).filter(mode => Object.hasOwn(modes, mode));
    const main = Object.hasOwn(modes, agent.desired_response_mode) ? modes[agent.desired_response_mode] : "";
    const response = main ? [main, ...(services.length ? [`서비스별 ${services.map(mode => modes[mode]).join("·")}`] : [])].join(" · ") : "";
    return {
      name: template?.name || agent.desired_policy_id || "콘솔 밖에서 발급한 정책", id: agent.desired_policy_id || "", response,
      enforce: agent.desired_response_mode === "enforce" || services.includes("enforce"), template: agent.policy_template_state || ""
    };
  };

  // Events matching a detection rule in the server's 24-hour window, by central
  // receipt time. Older servers omit the count: unknown, not zero. A truncated
  // scan makes every count a lower bound and a zero unconfirmed.
  C.detectionSummary = agent => Number.isSafeInteger(agent.detections_24h) && agent.detections_24h >= 0
    ? {count: agent.detections_24h, last: typeof agent.last_detection_at === "string" ? agent.last_detection_at : "", truncated: C.state.detections?.truncated === true}
    : null;

  // Mounts reporting identical capacity, usage and inodes are one filesystem
  // (bind mounts, container volumes). Empty filesystems are never merged.
  C.groupFilesystems = list => {
    const groups = [], index = new Map();
    for (const value of C.array(list)) {
      const item = C.object(value);
      const key = item.used_bytes > 0 && item.total_bytes > 0 ? JSON.stringify([item.type, item.total_bytes, item.used_bytes, item.available_bytes, item.total_inodes, item.free_inodes]) : "";
      if (key && index.has(key)) { groups[index.get(key)].mounts.push(item.mount); continue; }
      if (key) index.set(key, groups.length);
      groups.push({...item, mounts: [item.mount]});
    }
    for (const group of groups) {
      group.mounts.sort((a, b) => a === "/" ? -1 : b === "/" ? 1 : String(a).length - String(b).length || String(a).localeCompare(String(b)));
      group.mount = group.mounts[0];
    }
    return groups;
  };

  C.splitInterfaces = list => {
    const physical = [], virtual = [];
    for (const value of C.array(list)) { const item = C.object(value); (virtualInterface.test(String(item.name || "")) ? virtual : physical).push(item); }
    return {physical, virtual};
  };

  // Items for the overview's "확인 필요" list, most severe first. Resource and
  // capability items need a current heartbeat; older reports are summarised
  // by the connection state alone.
  C.agentIssues = agent => {
    if (agent.revoked) return [];
    const issues = [], state = C.agentStatus(agent), hb = heartbeat(agent), live = status(agent);
    if (state.attention) issues.push({tone: state.tone === "danger" ? "danger" : "warning", title: state.reason, tab: state.key === "policy" ? "policy" : ""});
    const errors = [live.last_error, C.object(hb.policy_status).error, hb.policy_error].filter(value => typeof value === "string" && value);
    if (errors.length) issues.push({tone: "warning", title: "에이전트가 오류를 보고했습니다", detail: errors.join(" · ")});
    if (agent.desired_policy_revision && agent.policy_template_state === "changed") issues.push({tone: "warning", title: "배포 후 정책 저장본이 바뀌었습니다 · 재배포 필요", tab: "policy"});
    if (C.connection(agent).key !== "online") return issues.sort(byTone);
    for (const [count, label] of [[live.dropped, "수집 이벤트 유실"], [live.parse_errors, "수집 이벤트 해석 오류"]]) {
      if (Number.isSafeInteger(count) && count > 0) issues.push({tone: "warning", title: `에이전트 시작 이후 ${label} ${C.number(count)}건`, tab: "capabilities"});
    }
    const resources = C.object(hb.resources);
    if (resources.sampled_at && C.fresh(resources.sampled_at)) {
      for (const item of C.groupFilesystems(resources.filesystems)) {
        if (imageFilesystems.has(item.type)) continue;
        const used = percentOf(item.used_bytes, item.total_bytes), tone = C.usageTone("disk", used);
        if (tone) issues.push({tone, title: `디스크 ${item.mount} 사용률 ${C.percent(used)}`, detail: `가용 ${C.bytes(item.available_bytes)} / 전체 ${C.bytes(item.total_bytes)}`, tab: "resources"});
      }
      const memory = C.object(resources.memory), used = percentOf(memory.used_bytes, memory.total_bytes), tone = C.usageTone("memory", used);
      if (tone) issues.push({tone, title: `메모리 사용률 ${C.percent(used)}`, detail: `${C.bytes(memory.used_bytes)} / ${C.bytes(memory.total_bytes)}`, tab: "resources"});
      if (C.array(resources.errors).length) issues.push({tone: "warning", title: "일부 자원 정보를 수집하지 못했습니다", tab: "resources"});
    }
    for (const [name, value] of Object.entries(C.object(C.object(live.capability_report).capabilities))) {
      const item = C.object(value);
      if (item.implementation === "planned") continue;
      const shown = C.capability(name, item, C.capabilityFresh(name, item, agent));
      if (shown.tone === "danger" || shown.tone === "warning" && coreCapabilities.has(name)) issues.push({tone: shown.tone, title: `${shown.title} · ${shown.label}`, tab: "capabilities"});
    }
    return issues.sort(byTone);
  };

  const metric = (title, value, note, tone) => {
    const article = C.el("article", `metric ${tone || ""}`);
    article.append(C.el("h2", "", title), C.el("strong", "", value), C.el("p", "", note)); return article;
  };
  C.renderOverview = () => {
    const agents = C.state.agents, active = agents.filter(a => !a.revoked), online = active.filter(a => C.connection(a).key === "online");
    const attention = active.filter(a => C.agentStatus(a).attention), assigned = active.filter(a => a.desired_policy_revision > 0), applied = assigned.filter(a => C.policyState(a).applied);
    C.id("overviewMetrics").replaceChildren(
      metric("등록 에이전트", active.length.toLocaleString("ko-KR"), `등록 해지 ${agents.length - active.length}대 별도`, "blue"),
      metric("최근 하트비트 수신", online.length.toLocaleString("ko-KR"), "최근 2분 이내 보고한 서버", "good"),
      metric("운영 확인 필요", attention.length.toLocaleString("ko-KR"), "보고 없음·지연·수집·정책 확인", attention.length ? "warning" : ""),
      metric("목표 정책 적용 보고", `${applied.length} / ${assigned.length}`, "중앙 정책을 지정한 서버 기준", "blue")
    );
    const attentionRows = attention.slice(0, 6).map(agent => {
      const row = C.el("div", "list-row"), identity = C.el("div", "identity");
      identity.append(C.el("strong", "", agent.hostname || agent.agent_id), C.el("small", "", `${agent.agent_id} · ${C.agentStatus(agent).reason}`));
      row.append(identity, C.tag(C.connection(agent).label, C.connection(agent).tone), C.button("확인", () => C.selectAgent(agent.agent_id), "mini-button")); return row;
    });
    C.id("attentionList").replaceChildren(...(attentionRows.length ? attentionRows : [C.empty(active.length ? "현재 기준에 해당하는 서버가 없습니다." : "등록된 에이전트가 없습니다. 등록 토큰을 발급해 서버를 연결하세요.")]));
    const pending = C.state.templates.filter(t => C.object(C.object(t.settings).integrity).enabled).length;
    C.id("policyOverview").replaceWith(Object.assign(C.facts([["저장된 정책", `${C.state.templates.length}개`], ["서버 그룹", `${C.state.groups.length}개`], ["중앙 정책 미지정", `${active.length - assigned.length}대`], ["무결성 초안 활성", `${pending}개 템플릿 · 에이전트 미적용`]]), {id: "policyOverview"}));
  };

  // List: attention first (most severe), then normal, revoked last.
  const statusOrder = agent => { const state = C.agentStatus(agent); return state.key === "revoked" ? 9 : state.attention ? toneRank[state.tone] ?? 2 : 5; };
  const sorters = {
    status: (a, b) => statusOrder(a) - statusOrder(b) || a.agent_id.localeCompare(b.agent_id),
    name: (a, b) => a.agent_id.localeCompare(b.agent_id),
    detections: (a, b) => Number(Boolean(a.revoked)) - Number(Boolean(b.revoked)) || (C.detectionSummary(b)?.count ?? -1) - (C.detectionSummary(a)?.count ?? -1) || a.agent_id.localeCompare(b.agent_id),
    disk: (a, b) => Number(Boolean(a.revoked)) - Number(Boolean(b.revoked)) || (C.resourceSummary(b)?.disk ?? -1) - (C.resourceSummary(a)?.disk ?? -1) || a.agent_id.localeCompare(b.agent_id)
  };
  const statusCell = agent => {
    const cell = C.el("td"), state = C.agentStatus(agent), sent = heartbeat(agent).sent_at;
    cell.append(C.tag(state.label, state.tone));
    if (state.key !== "revoked") { const age = C.el("span", "secondary", Date.parse(sent) > 0 ? C.age(sent) : "하트비트 없음"); age.title = C.time(sent); cell.append(age); }
    return cell;
  };
  const policyCell = agent => {
    const cell = C.el("td", "policy-cell"), summary = C.policySummary(agent);
    if (!summary) {
      cell.append(C.el("span", "cell-muted", "중앙 정책 없음"));
      if (C.object(heartbeat(agent).policy_status).result === "local") cell.append(C.el("span", "secondary", "로컬 설정 사용"));
      return cell;
    }
    const policy = C.policyState(agent), name = C.el("span", "policy-name", summary.name), line = C.el("span", "policy-line");
    if (summary.id && summary.id !== summary.name) name.title = summary.id;
    line.append(C.tag(policy.label, policy.tone));
    if (summary.response) line.append(C.el("span", `response-mode${summary.enforce ? " enforce" : ""}`, summary.response));
    if (summary.template === "changed") line.append(C.tag("재배포 필요", "warning"));
    cell.append(name, line); return cell;
  };
  // Detection counts open that agent's detection history for the same 24 hours.
  const detectionLink = (agent, summary) => {
    const link = C.el("a", "detection-count", `${C.number(summary.count)}건${summary.truncated ? " 이상" : ""}`);
    link.href = "#history"; link.title = "이 서버의 최근 24시간 탐지 이력 보기";
    link.addEventListener("click", event => { event.preventDefault(); C.openHistory?.({view: "detections", agent: agent.agent_id, range: "24h"}); });
    return link;
  };
  const detectionNodes = agent => {
    const summary = C.detectionSummary(agent);
    if (!summary) return [C.el("span", "cell-muted", "미확인")];
    if (!summary.count) {
      const none = C.el("span", "cell-muted", summary.truncated ? "확인 안 됨" : "없음");
      if (summary.truncated) none.title = "탐지가 많아 24시간 전체를 집계하지 못했습니다. 탐지 이력에서 확인하세요.";
      return [none];
    }
    const nodes = [detectionLink(agent, summary)];
    if (Date.parse(summary.last) > 0) { const last = C.el("span", "secondary", `마지막 ${C.age(summary.last)}`); last.title = C.time(summary.last); nodes.push(last); }
    return nodes;
  };
  const detectionCell = agent => { const cell = C.el("td", "detection-cell"); cell.append(...detectionNodes(agent)); return cell; };
  const resourceCell = agent => {
    const cell = C.el("td", "resource-cell"), summary = C.resourceSummary(agent);
    if (!summary) { cell.append(C.el("span", "cell-muted", "자원 보고 없음")); return cell; }
    const usage = (label, value, kind) => {
      const tone = summary.fresh && kind ? C.usageTone(kind, value) : "";
      return C.el("span", `usage${tone ? ` ${tone}` : ""}${summary.fresh ? "" : " stale"}`, `${label} ${C.percent(value)}`);
    };
    const line = C.el("span", "usage-line"); line.append(usage("CPU", summary.cpu), usage("메모리", summary.memory, "memory"), usage("디스크", summary.disk, "disk"));
    cell.append(line);
    if (!summary.fresh) cell.append(C.el("span", "secondary", `이전 측정 · ${C.age(summary.sampledAt)}`));
    return cell;
  };
  C.renderAgents = () => {
    const search = C.id("agentSearch").value.trim().toLowerCase(), filter = C.id("agentStatusFilter").value, sort = sorters[C.id("agentSort").value] || sorters.status;
    const agents = C.state.agents.filter(a => (!filter || (filter === "attention" ? C.agentStatus(a).attention : C.connection(a).key === filter)) && `${a.agent_id} ${a.hostname || ""}`.toLowerCase().includes(search)).sort(sort);
    C.text("agentResultCount", `${agents.length} / ${C.state.agents.length}대`);
    const rows = agents.map(agent => {
      const row = C.el("tr", "agent-row"), identity = C.el("td", "cell-primary"), link = C.el("a", "agent-link", agent.agent_id);
      link.href = `#agents/${encodeURIComponent(agent.agent_id)}`;
      identity.append(link, C.el("span", "secondary", [agent.hostname || "호스트명 보고 없음", C.osLabel(agent)].filter(Boolean).join(" · ")));
      row.append(identity, statusCell(agent), policyCell(agent), detectionCell(agent), resourceCell(agent), C.el("td", "cell-muted", status(agent).version || "미확인"));
      row.addEventListener("click", event => {
        if (event?.target?.closest?.("a,button") || String(root.getSelection?.() || "")) return;
        C.selectAgent(agent.agent_id);
      });
      return row;
    });
    if (!rows.length) { const row = C.el("tr"), cell = C.el("td", "empty-cell", "조건에 맞는 에이전트가 없습니다."); cell.colSpan = 6; row.append(cell); rows.push(row); }
    C.id("agentRows").replaceChildren(...rows);
    C.text("navAgentCount", C.state.agents.filter(a => !a.revoked).length);
    if (C.selectedAgent) C.renderAgentDetail();
  };

  // The detail is the #agents/<id> route; #agents alone shows the list.
  C.openAgentRoute = id => {
    const changed = id !== C.selectedAgent;
    if (changed) Object.assign(fleet, {processPage: 0, policy: null, policyKey: "", open: defaultOpen(), tab: "overview"});
    C.selectedAgent = id;
    C.id("agentListView").hidden = Boolean(id);
    C.id("agentDetail").hidden = !id;
    if (!id) return;
    C.renderAgentDetail();
    if (changed) { root.scrollTo?.(0, 0); C.id("agentDetailTitle").focus({preventScroll: true}); }
  };
  C.selectAgent = id => {
    const hash = `#agents/${encodeURIComponent(id)}`;
    if (root.location.hash !== hash) root.location.hash = hash;
    if (C.navigate) C.navigate(); else C.openAgentRoute(id);
  };
  C.showAgentTab = name => {
    if (!tabs.some(([key]) => key === name)) return;
    fleet.tab = name; C.renderAgentDetail();
    fleet.tabButtons.get(name)?.focus();
  };

  const collapsible = (key, title, ...children) => {
    const details = C.el("details", "detail-section"); details.open = fleet.open.has(key);
    details.addEventListener("toggle", () => { if (details.open) fleet.open.add(key); else fleet.open.delete(key); });
    details.append(C.el("summary", "", title), ...children); return details;
  };
  const scrollRegion = (title, child) => {
    const wrap = C.el("div", "table-scroll"); wrap.tabIndex = 0; wrap.setAttribute("role", "region"); wrap.setAttribute("aria-label", title); wrap.append(child); return wrap;
  };
  const detailSection = (key, title, child, note) => collapsible(key, title, ...(note ? [C.el("p", "panel-note", note)] : []), scrollRegion(title, child));
  const heading = (title, badge) => {
    const div = C.el("div", "section-heading"); div.append(C.el("h3", "", title)); if (badge) div.append(badge); return div;
  };
  const resourceMetric = (label, value, note, tone) => {
    const div = C.el("div", `resource-metric${tone ? ` ${tone}` : ""}`); div.append(C.el("span", "", label), C.el("strong", value.length > 15 ? "long" : "", value), C.el("small", "", note)); return div;
  };
  const resourceHeading = (agent, container) => {
    const resources = C.object(heartbeat(agent).resources);
    if (!resources.sampled_at) { container.append(heading("서버 자원"), C.empty("자원 보고가 없습니다. 에이전트 모니터링 설정과 버전을 확인하세요.")); return null; }
    const fresh = C.resourceSummary(agent).fresh;
    container.append(heading("서버 자원", C.tag(fresh ? "최근 측정" : "이전 측정 · 최신 미확인", fresh ? "good" : "warning")));
    return {resources, fresh};
  };
  const resourceCards = (agent, resources, fresh) => {
    const cpu = C.object(resources.cpu), memory = C.object(resources.memory), rootFS = C.array(resources.filesystems).map(C.object).find(f => f.mount === "/");
    const memoryUsed = percentOf(memory.used_bytes, memory.total_bytes), diskUsed = rootFS ? percentOf(rootFS.used_bytes, rootFS.total_bytes) : null;
    const tone = (kind, value) => fresh ? C.usageTone(kind, value) : "";
    const cards = C.el("div", "resource-metrics");
    cards.append(
      resourceMetric("CPU 사용률", C.percent(cpu.usage_percent), [Number.isFinite(cpu.load1) ? `부하(1분) ${cpu.load1.toFixed(2)}` : "", `논리 CPU ${C.number(cpu.logical_cpus)}개`].filter(Boolean).join(" · ")),
      resourceMetric("메모리", memoryUsed === null ? "미확인" : C.percent(memoryUsed), `${C.bytes(memory.used_bytes)} / ${C.bytes(memory.total_bytes)}`, tone("memory", memoryUsed)),
      resourceMetric("시스템 디스크 /", diskUsed === null ? "미확인" : C.percent(diskUsed), rootFS ? `${C.bytes(rootFS.used_bytes)} / ${C.bytes(rootFS.total_bytes)}` : "루트 파일시스템 보고 없음", tone("disk", diskUsed)),
      resourceMetric("프로세스", C.number(resources.process_count), `${C.array(resources.processes).length}개 표본 수신`));
    return cards;
  };
  const networkLabels = {up: "연결됨", down: "연결 안 됨", dormant: "연결 대기", lowerlayerdown: "하위 연결 끊김", notpresent: "장치 없음", testing: "점검 중"};
  const networkHeadings = ["장치", "연결 상태", "수신", "송신", "누적 수신 / 송신", "수신 / 송신 오류"];
  const networkRows = list => list.map(n => [n.name, networkLabels[n.state] || "미확인", C.rate(n.rx_bytes_per_second), C.rate(n.tx_bytes_per_second), `${C.bytes(n.rx_bytes)} / ${C.bytes(n.tx_bytes)}`, `${C.number(n.rx_errors)} / ${C.number(n.tx_errors)}`]);

  const overviewTab = (agent, container) => {
    const issues = C.agentIssues(agent);
    container.append(heading("확인 필요", issues.length ? C.tag(`${issues.length}건`, issues[0].tone) : C.tag("없음", "good")));
    if (!issues.length) container.append(C.el("p", "panel-note", agent.revoked ? "등록 해지된 에이전트입니다. 중앙 연결과 정책 배포 대상에서 제외됩니다." : "현재 보고 기준으로 확인할 항목이 없습니다."));
    else {
      const list = C.el("ul", "issue-list");
      for (const issue of issues) {
        const item = C.el("li", `issue ${issue.tone}`), text = C.el("div", "issue-text");
        text.append(C.el("strong", "", issue.title)); if (issue.detail) text.append(C.el("small", "", issue.detail));
        item.append(C.tag(issue.tone === "danger" ? "오류" : "경고", issue.tone), text);
        if (issue.tab) item.append(C.button(`${tabs.find(([key]) => key === issue.tab)[1]} 보기`, () => C.showAgentTab(issue.tab), "mini-button"));
        list.append(item);
      }
      container.append(list);
    }
    const sampled = resourceHeading(agent, container);
    if (sampled) container.append(resourceCards(agent, sampled.resources, sampled.fresh));
    const live = status(agent), hb = heartbeat(agent), p = platform(agent), collector = C.object(live.collector_health), connection = C.connection(agent), health = C.health(agent);
    const summary = C.policySummary(agent), policy = C.policyState(agent), policyValue = C.el("span", "fact-policy");
    if (summary) policyValue.append(C.el("span", "", policyName(agent, summary)), C.tag(policy.label, policy.tone)); else policyValue.textContent = C.object(hb.policy_status).result === "local" ? "중앙 정책 없음 · 로컬 설정 사용" : "중앙 정책 없음";
    const facts = C.el("div", "agent-summary");
    facts.append(C.facts([
      ["연결 상태", C.tag(connection.label, connection.tone)], ["마지막 하트비트", when(hb.sent_at)],
      ["수집 상태", C.tag(health.label, health.tone)], ["수집기", live.collector],
      ["마지막 수집 이벤트", when(collector.last_event_at || live.last_event_at)],
      ["에이전트 버전", live.version], ["에이전트 시작", when(live.started_at)]
    ]), C.facts([
      ["운영체제", p.pretty_name || C.osLabel(agent)], ["커널 / 아키텍처", [p.kernel_release, p.architecture].filter(Boolean).join(" · ")],
      ["중앙 정책", policyValue], ["대응 방식", summary?.response || (summary ? "미확인" : "—")],
      ["프로세스 종료 로컬 허용", C.localTermination ? C.localTermination(agent) : "미확인"],
      ["등록 ID", agent.enrollment_id], ["등록 시각", C.time(agent.enrolled_at)], ["마지막 인증 수신", C.time(agent.last_seen_at)]
    ]));
    container.append(heading("서버 정보"), facts);
  };

  // A directly issued policy has no console template; once the detail has
  // loaded the signed policy, its ID names it.
  const policyName = (agent, summary) => {
    const issued = fleet.policyKey === C.policyIdentity(agent) ? fleet.policy?.policy?.policy_id : "";
    return !summary.id && typeof issued === "string" && issued ? `${summary.name} · ${issued}` : summary.name;
  };
  const assignedPolicy = (agent, container) => {
    container.append(heading("현재 중앙 지정 정책"));
    if (!fleet.policy || fleet.policyKey !== C.policyIdentity(agent)) { container.append(C.el("p", "panel-note", fleet.policyLoading ? "지정된 정책을 확인하고 있습니다." : "지정된 정책을 불러오지 못했습니다. 상태를 갱신해 다시 확인하세요.")); return; }
    const policy = fleet.policy.policy;
    if (!policy) { container.append(C.el("p", "inline-note", "중앙에서 지정한 정책이 없습니다. 에이전트는 로컬 설정을 사용할 수 있습니다.")); return; }
    const detection = C.object(policy.detection);
    const selectedScope = fleet.policy.desired_settings?.service_scope;
    container.append(C.facts([["정책 / 리비전", `${policy.policy_id} / ${policy.revision}`], ["대응 방식", modes[C.object(policy.response).mode] || "미확인"], ["서비스별 파일·TCP 범위", C.serviceScopeSummary(detection)], ...(selectedScope ? [["웹 출처 범위", C.policyScopeLabel(selectedScope)]] : []), ["웹 서비스", C.array(detection.web_services).join(" · ") || "명시 서비스 없음"], ["웹 실행 파일", C.array(detection.web_executables).join(" · ") || "명시 실행 파일 없음"], ["탐지 셸", C.array(detection.shells).join(" · ") || "없음"],["전역 root·권한 변경",detection.privilege_rules?`사용 · ${detection.root_exec_alerts==="all"?"모든 root 실행 경보":"의심 문맥만 경보"} · 탐지 전용`:"사용 안 함"], ["정책 만료", C.time(policy.expires_at)]]));
    if (C.agentApplicationPolicies) container.append(C.agentApplicationPolicies(agent, fleet.policy));
    if (C.array(fleet.policy.pending_features).includes("integrity")) container.append(C.el("p", "notice warning", "추가 무결성 설정(TPM·임의 경로·강제 검증)은 중앙 초안에 보관합니다."));
    container.append(C.button("이 서버 정책으로 새 정책 작성", () => C.editTemplateFromPolicy(policy, fleet.policy.desired_settings), "primary small"));
    container.append(C.el("p", "panel-note", "현재 지정 정책을 복사하여 새 정책을 작성합니다. 저장·배포 전에는 서버 설정이 바뀌지 않습니다."), C.raw(policy, "지정된 정책 전체 보기"));
  };
  const templateStates = {current: ["현재 저장본과 같음", "good"], changed: ["저장본 변경됨 · 재배포 필요", "warning"], missing: ["원본 정책 삭제됨", "neutral"]};
  const policyTab = (agent, container) => {
    const policy = C.policyState(agent), summary = C.policySummary(agent), hb = heartbeat(agent);
    container.append(heading("정책 적용 상태", summary ? C.tag(policy.label, policy.tone) : C.tag("중앙 정책 없음", "neutral")));
    if (summary) {
      const line = C.el("p", "policy-state-line");
      line.append(C.el("strong", "", policyName(agent, summary)));
      if (summary.response) line.append(C.el("span", `response-mode${summary.enforce ? " enforce" : ""}`, summary.response));
      if (Object.hasOwn(templateStates, summary.template)) line.append(C.tag(...templateStates[summary.template]));
      container.append(line);
    }
    const errors = [C.object(hb.policy_status).error, hb.policy_error].filter(value => typeof value === "string" && value);
    if (errors.length) container.append(C.el("p", "notice warning", errors.join(" · ")));
    assignedPolicy(agent, container);
    if (C.hostBoundaryFacts) container.append(collapsible("boundary", "호스트 보안 경계 · 등록과 적용 근거",
      C.el("p", "panel-note", "에이전트는 등록 시 받은 키로 정책 서명과 대상 등록을 확인합니다. 중앙 등록 기록과 이 호스트가 보고한 상태입니다."),
      C.facts(C.hostBoundaryFacts(agent)),
      C.el("p", "field-note", "호스트의 신뢰 CA, 정책·업데이트 검증 키, root 작업자 권한, 복구 승인 정보, 중앙 연결 주소, SELinux 모드는 하트비트에 보고되지 않습니다.")));
    C.fileIntegrity(agent, container);
  };

  const servicesTab = (agent, container) => {
    if (agent.revoked) { container.append(C.empty("등록 해지된 에이전트의 서비스 목록은 조회하지 않습니다.")); return; }
    container.append(C.agentServiceInventory?.(agent) || C.empty("서비스 목록을 표시할 수 없습니다."));
  };

  const resourcesTab = (agent, container) => {
    const sampled = resourceHeading(agent, container);
    if (!sampled) return;
    const {resources, fresh} = sampled;
    container.append(C.el("p", "panel-note", `${C.time(resources.sampled_at)} 측정 · CPU·네트워크는 보고된 측정 구간의 값입니다. 미확인 값은 0으로 환산하지 않습니다.`), resourceCards(agent, resources, fresh));
    const mounts = C.array(resources.filesystems).length, groups = C.groupFilesystems(resources.filesystems);
    const filesystemRows = groups.map(item => {
      const path = C.el("div", "mount-cell"), others = item.mounts.slice(1), used = percentOf(item.used_bytes, item.total_bytes);
      path.append(C.el("span", "", C.value(item.mount)));
      if (others.length) path.append(C.el("small", "secondary", `같은 파일시스템 ${others.length}개: ${others.slice(0, 3).join(", ")}${others.length > 3 ? ` 외 ${others.length - 3}개` : ""}`));
      const tone = fresh && !imageFilesystems.has(item.type) ? C.usageTone("disk", used) : "";
      return [path, item.type, C.el("span", `usage${tone ? ` ${tone}` : ""}`, C.percent(used)), `${C.bytes(item.used_bytes)} / ${C.bytes(item.total_bytes)}`, C.bytes(item.available_bytes)];
    });
    container.append(detailSection("filesystems", `파일시스템 · ${groups.length}개${groups.length !== mounts ? ` (마운트 ${mounts}개)` : ""}`,
      C.table("파일시스템 용량", ["경로", "종류", "사용률", "사용 / 전체", "가용"], filesystemRows),
      groups.length !== mounts ? "용량·사용량·inode가 모두 같은 마운트(bind mount, 컨테이너 볼륨 등)는 한 줄로 묶었습니다." : ""));
    const {physical, virtual} = C.splitInterfaces(resources.network);
    const network = detailSection("network", `네트워크 · ${physical.length}개${virtual.length ? ` · 가상 ${virtual.length}개 별도` : ""}`, C.table("네트워크 사용량", networkHeadings, networkRows(physical)),
      virtual.length ? "lo, veth, docker, br- 등 이름으로 구분한 가상·컨테이너 장치는 아래에 따로 접어 두었습니다." : "");
    if (virtual.length) network.append(detailSection("network-virtual", `가상·컨테이너 장치 · ${virtual.length}개`, C.table("가상 장치 네트워크 사용량", networkHeadings, networkRows(virtual))));
    container.append(network);
    container.append(detailSection("io", `디스크 I/O · ${C.array(resources.disks).length}개`, C.table("디스크 읽기 쓰기", ["장치", "읽기", "쓰기", "읽기 / 쓰기 IOPS", "사용 시간 비율"], C.array(resources.disks).map(d => [d.name, C.rate(d.read_bytes_per_second), C.rate(d.write_bytes_per_second), `${C.number(d.read_iops)} / ${C.number(d.write_iops)}`, C.percent(d.busy_percent)]))));
    const processes = C.array(resources.processes), last = Math.max(0, Math.ceil(processes.length / 10) - 1); fleet.processPage = Math.min(last, fleet.processPage);
    const processTable = C.table("실행 중인 프로세스 표본", ["실행 파일 / 이름", "서비스", "PID / UID", "CPU", "메모리"], processes.slice(fleet.processPage * 10, fleet.processPage * 10 + 10).map(p => [p.exe || p.name, p.origin_service || "출처 미확인", `${p.pid ?? "미확인"} / ${p.uid ?? "미확인"}`, C.percent(p.cpu_percent), C.bytes(p.rss_bytes)]));
    const section = detailSection("processes", `프로세스 · ${processes.length}개 표본`, processTable, "한 코어 기준 CPU 사용률은 100%를 넘을 수 있습니다. 전체 프로세스 목록이 아닐 수 있습니다. 실행 인자와 환경변수는 수집하지 않습니다.");
    const pager = C.el("nav", "pager"); pager.setAttribute("aria-label", "프로세스 페이지");
    const previous = C.button("이전", () => { fleet.processPage--; C.renderAgentDetail(); }); previous.disabled = fleet.processPage === 0;
    const next = C.button("다음", () => { fleet.processPage++; C.renderAgentDetail(); }); next.disabled = fleet.processPage >= last;
    pager.append(previous, C.el("span", "", `${fleet.processPage + 1} / ${last + 1}페이지`), next); section.append(pager); container.append(section);
    if (C.array(resources.errors).length) container.append(C.el("p", "notice warning", "일부 자원 정보를 수집하지 못했습니다. 기능 진단 탭의 하트비트 보고 원문에서 수집 오류를 확인하세요."));
  };

  const support = {supported: "지원 조건 확인", limited: "일부 조건 미확인", unsupported: "지원 안 함", error: "진단 오류"};
  const capabilitiesTab = (agent, container) => {
    const report = C.object(status(agent).capability_report), entries = Object.entries(C.object(report.capabilities));
    const rows = entries.map(([name, value]) => { const item = C.object(value); return {name, item, shown: C.capability(name, item, C.capabilityFresh(name, item, agent))}; });
    const buildRows = list => list.map(({item, shown}) => {
      const identity = C.el("div"); identity.append(C.el("strong", "", shown.title));
      const impl = C.tag(shown.implementation, shown.implementation === "개발 예정" ? "pending" : "neutral");
      const note = C.el("div", "", shown.note); note.append(C.el("span", "capability-code", `사전 환경 진단: ${support[item.state] || "지원 여부 미확인"} · 진단 시각: ${C.time(report.probed_at)}`));
      if (item.verified_at) note.append(C.el("span", "capability-code", `실동작 확인: ${C.time(item.verified_at)}`));
      return [identity, impl, C.tag(shown.label, shown.tone), note];
    });
    const table = (title, list) => { const node = C.table(title, ["기능", "구현 구분", "실동작 / 적용", "확인 근거"], buildRows(list)); node.classList.add("capabilities-table"); return node; };
    const planned = rows.filter(row => row.item.implementation === "planned"), current = rows.filter(row => row.item.implementation !== "planned");
    const flagged = current.filter(row => ["danger", "warning"].includes(row.shown.tone)).sort((a, b) => byTone(a.shown, b.shown)), rest = current.filter(row => !flagged.includes(row));
    const good = rest.filter(row => row.shown.tone === "good").length;
    container.append(heading("기능 구현·실동작 상태", C.tag(flagged.length ? `확인 필요 ${flagged.length}개` : "확인 필요 없음", flagged.length ? flagged[0].shown.tone : "good")));
    container.append(C.el("p", "capability-counts", `동작·지원 확인 ${good}개 · 확인 필요 ${flagged.length}개 · 사용 안 함·참고 ${rest.length - good}개 · 개발 예정 ${planned.length}개`));
    container.append(C.el("p", "panel-note", "구현 여부·환경 지원과 실제 동작 보고를 구분합니다. 전용 정책 파일만으로 실행 옵션·파일 쓰기·TCP 연결 요청 수집이 확인되지는 않습니다. 각 기능의 실제 이벤트 수신과 확인 시각을 보세요. 관측은 코드 실행 성공·연결 완료나 자동 종료 허용을 뜻하지 않습니다."));
    if (flagged.length) container.append(scrollRegion("확인이 필요한 기능", table("확인이 필요한 기능", flagged)));
    else container.append(C.el("p", "inline-note", "경고나 오류로 보고된 기능이 없습니다."));
    if (rest.length) container.append(detailSection("capabilities-rest", `그 밖의 기능 · ${rest.length}개`, table("그 밖의 기능 구현과 보고된 실동작", rest)));
    if (planned.length) container.append(detailSection("planned", `추가 개발 예정 · ${planned.length}개`, table("현재 제공되지 않는 기능", planned), "아래 기능은 현재 탐지·대응에 사용되지 않습니다."));
    const live = status(agent), collector = C.object(live.collector_health);
    if (Object.keys(collector).length) container.append(heading("수집기 처리량"), C.facts([
      ["수집기", collector.name], ["실행 중", collector.running === true ? "예" : collector.running === false ? "아니요" : "미확인"],
      ["수신 / 처리 / 건너뜀", `${C.number(collector.events_received)} / ${C.number(collector.events_emitted)} / ${C.number(collector.events_skipped)}`],
      ["에이전트 유실 / 해석 오류", `${C.number(live.dropped)} / ${C.number(live.parse_errors)}`], ["마지막 수집 이벤트", when(collector.last_event_at)]
    ]), C.el("p", "field-note", "건너뜀은 에이전트가 처리하지 않는 원본 메시지 유형이며 커널 관측 유실을 뜻하지 않습니다. 값은 에이전트 시작 이후 누적입니다."));
    container.append(C.raw(report, "기술 보고 원문 보기"), C.raw(heartbeat(agent), "하트비트 보고 원문 보기"));
  };
  const panels = {overview: overviewTab, policy: policyTab, services: servicesTab, resources: resourcesTab, capabilities: capabilitiesTab};

  const loadPolicy = async agent => {
    const key = C.policyIdentity(agent);
    if (fleet.policyKey === key || fleet.policyLoading) return;
    fleet.policyLoading = true;
    try {
      const value = await C.request(`/api/agents/${encodeURIComponent(agent.agent_id)}/policy`);
      const current = C.state.agents.find(a=>a.agent_id===C.selectedAgent);
      if (current && C.policyIdentity(current) === key) {
        if(!C.policyResponseMatches(current,value))throw new Error("서버의 등록 또는 지정 정책이 변경되었습니다. 상태를 갱신한 뒤 정책을 다시 확인하세요.");
        fleet.policy = value; fleet.policyKey = key;
      }
    } catch (error) { C.error(error); }
    finally {
      fleet.policyLoading = false;
      const current=C.state.agents.find(a=>a.agent_id===C.selectedAgent);
      if(current)C.renderAgentDetail(C.policyIdentity(current)!==key);
    }
  };
  const renderHead = agent => {
    const connection = C.connection(agent), health = C.health(agent), policy = C.policyState(agent), live = status(agent);
    C.text("agentDetailSubtitle", [agent.hostname || "호스트명 보고 없음", C.osLabel(agent), live.version].filter(Boolean).join(" · "));
    const badge = (label, ...nodes) => { const span = C.el("span", "agent-badge"); span.append(C.el("span", "", label), ...nodes); return span; };
    const sent = heartbeat(agent).sent_at;
    C.id("agentDetailBadges").replaceChildren(
      badge("연결", C.tag(connection.label, connection.tone), C.el("span", "", Date.parse(sent) > 0 ? C.age(sent) : "")),
      badge("수집", C.tag(health.label, health.tone)),
      badge("정책", agent.desired_policy_revision ? C.tag(policy.label, policy.tone) : C.tag("중앙 정책 없음", "neutral")),
      badge("최근 24시간 탐지", ...detectionNodes(agent)));
    const actions = [C.button("이 서버 이력 조회", () => { C.id("historyAgent").value = agent.agent_id; root.location.hash = "history"; C.loadHistory(true); }, "small")];
    if (!agent.revoked) actions.push(C.button("제거 승인으로 이동", () => { C.id("removalAgent").value = agent.agent_id; C.populateRemoval(); root.location.hash = "approvals"; }, "small quiet"));
    C.id("agentDetailActions").replaceChildren(...actions);
    const issues = C.agentIssues(agent).length;
    fleet.tabButtons = new Map(tabs.map(([key, label]) => {
      const button = C.button(label, () => C.showAgentTab(key));
      if (key === "overview" && issues) button.append(C.el("span", "tab-count", String(issues)));
      button.setAttribute("aria-pressed", String(key === fleet.tab));
      return [key, button];
    }));
    C.id("agentDetailTabs").replaceChildren(...fleet.tabButtons.values());
  };
  C.renderAgentDetail = (load = true) => {
    const id = C.selectedAgent, agent = C.state.agents.find(a => a.agent_id === id);
    C.id("agentDetail").hidden = !id; if (!id) return;
    const areas = ["agentDetailActions", "agentDetailTabs", "agentDetailBody"].map(name => C.id(name));
    const active = document.activeElement, focus = active && areas.some(area => area.contains(active)) ? active.textContent : "";
    C.text("agentDetailTitle", id);
    if (!agent) {
      C.text("agentDetailSubtitle", "");
      for (const area of [C.id("agentDetailBadges"), ...areas.slice(0, 2)]) area.replaceChildren();
      C.id("agentDetailBody").replaceChildren(C.el("p", C.state.server_time ? "notice warning" : "panel-note", C.state.server_time ? "이 ID의 에이전트가 목록에 없습니다. 에이전트 목록에서 다시 선택하세요." : "에이전트 정보를 불러오는 중입니다."));
      return;
    }
    if (!Object.hasOwn(panels, fleet.tab)) fleet.tab = "overview";
    renderHead(agent);
    const content = C.el("div", "agent-tab-panel");
    panels[fleet.tab](agent, content);
    C.id("agentDetailBody").replaceChildren(content);
    if (focus) for (const node of areas.flatMap(area => [...area.querySelectorAll("button,summary")])) if (node.textContent === focus) { node.focus({preventScroll: true}); break; }
    if (load) loadPolicy(agent);
  };
  C.initFleet = () => {
    C.id("agentSearch").addEventListener("input", C.renderAgents);
    C.id("agentStatusFilter").addEventListener("change", C.renderAgents);
    C.id("agentSort").addEventListener("change", C.renderAgents);
    C.onState(() => { C.renderOverview(); C.renderAgents(); });
  };
})(globalThis.XEC);
