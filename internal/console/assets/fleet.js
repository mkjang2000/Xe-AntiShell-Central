"use strict";

(function (C) {
  const fleet = {policy: null, policyKey: "", policyLoading: false, processPage: 0, open: new Set()};
  const heartbeat = agent => C.object(agent.heartbeat);
  const status = agent => C.object(heartbeat(agent).status);
  const metric = (title, value, note, tone) => {
    const article = C.el("article", `metric ${tone || ""}`);
    article.append(C.el("h2", "", title), C.el("strong", "", value), C.el("p", "", note)); return article;
  };
  const agentButton = (agent, label = "상세 보기") => C.button(label, () => C.selectAgent(agent.agent_id), "mini-button");
  const issue = agent => {
    const connection = C.connection(agent), health = C.health(agent), policy = C.policyState(agent);
    if (connection.key === "revoked") return "";
    if (connection.key === "unknown") return "등록 후 하트비트 보고 없음";
    if (connection.key === "stale") return "하트비트 수신 지연";
    if (["warning", "danger"].includes(health.tone)) return health.label;
    if (policy.desired > 0 && !policy.applied) return policy.label;
    return "";
  };
  C.renderOverview = () => {
    const agents = C.state.agents, active = agents.filter(a => !a.revoked), online = active.filter(a => C.connection(a).key === "online");
    const attention = active.filter(issue), assigned = active.filter(a => a.desired_policy_revision > 0), applied = assigned.filter(a => C.policyState(a).applied);
    C.id("overviewMetrics").replaceChildren(
      metric("등록 에이전트", active.length.toLocaleString("ko-KR"), `등록 해지 ${agents.length - active.length}대 별도`, "blue"),
      metric("최근 하트비트 수신", online.length.toLocaleString("ko-KR"), "최근 2분 이내 보고한 서버", "good"),
      metric("운영 확인 필요", attention.length.toLocaleString("ko-KR"), "보고 없음·지연·수집·정책 확인", attention.length ? "warning" : ""),
      metric("목표 정책 적용 보고", `${applied.length} / ${assigned.length}`, "중앙 정책을 지정한 서버 기준", "blue")
    );
    const attentionRows = attention.slice(0, 6).map(agent => {
      const row = C.el("div", "list-row"), identity = C.el("div", "identity");
      identity.append(C.el("strong", "", agent.hostname || agent.agent_id), C.el("small", "", `${agent.agent_id} · ${issue(agent)}`));
      row.append(identity, C.tag(C.connection(agent).label, C.connection(agent).tone), agentButton(agent, "확인")); return row;
    });
    C.id("attentionList").replaceChildren(...(attentionRows.length ? attentionRows : [C.empty(active.length ? "현재 기준에 해당하는 서버가 없습니다." : "등록된 에이전트가 없습니다. 등록 토큰을 발급해 서버를 연결하세요.")]));
    const pending = C.state.templates.filter(t => C.object(C.object(t.settings).integrity).enabled).length;
    C.id("policyOverview").replaceWith(Object.assign(C.facts([["저장된 템플릿", `${C.state.templates.length}개`], ["서버 그룹", `${C.state.groups.length}개`], ["중앙 정책 미지정", `${active.length - assigned.length}대`], ["무결성 초안 활성", `${pending}개 템플릿 · 에이전트 미적용`]]), {id: "policyOverview"}));
  };
  C.renderAgents = () => {
    const search = C.id("agentSearch").value.trim().toLowerCase(), filter = C.id("agentStatusFilter").value;
    const agents = C.state.agents.filter(a => (!filter || C.connection(a).key === filter) && `${a.agent_id} ${a.hostname || ""}`.toLowerCase().includes(search));
    C.text("agentResultCount", `${agents.length} / ${C.state.agents.length}대`);
    const rows = agents.map(agent => {
      const row = C.el("tr"), connection = C.connection(agent), health = C.health(agent), policy = C.policyState(agent), hb = heartbeat(agent), resources = C.object(hb.resources), cpu = C.object(resources.cpu), memory = C.object(resources.memory);
      const identity = C.el("td", "cell-primary", agent.agent_id); identity.append(C.el("span", "secondary", agent.hostname || "호스트명 보고 없음")); row.append(identity);
      for (const child of [C.tag(connection.label, connection.tone), C.tag(health.label, health.tone)]) { const td = C.el("td"); td.append(child); row.append(td); }
      const resourceCell = C.el("td", "cell-muted");
      if (resources.sampled_at) {
        resourceCell.append(C.el("span", "", `${C.percent(cpu.usage_percent)} / ${memory.total_bytes > 0 && Number.isFinite(memory.used_bytes) ? C.percent(memory.used_bytes / memory.total_bytes * 100) : "미확인"}`));
        resourceCell.append(C.el("span", "secondary", C.fresh(resources.sampled_at) && connection.key === "online" ? "최근 보고 자원" : "이전 측정값 · 최신 미확인"));
      } else resourceCell.textContent = "자원 보고 없음";
      const policyCell = C.el("td"); policyCell.append(C.el("span", "", `${policy.active ?? "—"} / ${policy.desired ?? "—"}`), C.el("span", "secondary", policy.label));
      const last = C.el("td", "cell-muted", C.age(hb.sent_at)); last.append(C.el("span", "secondary", C.time(hb.sent_at)));
      const action = C.el("td"); action.append(agentButton(agent)); row.append(resourceCell, policyCell, last, action); return row;
    });
    if (!rows.length) { const row = C.el("tr"), cell = C.el("td", "empty-cell", "조건에 맞는 에이전트가 없습니다."); cell.colSpan = 7; row.append(cell); rows.push(row); }
    C.id("agentRows").replaceChildren(...rows);
    C.text("navAgentCount", C.state.agents.filter(a => !a.revoked).length);
    if (C.selectedAgent) C.renderAgentDetail();
  };
  C.selectAgent = id => {
    if (C.selectedAgent !== id) { fleet.processPage = 0; fleet.policy = null; fleet.policyKey = ""; fleet.open.clear(); }
    C.selectedAgent = id;
    if (root.location.hash !== "#agents") root.location.hash = "agents";
    if(C.navigate)C.navigate();
    C.renderAgentDetail();
    C.id("agentDetail").scrollIntoView({behavior: "instant", block: "start"});
    C.id("agentDetailTitle").tabIndex = -1; C.id("agentDetailTitle").focus({preventScroll: true});
  };
  const detailSection = (key, title, child, note) => {
    const details = C.el("details", "detail-section"); details.open = fleet.open.has(key);
    details.addEventListener("toggle", () => { if (details.open) fleet.open.add(key); else fleet.open.delete(key); });
    details.append(C.el("summary", "", title)); if (note) details.append(C.el("p", "panel-note", note));
    const wrap = C.el("div", "table-scroll"); wrap.tabIndex = 0; wrap.setAttribute("role", "region"); wrap.setAttribute("aria-label", title); wrap.append(child); details.append(wrap); return details;
  };
  const heading = (title, badge) => {
    const div = C.el("div", "section-heading"); div.append(C.el("h3", "", title)); if (badge) div.append(badge); return div;
  };
  const resourceMetric = (label, value, note) => {
    const div = C.el("div", "resource-metric"); div.append(C.el("span", "", label), C.el("strong", value.length > 15 ? "long" : "", value), C.el("small", "", note)); return div;
  };
  const resourceDetails = (agent, container) => {
    const resources = C.object(heartbeat(agent).resources);
    if (!resources.sampled_at) { container.append(heading("서버 자원"), C.empty("자원 보고가 없습니다. 에이전트 모니터링 설정과 버전을 확인하세요.")); return; }
    const fresh = C.fresh(resources.sampled_at) && C.connection(agent).key === "online", cpu = C.object(resources.cpu), memory = C.object(resources.memory), rootDisk = C.array(resources.filesystems).find(f => f.mount === "/");
    container.append(heading("서버 자원", C.tag(fresh ? "최근 측정" : "이전 측정 · 최신 미확인", fresh ? "good" : "warning")));
    container.append(C.el("p", "panel-note", `${C.time(resources.sampled_at)} 측정 · CPU·네트워크는 보고된 측정 구간의 값입니다. 미확인 값은 0으로 환산하지 않습니다.`));
    const cards = C.el("div", "resource-metrics");
    cards.append(resourceMetric("CPU 사용률", C.percent(cpu.usage_percent), `논리 CPU ${C.number(cpu.logical_cpus)}개`), resourceMetric("메모리", memory.total_bytes > 0 && Number.isFinite(memory.used_bytes) ? C.percent(memory.used_bytes / memory.total_bytes * 100) : "미확인", `${C.bytes(memory.used_bytes)} / ${C.bytes(memory.total_bytes)}`), resourceMetric("시스템 디스크 /", rootDisk && rootDisk.total_bytes > 0 ? C.percent(rootDisk.used_bytes / rootDisk.total_bytes * 100) : "미확인", rootDisk ? `${C.bytes(rootDisk.used_bytes)} / ${C.bytes(rootDisk.total_bytes)}` : "루트 파일시스템 보고 없음"), resourceMetric("프로세스", C.number(resources.process_count), `${C.array(resources.processes).length}개 표본 수신`)); container.append(cards);
    container.append(detailSection("disk", `디스크 용량 · ${C.array(resources.filesystems).length}개`, C.table("파일시스템 용량", ["경로", "종류", "사용률", "사용 / 전체", "가용"], C.array(resources.filesystems).map(f => [f.mount,f.type,f.total_bytes > 0 ? C.percent(f.used_bytes / f.total_bytes * 100) : "미확인",`${C.bytes(f.used_bytes)} / ${C.bytes(f.total_bytes)}`,C.bytes(f.available_bytes)]))));
    container.append(detailSection("io", `디스크 I/O · ${C.array(resources.disks).length}개`, C.table("디스크 읽기 쓰기", ["장치", "읽기", "쓰기", "읽기 / 쓰기 IOPS", "사용 시간 비율"], C.array(resources.disks).map(d => [d.name,C.rate(d.read_bytes_per_second),C.rate(d.write_bytes_per_second),`${C.number(d.read_iops)} / ${C.number(d.write_iops)}`,C.percent(d.busy_percent)]))));
    const networkLabels = {up:"연결됨",down:"연결 안 됨",dormant:"연결 대기",lowerlayerdown:"하위 연결 끊김",notpresent:"장치 없음",testing:"점검 중"};
    container.append(detailSection("network", `네트워크 · ${C.array(resources.network).length}개`, C.table("네트워크 사용량", ["장치", "연결 상태", "수신", "송신", "누적 수신 / 송신", "수신 / 송신 오류"], C.array(resources.network).map(n => [n.name,networkLabels[n.state] || "미확인",C.rate(n.rx_bytes_per_second),C.rate(n.tx_bytes_per_second),`${C.bytes(n.rx_bytes)} / ${C.bytes(n.tx_bytes)}`,`${C.number(n.rx_errors)} / ${C.number(n.tx_errors)}`]))));
    const processes = C.array(resources.processes), last = Math.max(0, Math.ceil(processes.length / 10) - 1); fleet.processPage = Math.min(last, fleet.processPage);
    const processTable = C.table("실행 중인 프로세스 표본", ["실행 파일 / 이름", "서비스", "PID / UID", "CPU", "메모리"], processes.slice(fleet.processPage * 10, fleet.processPage * 10 + 10).map(p => [p.exe || p.name,p.origin_service || "출처 미확인",`${p.pid ?? "미확인"} / ${p.uid ?? "미확인"}`,C.percent(p.cpu_percent),C.bytes(p.rss_bytes)]));
    const section = detailSection("processes", `프로세스 · ${processes.length}개 표본`, processTable, "한 코어 기준 CPU 사용률은 100%를 넘을 수 있습니다. 전체 프로세스 목록이 아닐 수 있습니다. 실행 인자와 환경변수는 수집하지 않습니다.");
    const pager = C.el("nav", "pager"); pager.setAttribute("aria-label", "프로세스 페이지");
    const previous = C.button("이전", () => { fleet.processPage--; C.renderAgentDetail(); }); previous.disabled = fleet.processPage === 0;
    const next = C.button("다음", () => { fleet.processPage++; C.renderAgentDetail(); }); next.disabled = fleet.processPage >= last;
    pager.append(previous, C.el("span", "", `${fleet.processPage + 1} / ${last + 1}페이지`), next); section.append(pager); container.append(section);
    if (C.array(resources.errors).length) { container.append(C.el("p", "notice warning", "일부 자원 정보를 수집하지 못했습니다. 보고 원문에서 수집 오류를 확인하세요.")); }
  };
  const capabilities = (agent, container) => {
    const report = C.object(status(agent).capability_report), entries = Object.entries(C.object(report.capabilities));
    container.append(heading("기능 구현·실동작 상태"));
    container.append(C.el("p", "panel-note", "구현 여부·환경 지원과 실제 동작 보고를 구분합니다. 전용 정책 파일만으로 실행 옵션·파일 쓰기·TCP 연결 요청 수집이 확인되지는 않습니다. 각 기능의 실제 이벤트 수신과 확인 시각을 보세요. 관측은 코드 실행 성공·연결 완료나 자동 종료 허용을 뜻하지 않습니다."));
    const buildRows = list => list.map(([name, value]) => {
      const item = C.object(value), presentation = C.capability(name, item, C.capabilityFresh(name, item, agent));
      const identity = C.el("div"); identity.append(C.el("strong", "", presentation.title));
      const impl = C.tag(presentation.implementation, presentation.implementation === "개발 예정" ? "pending" : "neutral");
      const support = {supported:"지원 조건 확인",limited:"일부 조건 미확인",unsupported:"지원 안 함",error:"진단 오류"};
      const note = C.el("div", "", presentation.note); note.append(C.el("span", "capability-code", `사전 환경 진단: ${support[item.state] || "지원 여부 미확인"} · 진단 시각: ${C.time(report.probed_at)}`));
      if (item.verified_at) note.append(C.el("span", "capability-code", `실동작 확인: ${C.time(item.verified_at)}`));
      return [identity, impl, C.tag(presentation.label, presentation.tone), note];
    });
    const table = C.table("기능 구현과 보고된 실동작", ["기능", "구현 구분", "실동작 / 적용", "확인 근거"], buildRows(entries.filter(([,item])=>C.object(item).implementation!=="planned"))); table.classList.add("capabilities-table");
    const scroll = C.el("div", "table-scroll"); scroll.tabIndex = 0; scroll.setAttribute("role", "region"); scroll.setAttribute("aria-label", "기능 상태 목록"); scroll.append(table); container.append(scroll);
    const planned = entries.filter(([,item])=>C.object(item).implementation==="planned");
    if(planned.length)container.append(detailSection("planned",`추가 개발 예정 · ${planned.length}개`,C.table("현재 제공되지 않는 기능",["기능","구현 구분","실동작 / 적용","설명"],buildRows(planned)),"아래 기능은 현재 탐지·대응에 사용되지 않습니다."));
    container.append(C.raw(report,"기술 보고 원문 보기"));
  };
  const assignedPolicy = (agent, container) => {
    container.append(heading("현재 중앙 지정 정책"));
    if (!fleet.policy || fleet.policyKey !== C.policyIdentity(agent)) { container.append(C.el("p", "panel-note", fleet.policyLoading ? "지정된 정책을 확인하고 있습니다." : "지정된 정책을 불러오지 못했습니다. 상태를 갱신해 다시 확인하세요.")); return; }
    const policy = fleet.policy.policy;
    if (!policy) { container.append(C.el("p", "inline-note", "중앙에서 지정한 정책이 없습니다. 에이전트는 로컬 설정을 사용할 수 있습니다.")); return; }
    const modes = {observe:"탐지 전용",would_block:"모의 대응",enforce:"자동 종료"}, detection = C.object(policy.detection);
    container.append(C.facts([["정책 / 리비전", `${policy.policy_id} / ${policy.revision}`], ["대응 방식", modes[C.object(policy.response).mode] || "미확인"], ["서비스별 파일·TCP 범위", C.serviceScopeSummary(detection)], ["웹 서비스", C.array(detection.web_services).join(" · ") || "명시 서비스 없음"], ["웹 실행 파일", C.array(detection.web_executables).join(" · ") || "명시 실행 파일 없음"], ["탐지 셸", C.array(detection.shells).join(" · ") || "없음"],["전역 root·권한 변경",detection.privilege_rules?`사용 · ${detection.root_exec_alerts==="all"?"모든 root 실행 경보":"의심 문맥만 경보"} · 탐지 전용`:"사용 안 함"], ["정책 만료", C.time(policy.expires_at)]]));
    if (C.agentApplicationPolicies) container.append(C.agentApplicationPolicies(agent, fleet.policy));
    if (C.array(fleet.policy.pending_features).includes("integrity")) container.append(C.el("p", "notice warning", "추가 무결성 설정(TPM·임의 경로·강제 검증)은 중앙 초안에 보관합니다."));
    container.append(C.button("이 서버 정책으로 새 정책 작성", () => C.editTemplateFromPolicy(policy, fleet.policy.desired_settings), "primary small"));
    container.append(C.el("p", "panel-note", "현재 지정 정책을 복사하여 새 템플릿을 작성합니다. 저장·배포 전에는 서버 설정이 바뀌지 않습니다."), C.raw(policy, "지정된 정책 전체 보기"));
  };
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
  C.renderAgentDetail = (load = true) => {
    const agent = C.state.agents.find(a => a.agent_id === C.selectedAgent);
    C.id("agentDetail").hidden = !agent; if (!agent) return;
    const hb = heartbeat(agent), liveStatus = status(agent), policy = C.policyState(agent), platform = C.object(C.object(liveStatus.capability_report).platform);
    const focus = document.activeElement && C.id("agentDetailBody").contains(document.activeElement) ? document.activeElement.textContent : "";
    const content = C.el("div"), summary = C.el("div", "agent-summary");
    C.text("agentDetailTitle", `${agent.agent_id}${agent.hostname ? ` · ${agent.hostname}` : ""}`);
    summary.append(C.facts([["연결 상태",C.tag(C.connection(agent).label,C.connection(agent).tone)],["등록 ID",agent.enrollment_id],["등록 시각",C.time(agent.enrolled_at)],["마지막 인증 수신",C.time(agent.last_seen_at)],["하트비트 시각",C.time(hb.sent_at)],["에이전트 버전",liveStatus.version]]), C.facts([["수집 상태",C.tag(C.health(agent).label,C.health(agent).tone)],["수집기",liveStatus.collector],["운영체제",platform.pretty_name || platform.distribution],["커널",platform.kernel_release],["적용 / 목표 리비전",`${policy.active ?? "미확인"} / ${policy.desired ?? "미확인"}`],["정책 상태",C.tag(policy.label,policy.tone)]])); content.append(summary);
    const errors = [liveStatus.last_error,C.object(hb.policy_status).error,hb.policy_error].filter(Boolean);
    if (errors.length) content.append(C.el("p", "notice warning", errors.join(" · ")));
    const actions = C.el("div", "form-actions");
    actions.append(C.button("이 서버 이력 조회", () => { C.id("historyAgent").value = agent.agent_id; root.location.hash = "history"; C.loadHistory(true); }, "small"));
    if (!agent.revoked) actions.append(C.button("제거 승인으로 이동", () => { C.id("removalAgent").value = agent.agent_id; C.populateRemoval(); root.location.hash = "approvals"; }, "small"));
    content.append(actions);
    assignedPolicy(agent, content); C.fileIntegrity(agent, content); resourceDetails(agent, content); capabilities(agent, content);
    content.append(C.raw(hb, "하트비트 보고 원문 보기"));
    C.id("agentDetailBody").replaceChildren(content);
    if (focus) for (const button of C.id("agentDetailBody").querySelectorAll("button,summary")) if (button.textContent === focus) { button.focus({preventScroll: true}); break; }
    if (load) loadPolicy(agent);
  };
  C.initFleet = () => {
    C.id("agentSearch").addEventListener("input", C.renderAgents);
    C.id("agentStatusFilter").addEventListener("change", C.renderAgents);
    C.id("closeAgentDetail").addEventListener("click", () => { C.selectedAgent = ""; C.id("agentDetail").hidden = true; });
    C.onState(() => { C.renderOverview(); C.renderAgents(); });
  };
  const root = globalThis;
})(globalThis.XEC);
