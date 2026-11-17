"use strict";

// Shared state, evidence-based presentation and DOM construction.
(function (root) {
  const C = root.XEC = {};
  C.state = {agents: [], groups: [], templates: [], defaults: {}, enrollment: {}};
  C.session = null;
  C.view = "overview";
  C.selectedAgent = "";
  C.listeners = [];
  C.clockOffset = 0;
  C.now = () => Date.now() + C.clockOffset;
  C.object = value => value && typeof value === "object" && !Array.isArray(value) ? value : {};
  C.array = value => Array.isArray(value) ? value : [];
  C.value = value => value === undefined || value === null || value === "" ? "미확인" : String(value);
  C.number = value => Number.isFinite(value) && value >= 0 ? value.toLocaleString("ko-KR") : "미확인";
  C.percent = value => Number.isFinite(value) && value >= 0 ? `${value.toFixed(1)}%` : "미확인";
  C.bytes = value => {
    if (!Number.isFinite(value) || value < 0) return "미확인";
    const units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++; }
    return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
  };
  C.rate = value => Number.isFinite(value) && value >= 0 ? `${C.bytes(value)}/s` : "미확인";
  C.time = value => {
    const stamp = Date.parse(value);
    return Number.isFinite(stamp) && stamp > 0 ? new Date(stamp).toLocaleString("ko-KR", {hour12: false}) : "보고 없음";
  };
  C.age = value => {
    const stamp = Date.parse(value);
    if (!Number.isFinite(stamp) || stamp <= 0) return "보고 없음";
    const seconds = Math.max(0, Math.floor((C.now() - stamp) / 1000));
    if (seconds < 60) return `${seconds}초 전`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}분 전`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}시간 전`;
    return `${Math.floor(seconds / 86400)}일 전`;
  };
  C.fresh = (stamp, maxAge = 120000) => {
    const time = Date.parse(stamp);
    return Number.isFinite(time) && time > 0 && C.now() - time >= -60000 && C.now() - time <= maxAge;
  };
  C.connection = agent => {
    if (agent.revoked) return {key: "revoked", label: "등록 해지", tone: "danger"};
    const heartbeat = C.object(agent.heartbeat);
    if (!Date.parse(heartbeat.sent_at)) return {key: "unknown", label: "보고 없음", tone: "neutral"};
    if (!C.fresh(heartbeat.sent_at)) return {key: "stale", label: "수신 지연", tone: "warning"};
    return {key: "online", label: "최근 수신", tone: "good"};
  };
  C.policyState = agent => {
    const heartbeat = C.object(agent.heartbeat), policy = C.object(heartbeat.policy_status);
    const active = policy.active_revision ?? heartbeat.policy_revision;
    const desired = agent.desired_policy_revision;
    const wireApplied = policy.result === "applied" && Number.isFinite(active) && active === desired && C.connection(agent).key === "online";
    const pending = C.array(agent.pending_features), applied = wireApplied && !pending.length;
    let label = "미확인", tone = "neutral";
    if (desired === 0) label = "중앙 정책 없음";
    else if (policy.result === "rejected" || policy.error || heartbeat.policy_error) { label = "적용 오류"; tone = "danger"; }
    else if (wireApplied && pending.includes("integrity")) { label = "일부 적용 · 무결성 대기"; tone = "warning"; }
    else if (applied) { label = "적용 보고"; tone = "good"; }
    else if (C.connection(agent).key !== "online") { label = "최신 상태 미확인"; tone = "warning"; }
    else { label = "적용 대기"; tone = "warning"; }
    return {active: Number.isFinite(active) ? active : null, desired, applied, wireApplied, pending, label, tone};
  };
  C.policyIdentity = agent => JSON.stringify([agent.agent_id,agent.enrollment_id,agent.desired_policy_revision]);
  C.policyResponseMatches = (agent, value) => {
    const policy = C.object(value).policy;
    if (policy === null) return agent.desired_policy_revision === 0;
    return Boolean(policy && policy.agent_id === agent.agent_id && policy.enrollment_id === agent.enrollment_id && policy.revision === agent.desired_policy_revision);
  };
  C.health = agent => {
    const heartbeat = C.object(agent.heartbeat), status = C.object(heartbeat.status);
    const connection = C.connection(agent);
    if (connection.key !== "online") return {label: connection.key === "stale" ? "최신 상태 미확인" : "미확인", tone: "neutral"};
    const labels = {healthy: ["정상 보고", "good"], starting: ["시작 중", "neutral"], degraded: ["점검 필요", "warning"], error: ["수집 오류", "danger"]};
    const found = Object.hasOwn(labels, status.health) ? labels[status.health] : ["미확인", "neutral"];
    return {label: found[0], tone: found[1]};
  };
  C.capabilityNames = {
    "observation.process_exec": "프로세스 실행 수집", "observation.process_lineage": "서비스 실행 경로 추적",
    "response.terminate": "안전 조건에 따른 프로세스 종료", "collector.tetragon": "실시간 실행 수집기",
    "collector.audit": "감사 기록 수집기", "host.platform": "운영체제 정보", "kernel.ebpf": "eBPF 실행 환경",
    "kernel.btf": "커널 형식 정보", "kernel.cgroup": "서비스 구분 정보", "integrity.ima": "운영체제 파일 측정 정보",
    "integrity.tpm": "TPM 장치 진단", "observation.file": "파일 활동 감시", "observation.network": "네트워크 활동 감시",
    "observation.credential_change": "권한 변경 감시"
  };
  C.capability = (name, value, fresh) => {
    const item = C.object(value);
    const result = {name, title: C.capabilityNames[name] || "추가 진단 항목", implementation: "미확인", label: "미확인", tone: "neutral", note: "실동작을 확인할 보고가 없습니다."};
    const diagnostic = name.startsWith("host.") || name.startsWith("kernel.") || name.startsWith("integrity.");
    if (item.implementation === "planned") return {...result, implementation: "개발 예정", label: "미제공", tone: "pending", note: "현재 탐지·대응에 사용되지 않는 기능입니다."};
    if (!Object.hasOwn(C.capabilityNames,name)) return result;
    if (item.implementation === "implemented") result.implementation = "구현됨";
    if (diagnostic) result.implementation = "환경 진단";
    if (!fresh) return {...result, label: "최신 상태 미확인", tone: "warning", note: "기능 보고가 없거나 오래되었습니다. 이전 보고 원문만 참고하세요."};
    if (name.startsWith("integrity.")) return {...result, label: "검증 미제공", tone: "pending", note: "장치·측정 정보의 진단 항목입니다. 에이전트 무결성 검증은 현재 제공하지 않습니다."};
    if (item.runtime_state === "error" || item.state === "error") return {...result, label: "확인 오류", tone: "danger", note: "기능 실행 또는 환경 확인에서 오류가 보고되었습니다. 서버 설정과 수집기 로그를 확인하세요."};
    if (item.state === "unsupported") return {...result, label: "지원 안 함", tone: "neutral", note: "현재 서버 환경에서 이 기능의 지원 조건을 충족하지 못했습니다."};
    if (diagnostic) {
      const label = item.runtime_state === "active" ? "동작 진단 확인" : item.state === "supported" ? "환경 조건 확인" : "일부 조건 미확인";
      return {...result, label, tone: item.runtime_state === "active" ? "good" : "neutral", note: "수집·대응에 필요한 서버 환경의 진단 결과입니다. 실제 수집 여부는 해당 수집 기능의 실동작 보고에서 확인하세요."};
    }
    if (item.implementation !== "implemented") return result;
    if (name === "response.terminate") {
      if (item.runtime_state === "active") return {...result, label: "조건부 대응 가능", tone: "blue", note: "로컬 종료 허용이 보고되었습니다. 실제 종료는 정책·기능·안전 조건을 모두 만족해야 합니다."};
      if (["available", "inactive"].includes(item.runtime_state)) return {...result, label: "자동 종료 꺼짐", note: "로컬 종료 허용 설정을 확인하세요. 중앙 정책만으로 자동 종료가 활성화되지 않습니다."};
    }
    const states = {
      active:["수집 동작 보고","good",name === "observation.process_lineage" ? "프로그램이 어느 서비스에서 실행되었는지 추적합니다. 일부 상위 프로세스 정보는 누락될 수 있습니다." : "에이전트에서 실행 정보를 수신하고 있습니다. 보존 이력은 탐지와 관련된 기록을 중심으로 표시합니다."],
      available:["사용 가능 · 미동작","neutral","서버 지원 조건은 확인했지만 실제 기능 동작은 아직 보고되지 않았습니다."],
      inactive:["사용 안 함","neutral","현재 이 기능을 사용하지 않습니다. 다른 수집기 사용 여부와 서버 설정을 확인하세요."],
      unverified:["동작 미확인","warning","실제 정보 수신을 확인하지 못했습니다. 에이전트 수집기 연결 상태를 확인하세요."]
    };
    if (Object.hasOwn(states, item.runtime_state)) { result.label = states[item.runtime_state][0]; result.tone = states[item.runtime_state][1]; result.note = states[item.runtime_state][2]; }
    return result;
  };
  C.lines = value => String(value || "").split(/\r?\n/).map(item => item.trim()).filter(Boolean);
  C.parseChallenge = (text, agentID, enrollmentID) => {
    let challenge = String(text || "").trim();
    if (challenge.startsWith("{")) {
      let request;
      try { request = C.object(JSON.parse(challenge)); } catch (_) { throw new Error("제거 요청 JSON 형식을 확인하세요."); }
      if (request.agent_id && request.agent_id !== agentID || request.enrollment_id && request.enrollment_id !== enrollmentID) throw new Error("제거 요청 JSON의 대상 또는 등록 ID가 선택한 서버와 다릅니다.");
      challenge = typeof request.challenge === "string" ? request.challenge : "";
    }
    if (!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(challenge)) throw new Error("제거 챌린지는 서버에서 생성한 43자 요청값입니다. 'sentinel managed challenge'의 challenge 값 또는 출력 JSON을 입력하세요.");
    return challenge;
  };
  C.settingsFromValues = values => ({
    detection: {enabled: Boolean(values.detectionEnabled), extended_process_rules: Boolean(values.extendedRules), web_executables: C.lines(values.webExecutables), web_services: C.lines(values.webServices), shells: C.lines(values.shells), allowed_pairs: C.lines(values.allowedPairs)},
    response: {mode: values.responseMode, action: values.responseAction, risk_threshold: Number(values.riskThreshold), min_confidence: Number(values.minConfidence), required_capabilities: C.lines(values.requiredCapabilities)},
    uninstall_mode: values.uninstallMode,
    monitoring: {enabled: Boolean(values.monitoringEnabled), sample_interval_seconds: Number(values.sampleInterval), process_limit: Number(values.processLimit)},
    integrity: {enabled: Boolean(values.integrityEnabled), mode: values.integrityMode, require_tpm: Boolean(values.integrityTPM), paths: C.lines(values.integrityPaths)},
    validity_hours: Number(values.validityHours)
  });
  C.settingsFromPolicy = (policy, desired) => {
    const p = C.object(policy), source = C.object(desired);
    const hours = Math.round((Date.parse(p.expires_at) - Date.parse(p.issued_at)) / 3600000);
    return {detection: structuredClone(p.detection || {}), response: structuredClone(p.response || {}), uninstall_mode: p.uninstall_mode, monitoring: structuredClone(p.monitoring || {}), integrity: structuredClone(source.integrity || {enabled: false, mode: "observe", require_tpm: false, paths: []}), validity_hours: Number.isFinite(hours) ? Math.max(1, Math.min(8760, hours)) : 24};
  };
  C.validateSettings = settings => {
    const d = settings.detection, r = settings.response, m = settings.monitoring;
    if (d.enabled && (!d.shells.length || !d.web_executables.length && !d.web_services.length)) throw new Error("탐지를 사용하려면 웹 실행 파일 또는 서비스, 탐지할 셸을 입력하세요.");
    if (r.mode !== "observe" && (!d.enabled || r.action !== "terminate" || !r.required_capabilities.length || r.risk_threshold <= 0 || r.min_confidence <= 0)) throw new Error("모의 대응·자동 종료는 탐지 활성화, 종료 동작, 필수 기능 조건, 0보다 큰 위험 점수·신뢰도가 필요합니다.");
    const ranges = [[r.risk_threshold,0,100,"위험 점수",true],[r.min_confidence,0,1,"신뢰도",false],[m.sample_interval_seconds,5,3600,"수집 간격",true],[m.process_limit,1,2000,"프로세스 조회 수",true],[settings.validity_hours,1,8760,"정책 유효 기간",true]];
    for (const [n,min,max,label,integer] of ranges) if (!Number.isFinite(n) || n < min || n > max || integer && !Number.isInteger(n)) throw new Error(`${label}은 ${min}–${max} 범위${integer ? "의 정수" : ""}로 입력하세요.`);
    return settings;
  };
  C.previewSnapshot = (preview, templateID) => {
    const template = C.object(C.object(preview).template), settings = C.object(template.settings);
    const detection = C.object(settings.detection), response = C.object(settings.response), monitoring = C.object(settings.monitoring), integrity = C.object(settings.integrity);
    if (template.id !== templateID || typeof template.name !== "string" || !template.name || !Number.isSafeInteger(template.version) || template.version < 1 ||
        typeof detection.enabled !== "boolean" || !["web_executables","web_services","shells","allowed_pairs"].every(key=>detection[key]===null||Array.isArray(detection[key])) ||
        !["observe","would_block","enforce"].includes(response.mode) || !["none","terminate"].includes(response.action) || !Array.isArray(response.required_capabilities) && response.required_capabilities !== null ||
        typeof monitoring.enabled !== "boolean" || typeof integrity.enabled !== "boolean" || !["observe","enforce"].includes(integrity.mode)) {
      throw new Error("서버에서 실제 배포 정책을 확인할 수 없습니다. 새로고침 후 미리보기를 다시 생성하세요.");
    }
    // Decode nullable wire arrays before checking settings. The snapshot remains
    // independent from mutable list state while the operator reviews it.
    const snapshot = structuredClone(template);
    for (const key of ["web_executables","web_services","shells","allowed_pairs"]) snapshot.settings.detection[key] = C.array(snapshot.settings.detection[key]);
    snapshot.settings.response.required_capabilities = C.array(snapshot.settings.response.required_capabilities);
    C.validateSettings(snapshot.settings);
    return snapshot;
  };
  C.findings = record => {
    const payload = C.object(record.payload);
    if (record.kind === "finding") return [payload];
    return record.kind === "event_bundle" ? C.array(payload.findings) : [];
  };
  C.el = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = String(value);
    return node;
  };
  C.id = id => document.getElementById(id);
  C.text = (id, value) => { C.id(id).textContent = value === undefined || value === null ? "미확인" : String(value); };
  C.tag = (text, tone = "neutral") => C.el("span", `tag ${tone}`, text);
  C.empty = text => C.el("p", "empty", text);
  C.button = (text, action, className = "") => {
    const button = C.el("button", className, text); button.type = "button";
    button.addEventListener("click", action); return button;
  };
  C.facts = pairs => {
    const dl = C.el("dl", "facts");
    for (const [name, value] of pairs) { const dd = C.el("dd"); dd.append(value instanceof Node ? value : C.value(value)); dl.append(C.el("dt", "", name), dd); }
    return dl;
  };
  C.raw = (value, title = "보고 원문 보기") => {
    const details = C.el("details", "technical"); details.append(C.el("summary", "", title), C.el("pre", "raw-json", JSON.stringify(value, null, 2))); return details;
  };
  C.table = (title, headings, rows) => {
    const table = C.el("table"); table.append(C.el("caption", "sr-only", title));
    const thead = C.el("thead"), header = C.el("tr");
    for (const label of headings) { const th = C.el("th", "", label); th.scope = "col"; header.append(th); }
    thead.append(header); const tbody = C.el("tbody");
    for (const values of rows) { const row = C.el("tr"); for (const value of values) { const td = C.el("td"); td.append(value instanceof Node ? value : C.value(value)); row.append(td); } tbody.append(row); }
    if (!rows.length) { const row = C.el("tr"), cell = C.el("td", "empty-cell", "표시할 보고 정보가 없습니다."); cell.colSpan = headings.length; row.append(cell); tbody.append(row); }
    table.append(thead, tbody); return table;
  };
  C.notify = message => { C.id("statusBanner").hidden = false; C.text("statusBanner", message); C.id("errorBanner").hidden = true; };
  C.error = error => { C.id("errorBanner").hidden = false; C.text("errorBanner", error instanceof Error ? error.message : error); C.id("statusBanner").hidden = true; };
  C.run = async (button, operation) => {
    if (button && button.disabled) return;
    const disabled = button ? button.disabled : false;
    if (button) { button.disabled = true; button.setAttribute("aria-busy", "true"); }
    try { return await operation(); } catch (err) { C.error(err); }
    finally { if (button) { button.disabled = disabled; button.removeAttribute("aria-busy"); } }
  };
  C.request = async (path, options = {}) => {
    const method = options.method || "GET", controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    try {
      const headers = {Accept: "application/json"};
      if (options.body !== undefined) headers["Content-Type"] = "application/json";
      if (method !== "GET") headers["X-CSRF-Token"] = C.session ? C.session.csrf_token : "";
      const response = await fetch(path, {method, headers, credentials: "same-origin", cache: "no-store", signal: controller.signal, ...(options.body !== undefined ? {body: JSON.stringify(options.body)} : {})});
      if (response.status === 401) { root.location.assign("/login"); throw new Error("세션이 만료되었습니다. 다시 로그인하세요."); }
      let body = null;
      if (response.status !== 204) { try { body = await response.json(); } catch (_) { if (response.ok) throw new Error("서버 응답 형식을 확인할 수 없습니다."); } }
      if (!response.ok) {
        const messages = {400: "입력값을 확인하세요.",403: "이 작업에 대한 권한 또는 요청 인증을 확인하세요.",404: "대상을 찾을 수 없습니다. 목록을 갱신하세요.",409: "편집 또는 배포 대상이 변경되었습니다. 최신 상태를 불러온 뒤 다시 확인하세요.",429: "요청이 많습니다. 잠시 후 다시 시도하세요."};
        throw new Error(C.object(body).error || messages[response.status] || "서버 요청을 처리하지 못했습니다.");
      }
      return options.page ? {items: C.array(body), next: response.headers.get("X-Next-Cursor") || ""} : body;
    } catch (error) {
      if (error.name === "AbortError") throw new Error("서버 응답 시간이 초과되었습니다. 연결 상태를 확인한 뒤 다시 시도하세요.");
      if (error instanceof TypeError) throw new Error("중앙 서버에 연결할 수 없습니다. 네트워크를 확인하세요.");
      throw error;
    } finally { clearTimeout(timeout); }
  };
  C.onState = fn => C.listeners.push(fn);
  C.updateState = next => {
    const serverTime = Date.parse(next.server_time);
    if (Number.isFinite(serverTime)) C.clockOffset = serverTime - Date.now();
    C.state = {agents: C.array(next.agents), groups: C.array(next.groups), templates: C.array(next.templates), defaults: C.object(next.defaults), enrollment: {ready: C.object(next.enrollment).ready === true, central_url: C.object(next.enrollment).central_url || ""}, server_time: next.server_time};
    C.listeners.forEach(fn => fn());
  };
  if (typeof module !== "undefined" && module.exports) module.exports = C;
})(globalThis);
