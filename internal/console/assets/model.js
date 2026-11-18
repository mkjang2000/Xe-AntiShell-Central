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
    else if (wireApplied && pending.includes("integrity.agent_files")) { label = "일부 적용 · 파일 측정 대기"; tone = "warning"; }
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
    "observation.interpreter_exec": "인터프리터 실행 옵션 관측",
    "response.terminate": "안전 조건에 따른 프로세스 종료", "collector.tetragon": "실시간 실행 수집기",
    "collector.audit": "감사 기록 수집기", "host.platform": "운영체제 정보", "kernel.ebpf": "eBPF 실행 환경",
    "kernel.btf": "커널 형식 정보", "kernel.cgroup": "서비스 구분 정보", "integrity.ima": "운영체제 파일 측정 정보",
    "integrity.tpm": "TPM 장치 진단", "integrity.agent_files": "에이전트 파일 무결성 측정", "observation.file": "파일 쓰기 관측", "observation.network": "TCP 연결 요청 관측",
    "observation.credential_change": "권한 변경 관측", "detection.privilege_rules": "전역 root·권한 변경 탐지 엔진",
    "detection.service_rule_controls": "서비스별 규칙·임시 예외",
    "detection.service_observations": "서비스별 파일·TCP 서명 정책"
  };
  C.capabilityFresh = (name, value, agent) => {
    if (C.connection(agent).key !== "online") return false;
    const item = C.object(value);
    const observed = Object.hasOwn(C.capabilityNames, name) && (name.startsWith("collector.") || name.startsWith("observation.") || name === "kernel.ebpf");
    return item.runtime_state !== "active" || !observed || C.fresh(item.verified_at, 300000);
  };
  C.capability = (name, value, fresh) => {
    const item = C.object(value);
    const result = {name, title: C.capabilityNames[name] || "추가 진단 항목", implementation: "미확인", label: "미확인", tone: "neutral", note: "실동작을 확인할 보고가 없습니다."};
    const integrityDiagnostic = name === "integrity.ima" || name === "integrity.tpm";
    const diagnostic = name.startsWith("host.") || name.startsWith("kernel.") || integrityDiagnostic;
    if (item.implementation === "planned") return {...result, implementation: "개발 예정", label: "미제공", tone: "pending", note: "현재 탐지·대응에 사용되지 않는 기능입니다."};
    if (!Object.hasOwn(C.capabilityNames,name)) return result;
    if (item.implementation === "implemented") result.implementation = "구현됨";
    if (diagnostic) result.implementation = "환경 진단";
    if (!fresh) return {...result, label: "최신 상태 미확인", tone: "warning", note: "기능 보고가 없거나 오래되었습니다. 이전 보고 원문만 참고하세요."};
    if (integrityDiagnostic) return {...result, label: "검증 미제공", tone: "pending", note: name === "integrity.ima" ? "운영체제 IMA 측정 목록의 가시성을 진단합니다. 실제 파일 다이제스트는 파일 검사 결과에서 확인합니다." : "TPM 장치의 가시성을 진단합니다. 원격 증명은 후속 기능입니다."};
    if (item.runtime_state === "error") return {...result, label: "확인 오류", tone: "danger", note: "기능 실행에서 오류가 보고되었습니다. 서버 설정과 수집기 로그를 확인하세요."};
    if (!["supported","limited","unsupported","error"].includes(item.state)) return result;
    if (name === "integrity.agent_files") {
      const supported = item.implementation === "implemented" && item.state === "supported" && item.runtime_state === "available" && C.object(item.details).contract === "1";
      return {...result, label: supported ? "파일 검사 지원 확인" : "파일 검사 지원 미확인", tone: supported ? "good" : "warning", note: "승인 정책이 배포되면 고정 대상 파일을 측정합니다. 최근 일치·변경 여부는 에이전트 파일 무결성의 검사 결과 조회에서 확인하세요."};
    }
    if (["detection.service_observations", "detection.service_rule_controls"].includes(name) && item.implementation === "implemented") {
      const supported = C.object(item.details).contract === "1" && ["available", "active"].includes(item.runtime_state);
      return {...result, label: supported ? "정책 지원 확인" : "정책 지원 미확인", tone: supported ? "good" : "warning",
        note: name === "detection.service_rule_controls" ? "서명된 서비스별 규칙과 만료 시각을 해석할 수 있는 에이전트입니다." : "실제 수신 시각은 파일 쓰기 관측과 TCP 연결 요청 관측에서 확인하세요."};
    }
    if (name === "detection.privilege_rules" && item.implementation === "implemented") {
      if (C.object(item.details).contract !== "1" || !["available","active"].includes(item.runtime_state)) return {...result,label:"엔진 지원 미확인",tone:"warning",note:"현재 보고에서 지원 계약과 엔진 가용성을 확인하지 못했습니다. 에이전트 버전과 실제 상태를 확인하세요."};
      return {...result,label:item.runtime_state==="active"?"탐지 사용 중":"엔진 지원 보고",tone:item.runtime_state==="active"?"good":"neutral",note:"전역 root 실행과 권한 변경 규칙을 지원합니다. 엔진 지원은 센서의 실제 이벤트 수신이나 침해 발생 증거가 아닙니다. 이 규칙은 자동 종료 대상에 포함되지 않습니다."};
    }
    const observationNotes = {
      "observation.process_lineage": "프로그램이 어느 서비스에서 실행되었는지 추적합니다. 일부 상위 프로세스 정보는 누락될 수 있습니다.",
      "observation.interpreter_exec": "실행 옵션 관측 이벤트가 보고됐습니다. 전용 수집 정책의 옵션 조건 또는 분리된 실행 인자로 직접 코드·임시 스크립트 실행 요청을 구분합니다. 기존 프로세스 내부 실행과 실행 성공·코드 내용은 확인하지 않습니다.",
      "observation.credential_change": "커널 권한 변경 후크의 관측 이벤트가 보고됐습니다. 변경 전후·적용 결과·사용자 namespace를 개별 확인해야 하며 모든 권한 변경이나 침해 탐지를 보장하지 않습니다.",
      "observation.file": "선택한 수집 정책의 파일 쓰기 이벤트가 보고됐습니다. 경로와 호출 반환값을 관측하며 파일 내용·모든 쓰기·디스크 반영을 보장하지 않습니다.",
      "observation.network": "선택한 수집 정책의 TCP 연결 요청 이벤트가 보고됐습니다. 대상과 호출 반환값을 관측하며 연결 완료·모든 통신·전송 내용은 확인하지 않습니다."
    };
    const activeNote = observationNotes[name] || "에이전트에서 실행 정보를 수신하고 있습니다. 보존 이력은 탐지와 관련된 기록을 중심으로 표시합니다.";
    const live = item.implementation === "implemented" && item.runtime_state === "active";
    const mismatch = ["unsupported", "error"].includes(item.state) ? " 사전 환경 진단은 실제 수집 보고와 일치하지 않습니다. 기술 보고 원문을 확인하세요." : "";
    if (live && name === "kernel.ebpf") return {...result, label: "동작 진단 확인", tone: "good", note: "Tetragon 실행 이벤트로 프로세스 eBPF 후크 동작을 확인했습니다. 확인 범위는 프로세스 실행 후크이며, 그 밖의 eBPF 기능은 별도 검증이 필요합니다." + mismatch};
    if (live && (name.startsWith("collector.") || name.startsWith("observation."))) {
      return {...result, label: "수집 동작 보고", tone: "good", note: activeNote + mismatch};
    }
    if (item.state === "error") return {...result, label: "확인 오류", tone: "danger", note: "환경 확인에서 오류가 보고되었습니다. 서버 설정과 수집기 로그를 확인하세요."};
    if (item.state === "unsupported") return {...result, label: "지원 안 함", tone: "neutral", note: "현재 서버 환경에서 이 기능의 지원 조건을 충족하지 못했습니다."};
    if (diagnostic) {
      const active = name !== "kernel.ebpf" && item.runtime_state === "active";
      const label = active ? "동작 진단 확인" : item.state === "supported" ? "환경 조건 확인" : "일부 조건 미확인";
      return {...result, label, tone: active ? "good" : "neutral", note: "수집·대응에 필요한 서버 환경의 진단 결과입니다. 실제 수집 여부는 해당 수집 기능의 실동작 보고에서 확인하세요."};
    }
    if (item.implementation !== "implemented") return result;
    if (name === "response.terminate") {
      if (item.runtime_state === "active") return {...result, label: "조건부 대응 가능", tone: "blue", note: "로컬 종료 허용이 보고되었습니다. 실제 종료는 정책·기능·안전 조건을 모두 만족해야 합니다."};
      if (["available", "inactive"].includes(item.runtime_state)) return {...result, label: "자동 종료 꺼짐", note: "로컬 종료 허용 설정을 확인하세요. 중앙 정책만으로 자동 종료가 활성화되지 않습니다."};
    }
    const states = {
      active:["수집 동작 보고","good",activeNote],
      available:["사용 가능 · 미동작","neutral","서버 지원 조건은 확인했지만 실제 기능 동작은 아직 보고되지 않았습니다."],
      inactive:["사용 안 함","neutral","현재 이 기능을 사용하지 않습니다. 다른 수집기 사용 여부와 서버 설정을 확인하세요."],
      unverified:["동작 미확인","warning",["observation.interpreter_exec","observation.file","observation.network","observation.credential_change"].includes(name)?"수집 정책이나 설정만으로 동작을 확인할 수 없습니다. 이 기능의 실제 관측 이벤트 수신은 아직 확인되지 않았습니다.":"실제 정보 수신을 확인하지 못했습니다. 에이전트 수집기 연결 상태를 확인하세요."]
    };
    if (Object.hasOwn(states, item.runtime_state)) { result.label = states[item.runtime_state][0]; result.tone = states[item.runtime_state][1]; result.note = states[item.runtime_state][2]; }
    return result;
  };
  C.eventLabel = value => {
    const labels = {"process.exec":"프로그램 실행","process.exit":"프로그램 종료","process.exec_observation":"실행 옵션 관측","file.write":"파일 쓰기 관측","network.connect":"TCP 연결 요청 관측","process.credential_change":"프로세스 권한 변경 관측"};
    return Object.hasOwn(labels,value) ? labels[value] : "추가 수집 이벤트";
  };
  C.findingPresentation = value => {
    const rules = {
      "web-descendant-inline-interpreter":["웹 서비스에서 직접 코드 실행 요청","직접 코드 실행 옵션을 관측했습니다. 코드 내용과 실행 성공 여부는 확인하지 않습니다."],
      "web-descendant-temporary-script":["웹 서비스에서 임시 경로의 스크립트 실행 요청","임시·메모리·파일 디스크립터 경로의 스크립트 인자를 관측했습니다. 파일 내용과 실행 성공 여부는 확인하지 않습니다."],
      "web-descendant-temporary-executable":["웹 서비스에서 임시 경로의 실행 파일 실행","임시 또는 메모리 파일 경로의 프로그램이 실행됐습니다. 출처와 정상 운영 작업 여부를 확인하세요."]
    };
    const finding=C.object(value);
    return Object.hasOwn(rules,finding.rule_id) ? {title:rules[finding.rule_id][0],note:rules[finding.rule_id][1]} : {title:finding.summary||finding.rule_id||"의심 행위 탐지",note:"탐지 조건에 해당하는 기록이며 침해 확정을 뜻하지 않습니다."};
  };
  C.eventObservation = (event) => {
    const object = (value) => value && typeof value === "object" && !Array.isArray(value) ? value : {};
    const label = (labels, value) => Object.hasOwn(labels, value) ? labels[value] : "미확인";
    const returned = (value) => value === null || value === undefined ? "미수집" : Number.isSafeInteger(value) ? String(value) : "정확한 값 미확인";
    const fields = [];
    let summary = "";
    if (["process.exec", "process.exec_observation"].includes(event.event_type) && event.execution) {
      const value = object(event.execution);
      summary = value.mode === "inline" ? "인터프리터의 직접 코드 실행 옵션을 관측했습니다. 코드 내용과 실행 성공 여부는 확인하지 않습니다." : value.mode === "script" ? "임시·메모리·파일 디스크립터 경로의 스크립트 실행 인자를 관측했습니다. 파일 내용과 실행 성공 여부는 확인하지 않습니다." : "인터프리터 실행 근거가 보고됐습니다. 관측 범위는 상세 정보를 확인하세요.";
      const option = ["-c","-e","-E","-p","--eval","--print","-r","-f"].includes(value.option) ? value.option : value.mode === "script" && !value.option ? "위치 인자 (옵션 없음)" : "미확인";
      fields.push(["인터프리터", label({python:"Python",node:"Node.js",php:"PHP",perl:"Perl",ruby:"Ruby"}, value.runtime)], ["실행 방식", label({inline:"직접 코드 실행 옵션",script:"스크립트 파일 인자"}, value.mode)], ["관측 근거", label({exact_argv:"분리된 실행 인자의 정확한 옵션·위치",tetragon_policy:"전용 수집 정책의 실행 옵션 조건"}, value.evidence)], ["확인한 옵션", option], ["스크립트 경로 종류", value.mode === "inline" ? "해당 없음" : label({temporary:"임시 경로",memory:"메모리 파일 경로",fd:"파일 디스크립터 경로"}, value.script_location)], ["수집 정책", value.policy_name]);
    } else if (event.event_type === "file.write") {
      const value = object(event.file);
      summary = label({written:"파일 쓰기 호출에서 쓴 바이트 수가 보고됐습니다. 디스크 반영과 파일 내용은 확인하지 않습니다.",no_data:"파일 쓰기 호출이 0을 반환했습니다. 이 호출에서 쓴 데이터는 없습니다.",failed:"파일 쓰기 호출이 실패로 보고됐습니다.",unknown:"파일 쓰기 호출을 관측했습니다. 반환 결과는 확인되지 않았습니다."}, value.outcome);
      if (summary === "미확인") summary = "파일 쓰기 관측의 결과를 확인할 수 없습니다.";
      fields.push(["파일 경로",value.path], ["쓰기 결과",label({written:"쓰기 바이트 수 보고",no_data:"쓴 데이터 없음",failed:"실패",unknown:"결과 미확인"},value.outcome)], ["원래 반환값",returned(value.return_value)], ["반환값 의미","양수: 쓴 바이트 수 · 0: 쓴 데이터 없음 · 음수: 커널 오류. 디스크 반영 여부는 별도 확인이 필요합니다."], ["관측 함수",value.function], ["수집 정책",value.policy_name]);
    } else if (event.event_type === "network.connect") {
      const value = object(event.network);
      summary = label({initiated:"TCP 연결 요청이 커널에서 받아들여졌습니다. 연결 완료나 데이터 전송을 뜻하지 않습니다.",failed:"TCP 연결 요청이 실패로 보고됐습니다. 연결 완료 여부는 별도 관측이 필요합니다.",unknown:"TCP 연결 요청을 관측했습니다. 결과와 연결 완료 여부는 확인되지 않았습니다."},value.outcome);
      if (summary === "미확인") summary = "TCP 연결 요청의 결과를 확인할 수 없습니다.";
      fields.push(["대상 주소",value.destination_address], ["대상 포트",Number.isInteger(value.destination_port) && value.destination_port > 0 && value.destination_port <= 65535 ? value.destination_port : "미확인"], ["프로토콜",label({tcp:"TCP"},value.protocol)], ["주소 종류",label({ipv4:"IPv4",ipv6:"IPv6",AF_INET:"IPv4",AF_INET6:"IPv6"},value.family)], ["요청 결과",label({initiated:"연결 요청 시작",failed:"요청 실패",unknown:"결과 미확인"},value.outcome)], ["원래 반환값",returned(value.return_value)], ["반환값 의미","0: 커널 연결 요청 시작 · 음수: 커널 오류. 연결 완료·상대 응답·통신 내용은 확인하지 않습니다."], ["관측 함수",value.function], ["수집 정책",value.policy_name]);
    }
    return {summary, fields};
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
  const serviceScopeFields = values => {
    if (!values.centralServiceScopes) return {};
    let scopes;
    try {
      scopes = JSON.parse(values.serviceScopes);
    } catch (_) {
      throw new Error("서비스별 범위를 JSON 배열로 입력하세요. 모두 끄려면 []를 입력하세요.");
    }
    if (!Array.isArray(scopes)) throw new Error("서비스별 범위에는 목록이 필요합니다.");
    return {service_observations: scopes};
  };
  C.serviceScopeSummary = detection => {
    if (!Object.hasOwn(detection, "service_observations")) return "호스트 YAML 사용";
    const scopes = detection.service_observations;
    return scopes.length ? "중앙 정책 · " + scopes.map(scope => scope.service).join(" · ") : "중앙 정책 · 모든 서비스 범위 끔";
  };
  const serviceRuleFields = value => {
    if (!value?.trim()) return {};
    let controls;
    try { controls = JSON.parse(value); } catch (_) { throw new Error("서비스별 규칙을 JSON 배열로 입력하세요."); }
    if (!Array.isArray(controls)) throw new Error("서비스별 규칙 목록이 필요합니다.");
    return controls.length ? {service_rule_controls: controls} : {};
  };
  C.settingsFromValues = values => ({
    detection: {...serviceScopeFields(values), ...serviceRuleFields(values.serviceRuleControls), enabled: Boolean(values.detectionEnabled), extended_process_rules: Boolean(values.extendedRules), ...(values.privilegeRules ? {privilege_rules:true,root_exec_alerts:values.rootExecAlerts||"suspicious"} : {}), web_executables: C.lines(values.webExecutables), web_services: C.lines(values.webServices), shells: C.lines(values.shells), allowed_pairs: C.lines(values.allowedPairs)},
    response: {mode: values.responseMode, action: values.responseAction, risk_threshold: Number(values.riskThreshold), min_confidence: Number(values.minConfidence), required_capabilities: C.lines(values.requiredCapabilities)},
    uninstall_mode: values.uninstallMode,
    monitoring: {enabled: Boolean(values.monitoringEnabled), sample_interval_seconds: Number(values.sampleInterval), process_limit: Number(values.processLimit)},
    integrity: {...(values.integrityPackageFiles ? {package_files:true} : {}),...(values.integrityConfigSHA ? {config_sha256:values.integrityConfigSHA.trim()} : {}),enabled: Boolean(values.integrityEnabled), mode: values.integrityMode, require_tpm: Boolean(values.integrityTPM), paths: C.lines(values.integrityPaths)},
    validity_hours: Number(values.validityHours)
  });
  C.settingsFromPolicy = (policy, desired) => {
    const p = C.object(policy), source = C.object(desired);
    const hours = Math.round((Date.parse(p.expires_at) - Date.parse(p.issued_at)) / 3600000);
    return {detection: structuredClone(p.detection || {}), response: structuredClone(p.response || {}), uninstall_mode: p.uninstall_mode, monitoring: structuredClone(p.monitoring || {}), integrity: structuredClone(source.integrity || {enabled: false, mode: "observe", require_tpm: false, paths: []}), validity_hours: Number.isFinite(hours) ? Math.max(1, Math.min(8760, hours)) : 24};
  };
  C.validateSettings = settings => {
    const d = settings.detection, r = settings.response, m = settings.monitoring;
    if (Object.hasOwn(d, "service_rule_controls")) {
      const controls = d.service_rule_controls;
      if (!Array.isArray(controls) || controls.length > 256) throw new Error("서비스별 규칙 설정은 256개까지 입력하세요.");
      const seen = new Set();
      for (const c of controls) {
        if (!c || !c.service || !c.rule_id || !["enabled","disabled","suppress_until"].includes(c.mode)) throw new Error("서비스, 규칙 ID와 적용 방식을 확인하세요.");
        if (c.mode === "suppress_until" && (!c.reason?.trim() || !Number.isFinite(Date.parse(c.expires_at)) || !/(Z|[+]00:00)$/.test(c.expires_at))) throw new Error("임시 예외에는 사유와 UTC 만료 시각이 필요합니다.");
        if (c.mode !== "suppress_until" && (c.reason || c.expires_at)) throw new Error("사유와 만료 시각은 임시 예외에만 지정하세요.");
        const key = JSON.stringify([c.service, c.rule_id]);
        if (seen.has(key)) throw new Error("서비스와 규칙 조합이 중복됩니다.");
        seen.add(key);
      }
    }
    if (Object.hasOwn(d, "service_observations") && (!Array.isArray(d.service_observations) || d.service_observations.length > 64 || d.service_observations.some(scope => !scope || typeof scope.service !== "string" || !scope.service))) throw new Error("서비스 이름이 있는 범위를 최대 64개까지 입력하세요.");
    if (d.privilege_rules !== undefined && typeof d.privilege_rules !== "boolean" || d.root_exec_alerts !== undefined && typeof d.root_exec_alerts !== "string" || d.root_exec_alerts && (!d.privilege_rules || !["suspicious","all"].includes(d.root_exec_alerts))) throw new Error("전역 root 실행 경보 범위를 확인하세요.");
    if (d.enabled && !d.privilege_rules && (!d.shells.length || !d.web_executables.length && !d.web_services.length)) throw new Error("탐지를 사용하려면 웹 실행 파일 또는 서비스, 탐지할 셸을 입력하세요.");
    if (r.mode !== "observe" && (!d.enabled || r.action !== "terminate" || !r.required_capabilities.length || r.risk_threshold <= 0 || r.min_confidence <= 0)) throw new Error("모의 대응·자동 종료는 탐지 활성화, 종료 동작, 필수 기능 조건, 0보다 큰 위험 점수·신뢰도가 필요합니다.");
    if (settings.integrity.config_sha256 && (!settings.integrity.package_files || !/^[a-f0-9]{64}$/.test(settings.integrity.config_sha256))) throw new Error("에이전트 파일 검사를 선택한 후 승인된 YAML의 소문자 SHA-256을 입력하세요.");
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
        const error = new Error(C.object(body).error || messages[response.status] || "서버 요청을 처리하지 못했습니다.");
        error.status = response.status;
        throw error;
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
    C.state = {rule_ids: C.array(next.rule_ids), agents: C.array(next.agents), groups: C.array(next.groups), templates: C.array(next.templates), defaults: C.object(next.defaults), enrollment: {ready: C.object(next.enrollment).ready === true, central_url: C.object(next.enrollment).central_url || ""}, server_time: next.server_time};
    C.listeners.forEach(fn => fn());
  };
  if (typeof module !== "undefined" && module.exports) module.exports = C;
})(globalThis);
