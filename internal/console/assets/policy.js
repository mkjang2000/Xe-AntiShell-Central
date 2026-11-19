"use strict";

(function (C) {
  const P = {initialized: false, dirty: false, preview: null, selectionRevision: 0, integrityDraft: {}, section: "basics", observeAction: "none", saved: null, dirtySections: new Set()};
  const sections = ["basics", "detection", "response", "services", "agent", "usage"];
  const fields = ["detectionEnabled","extendedRules","privilegeRules","rootExecAlerts","policyServiceScope","webExecutables","webServices","shells","allowedPairs","responseMode","riskThreshold","minConfidence","requiredCapabilities","monitoringEnabled","sampleInterval","processLimit","uninstallMode","validityHours","integrityPackageFiles","integrityConfigSHA"];
  const modes = {observe: "탐지 전용", would_block: "모의 대응", enforce: "자동 종료"};
  const setValue = (id, value) => { const field = C.id(id); if (field.type === "checkbox") field.checked = Boolean(value); else field.value = value ?? ""; };
  const listValue = value => C.array(value).join("\n");
  const capabilityOptions = [
    ["observation.process_exec", "프로세스 실행 정보 수신", "선택한 수집기에서 실제 실행 이벤트를 받았는지 확인합니다.", true],
    ["observation.process_lineage", "부모·자식 실행 관계 확인", "실행 출처를 판단할 계보 정보가 확인되어야 합니다.", true],
    ["response.terminate", "서버의 안전한 프로세스 종료 허용", "대상 서버의 로컬 종료 허용과 pidfd 지원이 필요합니다. 선택만으로 종료를 허용하지 않습니다.", true],
    ["collector.tetragon", "Tetragon 수집기 사용", "Tetragon에서 실제 실행 정보가 수신되어야 합니다. 수집기를 설치하거나 전환하는 설정은 아닙니다."],
    ["collector.audit", "Linux audit 수집기 사용", "audit 디스패처에서 실제 실행 정보가 수신되어야 합니다. Tetragon과 함께 필수로 지정하지 마세요."],
    ["kernel.ebpf", "프로세스 eBPF 후크 동작 확인", "Tetragon 실행 이벤트로 확인한 프로세스 후크가 필요합니다. 모든 eBPF 기능을 검증하는 조건은 아닙니다."]
  ];
  const capabilityLabels = new Map(capabilityOptions.map(([key, label]) => [key, label]));
  const unavailableCapabilities = new Map([
    ["host.platform", "운영체제 정보"], ["kernel.btf", "커널 BTF"], ["kernel.cgroup", "cgroup"],
    ["observation.file", "파일 변경 수집"], ["observation.network", "네트워크 수집"],
    ["observation.credential_change", "자격 증명 변경 수집"], ["integrity.ima", "IMA 검증"], ["integrity.tpm", "TPM 검증"]
  ]);
  let capabilityEditor = null;
  const selectedCapabilityKeys = () => C.lines(C.id("requiredCapabilities").value);
  const capabilitySummary = keys => C.array(keys).map(key => capabilityLabels.get(key) || `${unavailableCapabilities.get(key) || "사용자 정의 조건"} (${key})`).join(" · ") || "명시 조건 없음";
  const savedTemplate = () => C.state.templates.find(t => t.id === P.saved?.id) || P.saved;
  const writable = () => ["admin", "operator"].includes(C.session?.role);

  // Section tabs. Every section stays in the form so hidden values are saved.
  const showSection = name => {
    if (!sections.includes(name)) return;
    if (name === "usage" && !(Number(C.id("templateVersionInput").value) > 0)) name = "basics";
    P.section = name;
    for (const key of sections) {
      C.id(`policySection-${key}`).hidden = key !== name;
      C.id(`policySectionTab-${key}`).setAttribute("aria-pressed", String(key === name));
    }
    C.showPolicyUsage?.(name === "usage");
  };
  const flag = (section, kind) => {
    const node = C.id(`policySectionTab-${section}`).querySelector?.(".section-flag");
    if (!node) return;
    node.hidden = !kind; node.className = `section-flag${kind ? ` ${kind}` : ""}`;
    node.title = kind === "error" ? "확인이 필요한 항목" : kind === "dirty" ? "저장하지 않은 변경" : "";
  };
  const setDirty = (dirty, section) => {
    P.dirty = dirty;
    if (!dirty) P.dirtySections.clear(); else if (section) P.dirtySections.add(section);
    for (const key of sections) if (key !== "usage") flag(key, P.dirtySections.has(key) ? "dirty" : "");
    C.text("templateDirty", dirty ? "저장하지 않은 변경 사항이 있습니다" : P.saved ? "저장된 상태입니다" : "아직 저장하지 않은 새 정책입니다");
    C.id("templateDirty").className = `save-state${dirty ? " dirty" : ""}`;
    C.id("revertTemplate").disabled = !dirty;
    C.id("deployFromEditor").disabled = !P.saved || !writable();
    if (!dirty) showFormError(null);
  };
  const showFormError = error => {
    const node = C.id("templateFormError");
    node.hidden = !error; node.textContent = error ? error.message : "";
    if (error?.section) { flag(error.section, "error"); showSection(error.section); }
  };

  // Response mode: radio cards drive the hidden wire value. The action follows
  // the mode; an observe policy keeps whatever action it was saved with.
  const modeRadios = () => [...(C.id("policySection-response").querySelectorAll?.("input[name=responseModeChoice]") || [])];
  const syncModeRadios = () => {
    const mode = C.id("responseMode").value;
    for (const radio of modeRadios()) {
      radio.checked = radio.value === mode;
      radio.closest?.(".mode-option")?.classList.toggle("selected", radio.checked);
    }
  };
  const capabilityHelp = () => {
    if (!capabilityEditor) return;
    const mode = C.id("responseMode").value, keys = selectedCapabilityKeys(), messages = [];
    capabilityEditor.help.textContent = mode === "would_block"
      ? "선택한 기능이 모두 실동작으로 확인된 경우에만 모의 대응 대상으로 기록합니다. 프로세스는 종료하지 않습니다."
      : mode === "enforce" ? "자동 종료는 선택 조건 외에도 실행 정보·계보·서버의 로컬 종료 허용을 항상 검사합니다. 실행 후 종료 신호를 보내며 실행 전 차단은 제공하지 않습니다." : "";
    if (keys.includes("collector.tetragon") && keys.includes("collector.audit")) messages.push("Tetragon과 Linux audit는 한 번에 하나만 실행 정보 수집기로 사용합니다. 두 수집기를 모두 필수로 선택하면 대응 조건이 충족되지 않습니다.");
    const unavailable = keys.filter(key => unavailableCapabilities.has(key));
    if (unavailable.length) messages.push(`기본 추천 목록 밖의 기존 조건: ${unavailable.map(key => unavailableCapabilities.get(key)).join(" · ")}. 실제 지원·수신 여부는 대상 에이전트에서 확인해야 합니다. 고급 편집에서 유지하거나 제거할 수 있습니다.`);
    capabilityEditor.warning.textContent = messages.join(" "); capabilityEditor.warning.hidden = !messages.length;
  };
  const syncCapabilityEditor = () => {
    const selected = [...capabilityEditor.inputs.filter(input => input.checked).map(input => input.value), ...C.lines(capabilityEditor.custom.value)];
    const remaining = selected.slice(), ordered = capabilityEditor.order.filter(key => {
      const index = remaining.indexOf(key); if (index < 0) return false;
      remaining.splice(index, 1); return true;
    });
    C.id("requiredCapabilities").value = [...ordered, ...remaining].join("\n");
    capabilityHelp();
  };
  const capabilityChanged = () => { syncCapabilityEditor(); changed("response"); };
  const fillCapabilityEditor = () => {
    if (!capabilityEditor) return;
    const keys = selectedCapabilityKeys(); capabilityEditor.order = keys.slice();
    for (const input of capabilityEditor.inputs) input.checked = keys.includes(input.value);
    capabilityEditor.custom.value = keys.filter(key => !capabilityLabels.has(key)).join("\n");
    capabilityHelp();
  };
  const initCapabilityEditor = () => {
    const container = C.id("requiredCapabilitiesEditor"); if (!container) return;
    const help = C.el("p", "field-note"), warning = C.el("p", "notice warning"), choices = C.el("div", "capability-options");
    help.setAttribute("aria-live", "polite"); warning.setAttribute("role", "status"); warning.hidden = true;
    const inputs = capabilityOptions.map(([key, label, description]) => {
      const row = C.el("label", "capability-option"), input = C.el("input"), text = C.el("span");
      input.type = "checkbox"; input.value = key; input.addEventListener("change", capabilityChanged);
      text.append(C.el("strong", "", label), C.el("small", "", description)); row.append(input, text); choices.append(row); return input;
    });
    const recommend = C.button("권장 조건 3개 선택", () => {
      for (const input of inputs) if (capabilityOptions.find(([key]) => key === input.value)[3]) input.checked = true;
      capabilityChanged();
    }, "small");
    const advanced = C.el("details", "editor-section"), custom = C.el("textarea"), customLabel = C.el("label", "", "기존·사용자 정의 기능 조건 (한 줄에 하나)");
    custom.id = "customRequiredCapabilities"; custom.rows = 3; custom.spellcheck = false; customLabel.htmlFor = custom.id;
    custom.addEventListener("input", capabilityChanged);
    advanced.append(C.el("summary", "", "기존 조건·사용자 정의 키 고급 편집"), customLabel, custom,
      C.el("p", "field-note", "기존 사용자 정의 키는 그대로 보존합니다. 대상 에이전트가 보고하지 않거나 실동작을 확인할 수 없는 키는 대응 조건을 충족하지 못합니다. 목록에 있는 기능은 위 체크박스에서 선택하세요."));
    container.replaceChildren(help, choices, recommend,
      C.el("p", "field-note", "파일 쓰기·TCP 연결·권한 변경 관측은 별도 센서 수신이 필요해 기본 추천 자동 종료 조건에 자동으로 추가하지 않습니다. 전역 root·권한 변경 규칙은 탐지 전용이며 IMA·TPM 검증은 미제공입니다. 대상 서버의 실제 수집 상태와 로컬 종료 허용은 배포 미리보기에서 확인하세요."), warning, advanced);
    capabilityEditor = {inputs, custom, help, warning, order: []};
  };

  // Dependent visibility and warnings that follow the current form values.
  const updateForm = () => {
    const mode = C.id("responseMode").value, observe = mode === "observe";
    const scope = C.id("policyServiceScope").value;
    C.id("webExecutablesField").hidden = scope !== "";
    C.id("webServicesField").hidden = scope === "all_listening";
    C.text("policyServiceScopeNote", scope === "all_listening"
      ? "배포할 때 각 에이전트의 최근 ‘전체 수집’ 보고에서 확인된 systemd 유닛을 확정합니다. 새로 발견한 서비스는 다음 배포 때 포함됩니다."
      : scope === "selected" ? "지정한 systemd 유닛 이름만 웹 출처 기준으로 사용합니다."
      : "입력한 웹 실행 파일과 서비스 이름을 웹 출처 기준으로 사용합니다.");
    syncModeRadios();
    C.id("responseConditions").hidden = observe;
    C.id("responseConditionsOff").hidden = !observe;
    C.id("rootExecAlertsField").hidden = !C.id("privilegeRules").checked;
    C.id("rootExecAlerts").disabled = !C.id("privilegeRules").checked;
    C.id("integrityConfigField").hidden = !C.id("integrityPackageFiles").checked && !C.id("integrityConfigSHA").value;
    let help = "";
    if (!observe && C.id("extendedRules").checked) help = "확장 실행 규칙이 켜져 있어 이 구성의 대응 대상 규칙은 0개입니다. 확장 프로필에서는 기본 웹 셸을 포함한 모든 규칙이 탐지 전용으로 기록됩니다. 대응하려면 탐지 탭에서 확장 실행 규칙을 끄세요.";
    else if (!observe && !C.id("detectionEnabled").checked) help = "탐지 엔진이 꺼져 있어 대응할 수 없습니다. 탐지 탭에서 탐지 엔진을 켜세요.";
    else if (!observe && !selectedCapabilityKeys().length) help = "대응하려면 필요한 기능을 1개 이상 선택해야 합니다. '권장 조건 3개 선택'으로 기본 조건을 고를 수 있습니다.";
    C.text("responseHelp", help); C.id("responseHelp").hidden = !help;
    capabilityHelp();
    C.applicationBindings?.hint?.();
    renderOverview();
  };

  const overviewFacts = () => {
    const detection = C.id("detectionEnabled").checked, mode = C.id("responseMode").value;
    const scope = C.id("policyServiceScope").value;
    const executables = C.lines(C.id("webExecutables").value).length, services = C.lines(C.id("webServices").value).length;
    const scopeText = scope === "all_listening" ? C.policyScopeLabel(scope) : scope === "selected" ? `지정된 서비스 ${services}개` : `웹 실행 파일 ${executables}개 · 웹 서비스 ${services}개`;
    const counts = C.policyServices?.counts?.() || {controls: 0, scopes: null};
    const bindings = C.applicationBindings?.count?.() ?? 0;
    const extras = [C.id("extendedRules").checked && "확장 실행 규칙", C.id("privilegeRules").checked && "전역 root·권한 변경"].filter(Boolean);
    const facts = [
      ["탐지", detection ? `사용 · ${scopeText}${extras.length ? ` · ${extras.join(" · ")}` : ""}` : "탐지 엔진 꺼짐"],
      ["대응", C.tag(modes[mode] || "미확인", mode === "enforce" ? "danger" : mode === "would_block" ? "warning" : "blue")],
      ["서비스별 설정", `정책 연결 ${bindings}개 · 규칙 설정 ${counts.controls}개 · 파일·TCP 범위 ${counts.scopes === null ? "호스트 YAML" : `중앙 ${counts.scopes}개`}`],
      ["에이전트", `${C.id("monitoringEnabled").checked ? `자원 보고 ${C.id("sampleInterval").value}초` : "자원 보고 꺼짐"} · 유효 기간 ${C.id("validityHours").value}시간${C.id("integrityPackageFiles").checked ? " · 파일 무결성 측정" : ""}`]
    ];
    if (P.saved) {
      const usage = deployments(P.saved.id);
      facts.push(["배포", usage.total ? `${usage.total}대에 지정${usage.outdated ? ` · ${usage.outdated}대는 이전 저장본` : " · 모두 현재 저장본"}` : "아직 배포하지 않았습니다"]);
    }
    return facts;
  };
  const renderOverview = () => { C.id("templateOverview").replaceChildren(C.facts(overviewFacts())); };
  const deployments = templateID => {
    const agents = C.state.agents.filter(agent => !agent.revoked && agent.desired_policy_id === templateID && agent.desired_policy_revision > 0);
    return {total: agents.length, outdated: agents.filter(agent => agent.policy_template_state === "changed").length};
  };

  const invalidatePreview = () => {
    P.selectionRevision++; P.preview = null;
    C.id("deploymentPreview").hidden = true; C.id("deployConfirm").checked = false; C.id("deployButton").disabled = true;
  };
  const changed = section => { setDirty(true, section); invalidatePreview(); updateForm(); };
  const canDiscard = async () => !P.dirty || await C.confirm({title:"편집 내용 버리기",description:"저장하지 않은 정책 변경 사항이 있습니다. 계속하면 현재 편집 내용이 사라집니다.",accept:"편집 내용 버리기"});

  const fillSettings = settings => {
    const d = C.object(settings.detection), r = C.object(settings.response), m = C.object(settings.monitoring), i = C.object(settings.integrity);
    P.integrityDraft = {enabled:i.enabled, mode:i.mode, require_tpm:i.require_tpm, paths:i.paths};
    const hasDraft = Boolean(i.enabled || i.require_tpm || i.mode === "enforce" || C.array(i.paths).length);
    C.id("integrityDraftNotice").hidden = !hasDraft;
    C.id("integrityDraftSummary").replaceChildren(...(hasDraft ? [C.facts([
      ["초안 활성", i.enabled ? "예" : "아니요"], ["TPM 조건", i.require_tpm ? "필수" : "미지정"],
      ["검증 방식", i.mode === "enforce" ? "강제 (초안)" : "관찰 (초안)"], ["검증 경로", C.array(i.paths).join("\n") || "미지정"]
    ])] : []));
    P.observeAction = (r.mode || "observe") === "observe" ? r.action || "none" : "none";
    const values = {detectionEnabled:d.enabled,extendedRules:d.extended_process_rules,privilegeRules:d.privilege_rules,rootExecAlerts:d.root_exec_alerts||"suspicious",policyServiceScope:settings.service_scope || "",webExecutables:listValue(d.web_executables),webServices:listValue(d.web_services),shells:listValue(d.shells),allowedPairs:listValue(d.allowed_pairs),responseMode:r.mode||"observe",riskThreshold:r.risk_threshold,minConfidence:r.min_confidence,requiredCapabilities:listValue(r.required_capabilities),monitoringEnabled:m.enabled,sampleInterval:m.sample_interval_seconds,processLimit:m.process_limit,uninstallMode:settings.uninstall_mode,validityHours:settings.validity_hours,integrityPackageFiles:i.package_files,integrityConfigSHA:i.config_sha256};
    for (const id of fields) setValue(id, values[id]);
    C.policyServices?.load(d);
    fillCapabilityEditor();
    C.applicationBindings?.load(settings);
    updateForm();
    C.policyInventory?.render();
  };
  const renderHeader = () => {
    const saved = P.saved, version = Number(C.id("templateVersionInput").value);
    C.text("templateEditorTitle", saved ? saved.name : C.id("templateName").value.trim() || "새 정책");
    C.text("templateVersion", saved ? `${saved.id} · 버전 ${saved.version}` : "새 정책");
    C.text("templateIDNote", version > 0 ? "저장된 정책의 ID는 바꿀 수 없습니다" : "영문·숫자·점·하이픈·밑줄 · 저장 후 바꿀 수 없습니다");
    const summary = [];
    if (saved) {
      summary.push(C.appPolicyTag ? C.appPolicyTag(C.object(saved.settings)) : C.tag(modes[C.object(saved.settings.response).mode] || "미확인"));
      const bindings = C.array(saved.settings?.application_bindings).length;
      if (bindings) summary.push(C.tag(`서비스 연결 ${bindings}개`, "neutral"));
      const usage = deployments(saved.id);
      summary.push(C.tag(usage.total ? `배포 ${usage.total}대` : "배포 안 됨", usage.total ? "good" : "neutral"));
      if (usage.outdated) summary.push(C.tag(`재배포 필요 ${usage.outdated}대`, "warning"));
    }
    C.id("templateSummary").replaceChildren(...summary);
    C.id("duplicateTemplate").disabled = !saved || !writable();
    C.id("deleteTemplate").disabled = !saved || !writable();
    C.id("deployFromEditor").disabled = !saved || !writable();
    C.id("policySectionTab-usage").disabled = !saved;
  };
  const fillTemplate = template => {
    const t = template || {id:"",name:"",description:"",version:0,settings:C.state.defaults};
    P.saved = template ? structuredClone(template) : null;
    setValue("templateID",t.id); setValue("templateName",t.name); setValue("templateDescription",t.description); setValue("templateVersionInput",t.version);
    C.id("templateID").readOnly = t.version > 0;
    fillSettings(C.object(t.settings)); C.selectPolicyUsage?.(t.id, t.version);
    setDirty(false); invalidatePreview(); renderHeader();
    showSection(template ? P.section : "basics");
    renderLists();
  };
  const readSettings = () => {
    const values = {};
    for (const id of fields) values[id] = C.id(id).type === "checkbox" ? C.id(id).checked : C.id(id).value;
    values.responseAction = values.responseMode === "observe" ? P.observeAction : "terminate";
    const policyID = C.id("templateID").value.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(policyID)) throw C.sectionError("basics", "정책 ID는 영문·숫자로 시작하고 영문·숫자·점·하이픈·밑줄만 128자까지 사용할 수 있습니다.");
    if (!C.id("templateName").value.trim()) throw C.sectionError("basics", "정책 이름을 입력하세요.");
    const keys = C.lines(values.requiredCapabilities), unique = new Set(keys.map(key => key.toLowerCase()));
    if (keys.length > 32 || keys.some(key => key.length > 255 || !/^[A-Za-z0-9_@.\\-]+$/.test(key) || key === "." || key === "..")) throw C.sectionError("response", "필수 기능 조건은 32개까지입니다. 키는 255자 이내의 영문·숫자·점·하이픈·밑줄·@·역슬래시로 입력하세요.");
    if (unique.size !== keys.length) throw C.sectionError("response", "필수 기능 조건에 중복된 키가 있습니다. 고급 편집과 체크박스 선택을 확인하세요.");
    if (capabilityEditor && C.lines(capabilityEditor.custom.value).some(key => capabilityLabels.has(key))) throw C.sectionError("response", "목록에 있는 기능은 고급 키 입력 대신 해당 체크박스에서 선택하세요.");
    const services = C.policyServices ? C.policyServices.read() : {};
    return C.validateSettings({...C.settingsFromValues(values, P.integrityDraft, services), ...C.applicationBindings?.read()});
  };

  const matchesFilter = (template, filter) => {
    const settings = C.object(template.settings), mode = C.object(settings.response).mode, usage = deployments(template.id);
    if (!filter) return true;
    if (filter === "bindings") return C.array(settings.application_bindings).length > 0;
    if (filter === "outdated") return usage.outdated > 0;
    if (filter === "unused") return usage.total === 0;
    return mode === filter;
  };
  const renderLists = () => {
    const selected = P.saved?.id || "";
    const focusedPolicy = document.activeElement?.dataset?.policyId;
    const query = C.id("templateSearch").value.trim().toLowerCase(), filter = C.id("templateFilter").value;
    const usages = new Map();
    for (const template of C.state.templates) {
      for (const ref of C.array(template.settings?.application_bindings)) {
        if (!usages.has(ref.policy_id)) usages.set(ref.policy_id, new Set());
        usages.get(ref.policy_id).add(ref.service);
      }
    }
    const visible = C.state.templates.filter(template => matchesFilter(template, filter) && [template.name, template.id, ...C.array(template.settings?.application_bindings).map(ref => ref.service), ...(usages.get(template.id) || [])].some(value => String(value).toLowerCase().includes(query)));
    C.text("templateCatalogCount", query || filter ? `${visible.length} / ${C.state.templates.length}` : C.state.templates.length);
    C.id("templateList").replaceChildren(...(visible.length ? visible.map(template => {
      const button = C.button("", async () => {
        if (P.saved?.id !== template.id && !await canDiscard()) return;
        fillTemplate(template);
        if (globalThis.matchMedia?.("(max-width: 880px)").matches) {
          C.id("templateEditorTitle").scrollIntoView({block:"start"});
          C.id("templateEditorTitle").focus({preventScroll:true});
        }
      }, `select-item${selected === template.id ? " selected" : ""}`);
      button.append(C.el("strong", "", template.name), C.el("small", "", `${template.id} · 버전 ${template.version}`));
      button.setAttribute("data-policy-id",template.id);
      button.setAttribute("aria-pressed", String(selected === template.id));
      const tags = C.el("span", "select-item-tags");
      if (C.appPolicyTag) tags.append(C.appPolicyTag(C.object(template.settings)));
      const count = C.array(template.settings?.application_bindings).length;
      if (count) tags.append(C.tag(`서비스 연결 ${count}개`, "neutral"));
      const usage = deployments(template.id);
      if (usage.total) tags.append(C.tag(`배포 ${usage.total}대`, "neutral"));
      if (usage.outdated) tags.append(C.tag(`재배포 필요 ${usage.outdated}대`, "warning"));
      if (C.object(C.object(template.settings).integrity).enabled) tags.append(C.tag("무결성 초안 포함", "pending"));
      button.append(tags);
      const referenced = usages.get(template.id);
      if (referenced) button.append(C.el("small","", "다른 정책에서 연결 · "+[...referenced].slice(0,2).join(" · ")+(referenced.size > 2 ? " 외 "+(referenced.size-2)+"개" : "")));
      return button;
    }) : [C.empty(query || filter ? "조건에 맞는 정책이 없습니다." : "저장된 정책이 없습니다. 새 정책으로 첫 정책을 작성하세요.")]));
    if (focusedPolicy) {
      const button = [...C.id("templateList").children].find(item => item.dataset?.policyId === focusedPolicy);
      button?.focus({preventScroll:true});
    }
    C.options("deployTemplate", C.state.templates.map(t => [t.id,`${t.name} · ${t.id} · v${t.version}`]), "정책을 선택하세요");
    C.choices("deployGroups", C.state.groups.map(g => [g.id,g.name,`${C.array(g.agent_ids).length}대`]), "deployGroup", "저장된 서버 그룹이 없습니다.");
    C.choices("deployAgents", C.state.agents.filter(a => !a.revoked).map(a => [a.agent_id,a.agent_id,a.hostname || "호스트명 보고 없음"]), "deployAgent", "배포 가능한 에이전트가 없습니다.");
    filterDeployAgents(); renderDeploySelection(); renderDeploySummary();
  };

  const saveTemplate = event => {
    event.preventDefault();
    C.run(event.submitter, async () => {
      let settings;
      try { settings = readSettings(); } catch (error) { showFormError(error); throw error; }
      const request = {id:C.id("templateID").value.trim(),name:C.id("templateName").value.trim(),description:C.id("templateDescription").value.trim(),version:Number(C.id("templateVersionInput").value),settings};
      try {
        const saved = await C.request("/api/templates", {method:"POST",body:request});
        fillTemplate(saved); await C.refresh(); renderHeader();
        C.notify(`정책 '${saved.name}'을 저장했습니다. 서버에는 아직 배포하지 않았습니다.`);
      } catch (error) { showFormError(error); throw error; }
    });
  };
  const deleteTemplate = async () => {
    await C.run(C.id("deleteTemplate"), async () => {
      const id = C.id("templateID").value, version = Number(C.id("templateVersionInput").value);
      if (!version || !await C.confirm({title:"정책 삭제",description:`'${P.saved?.name || id}' 정책을 삭제합니다. 이미 서버에 배포된 정책은 그대로 유지됩니다.`,accept:"정책 삭제"})) return;
      await C.request(`/api/templates/${encodeURIComponent(id)}?version=${version}`,{method:"DELETE"});
      fillTemplate(null); await C.refresh(); C.notify("정책을 삭제했습니다.");
    });
    C.id("deleteTemplate").disabled = !P.saved || !writable();
  };
  const duplicateTemplate = async () => {
    const source = savedTemplate();
    if (!source || !await canDiscard()) return;
    fillTemplate(null); fillSettings(structuredClone(C.object(source.settings)));
    setValue("templateName", `${source.name} 복사본`); setValue("templateDescription", source.description);
    setDirty(true, "basics"); renderHeader(); showSection("basics"); C.id("templateID").focus();
    C.notify(`'${source.name}'의 설정을 복사했습니다. 새 정책 ID를 입력하고 저장하세요.`);
  };
  const revertTemplate = async () => {
    if (!P.dirty || !await C.confirm({title:"변경 취소",description:"저장하지 않은 변경 사항을 버리고 마지막 저장 상태로 되돌립니다.",accept:"변경 취소"})) return;
    const section = P.section; fillTemplate(savedTemplate()); showSection(section);
  };

  // Deployment.
  const renderDeploySummary = () => {
    const template = C.state.templates.find(t => t.id === C.id("deployTemplate").value), out = C.id("deployTemplateSummary");
    if (!template) { out.replaceChildren(); return; }
    const settings = C.object(template.settings), usage = deployments(template.id), tags = C.el("div", "policy-summary");
    tags.append(C.appPolicyTag ? C.appPolicyTag(settings) : C.tag(modes[C.object(settings.response).mode] || "미확인"), C.tag(`버전 ${template.version}`, "neutral"));
    if (settings.service_scope) tags.append(C.tag(C.policyScopeLabel(settings.service_scope), "neutral"));
    if (C.array(settings.application_bindings).length) tags.append(C.tag(`서비스 연결 ${C.array(settings.application_bindings).length}개`, "neutral"));
    tags.append(C.tag(usage.total ? `현재 ${usage.total}대에 지정` : "아직 배포 안 됨", "neutral"));
    const edit = C.button("편집", () => { const target = C.state.templates.find(t => t.id === template.id); C.showPolicyPane?.("Catalog"); if (P.saved?.id !== template.id) canDiscard().then(ok => { if (ok) fillTemplate(target); }); }, "small quiet");
    if (P.dirty && P.saved?.id === template.id) out.replaceChildren(tags, C.el("p", "notice warning", "이 정책에 저장하지 않은 변경 사항이 있습니다. 배포는 마지막 저장 버전을 사용합니다."), edit);
    else out.replaceChildren(tags, edit);
  };
  const deployLabels = () => [...(C.id("deployAgents").children || [])].filter(node => node.tagName === "LABEL" || node.tagName === "label");
  const filterDeployAgents = () => {
    const query = C.id("deployAgentSearch").value.trim().toLowerCase();
    for (const label of deployLabels()) label.hidden = Boolean(query) && !String(label.textContent).toLowerCase().includes(query);
  };
  const renderDeploySelection = () => {
    const groups = C.checked("deployGroups"), agents = C.checked("deployAgents"), union = new Set(agents);
    for (const group of C.state.groups) if (groups.includes(group.id)) for (const agent of C.array(group.agent_ids)) union.add(agent);
    C.text("deploySelectionCount", groups.length || agents.length
      ? `그룹 ${groups.length}개 · 개별 ${agents.length}대 선택 → 대상 ${union.size}대 (중복 제외)`
      : "그룹 또는 에이전트를 선택하세요. 그룹과 개별 선택의 합집합에 배포합니다.");
  };
  const setDeployAgents = (ids, checked) => {
    const wanted = new Set(ids);
    for (const label of deployLabels()) {
      const input = label.querySelector?.("input");
      if (input && (!ids || wanted.has(input.value))) input.checked = checked;
    }
    invalidatePreview(); renderDeploySelection();
  };
  C.startDeployment = ({templateID = "", agentIDs = null} = {}) => {
    C.showPolicyPane?.("Deployment");
    if (templateID) C.id("deployTemplate").value = templateID;
    if (agentIDs) {
      C.id("deployAgentSearch").value = ""; filterDeployAgents();
      setDeployAgents(null, false);
      for (const input of C.id("deployGroups").querySelectorAll?.("input") || []) input.checked = false;
      setDeployAgents(agentIDs, true);
    }
    invalidatePreview(); renderDeploySummary(); renderDeploySelection();
    C.id("deployHeading").scrollIntoView?.({block:"start"}); C.id("deployHeading").focus?.({preventScroll:true});
  };
  const deployFromEditor = () => {
    if (!P.saved) return;
    if (P.dirty) { C.error("저장하지 않은 변경 사항이 있습니다. 정책을 저장한 뒤 배포하세요. 배포는 마지막 저장 버전을 사용합니다."); return; }
    C.startDeployment({templateID: P.saved.id});
  };
  const showPreview = (preview, template) => {
    const targets = C.array(preview.targets);
    const settings = C.object(template.settings), response = C.object(settings.response), detection = C.object(settings.detection);
    // Validate exact coverage before assigning the token or enabling confirmation.
    const allListening = settings.service_scope === "all_listening";
    const resolvedServices = allListening ? C.serviceTargetPreview(preview.service_targets, targets) : null;
    P.preview = preview; C.id("deploymentPreview").hidden = false;
    C.id("deployConfirm").checked = false; C.id("deployButton").disabled = true;
    C.text("previewTargetCount", `${targets.length}대`);
    const onlyDetection = response.mode !== "observe" && detection.extended_process_rules;
    const responseSummary = onlyDetection ? "대응 대상 규칙 0개" : modes[response.mode];
    const notes = [C.el("p", "notice warning", `전체 정책 교체: '${template.name}' v${template.version} · ${responseSummary}. 기존 서버의 서비스·탐지 예외 목록은 자동으로 합쳐지지 않습니다.`)];
    if (response.mode === "enforce" && !onlyDetection) notes.push(C.el("p", "notice error", "자동 종료 정책입니다. 실제 서비스 프로세스가 종료될 수 있으므로 대상과 예외를 확인하세요. 에이전트 로컬 종료 허용이 별도로 필요합니다."));
    const warningCount = targets.filter(target => C.array(target.warnings).length).length;
    if (warningCount) notes.push(C.el("p", "inline-note", `확인 사항이 있는 에이전트 ${warningCount}대 · 아래 대상별 내용을 확인하세요.`));
    if (C.array(preview.pending_features).includes("integrity")) notes.push(C.el("p", "notice warning", "추가 무결성 설정(TPM·임의 경로·강제 검증)은 향후 적용을 위해 중앙 초안으로 보관합니다."));
    const apps = C.array(settings.applications);
    if (apps.length && C.appProjectionTable) notes.push(C.el("p", "panel-note", "이번에 발행할 전체 서비스 연결입니다. 목록에서 빠진 기존 서비스는 호스트 기본 정책을 사용합니다."), C.appProjectionTable(apps, "이 배포에 포함되는 서비스별 정책"));
    if (resolvedServices) notes.push(resolvedServices);
    const full = C.el("details","technical"), monitoring = C.object(settings.monitoring), integrity = C.object(settings.integrity);
    full.append(C.el("summary","","배포할 정책 전체 설정"),C.facts([
      ["탐지 / 확장 규칙",`${detection.enabled?"사용":"사용 안 함"} / ${detection.extended_process_rules?"사용":"사용 안 함"}`],
      ["웹 서비스 대상",allListening ? "발견된 모든 서비스 · 대상별 웹 서비스 확인" : `${C.policyScopeLabel(settings.service_scope)} · ${C.array(detection.web_services).length}개 · ${C.array(detection.web_services).join(" · ") || "명시 서비스 없음"}`],
      ["웹 실행 파일",C.array(detection.web_executables).join(" · ") || "명시 실행 파일 없음"],
      ["서비스별 파일·TCP 범위", C.serviceScopeSummary(detection)],
      ["서비스별 규칙", C.array(detection.service_rule_controls).map(c => [c.service,c.rule_id,c.mode,c.reason,c.expires_at].filter(Boolean).join(" · ")).join("\n") || "프로필 기본값"],
      ["전역 root·권한 변경 탐지",detection.privilege_rules?`사용 · ${detection.root_exec_alerts==="all"?"모든 root 실행 경보":"의심 문맥만 경보"} · 자동 종료 대상 아님`:"사용 안 함"],
      ["탐지 셸",C.array(detection.shells).join(" · ")||"없음"],["탐지 예외",C.array(detection.allowed_pairs).join(" · ")||"없음"],
      ["대응 동작",response.action==="terminate"?"프로세스 종료":"동작 없음"],["위험 점수 / 신뢰도",`${response.risk_threshold} / ${response.min_confidence}`],["필수 기능 조건",capabilitySummary(response.required_capabilities)],
      ["자원 모니터링",`${monitoring.enabled?"사용":"사용 안 함"} · ${monitoring.sample_interval_seconds}초 간격 · 프로세스 ${monitoring.process_limit}개`],
      ["에이전트 제거 정책",{allow:"허용 · 일회용 승인 필요",approval_required:"중앙 승인 필요",deny:"일반 제거 금지"}[settings.uninstall_mode] || "미확인"],
      ["정책 유효 기간",`${settings.validity_hours}시간`],["패키지 파일 검사",integrity.package_files?"사용":"사용 안 함"],["추가 무결성 초안",integrity.enabled?"활성 초안 · 에이전트 적용 대기":"사용 안 함"]
    ]),C.raw({detection, response, monitoring, uninstall_mode:settings.uninstall_mode, validity_hours:settings.validity_hours},"서명 정책 생성에 쓰는 설정 JSON"));
    notes.push(full);
    C.id("previewWarnings").replaceChildren(...notes);
    const changes = C.policyChanges?.(preview.current_policies, template);
    C.id("previewChanges").replaceChildren(...(changes ? [changes] : []));
    const rows = targets.map(target => {
      const warnings = C.array(target.warnings);
      const list = C.el("ul", "compact-list");
      for (const warning of warnings) list.append(C.el("li", "", warning));
      return [target.agent_id, `${target.current_revision} → ${target.next_revision}`, target.enrollment_id, warnings.length ? list : "—"];
    });
    C.id("previewTargets").replaceChildren(C.table("배포 대상과 정책 리비전 변경", ["에이전트", "현재 → 다음 리비전", "현재 등록 ID", "확인 사항"], rows));
    if (allListening) C.id("trialStart").replaceChildren(C.el("p", "panel-note", "발견 범위는 일반 배포에서 서버 한 대를 먼저 선택해 확인할 수 있습니다."));
    else if (apps.length) C.id("trialStart").replaceChildren(C.el("p", "panel-note", "서비스 정책은 호스트 한 대에 먼저 배포해 적용 리비전과 서비스 귀속을 확인할 수 있습니다. 오프라인 표본 비교는 서비스별 정책을 지원하지 않습니다."));
    else C.policyTrialStart?.(preview);
    C.id("deploymentPreview").scrollIntoView({behavior:"instant",block:"nearest"});
  };
  const previewDeploy = event => {
    event.preventDefault();
    C.run(event.submitter, async () => {
      const templateID = C.id("deployTemplate").value, template = C.state.templates.find(t => t.id === templateID);
      if (!template) throw new Error("배포할 정책을 선택하세요.");
      if (P.dirty && templateID === P.saved?.id) throw new Error("선택한 정책의 편집 내용을 먼저 저장하세요. 배포는 마지막 저장 버전을 사용합니다.");
      const agentIDs = C.checked("deployAgents"), groupIDs = C.checked("deployGroups");
      if (!agentIDs.length && !groupIDs.length) throw new Error("배포할 그룹 또는 에이전트를 선택하세요.");
      invalidatePreview(); const generation = P.selectionRevision;
      const preview = await C.request("/api/deploy/preview",{method:"POST",body:{template_id:templateID,agent_ids:agentIDs,group_ids:groupIDs}});
      if (generation !== P.selectionRevision) throw new Error("미리보기 중 대상 또는 설정이 바뀌었습니다. 다시 미리보기하세요.");
      const snapshot = C.previewSnapshot(preview, templateID);
      showPreview(preview, snapshot); C.notify("배포 미리보기를 생성했습니다. 변경 사항과 대상을 확인한 후 배포를 확정하세요.");
    });
  };
  const deploy = async () => {
    await C.run(C.id("deployButton"), async () => {
      if (!P.preview || !C.id("deployConfirm").checked) return;
      const preview = P.preview;
      try {
        const result = await C.request("/api/deploy",{method:"POST",body:{preview_token:preview.preview_token,confirm:true}});
        invalidatePreview(); await C.refresh(); C.notify(`${C.array(result.targets).length}대의 목표 정책을 배포했습니다. 적용 결과는 적용 현황 탭에서 확인하세요.`);
      } catch (error) { invalidatePreview(); throw error; }
    });
    C.id("deployButton").disabled = !P.preview || !C.id("deployConfirm").checked;
  };

  C.editTemplateFromPolicy = async (policy, desired) => {
    if (!await canDiscard()) return;
    fillTemplate(null); fillSettings(C.settingsFromPolicy(policy, desired));
    setValue("templateName", `${policy.agent_id} 정책 복사`); setValue("templateDescription", `${policy.agent_id}의 중앙 지정 정책 ${policy.policy_id} 리비전 ${policy.revision}에서 복사`);
    setDirty(true, "basics"); renderHeader(); C.showPolicyPane?.("Catalog"); showSection("basics"); globalThis.location.hash = "policies";
    if(C.navigate)C.navigate();
    C.notify(`'${policy.agent_id}' 정책을 새 정책 편집기에 복사했습니다. 서비스 목록·예외·대응 설정을 보존했습니다. 새 ID를 입력해 저장하세요.`);
    C.id("templateID").focus();
  };
  C.initPolicy = () => {
    initCapabilityEditor();
    C.applicationBindings?.init(() => changed("services"));
    C.policyServices?.init(() => changed("services"));
    C.policyInventory?.init(() => changed("detection"));
    C.initAppliedPolicies?.();
    C.initPolicyUsage?.();
    for (const key of sections) C.id(`policySectionTab-${key}`).addEventListener("click", () => showSection(key));
    for (const radio of modeRadios()) radio.addEventListener("input", () => { C.id("responseMode").value = radio.value; });
    C.id("templateSearch").addEventListener("input", renderLists);
    C.id("templateFilter").addEventListener("change", renderLists);
    C.id("newTemplate").addEventListener("click", async () => { if (await canDiscard()) { fillTemplate(null); C.id("templateID").focus(); } });
    C.id("templateForm").addEventListener("submit",saveTemplate);
    C.id("templateForm").addEventListener("input",event => {
      if (["policyServiceScope", "policyInventoryAgent"].includes(event?.target?.id)) return;
      const section = event?.target?.closest?.(".policy-section")?.id?.replace("policySection-", "");
      changed(sections.includes(section) ? section : undefined);
      if (event?.target?.id === "templateName" && !P.saved) renderHeader();
    });
    C.id("policyServiceScope").addEventListener("change", () => { changed("detection"); C.policyInventory?.render(); C.policyServices?.refreshNameHints(); });
    C.id("webServices").addEventListener("input", () => C.policyInventory?.render());
    C.id("deleteTemplate").addEventListener("click",deleteTemplate);
    C.id("duplicateTemplate").addEventListener("click",duplicateTemplate);
    C.id("revertTemplate").addEventListener("click",revertTemplate);
    C.id("deployFromEditor").addEventListener("click",deployFromEditor);
    C.initPolicyTrials?.();
    C.id("previewForm").addEventListener("submit",previewDeploy);
    C.id("previewForm").addEventListener("change",() => { invalidatePreview(); renderDeploySelection(); renderDeploySummary(); });
    C.id("deployAgentSearch").addEventListener("input",filterDeployAgents);
    C.id("deploySelectVisible").addEventListener("click",() => setDeployAgents(deployLabels().filter(label => !label.hidden).map(label => label.querySelector?.("input")?.value).filter(Boolean), true));
    C.id("deployClearAgents").addEventListener("click",() => setDeployAgents(null, false));
    C.id("deployConfirm").addEventListener("change",() => { C.id("deployButton").disabled = !C.id("deployConfirm").checked || !P.preview; });
    C.id("deployButton").addEventListener("click",deploy);
    C.id("cancelPreview").addEventListener("click",invalidatePreview);
    C.onState(() => {
      if (!P.initialized) { P.initialized = true; fillTemplate(C.state.templates[0] || null); }
      renderLists(); renderHeader(); renderOverview(); C.applicationBindings?.render();
      C.policyInventory?.syncAgents();
    });
    C.hasUnsavedPolicy = () => P.dirty;
  };
})(globalThis.XEC);
