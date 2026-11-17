"use strict";

(function (C) {
  const P = {initialized: false, dirty: false, preview: null, selectionRevision: 0};
  const fields = ["detectionEnabled","extendedRules","webExecutables","webServices","shells","allowedPairs","responseMode","responseAction","riskThreshold","minConfidence","requiredCapabilities","monitoringEnabled","sampleInterval","processLimit","uninstallMode","validityHours","integrityEnabled","integrityTPM","integrityMode","integrityPaths"];
  const setValue = (id, value) => { const field = C.id(id); if (field.type === "checkbox") field.checked = Boolean(value); else field.value = value ?? ""; };
  const listValue = value => C.array(value).join("\n");
  const setDirty = dirty => { P.dirty = dirty; C.text("templateDirty", dirty ? "저장하지 않은 변경 사항" : "저장 상태와 일치"); };
  const responseHelp = () => {
    const mode = C.id("responseMode").value;
    C.text("responseHelp", mode === "enforce" ? "자동 종료는 서비스에 영향을 줄 수 있습니다. 위험 점수·신뢰도·필수 기능과 에이전트 로컬 종료 허용을 모두 만족해야 실행됩니다." : mode === "would_block" ? "실제 프로세스를 종료하지 않고 대응 조건 충족 여부를 기록합니다. 종료 동작·기능 조건·임계값을 명시하세요." : "탐지 결과를 기록하며 프로세스를 종료하지 않습니다.");
  };
  const invalidatePreview = () => {
    P.selectionRevision++; P.preview = null;
    C.id("deploymentPreview").hidden = true; C.id("deployConfirm").checked = false; C.id("deployButton").disabled = true;
  };
  const canDiscard = async () => !P.dirty || await C.confirm({title:"편집 내용 버리기",description:"저장하지 않은 템플릿 변경 사항이 있습니다. 다른 템플릿을 열면 현재 편집 내용이 사라집니다.",accept:"편집 내용 버리기"});
  const fillSettings = settings => {
    const d = C.object(settings.detection), r = C.object(settings.response), m = C.object(settings.monitoring), i = C.object(settings.integrity);
    const values = {detectionEnabled:d.enabled,extendedRules:d.extended_process_rules,webExecutables:listValue(d.web_executables),webServices:listValue(d.web_services),shells:listValue(d.shells),allowedPairs:listValue(d.allowed_pairs),responseMode:r.mode,responseAction:r.action,riskThreshold:r.risk_threshold,minConfidence:r.min_confidence,requiredCapabilities:listValue(r.required_capabilities),monitoringEnabled:m.enabled,sampleInterval:m.sample_interval_seconds,processLimit:m.process_limit,uninstallMode:settings.uninstall_mode,validityHours:settings.validity_hours,integrityEnabled:i.enabled,integrityTPM:i.require_tpm,integrityMode:i.mode || "observe",integrityPaths:listValue(i.paths)};
    for (const id of fields) setValue(id, values[id]); responseHelp();
  };
  const fillTemplate = template => {
    const t = template || {id:"",name:"",description:"",version:0,settings:C.state.defaults};
    setValue("templateID",t.id); setValue("templateName",t.name); setValue("templateDescription",t.description); setValue("templateVersionInput",t.version);
    C.id("templateID").readOnly = t.version > 0; C.id("deleteTemplate").disabled = !(t.version > 0);
    C.text("templateEditorTitle", t.version > 0 ? "템플릿 편집" : "템플릿 만들기"); C.text("templateVersion", t.version > 0 ? `버전 ${t.version}` : "새 템플릿");
    fillSettings(C.object(t.settings)); setDirty(false); invalidatePreview(); renderLists();
  };
  const readSettings = () => {
    const values = {};
    for (const id of fields) values[id] = C.id(id).type === "checkbox" ? C.id(id).checked : C.id(id).value;
    return C.validateSettings(C.settingsFromValues(values));
  };
  const renderLists = () => {
    const selected = C.id("templateID").value;
    C.id("templateList").replaceChildren(...(C.state.templates.length ? C.state.templates.map(template => {
      const button = C.button("", async () => { if (await canDiscard()) fillTemplate(template); }, `select-item${selected === template.id ? " selected" : ""}`);
      button.append(C.el("strong", "", template.name), C.el("small", "", `${template.id} · 버전 ${template.version}`));
      if (C.object(C.object(template.settings).integrity).enabled) button.append(C.tag("무결성 초안 포함", "pending")); return button;
    }) : [C.empty("저장된 템플릿이 없습니다.")]));
    C.options("deployTemplate", C.state.templates.map(t => [t.id,`${t.name} · ${t.id} · v${t.version}`]), "템플릿을 선택하세요");
    C.choices("deployGroups", C.state.groups.map(g => [g.id,g.name,`${C.array(g.agent_ids).length}대`]), "deployGroup", "저장된 서버 그룹이 없습니다.");
    C.choices("deployAgents", C.state.agents.filter(a => !a.revoked).map(a => [a.agent_id,a.agent_id,a.hostname || "호스트명 보고 없음"]), "deployAgent", "배포 가능한 에이전트가 없습니다.");
  };
  const saveTemplate = event => {
    event.preventDefault();
    C.run(event.submitter, async () => {
      const request = {id:C.id("templateID").value.trim(),name:C.id("templateName").value.trim(),description:C.id("templateDescription").value.trim(),version:Number(C.id("templateVersionInput").value),settings:readSettings()};
      const saved = await C.request("/api/templates", {method:"POST",body:request});
      fillTemplate(saved); await C.refresh(); C.notify(`정책 템플릿 '${saved.name}'을 저장했습니다. 서버에는 아직 배포하지 않았습니다.`);
    });
  };
  const deleteTemplate = async () => {
    await C.run(C.id("deleteTemplate"), async () => {
    const id = C.id("templateID").value, version = Number(C.id("templateVersionInput").value);
    if (!version || !await C.confirm({title:"정책 템플릿 삭제",description:`'${C.id("templateName").value}' 템플릿을 삭제합니다. 이미 지정된 서버 정책은 유지됩니다.`,accept:"템플릿 삭제"})) return;
    await C.request(`/api/templates/${encodeURIComponent(id)}?version=${version}`,{method:"DELETE"});
    fillTemplate(null); await C.refresh(); C.notify("정책 템플릿을 삭제했습니다.");
    });
    C.id("deleteTemplate").disabled = Number(C.id("templateVersionInput").value) <= 0;
  };
  const showPreview = (preview, template) => {
    P.preview = preview; C.id("deploymentPreview").hidden = false;
    C.id("deployConfirm").checked = false; C.id("deployButton").disabled = true;
    C.text("previewTargetCount", `${C.array(preview.targets).length}대`);
    const settings = C.object(template.settings), response = C.object(settings.response), detection = C.object(settings.detection);
    const modes = {observe:"탐지 전용",would_block:"모의 대응",enforce:"자동 종료"};
    const notes = [C.el("p", "notice warning", `전체 정책 교체: '${template.name}' v${template.version} · ${modes[response.mode] || response.mode}. 기존 서버의 서비스·탐지 예외 목록은 자동으로 합쳐지지 않습니다.`), C.facts([["웹 서비스 대상",`${C.array(detection.web_services).length}개 · ${C.array(detection.web_services).join(" · ") || "명시 서비스 없음"}`],["웹 실행 파일",C.array(detection.web_executables).join(" · ") || "명시 실행 파일 없음"],["위험 점수 / 신뢰도",`${response.risk_threshold} / ${response.min_confidence}`],["에이전트 제거 정책",{allow:"허용",approval_required:"중앙 승인 필요",deny:"일반 제거 금지"}[settings.uninstall_mode] || "미확인"]])];
    const full = C.el("details","technical"), monitoring = C.object(settings.monitoring), integrity = C.object(settings.integrity);
    full.append(C.el("summary","","탐지 범위·대응 조건·모니터링 전체 확인"),C.facts([
      ["탐지 / 확장 규칙",`${detection.enabled?"사용":"사용 안 함"} / ${detection.extended_process_rules?"사용":"사용 안 함"}`],
      ["탐지 셸",C.array(detection.shells).join(" · ")||"없음"],["탐지 예외",C.array(detection.allowed_pairs).join(" · ")||"없음"],
      ["대응 동작",response.action==="terminate"?"프로세스 종료":"동작 없음"],["필수 기능 조건",C.array(response.required_capabilities).join(" · ")||"명시 조건 없음"],
      ["자원 모니터링",`${monitoring.enabled?"사용":"사용 안 함"} · ${monitoring.sample_interval_seconds}초 간격 · 프로세스 ${monitoring.process_limit}개`],
      ["정책 유효 기간",`${settings.validity_hours}시간`],["무결성 초안",integrity.enabled?"활성 초안 · 에이전트 적용 대기":"사용 안 함"]
    ]),C.raw(settings,"배포할 설정 JSON 보기"));
    notes.push(full);
    if (C.array(preview.pending_features).includes("integrity")) notes.push(C.el("p", "notice warning", "적용 대기: 무결성 검증은 중앙 초안에만 보존됩니다. 이번 배포에서 에이전트에 적용되지 않습니다."));
    for (const target of C.array(preview.targets)) for (const warning of C.array(target.warnings)) notes.push(C.el("p", "inline-note", `${target.agent_id}: ${warning}`));
    if (response.mode === "enforce") notes.push(C.el("p", "notice error", "자동 종료 정책입니다. 실제 서비스 프로세스가 종료될 수 있으므로 대상과 예외를 확인하세요. 에이전트 로컬 종료 허용이 별도로 필요합니다."));
    C.id("previewWarnings").replaceChildren(...notes);
    C.id("previewTargets").replaceChildren(C.table("배포 대상과 정책 리비전 변경",["에이전트","현재 → 다음 리비전","현재 등록 ID"],C.array(preview.targets).map(t=>[t.agent_id,`${t.current_revision} → ${t.next_revision}`,t.enrollment_id])));
    C.id("deploymentPreview").scrollIntoView({behavior:"instant",block:"nearest"});
  };
  const previewDeploy = event => {
    event.preventDefault();
    C.run(event.submitter, async () => {
      const templateID = C.id("deployTemplate").value, template = C.state.templates.find(t => t.id === templateID);
      if (!template) throw new Error("저장된 정책 템플릿을 선택하세요.");
      if (P.dirty && templateID === C.id("templateID").value) throw new Error("선택한 템플릿의 편집 내용을 먼저 저장하세요. 배포는 마지막 저장 버전을 사용합니다.");
      const agentIDs = C.checked("deployAgents"), groupIDs = C.checked("deployGroups");
      if (!agentIDs.length && !groupIDs.length) throw new Error("배포할 그룹 또는 에이전트를 선택하세요.");
      invalidatePreview(); const generation = P.selectionRevision;
      const preview = await C.request("/api/deploy/preview",{method:"POST",body:{template_id:templateID,agent_ids:agentIDs,group_ids:groupIDs}});
      if (generation !== P.selectionRevision) throw new Error("미리보기 중 대상 또는 설정이 바뀌었습니다. 다시 미리보기하세요.");
      const snapshot = C.previewSnapshot(preview, templateID);
      showPreview(preview, snapshot); C.notify("배포 미리보기를 생성했습니다. 대상과 전체 교체 내용을 확인한 후 배포를 확정하세요.");
    });
  };
  const deploy = async () => {
    await C.run(C.id("deployButton"), async () => {
    if (!P.preview || !C.id("deployConfirm").checked) return;
    const preview = P.preview;
    try {
      const result = await C.request("/api/deploy",{method:"POST",body:{preview_token:preview.preview_token,confirm:true}});
      invalidatePreview(); await C.refresh(); C.notify(`${C.array(result.targets).length}대의 목표 정책을 배포했습니다. 적용 완료 여부는 에이전트의 다음 보고에서 확인하세요.`);
    } catch (error) { invalidatePreview(); throw error; }
    });
    C.id("deployButton").disabled = !P.preview || !C.id("deployConfirm").checked;
  };
  C.editTemplateFromPolicy = async (policy, desired) => {
    if (!await canDiscard()) return;
    fillTemplate(null); fillSettings(C.settingsFromPolicy(policy, desired));
    setValue("templateName", `${policy.agent_id} 정책 복사`); setValue("templateDescription", `${policy.agent_id}의 중앙 지정 정책 ${policy.policy_id} 리비전 ${policy.revision}에서 복사`);
    setDirty(true); globalThis.location.hash = "policies";
    if(C.navigate)C.navigate();
    C.notify(`'${policy.agent_id}' 정책을 새 템플릿 편집기에 복사했습니다. 서비스 목록·예외·대응 설정을 보존했습니다. 새 ID를 입력해 저장하세요.`);
    C.id("templateID").focus();
  };
  C.initPolicy = () => {
    C.id("newTemplate").addEventListener("click", async () => { if (await canDiscard()) { fillTemplate(null); C.id("templateID").focus(); } });
    C.id("templateForm").addEventListener("submit",saveTemplate);
    C.id("templateForm").addEventListener("input",() => { setDirty(true); invalidatePreview(); responseHelp(); });
    C.id("deleteTemplate").addEventListener("click",deleteTemplate);
    C.id("previewForm").addEventListener("submit",previewDeploy);
    C.id("previewForm").addEventListener("change",invalidatePreview);
    C.id("deployConfirm").addEventListener("change",() => { C.id("deployButton").disabled = !C.id("deployConfirm").checked || !P.preview; });
    C.id("deployButton").addEventListener("click",deploy);
    C.id("cancelPreview").addEventListener("click",invalidatePreview);
    C.onState(() => { if (!P.initialized) { P.initialized = true; fillTemplate(null); } renderLists(); });
    C.hasUnsavedPolicy = () => P.dirty;
  };
})(globalThis.XEC);
