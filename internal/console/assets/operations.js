"use strict";

(function (C) {
  const group = {initialized:false,dirty:false};
  const history = {items:[],cursors:[""],page:0,next:"",generation:0,loaded:false};
  const audit = {items:[],cursors:[""],page:0,next:"",generation:0,loaded:false};
  C.checked = id => [...C.id(id).querySelectorAll("input[type=checkbox]:checked")].map(input => input.value);
  C.options = (id, values, placeholder) => {
    const select = C.id(id), current = select.value, fragment = document.createDocumentFragment();
    const empty = C.el("option","",placeholder); empty.value = ""; fragment.append(empty);
    for (const [value,label] of values) { const option = C.el("option","",label); option.value = value; fragment.append(option); }
    select.replaceChildren(fragment); if (values.some(([value]) => value === current)) select.value = current;
  };
  C.choices = (id, values, prefix, empty, selected) => {
    const target = C.id(id), current = new Set(selected || C.checked(id));
    const focus = target.contains(document.activeElement) ? document.activeElement.value : null;
    const rows = values.map(([value,label,note],index) => {
      const row = C.el("label"), input = C.el("input"); input.type = "checkbox"; input.value = value; input.id = `${prefix}-${index}`; input.checked = current.has(value); row.htmlFor = input.id;
      const name = C.el("span","",label); if (note) name.append(C.el("small","",note)); row.append(input,name); return row;
    });
    target.replaceChildren(...(rows.length ? rows : [C.empty(empty)]));
    if (focus !== null) for (const input of target.querySelectorAll("input")) if (input.value === focus) { input.focus({preventScroll:true}); break; }
  };
  const groupDirty = dirty => { group.dirty = dirty; C.text("groupDirty",dirty ? "저장하지 않은 변경 사항" : ""); };
  const memberOptions = () => {
    const options = C.state.agents.map(a => [a.agent_id,a.agent_id,a.revoked ? "등록 해지" : a.hostname || "호스트명 보고 없음"]);
    for (const selected of C.checked("groupMembers")) if (!options.some(([id]) => id === selected)) options.push([selected,selected,"현재 목록에 없음"]);
    return options;
  };
  const fillGroup = value => {
    const g = value || {id:"",name:"",description:"",version:0,agent_ids:[]};
    C.id("groupID").value = g.id; C.id("groupID").readOnly = g.version > 0; C.id("groupName").value = g.name; C.id("groupDescription").value = g.description || ""; C.id("groupVersionInput").value = g.version;
    C.id("deleteGroup").disabled = !(g.version > 0); C.text("groupEditorTitle",g.version > 0 ? "그룹 편집" : "그룹 만들기"); C.text("groupVersion",g.version > 0 ? `버전 ${g.version}` : "새 그룹");
    const choices = C.state.agents.map(a=>[a.agent_id,a.agent_id,a.revoked ? "등록 해지" : a.hostname || ""]);
    for (const id of C.array(g.agent_ids)) if (!choices.some(([value]) => value === id)) choices.push([id,id,"현재 목록에 없음"]);
    C.choices("groupMembers",choices,"member","등록된 에이전트가 없습니다.",C.array(g.agent_ids)); groupDirty(false); renderGroupList();
  };
  const discardGroup = async () => !group.dirty || await C.confirm({title:"그룹 편집 내용 버리기",description:"저장하지 않은 그룹 변경 사항이 있습니다. 선택을 바꾸면 편집 내용이 사라집니다.",accept:"편집 내용 버리기"});
  const renderGroupList = () => {
    C.id("groupList").replaceChildren(...(C.state.groups.length ? C.state.groups.map(g => {
      const button = C.button("",async()=>{if(await discardGroup())fillGroup(g);},`select-item${C.id("groupID").value === g.id ? " selected" : ""}`);
      button.append(C.el("strong","",g.name),C.el("small","",`${g.id} · ${C.array(g.agent_ids).length}대 · v${g.version}`)); return button;
    }) : [C.empty("서버 그룹이 없습니다.")]));
  };
  const initGroups = () => {
    C.id("newGroup").addEventListener("click",async()=>{if(await discardGroup()){fillGroup(null);C.id("groupID").focus();}});
    C.id("groupForm").addEventListener("input",()=>groupDirty(true));
    C.id("groupForm").addEventListener("submit",event=>{
      event.preventDefault(); C.run(event.submitter,async()=>{
        const request={id:C.id("groupID").value.trim(),name:C.id("groupName").value.trim(),description:C.id("groupDescription").value.trim(),version:Number(C.id("groupVersionInput").value),agent_ids:C.checked("groupMembers")};
        const saved=await C.request("/api/groups",{method:"POST",body:request}); fillGroup(saved); await C.refresh(); C.notify(`'${saved.name}' 그룹을 저장했습니다. 정책은 배포하지 않았습니다.`);
      });
    });
    C.id("deleteGroup").addEventListener("click",async()=>{
      await C.run(C.id("deleteGroup"),async()=>{
      const id=C.id("groupID").value,version=Number(C.id("groupVersionInput").value);
      if(!version || !await C.confirm({title:"서버 그룹 삭제",description:`'${C.id("groupName").value}' 그룹을 삭제합니다. 서버 등록과 기존 정책은 유지됩니다.`,accept:"그룹 삭제"}))return;
      await C.request(`/api/groups/${encodeURIComponent(id)}?version=${version}`,{method:"DELETE"});fillGroup(null);await C.refresh();C.notify("서버 그룹을 삭제했습니다.");
      });
      C.id("deleteGroup").disabled=Number(C.id("groupVersionInput").value)<=0;
    });
  };
  const severity = value => {
    const names={critical:"매우 높음",high:"높음",medium:"보통",low:"낮음",info:"정보"};
    return C.tag(names[value]||"미분류",["critical","high"].includes(value)?"danger":value==="medium"?"warning":"neutral");
  };
  const responseLabel = value => ({observe:"탐지 전용",detection_only:"확장 탐지 전용",would_block:"모의 대응 대상",below_threshold:"대응 기준 미달",insufficient_capability:"기능 조건 미충족",terminate_pending:"종료 요청 준비",sigterm_sent:"종료 신호 전송",refused:"안전 조건 미충족",not_repeated:"재실행 생략"}[value]||"대응 보고 없음");
  const findingSummary = finding => finding.summary || finding.rule_id || "의심 행위 탐지";
  C.renderRecent = records => {
    const findings=records.flatMap(record=>C.findings(record).map(finding=>({record,finding}))).slice(0,5);
    C.id("recentFindings").replaceChildren(...(findings.length ? findings.map(({record,finding})=>{
      const row=C.el("div","list-row"),identity=C.el("div","identity");identity.append(C.el("strong","",findingSummary(finding)),C.el("small","",`${record.agent_id} · ${finding.origin_service||"서비스 미확인"} · ${C.time(finding.created_at||record.received_at)}`));
      row.append(identity,severity(finding.severity),C.button("이력",()=>{C.id("historyAgent").value=record.agent_id;C.id("historyKind").value="detections";globalThis.location.hash="history";C.loadHistory(true);},"mini-button"));return row;
    }):[C.empty("중앙에 보존된 탐지 기록이 없습니다.")]));
  };
  const recordCard = record => {
    const payload=C.object(record.payload),findings=C.findings(record),event=record.kind==="event_bundle"?C.object(payload.event):payload,process=C.object(event.process);
    const names={finding:"탐지",event:"실행 이력",event_bundle:"실행·탐지 묶음",audit:"에이전트 감사"};
    const card=C.el("article",`record${findings.length?" finding":""}`),head=C.el("div","record-head");
    const title=C.el("span","record-title",`${record.agent_id} · ${names[record.kind]||record.kind}`);head.append(title,C.el("time","",C.time(record.received_at)));card.append(head);
    if(findings.length){
      for(const finding of findings){
        const summary=C.el("p","record-summary");summary.append(severity(finding.severity),document.createTextNode(` ${findingSummary(finding)}`));card.append(summary);
        const meta=C.el("div","record-meta");meta.append(C.el("span","",`서비스: ${finding.origin_service||"미확인"}`),C.el("span","",`위험 점수: ${Number.isFinite(finding.risk_score)?finding.risk_score:"미확인"}`),C.el("span","",`신뢰도: ${Number.isFinite(finding.confidence)?finding.confidence:"미확인"}`),C.el("span","",responseLabel(finding.response_decision)));card.append(meta);
      }
    }else if(record.kind==="audit")card.append(C.el("p","record-summary",payload.action||payload.result||"에이전트 감사 기록"));
    else card.append(C.el("p","record-summary",`${process.exe||"실행 파일 미확인"} · ${process.origin_service||"서비스 미확인"}`));
    if(event.event_type){const meta=C.el("div","record-meta");meta.append(C.el("span","",`프로세스: ${process.exe||"미확인"}`),C.el("span","",`PID: ${process.pid??"미확인"}`),C.el("span","",`실행 시각: ${C.time(event.event_time)}`));card.append(meta);}
    card.append(C.raw(record,"보존된 기록 원문 보기"));return card;
  };
  const pager = (id,state,reload) => {
    const previous=C.button("이전",()=>{state.page--;reload(false);});previous.disabled=state.page===0;
    const next=C.button("다음",()=>{state.cursors[state.page+1]=state.next;state.page++;reload(false);});next.disabled=!state.next;
    C.id(id).replaceChildren(previous,C.el("span","",`${state.page+1}페이지 · ${state.items.length}개 수신`),next);
  };
  const renderHistory = () => {
    const search=C.id("historySearch").value.trim().toLowerCase();
    const items=history.items.filter(record=>!search||JSON.stringify(record).toLowerCase().includes(search));
    C.id("historyRows").replaceChildren(...(items.length?items.map(recordCard):[C.empty(search?"현재 페이지에서 검색 조건에 맞는 기록이 없습니다.":"조건에 맞는 기록이 없습니다.")]));
    C.text("historyScope",`중앙 보존 기록 · 수신 시각 역순 · 페이지당 최대 20개${search?` · 현재 페이지 검색 ${items.length}개`:""}. 기록 원문에서 탐지 근거와 실행 경로를 확인하세요.`);
    pager("historyPager",history,C.loadHistory);
  };
  C.loadHistory = async (reset = false) => {
    if(reset){history.page=0;history.cursors=[""];}
    const generation=++history.generation;
    const params=new URLSearchParams({limit:"20",agent_id:C.id("historyAgent").value,kind:C.id("historyKind").value});
    if(history.cursors[history.page])params.set("before",history.cursors[history.page]);
    C.id("historyRows").setAttribute("aria-busy","true");
    try{const result=await C.request(`/api/history?${params}`,{page:true});if(generation!==history.generation)return;history.items=result.items;history.next=result.next;history.loaded=true;renderHistory();}
    catch(error){if(generation===history.generation)C.error(error);}
    finally{if(generation===history.generation)C.id("historyRows").setAttribute("aria-busy","false");}
  };
  const auditName = kind => ({"agent.enrolled":"에이전트 등록","agent.revoked":"에이전트 등록 해지","policy.assigned":"정책 지정","removal.authorized":"제거 승인 발급","group.saved":"서버 그룹 저장","group.deleted":"서버 그룹 삭제","template.saved":"정책 템플릿 저장","template.deleted":"정책 템플릿 삭제","policy.deployed":"정책 배포","enrollment.issued":"등록 토큰 발급"}[String(kind||"").replace(/^console\./,"")]||"중앙 관리 작업");
  const renderAudit = () => {
    const search=C.id("auditSearch").value.trim().toLowerCase(),items=audit.items.filter(item=>!search||`${JSON.stringify(item)} ${auditName(item.kind)}`.toLowerCase().includes(search));
    C.id("auditRows").replaceChildren(...(items.length?items.map(item=>{
      const details=C.object(item.details),target=item.agent_id||details.template_id||details.group_id||details.id||"중앙 관리";
      const card=C.el("article","record"),head=C.el("div","record-head");head.append(C.el("span","record-title",auditName(item.kind)),C.el("time","",C.time(item.created_at)));card.append(head,C.el("p","record-summary",target));
      const meta=C.el("div","record-meta");
      for(const [label,key] of [["버전","version"],["템플릿 버전","template_version"],["정책 리비전","revision"],["대상 서버 수","target_count"],["그룹 서버 수","agent_count"]])if(details[key]!==undefined)meta.append(C.el("span","",`${label}: ${details[key]}`));
      if(C.array(details.pending_features).includes("integrity"))meta.append(C.tag("무결성 적용 대기","pending"));
      card.append(meta,C.raw(item,"감사 기록 상세 보기"));return card;
    }):[C.empty(search?"현재 페이지에서 일치하는 작업이 없습니다.":"중앙 감사 기록이 없습니다.")]));pager("auditPager",audit,C.loadAudit);
  };
  C.loadAudit = async (reset = false) => {
    if(reset){audit.page=0;audit.cursors=[""];}
    const generation=++audit.generation,params=new URLSearchParams({limit:"20"});if(audit.cursors[audit.page])params.set("before",audit.cursors[audit.page]);
    try{const result=await C.request(`/api/audit?${params}`,{page:true});if(generation!==audit.generation)return;audit.items=result.items;audit.next=result.next;audit.loaded=true;renderAudit();}catch(error){if(generation===audit.generation)C.error(error);}
  };
  C.populateRemoval = () => {
    const agent=C.state.agents.find(a=>a.agent_id===C.id("removalAgent").value&&!a.revoked);C.id("removalEnrollment").value=agent?agent.enrollment_id:"";
    C.id("removalChallenge").value="";C.id("removalConfirm").checked=false;
  };
  const initApprovals = () => {
    C.id("enrollmentForm").addEventListener("submit",event=>{
      event.preventDefault();C.run(event.submitter,async()=>{
        const agentID=C.id("enrollmentAgent").value.trim();
        if(C.state.agents.some(a=>a.agent_id===agentID&&!a.revoked)&&!await C.confirm({title:"기존 에이전트의 새 등록 토큰",description:`'${agentID}'가 이미 등록되어 있습니다. 새 토큰으로 재등록하면 현재 등록이 교체되어 기존 인증서와 정책 연결에 영향을 줍니다.`,accept:"등록 토큰 발급"}))return;
        const result=await C.request("/api/enrollment",{method:"POST",body:{agent_id:agentID,ttl_seconds:Number(C.id("enrollmentTTL").value)}});
        C.showSecret({title:"등록 토큰 발급 완료",text:result.token,filename:`enrollment-${agentID}.token`,type:"text/plain",facts:[["대상 에이전트",result.agent_id],["만료 시각",C.time(result.expires_at)]]});C.notify("등록 토큰을 발급했습니다. 비밀값은 발급 결과 창에서만 확인할 수 있습니다.");
      });
    });
    C.id("removalAgent").addEventListener("change",C.populateRemoval);
    C.id("removalForm").addEventListener("submit",event=>{
      event.preventDefault();C.run(event.submitter,async()=>{
        if(!C.id("removalConfirm").checked)throw new Error("대상과 제거 요청 확인에 체크하세요.");
        const agentID=C.id("removalAgent").value,enrollmentID=C.id("removalEnrollment").value;
        const request={agent_id:agentID,enrollment_id:enrollmentID,challenge:C.parseChallenge(C.id("removalChallenge").value,agentID,enrollmentID),ttl_seconds:Number(C.id("removalTTL").value)};
        const result=await C.request("/api/removal",{method:"POST",body:request}),grant=C.object(result.grant);
        C.showSecret({title:"일회용 제거 승인 발급 완료",text:JSON.stringify(result,null,2),filename:`removal-${request.agent_id}.json`,type:"application/json",facts:[["대상 에이전트",grant.agent_id||request.agent_id],["만료 시각",C.time(grant.expires_at)],["사용 방법","대상 서버에 승인 JSON을 전달하여 제거 요청에 사용"]]});
        C.id("removalChallenge").value="";C.id("removalConfirm").checked=false;C.notify("일회용 제거 승인을 발급했습니다. 발급만으로 서버의 에이전트가 제거되지는 않습니다.");
      });
    });
    C.id("revokeForm").addEventListener("submit",event=>{
      event.preventDefault();C.run(event.submitter,async()=>{
        const agentID=C.id("revokeAgent").value;
        if(!agentID||!await C.confirm({title:"에이전트 등록 해지",description:`'${agentID}'의 현재 인증서를 무효화하고 중앙 연결을 차단합니다. 다시 연결하려면 재등록이 필요합니다.`,accept:"등록 해지",match:agentID}))return;
        await C.request("/api/revoke",{method:"POST",body:{agent_id:agentID,confirm:true}});await C.refresh();C.notify(`'${agentID}'의 등록을 해지했습니다. 서버의 설치 파일은 제거하지 않았습니다.`);
      });
    });
  };
  C.initOperations = () => {
    initGroups();initApprovals();
    C.id("historyFilters").addEventListener("submit",event=>{event.preventDefault();C.loadHistory(true);});
    C.id("historySearch").addEventListener("input",renderHistory);
    C.id("refreshAudit").addEventListener("click",()=>C.run(C.id("refreshAudit"),()=>C.loadAudit(true)));
    C.id("auditSearch").addEventListener("input",renderAudit);
    C.onState(()=>{
      if(!group.initialized){group.initialized=true;fillGroup(null);}else{renderGroupList();C.choices("groupMembers",memberOptions(),"member","등록된 에이전트가 없습니다.");}
      const agents=C.state.agents.filter(a=>!a.revoked).map(a=>[a.agent_id,`${a.agent_id}${a.hostname?` · ${a.hostname}`:""}`]);
      C.options("historyAgent",C.state.agents.map(a=>[a.agent_id,a.agent_id]),"전체 에이전트");
      const prior=C.id("removalAgent").value,priorEnrollment=C.id("removalEnrollment").value;
      C.options("removalAgent",agents,"에이전트 선택");C.options("revokeAgent",agents,"에이전트 선택");
      const current=C.state.agents.find(a=>a.agent_id===C.id("removalAgent").value);
      if(prior!==C.id("removalAgent").value||current&&priorEnrollment!==current.enrollment_id)C.populateRemoval();
    });
    C.hasUnsavedGroup=()=>group.dirty;
  };
})(globalThis.XEC);
