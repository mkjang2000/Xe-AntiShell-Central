"use strict";

(function (C) {
  const group = {initialized:false,dirty:false};
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
  const findingSummary = finding => finding.summary || finding.rule_id || "의심 행위 탐지";
  C.renderRecent = records => {
    const findings=records.flatMap(record=>C.findings(record).map(finding=>({record,finding}))).slice(0,5);
    C.id("recentFindings").replaceChildren(...(findings.length ? findings.map(({record,finding})=>{
      const row=C.el("div","list-row"),identity=C.el("div","identity");identity.append(C.el("strong","",findingSummary(finding)),C.el("small","",`${record.agent_id} · ${finding.origin_service||"서비스 미확인"} · ${C.time(finding.created_at||record.received_at)}`));
      row.append(identity,severity(finding.severity),C.button("이력",()=>{C.id("historyAgent").value=record.agent_id;C.id("historyKind").value="detections";globalThis.location.hash="history";C.loadHistory(true);},"mini-button"));return row;
    }):[C.empty("중앙에 보존된 탐지 기록이 없습니다.")]));
  };
  C.populateRemoval = () => {
    const agent=C.state.agents.find(a=>a.agent_id===C.id("removalAgent").value&&!a.revoked);C.id("removalEnrollment").value=agent?agent.enrollment_id:"";
    C.id("removalChallenge").value="";C.id("removalConfirm").checked=false;
  };
  const initApprovals = () => {
    C.id("enrollmentForm").addEventListener("submit",event=>{
      event.preventDefault();C.run(event.submitter,async()=>{
        const agentID=C.id("enrollmentAgent").value.trim();
        if(C.state.agents.some(a=>a.agent_id===agentID&&!a.revoked)&&!await C.confirm({title:"기존 에이전트의 새 등록 토큰",description:`'${agentID}'가 이미 등록되어 있습니다. 새 토큰으로 재등록하면 현재 등록이 교체되어 기존 인증서와 정책 연결에 영향을 줍니다.`,accept:"토큰 발급"}))return;
        const result=await C.request("/api/enrollment",{method:"POST",body:{agent_id:agentID,ttl_seconds:Number(C.id("enrollmentTTL").value)}});
        const complete=typeof result.installation_code==="string"&&result.installation_code.length>0;
        C.showSecret({title:complete?"설치 토큰 발급 완료":"기존 방식 등록 토큰 발급 완료",text:complete?result.installation_code:result.token,filename:`enrollment-${agentID}${complete?".xeas":".token"}`,type:"text/plain",facts:[["대상 에이전트",result.agent_id],["만료 시각",C.time(result.expires_at)],["사용 방법",complete?"대상 서버에서 install.sh를 실행하고 중앙 연결 단계에 설치 토큰을 붙여 넣으세요.":"기존 등록 방식에 사용하세요. 중앙 주소와 CA 인증서가 별도로 필요합니다."]]});C.notify("토큰을 발급했습니다. 비밀값은 발급 결과 창에서만 확인할 수 있습니다.");
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
    C.onState(()=>{
      const enrollment=C.object(C.state.enrollment),ready=enrollment.ready===true;
      C.text("enrollmentReadiness",ready?`중앙 연결 주소: ${enrollment.central_url}. 설치 토큰에 주소와 공개 CA 인증서가 함께 포함됩니다.`:"중앙 서버의 에이전트 접속 주소가 설정되지 않아 기존 방식 등록 토큰을 발급합니다. 중앙 주소와 CA 인증서는 별도로 전달하세요.");
      C.text("enrollmentSubmit",ready?"설치 토큰 발급":"기존 방식 등록 토큰 발급");
      if(!group.initialized){group.initialized=true;fillGroup(null);}else{renderGroupList();C.choices("groupMembers",memberOptions(),"member","등록된 에이전트가 없습니다.");}
      const agents=C.state.agents.filter(a=>!a.revoked).map(a=>[a.agent_id,`${a.agent_id}${a.hostname?` · ${a.hostname}`:""}`]);
      const prior=C.id("removalAgent").value,priorEnrollment=C.id("removalEnrollment").value;
      C.options("removalAgent",agents,"에이전트 선택");C.options("revokeAgent",agents,"에이전트 선택");
      const current=C.state.agents.find(a=>a.agent_id===C.id("removalAgent").value);
      if(prior!==C.id("removalAgent").value||current&&priorEnrollment!==current.enrollment_id)C.populateRemoval();
    });
    C.hasUnsavedGroup=()=>group.dirty;
  };
})(globalThis.XEC);
