"use strict";

(function (C) {
  const page = () => ({items:[],cursors:[""],page:0,next:"",generation:0,filter:""});
  const history=page(),audit=page();
  const titles={detections:"탐지 이력 · 의심 행위",events:"실행·수집 전체 이력",errors:"에이전트 오류 이력",agent_audit:"에이전트 감사 이력"};
  const transitions={occurred:"오류 발생",changed:"오류 변경",recovered:"복구 보고",baseline:"기존 오류 확인"};
  const categories={storage_order:"프로세스 관측 시각 순서 오류",storage:"저장소 읽기·저장 오류",parsing:"수집 데이터 해석 오류",policy_rejected:"정책 적용 거부",tls:"TLS 인증 오류",permission:"권한 오류",timeout:"처리 시간 초과",connection:"연결 오류",policy:"정책 처리 오류",collector:"수집기 동작 오류",runtime:"에이전트 실행 상태 오류"};
  const errorTypes={agent:"에이전트",collector:"수집기",policy:"정책 적용"};
  const explanations={storage_order:"수집 이벤트의 관측 시각 순서 때문에 저장이 거부된 상태 보고입니다.",storage:"이벤트 또는 운영 상태를 저장소에 읽거나 쓰는 과정에서 오류가 보고됐습니다.",parsing:"수집 데이터 형식 또는 해석 과정의 오류가 보고됐습니다.",policy_rejected:"에이전트가 정책을 수락하지 못했다고 보고했습니다.",tls:"연결 인증서 또는 TLS 검증 오류가 보고됐습니다.",collector:"프로세스 수집 스트림이 정상 동작하지 않는 상태 보고입니다."};
  const localInput = value => {
    const date=new Date(value);return new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16);
  };
  C.historyQuery = (values,cursor="") => {
    const params=new URLSearchParams({limit:"20",view:values.view,agent_id:values.agent.trim(),type:values.type.trim(),q:values.search.trim()});
    for(const key of ["from","until"]){if(!values[key])continue;const date=new Date(values[key]);if(!Number.isFinite(date.getTime()))throw new Error("조회 날짜·시간을 확인하세요.");params.set(key,date.toISOString());}
    if(values.from&&values.until&&Date.parse(values.from)>=Date.parse(values.until))throw new Error("종료 시각은 시작 시각보다 뒤여야 합니다.");
    if(cursor)params.set("before",cursor);return params;
  };
  const values = (prefix,view) => ({view,agent:C.id(prefix+"Agent").value,type:C.id(prefix+"Type").value,search:C.id(prefix+"Search").value,from:C.id(prefix+"From").value,until:C.id(prefix+"Until").value});
  const pager=(id,state,reload)=>{
    const previous=C.button("이전",()=>{state.page--;reload(false);});previous.disabled=state.page===0;
    const next=C.button("다음",()=>{state.cursors[state.page+1]=state.next;state.page++;reload(false);});next.disabled=!state.next;
    C.id(id).replaceChildren(previous,C.el("span","",`${state.page+1}페이지 · ${state.items.length}건`),next);
  };
  const severity=value=>C.tag(({critical:"매우 높음",high:"높음",medium:"보통",low:"낮음",info:"정보"})[value]||"미분류",["critical","high"].includes(value)?"danger":value==="medium"?"warning":"neutral");
  const recordCard=record=>{
    const payload=C.object(record.payload),process=C.object(payload.process),finding=record.kind==="finding";
    const card=C.el("article",`record${finding?" finding":""}`),head=C.el("div","record-head");
    head.append(C.el("strong","record-title",record.agent_id),C.el("time","",`중앙 수신 ${C.time(record.received_at)}`));card.append(head);
    if(finding){const copy=C.findingPresentation(payload),summary=C.el("p","record-summary");summary.append(severity(payload.severity),C.el("span","",` ${copy.title}`));card.append(summary,C.el("p","panel-note",copy.note),C.facts([["규칙",payload.rule_id],["탐지 시각",C.time(payload.created_at)],["관련 서비스",payload.origin_service],["위험 점수",`${C.value(payload.risk_score)} · 규칙 기여 점수이며 악성 확률이 아닙니다.`],["근거 이벤트",C.array(payload.evidence_event_ids).join(", ")],...(payload.detection_only===true?[["대응 범위","확장 탐지 전용 · 이 탐지는 자동 종료 대상에 포함되지 않습니다."]]:[])]));}
    else if(record.kind==="event"){
      const observation=C.eventObservation(payload);
      card.append(C.el("p","record-summary",`${process.exe||"실행 파일 미확인"} · ${C.eventLabel(payload.event_type)}`));
      if(observation.summary)card.append(C.el("p","panel-note",observation.summary));
      card.append(C.facts([["이벤트 시각",C.time(payload.event_time)],["서비스",process.origin_service],["PID",process.pid],["수집 소스",payload.source],...observation.fields]));
    }
    else card.append(C.el("p","record-summary",payload.kind||payload.action||payload.result||"에이전트 감사 기록"));
    card.append(C.raw(record,"중앙 보존 원문 보기"));return card;
  };
  const errorCard=item=>{
    const card=C.el("article","record"),head=C.el("div","record-head");
    head.append(C.el("strong","record-title",`${item.agent_id} · ${errorTypes[item.kind]||"오류"}`),C.tag(transitions[item.transition]||"상태 변경",item.transition==="recovered"?"good":"warning"));
    card.append(head,C.el("p","record-summary",`${categories[item.category]||"실행 상태"} · 중앙 기록 ${C.time(item.recorded_at)}`));
    card.append(C.el("p","panel-note",item.transition==="recovered"?"이전 오류가 다음 하트비트에 더 이상 보고되지 않았습니다. 현재 상세에서 최신 수집 상태를 확인하세요.":explanations[item.category]||"하트비트의 오류 상태가 변경됐습니다. 현재 상세에서 최신 진단을 확인하세요."));
    card.append(C.button("현재 에이전트 상세",()=>{if(C.selectAgent){C.selectAgent(item.agent_id);return;}C.selectedAgent=item.agent_id;globalThis.location.hash="agents";if(C.renderAgentDetail)C.renderAgentDetail(true);},"mini-button"));
    if(item.transition==="baseline")card.append(C.el("p","panel-note","업그레이드 시 최신 보고에서 확인한 기존 오류입니다. 최초 발생 시각은 알 수 없습니다."));
    return card;
  };
  const configure = () => {
    const view=C.id("historyKind").value;
    for(const name of Object.keys(titles))C.id("historyTab"+name).setAttribute("aria-pressed",String(name===view));
    C.text("historyTitle",titles[view]||titles.detections);
    C.id("historyType").placeholder=view==="events"?"전체 유형 · 예: process.exec":view==="errors"?"agent / collector / policy":view==="agent_audit"?"전체 감사 유형":"전체 규칙 · 규칙 ID";
    const types=view==="events"?["process.exec","process.exit","process.exec_observation","file.write","network.connect"]:view==="errors"?["agent","collector","policy"]:[];
    C.id("historyTypes").replaceChildren(...types.map(value=>{const option=C.el("option");option.value=value;if(view==="events")option.label=C.eventLabel(value);return option;}));
    C.text("historyScope",view==="events"?"중앙에 전달·보존된 실행·수집 이력을 탐지 여부와 관계없이 조회합니다. 실행 옵션·선택한 파일 쓰기·TCP 연결 요청을 포함하며 모든 실행·파일·통신이나 기존 프로세스 내부 코드 실행을 보장하지 않습니다. 조건은 서버 전체 조회에 적용되며 수신 시각 역순입니다.":view==="errors"?"하트비트에 보고된 오류의 발생·변경·복구 이력입니다. 동일 오류의 반복 보고는 쌓지 않으며, 원문 오류 메시지는 보존하지 않습니다. 이전 버전의 과거 오류 전체는 복원할 수 없습니다.":view==="agent_audit"?"에이전트가 중앙에 전달·보존한 감사 기록입니다. 중앙 관리자 활동은 별도 감사 기록에서 조회하세요.":"의심 행위로 탐지된 finding만 조회합니다. 실행 이력과 구분되며 침해 확정을 뜻하지 않습니다. 기간은 중앙 수신 시각에 적용됩니다.");
  };
  const load=async(prefix,state,view,endpoint,render,reset)=>{
    let params;
    try{params=C.historyQuery(values(prefix,view));}catch(error){state.generation++;state.items=[];state.next="";C.id(prefix+"Rows").replaceChildren(C.empty("조회 기간과 조건을 확인하세요."));pager(prefix+"Pager",state,prefix==="history"?C.loadHistory:C.loadAudit);C.error(error);return;}
    const filter=params.toString(),changed=filter!==state.filter;if(reset||changed){state.page=0;state.cursors=[""];state.filter=filter;}
    if(changed){state.items=[];state.next="";C.id(prefix+"Rows").replaceChildren(C.empty("조회 중입니다."));pager(prefix+"Pager",state,prefix==="history"?C.loadHistory:C.loadAudit);}
    if(state.cursors[state.page])params.set("before",state.cursors[state.page]);
    const generation=++state.generation;C.id(prefix+"Rows").setAttribute("aria-busy","true");
    try{const result=await C.request(`${endpoint}?${params}`,{page:true});if(generation!==state.generation)return;state.items=C.array(result.items);state.next=result.next;C.id(prefix+"Rows").replaceChildren(...(state.items.length?state.items.map(render):[C.empty("조건에 맞는 중앙 보존 기록이 없습니다.")]));pager(prefix+"Pager",state,prefix==="history"?C.loadHistory:C.loadAudit);}
    catch(error){if(generation===state.generation)C.error(error);}
    finally{if(generation===state.generation)C.id(prefix+"Rows").setAttribute("aria-busy","false");}
  };
  C.loadHistory=(reset=false)=>{configure();const view=C.id("historyKind").value;return load("history",history,view,view==="errors"?"/api/errors":"/api/history",view==="errors"?errorCard:recordCard,reset);};
  C.loadAudit=(reset=false)=>load("audit",audit,"audit","/api/audit",item=>{const card=C.el("article","record"),head=C.el("div","record-head");head.append(C.el("strong","record-title",item.kind),C.el("time","",C.time(item.created_at)));card.append(head,C.el("p","record-summary",item.agent_id||"중앙 전체"),C.raw(item.details,"관리 작업 상세"));return card;},reset);
  C.initHistory=()=>{
    const period=()=>{const value=C.id("historyPeriod").value;if(value==="custom")return;const now=C.now(),start=value==="today"?new Date(new Date(now).setHours(0,0,0,0)).getTime():now-({"24h":86400000,"7d":604800000,"30d":2592000000}[value]||0);C.id("historyFrom").value=value==="all"?"":localInput(start);C.id("historyUntil").value="";};
    C.id("historyPeriod").addEventListener("change",period);period();
    for(const id of ["historyFrom","historyUntil"])C.id(id).addEventListener("change",()=>{C.id("historyPeriod").value="custom";});
    C.id("historyKind").addEventListener("change",()=>{C.id("historyType").value="";C.loadHistory(true);});
    for(const view of Object.keys(titles))C.id("historyTab"+view).addEventListener("click",()=>{C.id("historyKind").value=view;C.id("historyType").value="";C.id("historySearch").value="";C.loadHistory(true);});
    for(const prefix of ["history","audit"])C.id(prefix+"Filters").addEventListener("submit",event=>{event.preventDefault();prefix==="history"?C.loadHistory(true):C.loadAudit(true);});
    C.id("refreshAudit").addEventListener("click",()=>C.loadAudit(true));
    C.listeners.push(()=>{C.id("historyAgents").replaceChildren(...C.state.agents.map(agent=>{const option=C.el("option");option.value=agent.agent_id;return option;}));});configure();
  };
})(globalThis.XEC);
