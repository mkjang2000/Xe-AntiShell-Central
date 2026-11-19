"use strict";

(function () {
  if (document.body.dataset.page === "login") {
    const messages = {invalid:"사용자 이름 또는 비밀번호가 올바르지 않습니다.",rate:"로그인 시도가 많습니다. 잠시 후 다시 시도하세요.",origin:"로그인 요청 출처를 확인할 수 없습니다. 이 페이지에서 다시 로그인하세요.",request:"로그인 요청 형식이 올바르지 않습니다. 입력값을 확인하세요."};
    const code = new URLSearchParams(location.search).get("error");
    if (code) { const error = document.getElementById("loginError"); error.textContent = Object.hasOwn(messages,code) ? messages[code] : "로그인하지 못했습니다. 다시 시도하세요."; error.hidden = false; }
    return;
  }
  const C = globalThis.XEC;
  const pages = {
    overview:["운영 현황","FLEET OVERVIEW","에이전트 연결, 정책 적용과 최근 보안 활동을 확인합니다."],
    agents:["에이전트","AGENT FLEET","서버별 하트비트와 자원, 수집 기능·정책 상태를 확인합니다."],
    groups:["서버 그룹","SERVER GROUPS","서버를 운영 단위로 묶어 정책 배포 대상을 관리합니다."],
    policies:["보안 정책","POLICY CONTROL","호스트 기본 정책과 서비스별 정책을 구성하고 에이전트의 적용 보고를 확인합니다."],
    history:["탐지·실행 이력","DETECTION & HISTORY","중앙에 전달된 탐지 근거와 실행 기록을 검토합니다."],
    approvals:["등록·제거 승인","ENROLLMENT & APPROVALS","단일 서버 설치 토큰과 일회용 제거 승인을 발급합니다."],
    updates:["업데이트","UPDATES","센트럴과 에이전트의 설치 상태를 확인하고 업데이트를 진행합니다."],
    audit:["감사 기록","OPERATOR AUDIT","기간별 중앙 관리 작업과 에이전트 감사 기록을 확인합니다."],
    accounts:["계정 관리","ACCOUNT MANAGEMENT","콘솔 계정과 권한을 관리하고 본인 비밀번호를 변경합니다."]
  };
  let refreshing = null, recentGeneration = 0, started = false;
  let confirmResolve = null, confirmMatch = "", secret = null;
  C.confirm = ({title,description,accept="확인",match=""}) => {
    if (confirmResolve) return Promise.resolve(false);
    C.text("confirmTitle",title);C.text("confirmDescription",description);C.text("confirmAccept",accept);
    confirmMatch = match; C.id("confirmInput").value=""; C.id("confirmInputWrap").hidden=!match;
    C.text("confirmInputLabel",match?`확인을 위해 '${match}'을(를) 입력하세요.`:"");
    C.id("confirmAccept").disabled=Boolean(match);C.id("confirmDialog").showModal();
    if(match)C.id("confirmInput").focus();else C.id("confirmCancel").focus();
    return new Promise(resolve=>{confirmResolve=resolve;});
  };
  const closeConfirm = result => {
    const resolve=confirmResolve;confirmResolve=null;C.id("confirmDialog").close();C.id("confirmInput").value="";confirmMatch="";if(resolve)resolve(result);
  };
  C.id("confirmInput").addEventListener("input",()=>{C.id("confirmAccept").disabled=C.id("confirmInput").value!==confirmMatch;});
  C.id("confirmAccept").addEventListener("click",()=>{if(!confirmMatch||C.id("confirmInput").value===confirmMatch)closeConfirm(true);});
  C.id("confirmCancel").addEventListener("click",()=>closeConfirm(false));C.id("confirmClose").addEventListener("click",()=>closeConfirm(false));
  C.id("confirmDialog").addEventListener("cancel",event=>{event.preventDefault();closeConfirm(false);});
  C.showSecret = value => {
    secret=value;C.text("secretTitle",value.title);C.id("secretValue").value=value.text;
    C.id("secretFacts").replaceWith(Object.assign(C.facts(value.facts),{id:"secretFacts"}));C.text("secretStatus","");C.id("secretDialog").showModal();C.id("downloadSecret").focus();
  };
  const clearSecret = () => {secret=null;C.id("secretValue").value="";C.id("secretFacts").replaceChildren();C.text("secretStatus","");};
  C.id("secretDialog").addEventListener("close",()=>{if(!C.id("secretDialog").open)clearSecret();});
  C.id("secretDialog").addEventListener("cancel",clearSecret);
  const dismissSecret=()=>{clearSecret();C.id("secretDialog").close();};
  C.id("secretClose").addEventListener("click",dismissSecret);C.id("dismissSecret").addEventListener("click",dismissSecret);
  C.id("copySecret").addEventListener("click",async()=>{
    if(!secret)return;const displayed=secret;
    try{await navigator.clipboard.writeText(displayed.text);if(secret===displayed)C.text("secretStatus","복사했습니다. 안전한 위치에 보관하세요.");}
    catch(_){if(secret!==displayed)return;C.id("secretValue").focus();C.id("secretValue").select();C.text("secretStatus","자동 복사가 허용되지 않습니다. 선택된 값을 직접 복사하세요.");}
  });
  C.id("downloadSecret").addEventListener("click",()=>{
    if(!secret)return;const url=URL.createObjectURL(new Blob([secret.text+"\n"],{type:secret.type}));
    const link=document.createElement("a");link.href=url;link.download=secret.filename;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);C.text("secretStatus","발급 파일 다운로드를 요청했습니다. 저장한 파일을 안전하게 보관하세요.");
  });
  const navigate = () => {
    const selected=location.hash.slice(1),view=Object.hasOwn(pages,selected)?selected:"overview";
    C.view=view;const [title,eyebrow,description]=pages[view];
    C.text("pageTitle",title);C.text("pageEyebrow",eyebrow);C.text("pageDescription",description);document.title=`${title} · Xe-AntiShell Central`;
    for(const key of Object.keys(pages))C.id(`view-${key}`).hidden=key!==view;
    for(const link of C.id("navigation").querySelectorAll("[data-view]")){if(link.dataset.view===view)link.setAttribute("aria-current","page");else link.removeAttribute("aria-current");}
    if(started&&view==="history")C.loadHistory(true);if(started&&view==="audit")C.loadAudit(true);if(started&&view==="accounts")C.loadAccounts();if(started&&view==="updates")C.loadUpdates?.();
  };
  C.navigate=navigate;
  const recent = async () => {
    const generation=++recentGeneration;
    try{const records=await C.request("/api/history?kind=detections&limit=5");if(generation===recentGeneration)C.renderRecent(C.array(records));}
    catch(error){if(generation===recentGeneration)C.id("recentFindings").replaceChildren(C.empty("최근 탐지를 불러오지 못했습니다. 탐지·실행 이력에서 다시 조회하세요."));}
  };
  C.refresh = () => {
    if(refreshing)return refreshing;
    refreshing=(async()=>{
      try{
        const state=await C.request("/api/state");C.updateState(state);C.applyAccess();
        C.text("lastUpdated",`${C.time(state.server_time||new Date().toISOString())} 갱신`);C.text("connectionState","중앙 연결됨");C.id("connectionState").className="connection connected";
        if(state.agents_truncated)C.error(`등록된 ${C.number(state.total_agents)}대 중 최대 1,000대만 표시합니다. 검색·집계·선택은 표시된 서버를 기준으로 합니다.`);
        await recent();
      }catch(error){C.text("connectionState","갱신 실패");C.id("connectionState").className="connection failed";C.error(error);}
      finally{refreshing=null;}
    })();return refreshing;
  };
  C.id("refreshButton").addEventListener("click",()=>C.run(C.id("refreshButton"),async()=>{await C.refresh();if(C.view==="history")await C.loadHistory(true);if(C.view==="audit")await C.loadAudit(true);if(C.view==="accounts")await C.loadAccounts();if(C.view==="updates")await C.loadUpdates?.();}));
  C.id("logoutButton").addEventListener("click",()=>C.run(C.id("logoutButton"),async()=>{
    if((C.hasUnsavedPolicy()||C.hasUnsavedGroup())&&!await C.confirm({title:"로그아웃 확인",description:"저장하지 않은 편집 내용이 있습니다. 로그아웃하면 편집 내용과 발급 결과가 사라집니다.",accept:"로그아웃"}))return;
    await C.request("/logout",{method:"POST"});clearSecret();location.assign("/login");
  }));
  globalThis.addEventListener("pagehide",clearSecret);
  globalThis.addEventListener("hashchange",navigate);
  globalThis.addEventListener("beforeunload",event=>{if(C.hasUnsavedPolicy()||C.hasUnsavedGroup()){event.preventDefault();event.returnValue="";}});
  C.initFleet();C.initOperations();C.initHistory();C.initPolicy();C.initAccounts();C.initUpdates?.();C.initCentralUpdate?.();navigate();
  (async()=>{
    try{C.session=await C.request("/api/session");C.text("sessionUser",C.session.username);C.applyAccess();started=true;await C.refresh();navigate();}
    catch(error){C.error(error);}
    setInterval(()=>{if(started&&!document.hidden)C.refresh();},15000);
    document.addEventListener("visibilitychange",()=>{if(started&&!document.hidden)C.refresh();});
  })();
})();
