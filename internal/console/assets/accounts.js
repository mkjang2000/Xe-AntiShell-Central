"use strict";

(function (C) {
  const roles = {admin:"관리자",operator:"운영자",viewer:"조회자"};
  const roleHelp = [
    ["관리자", "계정·권한 관리와 모든 조회·운영 작업"],
    ["운영자", "조회 기능, 정책·서버 그룹 관리, 설치 토큰 발급, 제거 승인(OTP) 발급과 등록 해지"],
    ["조회자", "서버 상태·보안 정책·이력 조회"],
    ["공통", "모든 역할은 본인 비밀번호를 변경할 수 있습니다."]
  ];
  const state = {accounts:[],generation:0,initialized:false};
  const dialogs = [];
  let adminPanel, rows, auditRows, detail, create, password, tooltip = null, tooltipNumber = 0, tooltipTimer = null;
  const el = (tag, name = "", text = "") => C.el(tag,name,text);
  const button = (text, id = "", type = "button") => Object.assign(el("button","",text),{id,type});
  const errorText = error => error?.message || String(error);
  const field = (label,type,id,autocomplete = "") => {
    const wrap=el("div","field"),caption=el("label","",label),input=Object.assign(el("input"),{id,name:id,type,required:true,maxLength:type==="password"?1024:64});
    caption.htmlFor=id;if(autocomplete)input.autocomplete=autocomplete;wrap.append(caption,input);return {wrap,input};
  };
  const validPassword = value => {
    const length=new TextEncoder().encode(value).length;
    if(length<16||length>1024)throw new Error("비밀번호는 UTF-8 기준 16~1,024바이트로 입력하세요.");
    return value;
  };
  const passwordPair = (first,second) => {
    const value=first.value,repeated=second.value;first.value="";second.value="";
    if(value!==repeated)throw new Error("새 비밀번호와 확인 값이 일치하지 않습니다.");
    return validPassword(value);
  };
  const hideTooltip = () => {
    clearTimeout(tooltipTimer);tooltipTimer=null;
    if(!tooltip)return;
    tooltip.tip.hidden=true;tooltip.control.setAttribute("aria-expanded","false");tooltip.pinned=false;tooltip=null;
  };
  const help = () => {
    const wrap=el("span","account-help-wrap"),control=button("?"),tip=el("span","account-tooltip");
    for(const [name,description] of roleHelp){const paragraph=el("p");paragraph.append(el("strong","",name),document.createTextNode(description));tip.append(paragraph);}
    control.className="account-help";control.setAttribute("aria-label","계정 권한 안내");control.setAttribute("aria-expanded","false");
    tip.id=`account-role-tooltip-${++tooltipNumber}`;tip.hidden=true;tip.setAttribute("role","tooltip");control.setAttribute("aria-describedby",tip.id);
    const item={wrap,control,tip,pinned:false};
    const show = () => {
      clearTimeout(tooltipTimer);
      if(tooltip!==item)hideTooltip();tooltip=item;tip.hidden=false;control.setAttribute("aria-expanded","true");
      const anchor=control.getBoundingClientRect(),bounds=tip.getBoundingClientRect(),width=globalThis.innerWidth||1024,height=globalThis.innerHeight||768;
      tip.style.left=`${Math.max(8,Math.min(anchor.left,width-bounds.width-8))}px`;
      tip.style.top=`${Math.max(8,anchor.bottom+8+bounds.height>height?anchor.top-bounds.height-8:anchor.bottom+8)}px`;
    };
    wrap.addEventListener("pointerenter",show);
    wrap.addEventListener("pointerleave",()=>{if(!item.pinned&&document.activeElement!==control)tooltipTimer=setTimeout(hideTooltip,150);});
    tip.addEventListener("pointerenter",show);
    tip.addEventListener("pointerleave",()=>{if(!item.pinned&&document.activeElement!==control)hideTooltip();});
    control.addEventListener("focus",show);
    control.addEventListener("blur",()=>{if(!item.pinned)hideTooltip();});
    control.addEventListener("click",()=>{if(item.pinned){hideTooltip();}else{show();item.pinned=true;}});
    wrap.append(control,tip);return wrap;
  };
  const roleSelect = (id,role,all = false) => {
    const select=Object.assign(el("select"),{id});
    if(all){const option=el("option","","전체 권한");option.value="";select.append(option);}
    for(const [value,label] of Object.entries(roles)){const option=el("option","",label);option.value=value;select.append(option);}
    select.value=role;return select;
  };
  const roleField = (id,role) => {
    const wrap=el("div","field"),label=el("label","","권한"),select=roleSelect(id,role);label.htmlFor=id;wrap.append(label,help(),select);return {wrap,input:select};
  };
  const wipe = panel => {for(const input of panel.dialog.querySelectorAll('input[type="password"]'))input.value="";};
  const lock = panel => {for(const item of panel.fields)item.node.disabled=panel.busy||panel.stale||item.permanent;};
  const panelError = (panel,error) => {panel.error.textContent=errorText(error);panel.error.hidden=false;};
  const restoreFocus = panel => {
    let target=panel.opener;
    if(panel.username)target=[...rows.querySelectorAll("[data-account-username]")].find(node=>node.dataset.accountUsername===panel.username)||target;
    if(!target?.isConnected||target.disabled)target=C.id("accountSearch")||C.id("accountOwnPasswordOpen");
    target?.focus({preventScroll:true});
  };
  const finishClose = (panel,focus = true) => {
    wipe(panel);if(!panel.visible)return;
    panel.visible=false;panel.generation++;panel.busy=false;panel.stale=false;hideTooltip();panel.error.hidden=true;panel.status.textContent="";if(focus)restoreFocus(panel);
  };
  const close = (panel,focus = true) => {wipe(panel);if(panel.dialog.open)panel.dialog.close();finishClose(panel,focus);};
  const closeAll = () => {hideTooltip();for(const panel of dialogs)close(panel);};
  const shell = (id,title) => {
    const dialog=Object.assign(el("dialog","account-dialog"),{id}),head=el("div","dialog-head"),heading=Object.assign(el("h2","",title),{id:`${id}Title`,tabIndex:-1}),dismiss=button("×",`${id}Close`);
    dismiss.className="icon-button";dismiss.setAttribute("aria-label",`${title} 창 닫기`);head.append(heading,dismiss);
    const content=el("div","account-dialog-body"),error=el("p","account-dialog-error"),status=el("p","account-dialog-status"),footer=el("div","dialog-actions"),cancel=button("닫기",`${id}Cancel`);
    error.hidden=true;error.setAttribute("role","alert");status.setAttribute("role","status");status.setAttribute("aria-live","polite");footer.append(cancel);dialog.setAttribute("aria-labelledby",heading.id);dialog.setAttribute("aria-modal","true");dialog.append(head,content,error,status,footer);
    const panel={dialog,heading,content,error,status,footer,cancel,fields:[],generation:0,busy:false,stale:false,visible:false,opener:null,username:""};
    dismiss.addEventListener("click",()=>close(panel));cancel.addEventListener("click",()=>close(panel));dialog.addEventListener("cancel",event=>{event.preventDefault();close(panel);});dialog.addEventListener("close",()=>{if(!dialog.open)finishClose(panel);});
    dialogs.push(panel);return panel;
  };
  const open = (panel,opener,initial) => {
    closeAll();panel.generation++;panel.visible=true;panel.busy=false;panel.stale=false;panel.opener=opener;panel.error.hidden=true;panel.status.textContent="";lock(panel);panel.dialog.showModal();(initial||panel.heading).focus({preventScroll:true});
  };
  const run = async (panel,operation,success) => {
    if(panel.busy||panel.stale||!panel.visible)return;
    const generation=panel.generation;panel.busy=true;panel.error.hidden=true;panel.status.textContent="요청 처리 중입니다. 창을 닫아도 서버 작업은 계속됩니다.";lock(panel);
    try{
      const result=await operation();
      if(result?.reauthenticate){closeAll();C.session=null;globalThis.location.assign("/login");return;}
      if(!panel.visible||generation!==panel.generation)return;
      await success(result);
    }catch(error){
      if(panel.visible&&generation===panel.generation){panelError(panel,error);panel.status.textContent="";if(panel===detail){panel.stale=error?.status===409||error?.status===404;detail.reload.hidden=!panel.stale;}}
    }finally{
      if(panel.visible&&generation===panel.generation){panel.busy=false;lock(panel);}
    }
  };
  const confirmation = (text,id) => {
    const wrap=el("label","check-label"),input=Object.assign(el("input"),{type:"checkbox",id,required:true});wrap.append(input,document.createTextNode(text));return {wrap,input};
  };
  const mutationForm = (panel,title,permanent = false) => {
    const form=el("form","account-mutation-form"),fieldset=el("fieldset"),legend=el("legend","",title);fieldset.append(legend);form.append(fieldset);panel.fields.push({node:fieldset,permanent});return {form,fieldset};
  };
  const saved = async (panel,message) => {const generation=panel.generation;await C.loadAccounts();if(panel.visible&&panel.generation===generation)panel.status.textContent=message;};
  const populateDetail = account => {
    const operations=[];
    const operation=(title,id,form)=>{const section=Object.assign(el("details","account-detail-operation"),{id}),summary=el("summary","",title);section.append(summary,form);section.addEventListener("toggle",()=>{if(section.open)for(const item of operations)if(item!==section)item.open=false;});operations.push(section);return section;};
    detail.snapshot={...account};detail.username=account.username;detail.heading.textContent=`${account.username} 계정 상세`;detail.stale=false;detail.fields=[];detail.reload.hidden=true;
    const facts=Object.assign(el("dl","account-detail-facts"),{id:"accountDetailFacts"});
    for(const [label,value] of [["사용자 이름",account.username],["권한",roles[account.role]||"미확인"],["생성 시각",C.time(account.created_at)],["변경 시각",C.time(account.updated_at)]])facts.append(el("dt","",label),el("dd","",value));
    const last=account.role==="admin"&&state.accounts.filter(item=>item.username!==account.username&&item.role==="admin").length===0;
    const note=el("p","panel-note",last?"마지막 관리자입니다. 권한 변경과 삭제는 다른 관리자를 추가한 뒤 진행하세요.":"변경하면 대상 계정의 모든 기존 세션이 종료됩니다.");
    const role=mutationForm(detail,"권한 변경",last),select=roleField("accountDetailRole",account.role),confirmRole=confirmation("권한 변경과 기존 세션 종료를 확인했습니다.","accountRoleConfirm"),saveRole=button("권한 저장","accountRoleSave","submit");
    role.form.id="accountRoleForm";role.fieldset.append(select.wrap,confirmRole.wrap,saveRole);
    role.form.addEventListener("submit",event=>{event.preventDefault();return run(detail,()=>{
      if(!confirmRole.input.checked)throw new Error("권한 변경 확인에 체크하세요.");
      return C.request(`/api/accounts/${encodeURIComponent(account.username)}`,{method:"POST",body:{role:select.input.value,version:account.version}});
    },async result=>{populateDetail(result.account);detail.heading.focus();await saved(detail,"권한을 변경하고 기존 세션을 종료했습니다.");});});
    const content=[facts,note,operation("권한 변경","accountRoleOperation",role.form)];
    if(account.username!==C.session.username){
      const reset=mutationForm(detail,"비밀번호 재설정"),next=field("새 비밀번호","password","accountResetPassword","new-password"),repeat=field("새 비밀번호 확인","password","accountResetPasswordConfirm","new-password"),confirmed=confirmation("비밀번호 변경과 기존 세션 종료를 확인했습니다.","accountResetConfirm");
      reset.form.id="accountResetForm";reset.fieldset.append(next.wrap,repeat.wrap,confirmed.wrap,button("비밀번호 재설정","accountResetSubmit","submit"));content.push(operation("비밀번호 재설정","accountResetOperation",reset.form));
      reset.form.addEventListener("submit",event=>{event.preventDefault();return run(detail,()=>{
        const value=passwordPair(next.input,repeat.input);
        if(!confirmed.input.checked)throw new Error("비밀번호 변경 확인에 체크하세요.");
        return C.request(`/api/accounts/${encodeURIComponent(account.username)}/password`,{method:"POST",body:{password:value,version:account.version}});
      },async result=>{populateDetail(result.account);detail.heading.focus();await saved(detail,"비밀번호를 변경하고 기존 세션을 종료했습니다.");});});
    }else content.push(el("p","panel-note","본인 비밀번호는 목록 상단의 ‘내 비밀번호 변경’에서 변경하세요."));
    const removal=mutationForm(detail,"계정 삭제",last),match=field(`삭제하려면 '${account.username}' 입력`,"text","accountDeleteConfirm","off"),remove=button("계정 삭제","accountDeleteSubmit","submit");
    remove.className="danger";remove.disabled=true;match.input.pattern=account.username;removal.form.id="accountDeleteForm";removal.fieldset.append(match.wrap,remove);content.push(operation("계정 삭제","accountDeleteOperation",removal.form));
    match.input.addEventListener("input",()=>{remove.disabled=match.input.value!==account.username;});
    removal.form.addEventListener("submit",event=>{event.preventDefault();return run(detail,()=>{
      if(last||match.input.value!==account.username)throw new Error("삭제할 사용자 이름을 정확히 입력하세요.");
      return C.request(`/api/accounts/${encodeURIComponent(account.username)}?version=${account.version}`,{method:"DELETE"});
    },async()=>{close(detail,false);await C.loadAccounts();restoreFocus(detail);C.notify("계정을 삭제하고 기존 세션을 종료했습니다.");});});
    detail.content.replaceChildren(...content);lock(detail);
  };
  const renderTable = () => {
    const query=C.id("accountSearch").value.trim().toLocaleLowerCase(),role=C.id("accountRoleFilter").value;
    const accounts=state.accounts.filter(account=>(!query||account.username.toLocaleLowerCase().includes(query))&&(!role||account.role===role));
    C.text("accountTotal",`전체 ${state.accounts.length}개 · 표시 ${accounts.length}개`);
    rows.replaceChildren(...accounts.map(account=>{
      const row=el("tr"),name=el("th","",account.username);name.scope="row";
      const action=button("상세");action.dataset.accountUsername=account.username;action.setAttribute("aria-label",`${account.username} 계정 상세`);
      action.addEventListener("click",()=>{populateDetail(account);open(detail,action);});
      const cell=el("td");cell.append(action);row.append(name,el("td","",roles[account.role]||"미확인"),el("td","account-date",C.time(account.created_at)),el("td","account-date",C.time(account.updated_at)),cell);return row;
    }));
    if(!accounts.length){const row=el("tr"),cell=el("td","empty-cell","조건에 맞는 계정이 없습니다.");cell.colSpan=5;row.append(cell);rows.append(row);}
  };
  const table = (headings,id,dates = []) => {
    const wrap=el("div","account-table-scroll"),value=el("table","account-table"),head=el("thead"),row=el("tr"),body=Object.assign(el("tbody"),{id});
    headings.forEach((label,index)=>{const cell=el("th",dates.includes(index)?"account-date":"",label);cell.scope="col";if(label==="권한")cell.append(help());row.append(cell);});head.append(row);const caption=el("caption","sr-only",id==="accountTableRows"?"계정 목록":"계정 변경 감사 기록");value.append(caption,head,body);wrap.append(value);return {wrap,body};
  };
  C.loadAccounts = async () => {
    if(!C.session||!state.initialized)return false;
    const generation=++state.generation,session=C.session,admin=session.role==="admin",caller=dialogs.find(item=>item.visible),callerGeneration=caller?.generation;adminPanel.hidden=!admin;C.text("accountSelfName",`${session.username} · ${roles[session.role]||"미확인"}`);
    if(!admin){state.accounts=[];rows.replaceChildren();auditRows.replaceChildren();return true;}
    try{
      const [accounts,audit]=await Promise.all([C.request("/api/accounts"),C.request("/api/account-audit")]);
      if(generation!==state.generation||C.session!==session)return false;
      state.accounts=C.array(accounts);renderTable();
      const operations={created:"계정 추가",deleted:"계정 삭제",role_changed:"권한 변경",password_changed:"비밀번호 변경"};
      auditRows.replaceChildren(...C.array(audit).map(item=>{const row=el("tr");for(const value of [C.time(item.created_at),item.actor,item.target,operations[item.operation]||"계정 변경",roles[item.role]||"—"])row.append(el("td","",value));return row;}));
      if(!C.array(audit).length){const row=el("tr"),cell=el("td","empty-cell","계정 변경 감사 기록이 없습니다.");cell.colSpan=5;row.append(cell);auditRows.append(row);}
      C.text("accountAuditCount",`최근 ${C.array(audit).length}건`);
      if(detail.visible&&!detail.busy){const current=state.accounts.find(item=>item.username===detail.snapshot.username);if(!current||current.version!==detail.snapshot.version){detail.stale=true;detail.reload.hidden=false;panelError(detail,"계정 정보가 변경되었습니다. 최신 정보를 다시 조회한 뒤 수정하세요.");lock(detail);}}
      return true;
    }catch(error){if(generation!==state.generation||C.session!==session)return false;if(caller){if(caller.visible&&caller.generation===callerGeneration)panelError(caller,error);}else if(!dialogs.some(item=>item.visible))C.error(error);return false;}
  };
  C.initAccounts = () => {
    if(state.initialized)return;state.initialized=true;
    const root=C.id("view-accounts"),self=el("section","panel account-self-row"),selfName=Object.assign(el("strong"),{id:"accountSelfName"}),own=button("내 비밀번호 변경","accountOwnPasswordOpen");self.append(selfName,help(),own);
    adminPanel=Object.assign(el("section","panel"),{id:"accountAdminPanel"});adminPanel.hidden=true;
    const toolbar=el("div","accounts-toolbar"),search=field("사용자 이름 검색","search","accountSearch"),filter=roleSelect("accountRoleFilter","",true),filterWrap=el("div","field"),filterLabel=el("label","","권한 필터"),total=Object.assign(el("span","account-count"),{id:"accountTotal"}),add=button("계정 추가","accountCreateOpen");
    search.input.required=false;filterLabel.htmlFor=filter.id;filterWrap.append(filterLabel,filter);toolbar.append(search.wrap,filterWrap,total,add);adminPanel.append(toolbar);
    const accountTable=table(["사용자","권한","생성 시각","변경 시각","관리"],"accountTableRows",[2,3]);rows=accountTable.body;adminPanel.append(accountTable.wrap);
    const audit=el("details","account-audit"),summary=el("summary","","계정 변경 감사 기록 "),count=Object.assign(el("span"),{id:"accountAuditCount"}),auditTable=table(["시각","작업자","대상","작업","권한"],"accountAuditRows");summary.append(count);auditRows=auditTable.body;audit.append(summary,el("p","panel-note","최근 100건을 표시하며 비밀번호와 인증 비밀은 기록하지 않습니다."),auditTable.wrap);adminPanel.append(audit);root.replaceChildren(self,adminPanel);
    create=shell("accountCreateDialog","계정 추가");password=shell("accountPasswordDialog","내 비밀번호 변경");detail=shell("accountDetailDialog","계정 상세");
    detail.reload=button("최신 정보 다시 조회","accountDetailReload");detail.reload.hidden=true;detail.footer.prepend(detail.reload);
    detail.reload.addEventListener("click",()=>{if(detail.busy)return;detail.stale=false;return run(detail,async()=>{if(!await C.loadAccounts())throw new Error("계정 목록을 다시 조회하지 못했습니다.");const account=state.accounts.find(item=>item.username===detail.snapshot.username);if(!account)throw new Error("이 계정은 삭제되었습니다. 창을 닫고 목록을 확인하세요.");return account;},async account=>{populateDetail(account);detail.error.hidden=true;detail.status.textContent="최신 정보를 조회했습니다. 변경할 내용을 다시 입력하세요.";detail.heading.focus();});});
    const creation=mutationForm(create,"새 계정"),username=field("사용자 이름","text","accountCreateUsername","username"),initial=field("초기 비밀번호","password","accountCreatePassword","new-password"),repeat=field("비밀번호 확인","password","accountCreatePasswordConfirm","new-password"),role=roleField("accountCreateRole","viewer");creation.form.id="accountCreateForm";username.input.pattern="[A-Za-z0-9_-]{1,64}";creation.fieldset.append(username.wrap,role.wrap,initial.wrap,repeat.wrap,button("계정 추가","accountCreateSubmit","submit"));create.content.append(el("p","panel-note","비밀번호는 UTF-8 기준 16~1,024바이트입니다."),creation.form);
    creation.form.addEventListener("submit",event=>{event.preventDefault();return run(create,()=>C.request("/api/accounts",{method:"POST",body:{username:username.input.value.trim(),role:role.input.value,password:passwordPair(initial.input,repeat.input)}}),async()=>{close(create);await C.loadAccounts();C.notify("계정을 추가했습니다. 초기 비밀번호를 사용자에게 안전하게 전달하세요.");});});
    add.addEventListener("click",()=>{username.input.value="";role.input.value="viewer";create.username="";open(create,add,username.input);});
    const ownForm=mutationForm(password,"비밀번호 변경"),current=field("현재 비밀번호","password","accountCurrentPassword","current-password"),next=field("새 비밀번호","password","accountNewPassword","new-password"),confirm=field("새 비밀번호 확인","password","accountConfirmPassword","new-password");ownForm.form.id="accountPasswordForm";ownForm.fieldset.append(current.wrap,next.wrap,confirm.wrap,button("비밀번호 변경","accountPasswordSubmit","submit"));password.content.append(el("p","panel-note","UTF-8 기준 16~1,024바이트입니다. 변경하면 모든 기존 세션이 종료되며 다시 로그인해야 합니다."),ownForm.form);
    ownForm.form.addEventListener("submit",event=>{event.preventDefault();return run(password,()=>{const old=current.input.value;current.input.value="";const value=passwordPair(next.input,confirm.input);return C.request("/api/account/password",{method:"POST",body:{current_password:validPassword(old),password:value}});},async()=>{});});
    own.addEventListener("click",()=>{password.username="";open(password,own,current.input);});search.input.addEventListener("input",renderTable);filter.addEventListener("change",renderTable);
    root.append(...dialogs.map(panel=>panel.dialog));
    globalThis.addEventListener("keydown",event=>{if(event.key==="Escape"&&tooltip){event.preventDefault();event.stopPropagation();hideTooltip();}},true);
    globalThis.addEventListener("pointerdown",event=>{if(tooltip&&!tooltip.wrap.contains(event.target))hideTooltip();});
    for(const name of ["scroll","resize"])globalThis.addEventListener(name,hideTooltip,true);
    globalThis.addEventListener("pagehide",()=>{hideTooltip();for(const panel of dialogs)close(panel,false);});globalThis.addEventListener("hashchange",()=>{hideTooltip();for(const panel of dialogs)close(panel,false);});
  };
})(globalThis.XEC);
