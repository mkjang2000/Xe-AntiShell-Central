"use strict";

(function (C) {
  const roles = {admin: "관리자", operator: "운영자", viewer: "조회자"};
  const state = {accounts: [], generation: 0};
  let adminPanel, accountRows, auditRows;
  const field = (label, type, name, autocomplete = "") => {
    const wrap=C.el("div","field"), caption=C.el("label","",label), input=C.el("input");
    input.id=name;input.name=name;input.type=type;input.required=true;
    input.maxLength=type==="password"?1024:64;
    if(type==="password")input.minLength=16;
    if(autocomplete)input.autocomplete=autocomplete;
    caption.htmlFor=name;wrap.append(caption,input);return {wrap,input};
  };
  const roleSelect = role => {
    const input=C.el("select");input.setAttribute("aria-label","계정 권한");
    for(const [value,label] of Object.entries(roles)){const option=C.el("option","",label);option.value=value;input.append(option);}
    input.value=role;return input;
  };
  const button = (text, type = "submit") => {const value=C.el("button","",text);value.type=type;return value;};
  const changed = async result => {
    if(result&&result.reauthenticate){C.session=null;globalThis.location.assign("/login");return;}
    await C.loadAccounts();C.notify("계정 변경을 저장하고 해당 계정의 기존 세션을 무효화했습니다.");
  };
  const renderAccounts = () => {
    const administrators=state.accounts.filter(account=>account.role==="admin").length;
    accountRows.replaceChildren(...state.accounts.map(account=>{
      const card=C.el("article","record"),head=C.el("div","record-head");
      head.append(C.el("strong","record-title",account.username),C.tag(roles[account.role]||"알 수 없는 권한","neutral"));
      card.append(head,C.el("p","record-summary",`${account.username===C.session.username?"현재 로그인 계정 · ":""}마지막 변경 ${C.time(account.updated_at)}`));
      const controls=C.el("form","filter-bar"),role=roleSelect(account.role),save=button("권한 저장"),remove=button("계정 삭제","button");
      if(account.role==="admin"&&administrators===1){remove.disabled=true;remove.title="마지막 관리자는 삭제할 수 없습니다.";}
      controls.append(role,save,remove);card.append(controls);
      controls.addEventListener("submit",event=>{event.preventDefault();C.run(save,async()=>{
        if(!await C.confirm({title:"계정 권한 변경",description:`'${account.username}'의 권한을 ${roles[role.value]}로 변경하고 모든 기존 세션을 종료합니다.`,accept:"권한 변경"}))return;
        await changed(await C.request(`/api/accounts/${encodeURIComponent(account.username)}`,{method:"POST",body:{role:role.value,version:account.version}}));
      });});
      remove.addEventListener("click",()=>C.run(remove,async()=>{
        if(!await C.confirm({title:"계정 삭제",description:`'${account.username}'의 로그인을 차단하고 모든 기존 세션을 종료합니다.`,accept:"계정 삭제",match:account.username}))return;
        await changed(await C.request(`/api/accounts/${encodeURIComponent(account.username)}?version=${account.version}`,{method:"DELETE"}));
      }));
      if(account.username!==C.session.username){
        const form=C.el("form","filter-bar"),password=field("새 비밀번호","password",`reset-${account.username}`,"new-password"),reset=button("비밀번호 재설정");
        form.append(password.wrap,reset);card.append(form);
        form.addEventListener("submit",event=>{event.preventDefault();C.run(reset,async()=>{
          const value=password.input.value;password.input.value="";
          if(!await C.confirm({title:"비밀번호 재설정",description:`'${account.username}'의 비밀번호를 변경하고 모든 기존 세션을 종료합니다.`,accept:"비밀번호 변경"}))return;
          await changed(await C.request(`/api/accounts/${encodeURIComponent(account.username)}/password`,{method:"POST",body:{password:value,version:account.version}}));
        });});
      }
      return card;
    }));
  };
  C.loadAccounts = async () => {
    if(!C.session)return;
    const admin=C.session.role==="admin";adminPanel.hidden=!admin;
    C.text("accountSelfName",`${C.session.username} · ${roles[C.session.role]||"미확인"}`);
    if(!admin){state.accounts=[];accountRows.replaceChildren();auditRows.replaceChildren();return;}
    const generation=++state.generation;
    try{
      const [accounts,audit]=await Promise.all([C.request("/api/accounts"),C.request("/api/account-audit")]);
      if(generation!==state.generation)return;
      state.accounts=C.array(accounts);renderAccounts();
      const operations={created:"계정 추가",deleted:"계정 삭제",role_changed:"권한 변경",password_changed:"비밀번호 변경"};
      auditRows.replaceChildren(...C.array(audit).map(item=>{
        const row=C.el("article","record");row.append(C.el("strong","record-title",operations[item.operation]||"계정 변경"),C.el("p","record-summary",`${item.actor} → ${item.target}${item.role?` · ${roles[item.role]||"미확인"}`:""}`),C.el("time","",C.time(item.created_at)));return row;
      }));
    }catch(error){C.error(error);}
  };
  C.initAccounts = () => {
    const root=C.id("view-accounts"),self=C.el("section","panel");
    self.append(C.el("h2","","내 비밀번호 변경"),Object.assign(C.el("p","panel-note"),{id:"accountSelfName"}),C.el("p","panel-note","비밀번호는 16~1,024바이트입니다. 변경하면 모든 기존 세션이 종료되어 다시 로그인해야 합니다."));
    const form=C.el("form","form-grid"),current=field("현재 비밀번호","password","accountCurrentPassword","current-password"),password=field("새 비밀번호","password","accountNewPassword","new-password"),confirm=field("새 비밀번호 확인","password","accountConfirmPassword","new-password"),submit=button("내 비밀번호 변경");
    form.append(current.wrap,password.wrap,confirm.wrap,submit);self.append(form);
    form.addEventListener("submit",event=>{event.preventDefault();C.run(submit,async()=>{
      const old=current.input.value,next=password.input.value,repeated=confirm.input.value;
      current.input.value="";password.input.value="";confirm.input.value="";
      if(next!==repeated)throw new Error("새 비밀번호와 확인 값이 일치하지 않습니다.");
      await changed(await C.request("/api/account/password",{method:"POST",body:{current_password:old,password:next}}));
    });});
    adminPanel=C.el("section","panel");adminPanel.hidden=true;
    adminPanel.append(C.el("h2","","계정 및 권한 관리"),C.el("p","panel-note","관리자는 모든 작업과 계정을 관리합니다. 운영자는 정책·그룹·등록·승인을 관리하고, 조회자는 보고 조회와 본인 비밀번호 변경을 할 수 있습니다. 마지막 관리자는 보호됩니다."));
    const create=C.el("form","form-grid"),username=field("새 사용자 이름","text","accountCreateUsername","username"),initial=field("초기 비밀번호","password","accountCreatePassword","new-password"),role=roleSelect("viewer"),add=button("계정 추가");
    username.input.pattern="[A-Za-z0-9_-]{1,64}";role.id="accountCreateRole";
    const roleField=C.el("div","field"),roleLabel=C.el("label","","권한");roleLabel.htmlFor=role.id;roleField.append(roleLabel,role);
    create.append(username.wrap,initial.wrap,roleField,add);adminPanel.append(create);
    create.addEventListener("submit",event=>{event.preventDefault();C.run(add,async()=>{
      const body={username:username.input.value.trim(),password:initial.input.value,role:role.value};initial.input.value="";
      await C.request("/api/accounts",{method:"POST",body});username.input.value="";await C.loadAccounts();C.notify("계정을 추가했습니다. 초기 비밀번호를 사용자에게 안전하게 전달하세요.");
    });});
    accountRows=C.el("div","record-list");auditRows=C.el("div","record-list");
    adminPanel.append(accountRows,C.el("h3","","계정 변경 감사 기록"),C.el("p","panel-note","최근 100건을 표시합니다. 비밀번호와 인증 비밀은 기록하지 않습니다."),auditRows);root.replaceChildren(self,adminPanel);
  };
})(globalThis.XEC);
