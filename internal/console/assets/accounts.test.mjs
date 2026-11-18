import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

function harness() {
  const events=new Map(),closeEvents=[],timers=new Map(),calls=[],errors=[],notices=[],redirects=[];
  let timerID=0,document;
  class Node {
    constructor(tag="div"){this.tagName=tag;this.children=[];this.parent=null;this.handlers={};this.attributes={};this.dataset={};this.style={};this.value="";this.ownText="";this.hidden=false;this.disabled=false;this.open=false;this.checked=false;}
    set textContent(value){this.ownText=String(value);for(const node of this.children)node.parent=null;this.children=[];}
    get textContent(){return this.ownText+this.children.map(node=>node.textContent).join("");}
    set innerHTML(_){throw new Error("Unsafe HTML insertion");}
    append(...nodes){for(let node of nodes){if(typeof node==="string")node=Object.assign(new Node("#text"),{textContent:node});node.parent=this;this.children.push(node);}}
    prepend(...nodes){const old=this.children;this.children=[];this.append(...nodes,...old);}
    replaceChildren(...nodes){for(const node of this.children)node.parent=null;this.children=[];this.ownText="";this.append(...nodes);}
    setAttribute(name,value){this.attributes[name]=String(value);}
    addEventListener(name,callback){(this.handlers[name]??=[]).push(callback);}
    emit(name,extra={}){const event={target:this,currentTarget:this,preventDefault(){this.prevented=true;},stopPropagation(){this.stopped=true;},...extra};const results=(this.handlers[name]||[]).map(callback=>callback(event));return {event,done:Promise.all(results)};}
    contains(node){return node===this||this.children.some(child=>child.contains(node));}
    get isConnected(){return this===document.body||Boolean(this.parent?.isConnected);}
    focus(){if(document.modal&&!document.modal.contains(this))return;const previous=document.activeElement;document.activeElement=this;if(previous!==this){previous?.emit("blur");this.emit("focus");}}
    showModal(){assert.equal(this.open,false);assert.equal(document.modal,null,"dialogs must not nest");this.open=true;document.modal=this;}
    close(){this.open=false;if(document.modal===this)document.modal=null;closeEvents.push(()=>this.emit("close"));}
    getBoundingClientRect(){return this.attributes.role==="tooltip"?{left:0,top:0,bottom:90,width:260,height:90}:{left:490,top:340,bottom:360,width:20,height:20};}
    querySelectorAll(selector){const matches=node=>selector==='input[type="password"]'?node.tagName==="input"&&node.type==="password":selector==="[data-account-username]"?node.dataset.accountUsername!==undefined:selector.startsWith(".")?(node.className||"").split(" ").includes(selector.slice(1)):node.tagName===selector;return this.children.flatMap(child=>[...(matches(child)?[child]:[]),...child.querySelectorAll(selector)]);}
  }
  document={body:new Node("body"),modal:null,activeElement:null,createElement:tag=>new Node(tag),createTextNode:text=>Object.assign(new Node("#text"),{textContent:text}),getElementById:id=>[document.body,...document.body.querySelectorAll("*")].find(node=>node.id===id)||null};
  // The test DOM traverses IDs independently of selector matching.
  const descendants=node=>[node,...node.children.flatMap(descendants)];
  document.getElementById=id=>descendants(document.body).find(node=>node.id===id)||null;
  const root=Object.assign(new Node(),{id:"view-accounts"});document.body.append(root);
  const context=vm.createContext({document,Node,TextEncoder,Date,URLSearchParams,AbortController,innerWidth:520,innerHeight:400,location:{hash:"#accounts",assign:value=>redirects.push(value)},addEventListener:(name,handler)=>{if(!events.has(name))events.set(name,[]);events.get(name).push(handler);},setTimeout:handler=>{timers.set(++timerID,handler);return timerID;},clearTimeout:id=>timers.delete(id)});
  for(const filename of ["model.js","accounts.js"])vm.runInContext(fs.readFileSync(new URL(filename,import.meta.url),"utf8"),context);
  const C=context.XEC;C.view="accounts";C.session={username:"admin",role:"admin",csrf_token:"fixture"};C.error=error=>errors.push(String(error));C.notify=value=>notices.push(value);C.time=value=>value;
  const data={accounts:[{username:"admin",role:"admin",version:1,created_at:"2026-11-17T00:00:00Z",updated_at:"2026-11-17T01:00:00Z"},{username:"operator",role:"operator",version:1,created_at:"2026-11-17T00:00:00Z",updated_at:"2026-11-17T01:00:00Z"},{username:"viewer",role:"viewer",version:1,created_at:"2026-11-17T00:00:00Z",updated_at:"2026-11-17T01:00:00Z"}],audit:[]};
  let mutation=async()=>({});
  C.request=async(path,options={})=>{calls.push({path,options});if(!options.method){if(path==="/api/accounts")return structuredClone(data.accounts);if(path==="/api/account-audit")return structuredClone(data.audit);}return mutation(path,options);};
  C.initAccounts();
  const id=value=>document.getElementById(value),click=value=>id(value).emit("click").done,submit=value=>id(value).emit("submit").done;
  const global=(name,extra={})=>{const event={preventDefault(){this.prevented=true;},stopPropagation(){this.stopped=true;},...extra};for(const handler of events.get(name)||[])handler(event);return event;};
  const openDetail=name=>root.querySelectorAll("[data-account-username]").find(node=>node.dataset.accountUsername===name).emit("click").done;
  const passwordValues=(prefix,first="account-password-fixture1!",second=first)=>{id(prefix).value=first;id(`${prefix}Confirm`).value=second;};
  return {C,data,calls,errors,notices,redirects,document,root,id,click,submit,global,openDetail,passwordValues,setMutation:fn=>{mutation=fn;},flushClose:()=>{while(closeEvents.length)closeEvents.shift()();},tick:()=>{const pending=[...timers.values()];timers.clear();pending.forEach(handler=>handler());}};
}

test("account home is a compact table with name/role filters and a folded audit",async()=>{
  const h=harness();await h.C.loadAccounts();
  assert.equal(h.id("accountTableRows").children.length,3);assert.equal(h.id("accountTotal").textContent,"전체 3개 · 표시 3개");
  const row=h.id("accountTableRows").children[0];assert.equal(row.children[0].tagName,"th");assert.equal(row.children[0].scope,"row");assert.equal(row.children[2].className,"account-date");
  assert.match(row.children[4].children[0].attributes["aria-label"],/admin.*상세/);
  assert.equal(h.root.querySelectorAll(".account-audit")[0].open,false);assert.match(h.id("accountAuditRows").textContent,/감사 기록이 없습니다/);
  assert.equal(h.root.children.slice(0,2).flatMap(node=>node.querySelectorAll('input[type="password"]')).length,0,"home must not expose password forms");
  h.id("accountSearch").value="VIEW";await h.id("accountSearch").emit("input").done;assert.equal(h.id("accountTableRows").children.length,1);assert.match(h.id("accountTableRows").textContent,/viewer/);
  h.id("accountSearch").value="";h.id("accountRoleFilter").value="operator";await h.id("accountRoleFilter").emit("change").done;assert.equal(h.id("accountTotal").textContent,"전체 3개 · 표시 1개");
  const viewer=harness();viewer.C.session={username:"viewer",role:"viewer"};await viewer.C.loadAccounts();assert.equal(viewer.id("accountAdminPanel").hidden,true);assert.equal(viewer.calls.length,0);assert.match(viewer.id("accountSelfName").textContent,/viewer.*조회자/);
});

test("native dialog cancellation clears secrets and restores focus after inertness ends",async()=>{
  const h=harness();await h.C.loadAccounts();
  for(const action of ["cancel","close","escape","pagehide","hashchange"]){
    await h.click("accountOwnPasswordOpen");assert.equal(h.document.activeElement,h.id("accountCurrentPassword"));
    for(const id of ["accountCurrentPassword","accountNewPassword","accountConfirmPassword"])h.id(id).value="secret-fixture";
    if(action==="cancel")await h.click("accountPasswordDialogCancel");else if(action==="close")await h.click("accountPasswordDialogClose");else if(action==="escape")await h.id("accountPasswordDialog").emit("cancel").done;else h.global(action);
    assert.equal(h.id("accountPasswordDialog").open,false);for(const id of ["accountCurrentPassword","accountNewPassword","accountConfirmPassword"])assert.equal(h.id(id).value,"");
    if(["cancel","close","escape"].includes(action))assert.equal(h.document.activeElement,h.id("accountOwnPasswordOpen"));
    h.flushClose();
  }
  await h.click("accountOwnPasswordOpen");await h.click("accountPasswordDialogCancel");await h.click("accountOwnPasswordOpen");h.id("accountNewPassword").value="NEW_OPEN_FIXTURE";h.flushClose();
  assert.equal(h.id("accountPasswordDialog").open,true);assert.equal(h.id("accountNewPassword").value,"NEW_OPEN_FIXTURE","a queued old close event must not wipe a new opening");
});

test("creation and self password use the shared shorter composition policy",async()=>{
  const h=harness();await h.C.loadAccounts();await h.click("accountCreateOpen");assert.equal(h.document.activeElement,h.id("accountCreateUsername"));
  h.id("accountCreateUsername").value="short-policy";h.passwordValues("accountCreatePassword","Abc123!x");
  h.setMutation(async(path,options)=>{assert.equal(path,"/api/accounts");assert.equal(options.body.password,"Abc123!x");return {};});
  await h.submit("accountCreateForm");assert.equal(h.id("accountCreateDialog").open,false);assert.equal(h.id("accountCreatePassword").value,"");
  await h.click("accountOwnPasswordOpen");h.id("accountCurrentPassword").value="legacy-password-fixture";h.id("accountNewPassword").value="short";h.id("accountConfirmPassword").value="short";
  const count=h.calls.length;await h.submit("accountPasswordForm");assert.equal(h.calls.length,count);assert.match(h.id("accountPasswordDialog").textContent,/8자.*8~9자.*대문자.*1,024 UTF-8/);assert.equal(h.errors.length,0);
  h.id("accountCurrentPassword").value="legacy-password-fixture";h.id("accountNewPassword").value="abcdef12!x";h.id("accountConfirmPassword").value="abcdef12!x";
  h.setMutation(async(path,options)=>{assert.equal(options.body.current_password,"legacy-password-fixture");assert.equal(options.body.password,"abcdef12!x");return {reauthenticate:true};});
  await h.submit("accountPasswordForm");assert.deepEqual(h.redirects,["/login"]);assert.equal(h.C.session,null);
});

test("new password JS and native pattern agree at character and byte boundaries",async()=>{
  const cases=[
    ["Ab1!xyz",false],["Abc123!x",true],["Abcd123!x",true],["abcde12!x",false],["abcdef12!x",true],
    ["ABCDEF12!X",false],["abcdefghi!",false],["abcdef1234",false],["Abc123 x",false],["Ab1! xy ",true],
    ["Abc123😀x",false],["가Ab1!😀😃😄",true],["가a1!b",false],["가나다라마바a1!x",true],
    ["a1!"+"x".repeat(1021),true],["a1!"+"x".repeat(1022),false],
    ["a1!x"+"가".repeat(340),true],["a1!xx"+"가".repeat(340),false],["Abc12!xy\ud800",false]
  ];
  for(let code=0x21;code<=0x7e;code++){
    const special=(code>=0x21&&code<=0x2f)||(code>=0x3a&&code<=0x40)||(code>=0x5b&&code<=0x60)||(code>=0x7b&&code<=0x7e);
    cases.push(["Abc123xx"+String.fromCharCode(code),special]);
  }
  for(const [value,valid] of cases){
    const h=harness();await h.C.loadAccounts();await h.click("accountCreateOpen");h.id("accountCreateUsername").value="policy-case";
    const input=h.id("accountCreatePassword");assert.equal(input.minLength,8);assert.equal(input.maxLength,1024);assert.match(input.title,/소문자.*숫자.*특수문자/);
    const nativeFormat=new RegExp(`^(?:${input.pattern})$`,"v").test(value);
    const bytes=new TextEncoder().encode(value).length;
    assert.equal(nativeFormat&&bytes<=1024,valid,"native new-password format differs");
    h.passwordValues("accountCreatePassword",value);let submitted=false;h.setMutation(async()=>{submitted=true;return {};});
    await h.submit("accountCreateForm");assert.equal(submitted,valid,"JS new-password policy mismatch");
    assert.equal(h.id("accountCreatePassword").value,"");assert.equal(h.id("accountCreatePasswordConfirm").value,"");
    if(!valid)assert.match(h.id("accountCreateDialog").textContent,/8자.*대문자/);
  }
});

test("password reset fields use the same new-password constraints and help",async()=>{
  const h=harness();await h.C.loadAccounts();await h.openDetail("operator");
  for(const name of ["accountResetPassword","accountResetPasswordConfirm"]){assert.equal(h.id(name).minLength,8);assert.match(h.id(name).title,/8~9자/);}
  assert.match(h.id("accountResetForm").textContent,/영문 소문자.*숫자.*특수문자/);
  h.passwordValues("accountResetPassword","Abc123!x");h.id("accountResetConfirm").checked=true;let submitted=false;
  h.setMutation(async(path,options)=>{assert.equal(options.body.password,"Abc123!x");submitted=true;return {account:{...h.data.accounts[1],version:2}};});
  await h.submit("accountResetForm");assert.equal(submitted,true);
});

test("detail operations fold separately and local validation remains editable",async()=>{
  const h=harness();await h.C.loadAccounts();await h.openDetail("operator");
  const operations=h.id("accountDetailDialog").querySelectorAll(".account-detail-operation");assert.equal(operations.length,3);assert.ok(operations.every(item=>!item.open));
  operations[0].open=true;await operations[0].emit("toggle").done;operations[1].open=true;await operations[1].emit("toggle").done;assert.equal(operations[0].open,false);
  await h.submit("accountRoleForm");assert.match(h.id("accountDetailDialog").textContent,/확인에 체크/);assert.ok(h.id("accountDetailDialog").querySelectorAll("fieldset").every(item=>!item.disabled));assert.equal(h.errors.length,0);
  h.id("accountDeleteConfirm").value="wrong";await h.id("accountDeleteConfirm").emit("input").done;assert.equal(h.id("accountDeleteSubmit").disabled,true);
  await h.click("accountDetailDialogCancel");await h.openDetail("admin");assert.equal(h.id("accountRoleForm").children[0].disabled,true);assert.equal(h.id("accountDeleteForm").children[0].disabled,true);
});

test("409 errors stay inside the dialog and reload obtains a new mutation version",async()=>{
  const h=harness();await h.C.loadAccounts();await h.openDetail("operator");h.id("accountRoleConfirm").checked=true;
  h.setMutation(async()=>{const error=new Error("STALE_FIXTURE");error.status=409;throw error;});await h.submit("accountRoleForm");
  assert.match(h.id("accountDetailDialog").textContent,/STALE_FIXTURE/);assert.equal(h.id("accountDetailReload").hidden,false);assert.ok(h.id("accountDetailDialog").querySelectorAll("fieldset").every(item=>item.disabled));
  h.data.accounts[1].version=2;await h.click("accountDetailReload");assert.ok(h.id("accountDetailDialog").querySelectorAll("fieldset").every(item=>!item.disabled));
  h.id("accountRoleConfirm").checked=true;h.id("accountDetailRole").value="viewer";
  h.setMutation(async(path,options)=>{assert.equal(options.body.version,2);h.data.accounts[1]={...h.data.accounts[1],role:"viewer",version:3};return {account:h.data.accounts[1]};});
  await h.submit("accountRoleForm");assert.match(h.id("accountDetailFacts").textContent,/조회자/);assert.equal(h.errors.length,0);
});

test("pending requests allow safe closing without duplicate submits or late form updates",async()=>{
  const h=harness();await h.C.loadAccounts();await h.openDetail("operator");h.passwordValues("accountResetPassword");h.id("accountResetConfirm").checked=true;
  let resolve;h.setMutation(()=>new Promise(done=>{resolve=done;}));const pending=h.submit("accountResetForm");
  assert.equal(h.id("accountResetPassword").value,"");assert.ok(h.id("accountDetailDialog").querySelectorAll("fieldset").every(item=>item.disabled));
  const count=h.calls.length;await h.submit("accountResetForm");assert.equal(h.calls.length,count,"pending submit must be unique");
  await h.click("accountDetailDialogCancel");await h.openDetail("viewer");h.flushClose();
  resolve({account:{...h.data.accounts[1],version:2}});await pending;
  assert.equal(h.id("accountDetailDialog").open,true);assert.match(h.id("accountDetailFacts").textContent,/viewer/);assert.doesNotMatch(h.id("accountDetailDialog").textContent,/비밀번호를 변경하고/);
});

test("deleting from a snapshot restores focus to a connected control",async()=>{
  const h=harness();await h.C.loadAccounts();await h.openDetail("viewer");h.id("accountDeleteConfirm").value="viewer";await h.id("accountDeleteConfirm").emit("input").done;
  h.setMutation(async(path,options)=>{assert.equal(path,"/api/accounts/viewer?version=1");assert.equal(options.method,"DELETE");h.data.accounts=h.data.accounts.filter(account=>account.username!=="viewer");return {};});
  await h.submit("accountDeleteForm");assert.equal(h.id("accountDetailDialog").open,false);assert.equal(h.document.activeElement,h.id("accountSearch"));assert.equal(h.document.activeElement.isConnected,true);
});

test("role help supports hover transit, pinned clicks and Escape inside an open dialog",async()=>{
  const h=harness();await h.C.loadAccounts();await h.click("accountCreateOpen");
  const wrap=h.id("accountCreateDialog").querySelectorAll(".account-help-wrap")[0],control=wrap.children[0],tip=wrap.children[1];
  await wrap.emit("pointerenter").done;assert.equal(tip.hidden,false);assert.ok(Number.parseFloat(tip.style.left)>=8);assert.ok(Number.parseFloat(tip.style.top)>=8);assert.equal(control.attributes["aria-describedby"],tip.id);assert.match(tip.textContent,/관리자.*운영자.*조회자/);
  await wrap.emit("pointerleave").done;await tip.emit("pointerenter").done;h.tick();assert.equal(tip.hidden,false,"pointer must reach the tooltip over its gap");
  await control.emit("click").done;await wrap.emit("pointerleave").done;h.tick();assert.equal(tip.hidden,false,"first click pins an already hovered tooltip");
  const escape=h.global("keydown",{key:"Escape"});assert.equal(escape.prevented,true);assert.equal(escape.stopped,true);assert.equal(tip.hidden,true);assert.equal(h.id("accountCreateDialog").open,true);
  control.focus();assert.equal(tip.hidden,false);h.global("resize");assert.equal(tip.hidden,true);
});

test("a delayed post-save list cannot change a newly opened detail dialog",async()=>{
  const h=harness();await h.C.loadAccounts();await h.openDetail("operator");h.id("accountRoleConfirm").checked=true;h.id("accountDetailRole").value="admin";
  h.setMutation(async()=>{h.data.accounts[1]={...h.data.accounts[1],role:"admin",version:2};return {account:h.data.accounts[1]};});
  const request=h.C.request;let resolveList;
  h.C.request=(path,options={})=>path==="/api/accounts"&&!options.method?new Promise(resolve=>{resolveList=resolve;}):request(path,options);
  const pending=h.submit("accountRoleForm");await new Promise(resolve=>setImmediate(resolve));assert.equal(typeof resolveList,"function");
  assert.equal(h.id("accountRoleForm").children[0].disabled,true,"save remains busy while its list refresh is pending");
  await h.click("accountDetailDialogCancel");await h.openDetail("viewer");h.flushClose();
  resolveList(structuredClone(h.data.accounts));await pending;
  assert.match(h.id("accountDetailFacts").textContent,/viewer/);assert.doesNotMatch(h.id("accountDetailDialog").textContent,/권한을 변경하고 기존 세션을 종료했습니다/);
  await h.click("accountDetailDialogCancel");await h.openDetail("operator");assert.equal(h.id("accountRoleForm").children[0].disabled,false,"a newly added second administrator is not the final administrator");
});
