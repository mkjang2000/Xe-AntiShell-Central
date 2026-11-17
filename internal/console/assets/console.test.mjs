import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = name => fs.readFileSync(new URL(name, import.meta.url), "utf8");
const now = Date.parse("2026-11-17T03:00:00Z");
function model(extra = {}) {
  const context = vm.createContext({structuredClone,URLSearchParams,AbortController,setTimeout,clearTimeout,...extra});
  vm.runInContext(source("model.js"),context);
  context.XEC.now=()=>now;
  return {C:context.XEC,context};
}
const agent = (overrides = {}) => ({agent_id:"web-01",desired_policy_revision:3,heartbeat:{sent_at:"2026-11-17T02:59:50Z",policy_status:{active_revision:3,result:"applied"}},...overrides});

test("delivery activity cannot replace a missing or stale heartbeat",()=>{
  const {C}=model();
  assert.equal(C.connection(agent({heartbeat:null,last_seen_at:"2026-11-17T03:00:00Z"})).key,"unknown");
  assert.equal(C.connection(agent({heartbeat:{sent_at:"2026-11-17T02:00:00Z"},last_seen_at:"2026-11-17T03:00:00Z"})).key,"stale");
  assert.equal(C.connection(agent({revoked:true})).key,"revoked");
  assert.equal(C.connection(agent()).key,"online");
  assert.equal(C.connection(agent({heartbeat:{sent_at:"2026-11-18T02:00:00Z"}})).key,"stale");
});

test("wire-applied policy with pending integrity is not counted fully applied",()=>{
  const {C}=model();
  assert.equal(C.policyState(agent()).applied,true);
  const partial=C.policyState(agent({pending_features:["integrity"]}));
  assert.equal(partial.wireApplied,true);assert.equal(partial.applied,false);assert.match(partial.label,/일부 적용.*무결성 대기/);
  assert.equal(C.policyState(agent({heartbeat:{sent_at:"2026-11-17T01:00:00Z",policy_status:{active_revision:3,result:"applied"}}})).applied,false);
});
test("re-enrollment with reused policy revision cannot reuse an old policy cache entry",()=>{
  const {C}=model(),old=agent({enrollment_id:"enrollment-A"}),current=agent({enrollment_id:"enrollment-B"});
  assert.notEqual(C.policyIdentity(old),C.policyIdentity(current));
  assert.equal(C.policyResponseMatches(current,{policy:{agent_id:"web-01",enrollment_id:"enrollment-A",revision:3}}),false);
  assert.equal(C.policyResponseMatches(current,{policy:{agent_id:"web-01",enrollment_id:"enrollment-B",revision:3}}),true);
  assert.equal(C.policyResponseMatches(current,{policy:{agent_id:"web-01",enrollment_id:"enrollment-B",revision:4}}),false);
  assert.equal(C.policyResponseMatches(current,{policy:null}),false);
});

test("capability support alone never claims active collection or enforcement",()=>{
  const {C}=model();
  assert.equal(C.capability("observation.process_exec",{state:"supported",implementation:"implemented"},true).label,"미확인");
  assert.equal(C.capability("response.terminate",{state:"supported",implementation:"implemented",runtime_state:"available"},true).label,"자동 종료 꺼짐");
  assert.equal(C.capability("response.terminate",{state:"supported",implementation:"implemented",runtime_state:"active"},true).label,"조건부 대응 가능");
});

test("planned, diagnostic and stale capability evidence stay distinct",()=>{
  const {C}=model();
  assert.equal(C.capability("observation.file",{implementation:"planned",runtime_state:"active"},true).label,"미제공");
  assert.equal(C.capability("integrity.tpm",{state:"supported",runtime_state:"active"},true).label,"검증 미제공");
  assert.equal(C.capability("observation.process_exec",{implementation:"implemented",runtime_state:"active"},false).label,"최신 상태 미확인");
  const active=C.capability("observation.process_exec",{state:"supported",implementation:"implemented",runtime_state:"active",runtime_reason:"INTERNAL ENGLISH <script>"},true);
  assert.equal(active.tone,"good");assert.doesNotMatch(active.note,/INTERNAL|script/);
});

test("missing metrics remain unknown while observed zero remains zero",()=>{
  const {C}=model();
  assert.equal(C.percent(null),"미확인");assert.equal(C.bytes(undefined),"미확인");assert.equal(C.rate(null),"미확인");
  assert.equal(C.percent(0),"0.0%");assert.equal(C.bytes(0),"0 B");assert.equal(C.rate(0),"0 B/s");
});

function settings(C) {
  return C.settingsFromValues({detectionEnabled:true,extendedRules:true,webExecutables:"nginx\nphp-fpm",webServices:"nginx.service",shells:"sh\nbash",allowedPairs:"maintenance.service:bash",responseMode:"observe",responseAction:"none",riskThreshold:"90",minConfidence:"0.95",requiredCapabilities:"observation.process_exec\nresponse.terminate",monitoringEnabled:true,sampleInterval:"10",processLimit:"200",uninstallMode:"approval_required",validityHours:"24",integrityEnabled:true,integrityTPM:true,integrityMode:"enforce",integrityPaths:"/usr/sbin/sentineld\n/etc/xe-antishell"});
}
test("complete policy form preserves lists, gates, monitoring and pending integrity",()=>{
  const {C}=model(),s=settings(C);C.validateSettings(s);
  assert.equal(s.detection.extended_process_rules,true);assert.equal(s.detection.web_services[0],"nginx.service");
  assert.equal(s.response.required_capabilities.length,2);assert.equal(s.monitoring.process_limit,200);
  assert.equal(s.integrity.mode,"enforce");assert.equal(s.integrity.require_tpm,true);assert.equal(s.integrity.paths.length,2);
  assert.equal(s.validity_hours,24);assert.equal(s.uninstall_mode,"approval_required");
});
test("unsafe or incomplete non-observe response cannot be previewed from an edited form",()=>{
  const {C}=model(),s=settings(C);s.response.mode="enforce";
  assert.throws(()=>C.validateSettings(s),/종료 동작/);
  s.response.action="terminate";s.response.required_capabilities=[];assert.throws(()=>C.validateSettings(s),/필수 기능/);
  s.response.required_capabilities=["response.terminate"];s.response.risk_threshold=0;assert.throws(()=>C.validateSettings(s),/위험 점수/);
  s.response.risk_threshold=90;s.monitoring.process_limit=2001;assert.throws(()=>C.validateSettings(s),/프로세스 조회 수/);
  s.monitoring.process_limit=200;s.validity_hours=0;assert.throws(()=>C.validateSettings(s),/유효 기간/);
});
test("copying assigned policy preserves every service origin and never mutates source",()=>{
  const {C}=model(),s=settings(C),services=Array.from({length:22},(_,i)=>`service-${i}.service`);
  const policy={...s,detection:{...s.detection,web_services:services},issued_at:"2026-11-17T00:00:00Z",expires_at:"2026-11-18T00:00:00Z"};
  const copy=C.settingsFromPolicy(policy,{integrity:s.integrity});
  assert.equal(copy.detection.web_services.length,22);assert.equal(copy.detection.web_services[21],"service-21.service");
  assert.equal(copy.response.mode,"observe");assert.equal(copy.response.action,"none");assert.equal(copy.integrity.enabled,true);
  copy.detection.web_services.push("new.service");assert.equal(policy.detection.web_services.length,22);
});
test("removal challenge accepts canonical raw or JSON input and validates identity",()=>{
  const {C}=model(),challenge="A".repeat(43);
  assert.equal(C.parseChallenge(challenge,"web-01","enroll-01"),challenge);
  assert.equal(C.parseChallenge(JSON.stringify({operation_id:"operation-01",challenge}),"web-01","enroll-01"),challenge);
  assert.throws(()=>C.parseChallenge(JSON.stringify({agent_id:"other",challenge}),"web-01","enroll-01"),/대상/);
  assert.throws(()=>C.parseChallenge("A".repeat(42)+"B","web-01","enroll-01"),/43자/);
  assert.throws(()=>C.parseChallenge("{oops","web-01","enroll-01"),/JSON 형식/);
});
test("both standalone findings and event bundle findings are surfaced",()=>{
  const {C}=model();assert.equal(C.findings({kind:"finding",payload:{finding_id:"f1"}}).length,1);
  assert.equal(C.findings({kind:"event_bundle",payload:{event:{},findings:[{finding_id:"f2"},{finding_id:"f3"}]}}).length,2);
  assert.equal(C.findings({kind:"event",payload:{}}).length,0);
});

test("mutations include CSRF, same-origin credentials and exact JSON body",async()=>{
  const calls=[],{C}=model({fetch:async(path,options)=>{calls.push({path,options});return {ok:true,status:200,json:async()=>({result:"ok"}),headers:{get:()=>null}};}});
  C.session={csrf_token:"csrf-value"};await C.request("/api/groups",{method:"POST",body:{name:"운영 그룹"}});
  const {options}=calls[0];assert.equal(options.headers["X-CSRF-Token"],"csrf-value");assert.equal(options.credentials,"same-origin");assert.equal(JSON.parse(options.body).name,"운영 그룹");
  await C.request("/api/state");assert.equal(calls[1].options.headers["X-CSRF-Token"],undefined);
});
test("history preserves opaque server cursor for real paging",async()=>{
  const {C}=model({fetch:async()=>({ok:true,status:200,json:async()=>[{id:"one"}],headers:{get:name=>name==="X-Next-Cursor"?"opaque-token":""}})});
  const page=await C.request("/api/history?limit=20",{page:true});assert.equal(page.items.length,1);assert.equal(page.next,"opaque-token");
});

class FakeNode {
  constructor(tag,document){this.tagName=tag;this.document=document;this.children=[];this.textContent="";this.value="";this.checked=false;this.type="";this.handlers={};}
  set innerHTML(_){throw new Error("untrusted HTML insertion");}
  append(...nodes){for(const node of nodes){if(node.tagName==="fragment")this.children.push(...node.children);else this.children.push(node);}}
  replaceChildren(...nodes){this.children=[];this.append(...nodes);}
  querySelectorAll(selector){const all=this.children.flatMap(node=>[node,...(node.querySelectorAll?node.querySelectorAll("*"):[])]);return all.filter(node=>selector==="*"||node.tagName==="input"&&(!selector.includes(":checked")||node.checked));}
  contains(node){return this===node||this.querySelectorAll("*").includes(node);}
  focus(){this.document.activeElement=this;}
  addEventListener(name,callback){this.handlers[name]=callback;}
  setAttribute(){}
  removeAttribute(){}
  scrollIntoView(){}
  showModal(){this.open=true;}
  close(){this.open=false;}
  replaceWith(node){this.document.nodes[this.id]=node;}
}
test("closing issuance dialog clears secret synchronously before native close event",()=>{
  const document={nodes:{},body:{dataset:{page:"console"}},activeElement:null,title:"",createElement(tag){return new FakeNode(tag,this);}};
  document.getElementById=id=>document.nodes[id]||(document.nodes[id]=Object.assign(new FakeNode("div",document),{id}));
  const {C,context}=model({document,Node:FakeNode,location:{hash:"",assign(){}},addEventListener(){}});
  C.initFleet=()=>{};C.initOperations=()=>{};C.initPolicy=()=>{};C.request=()=>new Promise(()=>{});
  vm.runInContext(source("app.js"),context);
  C.showSecret({title:"Test token",text:"sensitive-token",filename:"test.token",facts:[["대상","web-01"]]});
  assert.equal(C.id("secretValue").value,"sensitive-token");
  C.id("secretClose").handlers.click();
  assert.equal(C.id("secretValue").value,"");assert.equal(C.id("secretFacts").children.length,0);assert.equal(C.id("secretDialog").open,false);
});
test("async preview shows server's enforce v2 snapshot when local list still says observe v1",async()=>{
  const document={activeElement:null,createElement(tag){return new FakeNode(tag,this);},createDocumentFragment(){return new FakeNode("fragment",this);}},nodes={};
  document.getElementById=id=>nodes[id]||(nodes[id]=new FakeNode("div",document));
  const {C,context}=model({document,Node:FakeNode});
  const local={id:"ops",name:"로컬 관찰",version:1,settings:settings(C)};
  const actual=structuredClone(local);actual.name="서버 자동 종료";actual.version=2;actual.settings.response.mode="enforce";actual.settings.response.action="terminate";
  C.state.templates=[local];C.checked=id=>id==="deployAgents"?["web-01"]:[];
  let resolveResponse,operation;const response=new Promise(resolve=>{resolveResponse=resolve;});
  C.request=()=>response;C.run=(_button,callback)=>{operation=callback();return operation;};
  vm.runInContext(source("policy.js"),context);C.initPolicy();
  C.id("deployTemplate").value="ops";C.id("templateID").value="ops";C.id("deploymentPreview").hidden=true;
  nodes.previewForm.handlers.submit({preventDefault(){},submitter:new FakeNode("button",document)});
  resolveResponse({preview_token:"bound-to-actual-v2",template:actual,targets:[{agent_id:"web-01",enrollment_id:"enrollment-01",current_revision:2,next_revision:3,warnings:[]}],pending_features:["integrity"]});
  await operation;
  const text=node=>typeof node==="string"?node:node.textContent+node.children.map(text).join("");
  assert.equal(nodes.deploymentPreview.hidden,false);assert.match(text(nodes.previewWarnings),/서버 자동 종료.*v2.*자동 종료/);
  assert.doesNotMatch(text(nodes.previewWarnings),/로컬 관찰|v1/);assert.equal(local.settings.response.mode,"observe");
});
test("preview missing exact server template snapshot fails closed",()=>{
  const {C}=model();assert.throws(()=>C.previewSnapshot({preview_token:"old-server"},"ops"),/실제 배포 정책/);
  assert.throws(()=>C.previewSnapshot({template:{id:"ops",name:"incomplete",version:2,settings:{}}},"ops"),/실제 배포 정책/);
});
test("polling reconciles group choices without losing unsaved selection or keyboard focus",()=>{
  const document={activeElement:null,createElement(tag){return new FakeNode(tag,this);},createDocumentFragment(){return new FakeNode("fragment",this);}},nodes={};
  document.getElementById=id=>nodes[id]||(nodes[id]=new FakeNode("div",document));
  const {C,context}=model({document});vm.runInContext(source("operations.js"),context);
  C.choices("members",[["a","Agent A"],["b","Agent B"]],"member","none",["a"]);
  const inputs=nodes.members.querySelectorAll("input");inputs[0].checked=false;inputs[1].checked=true;inputs[1].focus();
  C.choices("members",[["a","Agent A"],["b","Agent B"],["c","Agent C"]],"member","none");
  assert.deepEqual(Array.from(C.checked("members")),["b"]);assert.equal(document.activeElement.value,"b");
});
test("server and finding text use textContent rather than executable HTML",()=>{
  const document={createElement(tag){return new FakeNode(tag,this);}}, {C}=model({document});
  const node=C.el("p","record-summary",'<img src=x onerror="alert(1)">');
  assert.equal(node.textContent,'<img src=x onerror="alert(1)">');assert.equal(node.children.length,0);
});
test("all login error variants are safe Korean messages",()=>{
  for(const code of ["invalid","rate","origin","request","<script>"]){
    const error={textContent:"",hidden:true},context=vm.createContext({document:{body:{dataset:{page:"login"}},getElementById:()=>error},location:{search:`?error=${encodeURIComponent(code)}`},URLSearchParams});
    vm.runInContext(source("app.js"),context);assert.equal(error.hidden,false);assert.match(error.textContent,/[가-힣]/);assert.doesNotMatch(error.textContent,/<script>/);
  }
});
