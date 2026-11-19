import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = name => fs.readFileSync(new URL(name, import.meta.url), "utf8");
const plain = value => JSON.parse(JSON.stringify(value));
class Element {
  constructor(tag) { this.tagName=tag; this.children=[]; this.events={}; this.attrs={}; this.value=""; this.textContent=""; this.hidden=false; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children=nodes; }
  addEventListener(event,fn) { this.events[event]=fn; }
  fire(event) { return this.events[event]?.({preventDefault(){}}); }
  setAttribute(name,value) { this.attrs[name]=value; }
  focus() {}
  set innerHTML(_) { throw new Error("unsafe HTML"); }
}
const walk = node => typeof node === "string" ? node : node.textContent+node.children.map(walk).join(" ");
const settings = {detection:{enabled:true,web_services:["nginx.service"],shells:["sh"]},response:{mode:"observe",risk_threshold:90,min_confidence:.95}};
const ref = {service:"nginx.service",policy_id:"app",policy_version:2};
const saved = {...ref,...settings};
function harness() {
  const nodes=new Map(), document={createElement:tag=>new Element(tag),getElementById(id){ if (!nodes.has(id)) nodes.set(id,new Element("div")); return nodes.get(id); }};
  const ctx=vm.createContext({document,Node:Element,structuredClone,URLSearchParams});
  for(const file of ["model.js","application-policies.js","applied-policies.js","policy-usage.js"]) vm.runInContext(source(file),ctx);
  const C=ctx.XEC; C.now=()=>Date.parse("2026-11-19T12:00:00Z"); C.session={role:"operator"};
  C.options=(id,entries)=>{const n=C.id(id); n.entries=entries; if(!entries.some(([v])=>v===n.value))n.value="";};
  C.state.templates=[{id:"app",name:"웹 정책",version:2,settings},{id:"host",name:"호스트",version:1,settings:{...settings,application_bindings:[ref]}}];
  C.id("templateID").value="host"; C.id("responseMode").value="observe"; C.applicationBindings.init(()=>{}); C.applicationBindings.load({});
  return C;
}
test("mapping selects a whole policy version, rejects conflicts and retains a superseded pin",()=>{
  const C=harness(), id=C.id;
  const add=service=>{id("appBindingService").value=service;id("appBindingSource").value='["app",2]';id("appBindingAdd").fire("click");};
  assert.deepEqual(plain(id("appBindingSource").entries.map(x=>x[0])),['["app",2]']);
  add("*.service"); assert.match(id("appBindingError").textContent,/정확한/);
  add("nginx.service"); assert.deepEqual(plain(C.applicationBindings.read()),{application_bindings:[ref]});
  add("nginx.service");assert.match(id("appBindingError").textContent,/이미 연결/);
  id("appBindingCancel").fire("click");id("responseMode").value="enforce";assert.throws(()=>C.applicationBindings.read(),/observe/);
  id("responseMode").value="observe";C.state.templates[0].version=3;
  C.applicationBindings.load({application_bindings:[ref],applications:[saved]});
  assert.match(walk(id("appBindingRows")),/v2.*최신 버전 v3/);
  assert.deepEqual(plain(C.applicationBindings.read()),{application_bindings:[ref]});
  C.state.templates=[];C.applicationBindings.render();assert.match(walk(id("appBindingRows")),/원본 정책이 목록에 없음/);
  const row=id("appBindingRows").children[0];
  const remove=row.children.at(-1).children.find(button=>button.textContent==="해제");remove.fire("click");
  assert.deepEqual(plain(C.applicationBindings.read()),{application_bindings:[]});
  C.applicationBindings.load({});assert.deepEqual(plain(C.applicationBindings.read()),{});
});
test("exact applied evidence is independent from desired and legacy never proves an application policy",()=>{
  const C=harness(), status={result:"applied",active_revision:4,policy_sha256:"a".repeat(64)};
  const a={agent_id:"agent",enrollment_id:"enrollment",desired_policy_revision:5,heartbeat:{agent_id:"agent",enrollment_id:"enrollment",sent_at:"2026-11-19T12:00:00Z",policy_status:status}};
  const p={agent_id:"agent",enrollment_id:"enrollment",policy_id:"host",revision:5,expires_at:"2026-11-20T12:00:00Z",applications:[saved],...settings};
  const applied={...p,revision:4};
  const view=(state,policy=applied)=>walk(C.agentApplicationPolicies(a,{policy:p,applied_policy:policy,application_status:{state,active_revision:4,desired_revision:5}}));
  assert.match(view("previous"),/이전 리비전 적용 확인.*호스트 적용 정책 · 리비전 4/s);
  assert.doesNotMatch(view("legacy_previous"),/호스트가 보고한 리비전의 정책/);
  assert.match(view("legacy_previous",{...applied,applications:[]}),/리비전 보고 · 해시 미보고/);
  assert.doesNotMatch(view("previous",{...applied,enrollment_id:"other"}),/호스트 적용 정책/);
  const first=C.policyIdentity(a);a.heartbeat.policy_status.active_revision=5;assert.notEqual(C.policyIdentity(a),first);
  const second=C.policyIdentity(a);a.heartbeat.sent_at="2026-11-19T12:00:01Z";assert.equal(C.policyIdentity(a),second);
});
test("usage pagination supports empty scan windows and always reads the selected immutable request",async()=>{
  const C=harness(), calls=[];C.initPolicyUsage();C.id("templateUsage").open=true;
  C.request=async url=>{calls.push(url);return calls.length===1?{items:[],next_after:"a"}:{items:[{agent_id:"b",desired_revision:3,bindings:[ref],application_status:{state:"previous"}}]};};
  C.selectPolicyUsage("app",2);await new Promise(r=>setImmediate(r));
  assert.equal(C.id("templateUsageNext").disabled,false);
  C.id("templateUsageNext").fire("click");await new Promise(r=>setImmediate(r));
  assert.match(calls[1],/after=a/);assert.match(walk(C.id("templateUsageReport")),/nginx.service/);
});
