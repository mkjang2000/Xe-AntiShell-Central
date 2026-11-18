import test from "node:test";
import assert from "node:assert/strict";
import vm from "node:vm";
import fs from "node:fs";

const code = fs.readFileSync(new URL("central-update.js", import.meta.url), "utf8");
const old = "v0.1.0-r19", next = "v0.1.0-r20";
const installed = {state:"idle", current_version:"0.1.0-19.el9.x86_64"};
const accepted = {state:"queued", current_version:installed.current_version, target:next};
const file = {size:42};
const manifest = {manifest:{schema_version:"1",tag:next,artifact_name:"xe-antishell-central-0.1.0-20.el9.x86_64.rpm",os_major:"9",sha256:"a".repeat(64),size:file.size},key_id:"release-"+"a".repeat(16),signature:"A".repeat(86)+"=="};
const fileOf = o => ({size:JSON.stringify(o).length,text:async()=>JSON.stringify(o)});
function harness(role="admin") {
  const nodes=new Map(), calls=[], prompts=[], timers=new Map();
  const state={current:installed, accepted, confirm:true};
  function node() {
    return {open:true,hidden:false,disabled:false,files:[],value:"",options:[],events:{},textContent:"",
      get selectedOptions(){return this.options.filter(o=>o.value===this.value);},
      addEventListener(type,fn){this.events[type]=fn;}, emit(type){return this.events[type]?.();},
      append(o){this.options.push(o);if(this.options.length===1)this.value=o.value;},
      replaceChildren(...items){this.options=items;this.value="";this.textContent=JSON.stringify(items);}
    };
  }
  const id = name => {if(!nodes.has(name))nodes.set(name,node());return nodes.get(name);};
  const C={id,el:node,text:(name,text)=>{id(name).textContent=text;},array:v=>Array.isArray(v)?v:[],facts:x=>x,
    session:{role},view:"updates",confirm:async prompt=>{prompts.push(prompt);return state.confirm;},
    request:async(path,opts={})=>{
      calls.push({path,opts});
      if(path.endsWith("/status")){if(state.current instanceof Error)throw state.current;return state.current;}
      if(path.endsWith("/releases"))return {items:[{tag:old},{tag:next}]};
      if(state.accepted instanceof Error)throw state.accepted;
      state.current=state.accepted;return state.accepted;
    }};
  vm.runInContext(code,vm.createContext({XEC:C,btoa,addEventListener(){},document:{hidden:false,addEventListener(){}},clearTimeout:key=>timers.delete(key),setTimeout:(fn,ms)=>{const key=Symbol();timers.set(key,{fn,ms});return key;}}));
  C.initCentralUpdate();
  const settle=async()=>{for(let i=0;i<6;i++)await Promise.resolve();};
  return {C,id,state,calls,prompts,timers,settle,open:async()=>{id("centralUpdate").open=true;id("centralUpdate").emit("toggle");await settle();}};
}

test("central updates require an administrator and install nothing on page refresh",async()=>{
  const forbidden=harness("operator");await forbidden.open();
  assert.equal(forbidden.id("centralUpdate").hidden,true);
  await forbidden.id("centralGithubInstall").emit("click");assert.equal(forbidden.calls.length,0);
  const h=harness();await h.open();
  assert.equal(h.id("centralRelease").options[0].disabled,true);
  assert.equal(h.id("centralRelease").value,next);
  assert.equal(h.calls.some(c=>c.opts.method==="POST"),false);
  h.state.confirm=false;await h.id("centralGithubInstall").emit("click");
  assert.equal(h.calls.some(c=>c.opts.method==="POST"),false);
  h.state.confirm=true;await h.id("centralGithubInstall").emit("click");await h.settle();
  const call=h.calls.find(c=>c.opts.method==="POST");
  assert.equal(call.path,"/api/central-update/github");assert.equal(call.opts.body.tag,next);
  assert.equal(call.opts.body.confirm,true);assert.ok(call.opts.timeoutMS>20000);
  assert.equal(h.id("centralGithubInstall").disabled,true);
});

test("central file install forwards a bounded public manifest and streams the selected file",async()=>{
  const h=harness();await h.open();h.id("centralRPM").files=[file];
  h.id("centralManifest").files=[fileOf({...manifest,private_key:"invalid"})];
  await h.id("centralUploadInstall").emit("click");
  assert.equal(h.calls.some(c=>c.opts.method==="POST"),false);
  h.id("centralManifest").files=[fileOf(manifest)];
  await h.id("centralUploadInstall").emit("click");await h.settle();
  const {opts,path}=h.calls.find(c=>c.opts.method==="POST");
  assert.equal(path,"/api/central-update/upload");assert.equal(opts.rawBody,file);
  assert.equal(opts.headers["X-Xeas-Central-Confirm"],"true");
  assert.deepEqual(JSON.parse(Buffer.from(opts.headers["X-Xeas-Central-Manifest"],"base64url")),manifest);
});

test("status polling survives restart and never resubmits the update",async()=>{
  const h=harness();await h.open();
  await h.id("centralGithubInstall").emit("click");await h.settle();
  h.state.current=new Error("disconnected");
  await h.id("centralStatusRefresh").emit("click");
  assert.match(h.id("centralUpdateFacts").textContent,/연결이 복구/);
  assert.equal(h.id("centralUploadInstall").disabled,true);
  h.state.current={...accepted,state:"succeeded",current_version:"0.1.0-20.el9.x86_64"};
  assert.ok([...h.timers.values()].some(t=>t.ms===4000));
  await [...h.timers.values()].at(-1).fn();
  assert.match(h.id("centralUpdateFacts").textContent,/설치 완료/);
  assert.equal(h.calls.filter(c=>c.opts.method==="POST").length,1);
  assert.equal(h.id("centralGithubInstall").disabled,true);
});

test("RPM-only upload requests its matching official signature and never retries an invalid manual signature",async()=>{
  const h=harness();await h.open();
  const rpm={...file,name:manifest.manifest.artifact_name};
  h.id("centralRPM").files=[rpm];h.id("centralRPM").emit("change");
  assert.equal(h.id("centralUploadInstall").disabled,false);
  h.id("centralManifest").files=[fileOf({...manifest,private_key:"invalid"})];
  await h.id("centralUploadInstall").emit("click");assert.equal(h.calls.some(c=>c.opts.method==="POST"),false);
  h.id("centralManifest").files=[];
  await h.id("centralUploadInstall").emit("click");
  const {opts}=h.calls.find(c=>c.opts.method==="POST");
  assert.equal(opts.headers["X-Xeas-Central-Artifact"],rpm.name);
  assert.equal(opts.headers["X-Xeas-Central-Manifest"],undefined);
  assert.equal(opts.rawBody,rpm);
});

test("interrupted update keeps its backup location and requires another confirmation to retry",async()=>{
  const h=harness();
  h.state.current={...installed,state:"interrupted",target:next,backup:"/fixture/previous.tar",detail:"service recovered"};
  h.state.confirm=false;await h.open();
  assert.match(h.id("centralUpdateFacts").textContent,/previous.tar/);
  assert.match(h.id("centralUpdateFacts").textContent,/service recovered/);
  assert.equal(h.id("centralGithubInstall").disabled,false);
  await h.id("centralGithubInstall").emit("click");
  assert.equal(h.prompts.length,1);assert.equal(h.calls.some(c=>c.opts.method==="POST"),false);
});
