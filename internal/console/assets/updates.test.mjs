import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const digest="a".repeat(64),oldPackage={name:"xe-antishell",epoch:0,version:"0.1.0",release:"22.el9",arch:"x86_64"};
const release={id:digest,sha256:digest,package:{...oldPackage,release:"24.el9"},os_family:"rhel",os_major:"9",size:12345,created_at:"2026-11-17T12:00:00Z",uploaded_by:"admin",publisher_verified:true,publisher:{key_id:"release-fixture"},source:"manual"};
const signedManifest={manifest:{schema_version:"1",artifact_name:"xe-antishell-0.1.0-24.el9.x86_64.rpm",package:release.package,os_family:"rhel",os_major:"9",sha256:digest,size:12345,published_at:"2026-11-17T12:00:00Z"},key_id:"release-fixture",signature:"A".repeat(86)};
const manifestFile=(size=12345,value=signedManifest)=>{const text=typeof value==="string"?value:JSON.stringify({...value,manifest:{...value.manifest,size}}),bytes=new TextEncoder().encode(text);return {size:bytes.length,arrayBuffer:async()=>bytes.buffer};};
const settle=async()=>{for(let count=0;count<12;count++)await Promise.resolve();};
function harness(role="admin") {
  const globals={},closeEvents=[],timers=new Map(),calls=[],xhrs=[],notices=[],redirects=[];
  let timerID=0,random=0,document;
  class Node {
    constructor(tag="div"){this.tagName=tag;this.children=[];this.parent=null;this.handlers={};this.attributes={};this.value="";this.text="";this.disabled=false;this.hidden=false;this.open=false;this.checked=false;this.files=[];this.className="";}
    set textContent(value){this.text=String(value);for(const node of this.children)node.parent=null;this.children=[];}
    get textContent(){return this.text+this.children.map(node=>node.textContent).join("");}
    set innerHTML(_){throw new Error("Unsafe HTML insertion");}
    append(...values){for(let node of values){if(typeof node!=="object")node=Object.assign(new Node("#text"),{textContent:node});node.parent=this;this.children.push(node);}}
    prepend(...values){const old=this.children;this.children=[];this.append(...values,...old);}
    replaceChildren(...values){for(const node of this.children)node.parent=null;this.children=[];this.text="";this.append(...values);}
    setAttribute(key,value){this.attributes[key]=String(value);}
    addEventListener(name,handler){(this.handlers[name]??=[]).push(handler);}
    emit(name,extra={}){if(name==="click"&&this.disabled)return Promise.resolve();const event={target:this,currentTarget:this,preventDefault(){},...extra};return Promise.all((this.handlers[name]||[]).map(handler=>handler(event)));}
    contains(node){return node===this||this.children.some(child=>child.contains(node));}
    get isConnected(){return this===document.body||Boolean(this.parent?.isConnected);}
    focus(){if(document.modal&&!document.modal.contains(this))return;document.activeElement=this;}
    showModal(){assert.equal(document.modal,null,"dialogs cannot nest");this.open=true;document.modal=this;}
    close(){this.open=false;if(document.modal===this)document.modal=null;closeEvents.push(()=>this.emit("close"));}
    click(){return this.emit("click");}
    querySelectorAll(selector){return this.children.flatMap(node=>[...(selector==="*"||node.tagName===selector?[node]:[]),...node.querySelectorAll(selector)]);}
  }
  document={body:new Node("body"),activeElement:null,modal:null,hidden:false,handlers:{},createElement:tag=>new Node(tag),createTextNode:value=>Object.assign(new Node("#text"),{textContent:value}),addEventListener(name,handler){(this.handlers[name]??=[]).push(handler);}};
  document.getElementById=id=>[document.body,...document.body.querySelectorAll("*")].find(node=>node.id===id)||null;
  document.body.append(Object.assign(new Node("section"),{id:"view-updates"}));
  class XHR {
    constructor(){this.headers={};this.handlers={};this.upload={handlers:{},addEventListener:(name,handler)=>{this.upload.handlers[name]=handler;}};xhrs.push(this);}
    open(method,path){this.method=method;this.path=path;}
    setRequestHeader(key,value){this.headers[key]=value;}
    addEventListener(name,handler){this.handlers[name]=handler;}
    send(value){this.body=value;}
    abort(){this.aborted=true;this.handlers.abort?.();}
    finish(code,value){this.status=code;this.responseText=typeof value==="string"?value:JSON.stringify(value);this.handlers.load();}
  }
  const context=vm.createContext({document,Node,XMLHttpRequest:XHR,TextEncoder,TextDecoder,btoa:value=>Buffer.from(value,"binary").toString("base64"),Date,URLSearchParams,AbortController,location:{hash:"#updates",assign:value=>redirects.push(value)},crypto:{getRandomValues:bytes=>bytes.fill(++random)},addEventListener:(name,handler)=>{(globals[name]??=[]).push(handler);},setTimeout:handler=>{timers.set(++timerID,handler);return timerID;},clearTimeout:id=>timers.delete(id)});
  for(const name of ["model.js","updates-source.js","updates.js"])vm.runInContext(fs.readFileSync(new URL(name,import.meta.url),"utf8"),context);
  const C=context.XEC;C.view="updates";C.now=()=>Date.parse("2026-11-17T12:00:00Z");C.session={username:role,role,csrf_token:"csrf-fixture"};C.notify=value=>notices.push(value);C.error=error=>notices.push(String(error));
  C.state.groups=[{id:"web",name:"웹 그룹",agent_ids:["server-a","old-server"]}];
  const inventory=[{agent_id:"server-a",enrollment_id:"e1",inventory:{supported:true,enabled:true,installed_package:oldPackage,running_version:"0.1.0",os_family:"rhel",os_major:"9",arch:"x86_64"},received_at:"2026-11-17T12:00:00Z"},{agent_id:"old-server",enrollment_id:"e2",inventory:null}];
  const preview={preview_token:"preview-fixture",expires_at:"2026-11-17T12:05:00Z",release,targets:[{agent_id:"server-a",current_package:oldPackage,eligible:true},{agent_id:"old-server",eligible:false,exclude_reason:"unsupported"}],eligible_count:1,excluded_count:1};
  const rollout={id:"rollout-1",release_id:digest,created_by:"operator",created_at:"2026-11-17T12:00:00Z",concurrency:1,counters:{queued:1,installing:1}};
  const jobs=[{id:"job-1",agent_id:"server-a",state:"queued",terminal:false,current_package:oldPackage,target_package:release.package,observed_package:null,last_report_at:null,error_code:""},{id:"job-2",agent_id:"server-b",state:"installing",terminal:false,current_package:oldPackage,target_package:release.package,last_report_at:"2026-11-17T11:00:00Z",error_code:""}];
  let mutation=async(path)=>path.endsWith("/preview")?structuredClone(preview):path.endsWith("/cancel")?{cancelled:1,installing:1}:path.endsWith("/delete")?{deleted:true}:{rollout:structuredClone(rollout),jobs:structuredClone(jobs)};
  let read=async path=>path.includes("/rollouts/")?{rollout:structuredClone(rollout),jobs:structuredClone(jobs),next:""}:path.includes("/rollouts?")?{items:[structuredClone(rollout)],next:""}:path.includes("/agents?")?{items:structuredClone(inventory),next:"",total:inventory.length}:{items:[structuredClone(release)],max_bytes:64*1024*1024};
  C.request=async(path,options={})=>{calls.push({path,options});return options.method?mutation(path,options):read(path,options);};C.initUpdates();
  const id=value=>document.getElementById(value),click=async value=>{await id(value).emit("click");await settle();},submit=async value=>{await id(value).emit("submit");await settle();};
  const global=name=>{for(const handler of globals[name]||[])handler();};
  return {C,context,document,id,click,submit,global,calls,xhrs,notices,redirects,closeEvents,timers,preview,rollout,jobs,inventory,read:fn=>{read=fn;},mutate:fn=>{mutation=fn;},flushClose:async()=>{while(closeEvents.length)await closeEvents.shift()();},tab:async name=>click("updateTab"+name)};
}

test("release, inventory and outcome lists use dedicated APIs and fixed permission boundaries",async()=>{
  for(const role of ["admin","operator","viewer"]){
    const h=harness(role);await h.C.loadUpdates();
    assert.equal(h.id("updateUploadOpen").disabled,role!=="admin");assert.equal(h.id("updatePrepareOpen").disabled,role==="viewer");
    assert.match(h.id("updateReleaseRows").textContent,/0.1.0-24.el9.x86_64/);assert.match(h.id("updateAgentRows").textContent,/최초 1회 수동 업데이트 필요/);
    assert.match(h.id("updateAgentRows").textContent,/0.1.0-22.el9.x86_64/);assert.match(h.id("updateRolloutRows").textContent,/설치 승인·진행 중/);
    assert.ok(h.calls.every(call=>call.path.startsWith("/api/updates/")));assert.ok(h.calls.every(call=>!call.options.method));
    await h.click("updateUploadOpen");assert.equal(h.id("updateDialog").open,role==="admin");
    if(role!=="admin")await assert.rejects(h.C.uploadRPM({size:12}),/관리자만/);
  }
});

test("raw upload carries bytes, CSRF and bounded timeout without JSON or filename metadata",async()=>{
  const h=harness(),file={size:12345,name:"untrusted-name.rpm"},progress=[];
  const pending=h.C.uploadRPM(file,manifestFile(),value=>progress.push(value));await settle();const xhr=h.xhrs[0];
  assert.equal(xhr.path,"/api/updates/releases");assert.equal(xhr.method,"POST");assert.equal(xhr.timeout,300000);assert.equal(xhr.withCredentials,true);
  assert.equal(xhr.headers["X-CSRF-Token"],"csrf-fixture");assert.equal(xhr.headers["Content-Type"],"application/x-rpm");assert.equal(xhr.body,file);assert.equal(Object.keys(xhr.headers).some(key=>/filename/i.test(key)),false);
  xhr.upload.handlers.progress({lengthComputable:true,loaded:5,total:10});xhr.upload.handlers.progress({lengthComputable:false});assert.deepEqual(progress,[50]);
  xhr.finish(201,{release,duplicate:false});assert.equal((await pending).release.id,digest);
  for(const size of [0,-1,64*1024*1024+1])await assert.rejects(h.C.uploadRPM({size}),/64 MiB/);
  assert.equal(h.xhrs.length,1);
  const duplicate=h.C.uploadRPM(file,manifestFile());await settle();h.xhrs[1].finish(200,{release,duplicate:true});assert.equal((await duplicate).duplicate,true);
});

test("upload errors and partial transport completion never claim registration or installation",async()=>{
  const h=harness(),file={size:12};
  for(const [event,message] of [["timeout",/초과.*등록됐는지/],["abort",/중단.*등록됐는지/],["error",/연결이 끊겼습니다/]]){
    const pending=h.C.uploadRPM(file,manifestFile(file.size));await settle();const xhr=h.xhrs.at(-1);xhr.handlers[event]();await assert.rejects(pending,message);
  }
  const malformed=h.C.uploadRPM(file,manifestFile(file.size));await settle();h.xhrs.at(-1).finish(201,{});await assert.rejects(malformed,/발행자 서명 검증/);
  const nullReply=h.C.uploadRPM(file,manifestFile(file.size));await settle();h.xhrs.at(-1).finish(201,"null");await assert.rejects(nullReply,/발행자 서명 검증/);
  const denied=h.C.uploadRPM(file,manifestFile(file.size));await settle();h.xhrs.at(-1).finish(403,{error:"관리자만 등록할 수 있습니다."});await assert.rejects(denied,error=>error.status===403);
  const expired=h.C.uploadRPM(file,manifestFile(file.size));await settle();h.xhrs.at(-1).finish(401,{error:"재로그인"});await assert.rejects(expired,/재로그인/);assert.deepEqual(h.redirects,["/login"]);
});

test("upload dialog confirms root deployment trust and protects reopened forms from late events",async()=>{
  const h=harness();await h.C.loadUpdates();await h.click("updateUploadOpen");
  assert.equal(h.id("updateDialog").attributes["aria-labelledby"],"updateDialogTitle");assert.equal(h.document.activeElement,h.id("updateDialogTitle"));
  assert.match(h.id("updateDialog").textContent,/root 권한/);h.id("updateRPMFile").files=[{size:12}];h.id("updateManifestFile").files=[manifestFile(12)];
  await h.submit("updateUploadForm");assert.equal(h.xhrs.length,0);assert.match(h.id("updateDialogError").textContent,/체크하세요/);
  h.id("updateUploadConfirm").checked=true;await h.submit("updateUploadForm");assert.equal(h.xhrs.length,1);
  h.xhrs[0].upload.handlers.progress({lengthComputable:true,loaded:12,total:12});assert.match(h.id("updateDialogStatus").textContent,/서버가 RPM을 검증/);assert.doesNotMatch(h.id("updateDialogStatus").textContent,/등록했습니다|설치 성공/);
  await h.click("updateDialogDismiss");assert.equal(h.document.activeElement,h.id("updateUploadOpen"));await h.click("updateUploadOpen");await h.flushClose();
  h.xhrs[0].upload.handlers.progress({lengthComputable:true,loaded:1,total:12});assert.equal(h.id("updateDialogStatus").textContent,"");assert.equal(h.id("updateDialog").open,true);
  h.xhrs[0].finish(201,{release,duplicate:false});await settle();assert.equal(h.id("updateDialogStatus").textContent,"");
  h.id("updateRPMFile").value="private-selection";h.global("pagehide");assert.equal(h.id("updateRPMFile").value,"");assert.equal(h.id("updateDialog").open,false);
});

test("preview shows exclusions, requires root confirmation and keeps request ID stable on retry",async()=>{
  const h=harness("operator");await h.C.loadUpdates();await h.click("updatePrepareOpen");
  assert.equal(h.id("updateConcurrency").value,"1");h.id("update-group-web").checked=true;await h.id("update-group-web").emit("change");
  await h.click("updatePreviewSubmit");assert.match(h.id("updatePreview").textContent,/최초 1회 수동 업데이트 필요/);assert.match(h.id("updatePreview").textContent,/배포 가능1대/);
  const request=h.calls.find(call=>call.path.endsWith("/preview"));assert.equal(request.options.body.release_id,digest);assert.deepEqual(Array.from(request.options.body.group_ids),["web"]);assert.equal(request.options.body.concurrency,1);
  assert.equal(h.id("updateDeploySubmit").disabled,true);h.id("updateDeployConfirm").checked=true;await h.id("updateDeployConfirm").emit("change");assert.equal(h.id("updateDeploySubmit").disabled,false);
  let attempts=0;h.mutate(async(path)=>{if(path.endsWith("/rollouts")){if(++attempts===1)throw new Error("network failure");return {rollout:h.rollout,jobs:h.jobs};}return h.preview;});
  await h.click("updateDeploySubmit");assert.match(h.id("updateDialogError").textContent,/network failure/);await h.click("updateDeploySubmit");
  const confirmed=h.calls.filter(call=>call.path.endsWith("/rollouts")&&call.options.method);assert.equal(confirmed.length,2);assert.equal(confirmed[0].options.body.client_request_id,confirmed[1].options.body.client_request_id);assert.match(confirmed[0].options.body.client_request_id,/^ui-[0-9a-f]{32}$/);
  assert.match(h.id("updateDialogTitle").textContent,/배포 상세/);assert.match(h.id("updateDialog").textContent,/보고 지연/);assert.doesNotMatch(h.id("updateDialog").textContent,/설치 성공/);
});

test("late preview cannot approve changed selections or a newly reopened dialog",async()=>{
  const h=harness();await h.C.loadUpdates();await h.click("updatePrepareOpen");h.id("update-target-server-a").checked=true;await h.id("update-target-server-a").emit("change");
  let resolve;h.mutate(()=>new Promise(done=>{resolve=done;}));const pending=h.id("updatePreviewSubmit").emit("click");await settle();
  h.id("update-group-web").checked=true;await h.id("update-group-web").emit("change");resolve(h.preview);await pending;assert.match(h.id("updateDialogError").textContent,/바뀌었습니다/);assert.equal(h.id("updateDeploySubmit").disabled,true);assert.equal(h.id("updatePreview").textContent,"");
  const second=h.id("updatePreviewSubmit").emit("click");await settle();await h.click("updateDialogDismiss");await h.click("updateUploadOpen");resolve(h.preview);await second;assert.equal(h.id("updateDialogTitle").textContent,"에이전트 RPM 등록");assert.equal(h.id("updateDialogError").hidden,true);
});

test("zero eligibility, expired preview and stale server conflict cannot create jobs",async()=>{
  const h=harness();await h.C.loadUpdates();await h.click("updatePrepareOpen");h.id("update-group-web").checked=true;await h.id("update-group-web").emit("change");
  h.mutate(async()=>({...h.preview,eligible_count:0}));await h.click("updatePreviewSubmit");h.id("updateDeployConfirm").checked=true;await h.id("updateDeployConfirm").emit("change");assert.equal(h.id("updateDeploySubmit").disabled,true);
  h.mutate(async()=>({...h.preview,expires_at:"2026-11-17T11:00:00Z"}));await h.click("updatePreviewSubmit");assert.match(h.id("updateDialogError").textContent,/유효한 대상 미리보기/);assert.equal(h.id("updateDeploySubmit").disabled,true);
  h.mutate(async()=>h.preview);await h.click("updatePreviewSubmit");h.id("updateDeployConfirm").checked=true;await h.id("updateDeployConfirm").emit("change");h.mutate(async()=>{const error=new Error("snapshot changed");error.status=409;throw error;});await h.click("updateDeploySubmit");assert.equal(h.id("updateDeploySubmit").disabled,true);assert.equal(h.id("updatePreview").textContent,"");
});

test("rollout cancellation preserves claimed installs and shows failure stop uncertainty",async()=>{
  const h=harness("operator");await h.C.loadUpdates();await h.tab("rollouts");const detail=h.id("updateRolloutRows").querySelectorAll("button")[0];await detail.emit("click");await settle();
  assert.match(h.id("updateDialog").textContent,/이미 설치 승인을 받은 서버의 설치는 계속/);assert.equal(h.id("updateRolloutCancel").disabled,false);
  await h.click("updateRolloutCancel");assert.equal(h.calls.filter(call=>call.path.endsWith("/cancel")).length,0);
  h.id("updateCancelConfirm").checked=true;await h.click("updateRolloutCancel");assert.match(h.id("updateDialogStatus").textContent,/1대 취소.*1대는 계속/);
  h.rollout.paused=true;h.rollout.stop_reason="interrupted";h.rollout.counters={failed:1,cancelled:1};h.jobs[0]={...h.jobs[0],state:"failed",terminal:true,error_code:"interrupted"};h.jobs[1]={...h.jobs[1],state:"cancelled",terminal:true,error_code:"rollout_stopped",stopped_after_failure:true};
  await h.click("updateDetailRefresh");assert.match(h.id("updateDialog").textContent,/최종 설치 결과 미확인/);assert.match(h.id("updateDialog").textContent,/후속 배포 자동 중지/);assert.match(h.id("updateDialog").textContent,/실제 설치가 멈췄거나 복구됐다는 뜻은 아닙니다/);assert.equal(h.id("updateRolloutCancel").disabled,true);
});

test("independent inventory pagination retains selected IDs and reports unknown metadata as text",async()=>{
  const h=harness();let page=0;h.read(async path=>path.includes("/agents?")?{items:page?[{agent_id:"<img src=x>",inventory:null}]:h.inventory,next:page?"":"next-agent",total:3}:path.includes("/rollouts?")?{items:[],next:""}:{items:[release]});await h.C.loadUpdates();
  await h.click("updatePrepareOpen");h.id("update-target-server-a").checked=true;await h.id("update-target-server-a").emit("change");assert.match(h.id("updateSelectedCount").textContent,/개별 서버 1대/);
  page=1;await h.id("updateTargetPager").children[2].emit("click");await settle();assert.match(h.calls.at(-1).path,/after=next-agent/);assert.match(h.id("updateAgentRows").textContent,/<img src=x>/);assert.match(h.id("updateSelectedCount").textContent,/개별 서버 1대/);
});

test("release deletion is admin-only and version conflicts stay inside the detail dialog",async()=>{
  for(const role of ["admin","operator","viewer"]){
    const h=harness(role);await h.C.loadUpdates();await h.id("updateReleaseRows").querySelectorAll("button")[0].emit("click");await settle();
    if(role!=="admin"){assert.equal(h.id("updateDeleteRelease"),null);continue;}
    await h.click("updateDeleteRelease");assert.equal(h.calls.some(call=>call.path.endsWith("/delete")),false);
    h.id("updateDeleteConfirm").checked=true;h.mutate(async()=>{const error=new Error("진행 중인 배포가 사용 중입니다.");error.status=409;throw error;});await h.click("updateDeleteRelease");
    assert.match(h.id("updateDialogError").textContent,/진행 중인 배포/);assert.equal(h.id("updateDialog").open,true);assert.equal(h.id("updateDeleteRelease").disabled,false);
    assert.equal(h.calls.at(-1).options.body.confirm,true);
  }
});

test("late reports retain the terminal failure and never resume a stopped rollout",async()=>{
  const h=harness();h.rollout.paused=true;h.rollout.stop_reason="interrupted";h.rollout.counters={failed:1};h.jobs.splice(0,h.jobs.length,{...h.jobs[0],state:"failed",terminal:true,error_code:"interrupted",observed_package:release.package,late_report:true,last_report_at:"2026-11-17T12:00:00Z"});
  await h.C.loadUpdates();await h.id("updateRolloutRows").querySelectorAll("button")[0].emit("click");await settle();
  assert.match(h.id("updateDialog").textContent,/최종 설치 결과 미확인/);assert.match(h.id("updateDialog").textContent,/종료 후 늦게 수신/);assert.match(h.id("updateDialog").textContent,/기존 실패·중지 결과나 후속 배포를 다시 진행시키지 않습니다/);
  assert.doesNotMatch(h.id("updateDialog").textContent,/설치 결과 확인1대/);assert.equal(h.id("updateRolloutCancel").disabled,true);assert.equal(h.timers.size,0);
});

test("visible rollout polling preserves confirmation focus and stops on dismissal",async()=>{
  const h=harness();await h.C.loadUpdates();await h.id("updateRolloutRows").querySelectorAll("button")[0].emit("click");await settle();
  h.id("updateCancelConfirm").checked=true;h.id("updateCancelConfirm").focus();assert.equal(h.timers.size,1);
  const callback=[...h.timers.values()][0];h.timers.clear();await callback();assert.equal(h.id("updateCancelConfirm").checked,true);assert.equal(h.document.activeElement,h.id("updateCancelConfirm"));
  await h.id("updateDialog").emit("cancel");assert.equal(h.id("updateDialog").open,false);assert.equal(h.timers.size,0);await h.flushClose();assert.equal(h.id("updateDialog").open,false);
});

test("accepted rollout followed by delayed refresh cannot replace a newer dialog",async()=>{
  const h=harness();await h.C.loadUpdates();await h.click("updatePrepareOpen");h.id("update-group-web").checked=true;await h.id("update-group-web").emit("change");await h.click("updatePreviewSubmit");h.id("updateDeployConfirm").checked=true;await h.id("updateDeployConfirm").emit("change");
  let resolveCatalog;h.read(async path=>path.endsWith("/releases")?new Promise(resolve=>{resolveCatalog=resolve;}):path.includes("/agents?")?{items:h.inventory,next:"",total:2}:{items:[h.rollout],next:""});
  const pending=h.id("updateDeploySubmit").emit("click");await settle();assert.equal(typeof resolveCatalog,"function");await h.click("updateDialogDismiss");await h.click("updateUploadOpen");resolveCatalog({items:[release]});await pending;
  assert.equal(h.id("updateDialogTitle").textContent,"에이전트 RPM 등록");assert.equal(h.id("updateDialog").open,true);
});

test("only strictly public signed manifest fields can enter the upload header",async()=>{
  const h=harness(),pending=h.C.uploadRPM({size:12345},manifestFile());await settle();const xhr=h.xhrs[0];
  const header=xhr.headers["X-XEAS-Release-Manifest"];assert.match(header,/^[A-Za-z0-9_-]+$/);assert.deepEqual(JSON.parse(Buffer.from(header,"base64url").toString("utf8")),signedManifest);
  assert.equal(xhr.headers["Content-Type"],"application/x-rpm");xhr.finish(201,{release,duplicate:false});await pending;
  await h.C.loadUpdates();await h.id("updateReleaseRows").querySelectorAll("button")[0].emit("click");assert.match(h.id("updateDialog").textContent,/중앙 검증 완료 · 에이전트에서 다시 검증/);assert.match(h.id("updateDialog").textContent,/release-fixture/);
});

test("private PEM, private JSON, unknown or duplicate fields never create a request",async()=>{
  const h=harness(),secret="SYNTHETIC_PRIVATE_MARKER",pem=["-----BEGIN ","PRIVATE KEY-----\n",secret,"\n-----END ","PRIVATE KEY-----"].join("");
  const values=[pem,{private_key:secret},{key_id:"public-only",public_key:"PUBLIC_FIXTURE"},{...signedManifest,private_key:secret},{...signedManifest,extra:secret},{...signedManifest,manifest:{...signedManifest.manifest,private_key:secret}},{...signedManifest,signature:"bad"},null,[],`{"key_id":"discarded","key_id":"release-fixture","manifest":${JSON.stringify(signedManifest.manifest)},"signature":"${signedManifest.signature}"}`];
  for(const value of values){const file=typeof value==="string"?manifestFile(12345,value):manifestFile(12345,JSON.stringify(value));await assert.rejects(h.C.uploadRPM({size:12345},file),error=>{assert.doesNotMatch(error.message,new RegExp(secret));assert.match(error.message,/서명된 공개 manifest JSON만/);return true;});}
  assert.equal(h.xhrs.length,0);assert.equal(h.calls.length,0);assert.equal(h.notices.length,0);
});

test("manifest size, UTF-8, metadata binding and page-hide abort fail before transport",async()=>{
  const h=harness();
  for(const manifest of [undefined,{size:16385,arrayBuffer:async()=>new ArrayBuffer(16385)},manifestFile(12344),{size:1,arrayBuffer:async()=>new Uint8Array([255]).buffer},manifestFile(12345,{...signedManifest,manifest:{...signedManifest.manifest,os_major:"10"}})])await assert.rejects(h.C.uploadRPM({size:12345},manifest),/서명된 공개 manifest/);
  let finish;const bytes=new TextEncoder().encode(JSON.stringify(signedManifest)),file={size:bytes.length,arrayBuffer:()=>new Promise(resolve=>{finish=resolve;})};let transport;
  const pending=h.C.uploadRPM({size:12345},file,()=>{},value=>{transport=value;});transport.abort();finish(bytes.buffer);await assert.rejects(pending,/전송을 중단/);assert.equal(h.xhrs.length,0);
});

test("GitHub import is an explicit admin-only fixed-repository lookup and five-minute JSON transfer",async()=>{
  const h=harness();assert.equal(h.calls.some(call=>call.path.includes("github")),false);
  h.read(async()=>({repository:"mkjang2000/Xe-AntiShell",fetched_at:"2026-11-17T12:00:00Z",items:[{tag:"v0.1.0",name:"<img src=x>",published_at:"2026-11-17T12:00:00Z",prerelease:false,manifest_assets:[{name:"xe-antishell.rpm.manifest.json",size:1000}]}]}));
  await h.click("updateGithubOpen");assert.equal(h.calls[0].path,"/api/updates/github/releases");assert.equal(h.id("updateGithubImport").disabled,true);assert.match(h.id("updateDialog").textContent,/중앙의 배포 승인 서명은 별도로/);assert.equal(h.id("updateGithubTag").children[0].textContent.includes("<img src=x>"),true);
  h.id("updateGithubConfirm").checked=true;await h.id("updateGithubConfirm").emit("change");const pending=h.id("updateGithubImport").emit("click");await settle();const xhr=h.xhrs[0];assert.equal(xhr.path,"/api/updates/github/import");assert.equal(xhr.timeout,300000);assert.equal(xhr.headers["X-CSRF-Token"],"csrf-fixture");assert.equal(xhr.headers["Content-Type"],"application/json");assert.deepEqual(JSON.parse(xhr.body),{tag:"v0.1.0",manifest_asset:"xe-antishell.rpm.manifest.json"});
  xhr.finish(200,{release,duplicate:false});await pending;assert.match(h.id("updateDialogStatus").textContent,/발행자 서명을 검증하고 중앙에 등록/);assert.doesNotMatch(h.id("updateDialogStatus").textContent,/설치 성공/);
  for(const role of ["operator","viewer"]){const reader=harness(role);assert.equal(reader.id("updateGithubOpen").disabled,true);await assert.rejects(reader.C.importGithubRelease("v0.1.0","file.json"),/관리자만/);assert.equal(reader.xhrs.length,0);}
});

test("collector result and late metadata never promote an interrupted terminal job",async()=>{
  const h=harness();h.rollout.paused=true;h.rollout.stop_reason="interrupted";h.rollout.counters={failed:1};h.jobs.splice(0,h.jobs.length,{...h.jobs[0],state:"failed",terminal:true,error_code:"interrupted",observed_package:release.package,late_report:true,last_report_at:"2026-11-17T12:00:00Z",collection_check:"verified"});
  await h.C.loadUpdates();await h.id("updateRolloutRows").querySelectorAll("button")[0].emit("click");await settle();assert.match(h.id("updateDialog").textContent,/수집 검증됨/);assert.match(h.id("updateDialog").textContent,/최종 설치 결과 미확인/);assert.doesNotMatch(h.id("updateDialog").textContent,/설치 결과 확인1대/);
  for(const [collection,label] of [["not_applicable","수집기 사용 안 함 · 해당 없음"],["failed","수집 검증 실패"],["future","수집 검증 미확인"]]){h.jobs[0].collection_check=collection;await h.click("updateDetailRefresh");assert.ok(h.id("updateDialog").textContent.includes(label));}
});

test("unverified publisher evidence cannot become a deployable release",async()=>{
  const h=harness();h.read(async path=>path.endsWith("/releases")?{items:[{...release,publisher_verified:false,publisher:null}],publisher_keys:["release-fixture"]}:path.includes("/agents?")?{items:h.inventory,total:2}:{items:[]});await h.C.loadUpdates();assert.match(h.id("updateReleaseRows").textContent,/서명 확인 안 됨/);assert.equal(h.id("updateReleaseRows").querySelectorAll("button")[1].disabled,true);assert.match(h.id("updatePublisherKeys").textContent,/내장 발행자 키: release-fixture/);
  await h.click("updatePrepareOpen");h.id("update-group-web").checked=true;await h.id("update-group-web").emit("change");await h.click("updatePreviewSubmit");assert.match(h.id("updateDialogError").textContent,/발행자 서명이 확인된 릴리즈/);assert.equal(h.calls.some(call=>call.path.endsWith("/preview")),false);
});
