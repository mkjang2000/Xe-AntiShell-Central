import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Node {
  constructor(tag="div"){this.tagName=tag;this.children=[];this.value="";this.handlers={};this.attributes={};this.textContent="";}
  append(...nodes){this.children.push(...nodes);}
  replaceChildren(...nodes){this.children=[...nodes];}
  addEventListener(name,callback){this.handlers[name]=callback;}
  setAttribute(name,value){this.attributes[name]=value;}
  removeAttribute(name){delete this.attributes[name];}
  set innerHTML(_){throw new Error("Unsafe HTML insertion");}
}
function harness(request=async()=>({items:[],next:""})) {
  const nodes={},document={createElement:tag=>new Node(tag),getElementById:id=>nodes[id]??(nodes[id]=new Node()),createDocumentFragment:()=>new Node("fragment")};
  const context=vm.createContext({URLSearchParams,Date,Node,document,location:{hash:""},structuredClone,AbortController,crypto:globalThis.crypto,TextEncoder,setTimeout,clearTimeout});
  for(const name of ["model.js","finding-reviews.js","history.js"])vm.runInContext(fs.readFileSync(new URL(name,import.meta.url),"utf8"),context);
  const C=context.XEC;C.now=()=>Date.parse("2026-11-17T12:00:00Z");C.request=request;C.error=error=>{C.lastError=String(error);};C.id("historyKind").value="detections";C.id("historyPeriod").value="7d";C.initHistory();
  const text=node=>typeof node==="string"?node:(node.textContent||"")+node.children.map(text).join("");
  return {C,nodes,context,text};
}
test("history query applies dates and search on the server with an opaque cursor",()=>{
  const {C}=harness(),query=C.historyQuery({view:"events",agent:" server-a ",type:" process.exec ",search:" bash ",from:"2026-11-10T00:00",until:"2026-11-17T00:00"},"opaque/page+cursor");
  assert.equal(query.get("view"),"events");assert.equal(query.get("agent_id"),"server-a");assert.equal(query.get("q"),"bash");assert.equal(query.get("type"),"process.exec");assert.equal(query.get("before"),"opaque/page+cursor");assert.equal(query.get("from"),new Date("2026-11-10T00:00").toISOString());
  assert.throws(()=>C.historyQuery({view:"events",agent:"",type:"",search:"",from:"bad",until:""}),/날짜/);
  assert.throws(()=>C.historyQuery({view:"events",agent:"",type:"",search:"",from:"2026-11-17T00:00",until:"2026-11-10T00:00"}),/종료/);
});
test("visible history tabs select separate APIs and clear type search while keeping the agent",async()=>{
  const calls=[],{C,nodes}=harness(async path=>{calls.push(path);return {items:[],next:""};});
  C.id("historyAgent").value="agent-a";C.id("historyType").value="rule.old";C.id("historySearch").value="old";
  await nodes.historyTaberrors.handlers.click();await Promise.resolve();
  assert.equal(C.id("historyKind").value,"errors");assert.equal(C.id("historyType").value,"");assert.equal(C.id("historySearch").value,"");assert.equal(C.id("historyAgent").value,"agent-a");assert.match(calls[0],/^\/api\/errors\?/);assert.equal(nodes.historyTaberrors.attributes["aria-pressed"],"true");assert.equal(nodes.historyTabdetections.attributes["aria-pressed"],"false");
  C.id("historyKind").value="events";await C.loadHistory(true);assert.match(calls[1],/view=events/);
});
test("a delayed prior response cannot mix findings into the error tab",async()=>{
  let resolveFirst;const {C,text}=harness(path=>path.startsWith("/api/errors")?Promise.resolve({items:[{agent_id:"a",kind:"agent",transition:"occurred",category:"storage_order",recorded_at:"2026-11-17T12:00:00Z"}],next:""}):new Promise(resolve=>{resolveFirst=resolve;}));
  const old=C.loadHistory(true);C.id("historyKind").value="errors";await C.loadHistory(true);resolveFirst({items:[{agent_id:"a",kind:"finding",payload:{summary:"OLD_FINDING"}}],next:""});await old;
  assert.match(text(C.id("historyRows")),/프로세스 관측 시각 순서 오류/);assert.doesNotMatch(text(C.id("historyRows")),/OLD_FINDING/);assert.match(text(C.id("historyRows")),/현재 에이전트 상세/);
});
test("changing filters clears results before a failed new request",async()=>{
  let fail=false;const {C,text}=harness(async()=>{if(fail)throw new Error("network failure");return {items:[{agent_id:"a",kind:"finding",payload:{summary:"PREVIOUS_FINDING"}}],next:""};});
  await C.loadHistory(true);assert.match(text(C.id("historyRows")),/PREVIOUS_FINDING/);fail=true;C.id("historyKind").value="errors";await C.loadHistory(true);assert.doesNotMatch(text(C.id("historyRows")),/PREVIOUS_FINDING/);assert.match(C.lastError,/network failure/);
});

test("execution and collection history includes typed operation filters and metadata",async()=>{
  const records=[
    {event_type:"process.exec_observation",execution:{runtime:"python",mode:"inline",option:"-c",evidence:"tetragon_policy",code:"SECRET_SOURCE"}},
    {event_type:"process.exec",execution:{runtime:"php",mode:"script",evidence:"exact_argv",script_location:"fd"}},
    {event_type:"file.write",file:{path:"/tmp/<img>",outcome:"written",return_value:12,function:"vfs_write"}},
    {event_type:"network.connect",network:{protocol:"tcp",family:"ipv6",destination_address:"::1",destination_port:443,outcome:"initiated",return_value:0,function:"tcp_v6_connect"}}
  ];
  const {C,text}=harness(async()=>({items:records.map((payload,index)=>({kind:"event",agent_id:"a",payload:{event_id:`e-${index}`,process:{exe:"/usr/bin/php",pid:42},...payload}})),next:""}));
  C.id("historyKind").value="events";await C.loadHistory(true);
  const values=C.id("historyTypes").children.map(node=>node.value);
  for(const value of ["process.exec","process.exit","process.exec_observation","file.write","network.connect"])assert.ok(values.includes(value));
  assert.equal(C.id("historyTypes").children.find(node=>node.value==="network.connect").label,"TCP 연결 요청 관측");
  const cards=C.id("historyRows").children,visible=cards.map(card=>card.children.filter(node=>node.tagName!=="details").map(text).join(" ")).join(" ");
  assert.match(visible,/실행 옵션 관측/);assert.match(visible,/전용 수집 정책의 실행 옵션 조건/);assert.match(visible,/파일 디스크립터 경로/);
  assert.match(visible,/파일 쓰기 관측/);assert.match(visible,/원래 반환값12/);assert.match(visible,/\/tmp\/<img>/);
  assert.match(visible,/TCP 연결 요청 관측/);assert.match(visible,/원래 반환값0/);assert.match(visible,/IPv6/);assert.match(visible,/::1/);assert.match(visible,/연결 완료/);
  assert.doesNotMatch(visible,/SECRET_SOURCE|연결 완료했습니다|통신 성공|ESTABLISHED/);
  assert.match(text(C.id("historyScope")),/기존 프로세스 내부 코드 실행을 보장하지 않습니다/);
  for(const card of cards)assert.notEqual(card.children.at(-1).open,true,"original evidence remains collapsed");
  C.id("historyType").value="file.write";assert.equal(C.historyQuery({view:"events",agent:"a",type:"file.write",search:"",from:"",until:""}).get("type"),"file.write");
});

test("return values preserve absent, zero, error and conservative unknown distinctions",()=>{
  const {C}=harness();
  const field=(copy,name)=>copy.fields.find(entry=>entry[0]===name)?.[1];
  for(const [outcome,result,expected] of [["written",5,"쓰기 바이트 수 보고"],["no_data",0,"쓴 데이터 없음"],["failed",-13,"실패"],["unknown",null,"결과 미확인"]]){
    const copy=C.eventObservation({event_type:"file.write",file:{outcome,return_value:result}});
    assert.equal(field(copy,"쓰기 결과"),expected);assert.equal(field(copy,"원래 반환값"),result===null?"미수집":String(result));
    assert.match(field(copy,"반환값 의미"),/디스크 반영 여부는 별도 확인/);
  }
  for(const [outcome,result] of [["initiated",0],["failed",-111],["unknown",undefined]]){
    const copy=C.eventObservation({event_type:"network.connect",network:{outcome,return_value:result}});
    assert.equal(field(copy,"원래 반환값"),result===undefined?"미수집":String(result));assert.match(copy.summary,/연결 완료/);
  }
  const bad=C.eventObservation({event_type:"network.connect",network:{outcome:"constructor",return_value:"0",destination_port:0}});
  assert.match(bad.summary,/확인할 수 없습니다/);assert.equal(field(bad,"원래 반환값"),"정확한 값 미확인");assert.equal(field(bad,"대상 포트"),"미확인");
  assert.equal(C.eventObservation({event_type:"process.exit",file:{path:"WRONG_TYPE"}}).fields.length,0);
  const code=C.eventObservation({event_type:"process.exec",execution:{runtime:"__proto__",mode:"inline",evidence:"constructor",option:"SECRET_CODE",code:"SECRET_SOURCE"}});
  assert.doesNotMatch(JSON.stringify(code),/SECRET_CODE|SECRET_SOURCE/);assert.equal(field(code,"관측 근거"),"미확인");
});

test("inline and temporary script findings show request evidence and detection-only scope",async()=>{
  const {C,text}=harness(async()=>({items:["web-descendant-inline-interpreter","web-descendant-temporary-script"].map(rule_id=>({kind:"finding",agent_id:"a",payload:{rule_id,severity:"high",risk_score:70,detection_only:true,summary:"RAW_OLD_SUMMARY"}})),next:""}));
  await C.loadHistory(true);
  const visible=C.id("historyRows").children.map(card=>card.children.filter(node=>node.tagName!=="details").map(text).join(" ")).join(" ");
  assert.match(visible,/직접 코드 실행 요청/);assert.match(visible,/임시 경로의 스크립트 실행 요청/);assert.match(visible,/실행 성공 여부는 확인하지 않습니다/);
  assert.match(visible,/자동 종료 대상에 포함되지 않습니다/);assert.match(visible,/악성 확률이 아닙니다/);assert.doesNotMatch(visible,/RAW_OLD_SUMMARY/);
});

test("finding review targets the selected bundle item and retries one decision after a lost response",async()=>{
  const ref={source:"event_bundle",item:2}, posts=[],calls=[];
  let role="operator";
  const {C,text}=harness(async(path,options={})=>{
    calls.push(path);
    if(options.method==="POST"){
      posts.push(options.body);
      if(posts.length===1)throw new Error("connection interrupted");
      return {version:1};
    }
    const q=new URL(path,"http://localhost").searchParams;
    assert.equal(q.get("item"),"2");assert.equal(q.get("record_id"),"bundle");
    return {finding:{finding_id:"second",rule_id:"file",policy_revision:11},latest_version:posts.length>=2?1:0,items:[]};
  });
  const create=()=>{C.session={role};return C.findingReviews({agent_id:"agent",id:"bundle",finding_location:ref});};
  const find=(node,tag)=>node.tagName===tag?node:node.children?.map(child=>find(child,tag)).find(Boolean);
  const box=create();assert.equal(calls.length,0);box.open=true;await box.handlers.toggle();
  const form=find(box,"form");find(form,"select").value="normal";find(form,"textarea").value="관리자 승인";
  await form.handlers.submit({preventDefault(){}});assert.match(text(box),/connection interrupted/);
  await form.handlers.submit({preventDefault(){}});assert.equal(posts[0].request_id,posts[1].request_id);
  assert.deepEqual(JSON.parse(JSON.stringify(posts[1].target)),{agent_id:"agent",record_id:"bundle",...ref});
  assert.equal(posts[1].expected_version,0);assert.match(text(box),/기록했습니다/);
  role="viewer";const view=create();view.open=true;await view.handlers.toggle();assert.equal(find(view,"form"),undefined);
});
