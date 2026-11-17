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
  set innerHTML(_){throw new Error("Unsafe HTML insertion");}
}
function harness(request=async()=>({items:[],next:""})) {
  const nodes={},document={createElement:tag=>new Node(tag),getElementById:id=>nodes[id]??(nodes[id]=new Node()),createDocumentFragment:()=>new Node("fragment")};
  const context=vm.createContext({URLSearchParams,Date,Node,document,location:{hash:""},structuredClone,AbortController,setTimeout,clearTimeout});
  for(const name of ["model.js","history.js"])vm.runInContext(fs.readFileSync(new URL(name,import.meta.url),"utf8"),context);
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
