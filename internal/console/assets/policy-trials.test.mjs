import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Element {
  constructor(tag,_,text=""){this.tag=tag;this.text=text;this.children=[];this.value="";this.handlers={};}
  append(...items){this.children.push(...items);}
  replaceChildren(...items){this.children=items;}
  addEventListener(name,fn){this.handlers[name]=fn;}
  scrollIntoView(){}
  find(fn){if(fn(this))return this;for(const child of this.children){const match=child?.find?.(fn);if(match)return match;}}
}
function harness(role){
  const nodes=new Map(),calls=[];const request=async(path,options={})=>{
    calls.push({path,body:options.body});if(path==='/api/policy-trials')return {id:'trial-one'};
    if(path.endsWith('/preview'))return {confirmation:'bound-ticket',expires_at:'2026-01-01',targets:['a'],new_revisions:{a:5}};
    if(path.endsWith('/apply'))return {};
    return {trial:{canary:'a',phase:'prepared'},targets:[{agent_id:'a',baseline:4,expected:4,desired:4,active:4,state:'applied'}],template_id:'web',template_version:1};};
  const C={session:{role},id:key=>{if(!nodes.has(key))nodes.set(key,new Element('div'));return nodes.get(key);},el:(...args)=>new Element(...args),button:(text,fn)=>Object.assign(new Element('button','',text),{click:fn}),run:(_,fn)=>fn(),facts:()=>new Element('dl'),table:()=>new Element('table'),time:x=>x,request,confirm:async()=>true};
  vm.runInNewContext(fs.readFileSync(new URL('policy-trials.js',import.meta.url),'utf8'),{XEC:C,URLSearchParams});return {C,calls};
}
test('receipt upload rejects raw events locally and per-stage confirmation refers to the offered ticket',async()=>{
  const {C,calls}=harness('operator');C.policyTrialStart({preview_token:'snapshot',targets:[{agent_id:'a'}]});
  const start=C.id('trialStart');start.find(n=>n.tag==='select').value='a';await start.find(n=>n.tag==='button').click();assert.equal(calls[0].body.canary,'a');
  const view=C.id('trialDetail');view.find(n=>n.tag==='input').files=[{size:100,text:async()=>'{"event_type":"process.exec"}'}];const n=calls.length;
  await assert.rejects(()=>view.find(n=>n.text==='선택 호스트의 결과 등록').click(),/집계/);assert.equal(calls.length,n);
  await view.find(n=>n.text==='한 대 선행 배포 미리보기').click();const mutation=calls.find(x=>x.path.endsWith('/apply'));
  assert.equal(mutation.body.confirmation,'bound-ticket');assert.equal(mutation.body.phase,'prepared');assert.equal(mutation.body.action,'canary');
});
test('viewer starts no trial',()=>{const {C,calls}=harness('viewer');C.policyTrialStart({targets:[]});assert.equal(C.id('trialStart').children.length,0);assert.equal(calls.length,0);});
