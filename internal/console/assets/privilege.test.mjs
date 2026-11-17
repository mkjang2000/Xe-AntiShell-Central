import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

function model() {
 const context=vm.createContext({structuredClone,URLSearchParams,AbortController,setTimeout,clearTimeout});
 for(const name of ["model.js","privilege.js"])vm.runInContext(fs.readFileSync(new URL(name,import.meta.url),"utf8"),context);
 return context.XEC;
}
const text=value=>JSON.stringify(value);
const settings=C=>C.settingsFromValues({detectionEnabled:true,webExecutables:"nginx",shells:"sh",responseMode:"observe",responseAction:"none",riskThreshold:"90",minConfidence:"0.95",monitoringEnabled:true,sampleInterval:"10",processLimit:"200",uninstallMode:"approval_required",validityHours:"24",integrityMode:"observe"});
function credentialEvent() {
 const snapshot=euid=>({uid:1000,euid,suid:1000,fsuid:1000,gid:1000,egid:1000,sgid:1000,fsgid:1000,capabilities:{effective:euid===0?["CAP_SETUID"]:[],permitted:["CAP_SETUID"],inheritable:[]},user_namespace:{inum:10,is_host:true,level:0}});
 return {event_type:"process.credential_change",source:"tetragon",boot_id:"boot",event_time:"2026-11-18T01:00:01Z",process:{pid:22,tid:23,exec_id:"exec",start_time:"2026-11-18T01:00:00Z"},credential:{before:snapshot(1000),after:snapshot(0),tgid:22,tid:23,task_start_time_ns:"9007199254740993",return_value:0,outcome:"applied",function:"commit_creds",evidence:"tetragon_commit_creds_pair",policy_name:"xeas-credential-change-v1"}};
}
const renderedFields=(C,event)=>new Map(C.eventObservation(event).fields);

test("old policy edits omit privilege fields and root-only opt-in validates",()=>{
 const C=model(),old=settings(C);
 assert.equal(Object.hasOwn(old.detection,"privilege_rules"),false);
 assert.equal(Object.hasOwn(old.detection,"root_exec_alerts"),false);
 const root=structuredClone(old);root.detection={...root.detection,privilege_rules:true,root_exec_alerts:"suspicious",web_executables:[],shells:[]};
 assert.equal(C.validateSettings(root),root);
 root.detection.root_exec_alerts="all";assert.equal(C.validateSettings(root),root);
 root.detection.privilege_rules=false;assert.throws(()=>C.validateSettings(root),/root 실행 경보/);
 const invalid=structuredClone(old);invalid.detection.privilege_rules="true";assert.throws(()=>C.validateSettings(invalid),/root 실행 경보/);
});

test("privilege engine support is separate from a credential event receipt",()=>{
 const C=model(),cap={state:"supported",implementation:"implemented",runtime_state:"available",details:{contract:"1"}};
 const copy=C.capability("detection.privilege_rules",cap,true);
 assert.equal(copy.label,"엔진 지원 보고");assert.match(copy.note,/센서의 실제 이벤트 수신.*아닙니다/);
 assert.equal(C.capability("detection.privilege_rules",{...cap,details:{contract:"2"}},true).label,"엔진 지원 미확인");
 assert.equal(C.capability("detection.privilege_rules",cap,false).label,"최신 상태 미확인");
});

test("credential observation preserves zero, unknown, namespace and bounded capability distinctions",()=>{
 const C=model(),e=credentialEvent(),after=e.credential.after;e.credential.payload="SECRET";
 const rendered=C.eventObservation(e),all=text(rendered);
 assert.match(all,/1000 → 0/);assert.match(all,/적용 확인 보고/);assert.match(all,/초기 사용자 namespace.*컨테이너/);assert.doesNotMatch(all,/SECRET/);
 assert.deepEqual(Array.from(rendered.fields.find(([label])=>label==="추가 effective")),["추가 effective","CAP_SETUID"]);
 const unknown=C.eventObservation({event_type:e.event_type,credential:{after,outcome:"unknown"}});
 assert.match(text(unknown),/미수집 → 0/);assert.equal(unknown.fields.find(([label])=>label==="추가 effective")[1],"미수집");assert.match(text(unknown),/적용 여부 미확인/);
 const inconsistent=C.eventObservation({event_type:e.event_type,credential:{after,outcome:"applied",return_value:0}});assert.match(text(inconsistent),/적용 여부 미확인/);
 after.user_namespace={inum:12,is_host:false};assert.match(text(C.eventObservation(e)),/호스트 root와 동일시하지 않음/);
 after.user_namespace={inum:12};assert.match(text(C.eventObservation(e)),/범위 미확인/);
 after.capabilities={effective:["<script>"],permitted:[]};assert.doesNotMatch(text(C.eventObservation(e)),/<script>/);
});

test("only an exact missing-scope advisory preserves a complete unknown-scope pair",()=>{
 const C=model(),advisory=credentialEvent();
 delete advisory.credential.before.user_namespace.is_host;delete advisory.credential.after.user_namespace.is_host;
 advisory.missing_fields=["credential.user_namespace_scope"];
 const fields=renderedFields(C,advisory);
 assert.equal(fields.get("적용 결과"),"적용 확인 보고");assert.equal(fields.get("추가 effective"),"CAP_SETUID");
 assert.equal(fields.get("변경 후 사용자 namespace"),"범위 미확인");assert.match(C.eventObservation(advisory).summary,/같은 커널 호출/);
 for(const mutate of [
  e=>{e.missing_fields=["credential.user_namespace_scope.extra"];},
  e=>{e.missing_fields.push("credential.before.euid");},
  e=>{e.missing_fields.push("credential.before.capabilities");},
  e=>{e.missing_fields=["credential"];},
  e=>{e.redacted_fields=["credential.user_namespace_scope"];},
  e=>{e.truncated_fields=["credential.user_namespace_scope"];},
  e=>{e.redacted_fields=["credential.after.capabilities.effective"];},
  e=>{e.missing_fields.push("process.exec_id");},
  e=>{e.credential.before.user_namespace.inum=0;},
  e=>{e.credential.before.user_namespace.is_host=true;e.credential.after.user_namespace.is_host=true;},
 ]){
  const event=structuredClone(advisory);mutate(event);const value=renderedFields(C,event);
  assert.equal(value.get("적용 결과"),"적용 여부 미확인");assert.equal(value.get("추가 effective"),"미수집");
  assert.match(C.eventObservation(event).summary,/정확한 이전→이후.*단정하지 않습니다/);
 }
 const missingID=structuredClone(advisory);missingID.missing_fields.push("credential.after.euid");
 assert.equal(renderedFields(C,missingID).get("변경 전 → 후 EUID"),"1000 → 미수집");
 const hiddenCaps=structuredClone(advisory);hiddenCaps.redacted_fields=["credential.after.capabilities"];
 assert.equal(renderedFields(C,hiddenCaps).get("이후 effective / permitted"),"미수집 / 미수집");
});

test("credential application and capability differences require complete same-task proof",()=>{
 const C=model();
 for(const mutate of [
  e=>{delete e.credential.before;},e=>{delete e.credential.before.capabilities.inheritable;},
  e=>{e.credential.after.capabilities.effective.push("CAP_SETUID");},
  e=>{e.credential.before.user_namespace.level=1;},e=>{e.credential.after.user_namespace.inum=4294967296;},
  e=>{e.process.tid=99;},e=>{e.process.pid=99;},e=>{e.credential.evidence="cached_exec";},
  e=>{e.source="audit";},e=>{delete e.boot_id;},e=>{delete e.process.exec_id;},
  e=>{e.event_time="0001-01-01T00:00:00Z";},e=>{e.process.start_time="invalid";},
  e=>{e.credential.return_value=null;},e=>{e.credential.task_start_time_ns=9007199254740992;},
 ]){
  const event=credentialEvent();mutate(event);const fields=renderedFields(C,event);
  assert.equal(fields.get("적용 결과"),"적용 여부 미확인");assert.equal(fields.get("추가 effective"),"미수집");
 }
 const unknown=credentialEvent();delete unknown.credential.after.user_namespace.is_host;
 assert.equal(renderedFields(C,unknown).get("적용 결과"),"적용 확인 보고");
 assert.equal(renderedFields(C,unknown).get("변경 후 사용자 namespace"),"범위 미확인");
 const failed=credentialEvent();failed.credential.return_value=-1;failed.credential.outcome="failed";
 assert.equal(renderedFields(C,failed).get("적용 결과"),"호출 실패 보고");assert.equal(renderedFields(C,failed).get("추가 effective"),"미수집");
});

test("new privilege findings do not become intrusion or escape proof",()=>{
 const C=model();
 for(const id of ["privilege-root-execution","privilege-root-restored","privilege-host-root-gain","privilege-root-identity-change","privilege-capability-gain","privilege-capability-activated"]){
  const value=C.findingPresentation({rule_id:id,summary:"RAW_SOURCE"});assert.doesNotMatch(text(value),/RAW_SOURCE/);assert.notEqual(value.title,id);
 }
 assert.match(C.findingPresentation({rule_id:"privilege-root-restored"}).note,/새로운 권한 탈취 판정은 아닙니다/);
 assert.match(C.findingPresentation({rule_id:"privilege-host-root-gain"}).note,/컨테이너 탈출 증거 자체는 아닙니다/);
 assert.equal(C.eventLabel("process.credential_change"),"프로세스 권한 변경 관측");
 const root=C.eventObservation({event_type:"process.exec",process:{uid:0,euid:0}});assert.match(text(root),/0 \/ 0/);assert.match(text(root),/범위 미확인/);
});

test("kernel task identity preserves exact uint64 decimal strings",()=>{
 const C=model(),field=value=>C.eventObservation({event_type:"process.credential_change",credential:{task_start_time_ns:value}}).fields.find(([label])=>label==="커널 task 시작 시각(ns)")[1];
 for(const value of ["1","9007199254740993","18446744073709551615"])assert.equal(field(value),value);
 for(const value of [undefined,null,0,123,9007199254740992,"0","01","-1","+1","1.0","1e3","18446744073709551616","999999999999999999999","<script>"])assert.equal(field(value),"정확한 값 미확인");
 assert.match(text(C.eventObservation({event_type:"process.credential_change",credential:{task_start_time_ns:"9007199254740993"}})),/커널 단조 시각.*달력 시각이 아닙니다/);
});

test("served module is wired before history and admitted in the static allowlist",()=>{
 const html=fs.readFileSync(new URL("index.html",import.meta.url),"utf8"),handler=fs.readFileSync(new URL("../handler.go",import.meta.url),"utf8");
 assert.ok(html.indexOf('src="/assets/model.js"')<html.indexOf('src="/assets/privilege.js"'));
 assert.ok(html.indexOf('src="/assets/privilege.js"')<html.indexOf('src="/assets/history.js"'));
 assert.match(handler,/"privilege.js"/);assert.match(html,/id="privilegeRules"/);assert.match(html,/id="rootExecAlerts"/);
});
