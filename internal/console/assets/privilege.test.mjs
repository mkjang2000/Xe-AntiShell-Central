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
 const C=model(),before={uid:1000,euid:1000,suid:1000,capabilities:{effective:[],permitted:["CAP_SETUID"]},user_namespace:{inum:10,is_host:true}},after={uid:1000,euid:0,suid:1000,capabilities:{effective:["CAP_SETUID"],permitted:["CAP_SETUID"]},user_namespace:{inum:10,is_host:true}};
 const e={event_type:"process.credential_change",credential:{before,after,tgid:22,tid:23,return_value:0,outcome:"applied",function:"commit_creds",payload:"SECRET"}};
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
