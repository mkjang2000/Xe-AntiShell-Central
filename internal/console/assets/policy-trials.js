"use strict";
(function(C){
  const base="/api/policy-trials";
  const states={applied:"적용 확인",pending:"보고 대기",stale:"기한 경과",rejected:"거절",superseded:"등록·정책 변경",unhealthy:"상태 이상"};
  const phases={prepared:"비교 준비",canary:"한 대 선행 배포",expanded:"그룹 확대",restoring_canary:"선행 호스트 복구",restoring_all:"그룹 복구"};
  const write=()=>["admin","operator"].includes(C.session?.role);
  const post=(path,body)=>C.request(path,{method:"POST",body});
  const button=(text,act)=>{const b=C.button(text,()=>C.run(b,act));return b;};
  const label=(text,node)=>{const l=C.el("label","",text);l.append(node);return l;};
  const download=(object,name)=>{const href=URL.createObjectURL(new Blob([JSON.stringify(object)],{type:"application/json"}));const link=C.el("a");link.href=href;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(href),1000);};
  let displayGeneration=0;
  C.policyTrialStart=preview=>{
    const root=C.id("trialStart");if(!root)return;root.replaceChildren();if(!write())return;
    const options=C.el("select");for(const target of preview.targets){const o=C.el("option","",target.agent_id);o.value=target.agent_id;options.append(o);}
    root.append(label("선행 배포 호스트",options),button("이 미리보기로 비교 시작",async()=>{
      const t=await post(base,{preview_token:preview.preview_token,canary:options.value});await show(t.id);
      C.id("trialPanel").scrollIntoView({block:"nearest"});
    }));
  };
  function impactView(report){
    return C.table("규칙별 비교",["규칙","입력 표본","현행","후보","추가","감소","변경"],report.rules.map(r=>[r.id,r.has_input_type?"있음":"없음",r.current,r.candidate,r.added,r.removed,r.changed]));
  }
  // Reject unexpected fields before a file goes to the network. Event samples are local inputs.
  function reportShape(r){
    const exact=(value,names)=>!!value && Object.keys(value).length===names.length && names.every(k=>Object.hasOwn(value,k));
    return exact(r,["input_sha256","sample_sha256","host_config_sha256","evaluated_at","events","rules"]) && Array.isArray(r.rules) && r.rules.length>0 && r.rules.length<=128 && r.rules.every(v=>exact(v,["id","has_input_type","current","candidate","added","removed","changed"]));
  }
  async function show(id){
    const generation=++displayGeneration,path=base+"/"+encodeURIComponent(id),s=await C.request(path);if(generation!==displayGeneration)return;
    const body=C.id("trialDetail"),view=C.el("div"),t=s.trial;body.replaceChildren(view);
    view.append(C.facts([["단계",phases[t.phase]],["선행 호스트",t.canary],["템플릿",`${s.template_id} v${s.template_version}`],["비교 평가 시각",C.time(s.evaluated_at)]]));
    view.append(C.table("호스트별 실제 정책 적용",["호스트","기준","기대","중앙 목표","실제 적용","보고 상태","비교"],s.targets.map(a=>[a.agent_id,a.baseline,a.expected,a.desired,a.active,states[a.state],a.compared?"등록됨":"대기"])));
    const hosts=C.el("select"),result=C.el("div");for(const a of s.targets){const o=C.el("option","",a.agent_id);o.value=a.agent_id;hosts.append(o);}hosts.addEventListener("change",()=>result.replaceChildren());
    const query=view=>path+"?"+new URLSearchParams({agent_id:hosts.value,view});
    view.append(label("비교할 호스트",hosts),button("비교 입력 다운로드",async()=>{const input=await C.request(query("input"));download(input,"policy-impact.json");}),button("등록된 비교 결과",async()=>{
      const selected=hosts.value,r=await C.request(query("report"));if(selected!==hosts.value)return;
      result.replaceChildren(C.facts([["표본 건수",r.events],["표본 SHA-256",r.sample_sha256],["호스트 설정 SHA-256",r.host_config_sha256],["정책 입력 SHA-256",r.input_sha256]]),impactView(r));
    }),result);
    if(write()&&["prepared","canary"].includes(t.phase)){
      view.append(C.el("pre","raw-json","sentinel rules compare --managed-input policy-impact.json --host-config host.yaml --events sample.jsonl > impact-report.json"));
      const file=C.el("input");file.type="file";file.accept="application/json,.json";
      view.append(label("비교 결과 JSON",file),button("선택 호스트의 결과 등록",async()=>{
        const data=file.files[0],selected=hosts.value;if(!data||data.size>65536)throw new Error("64 KiB 이내의 비교 결과 JSON을 선택하세요.");
        const report=JSON.parse(await data.text());if(!reportShape(report))throw new Error("비교 CLI가 생성한 집계 결과 JSON을 선택하세요.");
        await post(path+"/report",{agent_id:selected,report});await show(id);
      }));
    }
    if(write()){
      const actions=t.phase==="prepared"?[["canary","한 대 선행 배포"]]:t.phase==="canary"?[["promote","그룹 확대"],["restore","선행 호스트 복구"]]:t.phase==="expanded"?[["restore","그룹 복구"]]:[];
      const note=C.el("textarea");if(t.phase==="canary")view.append(label("그룹 확대 전 확인한 수집·경보·부하 결과",note));
      for(const [action,title] of actions)view.append(button(title+" 미리보기",async()=>{
        const request={action,phase:t.phase},p=await post(path+"/preview",request);
        const list=p.targets.map(agent=>`${agent} → r${p.new_revisions[agent]}`).join(", ");
        if(!await C.confirm({title,description:`${list}. 확인 기한 ${C.time(p.expires_at)}`,accept:title}))return;
        await post(path+"/apply",{...request,confirmation:p.confirmation,note:note.value.trim()});await show(id);
      }));
    }
    view.append(button("실제 적용 상태 새로 조회",()=>show(id)));
  }
  C.initPolicyTrials=()=>{
    const list=C.id("trialList"),refresh=C.id("loadTrials");if(!list||!refresh)return;
    refresh.addEventListener("click",()=>C.run(refresh,async()=>{
      const trials=await C.request(base);list.replaceChildren(...trials.map(t=>button(`${t.canary} · ${phases[t.phase]} · ${t.id}`,()=>show(t.id))));
      if(!trials.length)list.append(C.empty("저장된 단계 배포가 없습니다."));
    }));
  };
})(globalThis.XEC);
