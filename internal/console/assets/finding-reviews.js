"use strict";
(function(C) {
  const verdicts = {normal:"정상", suspicious:"의심", deferred:"판정 보류"};
  const endpoint = "/api/finding-reviews";
  function requestID() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return Array.from(bytes, byte => byte.toString(16).padStart(2,"0")).join("");
  }
  C.findingReviews = record => {
    const target = {agent_id:record.agent_id, record_id:record.id, ...record.finding_location};
    const box = C.el("details"), summary = C.el("summary", "", "운영자 판정과 근거");
    const body = C.el("div"), status = C.el("p","panel-note");
    status.setAttribute("role","status");
    box.append(summary,status,body);
    let loaded=false, busy=false, before=0, latest=0, retry=null;
    function url(extra={}) { return endpoint + "?" + new URLSearchParams({...target,...extra}); }
    async function run(fn) {
      if (busy) return;
      busy=true;box.setAttribute("aria-busy","true");status.textContent="";
      try { await fn(); }
      catch (error) { status.textContent=error.message; }
      finally { busy=false;box.removeAttribute("aria-busy"); }
    }
    function editor() {
      const form=C.el("form"), choice=C.el("select"), reason=C.el("textarea");
      choice.required=true;reason.required=true;reason.maxLength=2048;
      const placeholder=C.el("option","","선택하세요");placeholder.value="";choice.append(placeholder);
      for (const [value,label] of Object.entries(verdicts)) {
        const option=C.el("option","",label);option.value=value;choice.append(option);
      }
      const choiceLabel=C.el("label","","판정"), reasonLabel=C.el("label","","판정 사유");
      choiceLabel.append(choice);reasonLabel.append(reason);
      const submit=C.el("button","","판정 기록");submit.type="submit";
      form.append(choiceLabel, reasonLabel, submit);
      form.addEventListener("submit", event => {
        event.preventDefault();
        return run(async()=>{
          const payload={target,expected_version:latest,verdict:choice.value,reason:reason.value.trim()};
          if (!Object.hasOwn(verdicts,payload.verdict) || !payload.reason) {throw new Error("판정과 사유를 입력하세요.");}
          if (new TextEncoder().encode(payload.reason).length>2048) throw new Error("판정 사유를 UTF-8 2,048바이트 이내로 입력하세요.");
          // Reuse the key after a lost response, including a failed refresh after a successful save.
          const key=JSON.stringify(payload);
          if (retry?.key!==key) retry={key,id:requestID()};
          await C.request(endpoint,{method:"POST",body:{...payload,request_id:retry.id}});
          await load(0);retry=null;status.textContent="판정을 기록했습니다.";
        });
      });
      return form;
    }
    function evidenceControls(finding) {
      const group=C.el("div"), refs=C.array(finding.evidence_event_ids);
      if (!refs.length) return group;
      const label=C.el("label","","근거 이벤트"), select=C.el("select");
      for (const id of refs) {const option=C.el("option","",id); option.value=id;select.append(option);}
      label.append(select);
      const facts=C.el("div"), open=C.button("근거 조회",()=>run(async()=>{
        facts.replaceChildren();
        const event=await C.request(url({evidence_id:select.value})), observation=C.eventObservation(event);
        facts.replaceChildren(C.facts([["관측 시각",C.time(event.event_time)],["유형",event.event_type],["서비스",event.process?.origin_service],...observation.fields]));
      }));
      group.append(label,open,facts);return group;
    }
    async function load(cursor) {
      const page=await C.request(url(cursor?{before:cursor}:{}));
      const finding=page.finding;
      const rows=C.array(page.items).map(row=>[row.version,verdicts[row.verdict],row.reason,row.actor,C.time(row.created_at)]);
      const children=[C.facts([["규칙",finding.rule_id],["규칙 버전",finding.rule_version],["발생 당시 정책 리비전",finding.policy_revision ?? "기록 없음"],["당시 탐지 근거",finding.summary]]),evidenceControls(finding)];
      children.push(rows.length ? C.table("운영자 판정 이력",["차수","판정","사유","판정자","시각"],rows) : C.empty("기록된 판정이 없습니다."));
      const nav=C.el("nav");nav.setAttribute("aria-label","판정 이력 페이지");
      nav.append(C.button(cursor?"최신 판정 보기":"새로 조회",()=>run(()=>load(0))));
      if(page.next_before) nav.append(C.button("이전 판정 보기",()=>run(()=>load(page.next_before))));
      children.push(nav);
      if (!cursor && ["admin","operator"].includes(C.session?.role)) children.push(editor());
      body.replaceChildren(...children);latest=page.latest_version;before=cursor;loaded=true;
    }
    box.addEventListener("toggle",()=>{if(box.open && !loaded)return run(()=>load(before));});
    return box;
  };
})(globalThis.XEC);
