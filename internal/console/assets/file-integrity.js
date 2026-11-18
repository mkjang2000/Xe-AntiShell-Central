"use strict";
(function (C) {
  const labels = {disabled:"검사 꺼짐",policy_expired:"승인 정책 만료",unverified_support:"에이전트 지원 미확인",awaiting_measurement:"새 측정 대기",matched:"승인 기준 일치",approved_update:"승인 업데이트 후 일치",baseline_missing:"승인 기준 미등록",inventory_unverified:"설치·실행 정보 미확인",update_in_progress:"설치·실행 버전 전환 중",stale:"측정 기한 경과",too_large:"파일 크기 한도 초과",unreadable:"읽기 실패",changed_during_read:"검사 중 파일 변경",missing:"파일 누락",mismatch:"예상 밖 변경"};
  const text = value => labels[value] || "미확인";
  let requestedKey = "", result = null, loading = false;
  C.fileIntegrity = (agent, container) => {
    if(agent.revoked) return;
    const key = C.policyIdentity(agent), section = C.el("section", "detail-section");
    section.append(C.el("h3", "", "에이전트 파일 무결성"));
    section.append(C.button("검사 결과 조회", async () => {
      requestedKey = key; result = null; loading = true;
      C.renderAgentDetail(false);
      try {
        const value = await C.request(`/api/agents/${encodeURIComponent(agent.agent_id)}/integrity`);
        if(requestedKey === key) result = value;
      } catch(error) { C.error(error); }
      finally { if(requestedKey === key){loading = false; C.renderAgentDetail(false);} }
    },"small"));
    if(requestedKey === key && loading) section.append(C.el("p","panel-note","검사 결과를 불러오는 중입니다."));
    if(requestedKey === key && result){
      section.append(C.facts([["판정",text(result.state)],["승인 리비전",result.revision || "—"],["실행 패키지",result.package || "—"],["중앙 수신",result.received_at ? C.time(result.received_at) : "—"]]));
      const rows=Object.entries(result.files || {}).map(([id,value])=>[id,text(value.verdict),C.time(value.measured_at)]);
      if(rows.length)section.append(C.table("검사 대상별 판정",["대상","판정","측정 시각"],rows),C.raw(result,"승인·측정 다이제스트 보기"));
    }
    container.append(section);
  };
})(globalThis.XEC);
