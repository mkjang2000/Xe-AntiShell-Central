((C) => {
  "use strict";

  const id = C.id, el = C.el;
  const statuses = {
    queued: "대기", claimed: "에이전트가 인수함", started: "제거 시작",
    succeeded: "제거 완료", failed: "제거 실패", expired: "만료",
    cancelled: "취소", result_unknown: "결과 미확인"
  };
  const reasons = {
    unsupported: "지원 버전 아님", disabled: "호스트에서 차단", stale: "최근 보고 없음",
    policy_denied: "보안 정책에서 제거 금지", update_busy: "업데이트 진행 중",
    removal_busy: "다른 제거 진행 중", revoked: "등록 해지",
    authorization_changed: "요청자의 제거 권한이 변경됨", site_changed: "에이전트 소속 사이트가 변경됨",
    unavailable: "대상 등록 또는 그룹 구성 변경"
  };
  let preview = null, batchID = "", busy = false, generation = 0;
  const selectedAgents = new Set();
  const present = value => Object.hasOwn(statuses, value) ? statuses[value] : value || "—";
  const option = (name, value) => Object.assign(el("option", "", name), {value});

  const resetPreview = () => {
    generation++;
    preview = null;
    id("batchRemovalPreviewResult").replaceChildren();
    id("batchRemovalConfirm").disabled = true;
  };

  const showRows = (destination, targets, forPreview) => {
    const rows = C.array(targets).map(target => {
      const value = target.reason || target.job?.code;
      const state = forPreview ? target.eligible ? "제거 가능" : "제외" : present(target.job?.state);
      return [target.agent_id, C.siteName?.(target.site_id) || target.site_id, state, Object.hasOwn(reasons, value) ? reasons[value] : value || "—"];
    });
    destination.replaceChildren(C.table("일괄 제거 대상", ["에이전트", "사이트", "상태", "사유"], rows));
  };

  const renderTargets = () => {
    const targetType = id("batchRemovalTargetType").value;
    const list = id("batchRemovalAgentList"), select = id("batchRemovalTargetID");
    list.hidden = targetType !== "agents";
    select.hidden = targetType === "agents";
    const current = select.value;
    if (targetType === "group") {
      select.replaceChildren(option("서버 그룹 선택", ""), ...C.array(C.state.groups).map(group => option(group.name, group.id)));
    } else if (targetType === "site") {
      select.replaceChildren(option("사이트 선택", ""), ...(C.siteOptions?.() || [])
        .filter(([key]) => key !== "*" && (!C.activeSite || C.activeSite === "*" || C.activeSite === key) && C.can("agents.remove", key))
        .map(([key, name]) => option(name, key)));
    } else {
      const query = id("batchRemovalFilter").value.trim().toLocaleLowerCase();
      const agents = C.array(C.state.agents).filter(agent => !agent.revoked && C.can("agents.remove", agent.site_id) &&
        (!query || (agent.agent_id + " " + (agent.hostname || "")).toLocaleLowerCase().includes(query)));
      list.replaceChildren(...agents.map(agent => {
        const check = Object.assign(el("input"), {type: "checkbox", checked: selectedAgents.has(agent.agent_id)});
        check.addEventListener("change", () => {
          if (check.checked) selectedAgents.add(agent.agent_id);
          else selectedAgents.delete(agent.agent_id);
          resetPreview();
          C.text("batchRemovalSelected", selectedAgents.size + "대 선택");
        });
        const label = el("label", "check-label");
        label.append(check, el("span", "", agent.agent_id + (agent.hostname ? " · " + agent.hostname : "")));
        return label;
      }));
    }
    if (current && [...select.options].some(item => item.value === current)) select.value = current;
    id("batchRemovalFilterField").hidden = targetType !== "agents";
    C.text("batchRemovalSelected", targetType === "agents" ? selectedAgents.size + "대 선택" : "");
  };

  const readBatch = async requested => {
    if (!requested) return;
    const data = await C.request("/api/remote-removal/batches/" + encodeURIComponent(requested));
    if (batchID !== requested) return;
    C.text("batchRemovalStatus", "배치 " + data.batch_id);
    showRows(id("batchRemovalResult"), data.targets, false);
  };

  C.loadRemovalBatches = () => {
    if (!C.can("agents.remove")) return;
    renderTargets();
    if (batchID) return readBatch(batchID);
  };

  C.initRemovalBatches = () => {
    id("batchRemovalTargetType").addEventListener("change", () => { resetPreview(); renderTargets(); });
    id("batchRemovalTargetID").addEventListener("change", resetPreview);
    id("batchRemovalFilter").addEventListener("input", renderTargets);
    id("batchRemovalPreviewForm").addEventListener("submit", event => {
      event.preventDefault();
      C.run(id("batchRemovalPreview"), async () => {
        resetPreview();
        const type = id("batchRemovalTargetType").value;
        const selected = id("batchRemovalTargetID").value;
        const body = type === "agents" ? {agent_ids: [...selectedAgents]} :
          type === "group" ? {group_id: selected} : {site_id: selected};
        if (type === "agents" ? !selectedAgents.size : !selected) throw new Error("제거에 포함할 대상을 선택하세요.");
        const requestGeneration = generation;
        const response = await C.request("/api/remote-removal/preview", {method: "POST", body});
        if (generation !== requestGeneration) return;
        preview = response;
        showRows(id("batchRemovalPreviewResult"), preview.targets, true);
        id("batchRemovalConfirm").disabled = !preview.eligible_count;
      });
    });
    id("batchRemovalConfirm").addEventListener("click", async () => {
      await C.run(id("batchRemovalConfirm"), async () => {
      const snapshot = preview;
      if (!snapshot?.eligible_count) return;
      const count = String(snapshot.eligible_count);
      if (!await C.confirm({title: "에이전트 일괄 제거", description: "미리보기에서 제거 가능으로 표시된 " + count + "대에 요청을 발행합니다.", accept: "일괄 제거 요청", match: count})) return;
      if (preview !== snapshot) throw new Error("대상이 변경됐습니다. 미리보기를 다시 확인하세요.");
      const result = await C.request("/api/remote-removal/batches", {method: "POST", body: {preview_token: snapshot.preview_token, confirmation: count}});
      batchID = result.batch_id;
      id("batchRemovalLookup").value = batchID;
      resetPreview();
      await readBatch(batchID);
      C.notify("일괄 제거 요청을 발행했습니다.");
      });
      id("batchRemovalConfirm").disabled = !preview?.eligible_count;
    });
    id("batchRemovalLookupForm").addEventListener("submit", event => {
      event.preventDefault();
      C.run(id("batchRemovalLookupButton"), async () => {
        const next = id("batchRemovalLookup").value.trim();
        if (next !== batchID) id("batchRemovalResult").replaceChildren();
        batchID = next;
        await readBatch(batchID);
      });
    });
    C.onState(() => {
      if (C.view !== "decommission" || busy || !C.can("agents.remove")) return;
      busy = true;
      C.loadRemovalBatches().catch(C.error).finally(() => { busy = false; });
    });
  };
})(globalThis.XEC);
