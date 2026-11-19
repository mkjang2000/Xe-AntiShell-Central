"use strict";

(function (C) {
  let id = "", version = 0, turn = 0, page = 0, cursors = [""], next = "", loaded = false;
  const node = name => C.id(name);
  function controls(busy) {
    node("templateUsagePrevious").disabled = busy || page === 0;
    node("templateUsageNext").disabled = busy || !next;
    node("templateUsageReload").disabled = busy;
  }
  async function load() {
    if (!id || !node("templateUsage").open) return;
    const generation = ++turn, target = node("templateUsageReport");
    loaded = false; next = "";
    controls(true);
    target.replaceChildren(C.el("p","panel-note","현재 등록에 지정된 정책을 조회하고 있습니다."));
    try {
      const query = new URLSearchParams({limit:"100"});
      if (cursors[page]) query.set("after",cursors[page]);
      const result = await C.request("/api/templates/"+encodeURIComponent(id)+"/usage?"+query);
      if (generation !== turn) return;
      if (!Array.isArray(result.items)) throw new Error("사용처 응답 형식을 확인하세요.");
      next = result.next_after || ""; loaded = true;
      if (!result.items.length) {
        target.replaceChildren(C.empty(next || page ? "이 구간에는 해당 정책을 지정한 호스트가 없습니다." : "현재 등록에 이 정책을 지정한 호스트가 없습니다."));
        return;
      }
      const hosts = new Set(result.items.map(item => item.agent_id)), groups = new Map();
      for (const group of C.state.groups) {
        for (const agent of C.array(group.agent_ids)) {
          if (!hosts.has(agent)) continue;
          if (!groups.has(agent)) groups.set(agent,[]);
          groups.get(agent).push(group.name);
        }
      }
      const rows = result.items.map(item => {
        const scopes = C.array(item.bindings).map(ref => ref.service+" · v"+ref.policy_version);
        if (item.host_policy) scopes.unshift("호스트 기본 정책");
        return [item.agent_id, scopes.join("\n"), (groups.get(item.agent_id) || []).join(" · ") || "소속 없음", item.desired_revision, C.applicationStateTag(C.object(item.application_status).state)];
      });
      const wrapper = C.el("div","table-scroll app-policy-table");
      wrapper.append(C.table("선택한 정책의 사용처",["호스트","목표 정책·서비스","현재 소속 그룹","목표 리비전","호스트 보고"],rows));
      target.replaceChildren(wrapper);
    } catch (error) {
      if (generation === turn) target.replaceChildren(C.el("p","notice warning",error.message || "사용처 조회에 실패했습니다."));
    } finally {
      if (generation === turn) controls(false);
    }
  }
  C.initPolicyUsage = () => {
    node("templateUsage").addEventListener("toggle",() => { if (!loaded && node("templateUsage").open) load(); });
    node("templateUsagePrevious").addEventListener("click",() => { if(page) { page--; load(); } });
    node("templateUsageNext").addEventListener("click",() => { if(next) { cursors[++page]=next; load(); } });
    node("templateUsageReload").addEventListener("click",() => { page=0; cursors=[""]; load(); });
  };
  C.selectPolicyUsage = (selected, rev) => {
    if (selected === id && rev === version) return;
    id = selected; version = rev; turn++; page = 0; cursors = [""]; next = ""; loaded = false;
    node("templateUsage").hidden = !id;
    node("templateUsageReport").replaceChildren();
    controls(false);
    if (node("templateUsage").open) load();
  };
})(globalThis.XEC);
