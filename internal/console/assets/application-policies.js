"use strict";

(function (C) {
  const id = name => C.id(name);
  const key = ref => JSON.stringify([ref.policy_id, ref.policy_version]);
  const same = (a, b) => a.service === b.service && a.policy_id === b.policy_id && a.policy_version === b.policy_version;
  const validService = name => name.length > 8 && name.length <= 255 && /^[A-Za-z0-9_.@\\-]+\.service$/.test(name);
  const writable = () => ["admin", "operator"].includes(C.session?.role);
  const modes = {observe: ["관찰", "blue"], would_block: ["모의 대응", "warning"], enforce: ["조건부 종료", "danger"]};
  const profile = policy => {
    const response = C.object(policy.response), detection = C.object(policy.detection);
    if (detection.enabled === false) return ["탐지 꺼짐", "neutral"];
    if (!Object.hasOwn(modes, response.mode)) return ["대응 미확인", "neutral"];
    if (detection.extended_process_rules && response.mode !== "observe") return ["탐지 전용 · 대응 후보 없음", "warning"];
    return modes[response.mode];
  };
  const panes = ["Catalog", "Assignments", "Deployment"];
  let active = "Catalog", bindings = [], snapshots = [], editing = "", hadBindings = false, changed;

  C.showPolicyPane = name => {
    if (!panes.includes(name)) return;
    active = name;
    for (const pane of panes) {
      id("policy"+pane+"Pane").hidden = pane !== active;
      id("policy"+pane+"Tab").setAttribute("aria-pressed", String(pane === active));
    }
    if (name === "Assignments") C.refreshAppliedPolicies?.();
  };
  C.policyPane = () => active;
  C.appPolicyTag = policy => C.tag(...profile(policy));
  C.appProjectionTable = (apps, title) => {
    const wrap = C.el("div", "table-scroll app-policy-table");
    wrap.append(C.table(title, ["시스템 서비스", "정책 ID · 버전", "탐지·대응"], apps.map(app => [
      C.el("code", "", app.service), app.policy_id+" · v"+app.policy_version, C.appPolicyTag(app)
    ])));
    return wrap;
  };
  const sources = () => C.state.templates.filter(t => t.id !== id("templateID").value.trim() && !C.array(t.settings.application_bindings).length && !C.array(t.settings.applications).length);
  const fetchSource = ref => C.state.templates.find(t => t.id === ref.policy_id);

  function clearEntry() {
    editing = "";
    id("appBindingService").value = "";
    id("appBindingService").readOnly = false;
    id("appBindingSource").value = "";
    id("appBindingCancel").hidden = true;
    id("appBindingError").hidden = true;
    C.text("appBindingLegend", "서비스 연결");
    C.text("appBindingAdd", "연결 추가");
  }
  function renderHint() {
    const source = sources().find(t => key({policy_id:t.id, policy_version:t.version}) === id("appBindingSource").value);
    id("appBindingCancel").hidden = !editing && !id("appBindingService").value && !id("appBindingSource").value;
    const notes = [];
    if (source) notes.push(source.name+" · v"+source.version+" · "+profile(source.settings)[0]+".");
    else if (!sources().length) notes.push("먼저 서비스 연결이 없는 정책을 한 개 이상 저장하세요.");
    if (bindings.length && id("responseMode").value !== "observe") notes.push("서비스를 연결한 호스트의 기본 대응 방식은 관찰이어야 합니다.");
    C.text("appBindingHint", notes.join(" "));
    id("appBindingHint").hidden = !notes.length;
  }
  function edit(ref) {
    editing = ref.service;
    id("appBindingService").value = ref.service;
    id("appBindingService").readOnly = true;
    id("appBindingSource").value = "";
    id("appBindingCancel").hidden = false;
    id("appBindingError").hidden = true;
    C.text("appBindingLegend", ref.service+" 연결 변경");
    C.text("appBindingAdd", "연결 변경");
    renderHint();
    id("appBindingSource").focus();
  }
  function render() {
    C.options("appBindingSource", sources().map(t => [key({policy_id:t.id, policy_version:t.version}), t.name+" · "+t.id+" · v"+t.version]), "저장된 정책 선택");
    C.text("appBindingCount", bindings.length+" / 64");
    const rows = bindings.map(ref => {
      const t = fetchSource(ref);
      const saved = snapshots.find(app => same(app, ref));
      const current = t?.version === ref.policy_version ? t.settings : null;
      const row = C.el("div", "app-binding-row"), identity = C.el("div", "app-binding-identity");
      identity.append(C.el("code", "", ref.service), C.el("small", "", ref.policy_id+" · v"+ref.policy_version));
      if (!t || !current) identity.append(C.el("small","app-source-note",t ? "목록의 최신 버전 v"+t.version+" · 기존 연결 유지" : "원본 정책이 목록에 없음 · 저장한 연결 확인"));
      row.append(identity, saved || current ? C.appPolicyTag(saved || current) : C.tag("버전 확인 필요", "warning"));
      if (writable()) {
        const actions = C.el("div", "app-binding-actions");
        const change = C.button("변경", () => edit(ref), "small"), remove = C.button("해제", () => {
          bindings = bindings.filter(item => item.service !== ref.service);
          if (editing === ref.service) clearEntry();
          render(); changed();
        }, "small quiet");
        change.setAttribute("aria-label", ref.service+" 연결 변경"); remove.setAttribute("aria-label", ref.service+" 연결 해제");
        actions.append(change, remove); row.append(actions);
      }
      return row;
    });
    id("appBindingRows").replaceChildren(...(rows.length ? rows : [C.el("p","app-binding-empty","연결된 서비스가 없습니다. 호스트 기본 정책을 사용합니다.")]));
    renderHint();
  }
  function add() {
    const name = id("appBindingService").value.trim(), select = id("appBindingSource");
    const source = sources().find(t => key({policy_id:t.id, policy_version:t.version}) === select.value);
    let message = "";
    if (!validService(name)) message = "정확한 시스템 서비스 유닛 이름을 입력하세요. 예: nginx.service";
    else if (!source) message = "연결할 정책과 버전을 선택하세요.";
    else if (!editing && bindings.some(ref => ref.service === name)) message = "이미 연결된 서비스입니다. 해당 행의 변경을 선택하세요.";
    else if (!editing && bindings.length >= 64) message = "호스트 한 대에는 최대 64개 서비스를 연결할 수 있습니다.";
    if (message) { C.text("appBindingError",message); id("appBindingError").hidden=false; return; }
    const ref = {service:name, policy_id:source.id, policy_version:source.version};
    bindings = editing ? bindings.map(old => old.service === editing ? ref : old) : [...bindings, ref];
    clearEntry(); render(); changed(); id("appBindingService").focus();
  }
  C.applicationBindings = {
    init(onChange) {
      changed = onChange;
      for (const pane of panes) id("policy"+pane+"Tab").addEventListener("click",() => C.showPolicyPane(pane));
      id("appBindingAdd").addEventListener("click",add);
      id("appBindingCancel").addEventListener("click",() => { clearEntry(); render(); });
      id("appBindingSource").addEventListener("change",renderHint);
      id("appBindingService").addEventListener("input",renderHint);
      id("responseMode").addEventListener("change",renderHint);
      id("templateID").addEventListener("input",render);
    },
    load(settings) {
      bindings = structuredClone(C.array(settings.application_bindings));
      hadBindings = bindings.length > 0;
      snapshots = structuredClone(C.array(settings.applications));
      clearEntry(); render();
    },
    read() {
      if (editing || id("appBindingService").value.trim() || id("appBindingSource").value) throw new Error("입력 중인 서비스 연결을 먼저 추가·변경하거나 취소하세요.");
      if (bindings.length && id("responseMode").value !== "observe") throw new Error("서비스를 연결한 호스트 기본 정책의 대응 방식을 관찰(observe)로 설정하세요.");
      if (bindings.some(ref => ref.policy_id === id("templateID").value.trim())) throw new Error("호스트 정책을 자기 자신의 서비스 정책으로 연결할 수 없습니다.");
      return hadBindings || bindings.length ? {application_bindings:structuredClone(bindings)} : {};
    },
    render
  };
})(globalThis.XEC);
