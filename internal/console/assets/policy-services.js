"use strict";

// Row editors for per-service rule controls and file/TCP scopes. The rows hold
// the exact wire objects so an unchanged load and save returns the same values.
(function (C) {
  const id = name => C.id(name);
  const ruleNames = {
    "web-descendant-root-shell": "웹 서비스의 root 셸 실행",
    "web-descendant-shell": "웹 서비스의 셸 실행",
    "web-descendant-download-tool": "웹 서비스의 다운로드 도구 실행",
    "web-descendant-recon-tool": "웹 서비스의 정찰 도구 실행",
    "web-descendant-connection-tool": "웹 서비스의 원격 연결 도구 실행",
    "web-descendant-inline-interpreter": "웹 서비스의 직접 코드 실행 요청",
    "web-descendant-temporary-executable": "웹 서비스의 임시 경로 실행 파일",
    "web-descendant-temporary-script": "웹 서비스의 임시 경로 스크립트",
    "privilege-root-execution": "root 실행",
    "privilege-root-restored": "root 권한 복원",
    "privilege-host-root-gain": "호스트 root 권한 획득",
    "privilege-root-identity-change": "root 사용자 전환",
    "privilege-capability-gain": "커널 권한(capability) 획득",
    "privilege-capability-activated": "커널 권한(capability) 활성화",
    "service-protected-file-write": "보호 경로 파일 쓰기",
    "service-unexpected-tcp-destination": "허용 밖 TCP 연결 요청"
  };
  const modes = [["enabled", "규칙 사용"], ["disabled", "이 서비스에서 끄기"], ["suppress_until", "만료 시각까지 예외"]];
  let controls = [], scopes = [], changed = () => {};
  C.ruleName = rule => ruleNames[rule] || rule;

  const pad = value => String(value).padStart(2, "0");
  const localInput = stamp => {
    const time = Date.parse(stamp);
    if (!Number.isFinite(time)) return "";
    const d = new Date(time);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
  const utcStamp = local => {
    const time = Date.parse(local);
    return Number.isFinite(time) ? new Date(time).toISOString().replace(/\.000Z$/, "Z") : "";
  };
  const remaining = ms => {
    const minutes = Math.max(1, Math.round(ms / 60000));
    if (minutes < 60) return `${minutes}분`;
    if (minutes < 2880) return `${Math.round(minutes / 60)}시간`;
    return `${Math.round(minutes / 1440)}일`;
  };
  const field = (labelText, input, note) => {
    const wrap = C.el("div", "field"), label = C.el("label", "", labelText);
    label.htmlFor = input.id; wrap.append(label, input);
    if (note) wrap.append(note);
    return wrap;
  };
  const input = (key, value, onInput, type = "text") => {
    const node = C.el("input"); node.id = key; node.type = type; node.value = value ?? ""; node.spellcheck = false;
    node.addEventListener("input", () => onInput(node.value));
    return node;
  };
  const textarea = (key, value, onInput) => {
    const node = C.el("textarea"); node.id = key; node.rows = 3; node.spellcheck = false; node.value = value;
    node.addEventListener("input", () => onInput(node.value));
    return node;
  };
  const removeButton = (label, onClick) => {
    const button = C.button("삭제", onClick, "small quiet danger"); button.setAttribute("aria-label", label); return button;
  };
  const touched = () => { changed(); renderNames(); };

  // Rule controls.
  function controlRow(control, index) {
    const row = C.el("div", "policy-row rule-row"), main = C.el("div", "policy-row-fields");
    const service = input(`ruleControl-${index}-service`, control.service, value => { control.service = value.trim(); touched(); });
    service.setAttribute("list", "policyServiceNames"); service.placeholder = "예: nginx.service";
    const rule = C.el("select"); rule.id = `ruleControl-${index}-rule`;
    const known = C.array(C.state.rule_ids);
    const choices = known.includes(control.rule_id) || !control.rule_id ? known : [control.rule_id, ...known];
    const blank = C.el("option", "", "규칙 선택"); blank.value = ""; rule.append(blank);
    for (const key of choices) { const option = C.el("option", "", `${C.ruleName(key)} · ${key}`); option.value = key; rule.append(option); }
    rule.value = control.rule_id || "";
    rule.addEventListener("change", () => { control.rule_id = rule.value; changed(); });
    const mode = C.el("select"); mode.id = `ruleControl-${index}-mode`;
    for (const [value, label] of modes) { const option = C.el("option", "", label); option.value = value; mode.append(option); }
    mode.value = control.mode || "enabled";
    mode.addEventListener("change", () => {
      control.mode = mode.value;
      if (control.mode !== "suppress_until") { delete control.reason; delete control.expires_at; }
      renderControls(); changed();
    });
    main.append(field("서비스", service), field("규칙", rule), field("적용 방식", mode));
    row.append(main, removeButton(`${control.service || "새"} 규칙 설정 삭제`, () => { controls.splice(index, 1); renderControls(); touched(); }));
    if (control.mode === "suppress_until") {
      const extra = C.el("div", "policy-row-fields policy-row-extra");
      const reason = input(`ruleControl-${index}-reason`, control.reason, value => { control.reason = value.trim(); changed(); });
      reason.maxLength = 512; reason.placeholder = "예: 승인된 배포 작업";
      const expiry = input(`ruleControl-${index}-expires`, localInput(control.expires_at), value => { control.expires_at = utcStamp(value); changed(); renderExpiry(); }, "datetime-local");
      const note = C.el("small", "");
      const renderExpiry = () => {
        const time = Date.parse(control.expires_at);
        note.textContent = !Number.isFinite(time) ? "브라우저 현지 시각으로 입력하면 UTC로 저장합니다." : time <= C.now() ? "이미 만료된 예외입니다. 지금은 프로필 기본 판정을 따릅니다." : `UTC ${control.expires_at} · ${remaining(time - C.now())} 후 만료`;
        note.className = Number.isFinite(time) && time <= C.now() ? "expired-note" : "";
      };
      renderExpiry();
      extra.append(field("예외 사유", reason), field("만료 시각 (현지 시각)", expiry, note));
      row.append(extra);
    }
    return row;
  }
  function renderControls() {
    C.text("ruleControlCount", controls.length ? `${controls.length}개` : "");
    id("ruleControlRows").replaceChildren(...(controls.length ? controls.map(controlRow) : [C.el("p", "app-binding-empty", "설정된 규칙이 없습니다. 모든 서비스가 프로필 기본 판정을 따릅니다.")]));
  }

  // File/TCP scopes. Text fields are kept per row and parsed on save.
  const formatTCP = list => C.array(list).map(dst => C.array(dst.ports).length ? `${dst.cidr} ${dst.ports.join(",")}` : dst.cidr).join("\n");
  const scopeState = scope => ({source: structuredClone(scope), service: scope.service || "", protected: C.array(scope.protected_dirs).join("\n"), writable: C.array(scope.allowed_write_dirs).join("\n"), tcp: formatTCP(scope.allowed_tcp_destinations)});
  function scopeRow(scope, index) {
    const row = C.el("div", "policy-row scope-row"), grid = C.el("div", "scope-fields");
    const service = input(`serviceScope-${index}-service`, scope.service, value => { scope.service = value.trim(); touched(); renderWarnings(); });
    service.setAttribute("list", "policyServiceNames"); service.placeholder = "예: web.service";
    const warning = C.el("small", "scope-warning");
    const renderWarnings = () => {
      const listed = C.lines(id("webServices").value);
      warning.textContent = scope.service && !listed.includes(scope.service) ? "탐지 탭의 웹 서비스 목록에 없는 서비스입니다. 목록에 추가해야 범위가 적용됩니다." : "";
    };
    renderWarnings(); scope.renderWarnings = renderWarnings;
    const head = C.el("div", "scope-head");
    head.append(field("서비스", service, warning), removeButton(`${scope.service || "새"} 서비스 범위 삭제`, () => { scopes.splice(index, 1); renderScopes(); touched(); }));
    const protectedDirs = textarea(`serviceScope-${index}-protected`, scope.protected, value => { scope.protected = value; changed(); });
    protectedDirs.placeholder = "/srv/web";
    const writable = textarea(`serviceScope-${index}-writable`, scope.writable, value => { scope.writable = value; changed(); });
    writable.placeholder = "/srv/web/uploads";
    const tcp = textarea(`serviceScope-${index}-tcp`, scope.tcp, value => { scope.tcp = value; changed(); });
    tcp.placeholder = "192.0.2.0/24 443,8443\n2001:db8::/32";
    grid.append(field("보호 디렉터리", protectedDirs, C.el("small", "", "쓰기를 감시할 경로")),
      field("쓰기 허용 디렉터리", writable, C.el("small", "", "보호 디렉터리 안에서 쓰기를 허용할 경로")),
      field("허용 TCP 대상", tcp, C.el("small", "", "한 줄에 'CIDR 포트,포트' · 포트를 비우면 모든 포트")));
    row.append(head, grid);
    return row;
  }
  function renderScopes() {
    const central = id("centralServiceScopes").checked;
    id("serviceScopeEditor").hidden = !central;
    id("serviceScopeEmpty").hidden = !central || scopes.length > 0;
    C.text("serviceScopeCount", central ? `중앙 지정 · ${scopes.length}개` : "호스트 YAML 사용");
    id("serviceScopeRows").replaceChildren(...scopes.map(scopeRow));
  }

  // Service name suggestions come from every place this policy names a service.
  function renderNames() {
    const names = new Set([...C.lines(id("webServices").value), ...controls.map(c => c.service), ...scopes.map(s => s.service)].filter(Boolean));
    id("policyServiceNames").replaceChildren(...[...names].sort().map(name => { const option = C.el("option"); option.value = name; return option; }));
  }

  const cleanPath = path => path.startsWith("/") && (path === "/" || !path.endsWith("/")) && !path.split("/").slice(1).some(part => part === "" && path !== "/" || part === "." || part === "..");
  const within = (path, root) => root === "/" || path === root || path.startsWith(root + "/");
  const validCIDR = cidr => {
    const [address, bits, extra] = cidr.split("/");
    if (extra !== undefined || bits === undefined || !/^\d{1,3}$/.test(bits)) return false;
    const prefix = Number(bits);
    if (address.includes(":")) return prefix <= 128 && /^[0-9A-Fa-f:]+$/.test(address) && address.split("::").length <= 2;
    const octets = address.split(".");
    if (octets.length !== 4 || prefix > 32 || octets.some(o => !/^\d{1,3}$/.test(o) || Number(o) > 255 || o.length > 1 && o.startsWith("0"))) return false;
    const value = octets.reduce((sum, o) => sum * 256 + Number(o), 0), host = prefix === 32 ? 0 : 2 ** (32 - prefix);
    return host === 0 || value % host === 0;
  };
  function readScope(scope) {
    const fail = message => C.sectionError("services", `${scope.service || "이름 없는 서비스"} 범위: ${message}`);
    if (!scope.service || scope.service.includes("/") || /\s/.test(scope.service) || scope.service.toLowerCase() === "unknown") throw fail("서비스 이름을 확인하세요.");
    const protectedDirs = C.lines(scope.protected), writable = C.lines(scope.writable);
    for (const [label, dirs] of [["보호 디렉터리", protectedDirs], ["쓰기 허용 디렉터리", writable]]) {
      if (dirs.length > 32) throw fail(`${label}는 32개까지 입력하세요.`);
      if (dirs.some(dir => !cleanPath(dir))) throw fail(`${label}는 '/'로 시작하는 정규화된 경로여야 합니다.`);
      if (new Set(dirs).size !== dirs.length) throw fail(`${label}에 중복된 경로가 있습니다.`);
    }
    if (writable.some(dir => !protectedDirs.some(root => within(dir, root)))) throw fail("쓰기 허용 디렉터리는 보호 디렉터리 안에 있어야 합니다.");
    const destinations = C.lines(scope.tcp).map(line => {
      const [cidr, ports, extra] = line.split(/\s+/);
      if (extra !== undefined || !validCIDR(cidr)) throw fail(`TCP 대상 '${line}'의 CIDR을 확인하세요. 예: 192.0.2.0/24 443`);
      const list = ports ? ports.split(",").map(Number) : [];
      if (list.length > 64 || list.some(port => !Number.isInteger(port) || port < 1 || port > 65535) || new Set(list).size !== list.length) throw fail(`TCP 대상 '${line}'의 포트는 1~65535 사이의 서로 다른 값이어야 합니다.`);
      return list.length ? {cidr, ports: list} : {cidr};
    });
    if (destinations.length > 32) throw fail("허용 TCP 대상은 32개까지 입력하세요.");
    if (!protectedDirs.length && !destinations.length) throw fail("보호 디렉터리 또는 허용 TCP 대상을 하나 이상 입력하세요.");
    const result = {service: scope.service};
    if (protectedDirs.length) result.protected_dirs = protectedDirs;
    if (writable.length) result.allowed_write_dirs = writable;
    if (destinations.length) result.allowed_tcp_destinations = destinations;
    // Keep the loaded object (including CIDR spelling and port order) when nothing changed.
    const same = JSON.stringify(scopeState(scope.source)) === JSON.stringify({...scopeState(scope.source), service: scope.service, protected: scope.protected, writable: scope.writable, tcp: scope.tcp});
    return same && scope.source.service ? structuredClone(scope.source) : result;
  }

  C.policyServices = {
    init(onChange) {
      changed = onChange;
      id("ruleControlAdd").addEventListener("click", () => {
        controls.push({service: "", rule_id: "", mode: "disabled"}); renderControls(); changed();
        id(`ruleControl-${controls.length - 1}-service`)?.focus?.();
      });
      id("serviceScopeAdd").addEventListener("click", () => {
        scopes.push(scopeState({service: ""})); renderScopes(); changed();
        id(`serviceScope-${scopes.length - 1}-service`)?.focus?.();
      });
      id("centralServiceScopes").addEventListener("change", () => { renderScopes(); renderNames(); });
      id("webServices").addEventListener("input", () => { renderNames(); for (const scope of scopes) scope.renderWarnings?.(); });
    },
    load(detection) {
      const d = C.object(detection);
      controls = structuredClone(C.array(d.service_rule_controls));
      id("centralServiceScopes").checked = Object.hasOwn(d, "service_observations");
      scopes = C.array(d.service_observations).map(scopeState);
      renderControls(); renderScopes(); renderNames();
    },
    // Returns only the keys that the wire carries: an empty control list is
    // omitted, while an empty central scope list deliberately disables scopes.
    read() {
      const out = {};
      for (const c of controls) {
        const name = c.service || "이름 없는 서비스";
        if (!c.service || !c.rule_id) throw C.sectionError("services", "규칙 설정의 서비스와 규칙을 선택하세요.");
        if (c.mode === "suppress_until" && !c.reason) throw C.sectionError("services", `${name} · ${C.ruleName(c.rule_id)}: 예외 사유를 입력하세요.`);
        if (c.mode === "suppress_until" && !Number.isFinite(Date.parse(c.expires_at))) throw C.sectionError("services", `${name} · ${C.ruleName(c.rule_id)}: 만료 시각을 입력하세요.`);
      }
      if (controls.length) out.service_rule_controls = structuredClone(controls);
      if (id("centralServiceScopes").checked) {
        const result = scopes.map(readScope), names = result.map(scope => scope.service);
        if (result.length > 64) throw C.sectionError("services", "서비스 범위는 64개까지 지정할 수 있습니다.");
        if (new Set(names).size !== names.length) throw C.sectionError("services", "같은 서비스의 범위가 중복됩니다.");
        out.service_observations = result;
      }
      return out;
    },
    counts: () => ({controls: controls.length, scopes: id("centralServiceScopes").checked ? scopes.length : null}),
    render() { renderControls(); renderScopes(); renderNames(); }
  };
})(globalThis.XEC);
