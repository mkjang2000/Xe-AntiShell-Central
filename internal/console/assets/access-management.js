((C) => {
  "use strict";

  const scopeStorage = "xeas.console.site", tabStorage = "xeas.console.access-tab";
  const el = C.el, id = C.id;
  const globalOnly = new Set(["accounts.manage", "roles.manage", "sites.manage", "sites.assign_agents",
    "policies.manage", "policies.trial", "updates.releases", "central.update"]);
  const permissionGroups = [
    ["에이전트", ["agents.read", "agents.enroll", "agents.revoke", "agents.removal_grant", "agents.remove",
      "agent_configuration.read", "agent_configuration.write"]],
    ["서버 그룹·보안 정책", ["groups.read", "groups.manage", "policies.read", "policies.manage", "policies.deploy", "policies.trial"]],
    ["탐지·감사", ["history.read", "findings.review", "audit.read"]],
    ["업데이트", ["updates.read", "updates.deploy", "updates.releases", "central.update"]],
    ["사이트·계정 관리", ["sites.manage", "sites.assign_agents", "accounts.manage", "roles.manage"]]
  ];
  const roleIDPattern = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/, siteIDPattern = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;

  C.can = (permission, scope = C.activeSite) => {
    if (!C.session?.permissions) return false;
    const scopes = C.array(C.session.permissions[permission]);
    if (globalOnly.has(permission)) return scopes.includes("*");
    return scopes.includes("*") || (scope ? scopes.includes(scope) : scopes.length > 0);
  };
  C.canGlobally = permission => C.array(C.session?.permissions?.[permission]).includes("*");

  let catalog = {permissions: [], roles: []}, accounts = [], sites = [], globalSites = false, agents = [];
  let accountsLoaded = false, agentsError = "";
  const rolesByID = new Map(), permissionsByID = new Map();
  const ui = {tab: "", accountName: "", roleID: "", siteID: "", siteForm: "", moveResults: null, selected: new Set()};
  let grantDraft = null, roleDraft = null;

  const option = (label, value) => {
    const item = el("option", "", label);
    item.value = value;
    return item;
  };
  const choose = (select, items, value = "") => {
    select.replaceChildren(...items.map(([key, label]) => option(label, key)));
    select.value = items.some(([key]) => key === value) ? value : items[0]?.[0] || "";
  };
  const scopeOptions = () => [
    ...(globalSites ? [["*", "모든 사이트"]] : []),
    ...sites.map(site => [site.id, site.name])
  ];
  C.siteOptions = scopeOptions;
  C.siteName = siteID => sites.find(site => site.id === siteID)?.name || siteID;

  C.loadSites = async () => {
    const [permissions, data] = await Promise.all([C.request("/api/session/permissions", {site: ""}), C.request("/api/sites", {site: ""})]);
    C.session.permissions = C.object(permissions?.permissions);
    sites = C.array(data?.sites);
    globalSites = data?.global === true;
    const selector = id("consoleSiteSelect");
    let stored = "";
    try { stored = sessionStorage.getItem(scopeStorage) || ""; } catch (_) {}
    choose(selector, scopeOptions(), stored);
    C.activeSite = selector.value;
    id("consoleSiteField").hidden = !selector.value;
    C.applyAccess();
  };

  // Shared helpers --------------------------------------------------------------------------
  const access = () => ({
    roles: C.canGlobally("roles.manage"), accounts: C.canGlobally("accounts.manage"),
    sites: C.canGlobally("sites.manage"), move: C.canGlobally("sites.assign_agents")
  });
  const scopeLabel = siteID => siteID === "*" ? "모든 사이트" : C.siteName(siteID);
  const roleLabel = roleID => rolesByID.get(roleID)?.name || roleID;
  const isGlobal = permission => permissionsByID.get(permission)?.scope === "global" || globalOnly.has(permission);
  const grantKey = (roleID, siteID) => roleID + "\n" + siteID;
  const splitKey = key => { const [role_id, site_id] = key.split("\n"); return {role_id, site_id}; };
  const byteLength = text => new TextEncoder().encode(text).length;
  const tag = (text, tone = "neutral") => C.tag ? C.tag(text, tone) : el("span", "tag " + tone, text);
  const accountGrants = account => C.array(account?.grants).filter(grant => grant?.role_id && grant?.site_id);
  const usage = roleID => accounts.flatMap(account => accountGrants(account)
    .filter(grant => grant.role_id === roleID).map(grant => ({account, grant})));
  const note = (text, tone = "") => el("p", "inline-note" + (tone ? " " + tone : ""), text);
  const listItem = ({title, detail, selected, tags = [], draft = false, action}) => {
    const item = el("button", "select-item" + (selected ? " selected" : "") + (draft ? " draft" : ""));
    item.type = "button";
    item.setAttribute("aria-pressed", String(Boolean(selected)));
    const head = el("span", "access-item-head"), marks = el("span", "access-item-tags");
    marks.append(...tags);
    head.append(el("strong", "", title), marks);
    item.append(head, el("small", "", detail));
    item.addEventListener("click", action);
    return item;
  };
  const personRow = (account, grants) => {
    const row = el("div", "access-person");
    const name = C.button(account.username, () => openAccount(account.username), "link-button");
    name.title = "계정별 권한에서 열기";
    const roles = el("span", "access-person-roles");
    roles.append(...grants.map(grant => tag(grant.label, grant.tone || "neutral")));
    row.append(name, roles);
    return row;
  };
  const focusTitle = node => { try { node.focus({preventScroll: true}); } catch (_) {} };

  // Tabs ------------------------------------------------------------------------------------
  const tabs = () => {
    const allowed = access();
    return {accounts: allowed.accounts, roles: allowed.roles || allowed.accounts, sites: allowed.sites || allowed.move};
  };
  const showTab = (wanted, persist = true) => {
    const visible = tabs();
    const tab = visible[wanted] ? wanted : Object.keys(visible).find(key => visible[key]) || "";
    ui.tab = tab;
    for (const key of Object.keys(visible)) {
      const button = id("accessTab-" + key);
      button.hidden = !visible[key];
      button.setAttribute("aria-pressed", String(key === tab));
      id("accessPane-" + key).hidden = key !== tab;
    }
    if (persist && tab) try { sessionStorage.setItem(tabStorage, tab); } catch (_) {}
  };

  // Account grants --------------------------------------------------------------------------
  const grantDraftFor = account => {
    const base = new Set(accountGrants(account).map(grant => grantKey(grant.role_id, grant.site_id)));
    return {username: account.username, version: account.version, base, current: new Set(base)};
  };
  const grantDiff = () => {
    if (!grantDraft) return {added: [], removed: []};
    return {
      added: [...grantDraft.current].filter(key => !grantDraft.base.has(key)).map(splitKey),
      removed: [...grantDraft.base].filter(key => !grantDraft.current.has(key)).map(splitKey)
    };
  };
  const grantDirty = () => { const diff = grantDiff(); return diff.added.length + diff.removed.length > 0; };
  const grantText = grant => scopeLabel(grant.site_id) + " · " + roleLabel(grant.role_id);
  const grantSummary = grants => {
    if (!grants.length) return "역할 없음 · 접근할 수 없음";
    const ordered = [...grants].sort((a, b) => (a.site_id === "*" ? -1 : 0) - (b.site_id === "*" ? -1 : 0));
    const shown = ordered.slice(0, 2).map(grantText).join(", ");
    return ordered.length > 2 ? shown + " 외 " + (ordered.length - 2) + "건" : shown;
  };

  const renderAccountList = () => {
    const list = id("grantAccountList"), filter = id("grantAccountFilter").value.trim().toLowerCase();
    const shown = accounts.filter(account => !filter || account.username.toLowerCase().includes(filter));
    id("grantAccountCount").textContent = accounts.length ? String(accounts.length) : "";
    if (!shown.length) {
      list.replaceChildren(C.empty(accounts.length ? "검색과 일치하는 계정이 없습니다." : "표시할 계정이 없습니다."));
      return;
    }
    list.replaceChildren(...shown.map(account => {
      const grants = accountGrants(account), tags = [];
      if (grantDraft?.username === account.username && grantDirty()) tags.push(tag("편집 중", "warning"));
      else if (!grants.length) tags.push(tag("권한 없음", "warning"));
      if (account.username === C.session?.username) tags.push(tag("나"));
      return listItem({title: account.username, detail: grantSummary(grants), selected: account.username === ui.accountName,
        tags, action: () => selectAccount(account.username)});
    }));
  };

  const matrixScopes = () => {
    const ids = ["*", ...sites.map(site => site.id)];
    for (const key of [...(grantDraft?.base || []), ...(grantDraft?.current || [])]) {
      const {site_id} = splitKey(key);
      if (!ids.includes(site_id)) ids.push(site_id);
    }
    return ids;
  };
  const matrixRoles = () => {
    const ids = C.array(catalog.roles).map(role => role.id);
    for (const key of [...(grantDraft?.base || []), ...(grantDraft?.current || [])]) {
      const {role_id} = splitKey(key);
      if (!ids.includes(role_id)) ids.push(role_id);
    }
    return ids;
  };

  const renderGrantMatrix = editable => {
    const table = el("table", "grant-matrix");
    const caption = el("caption", "sr-only", grantDraft.username + " 계정의 사이트별 역할");
    const head = el("tr"), corner = el("th", "", "적용 범위");
    corner.scope = "col";
    head.append(corner);
    const roles = matrixRoles();
    for (const roleID of roles) {
      const role = rolesByID.get(roleID), cell = el("th", "", role?.name || roleID);
      cell.scope = "col";
      cell.append(el("small", "", role ? (role.builtin ? "기본 역할" : "권한 " + C.array(role.permissions).length + "개") : "알 수 없는 역할"));
      head.append(cell);
    }
    const thead = el("thead"), tbody = el("tbody");
    thead.append(head);
    for (const siteID of matrixScopes()) {
      const row = el("tr", siteID === "*" ? "global-scope" : "");
      const label = el("th", "", scopeLabel(siteID));
      label.scope = "row";
      label.append(el("small", "", siteID === "*" ? "현재와 이후 만드는 모든 사이트" : siteID));
      row.append(label);
      for (const roleID of roles) {
        const key = grantKey(roleID, siteID), cell = el("td"), box = el("label", "grant-cell"), input = el("input");
        Object.assign(input, {type: "checkbox", checked: grantDraft.current.has(key), disabled: !editable});
        Object.assign(input.dataset, {role: roleID, site: siteID});
        input.setAttribute("aria-label", scopeLabel(siteID) + "에서 " + roleLabel(roleID));
        box.append(input);
        cell.append(box);
        paintGrantCell(cell, key);
        row.append(cell);
      }
      tbody.append(row);
    }
    table.append(caption, thead, tbody);
    id("grantMatrix").replaceChildren(table);
  };
  const paintGrantCell = (cell, key) => {
    const on = grantDraft.current.has(key), was = grantDraft.base.has(key);
    cell.classList.toggle("on", on);
    cell.classList.toggle("added", on && !was);
    cell.classList.toggle("removed", !on && was);
  };

  const renderGrantStatus = () => {
    const allowed = access(), diff = grantDiff(), dirty = diff.added.length + diff.removed.length > 0;
    const current = [...grantDraft.current].map(splitKey);
    const warnings = [];
    if (!current.length) warnings.push("역할이 하나도 없으면 이 계정은 어떤 사이트에도 접근할 수 없습니다.");
    const globalRoles = new Set(current.filter(grant => grant.site_id === "*").map(grant => grant.role_id));
    const narrowed = new Map();
    for (const grant of current) {
      if (grant.site_id === "*") continue;
      if (globalRoles.has(grant.role_id)) {
        warnings.push(`'${roleLabel(grant.role_id)}' 역할이 이미 모든 사이트에 부여되어 있어 ${scopeLabel(grant.site_id)} 부여는 효과가 없습니다.`);
        continue;
      }
      const lost = C.array(rolesByID.get(grant.role_id)?.permissions).filter(isGlobal);
      if (lost.length) narrowed.set(grant.role_id, lost);
    }
    for (const [roleID, lost] of narrowed) {
      const labels = lost.map(permission => permissionsByID.get(permission)?.label || permission);
      warnings.push(`'${roleLabel(roleID)}' 역할의 전역 권한 ${lost.length}개(${labels.slice(0, 3).join(", ")}${labels.length > 3 ? " 등" : ""})는 사이트 단위로 부여하면 적용되지 않습니다. 필요하면 '모든 사이트'에 부여하세요.`);
    }
    const box = el("div", "access-notes");
    box.append(...warnings.map(text => note(text, "warning")));
    id("grantWarnings").replaceChildren(...(warnings.length ? [box] : []));

    const changes = id("grantChanges");
    changes.hidden = !dirty;
    if (dirty) {
      const list = el("ul");
      for (const grant of diff.added) { const item = el("li"); item.append(tag("추가", "good"), el("span", "", grantText(grant))); list.append(item); }
      for (const grant of diff.removed) { const item = el("li"); item.append(tag("제거", "danger"), el("span", "", grantText(grant))); list.append(item); }
      changes.replaceChildren(el("h4", "", "저장할 변경"), list);
    }
    const status = id("grantDirty");
    status.textContent = dirty ? `저장하지 않은 변경 ${diff.added.length + diff.removed.length}건` : "변경 없음";
    status.classList.toggle("dirty", dirty);
    id("grantSavebar").hidden = !allowed.roles;
    id("grantReset").disabled = !dirty;
    id("grantSave").disabled = !dirty || !allowed.roles;
    const summary = id("grantSummary");
    summary.replaceChildren(tag(current.length ? "역할 " + current.length + "건" : "역할 없음", current.length ? "neutral" : "warning"));
    if (globalRoles.size) summary.append(tag("모든 사이트 권한 포함", "blue"));
    renderAccountList();
  };

  const renderGrantEditor = () => {
    const account = accounts.find(item => item.username === ui.accountName);
    const allowed = access(), notes = el("div", "access-notes");
    id("grantEditor").hidden = !account;
    if (!account) {
      id("grantEyebrow").textContent = "계정";
      id("grantTitle").textContent = accounts.length ? "왼쪽에서 계정을 선택하세요" : "표시할 계정이 없습니다";
      id("grantSummary").replaceChildren();
      id("grantNotes").replaceChildren(note("계정을 선택하면 사이트마다 어떤 역할을 받았는지 표로 보고 바로 바꿀 수 있습니다."));
      return;
    }
    if (grantDraft?.username !== account.username) grantDraft = grantDraftFor(account);
    id("grantEyebrow").textContent = account.username === C.session?.username ? "내 계정" : "계정";
    id("grantTitle").textContent = account.username;
    if (!allowed.roles) notes.append(note("역할 부여를 바꾸려면 '권한 역할·할당 관리' 권한이 필요합니다. 지금은 조회만 할 수 있습니다."));
    if (!account.explicit_grants) notes.append(note(`계정 관리에서 지정한 기본 역할(${roleLabel(account.role)})이 모든 사이트에 적용되는 계정입니다. 여기서 저장하면 사이트별 역할 부여로 바뀝니다.`));
    if (account.username === C.session?.username && allowed.roles) notes.append(note("본인 계정입니다. 저장하면 바뀐 권한으로 페이지를 다시 불러옵니다.", "warning"));
    id("grantNotes").replaceChildren(...(notes.childNodes.length ? [notes] : []));
    renderGrantMatrix(allowed.roles);
    renderGrantStatus();
  };

  const confirmDiscard = async (dirty, what) => !dirty || C.confirm({
    title: "편집 내용 버리기", description: what + "에 저장하지 않은 변경이 있습니다. 버리고 이동할까요?", accept: "변경 버리기"
  });
  const selectAccount = async username => {
    if (username === ui.accountName) return;
    if (!await confirmDiscard(grantDirty(), grantDraft?.username + " 계정")) return;
    ui.accountName = username;
    grantDraft = null;
    renderAccountList();
    renderGrantEditor();
    focusTitle(id("grantTitle"));
  };
  const openAccount = async username => {
    showTab("accounts");
    await selectAccount(username);
  };

  const saveGrants = async () => {
    const account = accounts.find(item => item.username === grantDraft?.username);
    if (!account || !grantDirty()) return;
    const diff = grantDiff();
    const grants = [
      ...accountGrants(account).filter(grant => grantDraft.current.has(grantKey(grant.role_id, grant.site_id))),
      ...diff.added
    ].map(grant => ({role_id: grant.role_id, site_id: grant.site_id}));
    const parts = [];
    if (diff.added.length) parts.push("추가: " + diff.added.map(grantText).join(", "));
    if (diff.removed.length) parts.push("제거: " + diff.removed.map(grantText).join(", "));
    if (!grants.length) parts.push("저장하면 이 계정은 어떤 사이트에도 접근할 수 없습니다.");
    if (!await C.confirm({title: account.username + " 계정의 역할 부여 저장", description: parts.join(" · "), accept: "역할 부여 저장"})) return;
    await C.request("/api/accounts/" + encodeURIComponent(account.username) + "/grants", {method: "POST", body: {version: account.version, grants}});
    if (account.username === C.session.username) return globalThis.location.reload();
    grantDraft = null;
    await loadData();
    C.notify(account.username + " 계정의 역할 부여를 저장했습니다.");
  };

  // Roles -----------------------------------------------------------------------------------
  const roleDraftFor = (role, copy = false) => ({
    base: copy ? null : role || null,
    id: copy ? "" : role?.id || "",
    name: copy && role ? role.name + " 복사본" : role?.name || "",
    permissions: new Set(C.array(role?.permissions))
  });
  const roleDirty = () => {
    if (!roleDraft) return false;
    const base = roleDraft.base;
    if (!base) return Boolean(roleDraft.id.trim() || roleDraft.name.trim() || roleDraft.permissions.size);
    const saved = new Set(C.array(base.permissions));
    return roleDraft.name.trim() !== base.name || saved.size !== roleDraft.permissions.size ||
      [...saved].some(permission => !roleDraft.permissions.has(permission));
  };
  const orderedPermissions = () => {
    const known = permissionGroups.flatMap(([, ids]) => ids);
    const extra = C.array(catalog.permissions).map(permission => permission.id).filter(permission => !known.includes(permission));
    const groups = permissionGroups.map(([label, ids]) => [label, ids.filter(permission => permissionsByID.has(permission))]);
    if (extra.length) groups.push(["기타", extra]);
    return groups.filter(([, ids]) => ids.length);
  };

  const renderRoleList = () => {
    const list = id("roleList"), roles = C.array(catalog.roles);
    id("roleCount").textContent = roles.length ? String(roles.length) : "";
    const items = roles.map(role => {
      const tags = [];
      if (roleDraft?.base?.id === role.id && roleDirty()) tags.push(tag("편집 중", "warning"));
      else if (role.builtin) tags.push(tag("기본"));
      const count = accountsLoaded ? " · 계정 " + new Set(usage(role.id).map(entry => entry.account.username)).size + "명" : "";
      return listItem({title: role.name, detail: "권한 " + C.array(role.permissions).length + "개" + count,
        selected: role.id === ui.roleID && roleDraft?.base?.id === role.id, tags, action: () => selectRole(role.id)});
    });
    if (roleDraft && !roleDraft.base) {
      items.push(listItem({title: roleDraft.name.trim() || "새 역할", detail: "작성 중 · 권한 " + roleDraft.permissions.size + "개",
        selected: true, draft: true, tags: [tag("새 역할", "blue")], action: () => {}}));
    }
    list.replaceChildren(...(items.length ? items : [C.empty("역할이 없습니다.")]));
  };

  const renderRoleStatus = () => {
    if (!roleDraft) return;
    const allowed = access(), base = roleDraft.base, editable = allowed.roles && !base?.builtin;
    const permissions = [...roleDraft.permissions], globals = permissions.filter(isGlobal).length;
    id("roleTitle").textContent = roleDraft.name.trim() || base?.name || "새 역할";
    const summary = id("roleSummary");
    summary.replaceChildren(tag("권한 " + permissions.length + "개"));
    if (globals) summary.append(tag("전역 권한 " + globals + "개", "blue"));
    if (base && accountsLoaded) {
      const people = new Set(usage(base.id).map(entry => entry.account.username)).size;
      summary.append(people ? tag("계정 " + people + "명에게 부여됨", "good") : tag("부여된 계정 없음"));
    }
    for (const group of id("rolePermissions").querySelectorAll(".permission-group")) {
      const inputs = [...group.querySelectorAll("input[type=checkbox]")];
      const checked = inputs.filter(input => input.checked).length;
      group.querySelector(".permission-count").textContent = checked + "/" + inputs.length;
      const toggle = group.querySelector(".permission-toggle");
      if (toggle) toggle.textContent = checked === inputs.length ? "모두 해제" : "모두 선택";
      for (const input of inputs) {
        const before = base ? C.array(base.permissions).includes(input.value) : false;
        input.closest(".permission-item").classList.toggle("changed", Boolean(base) && input.checked !== before);
      }
    }
    const dirty = roleDirty();
    const status = id("roleDirty");
    status.textContent = base ? (dirty ? "저장하지 않은 변경이 있습니다" : "변경 없음") : "새 역할은 저장해야 계정에 부여할 수 있습니다";
    status.classList.toggle("dirty", Boolean(base) && dirty);
    id("roleSavebar").hidden = !editable;
    id("roleReset").disabled = !dirty;
    id("roleSave").textContent = base ? "역할 저장" : "역할 만들기";
    id("roleSave").disabled = !editable || (base ? !dirty : !roleDraft.id.trim() || !roleDraft.name.trim());
    renderRoleList();
  };

  const renderRoleEditor = () => {
    const allowed = access(), roles = C.array(catalog.roles);
    if (!roleDraft) {
      const role = rolesByID.get(ui.roleID) || roles[0];
      if (!role) {
        id("roleTitle").textContent = "역할이 없습니다";
        return;
      }
      ui.roleID = role.id;
      roleDraft = roleDraftFor(role);
    }
    const base = roleDraft.base, editable = allowed.roles && !base?.builtin;
    id("roleNew").hidden = !allowed.roles;
    id("roleEyebrow").textContent = base ? (base.builtin ? "기본 역할 · " : "역할 · ") + base.id : "새 역할";
    const duplicate = id("roleDuplicate"), remove = id("roleDelete");
    duplicate.hidden = !allowed.roles || !base;
    remove.hidden = !allowed.roles || !base || base.builtin;
    const people = base && accountsLoaded ? new Set(usage(base.id).map(entry => entry.account.username)).size : 0;
    remove.disabled = people > 0;
    remove.title = people > 0 ? "계정 " + people + "명에게 부여되어 있습니다. 먼저 계정별 권한에서 부여를 제거하세요." : "";
    const roleNote = id("roleNote");
    roleNote.hidden = editable;
    roleNote.textContent = !allowed.roles ? "역할을 편집하려면 '권한 역할·할당 관리' 권한이 필요합니다. 지금은 조회만 할 수 있습니다." :
      "기본 역할은 바꿀 수 없습니다. 복제해서 새 역할로 만든 뒤 편집하세요.";
    id("roleFields").hidden = !editable;
    id("roleIDField").hidden = Boolean(base);
    id("roleID").value = roleDraft.id;
    id("roleName").value = roleDraft.name;

    id("rolePermissions").replaceChildren(...orderedPermissions().map(([label, ids]) => {
      const group = el("div", "permission-group"), head = el("div", "permission-group-head"), heading = el("h4", "", label);
      group.setAttribute("role", "group");
      group.setAttribute("aria-label", label);
      heading.append(el("small", "permission-count"));
      head.append(heading);
      if (editable) {
        const toggle = C.button("모두 선택", () => {
          const inputs = [...group.querySelectorAll("input[type=checkbox]")], value = !inputs.every(input => input.checked);
          for (const input of inputs) {
            input.checked = value;
            if (value) roleDraft.permissions.add(input.value); else roleDraft.permissions.delete(input.value);
          }
          renderRoleStatus();
        }, "quiet permission-toggle");
        head.append(toggle);
      }
      group.append(head);
      for (const permissionID of ids) {
        const permission = permissionsByID.get(permissionID), item = el("label", "permission-item"), input = el("input");
        Object.assign(input, {type: "checkbox", value: permissionID, checked: roleDraft.permissions.has(permissionID), disabled: !editable});
        const text = el("span", "", permission?.label || permissionID);
        text.append(el("code", "", permissionID));
        item.append(input, text);
        if (isGlobal(permissionID)) item.append(tag("전역", "blue"));
        group.append(item);
      }
      return group;
    }));

    const usageSection = id("roleUsageSection");
    usageSection.hidden = !base || !accountsLoaded;
    if (base && accountsLoaded) {
      const byAccount = new Map();
      for (const {account, grant} of usage(base.id)) {
        if (!byAccount.has(account.username)) byAccount.set(account.username, {account, grants: []});
        byAccount.get(account.username).grants.push({label: scopeLabel(grant.site_id), tone: grant.site_id === "*" ? "blue" : "neutral"});
      }
      const people = el("div", "access-people");
      people.append(...[...byAccount.values()].map(entry => personRow(entry.account, entry.grants)));
      id("roleUsage").replaceChildren(byAccount.size ? people : C.empty("이 역할을 받은 계정이 없습니다."));
    }
    renderRoleStatus();
  };

  const selectRole = async roleID => {
    if (roleDraft?.base?.id === roleID) return;
    if (!await confirmDiscard(roleDirty(), "역할 편집")) return;
    ui.roleID = roleID;
    roleDraft = roleDraftFor(rolesByID.get(roleID));
    renderRoleEditor();
    focusTitle(id("roleTitle"));
  };
  const startRole = async (from = null) => {
    if (!await confirmDiscard(roleDirty(), "역할 편집")) return;
    ui.roleID = "";
    roleDraft = roleDraftFor(from, true);
    renderRoleEditor();
    id("roleID").focus();
  };

  const saveRole = async () => {
    const draft = roleDraft, base = draft?.base;
    if (!draft || base?.builtin) return;
    const name = draft.name.trim(), roleID = draft.id.trim();
    if (!base && !roleIDPattern.test(roleID)) throw new Error("역할 ID는 영문·숫자로 시작하고 영문·숫자와 . _ : - 만 쓸 수 있습니다 (최대 64자).");
    if (!base && rolesByID.has(roleID)) throw new Error("이미 있는 역할 ID입니다. 다른 ID를 입력하세요.");
    if (!name) throw new Error("역할 이름을 입력하세요.");
    if (byteLength(name) > 144) throw new Error("역할 이름이 너무 깁니다. 더 짧게 입력하세요.");
    const order = C.array(catalog.permissions).map(permission => permission.id);
    const permissions = [...draft.permissions].sort((a, b) => order.indexOf(a) - order.indexOf(b));
    const body = {name, permissions};
    if (base) body.version = base.version;
    else body.id = roleID;
    const saved = await C.request("/api/rbac/roles" + (base ? "/" + encodeURIComponent(base.id) : ""), {method: "POST", body});
    roleDraft = null;
    ui.roleID = saved?.id || roleID;
    await loadData();
    C.notify(base ? `'${name}' 역할을 저장했습니다.` : `'${name}' 역할을 만들었습니다. 계정별 권한에서 계정에 부여하세요.`);
  };
  const deleteRole = async () => {
    const role = roleDraft?.base;
    if (!role || role.builtin) return;
    if (!await C.confirm({title: "역할 삭제", description: `'${role.name}' (${role.id}) 역할을 삭제합니다. 되돌릴 수 없습니다.`, accept: "역할 삭제"})) return;
    await C.request("/api/rbac/roles/" + encodeURIComponent(role.id) + "?version=" + role.version, {method: "DELETE"});
    roleDraft = null;
    ui.roleID = "";
    await loadData();
    C.notify(`'${role.name}' 역할을 삭제했습니다.`);
  };

  // Sites -----------------------------------------------------------------------------------
  const siteAgents = siteID => agents.filter(agent => agent.site_id === siteID);
  const siteAccess = siteID => accounts.map(account => ({
    account, grants: accountGrants(account).filter(grant => grant.site_id === siteID || grant.site_id === "*")
  })).filter(entry => entry.grants.length);

  const renderSiteList = () => {
    const list = id("siteList"), allowed = access();
    id("siteCount").textContent = sites.length ? String(sites.length) : "";
    id("siteNew").hidden = !allowed.sites;
    const items = sites.map(site => {
      const parts = [site.id];
      if (!agentsError) parts.push("에이전트 " + siteAgents(site.id).filter(agent => !agent.revoked).length + "대");
      if (accountsLoaded) parts.push("계정 " + siteAccess(site.id).length + "명");
      return listItem({title: site.name, detail: parts.join(" · "), selected: site.id === ui.siteID && ui.siteForm !== "new",
        tags: site.id === C.activeSite ? [tag("보는 중", "blue")] : [], action: () => selectSite(site.id)});
    });
    if (ui.siteForm === "new") items.push(listItem({title: id("siteName").value.trim() || "새 사이트", detail: "작성 중",
      selected: true, draft: true, tags: [tag("새 사이트", "blue")], action: () => {}}));
    list.replaceChildren(...(items.length ? items : [C.empty("사이트가 없습니다.")]));
  };

  const renderSiteAgents = site => {
    const allowed = access(), filter = id("siteAgentFilter").value.trim().toLowerCase();
    const members = siteAgents(site.id);
    const active = members.filter(agent => !agent.revoked);
    id("siteAgentCount").textContent = String(active.length) + (members.length > active.length ? " · 해지 " + (members.length - active.length) : "");
    for (const agentID of [...ui.selected]) if (!active.some(agent => agent.agent_id === agentID)) ui.selected.delete(agentID);
    id("siteMoveBar").hidden = !allowed.move || Boolean(agentsError) || !active.length;
    if (agentsError) {
      id("siteAgents").replaceChildren(C.empty(agentsError));
      return;
    }
    const shown = members.filter(agent => !filter || (agent.agent_id + " " + (agent.hostname || "")).toLowerCase().includes(filter));
    if (!shown.length) {
      id("siteAgents").replaceChildren(C.empty(members.length ? "검색과 일치하는 에이전트가 없습니다." : "이 사이트에 등록된 에이전트가 없습니다."));
      renderMoveBar(site);
      return;
    }
    const table = el("table", "access-agent-table"), thead = el("thead"), head = el("tr"), tbody = el("tbody");
    const selectable = shown.filter(agent => !agent.revoked);
    if (allowed.move) {
      const all = el("input"), cell = el("th", "check-column");
      Object.assign(all, {type: "checkbox", checked: selectable.length > 0 && selectable.every(agent => ui.selected.has(agent.agent_id)), disabled: !selectable.length});
      all.indeterminate = !all.checked && selectable.some(agent => ui.selected.has(agent.agent_id));
      all.setAttribute("aria-label", "표시된 에이전트 모두 선택");
      all.addEventListener("change", () => {
        for (const agent of selectable) if (all.checked) ui.selected.add(agent.agent_id); else ui.selected.delete(agent.agent_id);
        renderSiteAgents(site);
      });
      cell.scope = "col";
      cell.append(all);
      head.append(cell);
    }
    for (const label of ["에이전트", "상태", "마지막 보고"]) { const cell = el("th", "", label); cell.scope = "col"; head.append(cell); }
    thead.append(head);
    for (const agent of shown) {
      const row = el("tr", ui.selected.has(agent.agent_id) ? "selected" : ""), connection = C.connection ? C.connection(agent) : {label: agent.revoked ? "등록 해지" : "미확인", tone: agent.revoked ? "danger" : "neutral"};
      if (allowed.move) {
        const box = el("input"), cell = el("td", "check-column");
        Object.assign(box, {type: "checkbox", checked: ui.selected.has(agent.agent_id), disabled: Boolean(agent.revoked)});
        box.setAttribute("aria-label", agent.agent_id + " 선택");
        box.addEventListener("change", () => {
          if (box.checked) ui.selected.add(agent.agent_id); else ui.selected.delete(agent.agent_id);
          renderSiteAgents(site);
        });
        cell.append(box);
        row.append(cell);
      }
      const name = el("td");
      name.append(el("strong", "", agent.hostname || agent.agent_id), el("span", "secondary", agent.agent_id));
      const state = el("td");
      state.append(tag(connection.label, connection.tone));
      const seen = C.object(agent.heartbeat).sent_at || agent.last_seen_at;
      row.append(name, state, el("td", "", C.age ? C.age(seen) : C.time(seen)));
      tbody.append(row);
    }
    table.append(el("caption", "sr-only", site.name + " 사이트의 에이전트"), thead, tbody);
    id("siteAgents").replaceChildren(table);
    renderMoveBar(site);
  };

  const renderMoveBar = site => {
    const count = ui.selected.size, target = id("siteMoveTarget"), previous = target.value;
    choose(target, [["", "사이트 선택"], ...sites.filter(item => item.id !== site.id).map(item => [item.id, item.name])], previous);
    id("siteMoveSelected").textContent = count ? `${count}대 선택됨` : "옮길 에이전트를 선택하세요";
    id("siteMoveSave").disabled = !count || !target.value;
    id("siteMoveSave").textContent = count ? `${count}대 이동…` : "선택한 에이전트 이동…";
  };

  const renderMoveResults = () => {
    const box = id("siteMoveResult"), results = ui.moveResults;
    if (!results?.length) { box.replaceChildren(); return; }
    const failed = results.filter(result => !result.ok);
    if (!failed.length) { box.replaceChildren(); return; }
    const wrap = el("div", "access-notes");
    wrap.append(note(`${failed.length}대는 옮기지 못했습니다. 선택을 유지했으니 원인을 확인한 뒤 다시 시도하세요.`, "warning"));
    const list = el("div", "access-people");
    for (const result of failed) {
      const row = el("div", "access-person");
      row.append(el("strong", "", result.agent), el("span", "muted", result.error));
      list.append(row);
    }
    wrap.append(list);
    box.replaceChildren(wrap);
  };

  const renderSiteEditor = () => {
    const allowed = access();
    if (ui.siteForm !== "new" && !sites.some(site => site.id === ui.siteID)) ui.siteID = sites.find(site => site.id === C.activeSite)?.id || sites[0]?.id || "";
    const site = sites.find(item => item.id === ui.siteID);
    const creating = ui.siteForm === "new", renaming = ui.siteForm === "rename" && Boolean(site);
    id("siteForm").hidden = !creating && !renaming;
    id("siteIDField").hidden = !creating;
    id("siteSave").textContent = creating ? "사이트 만들기" : "이름 저장";
    id("siteRename").hidden = !allowed.sites || creating || !site;
    id("siteRename").disabled = renaming;
    id("siteAgentsSection").hidden = creating || !site;
    id("siteAccessSection").hidden = creating || !site || !accountsLoaded;
    if (creating) {
      id("siteEyebrow").textContent = "새 사이트";
      id("siteTitle").textContent = id("siteName").value.trim() || "새 사이트";
      id("siteSummary").replaceChildren();
      renderSiteList();
      return;
    }
    if (!site) {
      id("siteEyebrow").textContent = "사이트";
      id("siteTitle").textContent = "사이트가 없습니다";
      id("siteSummary").replaceChildren();
      renderSiteList();
      return;
    }
    id("siteEyebrow").textContent = "사이트 · " + site.id;
    id("siteTitle").textContent = site.name;
    const summary = id("siteSummary");
    summary.replaceChildren();
    if (!agentsError) summary.append(tag("에이전트 " + siteAgents(site.id).filter(agent => !agent.revoked).length + "대"));
    if (accountsLoaded) summary.append(tag("접근 계정 " + siteAccess(site.id).length + "명"));
    if (site.id === C.activeSite) summary.append(tag("상단에서 보는 중", "blue"));
    renderSiteAgents(site);
    renderMoveResults();
    if (accountsLoaded) {
      const entries = siteAccess(site.id);
      const direct = entries.filter(entry => entry.grants.some(grant => grant.site_id === site.id));
      const everywhere = entries.filter(entry => !entry.grants.some(grant => grant.site_id === site.id));
      const block = (label, list) => {
        if (!list.length) return [];
        const people = el("div", "access-people");
        people.append(...list.map(entry => personRow(entry.account, entry.grants.map(grant => ({
          label: roleLabel(grant.role_id) + (grant.site_id === "*" ? " · 모든 사이트" : ""), tone: grant.site_id === "*" ? "blue" : "neutral"
        })))));
        return [el("p", "access-group-label", label + " " + list.length + "명"), people];
      };
      const nodes = [...block("이 사이트에 지정", direct), ...block("모든 사이트 권한으로 접근", everywhere)];
      id("siteAccounts").replaceChildren(...(nodes.length ? nodes : [C.empty("이 사이트에 접근할 수 있는 계정이 없습니다. 계정별 권한에서 역할을 부여하세요.")]));
    }
    renderSiteList();
  };

  const selectSite = siteID => {
    if (siteID === ui.siteID && !ui.siteForm) return;
    ui.siteID = siteID;
    ui.siteForm = "";
    ui.selected.clear();
    ui.moveResults = null;
    id("siteAgentFilter").value = "";
    renderSiteEditor();
    focusTitle(id("siteTitle"));
  };
  const openSiteForm = mode => {
    ui.siteForm = mode;
    const site = sites.find(item => item.id === ui.siteID);
    id("siteID").value = "";
    id("siteName").value = mode === "rename" ? site?.name || "" : "";
    renderSiteEditor();
    (mode === "new" ? id("siteID") : id("siteName")).focus();
  };
  const saveSite = async () => {
    const creating = ui.siteForm === "new", existing = creating ? null : sites.find(site => site.id === ui.siteID);
    const siteID = creating ? id("siteID").value.trim() : existing?.id, name = id("siteName").value.trim();
    if (!siteID) throw new Error("사이트 ID를 입력하세요.");
    if (creating && !siteIDPattern.test(siteID)) throw new Error("사이트 ID는 영문·숫자로 시작하고 영문·숫자와 . _ - 만 쓸 수 있습니다.");
    if (creating && sites.some(site => site.id === siteID)) throw new Error("이미 있는 사이트 ID입니다. 다른 ID를 입력하세요.");
    if (!name) throw new Error("사이트 이름을 입력하세요.");
    if (byteLength(name) > 256) throw new Error("사이트 이름이 너무 깁니다. 더 짧게 입력하세요.");
    await C.request("/api/sites", {method: "POST", site: "", body: {id: siteID, name, version: existing?.version || 0}});
    await C.loadSites();
    ui.siteID = siteID;
    ui.siteForm = "";
    await loadData();
    C.notify(creating ? `'${name}' 사이트를 만들었습니다.` : "사이트 이름을 바꿨습니다.");
  };

  const moveAgents = async () => {
    const site = sites.find(item => item.id === ui.siteID), target = id("siteMoveTarget").value;
    const selected = siteAgents(ui.siteID).filter(agent => ui.selected.has(agent.agent_id) && !agent.revoked);
    if (!site || !target || !selected.length || target === site.id) return;
    if (!await C.confirm({
      title: "에이전트 사이트 이동",
      description: `${selected.length}대를 ${site.name}에서 ${C.siteName(target)}(으)로 옮깁니다. 이전 사이트의 서버 그룹에서 빠지고, 다음 보고 전까지 상태가 '보고 없음'으로 보입니다. 업데이트·제거 작업이 진행 중인 에이전트는 옮겨지지 않습니다.`,
      accept: selected.length + "대 이동"
    })) return;
    const results = [];
    for (const [index, agent] of selected.entries()) {
      id("siteMoveSelected").textContent = `옮기는 중… ${index + 1}/${selected.length}`;
      try {
        await C.request("/api/sites/" + encodeURIComponent(target) + "/agents", {method: "POST", site: "", body: {agent_id: agent.agent_id, enrollment_id: agent.enrollment_id}});
        results.push({agent: agent.agent_id, ok: true});
        ui.selected.delete(agent.agent_id);
      } catch (error) {
        results.push({agent: agent.agent_id, ok: false, error: error instanceof Error ? error.message : String(error)});
      }
    }
    ui.moveResults = results;
    await loadData();
    await C.refresh?.();
    const moved = results.filter(result => result.ok).length, failed = results.length - moved;
    if (moved) C.notify(`${moved}대를 ${C.siteName(target)}(으)로 옮겼습니다.` + (failed ? ` ${failed}대는 옮기지 못했습니다.` : ""));
    else C.error("선택한 에이전트를 옮기지 못했습니다. 아래 사유를 확인하세요.");
  };

  // Loading ---------------------------------------------------------------------------------
  const setCatalog = data => {
    catalog = {permissions: C.array(data?.permissions), roles: C.array(data?.roles)};
    rolesByID.clear();
    permissionsByID.clear();
    for (const role of catalog.roles) rolesByID.set(role.id, role);
    for (const permission of catalog.permissions) permissionsByID.set(permission.id, permission);
  };
  const render = () => {
    showTab(ui.tab, false);
    const visible = tabs();
    if (visible.accounts) { renderAccountList(); renderGrantEditor(); }
    if (visible.roles) renderRoleEditor();
    if (visible.sites) renderSiteEditor();
  };
  const loadData = async () => {
    const allowed = access();
    const [rbac, accountData, state] = await Promise.all([
      allowed.roles || allowed.accounts ? C.request("/api/rbac") : null,
      allowed.accounts ? C.request("/api/accounts") : null,
      allowed.sites || allowed.move ? C.request("/api/state", {site: "*"}).catch(error => ({failed: error})) : null
    ]);
    if (rbac) setCatalog(rbac);
    accountsLoaded = Boolean(accountData);
    accounts = C.array(Array.isArray(accountData) ? accountData : accountData?.accounts)
      .slice().sort((a, b) => a.username.localeCompare(b.username));
    agents = state && !state.failed ? C.array(state.agents) : [];
    agentsError = state?.failed ? "에이전트 목록을 불러오지 못했습니다. 모든 사이트의 에이전트 조회 권한이 필요합니다." : "";
    const account = accounts.find(item => item.username === grantDraft?.username);
    if (grantDraft && (!account || account.version !== grantDraft.version || !grantDirty())) grantDraft = null;
    if (!accounts.some(item => item.username === ui.accountName)) ui.accountName = accounts[0]?.username || "";
    const role = roleDraft?.base && rolesByID.get(roleDraft.base.id);
    if (roleDraft?.base && (!role || role.version !== roleDraft.base.version || !roleDirty())) roleDraft = null;
    render();
  };

  const siteFormDirty = () => {
    if (ui.siteForm === "new") return Boolean(id("siteID").value.trim() || id("siteName").value.trim());
    return ui.siteForm === "rename" && id("siteName").value.trim() !== (sites.find(site => site.id === ui.siteID)?.name || "");
  };
  C.hasUnsavedAccess = () => grantDirty() || roleDirty() || siteFormDirty();
  // C.run restores each button's previous disabled state, so recompute state-derived controls afterwards.
  const act = (button, operation, after) => C.run(button, operation).then(() => after());
  C.loadAccessManagement = async () => {
    if (!ui.tab) {
      let stored = "";
      try { stored = sessionStorage.getItem(tabStorage) || ""; } catch (_) {}
      ui.tab = stored;
    }
    showTab(ui.tab, false);
    await loadData();
  };

  C.initAccessManagement = () => {
    id("consoleSiteSelect").addEventListener("change", async event => {
      const value = event.target.value;
      if (value === C.activeSite) return;
      if ((C.hasUnsavedPolicy?.() || C.hasUnsavedGroup?.() || C.hasUnsavedAccess()) && !await C.confirm({
        title: "사이트 바꾸기", description: "저장하지 않은 편집 내용이 사라집니다.", accept: "사이트 바꾸기"
      })) {
        event.target.value = C.activeSite;
        return;
      }
      try { sessionStorage.setItem(scopeStorage, value); } catch (_) {}
      C.changingSite = true;
      globalThis.location.reload();
    });
    for (const button of document.querySelectorAll("[data-access-tab]")) {
      button.addEventListener("click", () => showTab(button.dataset.accessTab));
    }

    id("grantAccountFilter").addEventListener("input", renderAccountList);
    id("grantMatrix").addEventListener("change", event => {
      const input = event.target;
      if (!grantDraft || !input?.dataset?.role || !input.dataset.site) return;
      const key = grantKey(input.dataset.role, input.dataset.site);
      if (input.checked) grantDraft.current.add(key); else grantDraft.current.delete(key);
      paintGrantCell(input.closest("td"), key);
      renderGrantStatus();
    });
    id("grantReset").addEventListener("click", () => {
      if (!grantDraft) return;
      grantDraft.current = new Set(grantDraft.base);
      renderGrantEditor();
    });
    id("grantSave").addEventListener("click", () => act(id("grantSave"), saveGrants, () => { if (grantDraft) renderGrantStatus(); }));

    id("roleNew").addEventListener("click", () => startRole());
    id("roleDuplicate").addEventListener("click", () => startRole(roleDraft?.base));
    id("roleDelete").addEventListener("click", () => act(id("roleDelete"), deleteRole, renderRoleEditor));
    id("roleID").addEventListener("input", event => { if (roleDraft) { roleDraft.id = event.target.value; renderRoleStatus(); } });
    id("roleName").addEventListener("input", event => { if (roleDraft) { roleDraft.name = event.target.value; renderRoleStatus(); } });
    id("rolePermissions").addEventListener("change", event => {
      const input = event.target;
      if (!roleDraft || input?.type !== "checkbox") return;
      if (input.checked) roleDraft.permissions.add(input.value); else roleDraft.permissions.delete(input.value);
      renderRoleStatus();
    });
    id("roleReset").addEventListener("click", () => {
      if (!roleDraft) return;
      if (!roleDraft.base) { roleDraft = null; ui.roleID = C.array(catalog.roles)[0]?.id || ""; }
      else roleDraft = roleDraftFor(roleDraft.base);
      renderRoleEditor();
    });
    id("roleForm").addEventListener("submit", event => {
      event.preventDefault();
      act(id("roleSave"), saveRole, renderRoleStatus);
    });

    id("siteNew").addEventListener("click", () => openSiteForm("new"));
    id("siteRename").addEventListener("click", () => openSiteForm("rename"));
    id("siteCancel").addEventListener("click", () => { ui.siteForm = ""; renderSiteEditor(); });
    id("siteName").addEventListener("input", () => { if (ui.siteForm === "new") { id("siteTitle").textContent = id("siteName").value.trim() || "새 사이트"; renderSiteList(); } });
    id("siteForm").addEventListener("submit", event => {
      event.preventDefault();
      C.run(id("siteSave"), saveSite);
    });
    id("siteAgentFilter").addEventListener("input", () => {
      const site = sites.find(item => item.id === ui.siteID);
      if (site) renderSiteAgents(site);
    });
    id("siteMoveTarget").addEventListener("change", () => {
      const site = sites.find(item => item.id === ui.siteID);
      if (site) renderMoveBar(site);
    });
    id("siteMoveSave").addEventListener("click", () => act(id("siteMoveSave"), moveAgents, () => {
      const site = sites.find(item => item.id === ui.siteID);
      if (site) renderMoveBar(site);
    }));
  };
})(globalThis.XEC);
