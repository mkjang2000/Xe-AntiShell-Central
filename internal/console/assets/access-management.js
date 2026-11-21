((C) => {
  "use strict";

  const scopeStorage = "xeas.console.site";
  const rolesByID = new Map();
  let catalog = {permissions: [], roles: []}, accounts = [], sites = [], globalSites = false;
  let activeRole = null, activeSite = null;
  const el = C.el, id = C.id;
  const globalOnly = new Set(["accounts.manage", "roles.manage", "sites.manage", "sites.assign_agents",
    "policies.manage", "policies.trial", "updates.releases", "central.update"]);

  C.can = (permission, scope = C.activeSite) => {
    if (!C.session?.permissions) return false;
    const scopes = C.array(C.session.permissions[permission]);
    if (globalOnly.has(permission)) return scopes.includes("*");
    return scopes.includes("*") || (scope ? scopes.includes(scope) : scopes.length > 0);
  };
  C.canGlobally = permission => C.array(C.session?.permissions?.[permission]).includes("*");

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
  const field = (label, control) => {
    const wrap = el("label", "field", label);
    wrap.append(control);
    return wrap;
  };

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

  const loadCatalog = async () => {
    if (C.canGlobally("roles.manage") || C.canGlobally("accounts.manage")) {
      catalog = await C.request("/api/rbac");
    }
    rolesByID.clear();
    for (const role of C.array(catalog.roles)) rolesByID.set(role.id, role);
  };

  const renderRole = roleID => {
    activeRole = rolesByID.get(roleID) || null;
    const canEdit = C.canGlobally("roles.manage") && !activeRole?.builtin;
    id("rbacRoleID").value = activeRole?.id || "";
    id("rbacRoleID").disabled = !canEdit || Boolean(activeRole);
    id("rbacRoleName").value = activeRole?.name || "";
    id("rbacRoleName").disabled = !canEdit;
    const permissions = C.array(catalog.permissions);
    id("rbacPermissions").replaceChildren(...permissions.map(permission => {
      const check = el("input");
      Object.assign(check, {
        type: "checkbox", value: permission.id, checked: Boolean(activeRole?.permissions?.includes(permission.id)),
        disabled: !canEdit
      });
      const label = el("label", "check-label");
      label.append(check, el("span", "", permission.label + (permission.scope === "global" ? " · 전역" : "")));
      return label;
    }));
    id("rbacRoleSave").disabled = !canEdit;
    id("rbacRoleDelete").disabled = !canEdit || !activeRole;
  };

  const renderRoles = selected => {
    const select = id("rbacRoleSelect");
    choose(select, [["", "새 역할"], ...C.array(catalog.roles).map(role => [role.id, role.name + (role.builtin ? " · 기본" : "")])], selected);
    renderRole(select.value);
  };

  const addGrant = (grant = {}) => {
    const wrap = el("div", "form-grid rbac-grant");
    const role = el("select"), site = el("select");
    choose(role, [["", "역할 선택"], ...C.array(catalog.roles).map(item => [item.id, item.name])], grant.role_id);
    choose(site, [["", "범위 선택"], ...scopeOptions()], grant.site_id);
    role.className = "rbac-grant-role";
    site.className = "rbac-grant-site";
    wrap.append(field("역할", role), field("범위", site),
      C.button("이 역할 부여 삭제", () => wrap.remove(), "small quiet"));
    id("rbacGrantRows").append(wrap);
  };

  const renderGrants = () => {
    const account = accounts.find(item => item.username === id("rbacGrantAccount").value);
    id("rbacGrantRows").replaceChildren();
    for (const grant of C.array(account?.grants)) addGrant(grant);
    id("rbacGrantAdd").disabled = !account || !rolesByID.size || !scopeOptions().length;
    id("rbacGrantSave").disabled = !account;
  };

  const saveGrants = async () => {
    const account = accounts.find(item => item.username === id("rbacGrantAccount").value);
    if (!account) return;
    const grants = [...id("rbacGrantRows").querySelectorAll(".rbac-grant")].map(row => ({
      role_id: row.querySelector(".rbac-grant-role").value,
      site_id: row.querySelector(".rbac-grant-site").value
    }));
    if (grants.some(grant => !grant.role_id || !grant.site_id)) throw new Error("각 항목의 역할과 사이트를 선택하세요.");
    if (!await C.confirm({title: "사이트별 역할 저장", description: account.username + " 계정의 역할 부여를 현재 목록으로 교체합니다.", accept: "역할 저장"})) return;
    await C.request("/api/accounts/" + encodeURIComponent(account.username) + "/grants", {method: "POST", body: {version: account.version, grants}});
    if (account.username === C.session.username) return globalThis.location.reload();
    C.notify("계정의 사이트별 역할을 저장했습니다.");
    await C.loadAccessManagement();
  };

  const renderSite = siteID => {
    activeSite = sites.find(site => site.id === siteID) || null;
    id("rbacSiteID").value = activeSite?.id || "";
    id("rbacSiteID").disabled = Boolean(activeSite);
    id("rbacSiteName").value = activeSite?.name || "";
  };

  const renderMovableAgents = async () => {
    if (!C.canGlobally("sites.assign_agents")) return;
    const data = await C.request("/api/state", {site: "*"});
    const select = id("rbacMoveAgent");
    select.replaceChildren(option("이동할 에이전트 선택", ""));
    for (const agent of C.array(data?.agents).filter(agent => !agent.revoked)) {
      const target = option(agent.agent_id + " · " + C.siteName(agent.site_id), agent.agent_id);
      target.dataset.enrollment = agent.enrollment_id;
      target.dataset.site = agent.site_id;
      select.append(target);
    }
    choose(id("rbacMoveSite"), sites.map(site => [site.id, site.name]));
  };

  C.loadAccessManagement = async () => {
    const roleManagement = C.canGlobally("roles.manage"), accountManagement = C.canGlobally("accounts.manage");
    const siteManagement = C.canGlobally("sites.manage"), agentMove = C.canGlobally("sites.assign_agents");
    id("rbacRolePanel").hidden = !roleManagement;
    id("rbacGrantPanel").hidden = !accountManagement;
    id("rbacSitePanel").hidden = !siteManagement;
    id("rbacMovePanel").hidden = !agentMove;
    if (roleManagement || accountManagement) await loadCatalog();
    if (roleManagement) renderRoles(activeRole?.id);
    if (accountManagement) {
      const data = await C.request("/api/accounts");
      accounts = C.array(Array.isArray(data) ? data : data?.accounts);
      const select = id("rbacGrantAccount");
      choose(select, [["", "계정 선택"], ...accounts.map(account => [account.username, account.username])], select.value);
      renderGrants();
    }
    if (siteManagement) {
      choose(id("rbacSiteSelect"), [["", "새 사이트"], ...sites.map(site => [site.id, site.name])], activeSite?.id);
      renderSite(id("rbacSiteSelect").value);
    }
    if (agentMove) await renderMovableAgents();
  };

  C.initAccessManagement = () => {
    id("consoleSiteSelect").addEventListener("change", async event => {
      const value = event.target.value;
      if (value === C.activeSite) return;
      if ((C.hasUnsavedPolicy?.() || C.hasUnsavedGroup?.()) && !await C.confirm({
        title: "사이트 바꾸기", description: "저장하지 않은 편집 내용이 사라집니다.", accept: "사이트 바꾸기"
      })) {
        event.target.value = C.activeSite;
        return;
      }
      try { sessionStorage.setItem(scopeStorage, value); } catch (_) {}
      C.changingSite = true;
      globalThis.location.reload();
    });
    id("rbacRoleSelect").addEventListener("change", event => renderRole(event.target.value));
    id("rbacRoleForm").addEventListener("submit", event => {
      event.preventDefault();
      C.run(id("rbacRoleSave"), async () => {
        const role = activeRole;
        const permissions = [...id("rbacPermissions").querySelectorAll("input:checked")].map(input => input.value);
        const body = {name: id("rbacRoleName").value.trim(), permissions};
        if (role) body.version = role.version;
        else body.id = id("rbacRoleID").value.trim();
        const saved = await C.request("/api/rbac/roles" + (role ? "/" + encodeURIComponent(role.id) : ""), {method: "POST", body});
        await loadCatalog();
        renderRoles(saved.id);
        C.notify("권한 역할을 저장했습니다.");
      });
    });
    id("rbacRoleDelete").addEventListener("click", () => C.run(id("rbacRoleDelete"), async () => {
      const role = activeRole;
      if (!role || !await C.confirm({title: "권한 역할 삭제", description: role.name, accept: "삭제"})) return;
      await C.request("/api/rbac/roles/" + encodeURIComponent(role.id) + "?version=" + role.version, {method: "DELETE"});
      await loadCatalog();
      renderRoles("");
    }));
    id("rbacGrantAccount").addEventListener("change", renderGrants);
    id("rbacGrantAdd").addEventListener("click", () => addGrant());
    id("rbacGrantSave").addEventListener("click", () => C.run(id("rbacGrantSave"), saveGrants));
    id("rbacSiteSelect").addEventListener("change", event => renderSite(event.target.value));
    id("rbacSiteForm").addEventListener("submit", event => {
      event.preventDefault();
      C.run(id("rbacSiteSave"), async () => {
        const siteID = activeSite?.id || id("rbacSiteID").value.trim();
        await C.request("/api/sites", {method: "POST", site: "", body: {id: siteID, name: id("rbacSiteName").value.trim(), version: activeSite?.version || 0}});
        await C.loadSites();
        activeSite = sites.find(site => site.id === siteID);
        await C.loadAccessManagement();
        C.notify("사이트를 저장했습니다.");
      });
    });
    id("rbacMoveForm").addEventListener("submit", event => {
      event.preventDefault();
      C.run(id("rbacMoveSave"), async () => {
        const select = id("rbacMoveAgent"), selected = select.selectedOptions[0], target = id("rbacMoveSite").value;
        if (!select.value || !target || selected.dataset.site === target) return;
        if (!await C.confirm({title: "에이전트 사이트 이동", description: select.value + " → " + C.siteName(target), accept: "사이트 이동"})) return;
        await C.request("/api/sites/" + encodeURIComponent(target) + "/agents", {method: "POST", site: "", body: {agent_id: select.value, enrollment_id: selected.dataset.enrollment}});
        await renderMovableAgents();
        await C.refresh();
        C.notify("에이전트의 사이트를 변경했습니다.");
      });
    });
  };
})(globalThis.XEC);
