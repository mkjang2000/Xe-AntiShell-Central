import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = name => fs.readFileSync(new URL(name, import.meta.url), "utf8");
const plain = value => JSON.parse(JSON.stringify(value));
const text = node => typeof node === "string" ? node : node.textContent + node.children.map(text).join("");

class Element {
  constructor(tag, document) {
    this.tagName = tag; this.document = document; this.children = []; this.handlers = {};
    this.textContent = ""; this.value = ""; this.type = ""; this.checked = false; this.hidden = false;
  }
  set id(value) { this.identifier = value; this.document.nodes[value] = this; }
  get id() { return this.identifier; }
  set innerHTML(_) { throw new Error("HTML insertion is forbidden"); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  addEventListener(name, callback) { this.handlers[name] = callback; }
  fire(name, extra = {}) { return this.handlers[name]?.({preventDefault() {}, target: this, ...extra}); }
  setAttribute() {}
  removeAttribute() {}
  focus() { this.document.activeElement = this; }
  scrollIntoView() {}
  descendants() { return this.children.flatMap(node => typeof node === "string" ? [] : [node, ...node.descendants()]); }
}

function harness(keys = [], previewKeys = keys, options = {}) {
  const document = {nodes: {}, activeElement: null, createElement(tag) { return new Element(tag, this); }};
  document.getElementById = id => {
    if (!document.nodes[id]) { const node = new Element("div", document); node.id = id; }
    return document.nodes[id];
  };
  for (const id of ["detectionEnabled", "extendedRules", "privilegeRules", "centralServiceScopes", "monitoringEnabled", "integrityPackageFiles", "deployConfirm"]) document.getElementById(id).type = "checkbox";
  const context = vm.createContext({document, Node: Element, structuredClone, AbortController, setTimeout, clearTimeout, location: {hash: ""}});
  vm.runInContext(source("model.js"), context); const C = context.XEC;
  const settings = {
    detection: {enabled: true, extended_process_rules: false, web_executables: ["nginx"], web_services: [], shells: ["sh", "bash"], allowed_pairs: []},
    response: {mode: "observe", action: "none", risk_threshold: 90, min_confidence: 0.95, required_capabilities: keys.slice()},
    monitoring: {enabled: true, sample_interval_seconds: 10, process_limit: 200},
    uninstall_mode: "approval_required", validity_hours: 24, integrity: {enabled: false, mode: "observe", require_tpm: false, paths: []}
  };
  const template = {id: "ops", name: "운영 정책", description: "기존 템플릿", version: 1, settings};
  const requests = [], errors = []; let pending;
  C.session = {role: "operator"};
  C.options = () => {}; C.choices = () => {}; C.checked = id => id === "deployAgents" ? ["web-01"] : [];
  C.confirm = async () => true; C.refresh = async () => {}; C.notify = () => {};
  C.run = (_button, operation) => { pending = Promise.resolve().then(operation).catch(error => { errors.push(error.message); }); return pending; };
  C.request = async (path, request) => {
    requests.push({path, body: request?.body === undefined ? undefined : plain(request.body)});
    if (path === "/api/templates") return {...request.body, version: Number(request.body.version) + 1};
    if (path === "/api/deploy/preview") {
      const actual = structuredClone(template); actual.version = 2; actual.settings.response.required_capabilities = previewKeys.slice();
      if (options.scopedPreview) Object.assign(actual.settings, {service_scope: "all_listening", detection: {...actual.settings.detection, web_executables: [], web_services: []}});
      return {preview_token: "exact-server-preview", template: actual, targets: [{agent_id: "web-01", enrollment_id: "current", current_revision: 1, next_revision: 2, warnings: []}], pending_features: [], ...options.preview};
    }
    if (path === "/api/deploy") return {targets: [{agent_id: "web-01"}]};
    if (options.inventory && path.endsWith("/service-inventory")) return options.inventory(path);
    throw new Error(`Unexpected request: ${path}`);
  };
  for (const name of ["service-inventory.js", "policy-services.js", "policy-diff.js", "policy.js"]) vm.runInContext(source(name), context);
  C.initPolicy();
  C.updateState({defaults: settings, templates: [template], agents: options.agents || [], groups: [], rule_ids: ["web-descendant-shell", "web-descendant-download-tool", "service-protected-file-write"]});
  const editor = C.id("requiredCapabilitiesEditor");
  const choices = editor.descendants().filter(node => node.tagName === "input");
  return {
    C, template, requests, errors, editor, choices,
    custom: C.id("customRequiredCapabilities"),
    async open() { await C.id("templateList").children[0].fire("click"); },
    choose(key, checked = true) { const input = choices.find(node => node.value === key); assert.ok(input, `Missing choice ${key}`); input.checked = checked; input.fire("change"); },
    recommend() { editor.descendants().find(node => node.tagName === "button").fire("click"); },
    customInput(value) { this.custom.value = value; this.custom.fire("input"); },
    async submit() { C.id("templateForm").fire("submit", {submitter: new Element("button", document)}); await pending; },
    set(id, value, event = "input") { const node = C.id(id); if (node.type === "checkbox") node.checked = value; else node.value = value; node.fire(event); C.id("templateForm").fire("input", {target: node}); },
    settings() { return requests.at(-1).body.settings; },
    async preview() { C.id("deployTemplate").value = "ops"; C.id("previewForm").fire("submit", {submitter: new Element("button", document)}); await pending; },
    async deploy() { C.id("deployConfirm").checked = true; C.id("deployConfirm").fire("change"); C.id("deployButton").fire("click"); await pending; }
  };
}

test("capability editor preserves existing order, custom and unsupported keys on unchanged save", async () => {
  const keys = ["vendor.custom", "collector.tetragon", "observation.process_exec", "observation.file", "custom_gate@v1"];
  const h = harness(keys), before = plain(h.template); await h.open();
  assert.equal(h.choices.length, 6); assert.equal(h.choices.some(input => input.value === "observation.file"), false);
  assert.equal(h.custom.value, "vendor.custom\nobservation.file\ncustom_gate@v1");
  assert.match(text(h.editor), /별도 센서 수신/); assert.match(text(h.editor), /기본 추천 자동 종료 조건에 자동으로 추가하지 않습니다/); assert.match(text(h.editor), /파일 변경 수집/);
  assert.equal(h.C.hasUnsavedPolicy(), false);
  await h.submit();
  assert.deepEqual(h.errors, []); assert.deepEqual(h.requests[0].body.settings.response.required_capabilities, keys);
  assert.deepEqual(h.requests[0].body.settings, before.settings); assert.deepEqual(plain(h.template), before);
});

test("policy scopes preserve legacy defaults and compile exact manual selections or discovered-only drafts", async () => {
  const h = harness(); await h.open();
  h.set("policyServiceScope", "selected", "change");
  assert.equal(h.C.id("webExecutablesField").hidden, true);
  for (const invalid of ["", "*.service", "nginx.service\nNGINX.service"]) {
    h.set("webServices", invalid); await h.submit();
    assert.match(h.errors.at(-1), /지정된 서비스/);
    assert.equal(h.requests.length, 0);
  }
  h.set("webServices", "nginx.service\npm2-app.service");
  await h.submit();
  assert.equal(h.settings().service_scope, "selected");
  assert.deepEqual(h.settings().detection.web_services, ["nginx.service", "pm2-app.service"]);
  assert.deepEqual(h.settings().detection.web_executables, []);
  h.set("policyServiceScope", "all_listening", "change");
  assert.equal(h.C.id("webServicesField").hidden, true);
  await h.submit();
  assert.equal(h.settings().service_scope, "all_listening");
  assert.deepEqual(h.settings().detection.web_services, []);
  assert.deepEqual(h.settings().detection.web_executables, []);
  assert.deepEqual(h.settings().detection.shells, ["sh", "bash"]);
});

test("discovered preview shows exact scopes before accepting the server's deployment token", async () => {
  const serviceTargets = [{agent_ids: ["web-01"], services: ["nginx.service", "php-fpm.service"]}];
  const h = harness([], [], {scopedPreview: true, preview: {service_targets: serviceTargets}});
  await h.open(); await h.preview();
  assert.deepEqual(h.errors, []);
  assert.match(text(h.C.id("previewServiceTargets")), /web-01.*nginx\.service.*php-fpm\.service/s);
  assert.match(text(h.C.id("trialStart")), /한 대를 먼저 선택/);
  await h.deploy();
  assert.deepEqual(h.requests.at(-1), {path: "/api/deploy", body: {preview_token: "exact-server-preview", confirm: true}});
});

test("missing, malformed or duplicate scope groups cannot enable deployment confirmation", async () => {
  const second = {agent_id: "web-02", enrollment_id: "other", current_revision: 1, next_revision: 2, warnings: []};
  const first = {...second, agent_id: "web-01"};
  const a = {agent_ids: ["web-01"], services: ["nginx.service"]};
  const b = {agent_ids: ["web-02"], services: ["php-fpm.service"]};
  for (const groups of [undefined, [], [a], [a, a], [a, {...b, agent_ids: ["web-03"]}], [a, {...b, services: []}],
    [a, {...b, services: ["php-fpm.service", "PHP-FPM.service"]}], [a, {...b, services: ["*.service"]}]]) {
    const h = harness([], [], {scopedPreview: true, preview: {targets: [first, second], service_targets: groups}});
    await h.open(); await h.preview();
    assert.match(h.errors.at(-1), /목록이 배포 대상과 일치하지 않습니다/);
    assert.equal(h.C.id("deploymentPreview").hidden, true);
    await h.deploy();
    assert.equal(h.C.id("deployButton").disabled, true);
    assert.equal(h.requests.some(item => item.path === "/api/deploy"), false);
  }
});

const inventoryAgent = (id, enrollment = "enrolled") => ({agent_id: id, enrollment_id: enrollment});
const inventoryReply = (agent, state, listeners, time = new Date().toISOString()) => ({...agent, state, sampled_at: time, received_at: time, listeners});
const listener = (service, port) => ({service, port, family: "ipv4", binding: "wildcard"});

test("picker preserves the current host after races and only adds attributed fresh names", async () => {
  const a = inventoryAgent("web-01"), b = inventoryAgent("web-02");
  let finishFirst;
  const pending = new Promise(resolve => { finishFirst = resolve; });
  const reply = inventoryReply(b, "partial", [listener("nginx.service", 443), listener("nginx.service", 80), listener(undefined, 9000)]);
  const h = harness([], [], {agents: [a, b], inventory: path => path.includes("web-01") ? pending : reply});
  await h.open();
  const picker = h.C.id("policyServiceInventory"), select = h.C.id("policyInventoryAgent"), result = h.C.id("policyInventoryResult");
  picker.open = true;
  select.value = a.agent_id; const first = select.fire("change");
  select.value = b.agent_id; await select.fire("change");
  finishFirst(inventoryReply(a, "complete", [listener("another.service", 444)])); await first;
  assert.equal(h.C.hasUnsavedPolicy(), false);
  assert.match(text(result), /일부 수집.*nginx\.service.*443.*소속 미확인.*9000/s);
  assert.doesNotMatch(text(result), /another\.service/);
  assert.deepEqual(h.C.id("policyServiceNames").children.map(node => node.value), ["nginx.service"]);
  const buttons = result.descendants().filter(node => node.tagName === "button");
  assert.equal(buttons.length, 2);
  buttons[0].fire("click");
  assert.equal(h.C.hasUnsavedPolicy(), true);
  assert.equal(h.C.id("webServices").value, "nginx.service");
  assert.equal(buttons[1].disabled, true);
});

test("stale inventory is visible for reference but cannot supply choices or autocomplete", async () => {
  const agent = inventoryAgent("web-01");
  const snapshot = inventoryReply(agent, "complete", [listener("nginx.service", 443)], new Date(Date.now() - 4 * 60000).toISOString());
  const h = harness([], [], {agents: [agent], inventory: () => snapshot});
  await h.open();
  h.C.id("policyServiceInventory").open = true; h.C.id("policyInventoryAgent").value = agent.agent_id;
  await h.C.id("policyInventoryAgent").fire("change");
  const view = h.C.id("policyInventoryResult");
  assert.match(text(view), /이전 보고.*nginx\.service/s);
  assert.equal(view.descendants().some(node => node.tagName === "button"), false);
  assert.equal(h.C.id("policyServiceNames").children.length, 0);
});

test("agent detail is read-only and labels a mismatched enrollment instead of using its report", async () => {
  const current = inventoryAgent("web-01"), changed = inventoryAgent("web-01", "replacement");
  let reply = inventoryReply(changed, "complete", [listener("nginx.service", 443)]);
  const h = harness([], [], {agents: [current], inventory: () => reply});
  h.C.session = {role: "viewer"};
  const section = h.C.agentServiceInventory(current);
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(text(section), /등록이 변경/);
  assert.doesNotMatch(text(section), /nginx/);
  reply = inventoryReply(current, "complete", [listener("nginx.service", 443)]);
  await section.descendants().find(node => node.tagName === "button").fire("click");
  assert.match(text(section), /대기 중인 TCP 서비스.*전체 수집.*nginx\.service.*443/s);
  assert.equal(section.descendants().filter(node => node.tagName === "button").length, 1);
  assert.equal(h.C.agentServiceInventory({...current, revoked: true}), null);
});

test("editing monitoring preserves an archived integrity draft and warns of zero response rules", async () => {
  const h = harness(["observation.process_exec"]);
  const draft = {enabled: true, mode: "enforce", require_tpm: true, paths: ["/etc/xe-antishell"]};
  h.template.settings.integrity = draft;
  await h.open();
  assert.match(text(h.C.id("integrityDraftSummary")), /강제 \(초안\)/);
  h.C.id("sampleInterval").value = "30";
  h.C.id("extendedRules").checked = true;
  h.C.id("responseMode").value = "enforce";
  h.C.id("responseAction").value = "terminate";
  h.C.id("templateForm").fire("input");
  assert.match(text(h.C.id("responseHelp")), /대응 대상 규칙은 0개/);
  await h.submit();
  assert.deepEqual(h.errors, []);
  assert.equal(h.requests[0].body.settings.monitoring.sample_interval_seconds, 30);
  assert.deepEqual(h.requests[0].body.settings.integrity, draft);
});

test("explicit choices and recommended additions preserve custom gates and invalidate previews", async () => {
  const h = harness(["vendor.custom", "collector.tetragon", "observation.process_exec"]); await h.open();
  h.C.id("deploymentPreview").hidden = false; h.C.id("deployConfirm").checked = true;
  h.choose("observation.process_exec", false); h.choose("observation.process_lineage");
  h.customInput("vendor.custom\nextra.custom");
  assert.equal(h.C.hasUnsavedPolicy(), true); assert.equal(h.C.id("deploymentPreview").hidden, true); assert.equal(h.C.id("deployConfirm").checked, false);
  h.recommend();
  h.C.id("responseMode").value = "enforce"; h.C.id("responseAction").value = "terminate"; h.C.id("templateForm").fire("input");
  await h.submit();
  assert.deepEqual(h.errors, []);
  assert.deepEqual(h.requests[0].body.settings.response.required_capabilities, ["vendor.custom", "collector.tetragon", "observation.process_exec", "observation.process_lineage", "response.terminate", "extra.custom"]);
  assert.equal(h.requests[0].body.settings.response.mode, "enforce");
});

test("mode cards reveal response conditions without silently changing settings", async () => {
  const h = harness(["collector.tetragon"]); await h.open();
  const original = h.C.id("requiredCapabilities").value;
  assert.equal(h.C.id("responseConditions").hidden, true); assert.equal(h.C.id("responseConditionsOff").hidden, false);
  for (const [mode, message] of [["would_block", /모의 대응 대상으로 기록/], ["enforce", /실행 전 차단은 제공하지 않습니다/]]) {
    h.C.id("responseMode").value = mode; h.C.id("templateForm").fire("input");
    assert.equal(h.C.id("responseConditions").hidden, false); assert.equal(h.C.id("responseConditionsOff").hidden, true);
    assert.match(text(h.editor), message); assert.equal(h.C.id("requiredCapabilities").value, original);
  }
  h.C.id("responseMode").value = "observe"; h.choose("collector.audit");
  const warning = h.editor.descendants().find(node => node.className === "notice warning");
  assert.equal(warning.hidden, false); assert.match(warning.textContent, /두 수집기를 모두 필수로 선택하면 대응 조건이 충족되지 않습니다/);
  await h.submit(); assert.deepEqual(h.errors, []);
  assert.deepEqual(h.requests[0].body.settings.response.required_capabilities, ["collector.tetragon", "collector.audit"]);
});

test("response action follows the mode while an observe policy keeps its saved action", async () => {
  const h = harness(["observation.process_exec"]);
  h.template.settings.response.action = "terminate";
  await h.open(); await h.submit();
  assert.deepEqual(h.errors, []); assert.equal(h.settings().response.action, "terminate");
  h.C.id("responseMode").value = "enforce"; h.C.id("templateForm").fire("input"); await h.submit();
  assert.equal(h.settings().response.mode, "enforce"); assert.equal(h.settings().response.action, "terminate");
  const g = harness(["observation.process_exec"]);
  g.template.settings.response = {...g.template.settings.response, mode: "would_block", action: "terminate"};
  await g.open(); g.C.id("responseMode").value = "observe"; g.C.id("templateForm").fire("input"); await g.submit();
  assert.deepEqual(g.errors, []); assert.equal(g.settings().response.action, "none");
  const empty = harness(); await empty.open();
  empty.C.id("responseMode").value = "enforce"; empty.C.id("templateForm").fire("input");
  assert.equal(empty.C.id("responseHelp").hidden, false); assert.match(empty.C.id("responseHelp").textContent, /권장 조건 3개 선택/);
  assert.equal(empty.C.id("requiredCapabilities").value, "", "switching modes never adds conditions by itself");
});

test("an invalid value opens its section, explains the error near save and blocks the request", async () => {
  const h = harness(); await h.open();
  assert.equal(h.C.id("policySection-basics").hidden, false);
  h.set("sampleInterval", "1"); await h.submit();
  assert.equal(h.requests.length, 0); assert.match(h.errors.at(-1), /수집 간격/);
  assert.equal(h.C.id("policySection-agent").hidden, false); assert.equal(h.C.id("policySection-basics").hidden, true);
  assert.equal(h.C.id("templateFormError").hidden, false); assert.match(h.C.id("templateFormError").textContent, /수집 간격/);
  h.set("sampleInterval", "10"); h.set("templateName", " "); await h.submit();
  assert.equal(h.requests.length, 0); assert.equal(h.C.id("policySection-basics").hidden, false);
  h.set("templateName", "운영 정책"); await h.submit();
  assert.equal(h.requests.length, 1); assert.equal(h.C.id("templateFormError").hidden, true);
});

test("duplicate copies the saved settings into a new unsaved policy and deploy preselects the saved one", async () => {
  const h = harness(["observation.process_exec"]); h.C.session = {role: "operator"}; await h.open();
  assert.equal(h.C.id("duplicateTemplate").disabled, false);
  h.C.id("deployFromEditor").fire("click");
  assert.equal(h.C.id("deployTemplate").value, "ops");
  await h.C.id("duplicateTemplate").fire("click");
  assert.equal(h.C.id("templateID").value, ""); assert.equal(h.C.id("templateVersionInput").value, 0);
  assert.equal(h.C.id("templateName").value, "운영 정책 복사본"); assert.equal(h.C.hasUnsavedPolicy(), true);
  assert.equal(h.C.id("deployFromEditor").disabled, true);
  h.set("templateID", "ops-copy"); await h.submit();
  assert.deepEqual(h.errors, []);
  assert.equal(h.requests[0].body.id, "ops-copy"); assert.equal(h.requests[0].body.version, 0);
  assert.deepEqual(h.requests[0].body.settings, plain(h.template.settings));
  const viewer = harness(); viewer.C.session = {role: "viewer"}; await viewer.open();
  assert.equal(viewer.C.id("duplicateTemplate").disabled, true); assert.equal(viewer.C.id("deployFromEditor").disabled, true);
});

test("custom gate validation follows wire bounds and rejects duplicate or misplaced keys", async () => {
  for (const [value, message] of [
    ["vendor.custom\nvendor.custom", /중복/], ["vendor.custom\nVENDOR.CUSTOM", /중복/],
    [Array.from({length: 33}, (_, i) => `gate_${i}`).join("\n"), /32개/],
    ["<script>alert(1)</script>", /영문/], ["a".repeat(256), /255자/],
    ["observation.process_lineage", /체크박스/]
  ]) {
    const h = harness(["vendor.custom"]); await h.open(); h.customInput(value); await h.submit();
    assert.equal(h.requests.length, 0); assert.equal(h.errors.length, 1); assert.match(h.errors[0], message);
  }
  const h = harness(); await h.open(); h.customInput("vendor\\feature@v1"); await h.submit();
  assert.deepEqual(h.errors, []); assert.deepEqual(h.requests[0].body.settings.response.required_capabilities, ["vendor\\feature@v1"]);
});

test("preview labels use the exact server snapshot and deploy only its token", async () => {
  const actualKeys = ["observation.process_exec", "response.terminate", "vendor.remote"];
  const h = harness(["collector.audit"], actualKeys); await h.open(); await h.preview();
  assert.deepEqual(h.errors, []);
  assert.deepEqual(h.requests[0], {path: "/api/deploy/preview", body: {template_id: "ops", agent_ids: ["web-01"], group_ids: []}});
  const facts = h.C.id("previewWarnings").descendants().filter(node => node.tagName === "dd");
  assert.ok(facts.some(node => text(node).includes("프로세스 실행 정보 수신") && text(node).includes("서버의 안전한 프로세스 종료 허용") && text(node).includes("vendor.remote")));
  const json = h.C.id("previewWarnings").descendants().find(node => node.tagName === "pre");
  assert.deepEqual(JSON.parse(json.textContent).response.required_capabilities, actualKeys);
  await h.deploy();
  assert.deepEqual(h.requests[1], {path: "/api/deploy", body: {preview_token: "exact-server-preview", confirm: true}});
  assert.deepEqual(plain(h.template.settings.response.required_capabilities), ["collector.audit"]);
});


test("privilege opt-in and root alert mode roundtrip while disabled fields disappear", async () => {
 const h=harness();await h.open();
 h.C.id("privilegeRules").checked=true;h.C.id("rootExecAlerts").value="all";h.C.id("templateForm").fire("input");
 assert.equal(h.C.id("rootExecAlerts").disabled,false);
 await h.submit();assert.deepEqual(h.errors,[]);
 assert.equal(h.requests[0].body.settings.detection.privilege_rules,true);assert.equal(h.requests[0].body.settings.detection.root_exec_alerts,"all");
 h.C.id("privilegeRules").checked=false;h.C.id("templateForm").fire("input");
 assert.equal(h.C.id("rootExecAlerts").disabled,true);
 await h.submit();assert.deepEqual(h.errors,[]);
 assert.equal(Object.hasOwn(h.requests[1].body.settings.detection,"privilege_rules"),false);assert.equal(Object.hasOwn(h.requests[1].body.settings.detection,"root_exec_alerts"),false);
});

test("service scope editor preserves inheritance, an empty override, and an explicit policy", async () => {
  const h = harness();
  const scopes = [{service:"web.service", protected_dirs:["/srv/web"], allowed_tcp_destinations:[{cidr:"192.0.2.0/24", ports:[443]}]}];
  h.template.settings.detection.web_services = ["web.service"];
  h.template.settings.detection.service_observations = scopes;
  await h.open();
  assert.equal(h.C.id("centralServiceScopes").checked, true);
  assert.equal(h.C.id("serviceScope-0-tcp").value, "192.0.2.0/24 443");
  await h.submit();
  assert.deepEqual(h.settings().detection.service_observations, scopes);
  h.set("serviceScope-0-writable", "/srv/web/uploads");
  h.set("serviceScope-0-tcp", "192.0.2.0/24 443\n2001:db8::/32");
  await h.submit();
  assert.deepEqual(h.errors, []);
  assert.deepEqual(h.settings().detection.service_observations, [{service:"web.service", protected_dirs:["/srv/web"], allowed_write_dirs:["/srv/web/uploads"], allowed_tcp_destinations:[{cidr:"192.0.2.0/24", ports:[443]}, {cidr:"2001:db8::/32"}]}]);
  for (const [id, value, message] of [["serviceScope-0-writable", "/tmp/uploads", /보호 디렉터리 안/], ["serviceScope-0-tcp", "192.0.2.1/24 443", /CIDR/], ["serviceScope-0-tcp", "192.0.2.0/24 0", /포트/], ["serviceScope-0-protected", "srv/web", /정규화된 경로/]]) {
    const before = h.requests.length, saved = h.C.id(id).value;
    h.set(id, value); await h.submit();
    assert.equal(h.requests.length, before); assert.match(h.errors.at(-1), message);
    assert.equal(h.C.id("policySection-services").hidden, false);
    h.set(id, saved);
  }
  h.C.id("serviceScopeRows").descendants().find(node => node.textContent === "삭제").fire("click");
  assert.equal(h.C.id("serviceScopeEmpty").hidden, false);
  await h.submit();
  assert.deepEqual(h.settings().detection.service_observations, []);
  h.set("centralServiceScopes", false, "change");
  assert.equal(h.C.id("serviceScopeEditor").hidden, true);
  await h.submit();
  assert.equal(Object.hasOwn(h.settings().detection, "service_observations"), false);
});

test("rule controls edit as rows, keep unchanged expiries and clearing restores profile defaults", async () => {
  const h = harness();
  const controls = [{service:"web.service",rule_id:"web-descendant-shell",mode:"suppress_until",reason:"maintenance",expires_at:"2026-12-01T01:00:00Z"}];
  h.template.settings.detection.service_rule_controls = controls;
  await h.open();
  assert.equal(h.C.id("ruleControl-0-reason").value, "maintenance");
  await h.submit();
  assert.deepEqual(h.settings().detection.service_rule_controls, controls);
  h.C.id("ruleControlAdd").fire("click");
  h.set("ruleControl-1-service", "web.service"); h.set("ruleControl-1-rule", "web-descendant-shell", "change");
  await h.submit(); assert.match(h.errors.at(-1), /중복/);
  h.set("ruleControl-1-rule", "web-descendant-download-tool", "change");
  h.set("ruleControl-0-expires", "2026-12-24T09:30");
  await h.submit();
  const expiry = new Date("2026-12-24T09:30").toISOString().replace(/\.000Z$/, "Z");
  assert.deepEqual(h.settings().detection.service_rule_controls, [{...controls[0], expires_at: expiry}, {service:"web.service", rule_id:"web-descendant-download-tool", mode:"disabled"}]);
  h.set("ruleControl-1-mode", "suppress_until", "change"); await h.submit();
  assert.match(h.errors.at(-1), /예외 사유/);
  h.set("ruleControl-1-mode", "enabled", "change"); h.set("ruleControl-0-mode", "disabled", "change");
  await h.submit(); assert.deepEqual(h.settings().detection.service_rule_controls.map(c => Object.keys(c).length), [3, 3]);
  for (const _ of [0, 1]) h.C.id("ruleControlRows").descendants().find(node => node.textContent === "삭제").fire("click");
  await h.submit();
  assert.equal(Object.hasOwn(h.settings().detection, "service_rule_controls"), false);
});
