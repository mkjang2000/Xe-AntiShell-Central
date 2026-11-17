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

function harness(keys = [], previewKeys = keys) {
  const document = {nodes: {}, activeElement: null, createElement(tag) { return new Element(tag, this); }};
  document.getElementById = id => {
    if (!document.nodes[id]) { const node = new Element("div", document); node.id = id; }
    return document.nodes[id];
  };
  for (const id of ["detectionEnabled", "extendedRules", "monitoringEnabled", "integrityEnabled", "integrityTPM", "deployConfirm"]) document.getElementById(id).type = "checkbox";
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
  C.options = () => {}; C.choices = () => {}; C.checked = id => id === "deployAgents" ? ["web-01"] : [];
  C.confirm = async () => true; C.refresh = async () => {}; C.notify = () => {};
  C.run = (_button, operation) => { pending = Promise.resolve().then(operation).catch(error => { errors.push(error.message); }); return pending; };
  C.request = async (path, options) => {
    requests.push({path, body: plain(options.body)});
    if (path === "/api/templates") return {...options.body, version: Number(options.body.version) + 1};
    if (path === "/api/deploy/preview") {
      const actual = structuredClone(template); actual.version = 2; actual.settings.response.required_capabilities = previewKeys.slice();
      return {preview_token: "exact-server-preview", template: actual, targets: [{agent_id: "web-01", enrollment_id: "current", current_revision: 1, next_revision: 2, warnings: []}], pending_features: []};
    }
    if (path === "/api/deploy") return {targets: [{agent_id: "web-01"}]};
    throw new Error(`Unexpected request: ${path}`);
  };
  vm.runInContext(source("policy.js"), context); C.initPolicy();
  C.updateState({defaults: settings, templates: [template], agents: [], groups: []});
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
    async preview() { C.id("deployTemplate").value = "ops"; C.id("previewForm").fire("submit", {submitter: new Element("button", document)}); await pending; },
    async deploy() { C.id("deployConfirm").checked = true; C.id("deployConfirm").fire("change"); C.id("deployButton").fire("click"); await pending; }
  };
}

test("capability editor preserves existing order, custom and unsupported keys on unchanged save", async () => {
  const keys = ["vendor.custom", "collector.tetragon", "observation.process_exec", "observation.file", "custom_gate@v1"];
  const h = harness(keys), before = plain(h.template); await h.open();
  assert.equal(h.choices.length, 6); assert.equal(h.choices.some(input => input.value === "observation.file"), false);
  assert.equal(h.custom.value, "vendor.custom\nobservation.file\ncustom_gate@v1");
  assert.match(text(h.editor), /현재 제공하지 않습니다/); assert.match(text(h.editor), /파일 변경 수집/);
  assert.equal(h.C.hasUnsavedPolicy(), false);
  await h.submit();
  assert.deepEqual(h.errors, []); assert.deepEqual(h.requests[0].body.settings.response.required_capabilities, keys);
  assert.deepEqual(h.requests[0].body.settings, before.settings); assert.deepEqual(plain(h.template), before);
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

test("mode explanations and source conflict warnings do not silently change settings", async () => {
  const h = harness(["collector.tetragon"]); await h.open();
  const original = h.C.id("requiredCapabilities").value;
  assert.match(text(h.editor), /탐지 전용에서는 아래 조건을 판정하지 않습니다/);
  for (const [mode, message] of [["would_block", /모의 대응 대상으로 기록/], ["enforce", /실행 전 차단은 제공하지 않습니다/]]) {
    h.C.id("responseMode").value = mode; h.C.id("templateForm").fire("input");
    assert.match(text(h.editor), message); assert.equal(h.C.id("requiredCapabilities").value, original);
  }
  h.C.id("responseMode").value = "observe"; h.choose("collector.audit");
  const warning = h.editor.descendants().find(node => node.className === "notice warning");
  assert.equal(warning.hidden, false); assert.match(warning.textContent, /두 수집기를 모두 필수로 선택하면 대응 조건이 충족되지 않습니다/);
  await h.submit(); assert.deepEqual(h.errors, []);
  assert.deepEqual(h.requests[0].body.settings.response.required_capabilities, ["collector.tetragon", "collector.audit"]);
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
