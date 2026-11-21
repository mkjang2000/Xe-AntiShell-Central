import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = name => fs.readFileSync(new URL(name, import.meta.url), "utf8");
const paint = () => new Promise(resolve => setImmediate(resolve));

function load() {
  const nodes = new Map();
  const node = (tag = "", label = "") => ({
    tag, label, value: "", dataset: {}, children: [], events: {},
    get options() { return this.children; },
    get selectedOptions() { return this.children.filter(child => child.value === this.value); },
    append(...children) { this.children.push(...children); },
    replaceChildren(...children) { this.children = children; },
    addEventListener(type, action) { this.events[type] = action; }
  });
  const XEC = {
    session: {username: "site-ops"}, state: {agents: [], groups: []},
    id: id => { if (!nodes.has(id)) nodes.set(id, node()); return nodes.get(id); },
    el: (tag, _, label) => node(tag, label),
    text: (id, label) => { XEC.id(id).label = label; },
    array: value => Array.isArray(value) ? value : [],
    object: value => value || {},
    applyAccess() {}, onState() {}, notify() {},
    table: (_, headings, rows) => ({headings, rows}),
    run: (_, operation) => operation()
  };
  const context = vm.createContext({XEC, sessionStorage: {getItem: () => "unassigned"}});
  vm.runInContext(source("access-management.js"), context);
  vm.runInContext(source("removal-batches.js"), context);
  return XEC;
}

test("site selection falls back to a granted site and permissions remain scoped", async () => {
  const C = load();
  C.request = async route => route === "/api/sites" ?
    {global: false, sites: [{id: "south", name: "남부"}]} :
    {permissions: {"agents.read": ["south"], "agents.remove": ["north"], "sites.manage": ["south"]}};
  await C.loadSites();
  assert.equal(C.activeSite, "south");
  assert.equal(C.id("consoleSiteSelect").options.length, 1);
  assert.equal(C.can("agents.read"), true);
  assert.equal(C.can("agents.remove"), false);
  assert.equal(C.can("agents.remove", "north"), true);
  assert.equal(C.can("agents.remove", "*"), false);
  assert.equal(C.can("sites.manage", "south"), false);
});

test("batch confirmation is bound to preview count and sends the token exactly once", async () => {
  const C = load();
  C.activeSite = "south";
  C.session.permissions = {"agents.remove": ["south"]};
  C.state.groups = [{id: "retired", name: "미사용"}];
  C.id("batchRemovalTargetType").value = "group";
  C.id("batchRemovalTargetID").value = "retired";
  const requests = [], confirmations = [];
  C.confirm = async info => { confirmations.push(info); return true; };
  C.request = async (route, options) => {
    requests.push([route, options?.body && JSON.parse(JSON.stringify(options.body))]);
    if (route.endsWith("/preview")) return {eligible_count: 1, preview_token: "signed", targets: [
      {agent_id: "one", site_id: "south", eligible: true},
      {agent_id: "two", site_id: "south", eligible: false, reason: "update_busy"}
    ]};
    return {batch_id: "batch-1", targets: [{agent_id: "one", site_id: "south", job: {state: "queued"}}]};
  };
  C.initRemovalBatches();
  C.id("batchRemovalPreviewForm").events.submit({preventDefault() {}});
  await paint();
  assert.deepEqual(requests[0], ["/api/remote-removal/preview", {group_id: "retired"}]);
  assert.equal(C.id("batchRemovalPreviewResult").children[0].rows[1][2], "제외");
  await C.id("batchRemovalConfirm").events.click();
  assert.equal(confirmations[0].match, "1");
  assert.deepEqual(requests[1], ["/api/remote-removal/batches", {preview_token: "signed", confirmation: "1"}]);
  assert.equal(C.id("batchRemovalResult").children[0].rows[0][2], "대기");
  assert.equal(C.id("batchRemovalConfirm").disabled, true);
});
