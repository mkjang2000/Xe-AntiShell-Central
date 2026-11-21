import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = fs.readFileSync(new URL("./remote-removal.js", import.meta.url), "utf8");
const agent = {agent_id: "web-01", enrollment_id: "enrollment-01", revoked: false};
const ready = {agent_id: agent.agent_id, enrollment_id: agent.enrollment_id, can_request: true};
const route = "/api/agents/web-01/remote-removal";

class Node {
  constructor(label = "") { this.label = label; this.children = []; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  get text() { return this.label + this.children.map(item => item.text).join(" "); }
  find(label) {
    return this.label === label ? this : this.children.map(item => item.find(label)).find(Boolean);
  }
}

function load(responses) {
  const writes = [], confirmations = [];
  const C = {
    now: Date.now,
    state: {agents: [agent]},
    selectedAgent: agent.agent_id,
    session: {role: "admin"},
    el: (_, __, text) => new Node(text),
    button: (label, action) => Object.assign(new Node(label), {action}),
    tag: label => new Node(label),
    facts: rows => {
      const list = new Node();
      for (const [name, value] of rows) list.append(new Node(name), value instanceof Node ? value : new Node(value));
      return list;
    },
    time: value => value || "—",
    confirm: async options => { confirmations.push(options); return true; },
    run: async (_, task) => task(),
    request: async (url, options) => {
      if (!options) return responses.shift();
      writes.push([url, JSON.parse(JSON.stringify(options))]);
      return {};
    }
  };
  vm.runInNewContext(source, {XEC: C});
  return {C, writes, confirmations};
}

const paint = () => new Promise(resolve => setImmediate(resolve));

test("only admin sees removal controls and requests use typed ID and enrollment", async () => {
  const {C, writes, confirmations} = load([ready, {...ready, can_request: false, job: {state: "queued", order_id: "order-01"}}]);
  C.session.role = "operator";
  assert.equal(C.remoteRemovalPanel(agent), null);
  C.session.role = "admin";
  const section = C.remoteRemovalPanel(agent);
  await paint();
  await section.find("원격 제거…").action();
  assert.equal(confirmations[0].match, "web-01");
  assert.deepEqual(writes, [[route, {method: "POST", body: {enrollment_id: "enrollment-01", confirmation: "web-01"}}]]);
  assert.ok(section.find("대기 요청 취소"));
});

test("a queued order can be cancelled and an unknown result stays distinct from success", async () => {
  const job = {order_id: "order-01", state: "queued"};
  const {C, writes} = load([
    {...ready, can_request: false, job},
    {...ready, can_request: false, job: {...job, state: "result_unknown"}}
  ]);
  const section = C.remoteRemovalPanel(agent);
  await paint();
  await section.find("대기 요청 취소").action();
  assert.deepEqual(writes, [[route + "/cancel", {method: "POST", body: {enrollment_id: "enrollment-01", order_id: "order-01"}}]]);
  assert.ok(section.find("제거 결과 미확인"));
  assert.equal(section.find("제거 완료 · 등록 해지"), undefined);
  assert.equal(section.find("대기 요청 취소"), undefined);
});

test("navigation or enrollment change prevents submitting a stale confirmation", async () => {
  const {C, writes} = load([ready]);
  const section = C.remoteRemovalPanel(agent);
  C.confirm = async () => {
    C.state.agents = [{...agent, enrollment_id: "changed"}];
    return true;
  };
  await paint();
  await assert.rejects(section.find("원격 제거…").action(), /등록이 변경/);
  assert.equal(writes.length, 0);
});
