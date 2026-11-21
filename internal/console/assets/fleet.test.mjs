import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = name => fs.readFileSync(new URL(name, import.meta.url), "utf8");
const now = Date.parse("2026-11-19T03:00:00Z");
const recent = "2026-11-19T02:59:50Z", old = "2026-11-19T01:00:00Z";

class FakeNode {
  constructor(tag, document) { Object.assign(this, {tagName: tag, document, children: [], textContent: "", className: "", hidden: false, handlers: {}, classList: {add: name => { this.className += ` ${name}`; }}}); }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = []; this.append(...nodes); }
  querySelectorAll() { return this.children.flatMap(node => typeof node === "string" ? [] : [node, ...node.querySelectorAll()]); }
  contains(node) { return this === node || this.querySelectorAll().includes(node); }
  focus() { this.document.activeElement = this; }
  addEventListener(name, callback) { this.handlers[name] = callback; }
  setAttribute(name, value) { this[name] = value; }
  removeAttribute(name) { delete this[name]; }
  replaceWith(node) { this.document.nodes[this.id] = node; }
}
const text = node => typeof node === "string" ? node : node.textContent + node.children.map(text).join("");
const find = (node, predicate) => node.querySelectorAll().find(predicate);
// Values built inside the vm context carry its Array prototype.
const plain = value => JSON.parse(JSON.stringify(value));

function load({app = false, history = false} = {}) {
  const document = {nodes: {}, activeElement: null, title: "", createElement(tag) { return new FakeNode(tag, this); }};
  document.body = Object.assign(new FakeNode("body", document), {dataset: {page: "console"}});
  document.getElementById = id => document.nodes[id] || (document.nodes[id] = Object.assign(new FakeNode("div", document), {id, value: ""}));
  const location = {hash: "", assign() {}};
  const context = vm.createContext({document, Node: FakeNode, location, structuredClone, URLSearchParams, AbortController, setTimeout, clearTimeout, addEventListener() {}});
  vm.runInContext(source("model.js"), context);
  const C = context.XEC;
  C.now = () => now;
  C.request = () => new Promise(() => {});
  vm.runInContext(source("host-boundary.js"), context);
  vm.runInContext(source("file-integrity.js"), context);
  vm.runInContext(source("fleet.js"), context);
  if (history) vm.runInContext(source("history.js"), context);
  C.inventoryCalls = [];
  C.agentServiceInventory = agent => { C.inventoryCalls.push(agent.agent_id); return C.el("section", "service-inventory-result", "TCP 서비스 목록"); };
  if (app) {
    for (const name of ["initOperations", "initHistory", "initPolicy", "initAccounts", "applyAccess"]) C[name] = () => {};
    vm.runInContext(source("app.js"), context);
  }
  return {C, document, location};
}

const capabilities = (extra = {}) => ({probed_at: recent, capabilities: {
  "collector.tetragon": {state: "limited", implementation: "implemented", runtime_state: "active", verified_at: recent},
  "observation.process_exec": {state: "limited", implementation: "implemented", runtime_state: "active", verified_at: recent}, ...extra}});
const resources = (extra = {}) => ({sampled_at: recent, cpu: {usage_percent: 5, load1: 0.5, logical_cpus: 4}, memory: {total_bytes: 100, used_bytes: 40},
  filesystems: [{mount: "/", type: "xfs", total_bytes: 100, used_bytes: 50, available_bytes: 50, total_inodes: 10, free_inodes: 5}], network: [], disks: [], processes: [], process_count: 10, ...extra});
const agent = (overrides = {}, heartbeat = {}, status = {}) => ({
  agent_id: "web-01", enrollment_id: "enrollment-01", hostname: "web-01.example", desired_policy_revision: 3, ...overrides,
  heartbeat: overrides.heartbeat === null ? null : {agent_id: "web-01", enrollment_id: "enrollment-01", sent_at: recent,
    policy_status: {active_revision: 3, result: "applied"}, resources: resources(),
    status: {health: "healthy", version: "0.1.0-38.el9.x86_64", collector: "tetragon-json", dropped: 0, parse_errors: 0,
      capability_report: {...capabilities(), platform: {pretty_name: "Rocky Linux 9.9 (Blue Onyx)", kernel_release: "5.14.0", architecture: "x86_64"}}, ...status}, ...heartbeat}
});

test("agent status follows connection, collection and then policy precedence", () => {
  const {C} = load();
  const state = value => { const s = C.agentStatus(value); return [s.key, s.label, s.attention]; };
  assert.deepEqual(state(agent({revoked: true})), ["revoked", "등록 해지", false]);
  assert.deepEqual(state(agent({heartbeat: null})), ["unknown", "보고 없음", true]);
  assert.deepEqual(state(agent({}, {sent_at: old})), ["stale", "수신 지연", true]);
  assert.deepEqual(state(agent({}, {}, {health: "error"})), ["health", "수집 오류", true]);
  const pending = C.agentStatus(agent({}, {policy_status: {active_revision: 2, result: "applied"}}));
  assert.deepEqual([pending.key, pending.label, pending.reason, pending.attention], ["policy", "정책 확인 필요", "적용 대기", true]);
  assert.deepEqual(state(agent({}, {}, {health: "starting"})), ["health", "시작 중", false]);
  assert.deepEqual(state(agent()), ["ok", "정상", false]);
  assert.equal(C.osLabel(agent()), "Rocky Linux 9.9");
});

test("list names the policy, its response modes and redeploy state", () => {
  const {C} = load();
  C.state.templates = [{id: "web", name: "웹 기본"}];
  C.state.agents = [
    agent({agent_id: "a", desired_policy_id: "web", desired_response_mode: "observe", desired_service_response_modes: ["would_block", "enforce"], policy_template_state: "changed"}),
    agent({agent_id: "b", desired_policy_revision: 0}, {policy_status: {active_revision: 0, result: "local"}}),
    agent({agent_id: "c", desired_policy_revision: 2}, {policy_status: {active_revision: 2, result: "applied"}})
  ];
  C.renderAgents();
  const rows = C.id("agentRows").children, cell = (row, index) => rows[row].children[index];
  assert.equal(text(cell(0, 2)), "웹 기본적용 보고탐지 전용 · 서비스별 모의 대응·자동 종료재배포 필요");
  assert.match(find(cell(0, 2), node => /response-mode/.test(node.className)).className, /enforce/);
  assert.equal(text(cell(1, 2)), "중앙 정책 없음로컬 설정 사용");
  assert.equal(text(cell(2, 2)), "콘솔 밖에서 발급한 정책적용 보고");
  assert.equal(rows[0].children.length, 6);
  assert.equal(text(cell(0, 0)), "aweb-01.example · Rocky Linux 9.9");
  assert.equal(find(cell(0, 0), node => node.tagName === "a").href, "#agents/a");
  assert.equal(text(cell(0, 5)), "0.1.0-38.el9.x86_64");
});

test("resource column highlights fresh pressure and mutes an old sample", () => {
  const {C} = load();
  const pressured = resources({memory: {total_bytes: 100, used_bytes: 96}, filesystems: [{mount: "/", total_bytes: 100, used_bytes: 85, available_bytes: 15}]});
  C.state.agents = [agent({agent_id: "fresh"}, {resources: pressured}), agent({agent_id: "late"}, {sent_at: old, resources: {...pressured, sampled_at: old}})];
  C.state.agents[1].heartbeat.policy_status = {active_revision: 3, result: "applied"};
  C.id("agentSort").value = "name";
  C.renderAgents();
  const usage = row => C.id("agentRows").children[row].children[4].children[0].children.map(node => [node.textContent, node.className]);
  assert.deepEqual(usage(0), [["CPU 5.0%", "usage"], ["메모리 96.0%", "usage danger"], ["디스크 85.0%", "usage warning"]]);
  assert.deepEqual(usage(1).map(([, name]) => name), ["usage stale", "usage stale", "usage stale"]);
  assert.match(text(C.id("agentRows").children[1].children[4]), /이전 측정 · 2시간 전/);
});

test("detection column counts events, opens their history and marks unknown or truncated counts", () => {
  const {C} = load();
  const opened = []; C.openHistory = options => opened.push(plain(options));
  C.state.agents = [agent({agent_id: "a-none", detections_24h: 0}), agent({agent_id: "b-old-server"}),
    agent({agent_id: "c-busy", detections_24h: 29782, last_detection_at: "2026-11-19T02:57:00Z"}), agent({agent_id: "d-revoked", revoked: true, detections_24h: 90000})];
  C.id("agentSort").value = "name"; C.renderAgents();
  const cells = () => C.id("agentRows").children.map(row => text(row.children[3]));
  assert.deepEqual(cells().slice(0, 3), ["없음", "미확인", "29,782건마지막 3분 전"]);
  const link = find(C.id("agentRows").children[2].children[3], node => node.tagName === "a");
  let prevented = false; link.handlers.click({preventDefault: () => { prevented = true; }});
  assert.equal(prevented, true);
  assert.deepEqual(opened, [{view: "detections", agent: "c-busy", range: "24h"}]);
  C.id("agentSort").value = "detections"; C.renderAgents();
  assert.deepEqual(C.id("agentRows").children.map(row => row.children[0].children[0].textContent), ["c-busy", "a-none", "b-old-server", "d-revoked"]);
  // A truncated scan makes counts lower bounds and leaves zero unconfirmed.
  C.state.detections = {since: "2026-11-18T03:00:00Z", truncated: true}; C.id("agentSort").value = "name"; C.renderAgents();
  assert.deepEqual(cells().slice(0, 3), ["확인 안 됨", "미확인", "29,782건 이상마지막 3분 전"]);
  C.selectedAgent = "c-busy"; C.renderAgentDetail(false);
  assert.match(text(C.id("agentDetailBadges")), /최근 24시간 탐지29,782건 이상마지막 3분 전/);
});

test("detection history opens with only the agent and the last 24 hours", () => {
  const {C, location} = load({history: true});
  const requests = []; C.request = path => { requests.push(path); return new Promise(() => {}); };
  Object.assign(C.id("historyType"), {value: "web-shell"}); Object.assign(C.id("historySearch"), {value: "bash"}); C.id("historyKind").value = "events";
  location.hash = "#agents/web-01";
  C.openHistory({view: "detections", agent: "web-01", range: "24h"});
  // Navigation loads the view after the hash changes.
  assert.equal(location.hash, "history"); assert.equal(requests.length, 0);
  location.hash = "#history";
  C.openHistory({view: "detections", agent: "web-01", range: "24h"});
  const params = new URLSearchParams(requests[0].split("?")[1]);
  assert.deepEqual(Object.fromEntries(params), {limit: "20", view: "detections", agent_id: "web-01", type: "", q: "", from: "2026-11-18T03:00:00.000Z"});
  assert.equal(C.id("historyPeriod").value, "24h");
});

test("status sort puts attention first by severity and revoked last; filters narrow to attention", () => {
  const {C} = load();
  C.state.agents = [agent({agent_id: "a-ok"}), agent({agent_id: "b-revoked", revoked: true}), agent({agent_id: "c-stale"}, {sent_at: old}),
    agent({agent_id: "d-error"}, {}, {health: "error"}), agent({agent_id: "e-full"}, {resources: resources({filesystems: [{mount: "/", total_bytes: 100, used_bytes: 70}]})})];
  const order = () => C.id("agentRows").children.map(row => row.children[0].children[0].textContent);
  C.renderAgents();
  assert.deepEqual(order(), ["d-error", "c-stale", "a-ok", "e-full", "b-revoked"]);
  C.id("agentSort").value = "disk"; C.renderAgents();
  assert.deepEqual(order().slice(0, 2), ["e-full", "a-ok"]); assert.equal(order().at(-1), "b-revoked");
  C.id("agentStatusFilter").value = "attention"; C.renderAgents();
  assert.deepEqual(order().sort(), ["c-stale", "d-error"]);
  assert.equal(C.id("agentResultCount").textContent, "2 / 5대");
});

test("filesystems with identical usage merge under the shortest path, empty ones never do", () => {
  const {C} = load();
  const same = {type: "xfs", total_bytes: 100, used_bytes: 60, available_bytes: 40, total_inodes: 9, free_inodes: 3};
  const empty = {type: "tmpfs", total_bytes: 50, used_bytes: 0, available_bytes: 50, total_inodes: 4, free_inodes: 4};
  const groups = C.groupFilesystems([{mount: "/var/lib/app", ...same}, {mount: "/tmp", ...same}, {mount: "/", ...same}, {mount: "/run", ...empty}, {mount: "/dev/shm", ...empty}, {mount: "/boot", ...same, used_bytes: 61}]);
  assert.deepEqual(plain(groups.map(group => [group.mount, group.mounts.length])), [["/", 3], ["/run", 1], ["/dev/shm", 1], ["/boot", 1]]);
  assert.deepEqual(plain(groups[0].mounts), ["/", "/tmp", "/var/lib/app"]);
});

test("loopback, veth, bridge and container interfaces are grouped apart by name", () => {
  const {C} = load();
  const split = C.splitInterfaces(["lo", "eno1", "veth12ab", "br-0f1e", "br0", "docker0", "wlan0", "virbr0", "cni0"].map(name => ({name})));
  assert.deepEqual(plain(split.physical.map(item => item.name)), ["eno1", "br0", "wlan0"]);
  assert.deepEqual(plain(split.virtual.map(item => item.name)), ["lo", "veth12ab", "br-0f1e", "docker0", "virbr0", "cni0"]);
});

test("issues need a current heartbeat for resource and capability items and ignore quiet observations", () => {
  const {C} = load();
  const report = capabilities({
    "collector.tetragon": {state: "limited", implementation: "implemented", runtime_state: "active", verified_at: old},
    "observation.file": {state: "limited", implementation: "implemented", runtime_state: "active", verified_at: old},
    "observation.network": {state: "limited", implementation: "implemented", runtime_state: "unverified"},
    "kernel.btf": {state: "error", implementation: "implemented", runtime_state: "available"}
  });
  const full = resources({filesystems: [{mount: "/", type: "xfs", total_bytes: 100, used_bytes: 92, available_bytes: 8}, {mount: "/snap/core", type: "squashfs", total_bytes: 10, used_bytes: 10}]});
  const issues = C.agentIssues(agent({policy_template_state: "changed"}, {resources: full}, {dropped: 3, capability_report: report}));
  assert.deepEqual(plain(issues.map(issue => [issue.tone, issue.title])), [
    ["danger", "디스크 / 사용률 92.0%"], ["danger", "커널 형식 정보 · 확인 오류"],
    ["warning", "배포 후 정책 저장본이 바뀌었습니다 · 재배포 필요"], ["warning", "에이전트 시작 이후 수집 이벤트 유실 3건"],
    ["warning", "실시간 실행 수집기 · 최신 상태 미확인"]
  ]);
  const late = C.agentIssues(agent({}, {sent_at: old, resources: {...full, sampled_at: old}}, {last_error: "collector restarted", capability_report: report}));
  assert.deepEqual(plain(late.map(issue => issue.title)), ["하트비트 수신 지연", "에이전트가 오류를 보고했습니다"]);
  assert.equal(late[1].detail, "collector restarted");
  assert.equal(C.agentIssues(agent({revoked: true})).length, 0);
  assert.equal(C.agentIssues(agent()).length, 0);
});

test("overview attention uses the same state precedence as the list", () => {
  const {C} = load();
  C.state.agents = [agent({agent_id: "late"}, {sent_at: old}), agent({agent_id: "fine"})];
  C.renderOverview();
  assert.equal(C.id("attentionList").children.length, 1);
  assert.match(text(C.id("attentionList").children[0]), /late · 하트비트 수신 지연/);
});

test("detail route opens from the hash, returns to the list and tolerates unknown or malformed IDs", () => {
  const {C, document, location} = load({app: true});
  location.hash = "#agents/web-01"; C.navigate();
  assert.equal(C.id("agentListView").hidden, true); assert.equal(C.id("agentDetail").hidden, false);
  assert.match(text(C.id("agentDetailBody")), /불러오는 중/);
  assert.match(document.title, /^web-01 · 에이전트/);
  C.updateState({server_time: "2026-11-19T03:00:00Z", agents: [agent()]});
  assert.equal(C.id("agentDetailTitle").textContent, "web-01");
  assert.equal(C.id("agentDetailSubtitle").textContent, "web-01.example · Rocky Linux 9.9 · 0.1.0-38.el9.x86_64");
  assert.match(text(C.id("agentDetailBody")), /확인 필요.*현재 보고 기준으로 확인할 항목이 없습니다/);
  C.showAgentTab("resources");
  assert.equal(C.id("agentDetailTabs").children.find(button => button["aria-pressed"] === "true").textContent, "자원");
  location.hash = "#agents"; C.navigate();
  assert.equal(C.selectedAgent, ""); assert.equal(C.id("agentListView").hidden, false); assert.equal(C.id("agentDetail").hidden, true);
  C.selectAgent("web-01");
  assert.equal(location.hash, "#agents/web-01");
  assert.equal(C.id("agentDetailTabs").children.find(button => button["aria-pressed"] === "true").textContent, "개요", "reopening starts on the overview");
  location.hash = "#agents/missing"; C.navigate();
  assert.match(text(C.id("agentDetailBody")), /이 ID의 에이전트가 목록에 없습니다/);
  assert.equal(C.id("agentDetailTabs").children.length, 0);
  location.hash = "#agents/%E0%A4%A"; C.navigate();
  assert.equal(C.selectedAgent, ""); assert.equal(C.id("agentListView").hidden, false);
  location.hash = "#overview"; C.navigate();
  assert.equal(C.selectedAgent, "");
});

test("detail names a directly issued policy by its signed ID once loaded", async () => {
  const {C} = load();
  const direct = agent({desired_policy_revision: 2, desired_response_mode: "observe"}, {policy_status: {active_revision: 2, result: "applied"}});
  let resolve; const loaded = new Promise(done => { resolve = done; });
  C.request = async path => { assert.equal(path, "/api/agents/web-01/policy"); resolve(); return {policy: {policy_id: "operator-direct", agent_id: "web-01", enrollment_id: "enrollment-01", revision: 2, response: {mode: "observe"}}}; };
  C.state.agents = [direct]; C.selectedAgent = "web-01";
  C.renderAgentDetail();
  assert.match(text(C.id("agentDetailBody")), /콘솔 밖에서 발급한 정책적용 보고.*대응 방식탐지 전용/);
  await loaded; await new Promise(done => setTimeout(done, 0));
  assert.match(text(C.id("agentDetailBody")), /콘솔 밖에서 발급한 정책 · operator-direct/);
});

test("tabs render only the selected panel and load services on demand", () => {
  const {C} = load();
  const network = [{name: "eno1", state: "up"}, {name: "veth01", state: "up"}];
  const filesystems = [{mount: "/", type: "xfs", total_bytes: 100, used_bytes: 50, available_bytes: 50}, {mount: "/var/tmp", type: "xfs", total_bytes: 100, used_bytes: 50, available_bytes: 50}];
  C.state.agents = [agent({}, {resources: resources({network, filesystems})})];
  C.selectedAgent = "web-01"; C.renderAgentDetail(false);
  const body = () => text(C.id("agentDetailBody"));
  assert.match(body(), /서버 정보/); assert.doesNotMatch(body(), /기능 구현·실동작 상태|TCP 서비스 목록/);
  assert.deepEqual(Array.from(C.inventoryCalls), []);
  C.showAgentTab("services");
  assert.deepEqual(Array.from(C.inventoryCalls), ["web-01"]); assert.doesNotMatch(body(), /서버 정보/);
  C.showAgentTab("resources");
  assert.match(body(), /파일시스템 · 1개 \(마운트 2개\)/); assert.match(body(), /같은 파일시스템 1개: \/var\/tmp/);
  assert.match(body(), /네트워크 · 1개 · 가상 1개 별도/); assert.match(body(), /가상·컨테이너 장치 · 1개/);
  const filesystemsSection = find(C.id("agentDetailBody"), node => node.tagName === "details" && /파일시스템/.test(node.children[0].textContent));
  assert.equal(filesystemsSection.open, true);
  C.showAgentTab("capabilities");
  assert.match(body(), /확인 필요 없음.*동작·지원 확인 2개/);
  const rest = find(C.id("agentDetailBody"), node => node.tagName === "details" && /그 밖의 기능/.test(node.children[0].textContent));
  assert.notEqual(rest.open, true);
  C.showAgentTab("policy");
  assert.match(body(), /정책 적용 상태/); assert.match(body(), /호스트 보안 경계/);
  assert.equal(C.showAgentTab("unknown"), undefined);
  assert.match(body(), /정책 적용 상태/);
});
