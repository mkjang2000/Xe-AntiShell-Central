import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = name => fs.readFileSync(new URL(name, import.meta.url), "utf8");
const now = "2026-11-19T01:00:00Z";

function render({agent = {}, heartbeat = {}, cap} = {}) {
  const select = {value: "web", addEventListener(_, callback) { this.change = callback; }};
  const report = {replaceChildren(content) { this.content = content; }};
  const document = {getElementById: id => ({hostBoundaryAgent: select, hostBoundaryReport: report})[id]};
  const context = vm.createContext({document});
  vm.runInContext(source("model.js"), context);
  const C = context.XEC;
  C.now = () => Date.parse(now);
  C.options = () => {};
  C.facts = Object.fromEntries;
  C.empty = value => value;
  C.state.agents = [{
    agent_id: "web", enrollment_id: "web-registration", desired_policy_revision: 5,
    heartbeat: {
      agent_id: "web", enrollment_id: "web-registration", sent_at: now,
      policy_status: {result: "applied", active_revision: 4},
      status: {capability_report: {capabilities: {"response.terminate": cap}}}, ...heartbeat
    }, ...agent
  }];
  vm.runInContext(source("host-boundary.js"), context);
  assert.equal(C.listeners.length, 1);
  C.listeners[0]();
  select.change();
  return report.content;
}

const available = {provider: "pidfd", state: "supported", implementation: "implemented", runtime_state: "available"};
const active = {...available, runtime_state: "active", verified_at: "2026-11-10T00:00:00Z"};
const termination = "프로세스 종료 로컬 허용";

test("host boundary presents the authenticated report separately from the central target", () => {
  const report = render({cap: active});
  assert.equal(report[termination], "허용 · 호스트 보고");
  assert.equal(report["중앙 목표 정책 리비전"], "5");
  assert.equal(report["에이전트 적용 리비전"], "4");
  assert.equal(render({cap: available})[termination], "허용 안 함 · 호스트 보고");
  assert.equal(render({heartbeat: {policy_status: {result: "local", active_revision: 0}}})["에이전트 정책 적용 결과"], "로컬 설정 사용");
});

test("unsupported, missing or inconsistent pidfd evidence leaves local opt-in unknown", () => {
  for (const cap of [undefined, {...available, state: "unsupported", runtime_state: "inactive"},
    {...active, verified_at: null}, {...active, provider: "unknown"}, {...active, implementation: "planned"},
    {...active, verified_at: "2027-01-01T00:00:00Z"}]) {
    assert.equal(render({cap})[termination], "미확인");
  }
});

test("stale, revoked and other registrations never establish current host settings", () => {
  for (const data of [{agent: {revoked: true}}, {heartbeat: {enrollment_id: "previous"}},
    {heartbeat: {agent_id: "other"}}, {heartbeat: {sent_at: "2026-11-19T00:56:00Z"}},
    {agent: {heartbeat: null}}, {heartbeat: {sent_at: "2027-01-01T00:00:00Z"}}]) {
    const report = render({...data, cap: active});
    assert.equal(report[termination], "미확인");
    assert.equal(report["에이전트 적용 리비전"], "미확인");
  }
});
