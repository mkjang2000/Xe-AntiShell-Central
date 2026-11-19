import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = name => fs.readFileSync(new URL(name, import.meta.url), "utf8");
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.textContent = ""; this.className = ""; }
  append(...nodes) { this.children.push(...nodes); }
  set innerHTML(_) { throw new Error("HTML insertion is forbidden"); }
}
const plain = value => JSON.parse(JSON.stringify(value));
const text = node => typeof node === "string" ? node : node.textContent + " " + node.children.map(text).join(" ");

function load() {
  const document = {createElement: tag => new Element(tag)};
  const context = vm.createContext({document, Node: Element, structuredClone});
  for (const name of ["model.js", "policy-diff.js"]) vm.runInContext(source(name), context);
  return context.XEC;
}
const base = () => ({
  detection: {enabled: true, extended_process_rules: false, web_executables: ["nginx"], web_services: null, shells: ["sh", "bash", "zsh"], allowed_pairs: []},
  response: {mode: "observe", action: "none", risk_threshold: 90, min_confidence: 0.95, required_capabilities: null},
  monitoring: {enabled: true, sample_interval_seconds: 10, process_limit: 200}, uninstall_mode: "approval_required",
  integrity: {enabled: false, mode: "observe", require_tpm: false, paths: []}, validity_hours: 24
});

test("diff lists only changed fields with removed and added list items", () => {
  const C = load(), before = base(), after = base();
  after.detection.shells = ["sh", "bash", "fish"]; after.detection.web_services = [];
  after.response = {...after.response, mode: "enforce", action: "terminate", required_capabilities: ["response.terminate"]};
  after.detection.service_observations = [];
  const rows = C.policyDiff(before, after), byLabel = Object.fromEntries(rows.map(row => [row.label, row]));
  assert.deepEqual(plain(rows.map(row => row.label)), ["탐지 셸 (그대로 2개)", "파일·TCP 범위 출처", "대응 방식", "대응 동작", "필요한 기능"]);
  assert.equal(byLabel["탐지 셸 (그대로 2개)"].before, "− zsh"); assert.equal(byLabel["탐지 셸 (그대로 2개)"].after, "+ fish");
  assert.deepEqual([byLabel["대응 방식"].before, byLabel["대응 방식"].after], ["탐지 전용", "자동 종료"]);
  assert.deepEqual([byLabel["파일·TCP 범위 출처"].before, byLabel["파일·TCP 범위 출처"].after], ["호스트 YAML", "중앙 정책"]);
  assert.deepEqual(plain(C.policyDiff(base(), base())), [], "null and empty wire lists are equal");
});

test("changes group hosts by their current policy and never compare unknown settings", () => {
  const C = load(), template = {id: "ops", settings: base()};
  const changed = base(); changed.validity_hours = 48;
  const node = C.policyChanges([
    {kind: "none", agent_ids: ["new-01"]},
    {kind: "direct", policy_id: "manual", agent_ids: ["legacy-01"]},
    {kind: "console", policy_id: "ops", settings: base(), agent_ids: ["a", "b", "c", "d"]},
    {kind: "console", policy_id: "older", settings: changed, agent_ids: ["e"]},
    {kind: "console", policy_id: "many", comparison_omitted: true, agent_ids: ["f"]}
  ], template);
  const all = text(node);
  assert.match(all, /new-01.*처음 지정/s);
  assert.match(all, /legacy-01.*콘솔 밖에서 발급된 정책 \(manual\).*비교할 수 없습니다/s);
  assert.match(all, /a, b, c 외 1대.*4대.*설정 변경이 없습니다/s);
  assert.match(all, /'older'을\(를\) 'ops'\(으\)로 교체.*정책 유효 기간.*48시간.*24시간/s);
  assert.match(all, /f.*비교를 생략/s);
  assert.equal(C.policyChanges([], template), null);
  assert.equal(C.policyChanges(undefined, template), null);
});
