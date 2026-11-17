"use strict";

// Bounded presentation of privilege facts; no source argv, code, or arbitrary
// nested data is promoted into the human-facing summary.
(function (C) {
  const previousFinding = C.findingPresentation;
  const previousObservation = C.eventObservation;
  const rules = {
    "privilege-root-execution": ["전역 root 실행 관측", "root 신원의 실행을 관측했습니다. 정상 운영 작업일 수 있으며 웹 출처로 한정되지 않습니다."],
    "privilege-root-restored": ["기존 root 자격의 실효 권한 복귀", "변경 전 UID 또는 saved UID가 0인 상태에서 EUID 0으로 복귀했습니다. 정상 작업이라는 증명이나 새로운 권한 탈취 판정은 아닙니다."],
    "privilege-host-root-gain": ["초기 사용자 namespace에서 root 권한 획득", "같은 초기 사용자 namespace에서 비root EUID가 0으로 바뀐 근거가 보고됐습니다. 원인과 허용된 권한 상승 여부를 확인하세요. 컨테이너 탈출 증거 자체는 아닙니다."],
    "privilege-root-identity-change": ["root 신원 변경 관측 · 권한 범위 확인 필요", "사용자 namespace가 다르거나 범위를 알 수 없는 root 신원 변경입니다. 호스트 root 탈취로 단정하지 않습니다."],
    "privilege-capability-gain": ["Linux Capability 권한 집합 증가", "이전·이후 집합에서 새로운 권한 확보가 관측됐습니다. 사용자 namespace와 정상 운영 작업 여부를 함께 확인하세요."],
    "privilege-capability-activated": ["기존 허용 Capability 활성화", "이미 permitted 집합에 있던 권한의 effective 활성화입니다. 새 권한 확보와 구분해 확인하세요."]
  };
  C.findingPresentation = value => {
    const finding = C.object(value), copy = Object.hasOwn(rules, finding.rule_id) ? rules[finding.rule_id] : null;
    return copy ? {title: copy[0], note: copy[1]} : previousFinding(value);
  };
  const id = value => Number.isSafeInteger(value) && value >= 0 && value < 4294967295 ? String(value) : "미수집";
  const capabilities = value => Array.isArray(value) && value.length <= 64 && value.every(item => typeof item === "string" && /^CAP_[A-Z0-9_]{1,63}$/.test(item)) ? [...new Set(value)] : null;
  const list = value => value === null ? "미수집" : value.length ? value.join(" · ") : "없음 (빈 집합 확인)";
  const ns = value => {
    const n = C.object(value);
    if (!Number.isSafeInteger(n.inum) || n.inum < 1 || typeof n.is_host !== "boolean") return "범위 미확인";
    return n.is_host ? "초기 사용자 namespace · 컨테이너 격리/탈출 여부는 별도" : "별도 사용자 namespace · 호스트 root와 동일시하지 않음";
  };
  C.eventObservation = event => {
    if (C.object(event).event_type !== "process.credential_change") {
      const result = previousObservation(event), process = C.object(C.object(event).process);
      if (C.object(event).event_type === "process.exec") {
        const snapshot = C.object(process.credentials), execution = C.object(process.exec_privileges);
        result.fields.push(["실행 시점 UID / EUID",`${id(process.uid)} / ${id(process.euid)}`], ["사용자 namespace",ns(snapshot.user_namespace)]);
        if (execution.setuid !== undefined) result.fields.push(["실행 파일 setuid 메타데이터",id(execution.setuid)]);
        if (execution.setgid !== undefined) result.fields.push(["실행 파일 setgid 메타데이터",id(execution.setgid)]);
        result.fields.push(["신원 정보 범위","실행 시점의 관측값입니다. 동일 프로세스의 이전 권한이나 권한 변경 성공을 이 값만으로 추정하지 않습니다."]);
      }
      return result;
    }
    const value = C.object(event.credential), before = C.object(value.before), after = C.object(value.after);
    const oldCaps = C.object(before.capabilities), newCaps = C.object(after.capabilities);
    const oldEffective = capabilities(oldCaps.effective), newEffective = capabilities(newCaps.effective);
    const oldPermitted = capabilities(oldCaps.permitted), newPermitted = capabilities(newCaps.permitted);
    const diff = (oldValues, newValues) => oldValues !== null && newValues !== null ? newValues.filter(item => !oldValues.includes(item)) : null;
    const outcome = {applied: "적용 확인 보고", failed: "호출 실패 보고", unknown: "적용 여부 미확인"};
    const fields = [
      ["변경 전 → 후 UID", `${id(before.uid)} → ${id(after.uid)}`],
      ["변경 전 → 후 EUID", `${id(before.euid)} → ${id(after.euid)}`],
      ["변경 전 → 후 saved UID", `${id(before.suid)} → ${id(after.suid)}`],
      ["변경 전 → 후 FSUID", `${id(before.fsuid)} → ${id(after.fsuid)}`],
      ["변경 전 → 후 GID / EGID", `${id(before.gid)} / ${id(before.egid)} → ${id(after.gid)} / ${id(after.egid)}`],
      ["이전 effective / permitted", `${list(oldEffective)} / ${list(oldPermitted)}`],
      ["이후 effective / permitted", `${list(newEffective)} / ${list(newPermitted)}`],
      ["추가 effective", list(diff(oldEffective, newEffective))],
      ["추가 permitted", list(diff(oldPermitted, newPermitted))],
      ["변경 전 사용자 namespace", ns(before.user_namespace)],
      ["변경 후 사용자 namespace", ns(after.user_namespace)],
      ["적용 결과", Object.hasOwn(outcome, value.outcome) && (value.outcome !== "applied" || value.before && value.after && value.return_value === 0) ? outcome[value.outcome] : "적용 여부 미확인"],
      ["TGID / TID", `${id(value.tgid)} / ${id(value.tid)}`],
      ["관측 근거", value.evidence === "tetragon_commit_creds_pair" ? "동일 commit_creds 호출의 직접 전후 자격 정보" : "미확인"],
      ["수집 정책", value.policy_name === "xeas-credential-change-v1" ? "Xe-AntiShell 고정 권한 변경 정책" : "미확인"],
      ["원래 반환값", Number.isSafeInteger(value.return_value) ? String(value.return_value) : "미수집"],
      ["관측 함수", value.function === "commit_creds" ? "commit_creds" : "미확인"],
      ["증거 해석", "현재 실행 정보의 UID 비교만으로 변경을 추정하지 않습니다. 이전 값·결과가 누락되면 변경/권한 상승 확정 근거가 아닙니다."]
    ];
    return {summary: "프로세스의 권한 변경 관측입니다. 변경 전후·호출 결과·사용자 namespace를 구분하며 정상 권한 복귀와 새로운 권한 확보를 같은 의미로 보지 않습니다.", fields};
  };
})(globalThis.XEC);
