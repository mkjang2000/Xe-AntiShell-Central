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
  // Nanoseconds exceed JavaScript's safe integer range on long-running hosts.
  // Keep the protocol's uint64 decimal string intact rather than coercing it.
  const taskStart = value => typeof value === "string" && /^[1-9][0-9]{0,19}$/.test(value) && (value.length < 20 || value <= "18446744073709551615") ? value : "정확한 값 미확인";
  const capabilities = value => Array.isArray(value) && value.length <= 64 && new Set(value).size === value.length && value.every(item => typeof item === "string" && /^CAP_[A-Z0-9_]{1,63}$/.test(item)) ? [...value] : null;
  const list = value => value === null ? "미수집" : value.length ? value.join(" · ") : "없음 (빈 집합 확인)";
  const namespaceValid = value => {
    const n = C.object(value);
    return Number.isSafeInteger(n.inum) && n.inum > 0 && n.inum <= 4294967295 &&
      (n.is_host === undefined || typeof n.is_host === "boolean") &&
      (n.level === undefined || Number.isSafeInteger(n.level) && n.level >= 0 && n.level <= 64 && (n.is_host === undefined || (n.level === 0) === n.is_host));
  };
  const available = (event, path) => {
    for (const [group, fields] of [event.missing_fields, event.redacted_fields, event.truncated_fields].entries()) {
      for (const field of C.array(fields)) {
        if (typeof field !== "string") continue;
        // This exact missing-scope advisory does not erase a complete same-hook
        // pair. Redaction, truncation and contradictory known scope still fail.
        if (group === 0 && path === "credential" && field === "credential.user_namespace_scope") {
          const credential = C.object(event.credential);
          if ([credential.before, credential.after].some(snapshot => {
            const n = C.object(C.object(snapshot).user_namespace);
            return namespaceValid(n) && n.is_host === undefined;
          })) continue;
        }
        if (field === path || path.startsWith(`${field}.`) || path.startsWith(`${field}[`) || field.startsWith(`${path}.`) || field.startsWith(`${path}[`)) return false;
      }
    }
    return true;
  };
  const snapshotComplete = snapshot => {
    const value = C.object(snapshot), caps = C.object(value.capabilities);
    return ["uid","euid","gid","egid","suid","sgid","fsuid","fsgid"].every(key => id(value[key]) !== "미수집") &&
      ["effective","permitted","inheritable"].every(key => capabilities(caps[key]) !== null) && namespaceValid(value.user_namespace);
  };
  const taskID = value => Number.isSafeInteger(value) && value > 0 && value <= 2147483647;
  const observedTime = value => typeof value === "string" && !value.startsWith("0001-01-01") && Number.isFinite(Date.parse(value));
  const pairedEvidence = (event, value, before, after) => {
    const process = C.object(event.process);
    return event.source === "tetragon" && typeof event.boot_id === "string" && event.boot_id !== "" &&
      typeof process.exec_id === "string" && process.exec_id !== "" && observedTime(process.start_time) && observedTime(event.event_time) &&
      taskID(value.tgid) && taskID(value.tid) && process.pid === value.tgid && (!process.tid || process.tid === value.tid) &&
      taskStart(value.task_start_time_ns) !== "정확한 값 미확인" && value.evidence === "tetragon_commit_creds_pair" &&
      value.policy_name === "xeas-credential-change-v1" && value.function === "commit_creds" &&
      ["credential","process.pid","process.tid","process.exec_id","process.start_time","event_time","boot_id"].every(path => available(event,path)) &&
      snapshotComplete(before) && snapshotComplete(after);
  };
  const ns = value => {
    const n = C.object(value);
    if (!namespaceValid(n) || typeof n.is_host !== "boolean") return "범위 미확인";
    return n.is_host ? "초기 사용자 namespace · 컨테이너 격리/탈출 여부는 별도" : "별도 사용자 namespace · 호스트 root와 동일시하지 않음";
  };
  C.eventObservation = event => {
    if (C.object(event).event_type !== "process.credential_change") {
      const result = previousObservation(event), process = C.object(C.object(event).process);
      if (C.object(event).event_type === "process.exec") {
        const snapshot = C.object(process.credentials), execution = C.object(process.exec_privileges);
        result.fields.push(["실행 시점 UID / EUID",`${available(event,"process.uid")?id(process.uid):"미수집"} / ${available(event,"process.euid")?id(process.euid):"미수집"}`], ["사용자 namespace",available(event,"process.credentials.user_namespace")?ns(snapshot.user_namespace):"범위 미확인"]);
        if (available(event,"process.exec_privileges")) {
          if (execution.setuid !== undefined) result.fields.push(["실행 파일 setuid 메타데이터",id(execution.setuid)]);
          if (execution.setgid !== undefined) result.fields.push(["실행 파일 setgid 메타데이터",id(execution.setgid)]);
        }
        result.fields.push(["신원 정보 범위","실행 시점의 관측값입니다. 동일 프로세스의 이전 권한이나 권한 변경 성공을 이 값만으로 추정하지 않습니다."]);
      }
      return result;
    }
    const value = C.object(event.credential), before = C.object(value.before), after = C.object(value.after);
    const oldCaps = C.object(before.capabilities), newCaps = C.object(after.capabilities);
    const cap = (snapshot, key, prefix) => available(event,`${prefix}.capabilities.${key}`) ? capabilities(snapshot[key]) : null;
    const oldEffective = cap(oldCaps,"effective","credential.before"), newEffective = cap(newCaps,"effective","credential.after");
    const oldPermitted = cap(oldCaps,"permitted","credential.before"), newPermitted = cap(newCaps,"permitted","credential.after");
    const applied = pairedEvidence(event,value,before,after) && value.return_value === 0 && value.outcome === "applied";
    const failed = value.outcome === "failed" && Number.isSafeInteger(value.return_value) && value.return_value < 0 && available(event,"credential.return_value");
    const diff = (oldValues, newValues) => applied && oldValues !== null && newValues !== null ? newValues.filter(item => !oldValues.includes(item)) : null;
    const identity = (snapshot, key, prefix) => available(event,`${prefix}.${key}`) ? id(snapshot[key]) : "미수집";
    const oldID = key => identity(before,key,"credential.before"), newID = key => identity(after,key,"credential.after");
    const fields = [
      ["변경 전 → 후 UID", `${oldID("uid")} → ${newID("uid")}`],
      ["변경 전 → 후 EUID", `${oldID("euid")} → ${newID("euid")}`],
      ["변경 전 → 후 saved UID", `${oldID("suid")} → ${newID("suid")}`],
      ["변경 전 → 후 FSUID", `${oldID("fsuid")} → ${newID("fsuid")}`],
      ["변경 전 → 후 GID / EGID", `${oldID("gid")} / ${oldID("egid")} → ${newID("gid")} / ${newID("egid")}`],
      ["이전 effective / permitted", `${list(oldEffective)} / ${list(oldPermitted)}`],
      ["이후 effective / permitted", `${list(newEffective)} / ${list(newPermitted)}`],
      ["추가 effective", list(diff(oldEffective, newEffective))],
      ["추가 permitted", list(diff(oldPermitted, newPermitted))],
      ["변경 전 사용자 namespace", available(event,"credential.before.user_namespace")?ns(before.user_namespace):"범위 미확인"],
      ["변경 후 사용자 namespace", available(event,"credential.after.user_namespace")?ns(after.user_namespace):"범위 미확인"],
      ["적용 결과", applied ? "적용 확인 보고" : failed ? "호출 실패 보고" : "적용 여부 미확인"],
      ["TGID / TID", `${available(event,"credential.tgid")?id(value.tgid):"미수집"} / ${available(event,"credential.tid")?id(value.tid):"미수집"}`],
      ["커널 task 시작 시각(ns)", available(event,"credential.task_start_time_ns")?taskStart(value.task_start_time_ns):"정확한 값 미확인"],
      ["task 시각 범위", "동일 task 식별을 위한 커널 단조 시각입니다. 달력 시각이 아닙니다."],
      ["관측 근거", available(event,"credential.evidence") && value.evidence === "tetragon_commit_creds_pair" ? "고정 commit_creds 전후/반환 관측 종류" : "미확인"],
      ["수집 정책", available(event,"credential.policy_name") && value.policy_name === "xeas-credential-change-v1" ? "Xe-AntiShell 고정 권한 변경 정책" : "미확인"],
      ["원래 반환값", available(event,"credential.return_value") && Number.isSafeInteger(value.return_value) ? String(value.return_value) : "미수집"],
      ["관측 함수", available(event,"credential.function") && value.function === "commit_creds" ? "commit_creds" : "미확인"],
      ["증거 해석", "현재 실행 정보의 UID 비교만으로 변경을 추정하지 않습니다. 이전 값·결과가 누락되면 변경/권한 상승 확정 근거가 아닙니다."]
    ];
    const summary = applied ? "같은 커널 호출의 전후 자격 정보와 적용 반환을 확인했습니다. 승인된 작업인지와 사용자 namespace 범위는 별도로 확인해야 합니다." : failed ? "권한 변경 호출이 실패로 보고됐습니다. root 권한 획득을 뜻하지 않습니다." : "짝지어진 관측 근거 또는 적용 결과가 불충분합니다. 정확한 이전→이후 권한 변경이나 새 권한 확보로 단정하지 않습니다.";
    return {summary, fields};
  };
})(globalThis.XEC);
