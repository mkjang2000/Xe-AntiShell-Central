"use strict";

(function (C) {
  const base = "/api/central-update/";
  const tagPattern = /^v(\d{1,9})\.(\d{1,9})\.(\d{1,9})-r([1-9]\d{0,8})$/;
  const rpmPattern = /^(\d{1,9})\.(\d{1,9})\.(\d{1,9})-([1-9]\d{0,8})\.el(9|10)\.x86_64$/;
  const phases = {
    idle:"대기", queued:"접수됨", stopping:"센트럴 중지 중", backup:"백업 중",
    installing:"RPM 설치 중", starting:"센트럴 기동 확인 중", succeeded:"설치 완료",
    failed:"실패", interrupted:"중단됨 · 복구 상태 확인 필요"
  };
  const available = new Set(["idle","succeeded","failed","interrupted"]);
  const admin = () => C.session?.role === "admin";
  const compareVersions = (target, current) => {
    for (let i = 1; i <= 4; i++) {
      const order = Number(target[i]) - Number(current[i]);
      if (order !== 0) return order;
    }
    return 0;
  };
  const readyTag = (tag, installed) => {
    const target = tagPattern.exec(tag), current = rpmPattern.exec(installed);
    return Boolean(target && current && compareVersions(target, current) > 0);
  };
  const exact = (object, keys) => object && typeof object === "object" &&
    Object.keys(object).length === keys.length && keys.every(key => Object.hasOwn(object, key));

  // Send only the public, typed fields of a central release. The worker
  // verifies the signed bytes and RPM independently after upload.
  async function publicManifest(file, size) {
    const invalid = () => new Error("센트럴 RPM과 짝이 맞는 공개 서명 manifest를 선택하세요.");
    if (!file || file.size < 1 || file.size > 16384 || size < 1 || size > 64*1024*1024) throw invalid();
    let data;
    try { data = JSON.parse(await file.text()); } catch { throw invalid(); }
    if (!exact(data, ["key_id","signature","manifest"]) || !/^release-[a-f0-9]{16}$/.test(data.key_id) ||
        !/^[a-zA-Z0-9+/]{85}[AQgw]==$/.test(data.signature)) throw invalid();
    const m = data.manifest;
    if (!exact(m, ["schema_version","tag","artifact_name","os_major","sha256","size"]) ||
        typeof m.tag !== "string" || typeof data.key_id !== "string" || typeof data.signature !== "string" ||
        m.schema_version !== "1" || !["9","10"].includes(m.os_major) || m.size !== size ||
        typeof m.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(m.sha256)) throw invalid();
    const match = tagPattern.exec(m.tag);
    if (!match || m.artifact_name !== `xe-antishell-central-${match.slice(1,4).join(".")}-${match[4]}.el${m.os_major}.x86_64.rpm`) throw invalid();
    const header = btoa(JSON.stringify(data)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
    return {m, header};
  }

  C.initCentralUpdate = () => {
    const root = C.id("centralUpdate");
    if (!root) return;
    const id = C.id, select = id("centralRelease");
    let status = null, catalogLoaded = false, fetching = false, submitting = false, refreshing = false, timer;
    const visible = () => admin() && root.open && C.view === "updates" && !document.hidden;
    const usable = () => available.has(status?.state) && !!rpmPattern.exec(status?.current_version);
    const sync = () => {
      const enabled = admin() && usable() && !submitting;
      const current = rpmPattern.exec(status?.current_version);
      id("centralStatusRefresh").disabled = refreshing;
      id("centralReleaseRefresh").disabled = fetching || submitting;
      let firstAvailable;
      for (const option of select.options) {
        const target = tagPattern.exec(option.value);
        const order = current && target ? compareVersions(target, current) : null;
        option.disabled = order === null || order <= 0;
        option.textContent = option.value + (order === 0 ? " · 설치됨" : order < 0 ? " · 이전 버전" : "");
        if (!option.disabled) firstAvailable ??= option.value;
      }
      if (current && firstAvailable && (!select.selectedOptions[0] || select.selectedOptions[0].disabled)) {
        select.value = firstAvailable;
      }
      select.disabled = !enabled || !select.options.length;
      id("centralGithubInstall").disabled = !enabled || !readyTag(select.value, status?.current_version);
      id("centralRPM").disabled = id("centralManifest").disabled = !enabled;
      id("centralUploadInstall").disabled = !enabled || !id("centralRPM").files.length;
      if (catalogLoaded) C.text("centralCatalogNote", !select.options.length ? "이 운영체제용 서명 릴리즈가 없습니다." :
        !current ? "설치된 버전을 확인하는 중입니다." :
        firstAvailable ? "최신 버전순으로 표시합니다." : "설치된 버전보다 높은 릴리즈가 없습니다.");
    };
    const renderStatus = value => {
      if (!value || !Object.hasOwn(phases, value.state)) throw new Error("센트럴 업데이트 상태를 확인할 수 없습니다.");
      status = value;
      const facts = [["설치된 버전", value.current_version || "미확인"], ["업데이트 상태", phases[value.state]]];
      if (value.target) facts.push(["목표 릴리즈", value.target]);
      if (value.detail) facts.push(["상세", value.detail]);
      if (value.backup) facts.push(["백업 위치", value.backup]);
      id("centralUpdateFacts").replaceChildren(C.facts(facts));
    };
    const refresh = async () => {
      clearTimeout(timer);
      if (!visible() || refreshing) return;
      refreshing = true; sync();
      try {
        const result = await C.request(base+"status");
        if (visible()) renderStatus(result);
      } catch (error) {
        status = null;
        if (visible()) id("centralUpdateFacts").textContent = `상태 확인 대기 · ${error.message} 연결이 복구되면 다시 조회합니다.`;
      } finally {
        refreshing = false; sync();
        if (visible()) timer = setTimeout(refresh, status && available.has(status.state) ? 15000 : 4000);
      }
    };
    const catalog = async () => {
      if (fetching || !visible()) return;
      fetching = true; sync();
      try {
        const result = await C.request(base+"releases");
        if (!visible()) return;
        const selected = select.value;
        select.replaceChildren();
        for (const item of C.array(result.items)) {
          if (!tagPattern.test(item.tag)) continue;
          const option = C.el("option","",item.tag);
          option.value = item.tag; select.append(option);
        }
        if ([...select.options].some(option => option.value === selected)) select.value = selected;
        catalogLoaded = true;
      } catch (error) {
        if (visible()) {
          catalogLoaded = false;
          C.text("centralCatalogNote", error.message);
        }
      } finally { fetching = false; sync(); }
    };
    const install = async (upload) => {
      if (!admin() || !usable() || submitting) return;
      submitting = true; sync();
      let started = false;
      try {
        let tag = select.value, options;
        if (upload) {
          const file = id("centralRPM").files[0];
          if (!file) throw new Error("센트럴 RPM을 선택하세요.");
          if (file.size < 1 || file.size > 64*1024*1024) throw new Error("64 MiB 이하의 센트럴 RPM을 선택하세요.");
          const headers = {"Content-Type":"application/x-rpm","X-Xeas-Central-Confirm":"true"};
          const manifest = id("centralManifest").files[0];
          let major;
          if (manifest) {
            const {m,header} = await publicManifest(manifest,file.size);
            tag = m.tag; major = m.os_major;
            headers["X-Xeas-Central-Manifest"] = header;
          } else {
            const packaged = /^xe-antishell-central-(.+)\.rpm$/.exec(file.name || "");
            const parts = packaged && rpmPattern.exec(packaged[1]);
            if (!parts) throw new Error("GitHub 릴리즈의 원래 센트럴 RPM 파일명을 사용하거나 해당 서명 manifest를 선택하세요.");
            tag = `v${parts.slice(1,4).join(".")}-r${parts[4]}`; major = parts[5];
            headers["X-Xeas-Central-Artifact"] = file.name;
          }
          if (rpmPattern.exec(status?.current_version)?.[5] !== major) throw new Error("설치된 센트럴과 RPM의 EL 버전이 다릅니다.");
          options = {rawBody:file,headers};
        } else {
          options = {body:{tag,confirm:true}};
        }
        if (!readyTag(tag, status?.current_version)) throw new Error("현재 설치 버전보다 높은 릴리즈를 선택하세요.");
        if (!await C.confirm({title:"센트럴 업데이트 확인",description:`${status.current_version} → ${tag}. 센트럴 중지 후 상태를 백업하고 RPM을 설치합니다. 기동하는 동안 콘솔 연결이 잠시 끊길 수 있습니다.`,accept:"센트럴 업데이트"})) return;
        if (!visible() || !usable() || !readyTag(tag, status?.current_version)) return;
        started = true;
        C.text("centralUpdateMessage","RPM을 전송하고 서명을 확인하는 중입니다.");
        const result = await C.request(base+(upload?"upload":"github"), {method:"POST",timeoutMS:305000,...options});
        if (result?.target !== tag) throw new Error("목표 릴리즈를 확인할 수 없습니다.");
        renderStatus(result);
        C.text("centralUpdateMessage",`${tag} 요청이 접수됐습니다.`);
        id("centralRPM").value = id("centralManifest").value = "";
      } catch (error) {
        C.text("centralUpdateMessage", started ? `${error.message} 현재 작업 상태를 확인하세요.` : error.message);
        if (started) status = null;
      } finally {
        submitting = false; sync();
        if (started) refresh();
      }
    };
    C.applyCentralUpdateAccess = () => {
      root.hidden = !admin();
      if (!admin()) { root.open = false; status = null; clearTimeout(timer); }
      sync();
    };
    root.addEventListener("toggle", () => {
      if (visible()) { refresh(); catalog(); } else clearTimeout(timer);
    });
    const changedView = () => { if (visible()) refresh(); else clearTimeout(timer); };
    document.addEventListener("visibilitychange", changedView);
    globalThis.addEventListener("hashchange", () => setTimeout(changedView, 0));
    globalThis.addEventListener("pagehide", () => clearTimeout(timer));
    id("centralStatusRefresh").addEventListener("click", refresh);
    id("centralReleaseRefresh").addEventListener("click", catalog);
    id("centralGithubInstall").addEventListener("click", () => install(false));
    id("centralUploadInstall").addEventListener("click", () => install(true));
    for (const input of [select,id("centralRPM"),id("centralManifest")]) input.addEventListener("change",sync);
    C.applyCentralUpdateAccess();
  };
})(globalThis.XEC);
