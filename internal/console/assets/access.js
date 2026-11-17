"use strict";
(function (C) {
  const roleNames = {admin:"관리자",operator:"운영자",viewer:"조회자"};
  C.applyAccess = () => {
    const role = C.session?.role || "viewer";
    C.text("sessionUser", `${C.session?.username || ""} · ${roleNames[role] || "조회자"}`);
    C.text("accountsNavLabel", role === "admin" ? "계정 관리" : "내 계정");
    C.applyUpdateAccess?.();
    if (role === "admin" || role === "operator") return;
    for (const id of ["groupForm","templateForm","previewForm","enrollmentForm","removalForm","revokeForm"]) {
      const form = C.id(id);
      if (!form || form.querySelector(":scope > fieldset.access-fields")) continue;
      const fieldset = C.el("fieldset","access-fields");fieldset.disabled=true;
      const legend = C.el("legend","sr-only","조회 권한: 편집할 수 없습니다.");
      fieldset.append(legend,...form.childNodes);form.append(fieldset);
    }
    for (const id of ["newGroup","newTemplate","deployButton","deployConfirm"]) { const node=C.id(id);if(node)node.disabled=true; }
    for (const id of ["groups","policies","approvals"]) {
      const section=C.id(`view-${id}`);
      if(section&&!section.querySelector(".access-note"))section.prepend(C.el("p","inline-note access-note","조회 권한으로 접속했습니다. 변경·배포·승인은 운영자 또는 관리자에게 요청하세요."));
    }
  };
})(globalThis.XEC);
