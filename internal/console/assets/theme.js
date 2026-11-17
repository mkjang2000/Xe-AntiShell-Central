"use strict";
(function () {
  const key = "xeas-central-theme";
  let theme = "dark";
  try { const saved = localStorage.getItem(key); if (saved === "light" || saved === "dark") theme = saved; } catch (_) {}
  const apply = persist => {
    document.documentElement.dataset.theme = theme;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = theme === "dark" ? "#111820" : "#eef2f6";
    for (const button of document.querySelectorAll("[data-theme-toggle]")) {
      button.textContent = theme === "dark" ? "라이트 모드" : "다크 모드";
      button.setAttribute("aria-pressed", String(theme === "dark"));
      button.setAttribute("aria-label", button.textContent);
    }
    if (persist) try { localStorage.setItem(key, theme); } catch (_) {}
  };
  apply(false);
  document.addEventListener("DOMContentLoaded", () => {
    for (const button of document.querySelectorAll("[data-theme-toggle]")) button.addEventListener("click", () => { theme = theme === "dark" ? "light" : "dark"; apply(true); });
    apply(false);
  }, {once:true});
})();
