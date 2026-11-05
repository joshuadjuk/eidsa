/* ── Init ─────────────────────────────────────────────────────────────────── */
initAuth().then((ok) => {
  if (!ok) return;
  loadWorkspaces();
  renderOverview();
});

// Init theme
(function initTheme() {
  const saved = localStorage.getItem("eidsa_theme");
  if (saved === "light") {
    document.body.classList.add("theme-light");
    const btn = document.getElementById("btn-theme-toggle");
    if (btn) btn.innerHTML = '<i class="bi bi-moon-fill"></i>';
  }
})();
