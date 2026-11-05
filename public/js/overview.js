/* ── Cross-tenant overview (MSP dashboard) ────────────────────────────────── */
// Shown on the home screen: one row per workspace from its last analysis snapshot.

function showOverview() {
  state.activeWorkspace = null;
  state.analysisData = null;
  if (state.leafletMap) {
    state.leafletMap.remove();
    state.leafletMap = null;
  }
  destroyCharts();
  document.getElementById("workspace-view").classList.add("hidden");
  document.getElementById("workspace-view").innerHTML = "";
  document.getElementById("welcome").classList.remove("hidden");
  document.getElementById("app").classList.remove("rnav-visible");
  renderSidebar();
  renderOverview();
}

async function renderOverview() {
  const el = document.getElementById("overview");
  if (!el) return;
  let rows;
  try {
    rows = await api("GET", "/api/overview");
  } catch (e) {
    el.innerHTML = "";
    return;
  }
  if (rows.length === 0) {
    el.innerHTML = "";
    return;
  }

  const sevRank = (r) => {
    const c = r.summary?.riskCounts || {};
    return (c.CRITICAL || 0) * 1e6 + (c.HIGH || 0) * 1e3 + (c.MEDIUM || 0);
  };
  rows.sort((a, b) => sevRank(b) - sevRank(a) || a.name.localeCompare(b.name));

  const totals = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, events: 0, high: 0 };
  for (const r of rows) {
    const s = r.summary;
    if (!s) continue;
    totals.CRITICAL += s.riskCounts.CRITICAL || 0;
    totals.HIGH += s.riskCounts.HIGH || 0;
    totals.MEDIUM += s.riskCounts.MEDIUM || 0;
    totals.events += s.stats.total || 0;
    totals.high += s.stats.highFindings || 0;
  }

  const pill = (n, cls) =>
    `<span class="ov-pill ${n ? cls : "ov-zero"}">${n.toLocaleString()}</span>`;
  const topThreat = (s) => {
    const entry = Object.entries(s.detectionCounts || {}).sort((a, b) => b[1] - a[1])[0];
    return entry ? `${escHtml(entry[0].replace(/_/g, " ").toLowerCase())} <span class="hint">×${entry[1]}</span>` : '<span class="hint">—</span>';
  };

  const body = rows
    .map((r) => {
      const s = r.summary;
      const c = s?.riskCounts || {};
      return `
      <tr onclick="selectWorkspace('${r.id}')">
        <td><div class="ov-name">${escHtml(r.name)}</div><div class="hint">${escHtml(r.tenant || "")}</div></td>
        <td>${s ? `${cacheAgeLabel(s.ts)}${s.filtered ? ' <i class="bi bi-funnel-fill hint" title="Last run used the target user filter"></i>' : ""}` : '<span class="hint">not analyzed</span>'}</td>
        <td class="num">${s ? s.stats.total.toLocaleString() : "—"}</td>
        <td class="num">${pill(c.CRITICAL || 0, "ov-crit")}</td>
        <td class="num">${pill(c.HIGH || 0, "ov-high")}</td>
        <td class="num">${pill(c.MEDIUM || 0, "ov-med")}</td>
        <td class="num">${s ? (s.stats.highFindings || 0).toLocaleString() : "—"}</td>
        <td>${s ? topThreat(s) : ""}</td>
        <td>${r.lastSync ? `${cacheAgeLabel(Date.parse(r.lastSync))}${r.autoSync ? ' <i class="bi bi-arrow-repeat hint" title="Auto-sync on"></i>' : ""}` : '<span class="hint">manual</span>'}</td>
      </tr>`;
    })
    .join("");

  el.innerHTML = `
    <div class="ov-head">
      <div class="section-label" style="margin:0"><i class="bi bi-grid-3x3-gap"></i> All Tenants</div>
      <button class="btn-secondary btn-xs" onclick="renderOverview()"><i class="bi bi-arrow-clockwise"></i> Refresh</button>
    </div>
    <div class="ov-totals">
      <div class="ov-total"><div class="ov-total-val c-danger">${totals.CRITICAL}</div><div class="hint">critical users</div></div>
      <div class="ov-total"><div class="ov-total-val c-warn">${totals.HIGH}</div><div class="hint">high-risk users</div></div>
      <div class="ov-total"><div class="ov-total-val">${totals.high.toLocaleString()}</div><div class="hint">high findings</div></div>
      <div class="ov-total"><div class="ov-total-val">${totals.events.toLocaleString()}</div><div class="hint">events analyzed</div></div>
      <div class="ov-total"><div class="ov-total-val">${rows.length}</div><div class="hint">workspaces</div></div>
    </div>
    <div class="ov-table-wrap">
      <table class="simple-table ov-table">
        <thead><tr>
          <th>Workspace</th><th>Last analysis</th><th class="num">Events</th>
          <th class="num">Critical</th><th class="num">High</th><th class="num">Medium</th>
          <th class="num">High findings</th><th>Top detection</th><th>Graph sync</th>
        </tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>`;
}
