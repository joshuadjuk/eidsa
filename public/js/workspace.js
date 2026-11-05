/* ── Sidebar ──────────────────────────────────────────────────────────────── */
async function loadWorkspaces() {
  state.workspaces = await api("GET", "/api/workspaces");
  renderSidebar();
}

function renderSidebar() {
  const list = document.getElementById("workspace-list");
  list.innerHTML = "";
  if (state.workspaces.length === 0) {
    list.innerHTML =
      '<div style="padding:8px 10px;font-size:12px;color:var(--text3)">No workspaces yet</div>';
    return;
  }
  for (const ws of state.workspaces) {
    const isActive = state.activeWorkspace?.id === ws.id;
    const div = document.createElement("div");
    div.className = "ws-item" + (isActive ? " active" : "");
    const initials = ws.name
      .split(" ")
      .map((w) => w[0])
      .join("")
      .slice(0, 2)
      .toUpperCase();
    const prog = state.eventsLoading;
    const loadBar =
      isActive && prog
        ? `<div class="ws-load-bar"><div class="ws-load-bar-fill" style="width:${Math.round((prog.loaded / prog.total) * 100)}%"></div></div>`
        : "";
    div.innerHTML = `
      <div class="ws-item-icon">${initials}</div>
      <div class="ws-item-name" title="${escHtml(ws.name)}">${escHtml(ws.name)}</div>
      ${loadBar}`;
    div.onclick = () => selectWorkspace(ws.id);
    list.appendChild(div);
  }
}

async function selectWorkspace(id) {
  const ws = await api("GET", `/api/workspaces/${id}`);
  state.activeWorkspace = ws;
  state.analysisData = null;
  state.eventsPage = 1;
  state.eventsFilter = "";
  state.dateFrom = "";
  state.dateTo = "";
  state.correlationData = null;
  state.triages = ws.detectionTriages || {};
  state.userNotes = ws.userNotes || {};
  state.watchList = new Set(ws.watchList || []);
  state.detectionComments = ws.detectionComments || {};
  state.bulkSelected = new Set();
  state.eventsLoading = null;
  state.activeTab = "dashboard";
  if (state.leafletMap) {
    state.leafletMap.remove();
    state.leafletMap = null;
  }
  destroyCharts();
  renderSidebar();
  renderWorkspaceView();

  // Load from cache if available (and run with the current user-filter scope)
  const cached = await loadCache(ws.id);
  if (state.activeWorkspace?.id !== ws.id) return; // switched away while loading
  if (cached && cacheMatchesScope(cached.data, ws)) {
    state.analysisData = cached.data;
    renderAnalysis();
    if (cached.data?.eventsLimited) bgLoadEvents(ws.id, cached.data.total);
    const btnExport = document.getElementById("btn-export-pdf");
    if (btnExport) btnExport.style.display = "";
    const btnExecC = document.getElementById("btn-exec-summary");
    if (btnExecC) btnExecC.style.display = "";
    const btnDigestC = document.getElementById("btn-weekly-digest");
    if (btnDigestC) btnDigestC.style.display = "";
    const btnIOC = document.getElementById("btn-ioc-search");
    if (btnIOC) btnIOC.style.display = "";
    // Inject cache bar below the header
    const resultsEl = document.getElementById("analysis-results");
    if (resultsEl) {
      const bar = document.createElement("div");
      bar.id = "cache-bar";
      bar.className = "cache-bar";
      bar.innerHTML = `⏱ Cached · ${cacheAgeLabel(cached.ts)} <button onclick="runAnalysis()">Refresh</button>`;
      resultsEl.insertBefore(bar, resultsEl.firstChild);
    }
  } else {
    const btnExport = document.getElementById("btn-export-pdf");
    if (btnExport) btnExport.style.display = "none";
    const btnExecC2 = document.getElementById("btn-exec-summary");
    if (btnExecC2) btnExecC2.style.display = "none";
    const btnDigestC2 = document.getElementById("btn-weekly-digest");
    if (btnDigestC2) btnDigestC2.style.display = "none";
    const btnBaseC2 = document.getElementById("btn-set-baseline");
    if (btnBaseC2) btnBaseC2.style.display = "none";
    const btnIOC = document.getElementById("btn-ioc-search");
    if (btnIOC) btnIOC.style.display = "none";
  }
}

/* ── Workspace view ───────────────────────────────────────────────────────── */
function renderWorkspaceView() {
  const ws = state.activeWorkspace;
  document.getElementById("welcome").classList.add("hidden");
  document.getElementById("app").classList.remove("rnav-visible");
  const view = document.getElementById("workspace-view");
  view.classList.remove("hidden");

  view.innerHTML = `
    <div class="ws-header">
      <div class="ws-title">
        <h1>${escHtml(ws.name)}</h1>
        <div class="ws-breadcrumb">
          ${ws.tenant ? `<span>${escHtml(ws.tenant)}</span><span>·</span>` : ""}
          <span class="home-badge"><i class="bi bi-house-fill"></i> ${escHtml(ws.homeCountry || "ID")}</span>
        </div>
      </div>
      <div class="ws-header-actions">
        <button class="btn-secondary need-analyst" onclick="editWorkspaceModal()">Edit</button>
        <button class="btn-secondary need-admin" onclick="openIntegrations()" title="Microsoft Graph sync & alert webhook"><i class="bi bi-plug"></i> Integrations</button>
        ${ws.graph?.hasSecret ? `<button class="btn-secondary need-analyst" id="btn-graph-sync" onclick="startGraphSync()" title="Pull new sign-in/audit logs from Microsoft Graph, then analyze"><i class="bi bi-cloud-arrow-down"></i> Sync</button>` : ""}
        <button class="btn-primary" onclick="runAnalysis()"><i class="bi bi-play-fill"></i> Run Analysis</button>
        <button class="btn-secondary" onclick="openIOCSearch()" id="btn-ioc-search" title="IOC Search (press /)" style="display:none"><i class="bi bi-search"></i> IOC Search</button>
        <button class="btn-secondary" onclick="exportPDF()" id="btn-export-pdf" title="Export analysis as PDF" style="display:none"><i class="bi bi-download"></i> Export PDF</button>
        <button class="btn-secondary" onclick="exportExecutiveSummary()" id="btn-exec-summary" title="Executive Summary (management view)" style="display:none"><i class="bi bi-clipboard"></i> Executive</button>
        <button class="btn-secondary" onclick="exportWeeklyDigest()" id="btn-weekly-digest" title="Weekly Digest — full security brief (HTML)" style="display:none"><i class="bi bi-envelope"></i> Digest</button>
        <button class="btn-secondary" onclick="setBaselineNow()" id="btn-set-baseline" title="Save current run as drift baseline for future comparisons" style="display:none"><i class="bi bi-bar-chart-fill"></i> Set Baseline</button>
        <button class="btn-danger need-admin" onclick="deleteWorkspace()">Delete</button>
      </div>
    </div>
    <div class="ws-body">
      ${renderPlaybook(ws)}
      ${renderFileSection(ws)}
      ${renderUserListSection(ws)}
      <div id="analysis-results"></div>
    </div>
  `;

  setupDropZone();
  setupDropZone("userlist-drop-zone", uploadUserList);
}

function renderPlaybook(ws) {
  if (!ws.playbook)
    return `
    <div class="playbook-box">
      <div class="section-label"><i class="bi bi-journal-text"></i> Playbook / Notes</div>
      <p style="color:var(--text3);font-style:italic">No playbook set — click Edit to add investigation context, known IPs, or baseline countries.</p>
    </div>`;
  return `
    <div class="playbook-box">
      <div class="section-label"><i class="bi bi-journal-text"></i> Playbook / Notes</div>
      <p>${escHtml(ws.playbook)}</p>
    </div>`;
}

function renderFileSection(ws) {
  const files = ws.files || [];
  const fileItems = files
    .map(
      (f) => `
    <div class="file-item">
      <span class="file-item-icon"><i class="bi bi-file-text"></i></span>
      <span class="file-item-name">${escHtml(f.name)}</span>
      <span class="file-item-size">${formatBytes(f.size)}</span>
      <button class="file-item-del need-analyst" onclick="deleteFile('${escHtml(f.name)}')" title="Remove"><i class="bi bi-trash3"></i></button>
    </div>`,
    )
    .join("");

  return `
    <div class="file-section">
      <div class="file-section-header">
        <div class="section-label"><i class="bi bi-folder"></i> Sign-in Log Files <span style="color:var(--accent);margin-left:4px">${files.length}</span></div>
      </div>
      <div class="drop-zone need-analyst" id="drop-zone" onclick="document.getElementById('file-input').click()">
        <input type="file" id="file-input" multiple accept=".json" onchange="uploadFiles(this.files)" />
        Drop JSON files here or click to browse
      </div>
      <div class="file-list">${fileItems}</div>
    </div>`;
}

function renderUserListSection(ws) {
  const list = ws.userList;
  const hasList = !!list?.users?.length;
  const mode = hasList ? ws.userListMode || "all" : "all";
  const modeBtn = (m, icon, label, title) =>
    `<button class="${mode === m ? "active" : ""}" ${hasList ? "" : "disabled"} onclick="setUserListMode('${m}')" title="${title}"><i class="bi ${icon}"></i> ${label}</button>`;

  const listItem = hasList
    ? `
    <div class="file-item">
      <span class="file-item-icon"><i class="bi bi-people"></i></span>
      <span class="file-item-name">${escHtml(list.filename)}</span>
      <span class="file-item-size">${list.users.length.toLocaleString()} users</span>
      <button class="file-item-del need-analyst" onclick="deleteUserList()" title="Remove"><i class="bi bi-trash3"></i></button>
    </div>`
    : "";

  return `
    <div class="file-section">
      <div class="file-section-header">
        <div class="section-label"><i class="bi bi-person-lines-fill"></i> Target User List <span style="color:var(--accent);margin-left:4px">${hasList ? list.users.length.toLocaleString() : 0}</span></div>
        <div class="scope-seg need-analyst ${hasList ? "" : "disabled"}" title="${hasList ? "" : "Upload a user list first"}">
          ${modeBtn("all", "bi-list-ul", "All logs", "Analyze all sign-in logs, ignore the list")}
          ${modeBtn("highlight", "bi-star-fill", "Highlight", "Analyze all logs, mark listed users (IP-based detections still see every user)")}
          ${modeBtn("filter", "bi-funnel-fill", "Filtered users", "Analyze only sign-ins of listed users")}
        </div>
      </div>
      ${
        hasList
          ? ""
          : `
      <div class="drop-zone need-analyst" id="userlist-drop-zone" onclick="document.getElementById('userlist-input').click()">
        <input type="file" id="userlist-input" accept=".txt,text/plain" onchange="uploadUserList(this.files)" />
        Drop a .txt file with one userPrincipalName per line, or click to browse
      </div>`
      }
      <div class="file-list">${listItem}</div>
    </div>`;
}

function setupDropZone(zoneId = "drop-zone", onDrop = uploadFiles) {
  const zone = document.getElementById(zoneId);
  if (!zone) return;
  zone.addEventListener("dragover", (e) => {
    e.preventDefault();
    zone.classList.add("drag-over");
  });
  zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("drag-over");
    onDrop(e.dataTransfer.files);
  });
}

/* ── File operations ──────────────────────────────────────────────────────── */
async function uploadFiles(files) {
  if (!files || files.length === 0) return;
  const existing = (state.activeWorkspace?.files || []).map((f) => f.name);
  const duplicates = [...files]
    .filter((f) => existing.includes(f.name))
    .map((f) => f.name);
  if (duplicates.length > 0) {
    if (
      !confirm(
        `These files already exist and will be overwritten:\n${duplicates.join("\n")}\n\nContinue?`,
      )
    )
      return;
  }
  const fd = new FormData();
  for (const f of files) fd.append("files", f);
  try {
    const result = await api(
      "POST",
      `/api/workspaces/${state.activeWorkspace.id}/files`,
      fd,
    );
    toast(`Uploaded: ${result.uploaded.join(", ")}`);
    await selectWorkspace(state.activeWorkspace.id);
  } catch (e) {
    toast(e.message, "err");
  }
}

async function deleteFile(filename) {
  if (!confirm(`Remove ${filename}?`)) return;
  try {
    await api(
      "DELETE",
      `/api/workspaces/${state.activeWorkspace.id}/files/${encodeURIComponent(filename)}`,
    );
    toast(`Removed ${filename}`);
    await selectWorkspace(state.activeWorkspace.id);
  } catch (e) {
    toast(e.message, "err");
  }
}

/* ── Target user list ─────────────────────────────────────────────────────── */
// Any change to the list or the switch changes the analysis scope, so the cached
// result is dropped and the analysis re-runs if one was already on screen.
async function applyScopeChange(request, msg) {
  const wsId = state.activeWorkspace.id;
  const hadAnalysis = !!state.analysisData;
  try {
    await request();
    await clearCache(wsId);
    toast(msg);
    await selectWorkspace(wsId);
    if (hadAnalysis && (state.activeWorkspace.files || []).length > 0) runAnalysis();
  } catch (e) {
    toast(e.message, "err");
  }
}

async function uploadUserList(files) {
  const file = files?.[0];
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".txt")) {
    toast("User list must be a .txt file", "err");
    return;
  }
  const content = await file.text();
  await applyScopeChange(
    () => api("PUT", `/api/workspaces/${state.activeWorkspace.id}/userlist`, { filename: file.name, content }),
    `Loaded user list: ${escHtml(file.name)}`,
  );
}

async function deleteUserList() {
  if (!confirm("Remove the target user list? Analysis will cover all sign-in logs.")) return;
  await applyScopeChange(
    () => api("DELETE", `/api/workspaces/${state.activeWorkspace.id}/userlist`),
    "User list removed",
  );
}

const USER_LIST_MODE_MSG = {
  all: "Showing all sign-in logs",
  highlight: "Showing all logs — listed users highlighted",
  filter: "Showing listed users only",
};

async function setUserListMode(mode) {
  if ((state.activeWorkspace.userListMode || "all") === mode) return;
  await applyScopeChange(
    () => api("PATCH", `/api/workspaces/${state.activeWorkspace.id}`, { userListMode: mode }),
    USER_LIST_MODE_MSG[mode],
  );
}

// True when a cached analysis was run with the same user-list mode as the workspace now has
function cacheMatchesScope(data, ws) {
  const want = ws.userList?.users?.length ? ws.userListMode || "all" : "all";
  return (data?.userFilter?.mode || (data?.userFilter?.enabled ? "filter" : "all")) === want;
}

// Listed users when the workspace is in highlight mode (lowercased Set), else null
function highlightedUsers() {
  const uf = state.analysisData?.userFilter;
  return uf?.mode === "highlight" && uf.users ? new Set(uf.users) : null;
}

/* ── Cache helpers ────────────────────────────────────────────────────────── */
function cacheKey(wsId) {
  return `eidsa_analysis_${wsId}`;
}
function baselineKey(wsId) {
  return `eidsa_baseline_${wsId}`;
}

// Baselines are stored on the server (shared by the team) and arrive with the workspace
function saveBaseline(wsId, metrics) {
  const bl = { ts: Date.now(), metrics };
  if (state.activeWorkspace?.id === wsId) state.activeWorkspace.baseline = bl;
  api("POST", `/api/workspaces/${wsId}/baseline`, { metrics }).catch(() => {});
}
function loadBaseline(wsId) {
  if (state.activeWorkspace?.id === wsId && state.activeWorkspace.baseline) {
    return state.activeWorkspace.baseline;
  }
  // One-time migration of a baseline saved in this browser by older versions
  try {
    const r = localStorage.getItem(baselineKey(wsId));
    if (!r) return null;
    const bl = JSON.parse(r);
    localStorage.removeItem(baselineKey(wsId));
    if (hasRole("analyst")) saveBaseline(wsId, bl.metrics);
    return bl;
  } catch (e) {
    return null;
  }
}
function extractBaselineMetrics(data) {
  const home = (data.homeCountry || "ID").toUpperCase();
  const evs = data.events || [];
  const dets = data.detections || [];
  const sums = data.userSummaries || [];
  return {
    totalEvents: evs.length,
    foreignFailed: evs.filter(
      (e) => !e.success && e.country && e.country.toUpperCase() !== home,
    ).length,
    foreignSuccess: evs.filter(
      (e) => e.success && e.country && e.country.toUpperCase() !== home,
    ).length,
    detectionCount: dets.length,
    atRiskCount: sums.length,
    criticalCount: sums.filter((s) => s.riskLevel === "CRITICAL").length,
    highCount: sums.filter((s) => s.riskLevel === "HIGH").length,
    attackingCountries: [
      ...new Set(
        evs
          .filter((e) => e.country && e.country.toUpperCase() !== home)
          .map((e) => e.country),
      ),
    ].length,
  };
}

// Analysis results live in IndexedDB — localStorage's ~5 MB quota silently
// dropped large results. The old localStorage entry is removed on first read.
function saveCache(wsId, data) {
  return idb.set(cacheKey(wsId), { ts: Date.now(), data });
}

async function loadCache(wsId) {
  try {
    localStorage.removeItem(cacheKey(wsId));
  } catch (e) {}
  return (await idb.get(cacheKey(wsId))) || null;
}

function clearCache(wsId) {
  return idb.del(cacheKey(wsId));
}

function cacheAgeLabel(ts) {
  const mins = Math.round((Date.now() - ts) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  return hrs < 24 ? `${hrs}h ago` : `${Math.round(hrs / 24)}d ago`;
}

