
/* ── IndexedDB events cache ─────────────────────────────────────────────────
   Stores full sorted events arrays keyed by "wsId:filesSig".
   Survives page refresh; cleared automatically when files change (new sig).  */
const idb = (() => {
  let _db = null;
  function open() {
    return new Promise((res, rej) => {
      if (_db) return res(_db);
      const req = indexedDB.open('eidsa_events', 1);
      req.onupgradeneeded = e => e.target.result.createObjectStore('ev');
      req.onsuccess  = e => { _db = e.target.result; res(_db); };
      req.onerror    = e => rej(e.target.error);
    });
  }
  const tx = (mode, fn) => open().then(db => new Promise((res, rej) => {
    const t = db.transaction('ev', mode);
    const r = fn(t.objectStore('ev'));
    r.onsuccess = () => res(r.result);
    r.onerror   = () => res(null);
  })).catch(() => null);
  return {
    get: key  => tx('readonly',  s => s.get(key)),
    set: (key, val) => tx('readwrite', s => s.put(val, key)),
    del: key  => tx('readwrite', s => s.delete(key)),
  };
})();

/* ── State ────────────────────────────────────────────────────────────────── */
const state = {
  workspaces: [],
  activeWorkspace: null,
  analysisData: null,
  eventsPage: 1,
  eventsPageSize: 50,
  eventsFilter: '',
  eventsStatusFilter: 'all',
  eventsSort: { col: 'createdAt', dir: 'desc' },
  editingWorkspace: null,
  activeTab: 'events',
  leafletMap: null,
  chartInstances: {},
  timelinePage: 1,
  timelinePageSize: 50,
  timelineUser: null,
  dateFrom: '',
  dateTo: '',
  correlationData: null,
  triages: {},
  userNotes: {},
  killChainFilter: null,
  detectionsPage: 1,
  detectionsPageSize: 30,
  detectionsFilter: '',
  detectionsSevFilter: 'all',
  watchList: new Set(),
  detectionComments: {},
  bulkSelected: new Set(),
  rnavOpenGroups: new Set(['accounts']),
  eventsLoading: null,  // { loaded, total } while bgLoadEvents is running, null when idle
};

/* ── API helpers ──────────────────────────────────────────────────────────── */
async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body instanceof FormData) {
    opts.body = body;
  } else if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

/* ── Toast ────────────────────────────────────────────────────────────────── */
function toast(msg, type = 'ok') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = msg;
  document.body.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 3000);
}

/* ── Sidebar ──────────────────────────────────────────────────────────────── */
async function loadWorkspaces() {
  state.workspaces = await api('GET', '/api/workspaces');
  renderSidebar();
}

function renderSidebar() {
  const list = document.getElementById('workspace-list');
  list.innerHTML = '';
  if (state.workspaces.length === 0) {
    list.innerHTML = '<div style="padding:8px 10px;font-size:12px;color:var(--text3)">No workspaces yet</div>';
    return;
  }
  for (const ws of state.workspaces) {
    const isActive = state.activeWorkspace?.id === ws.id;
    const div = document.createElement('div');
    div.className = 'ws-item' + (isActive ? ' active' : '');
    const initials = ws.name.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
    const prog = state.eventsLoading;
    const loadBar = isActive && prog
      ? `<div class="ws-load-bar"><div class="ws-load-bar-fill" style="width:${Math.round(prog.loaded/prog.total*100)}%"></div></div>`
      : '';
    div.innerHTML = `
      <div class="ws-item-icon">${initials}</div>
      <div class="ws-item-name" title="${escHtml(ws.name)}">${escHtml(ws.name)}</div>
      ${loadBar}`;
    div.onclick = () => selectWorkspace(ws.id);
    list.appendChild(div);
  }
}

async function selectWorkspace(id) {
  const ws = await api('GET', `/api/workspaces/${id}`);
  state.activeWorkspace = ws;
  state.analysisData = null;
  state.eventsPage = 1;
  state.eventsFilter = '';
  state.dateFrom = '';
  state.dateTo = '';
  state.correlationData = null;
  state.triages = ws.detectionTriages || {};
  state.userNotes = ws.userNotes || {};
  state.watchList = new Set(ws.watchList || []);
  state.detectionComments = ws.detectionComments || {};
  state.bulkSelected = new Set();
  state.eventsLoading = null;
  state.activeTab = 'dashboard';
  if (state.leafletMap) { state.leafletMap.remove(); state.leafletMap = null; }
  destroyCharts();
  renderSidebar();
  renderWorkspaceView();

  // Load from cache if available
  const cached = loadCache(ws.id);
  if (cached) {
    state.analysisData = cached.data;
    renderAnalysis();
    if (cached.data?.eventsLimited) bgLoadEvents(ws.id, cached.data.total);
    const btnExport = document.getElementById('btn-export-pdf');
    if (btnExport) btnExport.style.display = '';
    const btnExecC = document.getElementById('btn-exec-summary');
    if (btnExecC) btnExecC.style.display = '';
    const btnDigestC = document.getElementById('btn-weekly-digest');
    if (btnDigestC) btnDigestC.style.display = '';
    const btnIOC = document.getElementById('btn-ioc-search');
    if (btnIOC) btnIOC.style.display = '';
    // Inject cache bar below the header
    const resultsEl = document.getElementById('analysis-results');
    if (resultsEl) {
      const bar = document.createElement('div');
      bar.id = 'cache-bar';
      bar.className = 'cache-bar';
      bar.innerHTML = `⏱ Cached · ${cacheAgeLabel(cached.ts)} <button onclick="runAnalysis()">Refresh</button>`;
      resultsEl.insertBefore(bar, resultsEl.firstChild);
    }
  } else {
    const btnExport = document.getElementById('btn-export-pdf');
    if (btnExport) btnExport.style.display = 'none';
    const btnExecC2 = document.getElementById('btn-exec-summary');
    if (btnExecC2) btnExecC2.style.display = 'none';
    const btnDigestC2 = document.getElementById('btn-weekly-digest');
    if (btnDigestC2) btnDigestC2.style.display = 'none';
    const btnBaseC2 = document.getElementById('btn-set-baseline');
    if (btnBaseC2) btnBaseC2.style.display = 'none';
    const btnIOC = document.getElementById('btn-ioc-search');
    if (btnIOC) btnIOC.style.display = 'none';
  }
}

/* ── Workspace view ───────────────────────────────────────────────────────── */
function renderWorkspaceView() {
  const ws = state.activeWorkspace;
  document.getElementById('welcome').classList.add('hidden');
  document.getElementById('app').classList.remove('rnav-visible');
  const view = document.getElementById('workspace-view');
  view.classList.remove('hidden');

  view.innerHTML = `
    <div class="ws-header">
      <div class="ws-title">
        <h1>${escHtml(ws.name)}</h1>
        <div class="ws-breadcrumb">
          ${ws.tenant ? `<span>${escHtml(ws.tenant)}</span><span>·</span>` : ''}
          <span class="home-badge"><i class="bi bi-house-fill"></i> ${escHtml(ws.homeCountry || 'ID')}</span>
        </div>
      </div>
      <div class="ws-header-actions">
        <button class="btn-secondary" onclick="editWorkspaceModal()">Edit</button>
        <button class="btn-primary" onclick="runAnalysis()"><i class="bi bi-play-fill"></i> Run Analysis</button>
        <button class="btn-secondary" onclick="openIOCSearch()" id="btn-ioc-search" title="IOC Search (press /)" style="display:none"><i class="bi bi-search"></i> IOC Search</button>
        <button class="btn-secondary" onclick="exportPDF()" id="btn-export-pdf" title="Export analysis as PDF" style="display:none"><i class="bi bi-download"></i> Export PDF</button>
        <button class="btn-secondary" onclick="exportExecutiveSummary()" id="btn-exec-summary" title="Executive Summary (management view)" style="display:none"><i class="bi bi-clipboard"></i> Executive</button>
        <button class="btn-secondary" onclick="exportWeeklyDigest()" id="btn-weekly-digest" title="Weekly Digest — full security brief (HTML)" style="display:none"><i class="bi bi-envelope"></i> Digest</button>
        <button class="btn-secondary" onclick="setBaselineNow()" id="btn-set-baseline" title="Save current run as drift baseline for future comparisons" style="display:none"><i class="bi bi-bar-chart-fill"></i> Set Baseline</button>
        <button class="btn-danger" onclick="deleteWorkspace()">Delete</button>
      </div>
    </div>
    <div class="ws-body">
      ${renderPlaybook(ws)}
      ${renderFileSection(ws)}
      <div id="analysis-results"></div>
    </div>
  `;

  setupDropZone();
}

function renderPlaybook(ws) {
  if (!ws.playbook) return `
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
  const fileItems = files.map(f => `
    <div class="file-item">
      <span class="file-item-icon"><i class="bi bi-file-text"></i></span>
      <span class="file-item-name">${escHtml(f.name)}</span>
      <span class="file-item-size">${formatBytes(f.size)}</span>
      <button class="file-item-del" onclick="deleteFile('${escHtml(f.name)}')" title="Remove"><i class="bi bi-trash3"></i></button>
    </div>`).join('');

  return `
    <div class="file-section">
      <div class="file-section-header">
        <div class="section-label"><i class="bi bi-folder"></i> Sign-in Log Files <span style="color:var(--accent);margin-left:4px">${files.length}</span></div>
      </div>
      <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
        <input type="file" id="file-input" multiple accept=".json" onchange="uploadFiles(this.files)" />
        Drop JSON files here or click to browse
      </div>
      <div class="file-list">${fileItems}</div>
    </div>`;
}

function setupDropZone() {
  const zone = document.getElementById('drop-zone');
  if (!zone) return;
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    uploadFiles(e.dataTransfer.files);
  });
}

/* ── File operations ──────────────────────────────────────────────────────── */
async function uploadFiles(files) {
  if (!files || files.length === 0) return;
  const existing = (state.activeWorkspace?.files || []).map(f => f.name);
  const duplicates = [...files].filter(f => existing.includes(f.name)).map(f => f.name);
  if (duplicates.length > 0) {
    if (!confirm(`These files already exist and will be overwritten:\n${duplicates.join('\n')}\n\nContinue?`)) return;
  }
  const fd = new FormData();
  for (const f of files) fd.append('files', f);
  try {
    const result = await api('POST', `/api/workspaces/${state.activeWorkspace.id}/files`, fd);
    toast(`Uploaded: ${result.uploaded.join(', ')}`);
    await selectWorkspace(state.activeWorkspace.id);
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function deleteFile(filename) {
  if (!confirm(`Remove ${filename}?`)) return;
  try {
    await api('DELETE', `/api/workspaces/${state.activeWorkspace.id}/files/${encodeURIComponent(filename)}`);
    toast(`Removed ${filename}`);
    await selectWorkspace(state.activeWorkspace.id);
  } catch (e) {
    toast(e.message, 'err');
  }
}

/* ── Cache helpers ────────────────────────────────────────────────────────── */
function cacheKey(wsId)    { return `eidsa_analysis_${wsId}`; }
function baselineKey(wsId) { return `eidsa_baseline_${wsId}`; }

function saveBaseline(wsId, metrics) {
  try { localStorage.setItem(baselineKey(wsId), JSON.stringify({ ts: Date.now(), metrics })); } catch(e) {}
}
function loadBaseline(wsId) {
  try { const r = localStorage.getItem(baselineKey(wsId)); return r ? JSON.parse(r) : null; } catch(e) { return null; }
}
function extractBaselineMetrics(data) {
  const home = (data.homeCountry || 'ID').toUpperCase();
  const evs  = data.events || [];
  const dets = data.detections || [];
  const sums = data.userSummaries || [];
  return {
    totalEvents:        evs.length,
    foreignFailed:      evs.filter(e => !e.success && e.country && e.country.toUpperCase() !== home).length,
    foreignSuccess:     evs.filter(e => e.success  && e.country && e.country.toUpperCase() !== home).length,
    detectionCount:     dets.length,
    atRiskCount:        sums.length,
    criticalCount:      sums.filter(s => s.riskLevel === 'CRITICAL').length,
    highCount:          sums.filter(s => s.riskLevel === 'HIGH').length,
    attackingCountries: [...new Set(evs.filter(e => e.country && e.country.toUpperCase() !== home).map(e => e.country))].length,
  };
}

function saveCache(wsId, data) {
  try { localStorage.setItem(cacheKey(wsId), JSON.stringify({ ts: Date.now(), data })); } catch(e) {}
}

function loadCache(wsId) {
  try {
    const raw = localStorage.getItem(cacheKey(wsId));
    return raw ? JSON.parse(raw) : null;
  } catch(e) { return null; }
}

function clearCache(wsId) {
  try { localStorage.removeItem(cacheKey(wsId)); } catch(e) {}
}

function cacheAgeLabel(ts) {
  const mins = Math.round((Date.now() - ts) / 60000);
  if (mins < 1)  return 'just now';
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.round(mins / 60);
  return hrs < 24 ? `${hrs}h ago` : `${Math.round(hrs/24)}d ago`;
}

/* ── Analysis ─────────────────────────────────────────────────────────────── */
async function runAnalysis() {
  const el = document.getElementById('analysis-results');
  el.innerHTML = '<div class="loading"><div class="spinner"></div><span>Analyzing sign-in logs…</span></div>';
  if (state.leafletMap) { state.leafletMap.remove(); state.leafletMap = null; }
  destroyCharts();
  try {
    state.analysisData = await api('GET', `/api/workspaces/${state.activeWorkspace.id}/analyze`);
    const wsId = state.activeWorkspace.id;
    // Save current cache as prev-run snapshot before overwriting
    const oldCache = loadCache(wsId);
    if (oldCache) savePrevRun(wsId, oldCache.data);
    saveCache(wsId, state.analysisData);
    // Auto-save baseline on first run for this workspace
    if (!loadBaseline(wsId)) {
      saveBaseline(wsId, extractBaselineMetrics(state.analysisData));
    }
    mergeRunHistory(wsId, state.analysisData);
    updateUserProfiles(wsId, state.analysisData.events || []);
    state.eventsPage = 1;
    state.detectionsPage = 1;
    state.detectionsFilter = '';
    state.detectionsSevFilter = 'all';
    state.activeTab = 'dashboard';
    renderAnalysis();
    if (state.analysisData.eventsLimited) {
      bgLoadEvents(wsId, state.analysisData.total);
    }
    // Fetch cross-workspace IP correlations in background
    api('GET', `/api/ip-correlation/${state.activeWorkspace.id}`)
      .then(corr => { state.correlationData = corr; renderCorrelationPanel(); })
      .catch(() => {});
    // Fetch IP enrichment in background (decoupled from main analysis so it doesn't block)
    const _wsIdEnrich = state.activeWorkspace.id;
    api('GET', `/api/workspaces/${_wsIdEnrich}/enrich`)
      .then(d => {
        if (!d.ipEnrichment || !state.analysisData) return;
        state.analysisData.ipEnrichment = d.ipEnrichment;
        // Re-render any open IP pivots so they pick up the new data
        const pivotIp = document.querySelector('.ip-pivot-panel [data-ip]');
        if (pivotIp) openIPPivot(pivotIp.dataset.ip);
      })
      .catch(() => {});
    const btnExport = document.getElementById('btn-export-pdf');
    if (btnExport) btnExport.style.display = '';
    const btnExec = document.getElementById('btn-exec-summary');
    if (btnExec) btnExec.style.display = '';
    const btnDigest = document.getElementById('btn-weekly-digest');
    if (btnDigest) btnDigest.style.display = '';
    const btnBase = document.getElementById('btn-set-baseline');
    if (btnBase) btnBase.style.display = '';
    const btnIOC = document.getElementById('btn-ioc-search');
    if (btnIOC) btnIOC.style.display = '';
  } catch (e) {
    el.innerHTML = `<div class="empty">${e.message}</div>`;
  }
}

function renderCacheBar(ts) {
  const el = document.getElementById('cache-bar');
  if (el) el.outerHTML = `<div class="cache-bar" id="cache-bar">⏱ Cached · ${cacheAgeLabel(ts)} <button onclick="runAnalysis()">Refresh</button></div>`;
}

function renderAnalysis() {
  const data = state.analysisData;
  const el = document.getElementById('analysis-results');
  if (!data) return;

  const events = data.events || [];
  const detections = data.detections || [];
  const homeCountry = data.homeCountry || 'ID';

  const failures    = events.filter(e => !e.success).length;
  const successes   = events.filter(e => e.success).length;
  const uniqueUsers = new Set(events.map(e => e.userPrincipal)).size;
  const uniqueCountries = new Set(events.map(e => e.country).filter(Boolean)).size;
  const highFindings = detections.filter(d => d.severity === 'high').length;

  // Foreign logins count (successful, not home country)
  const foreignLogins = events.filter(e => e.success && e.country && e.country.toUpperCase() !== homeCountry).length;

  // Compromised accounts = users that appear in any detection
  const compromisedUsers = new Set();
  for (const d of detections) {
    if (d.user) compromisedUsers.add(d.user);
    if (d.affectedUsers) d.affectedUsers.forEach(u => compromisedUsers.add(u));
  }

  // Parse warnings banner (truncated files)
  const warnings = (data.parseWarnings || []).filter(w => w.truncated);
  const warningBanner = warnings.length > 0 ? `
    <div style="background:rgba(245,166,35,0.1);border:1px solid rgba(245,166,35,0.3);border-radius:var(--radius);padding:10px 14px;margin-bottom:12px;font-size:12px;color:var(--warn)">
      <i class="bi bi-exclamation-triangle"></i> ${warnings.map(w => w.error
        ? `<strong>${escHtml(w.file)}</strong> — failed to parse (${escHtml(w.error)})`
        : `<strong>${escHtml(w.file)}</strong> — file was truncated, recovered <strong>${w.recovered.toLocaleString()}</strong> events (partial data)`
      ).join('<br>')}
    </div>` : '';

  const breachMatches = data.breachMatches || [];
  const breachBanner = breachMatches.length > 0 ? `
    <div style="background:rgba(220,38,38,0.1);border:1px solid rgba(220,38,38,0.35);border-radius:var(--radius);padding:10px 14px;margin-bottom:12px;font-size:12px;color:#dc2626">
      <i class="bi bi-unlock-fill"></i> <strong>Breach Alert:</strong> ${breachMatches.length} user(s) found in uploaded breach list — credentials may be compromised:
      <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px">${breachMatches.map(u=>`<strong style="background:rgba(220,38,38,0.15);border:1px solid rgba(220,38,38,0.3);border-radius:4px;padding:1px 8px">${escHtml(u)}</strong>`).join('')}</div>
    </div>` : '';

  el.innerHTML = warningBanner + breachBanner + `
    <!-- Tab panels — right nav controls which one shows; each panel is a full view -->
    <div class="tab-panels-wrap">
      <div id="tab-dashboard" class="tab-panel ${state.activeTab === 'dashboard' ? 'active' : ''}">
        <!-- Stats always shown inside dashboard -->
        <div class="stats-grid">
          <div class="stat-card info">
            <div class="stat-icon"><i class="bi bi-bar-chart-fill"></i></div>
            <div class="stat-label">Total Events</div>
            <div class="stat-value">${events.length.toLocaleString()}</div>
          </div>
          <div class="stat-card ok">
            <div class="stat-icon"><i class="bi bi-check-circle-fill"></i></div>
            <div class="stat-label">Successful</div>
            <div class="stat-value">${successes.toLocaleString()}</div>
          </div>
          <div class="stat-card danger">
            <div class="stat-icon"><i class="bi bi-x-circle-fill"></i></div>
            <div class="stat-label">Failed</div>
            <div class="stat-value">${failures.toLocaleString()}</div>
          </div>
          <div class="stat-card ${foreignLogins > 0 ? 'warn' : 'ok'}">
            <div class="stat-icon"><i class="bi bi-globe"></i></div>
            <div class="stat-label">Foreign Logins</div>
            <div class="stat-value">${foreignLogins.toLocaleString()}</div>
          </div>
          <div class="stat-card ${compromisedUsers.size > 0 ? 'danger' : 'ok'}">
            <div class="stat-icon"><i class="bi bi-exclamation-triangle-fill"></i></div>
            <div class="stat-label">Accounts at Risk</div>
            <div class="stat-value">${compromisedUsers.size}</div>
          </div>
          <div class="stat-card info">
            <div class="stat-icon"><i class="bi bi-geo-alt-fill"></i></div>
            <div class="stat-label">Countries</div>
            <div class="stat-value">${uniqueCountries}</div>
          </div>
          <div class="stat-card ${highFindings > 0 ? 'danger' : 'ok'}">
            <div class="stat-icon"><i class="bi bi-shield-exclamation"></i></div>
            <div class="stat-label">High Findings</div>
            <div class="stat-value">${highFindings}</div>
          </div>
          <div class="stat-card info">
            <div class="stat-icon"><i class="bi bi-person-fill"></i></div>
            <div class="stat-label">Unique Users</div>
            <div class="stat-value">${uniqueUsers.toLocaleString()}</div>
          </div>
        </div>
        <!-- User risk cards + timeline -->
        ${renderDashboard(data)}
      </div>
      <div id="tab-detections" class="tab-panel ${state.activeTab === 'detections' ? 'active' : ''}">
        ${buildDetectionsSection(detections)}
      </div>
      <div id="tab-remediation" class="tab-panel ${state.activeTab === 'remediation' ? 'active' : ''}">
        ${renderRemediationTab(data)}
      </div>
      <div id="tab-events" class="tab-panel ${state.activeTab === 'events' ? 'active' : ''}">
        ${renderEventsTable(events)}
      </div>
      <div id="tab-map" class="tab-panel ${state.activeTab === 'map' ? 'active' : ''}">
        <div id="map-container"></div>
      </div>
      <div id="tab-charts" class="tab-panel ${state.activeTab === 'charts' ? 'active' : ''}">
        <div id="charts-container"></div>
      </div>
      <div id="tab-killchain" class="tab-panel ${state.activeTab === 'killchain' ? 'active' : ''}">
        <div id="killchain-container"></div>
      </div>
      <div id="tab-velocity" class="tab-panel ${state.activeTab === 'velocity' ? 'active' : ''}">
        <div id="velocity-container"></div>
      </div>
      <div id="tab-graph" class="tab-panel ${state.activeTab === 'graph' ? 'active' : ''}">
        <div id="graph-container"></div>
      </div>
      <div id="tab-swimlane" class="tab-panel ${state.activeTab === 'swimlane' ? 'active' : ''}">
        <div id="swimlane-container"></div>
      </div>
      <div id="tab-sankey" class="tab-panel ${state.activeTab === 'sankey' ? 'active' : ''}">
        <div id="sankey-container"></div>
      </div>
      <div id="tab-countryapp" class="tab-panel ${state.activeTab === 'countryapp' ? 'active' : ''}">
        <div id="countryapp-container"></div>
      </div>
    </div>
  `;


  buildRightNav();
  if (state.activeTab === 'map')       { setTimeout(() => { initMap(); if (state.leafletMap) state.leafletMap.invalidateSize(); }, 50); }
  if (state.activeTab === 'charts')    { setTimeout(() => initCharts(), 50); }
  if (state.activeTab === 'killchain')  { setTimeout(() => initKillChain(), 50); }
  if (state.activeTab === 'velocity')   { setTimeout(() => initVelocity(), 50); }
  if (state.activeTab === 'graph')      { setTimeout(() => initAttackGraph(), 50); }
  if (state.activeTab === 'swimlane')   { setTimeout(() => initSwimlane(), 50); }
  if (state.activeTab === 'sankey')     { setTimeout(() => initSankey(), 50); }
  if (state.activeTab === 'countryapp') { setTimeout(() => initCountryApp(), 50); }
  setTimeout(() => initAllRadarCharts(), 80);
}

/* ── Dashboard ────────────────────────────────────────────────────────────── */
function renderDashboard(data) {
  const summaries     = data.userSummaries    || [];
  const timeline      = data.attackTimeline   || [];
  const events        = data.events           || [];
  const homeCountry   = data.homeCountry      || 'ID';

  const wl = state.watchList;
  const watching     = summaries.filter(s => wl.has(s.user));
  const nonWatching  = summaries.filter(s => !wl.has(s.user));
  const criticalUsers = nonWatching.filter(s => s.riskLevel === 'CRITICAL');
  const highUsers     = nonWatching.filter(s => s.riskLevel === 'HIGH');
  const mediumUsers   = nonWatching.filter(s => s.riskLevel === 'MEDIUM');
  const lowUsers      = nonWatching.filter(s => s.riskLevel === 'LOW');

  // Successful foreign logins
  const foreignSuccEvents = events.filter(e => e.success && e.country && e.country.toUpperCase() !== homeCountry);
  const foreignFailEvents = events.filter(e => !e.success && e.country && e.country.toUpperCase() !== homeCountry);

  const alertBanners = summaries
    .filter(s => s.foreignSuccess > 0)
    .map(s => {
      const e = s.successfulForeignEvents[0];
      const dt = e ? formatDate(e.createdAt || e.time) : '';
      const apps = (s.successfulForeignApps || []).slice(0, 2).join(' & ');
      return `
        <div class="alert-banner">
          <div class="alert-banner-icon"><i class="bi bi-shield-exclamation"></i></div>
          <div class="alert-banner-body">
            <div class="alert-banner-title">Critical — Successful Foreign Login</div>
            <div class="alert-banner-text">
              <strong>${escHtml(s.displayName)}</strong> successfully signed in from
              <strong>${escHtml(e?.foreignCountry || e?.country || '?')}</strong>
              ${e?.foreignCity ? '(' + escHtml(e.foreignCity) + ')' : ''}
              on ${dt}${apps ? ' to ' + escHtml(apps) : ''}.
              Credentials may be compromised — investigate immediately.
              <a href="#" style="color:var(--accent);margin-left:6px" onclick="openTimeline('${escHtml(s.user)}');return false">View Timeline →</a>
            </div>
          </div>
        </div>`;
    }).join('');

  const critSection = criticalUsers.length + highUsers.length > 0 ? `
    <div id="risk-group-high" class="risk-section">
      <div class="section-heading"><i class="bi bi-circle-fill" style="color:#ef4444"></i> High-Risk Accounts <span class="count-badge">${criticalUsers.length + highUsers.length}</span></div>
      <div class="risk-cards">
        ${[...criticalUsers, ...highUsers].map(s => renderRiskCard(s)).join('')}
      </div>
    </div>` : '';

  const medSection = mediumUsers.length > 0 ? `
    <div id="risk-group-medium" class="risk-section">
      <div class="section-heading" style="margin-top:4px"><i class="bi bi-circle-fill" style="color:#f59e0b"></i> Medium-Risk Accounts <span class="count-badge">${mediumUsers.length}</span></div>
      <div class="risk-cards">
        ${mediumUsers.map(s => renderRiskCard(s, true)).join('')}
      </div>
    </div>` : '';

  const lowSection = lowUsers.length > 0 ? `
    <div id="risk-group-low" class="risk-section">
      <div class="section-heading" style="margin-top:4px"><i class="bi bi-circle-fill" style="color:#10b981"></i> Low-Risk Accounts <span class="count-badge">${lowUsers.length}</span></div>
      <div class="risk-cards">
        ${lowUsers.map(s => renderRiskCard(s, true)).join('')}
      </div>
    </div>` : '';

  const watchSection = watching.length > 0 ? `
    <div class="section-heading"><i class="bi bi-star-fill"></i> Watch List <span class="count-badge">${watching.length}</span></div>
    <div class="risk-cards">
      ${watching.map(s => renderRiskCard(s)).join('')}
    </div>` : '';

  const noRisk = summaries.length === 0 ? `
    <div class="empty" style="padding:48px 0">
      <i class="bi bi-check-circle-fill"></i> No suspicious accounts detected in this workspace.
    </div>` : '';

  const timelineSection = timeline.length > 0 ? renderAttackTimeline(timeline) : '';

  return `
    <div class="dashboard-grid">
      <div class="dashboard-main">
        ${renderDriftBanner(data)}
        ${renderDeltaPanel(data)}
        ${alertBanners}
        ${watchSection}
        ${critSection}
        ${medSection}
        ${lowSection}
        ${noRisk}
      </div>
      <div class="dashboard-side">
        ${renderDashSideStats(events, summaries, homeCountry)}
        ${renderHealthScore(events, data.detections || [])}
        ${timelineSection}
      </div>
    </div>`;
}

function renderDashSideStats(events, summaries, homeCountry) {
  const home = homeCountry.toUpperCase();
  const totalEvents    = events.length;
  const foreignFail    = events.filter(e => !e.success && e.country && e.country.toUpperCase() !== home).length;
  const foreignSuccess = events.filter(e => e.success  && e.country && e.country.toUpperCase() !== home).length;
  const atRisk         = summaries.length;

  return `
    <div class="dash-panel">
      <div class="dash-panel-header">
        <span class="dash-panel-title">Summary</span>
      </div>
      <div class="dash-panel-body" style="display:flex;flex-direction:column;gap:10px">
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:12px;color:var(--text2)"><i class="bi bi-exclamation-triangle"></i> Accounts at Risk</span>
          <span style="font-size:18px;font-weight:700;color:${atRisk > 0 ? 'var(--danger)' : 'var(--ok)'}">${atRisk}</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:12px;color:var(--text2)"><i class="bi bi-bar-chart-fill"></i> Total Events</span>
          <span style="font-size:18px;font-weight:700;color:var(--accent)">${totalEvents.toLocaleString()}</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:12px;color:var(--text2)"><i class="bi bi-x-circle-fill"></i> Foreign Failed</span>
          <span style="font-size:18px;font-weight:700;color:${foreignFail > 0 ? 'var(--warn)' : 'var(--ok)'}">${foreignFail.toLocaleString()}</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0">
          <span style="font-size:12px;color:var(--text2)"><i class="bi bi-globe"></i> Foreign Success</span>
          <span style="font-size:18px;font-weight:700;color:${foreignSuccess > 0 ? 'var(--danger)' : 'var(--ok)'}">${foreignSuccess}</span>
        </div>
      </div>
    </div>`;
}

function renderRiskCard(s, collapsed = false) {
  const cls      = 'rc-' + s.riskLevel.toLowerCase();
  const rbCls    = 'rb-' + s.riskLevel.toLowerCase();
  const isPinned = state.watchList.has(s.user);
  const initials = s.displayName.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();
  const cardId = `rc-${Math.random().toString(36).slice(2)}`;

  const timeRange = s.attackStart && s.attackEnd ? (() => {
    const s1 = formatDate(s.attackStart);
    const s2 = formatDate(s.attackEnd);
    return s1 === s2 ? s1 : `${s1} — ${s2}`;
  })() : '';

  const chips = s.attackingCountries.slice(0, 12).map(c =>
    `<span class="country-chip">${escHtml(c)}</span>`
  ).join('');
  const moreChips = s.attackingCountries.length > 12
    ? `<span class="country-chip chip-more">+${s.attackingCountries.length - 12} more</span>`
    : '';

  const successColor = s.foreignSuccess > 0 ? 'c-danger' : 'c-ok';
  const attemptColor = s.foreignAttempts > 50 ? 'c-danger' : s.foreignAttempts > 10 ? 'c-warn' : 'c-accent';

  const notePreview = state.userNotes[s.user]
    ? `<div class="rc-note-badge" title="${escHtml(state.userNotes[s.user])}"><i class="bi bi-pencil"></i> ${escHtml(state.userNotes[s.user].slice(0, 60))}${state.userNotes[s.user].length > 60 ? '…' : ''}</div>`
    : '';

  const userHist = state.activeWorkspace ? getUserHistory(state.activeWorkspace.id, s.user) : null;
  const repeatBadge = userHist && userHist.count > 1
    ? `<span class="repeat-badge" title="Seen in ${userHist.count} previous runs — first: ${new Date(userHist.firstSeen).toLocaleDateString('en-GB')}">REPEAT ${userHist.count}×</span>`
    : '';

  const anomalyChips = renderUserAnomalyChips(s.user);

  return `
    <div class="risk-card ${cls}" id="${cardId}">
      <div class="rc-header" onclick="toggleRiskCard('${cardId}')">
        <div class="rc-avatar">${initials}</div>
        <div class="rc-header-info">
          <div class="rc-name">${escHtml(s.displayName)}</div>
          <div class="rc-meta">
            <span class="risk-badge ${rbCls}">${s.riskLevel}</span>
            ${s.riskScore != null ? `<span class="risk-score-badge risk-score-${s.riskLevel.toLowerCase()}" title="Risk Score: ${s.riskScore}/100">${s.riskScore}<span style="font-size:9px;opacity:0.7">/100</span></span>` : ''}
            ${repeatBadge}
            <span class="rc-threat">${escHtml(s.primaryThreat)}</span>
          </div>
          ${anomalyChips}
        </div>
        <button class="rc-expand-btn${isPinned ? ' rc-pin-active' : ''}" onclick="event.stopPropagation();toggleWatchList('${escHtml(s.user)}')" title="${isPinned ? 'Unpin from Watch List' : 'Pin to Watch List'}">${isPinned ? '<i class="bi bi-star-fill"></i>' : '<i class="bi bi-star"></i>'}</button>
        <button class="rc-expand-btn" onclick="event.stopPropagation();openTimeline('${escHtml(s.user)}')" title="View full timeline" style="margin-left:4px">↗</button>
        <button class="rc-expand-btn" onclick="event.stopPropagation();exportUserIncident('${escHtml(s.user)}')" title="Export Incident Report" style="margin-left:4px;font-size:11px">PDF</button>
        <button class="rc-expand-btn" onclick="event.stopPropagation();toggleRiskCard('${cardId}')" style="margin-left:4px">▾</button>
      </div>
      <div class="rc-stats">
        <div class="rc-stat">
          <div class="rc-stat-val ${attemptColor}">${s.foreignAttempts}</div>
          <div class="rc-stat-label">Foreign Attempts</div>
        </div>
        <div class="rc-stat">
          <div class="rc-stat-val ${successColor}">${s.foreignSuccess}</div>
          <div class="rc-stat-label">Successful</div>
        </div>
        <div class="rc-stat">
          <div class="rc-stat-val c-purple">${s.uniqueAttackingCountries}</div>
          <div class="rc-stat-label">Countries</div>
        </div>
        <div class="rc-stat">
          <div class="rc-stat-val" style="font-size:13px;padding-top:4px;color:var(--text2)">${timeRange || '—'}</div>
          <div class="rc-stat-label">Timeframe</div>
        </div>
      </div>
      <div class="rc-body ${collapsed ? '' : 'open'}" id="body-${cardId}">
        ${chips || moreChips ? `<div class="country-chips">${chips}${moreChips}</div>` : ''}
        ${s.narrative ? `<div class="rc-narrative">${escHtml(s.narrative)}</div>` : ''}
        ${notePreview}
        <div class="rc-radar-wrap"><canvas class="rc-radar-canvas" id="radar-${cardId}" width="160" height="160"></canvas></div>
      </div>
    </div>`;
}

function toggleRiskCard(cardId) {
  document.getElementById(`body-${cardId}`)?.classList.toggle('open');
}

function renderAttackTimeline(timeline) {
  const items = timeline.map(e => {
    const t = new Date(e.time);
    const timeStr = isNaN(t) ? '' : t.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    const errLabel = e.errorCode ? `<span class="atl-err">${e.errorCode}</span>` : '';
    const loc = [e.country, e.city].filter(Boolean).join(' / ');
    return `
      <div class="atl-item">
        <span class="atl-time">${timeStr}</span>
        <span class="atl-user atl-user-link" title="${escHtml(e.user)}" onclick="openTimeline('${escHtml(e.user)}')">${escHtml(e.displayName)}</span>
        <span class="atl-loc"><i class="bi bi-geo-alt-fill"></i> ${escHtml(loc)}</span>
        ${errLabel}
      </div>`;
  });

  // Group by date
  const byDate = {};
  for (let i = 0; i < timeline.length; i++) {
    const d = new Date(timeline[i].time);
    const key = isNaN(d) ? 'Unknown' : d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
    (byDate[key] = byDate[key] || []).push(items[i]);
  }

  const grouped = Object.entries(byDate).map(([date, rows]) => `
    <div class="atl-separator"><i class="bi bi-calendar"></i> ${date}</div>
    ${rows.join('')}
  `).join('');

  return `
    <div class="dash-panel">
      <div class="dash-panel-header">
        <span class="dash-panel-title">Attack Timeline</span>
        <span style="font-size:10px;color:var(--text3)">${timeline.length} events</span>
      </div>
      <div style="max-height:360px;overflow-y:auto">
        <div class="attack-timeline">${grouped}</div>
      </div>
    </div>`;
}

/* ── Conditional Access Recommendations ──────────────────────────────────── */
const CA_RECS = {
  PASSWORD_SPRAY:            { priority:'HIGH',     icon:'<i class="bi bi-shield-lock-fill"></i>', title:'Aktifkan Smart Lockout & Password Protection', desc:'Password spray terdeteksi. Smart Lockout mengunci akun setelah gagal berulang kali dari IP yang sama.', action:'Entra ID → Security → Authentication Methods → Password Protection', tip:'Set lockout threshold ≤5, lockout duration ≥60 detik. Aktifkan juga custom banned passwords.' },
  BRUTE_FORCE:               { priority:'HIGH',     icon:'<i class="bi bi-hammer"></i>', title:'Blokir Legacy Authentication Protocols', desc:'Brute force terdeteksi. Legacy auth (IMAP, POP3, SMTP AUTH) tidak mendukung MFA sehingga rentan.', action:'Entra ID → Security → Conditional Access → New Policy → Block legacy authentication', tip:'Target: Exchange ActiveSync + Other clients. Apply to All Users. Monitor 14 hari sebelum enforce.' },
  MFA_EXHAUSTION:            { priority:'CRITICAL', icon:'<i class="bi bi-phone-fill"></i>', title:'Aktifkan MFA Number Matching + Additional Context', desc:'MFA Fatigue Attack terdeteksi. Attacker membombardir notifikasi push MFA sampai user approve by reflex.', action:'Entra ID → Security → Authentication Methods → Microsoft Authenticator → Configure', tip:'Aktifkan Number Matching DAN Additional Context (tampilkan lokasi + app). Disable simple push approval.' },
  IMPOSSIBLE_TRAVEL:         { priority:'CRITICAL', icon:'<i class="bi bi-airplane-fill"></i>', title:'Terapkan Sign-in Risk Policy (Identity Protection)', desc:'Login dari lokasi yang tidak mungkin terdeteksi — indikasi credential compromise atau VPN abuse.', action:'Entra ID → Protection → Identity Protection → Sign-in risk policy', tip:'High risk → Require MFA atau Block. Medium risk → Require MFA. Butuh Entra ID P2 — pertimbangkan untuk akun kritis.' },
  FOREIGN_LOGIN:             { priority:'HIGH',     icon:'<i class="bi bi-globe"></i>', title:'Buat Named Location & Country Block CA Policy', desc:'Login sukses dari negara asing terdeteksi. Batasi akses dari negara yang tidak dioperasikan klien.', action:'Entra ID → Security → Conditional Access → Named Locations → Country/Region', tip:'Buat allowlist negara yang sah. Block sign-in dari semua negara lain, atau require MFA untuk negara baru.' },
  LEGACY_AUTH:               { priority:'HIGH',     icon:'<i class="bi bi-plug-fill"></i>', title:'Blokir Legacy Authentication (Policy Dedicated)', desc:'Login via protokol legacy terdeteksi. Protocol ini bypass MFA dan merupakan vektor serangan utama.', action:'Entra ID → Security → Conditional Access → New Policy → Conditions → Client apps', tip:'Buat CA policy khusus: kondisi "Other clients" dan "Exchange ActiveSync" → Grant "Block access".' },
  CA_GAP:                    { priority:'MEDIUM',   icon:'<i class="bi bi-shield-slash"></i>', title:'Audit Coverage Conditional Access Policies', desc:'Gap dalam coverage CA terdeteksi — ada user atau app yang tidak ter-cover policy apapun.', action:'Entra ID → Security → Conditional Access → Insights and Reporting', tip:'Gunakan CA "What If" tool untuk test coverage. Pastikan tidak ada user yang lolos semua policy.' },
  TOKEN_REPLAY:              { priority:'CRITICAL', icon:'<i class="bi bi-masks-theater"></i>', title:'Aktifkan Continuous Access Evaluation (CAE)', desc:'Token replay attack terdeteksi. Attacker menggunakan access token yang dicuri dari session lain.', action:'Entra ID → Security → Continuous Access Evaluation → Enable', tip:'CAE merevoke token secara real-time saat kondisi berubah. Aktifkan juga Token Protection di CA policy.' },
  ENUMERATION_ATTACK:        { priority:'MEDIUM',   icon:'<i class="bi bi-list-check"></i>', title:'Sembunyikan User Existence & Aktifkan SSPR Lockout', desc:'User enumeration terdeteksi. Attacker sedang memetakan akun valid untuk serangan berikutnya.', action:'Entra ID → Security → Authentication Methods → Password Reset', tip:'Pastikan error message login tidak membedakan "user tidak ada" vs "password salah". Enable SSPR lockout.' },
  CREDENTIAL_STUFFING:       { priority:'HIGH',     icon:'<i class="bi bi-unlock-fill"></i>', title:'Aktifkan User Risk Policy & Leaked Credential Detection', desc:'Credential stuffing terdeteksi — attacker menggunakan credential dari breach database pihak ketiga.', action:'Entra ID → Protection → Identity Protection → User risk policy', tip:'High user risk → Require password change. Aktifkan Password Hash Sync untuk leaked credential detection.' },
  ADMIN_TOOL_ABUSE:          { priority:'CRITICAL', icon:'<i class="bi bi-award-fill"></i>', title:'Terapkan Privileged Identity Management (PIM)', desc:'Admin tool abuse terdeteksi. Akses privileged tanpa oversight memudahkan lateral movement.', action:'Entra ID → Identity Governance → Privileged Identity Management → Roles', tip:'Terapkan just-in-time access dengan approval workflow + time limit untuk semua admin roles.' },
  SERVICE_PRINCIPAL_ANOMALY: { priority:'HIGH',     icon:'<i class="bi bi-robot"></i>', title:'Audit Service Principal Permissions', desc:'Anomali activity dari Service Principal/App terdeteksi — bisa indikasi compromised app credential.', action:'Entra ID → App Registrations → [App] → API Permissions + Certificates & Secrets', tip:'Review permission scope. Rotate client secrets. Terapkan least-privilege principle per service principal.' },
  TIME_OF_DAY_ANOMALY:       { priority:'MEDIUM',   icon:'<i class="bi bi-moon-fill"></i>', title:'Terapkan Business Hours Access Policy', desc:'Login di jam tidak wajar terdeteksi secara konsisten — anomali dari baseline normal user.', action:'Entra ID → Security → Conditional Access → New Policy → Conditions → Time (preview)', tip:'Require MFA tambahan atau block akses diluar jam kerja untuk user atau group berisiko tinggi.' },
  FIRST_SEEN_COUNTRY:        { priority:'MEDIUM',   icon:'<i class="bi bi-map"></i>', title:'Require MFA untuk Lokasi Baru (Named Locations)', desc:'Login dari negara yang belum pernah digunakan user sebelumnya terdeteksi.', action:'Entra ID → Security → Conditional Access → Named Locations', tip:'Buat policy: jika login dari lokasi di luar trusted countries → Require MFA. Log dan alert semua kasus.' },
  CONCURRENT_SESSIONS:       { priority:'HIGH',     icon:'<i class="bi bi-people-fill"></i>', title:'Konfigurasi Session Controls & Token Lifetime', desc:'Sesi concurrent mencurigakan terdeteksi — bisa indikasi token sharing atau session hijacking.', action:'Entra ID → Security → Conditional Access → Session controls → Sign-in frequency', tip:'Set sign-in frequency yang pendek untuk app sensitif. Disable persistent browser session untuk unmanaged devices.' },
  OAUTH_CONSENT_PHISHING:    { priority:'CRITICAL', icon:'<i class="bi bi-bug-fill"></i>', title:'Batasi User Consent untuk OAuth Applications', desc:'OAuth consent phishing terdeteksi — attacker membuat app berbahaya untuk mencuri token OAuth.', action:'Entra ID → Enterprise Applications → Consent and permissions → User consent settings', tip:'Set ke "Allow for verified publishers only" atau "Do not allow". Aktifkan admin consent workflow.' },
  DISTRIBUTED_BRUTE_FORCE:   { priority:'HIGH',     icon:'<i class="bi bi-globe2"></i>', title:'Aktifkan Risk-Based CA untuk Distributed Attack', desc:'Distributed brute force dari banyak IP terdeteksi — menghindari IP-based lockout tradisional.', action:'Entra ID → Protection → Identity Protection → Sign-in risk policy', tip:'IP-based lockout tidak efektif untuk distributed attack. Gunakan sign-in risk score untuk block/require MFA.' },
  MFA_METHOD_DOWNGRADE:      { priority:'HIGH',     icon:'<i class="bi bi-graph-down-arrow"></i>', title:'Require Phishing-Resistant MFA (Authentication Strength)', desc:'MFA method downgrade terdeteksi — attacker memaksa user ke metode MFA yang lebih mudah di-phish.', action:'Entra ID → Security → Authentication Methods → Authentication strengths', tip:'Buat custom Authentication Strength yang hanya izinkan FIDO2 Security Key atau Certificate-Based Auth.' },
  RARE_APP_ACCESS:           { priority:'LOW',      icon:'<i class="bi bi-box-seam"></i>', title:'Review App Permissions & Terapkan App-Based CA', desc:'Akses ke aplikasi yang jarang digunakan terdeteksi — perlu validasi apakah akses ini legitimate.', action:'Entra ID → Enterprise Applications → Usage & insights', tip:'Terapkan CA policy yang require MFA atau compliant device untuk apps sensitif atau jarang diakses.' },
  DEVICE_FINGERPRINT_ANOMALY:{ priority:'MEDIUM',   icon:'<i class="bi bi-laptop"></i>', title:'Terapkan Device Compliance CA Policy', desc:'Login dari device baru atau tidak dikenal secara konsisten terdeteksi.', action:'Entra ID → Security → Conditional Access → Require compliant device', tip:'Require Intune device compliance atau Hybrid AD Join untuk akses ke corporate resources.' },
};

function renderRemediationTab(data) {
  const detections = data.detections || [];
  const foundTypes = new Set(detections.map(d => d.type));
  const priorityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const colors = {
    CRITICAL: { bg:'rgba(209,52,56,0.09)',  border:'rgba(209,52,56,0.28)',  dot:'#ef4444', text:'#ff6b6b' },
    HIGH:     { bg:'rgba(249,115,22,0.08)', border:'rgba(249,115,22,0.25)', dot:'#f97316', text:'#fb923c' },
    MEDIUM:   { bg:'rgba(245,158,11,0.07)', border:'rgba(245,158,11,0.22)', dot:'#f59e0b', text:'#fbbf24' },
    LOW:      { bg:'rgba(0,120,212,0.07)',  border:'rgba(0,120,212,0.22)',  dot:'#0078d4', text:'#60a5fa' },
  };

  const activeRecs = Object.entries(CA_RECS)
    .filter(([type]) => foundTypes.has(type))
    .sort((a, b) => (priorityOrder[a[1].priority] ?? 4) - (priorityOrder[b[1].priority] ?? 4));

  const counts = { CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0 };
  activeRecs.forEach(([,r]) => { if (counts[r.priority] !== undefined) counts[r.priority]++; });

  if (activeRecs.length === 0) {
    return `<div class="empty" style="padding:60px 0"><i class="bi bi-check-circle-fill"></i> Tidak ada rekomendasi aktif — tidak ada deteksi yang memerlukan CA policy change.</div>`;
  }

  return `
    <div class="rem-header">
      <div>
        <div style="font-size:15px;font-weight:700;color:#fff;margin-bottom:4px">Rekomendasi Conditional Access Policy</div>
        <div style="font-size:12px;color:var(--text3)">${activeRecs.length} rekomendasi aktif berdasarkan ${foundTypes.size} tipe deteksi yang ditemukan</div>
      </div>
      <div class="rem-counts">
        ${Object.entries(counts).filter(([,v])=>v>0).map(([k,v])=>`
          <div class="rem-count-chip" style="background:${colors[k].bg};border:1px solid ${colors[k].border}">
            <span class="rem-count-dot" style="background:${colors[k].dot}"></span>
            <span style="color:${colors[k].text};font-weight:700">${v}</span>
            <span style="color:var(--text3)">${k}</span>
          </div>`).join('')}
      </div>
    </div>
    <div class="rem-list">
      ${activeRecs.map(([type, rec]) => {
        const c = colors[rec.priority] || colors.LOW;
        return `
          <div class="rem-card" style="background:${c.bg};border:1px solid ${c.border}">
            <div class="rem-card-top">
              <span class="rem-card-icon">${rec.icon}</span>
              <div style="flex:1;min-width:0">
                <div class="rem-card-title">${rec.title}</div>
                <div class="rem-card-desc">${rec.desc}</div>
              </div>
              <span class="rem-badge" style="background:${c.bg};border:1px solid ${c.border};color:${c.text}">${rec.priority}</span>
            </div>
            <div class="rem-card-path">
              <span style="opacity:.5;font-size:11px"><i class="bi bi-geo-alt-fill"></i></span>
              <span class="rem-path-text">${escHtml(rec.action)}</span>
            </div>
            <div class="rem-card-tip"><i class="bi bi-lightbulb-fill"></i> ${escHtml(rec.tip)}</div>
          </div>`;
      }).join('')}
    </div>`;
}

/* ── Right nav ────────────────────────────────────────────────────────────── */
const RNAV_TABS = [
  { id: 'dashboard',  icon: '◈',  label: 'Dashboard' },
  { id: 'accounts',   icon: '<i class="bi bi-person-fill"></i>', label: 'Accounts', children: [
    { id: 'accounts-high',   label: 'High Risk',   dot: '#ef4444' },
    { id: 'accounts-medium', label: 'Medium Risk',  dot: '#f59e0b' },
    { id: 'accounts-low',    label: 'Low Risk',     dot: '#10b981' },
  ]},
  { id: 'detections',   icon: '<i class="bi bi-search"></i>', label: 'Detections' },
  { id: 'remediation', icon: '<i class="bi bi-shield-check"></i>', label: 'CA Remediation' },
  { id: 'events',      icon: '≡',  label: 'Events' },
  { id: 'map',        icon: '◉',  label: 'Map' },
  { id: 'charts',     icon: '▦',  label: 'Charts' },
  { id: 'killchain',  icon: '⊕',  label: 'Kill Chain' },
  { id: 'velocity',   icon: '<i class="bi bi-lightning-charge-fill"></i>', label: 'Velocity' },
  { id: 'graph',      icon: '⬡',  label: 'Attack Graph' },
  { id: 'swimlane',   icon: '⊟',  label: 'Swimlane' },
  { id: 'sankey',     icon: '⊧',  label: 'Sankey' },
  { id: 'countryapp', icon: '⊞',  label: 'Country×App' },
];

function buildRightNav() {
  const items = document.getElementById('right-nav-items');
  if (!items) return;
  document.getElementById('app').classList.add('rnav-visible');
  items.innerHTML = RNAV_TABS.map(t => {
    if (t.children) {
      const open = state.rnavOpenGroups.has(t.id);
      return `
        <div class="rnav-group${open ? ' open' : ''}" id="rnav-group-${t.id}">
          <button class="rnav-item rnav-group-parent" onclick="toggleRnavGroup('${t.id}')" title="${t.label}">
            <span class="rnav-icon">${t.icon}</span>
            <span class="rnav-label">${t.label}</span>
            <svg class="rnav-arrow" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>
          </button>
          <div class="rnav-group-children">
            ${t.children.map(c => `
              <button class="rnav-item rnav-sub-item" onclick="gotoRiskSection('${c.id.replace('accounts-','')}')" title="${c.label}">
                <span class="rnav-sub-dot" style="background:${c.dot}"></span>
                <span class="rnav-label">${c.label}</span>
              </button>
            `).join('')}
          </div>
        </div>`;
    }
    return `
      <button class="rnav-item${state.activeTab === t.id ? ' active' : ''}"
              data-tab="${t.id}"
              onclick="switchTab('${t.id}')"
              title="${t.label}">
        <span class="rnav-icon">${t.icon}</span>
        <span class="rnav-label">${t.label}</span>
      </button>`;
  }).join('');
}

function toggleRightNav() {
  document.getElementById('app').classList.toggle('rnav-collapsed');
}

function toggleRnavGroup(id) {
  const grp = document.getElementById(`rnav-group-${id}`);
  if (!grp) return;
  grp.classList.toggle('open');
  if (grp.classList.contains('open')) {
    state.rnavOpenGroups.add(id);
  } else {
    state.rnavOpenGroups.delete(id);
  }
}

function gotoRiskSection(level) {
  switchTab('dashboard');
  setTimeout(() => {
    const el = document.getElementById(`risk-group-${level}`);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 80);
}

/* ── Tabs ─────────────────────────────────────────────────────────────────── */
function switchTab(tab) {
  state.activeTab = tab;
  document.querySelectorAll('.rnav-item').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  const btn = document.querySelector(`.rnav-item[data-tab="${tab}"]`);
  if (btn) btn.classList.add('active');
  const panel = document.getElementById(`tab-${tab}`);
  if (panel) panel.classList.add('active');
  // Scroll main panel to top when switching views
  const main = document.getElementById('main');
  if (main) main.scrollTop = 0;
  if (tab === 'map')       { setTimeout(() => { initMap(); if (state.leafletMap) state.leafletMap.invalidateSize(); }, 50); }
  if (tab === 'charts')    { setTimeout(() => initCharts(), 50); }
  if (tab === 'killchain') { setTimeout(() => initKillChain(), 50); }
  if (tab === 'velocity')  { setTimeout(() => initVelocity(), 50); }
  if (tab === 'graph')     {
    const gc = document.getElementById('graph-container');
    if (gc) gc.dataset.built = '';
    setTimeout(() => initAttackGraph(), 50);
  }
  if (tab === 'swimlane')   { setTimeout(() => initSwimlane(), 50); }
  if (tab === 'sankey')     { setTimeout(() => initSankey(), 50); }
  if (tab === 'countryapp') { setTimeout(() => initCountryApp(), 50); }
}

/* ── Detection cards ──────────────────────────────────────────────────────── */
/* ── MITRE ATT&CK mapping ─────────────────────────────────────────────────── */
const MITRE_MAP = {
  PASSWORD_SPRAY:            { id: 'T1110.003', name: 'Password Spraying',           tactic: 'Credential Access' },
  BRUTE_FORCE:               { id: 'T1110.001', name: 'Password Guessing',           tactic: 'Credential Access' },
  IMPOSSIBLE_TRAVEL:         { id: 'T1078',     name: 'Valid Accounts',              tactic: 'Defense Evasion' },
  FOREIGN_LOGIN:             { id: 'T1078',     name: 'Valid Accounts',              tactic: 'Defense Evasion' },
  TOKEN_REPLAY:              { id: 'T1550.001', name: 'Application Access Token',    tactic: 'Lateral Movement' },
  LEGACY_AUTH:               { id: 'T1078.004', name: 'Cloud Accounts',              tactic: 'Persistence' },
  ENUMERATION_ATTACK:        { id: 'T1087.002', name: 'Domain Account',              tactic: 'Discovery' },
  MFA_EXHAUSTION:            { id: 'T1621',     name: 'MFA Request Generation',      tactic: 'Credential Access' },
  CA_GAP:                    { id: 'T1556.006', name: 'Multi-Factor Authentication', tactic: 'Defense Evasion' },
  ADMIN_TOOL_ABUSE:          { id: 'T1059.009', name: 'Cloud API',                   tactic: 'Execution' },
  SERVICE_PRINCIPAL_ANOMALY: { id: 'T1528',     name: 'Steal Application Token',     tactic: 'Credential Access' },
  CONCURRENT_SESSIONS:       { id: 'T1550',     name: 'Use Alternate Auth Material', tactic: 'Lateral Movement' },
  FIRST_SEEN_COUNTRY:        { id: 'T1078',     name: 'Valid Accounts',              tactic: 'Initial Access' },
  TIME_OF_DAY_ANOMALY:       { id: 'T1078',     name: 'Valid Accounts',              tactic: 'Initial Access' },
  RARE_APP_ACCESS:           { id: 'T1550.001', name: 'Application Access Token',    tactic: 'Lateral Movement' },
  CREDENTIAL_STUFFING:       { id: 'T1110.004', name: 'Credential Stuffing',          tactic: 'Credential Access' },
  DEVICE_FINGERPRINT_ANOMALY:{ id: 'T1078.004', name: 'Cloud Accounts',               tactic: 'Initial Access' },
  OAUTH_CONSENT_PHISHING:    { id: 'T1528',     name: 'Steal Application Access Token', tactic: 'Credential Access' },
  DISTRIBUTED_BRUTE_FORCE:   { id: 'T1110.001', name: 'Password Guessing',              tactic: 'Credential Access' },
  MFA_METHOD_DOWNGRADE:      { id: 'T1556.006', name: 'Multi-Factor Authentication',    tactic: 'Defense Evasion' },
};

function getMitreTag(type) {
  const m = MITRE_MAP[type];
  if (!m) return '';
  return `<a class="mitre-badge" href="https://attack.mitre.org/techniques/${m.id.replace('.', '/')}/" target="_blank" rel="noopener"
    onclick="event.stopPropagation()" title="${escHtml(m.name)} — ${escHtml(m.tactic)}">
    ATT&amp;CK ${escHtml(m.id)}
  </a>`;
}

function getTriageKey(det) {
  const who = det.user || det.ip || (det.affectedUsers && det.affectedUsers[0]) || '';
  return `${det.type}:${who}`;
}

async function setTriage(key, status) {
  const wsId = state.activeWorkspace?.id;
  if (!wsId) return;
  try {
    const result = await api('POST', `/api/workspaces/${wsId}/triage`, { key, status });
    state.triages = result.triages || {};
    rerenderDetections();
  } catch(e) { toast('Failed to save triage', 'err'); }
}

function rerenderDetections() {
  const sec = document.getElementById('detections-section');
  if (!sec || !state.analysisData) return;
  sec.outerHTML = buildDetectionsSection(state.analysisData.detections || []);
}

function buildDetectionsSection(detections) {
  const nonFP = detections.filter(d => state.triages[getTriageKey(d)] !== 'FP');
  const fp    = detections.filter(d => state.triages[getTriageKey(d)] === 'FP');

  // Filter bar
  const q = (state.detectionsFilter || '').toLowerCase();
  const sf = state.detectionsSevFilter || 'all';
  let visible = nonFP;
  if (sf !== 'all') visible = visible.filter(d => d.severity === sf);
  if (q) visible = visible.filter(d =>
    (d.type + ' ' + (d.user || '') + ' ' + (d.ip || '') + ' ' + (d.message || '')).toLowerCase().includes(q)
  );

  // Pagination
  const totalPages = Math.max(1, Math.ceil(visible.length / state.detectionsPageSize));
  const page = Math.min(state.detectionsPage, totalPages);
  const start = (page - 1) * state.detectionsPageSize;
  const pageItems = visible.slice(start, start + state.detectionsPageSize);

  const fpHtml = fp.length > 0 ? `
    <div class="fp-suppressed" onclick="this.classList.toggle('open');this.querySelector('.fp-toggle-arrow').textContent=this.classList.contains('open')?'▾':'▸'">
      <span><span class="fp-toggle-arrow">▸</span> ${fp.length} False Positive${fp.length > 1 ? 's' : ''} suppressed — click to show</span>
      <div class="fp-suppressed-list">${fp.map(renderDetectionCard).join('')}</div>
    </div>` : '';

  const bulkBar = state.bulkSelected.size > 0 ? `
    <div class="bulk-action-bar">
      <span class="bulk-count">${state.bulkSelected.size} selected</span>
      <button class="bulk-btn bulk-tp"  onclick="bulkTriage('TP')"><i class="bi bi-check-lg"></i> Mark TP</button>
      <button class="bulk-btn bulk-fp"  onclick="bulkTriage('FP')"><i class="bi bi-x-lg"></i> Mark FP</button>
      <button class="bulk-btn bulk-inv" onclick="bulkTriage('INV')">? Investigating</button>
      <button class="bulk-btn bulk-clr" onclick="clearBulkSelection()"><i class="bi bi-x"></i> Clear</button>
    </div>` : '';

  const pagBar = totalPages > 1 ? `
    <div class="det-pagination">
      <button class="det-pg-btn" onclick="changeDetPage(-1)" ${page <= 1 ? 'disabled' : ''}>◀</button>
      <span class="det-pg-info">Page ${page} / ${totalPages} <span style="color:var(--text3)"> · ${visible.length} results</span></span>
      <button class="det-pg-btn" onclick="changeDetPage(1)" ${page >= totalPages ? 'disabled' : ''}>▶</button>
    </div>` : '';

  const filterBar = `
    <div class="det-filter-bar">
      <input class="det-filter-input" type="text" placeholder="Filter by type, user, IP, message…"
        value="${escHtml(state.detectionsFilter || '')}"
        oninput="filterDetections(this.value)" />
      <select class="det-sev-select" onchange="filterDetectionsSev(this.value)">
        <option value="all"   ${sf==='all'    ?'selected':''}>All severities</option>
        <option value="high"  ${sf==='high'   ?'selected':''}>High</option>
        <option value="medium"${sf==='medium' ?'selected':''}>Medium</option>
        <option value="low"   ${sf==='low'    ?'selected':''}>Low</option>
      </select>
    </div>`;

  return `<div id="detections-section">
    <div class="section-heading" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <i class="bi bi-search"></i> Detections
      <span class="count-badge">${detections.length}</span>
      ${nonFP.length !== detections.length ? `<span style="font-size:11px;color:var(--text3)">(${nonFP.length} active)</span>` : ''}
      ${detections.length > 0 ? `<button class="btn-ioc-export" onclick="exportIOC()" title="Export IPs, users & countries as CSV for SIEM / firewall"><i class="bi bi-download"></i> Export IOC</button>` : ''}
    </div>
    ${detections.length >= 2 ? renderCampaigns(detections) : ''}
    ${filterBar}
    ${bulkBar}
    ${pagBar}
    ${visible.length === 0 && fp.length === 0 && !q && sf === 'all'
      ? '<div class="empty">No detections triggered — all clear.</div>'
      : visible.length === 0
        ? `<div class="empty">No detections match the current filter.</div>`
        : pageItems.map(renderDetectionCard).join('')}
    ${pagBar}
    ${fpHtml}
  </div>`;
}

function filterDetections(val) {
  state.detectionsFilter = val;
  state.detectionsPage = 1;
  rerenderDetections();
}

function filterDetectionsSev(val) {
  state.detectionsSevFilter = val;
  state.detectionsPage = 1;
  rerenderDetections();
}

function changeDetPage(delta) {
  state.detectionsPage += delta;
  rerenderDetections();
  document.getElementById('detections-section')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

/* ── Attack Campaign Grouping ────────────────────────────────────────────── */
function groupIntoCampaigns(detections) {
  if (!detections.length) return [];
  const n = detections.length;
  const par = Array.from({length: n}, (_, i) => i);
  const find = i => par[i] === i ? i : (par[i] = find(par[i]));
  const union = (i, j) => { par[find(i)] = find(j); };

  // Link by shared source IP
  const byIP = {};
  for (let i = 0; i < n; i++) {
    const ip = detections[i].ip;
    if (!ip) continue;
    if (byIP[ip] !== undefined) union(i, byIP[ip]);
    else byIP[ip] = i;
  }
  // Link by shared target user
  const byUser = {};
  for (let i = 0; i < n; i++) {
    const users = new Set([detections[i].user, ...(detections[i].affectedUsers || [])].filter(Boolean));
    for (const u of users) {
      if (byUser[u] !== undefined) union(i, byUser[u]);
      else byUser[u] = i;
    }
  }
  // Gather groups with ≥2 detections
  const groups = {};
  for (let i = 0; i < n; i++) { const r = find(i); (groups[r] = groups[r] || []).push(detections[i]); }
  const sevW = { critical: 4, high: 3, medium: 2, low: 1 };
  const maxSev = g => Math.max(...g.map(d => sevW[d.severity?.toLowerCase()] || 0));
  return Object.values(groups)
    .filter(g => g.length >= 2)
    .sort((a, b) => maxSev(b) - maxSev(a) || b.length - a.length);
}

function renderCampaigns(detections) {
  const campaigns = groupIntoCampaigns(detections.filter(d => state.triages[getTriageKey(d)] !== 'FP'));
  if (!campaigns.length) return '';

  const cards = campaigns.map((group, idx) => {
    const types    = [...new Set(group.map(d => d.type.replace(/_/g,' ')))];
    const ips      = [...new Set(group.map(d => d.ip).filter(Boolean))];
    const users    = new Set(group.flatMap(d => [d.user, ...(d.affectedUsers||[])].filter(Boolean)));
    const countries= [...new Set(group.map(d => d.country).filter(Boolean))];
    const topSev   = group.some(d => d.severity === 'critical') ? 'critical' : group.some(d => d.severity === 'high') ? 'high' : 'medium';
    const sevColor = { critical:'#ef4444', high:'#f97316', medium:'#f59e0b' }[topSev];
    const sevBg    = { critical:'rgba(209,52,56,0.08)', high:'rgba(249,115,22,0.07)', medium:'rgba(245,158,11,0.06)' }[topSev];
    const sevBorder= { critical:'rgba(209,52,56,0.25)', high:'rgba(249,115,22,0.22)', medium:'rgba(245,158,11,0.2)' }[topSev];

    return `
      <div class="campaign-card" style="background:${sevBg};border:1px solid ${sevBorder}">
        <div class="campaign-header">
          <span class="campaign-num" style="color:${sevColor}"><i class="bi bi-lightning-charge-fill"></i> Campaign #${idx+1}</span>
          <div class="campaign-meta">
            <span class="campaign-stat"><i class="bi bi-search"></i> ${group.length} detections</span>
            ${users.size ? `<span class="campaign-stat"><i class="bi bi-person-fill"></i> ${users.size} user${users.size>1?'s':''}</span>` : ''}
            ${ips.length  ? `<span class="campaign-stat"><i class="bi bi-broadcast"></i> ${ips.length} IP${ips.length>1?'s':''}: ${ips.slice(0,2).map(escHtml).join(', ')}${ips.length>2?'…':''}</span>` : ''}
            ${countries.length ? `<span class="campaign-stat"><i class="bi bi-geo-alt-fill"></i> ${countries.slice(0,3).join(', ')}${countries.length>3?'…':''}</span>` : ''}
          </div>
        </div>
        <div class="campaign-types">
          ${types.slice(0,5).map(t=>`<span class="campaign-type-tag">${t}</span>`).join('')}
          ${types.length>5?`<span class="campaign-type-tag">+${types.length-5} more</span>`:''}
        </div>
      </div>`;
  }).join('');

  return `
    <div style="margin-bottom:14px">
      <div class="section-heading" style="margin-bottom:8px"><i class="bi bi-lightning-charge-fill"></i> Attack Campaigns <span class="count-badge">${campaigns.length}</span> <span style="font-size:11px;color:var(--text3);font-weight:400;margin-left:4px">— correlated detections dari IP / user yang sama</span></div>
      ${cards}
    </div>
    <div style="height:1px;background:var(--border);margin-bottom:16px"></div>`;
}

/* ── IOC Export ───────────────────────────────────────────────────────────── */
function exportIOC() {
  const data = state.analysisData;
  if (!data) return;

  const detections = (data.detections || []).filter(d => state.triages[getTriageKey(d)] !== 'FP');
  const sevNum = { critical: 4, high: 3, medium: 2, low: 1 };
  const iocs = { IP: {}, USER: {}, COUNTRY: {} };

  const add = (type, val, det) => {
    if (!val) return;
    val = String(val).trim();
    if (!val || val === 'null' || val === 'undefined') return;
    if (!iocs[type][val]) iocs[type][val] = { types: new Set(), sev: 0, sevLabel: 'LOW' };
    iocs[type][val].types.add(det.type);
    const n = sevNum[det.severity?.toLowerCase()] || 0;
    if (n > iocs[type][val].sev) { iocs[type][val].sev = n; iocs[type][val].sevLabel = (det.severity || 'LOW').toUpperCase(); }
  };

  for (const d of detections) {
    if (d.ip) add('IP', d.ip, d);
    (d.uniqueIPs || d.ips || []).forEach(ip => add('IP', ip, d));
    if (d.user) add('USER', d.user, d);
    (d.affectedUsers || []).forEach(u => add('USER', u, d));
    if (d.country && !d.user) add('COUNTRY', d.country, d);
  }

  const rows = [['IOC_TYPE', 'VALUE', 'SEVERITY', 'DETECTION_TYPES', 'DETECTION_COUNT', 'WORKSPACE', 'EXPORTED_AT']];
  const ws = state.activeWorkspace?.name || '';
  const ts = new Date().toISOString();

  for (const [type, map] of Object.entries(iocs)) {
    Object.entries(map)
      .sort((a, b) => b[1].sev - a[1].sev || a[0].localeCompare(b[0]))
      .forEach(([val, info]) => {
        rows.push([type, val, info.sevLabel, [...info.types].join('|'), info.types.size, ws, ts]);
      });
  }

  if (rows.length <= 1) { toast('No IOCs to export', 'warn'); return; }

  const csv = rows.map(r => r.map(c => {
    const s = String(c);
    return /[,"\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }).join(',')).join('\r\n');

  const fname = `EIDSA_IOC_${(ws || 'export').replace(/\W+/g,'_')}_${ts.slice(0,10)}.csv`;
  const a = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' })),
    download: fname,
  });
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  toast(`<i class="bi bi-check-circle-fill"></i> Exported ${rows.length - 1} IOC indicators → ${fname}`, 'ok');
}

function matchesKillChainFilter(det) {
  const f = state.killChainFilter;
  if (!f) return null;
  const mitre = MITRE_MAP[det.type];
  const tacticMatch = mitre && mitre.tactic === f.tactic;
  const users = new Set();
  if (det.user) users.add(det.user);
  if (det.affectedUsers) det.affectedUsers.forEach(u => users.add(u));
  if (det.ip && !det.user) users.add(`<i class="bi bi-broadcast"></i> ${det.ip}`);
  return tacticMatch && users.has(f.user);
}

function buildDetectionExplainer(det) {
  const TRIGGER = {
    PASSWORD_SPRAY:            d => `${d.userCount || d.affectedUsers?.length || '?'} accounts received failed logins from the same source within a short window — classic password spray: one password tried against many accounts to stay under lockout thresholds.`,
    BRUTE_FORCE:               d => `${d.attemptCount || '?'} failed login attempts for ${d.user ? d.user.split('@')[0] : 'this user'} — exceeds the brute force threshold. Attacker is guessing passwords for a single account.`,
    IMPOSSIBLE_TRAVEL:         d => `Login from ${d.from?.country || '?'} at ${d.from?.time ? formatDate(d.from.time) : '?'}, then from ${d.to?.country || '?'} at ${d.to?.time ? formatDate(d.to.time) : '?'}. The physical distance cannot be covered in the elapsed time — at least one login is suspicious.`,
    MFA_EXHAUSTION:            d => `${d.promptCount || d.attemptCount || '?'} consecutive MFA push notifications sent to ${d.user ? d.user.split('@')[0] : 'this user'}. Attacker already has the password and is flooding the user hoping for an accidental approval.`,
    ADMIN_TOOL_ABUSE:          d => `Admin/privileged application (${d.appName || d.app || '?'}) accessed from a foreign IP or country. Legitimate admin sessions rarely originate outside the home country.`,
    TOKEN_REPLAY:              d => `The same authentication token was used from multiple distinct IP addresses. A valid token was likely stolen and replayed from a different machine.`,
    CONCURRENT_SESSIONS:       d => `Active sessions detected from ${(d.uniqueIPs || []).length || d.ipCount || 'multiple'} different IPs at the same time. A single user cannot authenticate from multiple locations simultaneously.`,
    SERVICE_PRINCIPAL_ANOMALY: d => `Service principal signed in from an IP or location not previously seen for this application. May indicate compromised service account credentials or a new unauthorized app registration.`,
    LEGACY_AUTH:               d => `Authentication via a legacy protocol that bypasses modern Conditional Access policies. Legacy auth cannot enforce MFA, making it a common attacker entry point.`,
    CREDENTIAL_STUFFING:       d => `Multiple users targeted from distributed IPs using known breach credentials. Low per-IP attempt count combined with high breadth matches automated credential stuffing toolkits.`,
    DISTRIBUTED_BRUTE_FORCE:   d => `Brute force attack spread across ${(d.uniqueIPs || []).length || '?'} IPs to evade per-IP lockout policies. Rotating IP addresses while attacking the same target account.`,
    MFA_METHOD_DOWNGRADE:      d => `Attacker attempted to fall back to a weaker MFA method after the stronger method was challenged — a targeted MFA bypass technique.`,
    OAUTH_CONSENT_PHISHING:    d => `OAuth consent request from an unfamiliar application attempting to access tenant data. User may have been tricked into granting delegated permissions to a malicious third-party app.`,
    ENUMERATION_ATTACK:        d => `${d.userCount || '?'} username probes detected. Attacker observes different error codes for valid vs. invalid accounts to build a list of existing users before launching a targeted attack.`,
    FIRST_SEEN_COUNTRY:        d => `Login from ${d.country || '?'} — this country has not appeared for this account in the entire analyzed log history.`,
    TIME_OF_DAY_ANOMALY:       d => `Login at an unusual hour outside this account's normal activity pattern — may indicate a different timezone (foreign attacker) or automated tooling.`,
    RARE_APP_ACCESS:           d => `${d.user ? d.user.split('@')[0] : 'This user'} accessed ${d.appName || 'an application'} that they have never or rarely used. A compromised account often explores available resources.`,
    CA_GAP:                    d => `Successful authentication completed without any Conditional Access policy being enforced. This login bypassed MFA and device compliance checks entirely.`,
  };

  const explain = TRIGGER[det.type];
  const text = explain ? explain(det) : (det.message || 'No additional detail available.');

  const evid = [];
  if (det.windowStart && det.windowEnd)
    evid.push({ i: '<i class="bi bi-clock"></i>', l: 'Window', v: `${formatDate(det.windowStart)} → ${formatDate(det.windowEnd)}` });
  else if (det.time)
    evid.push({ i: '<i class="bi bi-clock"></i>', l: 'Time', v: formatDate(det.time) });
  if (det.ip)        evid.push({ i: '<i class="bi bi-broadcast"></i>', l: 'IP', v: det.ip });
  if (det.country)   evid.push({ i: '<i class="bi bi-geo-alt-fill"></i>', l: 'Country', v: det.country });
  const uc = det.userCount || det.affectedUsers?.length;
  if (uc)            evid.push({ i: '<i class="bi bi-people-fill"></i>', l: 'Users', v: uc });
  if (det.attemptCount) evid.push({ i: '<i class="bi bi-arrow-repeat"></i>', l: 'Attempts', v: det.attemptCount });
  if (det.promptCount)  evid.push({ i: '<i class="bi bi-phone-fill"></i>', l: 'MFA prompts', v: det.promptCount });
  const ipc = (det.uniqueIPs || []).length || det.ipCount;
  if (ipc)           evid.push({ i: '<i class="bi bi-globe2"></i>', l: 'Unique IPs', v: ipc });

  const evidHtml = evid.length ? `<div class="explainer-evidence">${
    evid.map(e => `<div class="ev-chip"><span class="ev-icon">${e.i}</span><span class="ev-label">${escHtml(String(e.l))}</span><span class="ev-val">${escHtml(String(e.v))}</span></div>`).join('')
  }</div>` : '';

  const m = MITRE_MAP[det.type];
  const mitreHtml = m ? `<div class="explainer-mitre">
    <span class="explainer-mitre-tag">MITRE ${escHtml(m.id)}</span>
    <span class="explainer-mitre-name">${escHtml(m.name)}</span>
    <span style="color:var(--text3);font-size:10px">· ${escHtml(m.tactic)}</span>
  </div>` : '';

  return `<div class="det-explainer">
    <div class="explainer-title"><i class="bi bi-lightning-charge-fill"></i> Why did this fire?</div>
    <div class="explainer-text">${escHtml(text)}</div>
    ${evidHtml}${mitreHtml}
  </div>
  <details class="det-raw-toggle"><summary>Raw JSON</summary><pre>${escHtml(JSON.stringify(det, null, 2))}</pre></details>`;
}

function renderDetectionCard(det) {
  const id     = `det-${Math.random().toString(36).slice(2)}`;
  const hasUser = det.user;
  const mitre   = getMitreTag(det.type);
  const key     = getTriageKey(det);
  const status  = state.triages[key] || '';
  const kcMatch = matchesKillChainFilter(det);
  const kcClass = kcMatch === true ? ' kc-highlight' : kcMatch === false ? ' kc-dim' : '';
  const isBulkSel = state.bulkSelected.has(key);
  const existingComment = state.detectionComments[key] || '';
  const commentId = `dc-${id}`;

  const triageBtns = `
    <div class="triage-btns" onclick="event.stopPropagation()">
      <button class="triage-btn tp${status === 'TP' ? ' active' : ''}" title="Mark True Positive"
        onclick="setTriage('${escHtml(key)}', '${status === 'TP' ? '' : 'TP'}')">TP</button>
      <button class="triage-btn fp${status === 'FP' ? ' active' : ''}" title="Mark False Positive — suppresses this detection"
        onclick="setTriage('${escHtml(key)}', '${status === 'FP' ? '' : 'FP'}')">FP</button>
      <button class="triage-btn inv${status === 'INV' ? ' active' : ''}" title="Mark as Investigating"
        onclick="setTriage('${escHtml(key)}', '${status === 'INV' ? '' : 'INV'}')">?</button>
    </div>`;

  const iocChips = (() => {
    const chips = [];
    if (det.ip) chips.push(`<span class="ioc-chip" onclick="event.stopPropagation();copyIOC('${escHtml(det.ip)}',this)" title="Copy IP"><i class="bi bi-broadcast"></i> ${escHtml(det.ip)}</span>`);
    if (det.user) chips.push(`<span class="ioc-chip" onclick="event.stopPropagation();copyIOC('${escHtml(det.user)}',this)" title="Copy user"><i class="bi bi-person-fill"></i> ${escHtml(det.user)}</span>`);
    if (det.country && !det.user) chips.push(`<span class="ioc-chip" onclick="event.stopPropagation();copyIOC('${escHtml(det.country)}',this)" title="Copy country"><i class="bi bi-geo-alt-fill"></i> ${escHtml(det.country)}</span>`);
    const extraIPs = (det.uniqueIPs || det.ips || []).filter(ip => ip !== det.ip).slice(0, 3);
    extraIPs.forEach(ip => chips.push(`<span class="ioc-chip" onclick="event.stopPropagation();copyIOC('${escHtml(ip)}',this)" title="Copy IP"><i class="bi bi-broadcast"></i> ${escHtml(ip)}</span>`));
    return chips.length ? `<div class="det-ioc-row">${chips.join('')}</div>` : '';
  })();

  return `
    <div class="detection-card sev-${det.severity}${status === 'TP' ? ' triage-tp' : status === 'INV' ? ' triage-inv' : ''}${kcClass}" onclick="toggleDetDetail('${id}')">
      <div class="det-header">
        <label class="det-checkbox" onclick="event.stopPropagation()" title="Select for bulk triage">
          <input type="checkbox" ${isBulkSel ? 'checked' : ''} onchange="bulkToggle('${escHtml(key)}')">
        </label>
        <span class="det-badge badge-${det.severity}">${det.severity}</span>
        <span class="det-type">${det.type.replace(/_/g, ' ')}</span>
        ${mitre}
        ${hasUser ? `<button class="btn-secondary" style="font-size:11px;padding:2px 8px"
          onclick="event.stopPropagation();openTimeline('${escHtml(det.user)}')">Timeline</button>` : ''}
        <button class="btn-secondary kql-btn" style="font-size:11px;padding:2px 8px"
          onclick="event.stopPropagation();showKQLPanel(${JSON.stringify(JSON.stringify(det))})">KQL</button>
        ${triageBtns}
      </div>
      <div class="det-message">${escHtml(det.message)}</div>
      ${buildDetSparkline(det)}
      ${iocChips}
      <div class="det-comment-row" onclick="event.stopPropagation()">
        ${existingComment
          ? `<div class="det-comment-preview" onclick="toggleDetComment('${commentId}')"><i class="bi bi-chat-fill"></i> <em>${escHtml(existingComment.slice(0,90))}${existingComment.length > 90 ? '…' : ''}</em></div>`
          : `<button class="det-comment-add" onclick="toggleDetComment('${commentId}')">+ Add comment</button>`}
        <div class="det-comment-input" id="${commentId}">
          <textarea class="det-comment-textarea" id="dct-${id}" placeholder="Investigation notes, evidence, action taken…" rows="2">${escHtml(existingComment)}</textarea>
          <div class="det-comment-actions">
            <button class="btn-primary" style="font-size:11px;padding:3px 10px" onclick="saveDetectionComment('${escHtml(key)}','dct-${id}')">Save</button>
            <button class="btn-secondary" style="font-size:11px;padding:3px 10px" onclick="toggleDetComment('${commentId}')">Cancel</button>
          </div>
        </div>
      </div>
      <div class="det-details" id="${id}">
        ${buildDetectionExplainer(det)}
      </div>
    </div>`;
}

function toggleDetDetail(id) {
  document.getElementById(id).classList.toggle('open');
}

/* ── Events table ─────────────────────────────────────────────────────────── */
function renderEventsTable(allEvents) {
  const q = state.eventsFilter.toLowerCase();
  const homeCountry = (state.analysisData?.homeCountry || 'ID').toUpperCase();

  let filtered = allEvents.filter(e => {
    if (state.eventsStatusFilter === 'success' && !e.success) return false;
    if (state.eventsStatusFilter === 'fail' && e.success) return false;
    if (state.dateFrom && e.createdAt < state.dateFrom) return false;
    if (state.dateTo   && e.createdAt.slice(0,10) > state.dateTo) return false;
    if (!q) return true;
    return (e.userPrincipal + e.ipAddress + e.country + e.appName + e.city + e.appType)
      .toLowerCase().includes(q);
  });

  const { col, dir } = state.eventsSort;
  filtered = filtered.sort((a, b) => {
    const av = a[col] ?? '';
    const bv = b[col] ?? '';
    if (av < bv) return dir === 'asc' ? -1 : 1;
    if (av > bv) return dir === 'asc' ? 1 : -1;
    return 0;
  });

  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / state.eventsPageSize));
  state.eventsPage = Math.min(state.eventsPage, pages);
  const start = (state.eventsPage - 1) * state.eventsPageSize;
  const pageEvents = filtered.slice(start, start + state.eventsPageSize);

  const th = (label, col) => {
    const arrow = state.eventsSort.col === col ? (state.eventsSort.dir === 'asc' ? ' ↑' : ' ↓') : '';
    return `<th onclick="sortEvents('${col}')">${label}${arrow}</th>`;
  };

  const rows = pageEvents.map(e => {
    const isForeign = e.country && e.country.toUpperCase() !== homeCountry;
    const rowClass = isForeign && e.success ? ' style="background:rgba(251,191,36,0.04)"' : '';
    const appTypeClass = `apptype apptype-${(e.appType || 'Other').replace(/[\/ ]/g, '')}`;
    return `
      <tr${rowClass} onclick="openTimeline('${escHtml(e.userPrincipal)}')" style="cursor:pointer">
        <td>${formatDate(e.createdAt)}</td>
        <td title="${escHtml(e.userPrincipal)}">${escHtml(e.displayName || e.userPrincipal)}</td>
        <td>${e.success ? '<span class="status-ok"><i class="bi bi-check-lg"></i></span>' : '<span class="status-fail"><i class="bi bi-x-lg"></i></span>'}</td>
        <td>${renderIPClickable(e.ipAddress)}</td>
        <td>${isForeign ? '<i class="bi bi-exclamation-triangle"></i> ' : ''}${escHtml(e.country)}${e.city ? ` / ${escHtml(e.city)}` : ''}</td>
        <td><span class="${appTypeClass}">${escHtml(e.appType || 'Other')}</span></td>
        <td title="${escHtml(e.appName)}">${escHtml(e.appName).slice(0, 28)}</td>
        <td title="${escHtml(e.failureReason)}">${e.errorCode !== null && e.errorCode !== 0 ? e.errorCode : ''}</td>
      </tr>`;
  }).join('');

  const totalAvailable = state.analysisData?.total || allEvents.length;
  const loadedCount = allEvents.length;
  const stillLoading = state.analysisData?.eventsLimited && loadedCount < totalAvailable;
  const loadingBar = stillLoading
    ? `<div id="events-load-progress" style="font-size:12px;color:var(--text2);padding:4px 0 2px;display:flex;align-items:center;gap:8px">
        <span class="spinner" style="width:12px;height:12px;border-width:2px"></span>
        Loading events… ${loadedCount.toLocaleString()} / ${totalAvailable.toLocaleString()} loaded
       </div>`
    : `<div id="events-load-progress" style="display:none"></div>`;

  return `
    ${loadingBar}
    <div class="events-filter">
      <input type="text" placeholder="Search user, IP, country, app…" value="${escHtml(state.eventsFilter)}"
        oninput="filterEvents(this.value)" />
      <select onchange="filterStatus(this.value)">
        <option value="all"     ${state.eventsStatusFilter === 'all'     ? 'selected' : ''}>All</option>
        <option value="success" ${state.eventsStatusFilter === 'success' ? 'selected' : ''}>Success only</option>
        <option value="fail"    ${state.eventsStatusFilter === 'fail'    ? 'selected' : ''}>Failed only</option>
      </select>
      <div class="date-filter">
        <span>From</span>
        <input type="date" value="${escHtml(state.dateFrom)}" onchange="filterDateFrom(this.value)" />
        <span>To</span>
        <input type="date" value="${escHtml(state.dateTo)}" onchange="filterDateTo(this.value)" />
        ${state.dateFrom || state.dateTo ? `<button class="btn-secondary" style="font-size:11px;padding:3px 8px" onclick="clearDateFilter()"><i class="bi bi-x"></i> Clear</button>` : ''}
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          ${th('Time', 'createdAt')}
          ${th('User', 'displayName')}
          ${th('Status', 'success')}
          ${th('IP', 'ipAddress')}
          ${th('Location', 'country')}
          ${th('Type', 'appType')}
          ${th('App', 'appName')}
          ${th('Error', 'errorCode')}
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="8" class="empty">No events match filter.</td></tr>'}</tbody>
      </table>
    </div>
    <div class="pagination">
      <button onclick="changePage(-1)" ${state.eventsPage === 1 ? 'disabled' : ''}>← Prev</button>
      <span>Page ${state.eventsPage} of ${pages} (${total.toLocaleString()} shown${stillLoading ? ` · ${totalAvailable.toLocaleString()} total` : ''} — click row for timeline)</span>
      <button onclick="changePage(1)" ${state.eventsPage === pages ? 'disabled' : ''}>Next →</button>
    </div>`;
}

function filterEvents(val) { state.eventsFilter = val; state.eventsPage = 1; rerenderTable(); }
function filterStatus(val) { state.eventsStatusFilter = val; state.eventsPage = 1; rerenderTable(); }
function filterDateFrom(val) { state.dateFrom = val; state.eventsPage = 1; rerenderTable(); }
function filterDateTo(val)   { state.dateTo   = val; state.eventsPage = 1; rerenderTable(); }
function clearDateFilter()   { state.dateFrom = ''; state.dateTo = ''; state.eventsPage = 1; rerenderTable(); }

function sortEvents(col) {
  if (state.eventsSort.col === col) {
    state.eventsSort.dir = state.eventsSort.dir === 'asc' ? 'desc' : 'asc';
  } else {
    state.eventsSort = { col, dir: 'asc' };
  }
  rerenderTable();
}

function changePage(delta) { state.eventsPage += delta; rerenderTable(); }

function rerenderTable() {
  const panel = document.getElementById('tab-events');
  if (!panel || !state.analysisData) return;
  panel.innerHTML = renderEventsTable(state.analysisData.events);
}

/* ── GeoIP Map (Leaflet) ──────────────────────────────────────────────────── */
// Country centroid coords (subset — same as server-side)
const COUNTRY_COORDS = {
  ID:[-2.5,118.0], US:[37.1,-95.7], CN:[35.0,105.0], RU:[61.5,105.3],
  IN:[20.6,78.9],  SG:[1.3,103.8],  AU:[-25.3,133.8],GB:[55.4,-3.4],
  NL:[52.1,5.3],   DE:[51.2,10.5],  FR:[46.2,2.2],   JP:[36.2,138.3],
  KR:[35.9,127.8], BR:[-14.2,-51.9],CA:[56.1,-106.3], MY:[4.2,109.5],
  PH:[12.9,121.8], TH:[15.9,100.9], VN:[14.1,108.3],  NG:[9.1,8.7],
  PK:[30.4,69.3],  BD:[23.7,90.4],  UA:[48.4,31.2],   TR:[38.9,35.2],
  IR:[32.4,53.7],  HK:[22.3,114.2], TW:[23.7,121.0],  SA:[23.9,45.1],
  AE:[23.4,53.8],  EG:[26.8,30.8],  ZA:[-30.6,22.9],  MX:[23.6,-102.6],
  AR:[-38.4,-63.6],IT:[41.9,12.6],  ES:[40.5,-3.7],   PL:[51.9,19.1],
  CZ:[49.8,15.5],  RO:[45.9,24.9],  SE:[60.1,18.6],   NO:[60.5,8.5],
  FI:[61.9,25.7],  DK:[56.3,9.5],   CH:[46.8,8.2],    AT:[47.5,14.6],
  BE:[50.5,4.5],   PT:[39.4,-8.2],  GR:[39.1,21.8],   NZ:[-40.9,174.9],
  IL:[31.0,34.9],  CL:[-35.7,-71.5],CO:[4.6,-74.1],   PE:[-9.2,-75.0],
};

function initMap() {
  const container = document.getElementById('map-container');
  if (!container) return;
  if (state.leafletMap) return; // already initialized

  const data = state.analysisData;
  if (!data) return;

  const homeCountry = (data.homeCountry || 'ID').toUpperCase();
  const geoSummary = data.geoSummary || {};

  const map = L.map('map-container', {
    center: [10, 20],
    zoom: 2,
    minZoom: 1,
    maxZoom: 8,
  });

  state.leafletMap = map;

  L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    attribution: '© OpenStreetMap, © CARTO',
    subdomains: 'abcd',
    maxZoom: 19
  }).addTo(map);

  for (const [country, stats] of Object.entries(geoSummary)) {
    const coords = COUNTRY_COORDS[country.toUpperCase()];
    if (!coords) continue;

    const isHome = country.toUpperCase() === homeCountry;
    const radius = Math.min(8 + Math.sqrt(stats.total) * 2.5, 40);
    const color  = isHome ? '#4f8ef7' : (stats.total > 10 ? '#f87171' : '#fbbf24');
    const fillOpacity = isHome ? 0.4 : 0.6;

    L.circleMarker(coords, {
      radius,
      color,
      fillColor: color,
      fillOpacity,
      weight: 1.5,
    }).addTo(map).bindPopup(`
      <b>${country}</b>${isHome ? ' <i class="bi bi-house-fill"></i> Home' : ' <i class="bi bi-exclamation-triangle"></i> Foreign'}<br>
      Total: ${stats.total}<br>
      Successful: ${stats.success}<br>
      Failed: ${stats.total - stats.success}
    `);
  }

  // Fit to markers if any
  const points = Object.keys(geoSummary)
    .map(c => COUNTRY_COORDS[c.toUpperCase()])
    .filter(Boolean);
  if (points.length > 0) {
    map.fitBounds(L.latLngBounds(points), { padding: [30, 30], maxZoom: 5 });
  }
}

/* ── Charts ───────────────────────────────────────────────────────────────── */
function destroyCharts() {
  Object.values(state.chartInstances).forEach(c => { try { c.destroy(); } catch(e) {} });
  state.chartInstances = {};
}

function initCharts() {
  const container = document.getElementById('charts-container');
  if (!container || !state.analysisData) return;

  destroyCharts();

  const data        = state.analysisData;
  const events      = data.events || [];
  const homeCountry = (data.homeCountry || 'ID').toUpperCase();

  // ── Data: events over time (daily) ──────────────────────────────────────
  const byDay = {};
  for (const e of events) {
    const day = e.createdAt?.slice(0, 10);
    if (!day) continue;
    if (!byDay[day]) byDay[day] = { success: 0, fail: 0 };
    if (e.success) byDay[day].success++; else byDay[day].fail++;
  }
  const days       = Object.keys(byDay).sort();
  const daySuccess = days.map(d => byDay[d].success);
  const dayFail    = days.map(d => byDay[d].fail);
  const dayLabels  = days.map(d => { const dt = new Date(d); return dt.toLocaleDateString('en-GB',{day:'numeric',month:'short'}); });

  // ── Data: top 10 attacking countries ────────────────────────────────────
  const ctryCounts = {};
  for (const e of events) {
    if (!e.country || e.country.toUpperCase() === homeCountry) continue;
    ctryCounts[e.country] = (ctryCounts[e.country] || 0) + 1;
  }
  const topCtry = Object.entries(ctryCounts).sort((a,b)=>b[1]-a[1]).slice(0,10);

  // ── Data: error code breakdown ───────────────────────────────────────────
  const errLabels = { 50126:'Invalid password', 50053:'Account locked', 50076:'MFA required', 50057:'Disabled', 50074:'MFA needed', 500121:'Strong auth failed', 53003:'Conditional Access' };
  const errCounts = {};
  for (const e of events) {
    if (e.success || !e.errorCode) continue;
    const label = errLabels[e.errorCode] || `Error ${e.errorCode}`;
    errCounts[label] = (errCounts[label] || 0) + 1;
  }
  const topErr = Object.entries(errCounts).sort((a,b)=>b[1]-a[1]).slice(0,6);

  // ── Data: app type distribution ──────────────────────────────────────────
  const appTypeCounts = {};
  for (const e of events) {
    const t = e.appType || 'Other';
    appTypeCounts[t] = (appTypeCounts[t] || 0) + 1;
  }

  const PALETTE = ['#5b8def','#f16060','#f5a623','#2ec99a','#a78bfa','#fb923c','#34d399','#60a5fa'];
  const chartDefaults = {
    responsive: true, maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#7a88a4', font: { size: 11 } } } },
  };

  container.innerHTML = `
    <div class="charts-grid">
      <div class="chart-card" style="grid-column:1/-1">
        <div class="chart-card-title">Events Over Time</div>
        <div class="chart-wrap"><canvas id="chart-timeline"></canvas></div>
      </div>
      <div class="chart-card">
        <div class="chart-card-title">Top Attacking Countries</div>
        <div class="chart-wrap"><canvas id="chart-countries"></canvas></div>
      </div>
      <div class="chart-card">
        <div class="chart-card-title">Error Code Breakdown</div>
        <div class="chart-wrap"><canvas id="chart-errors"></canvas></div>
      </div>
      <div class="chart-card">
        <div class="chart-card-title">App Type Distribution</div>
        <div class="chart-wrap"><canvas id="chart-apptypes"></canvas></div>
      </div>
    </div>`;

  // Events over time
  state.chartInstances.timeline = new Chart(document.getElementById('chart-timeline'), {
    type: 'bar',
    data: {
      labels: dayLabels,
      datasets: [
        { label: 'Success', data: daySuccess, backgroundColor: 'rgba(46,201,154,0.7)', borderRadius: 3 },
        { label: 'Failed',  data: dayFail,    backgroundColor: 'rgba(241,96,96,0.7)',  borderRadius: 3 },
      ]
    },
    options: { ...chartDefaults, scales: {
      x: { stacked: true, ticks: { color: '#7a88a4', maxRotation: 45, font: { size: 10 } }, grid: { color: '#1d2438' } },
      y: { stacked: true, ticks: { color: '#7a88a4', font: { size: 10 } }, grid: { color: '#1d2438' } },
    }},
  });

  // Top attacking countries
  state.chartInstances.countries = new Chart(document.getElementById('chart-countries'), {
    type: 'bar',
    data: {
      labels: topCtry.map(([c]) => c),
      datasets: [{ label: 'Events', data: topCtry.map(([,n]) => n), backgroundColor: PALETTE, borderRadius: 3 }],
    },
    options: { ...chartDefaults, indexAxis: 'y',
      scales: {
        x: { ticks: { color: '#7a88a4', font: { size: 10 } }, grid: { color: '#1d2438' } },
        y: { ticks: { color: '#e4eaf6', font: { size: 11 } }, grid: { display: false } },
      },
      plugins: { legend: { display: false } },
    },
  });

  // Error codes
  if (topErr.length > 0) {
    state.chartInstances.errors = new Chart(document.getElementById('chart-errors'), {
      type: 'doughnut',
      data: {
        labels: topErr.map(([l]) => l),
        datasets: [{ data: topErr.map(([,n]) => n), backgroundColor: PALETTE, borderWidth: 2, borderColor: '#111520' }],
      },
      options: { ...chartDefaults, cutout: '60%' },
    });
  } else {
    document.getElementById('chart-errors').parentElement.innerHTML += '<div style="text-align:center;color:var(--text3);padding-top:60px;font-size:12px">No failed events with error codes</div>';
  }

  // App types
  const appTypeEntries = Object.entries(appTypeCounts);
  state.chartInstances.apptypes = new Chart(document.getElementById('chart-apptypes'), {
    type: 'doughnut',
    data: {
      labels: appTypeEntries.map(([t]) => t),
      datasets: [{ data: appTypeEntries.map(([,n]) => n), backgroundColor: PALETTE, borderWidth: 2, borderColor: '#111520' }],
    },
    options: { ...chartDefaults, cutout: '60%' },
  });

  // ── Heatmap (hour × day-of-week) ─────────────────────────────────────────
  const grid = document.querySelector('.charts-grid');
  if (grid) {
    const heatAllHTML  = buildHeatmapSVG(events, 'Login Heatmap — All Events', '#5b8def');
    const heatFailHTML = buildHeatmapSVG(events.filter(e => !e.success), 'Login Heatmap — Failed Attempts', '#f16060');
    const heatDiv = document.createElement('div');
    heatDiv.style.cssText = 'grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr;gap:14px';
    heatDiv.innerHTML = heatAllHTML + heatFailHTML;
    grid.appendChild(heatDiv);

    // ── ASN / ISP clustering ────────────────────────────────────────────────
    const asnHTML = buildASNSection(data.ipEnrichment || {}, events, homeCountry);
    if (asnHTML) {
      const asnDiv = document.createElement('div');
      asnDiv.style.cssText = 'grid-column:1/-1';
      asnDiv.innerHTML = asnHTML;
      grid.appendChild(asnDiv);
    }
  }
}

/* ── Kill Chain Coverage Matrix ──────────────────────────────────────────── */
function initKillChain() {
  const container = document.getElementById('killchain-container');
  if (!container || !state.analysisData) return;

  const detections = state.analysisData.detections || [];
  if (detections.length === 0) {
    container.innerHTML = '<div style="padding:48px;text-align:center;color:var(--text3);font-size:13px">No detections — Kill Chain matrix is empty.</div>';
    return;
  }

  const TACTICS = ['Initial Access', 'Credential Access', 'Persistence', 'Defense Evasion', 'Execution', 'Discovery', 'Lateral Movement'];
  const SEV_COLOR = { high: '#dc2626', medium: '#d97706', low: '#2563eb' };
  const SEV_BG    = { high: 'rgba(220,38,38,0.13)', medium: 'rgba(217,119,6,0.11)', low: 'rgba(37,99,235,0.11)' };

  // Build matrix: user -> tactic -> { count, sev, types }
  const matrix = {};
  for (const det of detections) {
    const mitre = MITRE_MAP[det.type];
    if (!mitre || !TACTICS.includes(mitre.tactic)) continue;
    const tactic = mitre.tactic;

    const users = new Set();
    if (det.user) users.add(det.user);
    if (det.affectedUsers) det.affectedUsers.slice(0, 8).forEach(u => users.add(u));
    if (users.size === 0 && det.ip) users.add(`[IP] ${det.ip}`);

    for (const user of users) {
      if (!matrix[user]) matrix[user] = {};
      if (!matrix[user][tactic]) matrix[user][tactic] = { count: 0, sev: 'low', types: [] };
      matrix[user][tactic].count++;
      matrix[user][tactic].types.push(det.type);
      if (det.severity === 'high') matrix[user][tactic].sev = 'high';
      else if (det.severity === 'medium' && matrix[user][tactic].sev !== 'high') matrix[user][tactic].sev = 'medium';
    }
  }

  const users = Object.keys(matrix).sort((a, b) => {
    const ca = Object.values(matrix[a]).reduce((s, v) => s + v.count, 0);
    const cb = Object.values(matrix[b]).reduce((s, v) => s + v.count, 0);
    return cb - ca;
  }).slice(0, 25);

  const f = state.killChainFilter;

  const headerCells = TACTICS.map(t => `<th class="kc-th">${t.replace(' ', '<br>')}</th>`).join('');

  const rows = users.map(user => {
    const display = user.length > 34 ? user.slice(0, 32) + '…' : user;
    const cells = TACTICS.map(tactic => {
      const cell = matrix[user]?.[tactic];
      if (!cell) return `<td class="kc-td kc-empty"></td>`;
      const sev = cell.sev;
      const isActive = f && f.user === user && f.tactic === tactic;
      const typeNames = [...new Set(cell.types)].map(t => t.replace(/_/g,' ')).join(', ');
      return `<td class="kc-td kc-hit${isActive ? ' kc-active-cell' : ''}"
        style="background:${SEV_BG[sev]};border-color:${SEV_COLOR[sev]}40"
        onclick="killChainCellClick(${JSON.stringify(user)},${JSON.stringify(tactic)})"
        title="${escHtml(typeNames)}">
        <div class="kc-count" style="color:${SEV_COLOR[sev]}">${cell.count}</div>
        <div class="kc-sev" style="color:${SEV_COLOR[sev]}">${sev.toUpperCase()}</div>
      </td>`;
    }).join('');
    const total = Object.values(matrix[user]).reduce((s, v) => s + v.count, 0);
    const isFilteredUser = f && f.user === user;
    return `<tr class="${isFilteredUser ? 'kc-row-active' : ''}">
      <td class="kc-user" title="${escHtml(user)}">${escHtml(display)}</td>
      ${cells}
      <td class="kc-total">${total}</td>
    </tr>`;
  }).join('');

  const filterBar = f ? `
    <div class="kc-filter-bar">
      Highlighting: <strong>${escHtml(f.user)}</strong> — <em>${escHtml(f.tactic)}</em>
      <button class="btn-secondary" style="font-size:11px;padding:2px 10px;margin-left:12px" onclick="clearKillChainFilter()"><i class="bi bi-x"></i> Clear</button>
    </div>` : '';

  container.innerHTML = `
    <div class="kc-wrap">
      <div class="kc-header-row">
        <div>
          <div class="section-title" style="margin-bottom:4px">MITRE ATT&amp;CK Kill Chain Coverage</div>
          <div style="font-size:12px;color:var(--text3)">Tactic coverage per user — click a cell to highlight matching detections</div>
        </div>
      </div>
      ${filterBar}
      <div class="kc-scroll">
        <table class="kc-table">
          <thead><tr>
            <th class="kc-th kc-th-user">User / Entity</th>
            ${headerCells}
            <th class="kc-th">Total</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`;
}

function killChainCellClick(user, tactic) {
  state.killChainFilter = { user, tactic };
  initKillChain();
  rerenderDetections();
  switchTab('detections');
}

function clearKillChainFilter() {
  state.killChainFilter = null;
  initKillChain();
  rerenderDetections();
}

/* ── Attack Velocity Timeline ─────────────────────────────────────────────── */
function initVelocity() {
  const container = document.getElementById('velocity-container');
  if (!container || !state.analysisData) return;

  const events      = state.analysisData.events || [];
  const homeCountry = (state.analysisData.homeCountry || 'ID').toUpperCase();

  // Top 5 foreign IPs by failed event count
  const ipCounts = {};
  for (const e of events) {
    if (!e.ipAddress || e.success) continue;
    if (e.country && e.country.toUpperCase() === homeCountry) continue;
    ipCounts[e.ipAddress] = (ipCounts[e.ipAddress] || 0) + 1;
  }
  const topIPs = Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([ip]) => ip);

  if (topIPs.length === 0) {
    container.innerHTML = '<div style="padding:48px;text-align:center;color:var(--text3);font-size:13px">No foreign failed events to plot velocity for.</div>';
    return;
  }

  // Bucket events into 15-minute intervals
  const BUCKET_MS = 15 * 60 * 1000;
  const ipTimes = {};
  const allTs = [];

  for (const ip of topIPs) {
    const ts = events
      .filter(e => e.ipAddress === ip && !e.success)
      .map(e => new Date(e.createdAt).getTime())
      .filter(t => !isNaN(t));
    ipTimes[ip] = ts.sort((a, b) => a - b);
    allTs.push(...ts);
  }

  if (allTs.length === 0) {
    container.innerHTML = '<div style="padding:48px;text-align:center;color:var(--text3)">No data.</div>';
    return;
  }

  const minT = Math.min(...allTs);
  const maxT = Math.max(...allTs);
  const numBuckets = Math.ceil((maxT - minT) / BUCKET_MS) + 1;

  const labels = Array.from({ length: numBuckets }, (_, i) => {
    const t = new Date(minT + i * BUCKET_MS);
    return t.toLocaleString('en-GB', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  });

  const COLORS = ['#f16060', '#f5a623', '#5b8def', '#2ec99a', '#a78bfa'];
  const datasets = topIPs.map((ip, i) => {
    const counts = new Array(numBuckets).fill(0);
    for (const t of ipTimes[ip]) {
      const b = Math.min(Math.floor((t - minT) / BUCKET_MS), numBuckets - 1);
      counts[b]++;
    }
    return {
      label: ip,
      data: counts,
      borderColor: COLORS[i],
      backgroundColor: COLORS[i] + '18',
      fill: true,
      tension: 0.35,
      pointRadius: 2,
      borderWidth: 2,
    };
  });

  container.innerHTML = `
    <div style="padding:16px 20px 24px">
      <div class="section-title" style="margin-bottom:4px">Attack Velocity Timeline</div>
      <div style="font-size:12px;color:var(--text3);margin-bottom:16px">Failed sign-in events per 15-minute bucket — top ${topIPs.length} foreign attacking IP${topIPs.length > 1 ? 's' : ''}</div>
      <div style="height:340px"><canvas id="chart-velocity"></canvas></div>
    </div>`;

  new Chart(document.getElementById('chart-velocity'), {
    type: 'line',
    data: { labels, datasets },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { labels: { color: '#7a88a4', font: { size: 11 } } },
      },
      scales: {
        x: {
          ticks: { color: '#7a88a4', font: { size: 9 }, maxRotation: 45, maxTicksLimit: 24 },
          grid: { color: '#1d2438' },
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#7a88a4', font: { size: 10 }, precision: 0 },
          grid: { color: '#1d2438' },
          title: { display: true, text: 'Events / 15 min', color: '#7a88a4', font: { size: 10 } },
        },
      },
    },
  });
}

/* ── Login Heatmap ────────────────────────────────────────────────────────── */
function buildHeatmapSVG(events, title, color) {
  const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const grid = Array.from({ length: 7 }, () => new Array(24).fill(0));
  for (const e of events) {
    if (!e.createdAt) continue;
    const d = new Date(e.createdAt);
    if (isNaN(d)) continue;
    grid[d.getUTCDay()][d.getUTCHours()]++;
  }
  const maxVal = Math.max(...grid.flat(), 1);

  const CELL = 17; const GAP = 2; const LW = 30; const LH = 18;
  const W = LW + 24 * (CELL + GAP);
  const H = LH + 7  * (CELL + GAP) + 14;

  const cells = grid.flatMap((row, d) =>
    row.map((count, h) => {
      const alpha = count === 0 ? 0.06 : 0.12 + (count / maxVal) * 0.88;
      const x = LW + h * (CELL + GAP);
      const y = LH + d * (CELL + GAP);
      return `<rect x="${x}" y="${y}" width="${CELL}" height="${CELL}" rx="2"
        fill="${color}" fill-opacity="${alpha.toFixed(2)}">
        <title>${DAYS[d]} ${String(h).padStart(2,'0')}:00 UTC — ${count} event${count !== 1 ? 's' : ''}</title>
      </rect>`;
    })
  ).join('');

  const hLabels = [0,3,6,9,12,15,18,21].map(h =>
    `<text x="${LW + h*(CELL+GAP) + CELL/2}" y="${LH-4}" text-anchor="middle" font-size="9" fill="#4d5a72">${String(h).padStart(2,'0')}</text>`
  ).join('');

  const dLabels = DAYS.map((d, i) =>
    `<text x="${LW-4}" y="${LH + i*(CELL+GAP) + CELL/2 + 3}" text-anchor="end" font-size="9" fill="#7a88a4">${d}</text>`
  ).join('');

  return `
    <div class="chart-card">
      <div class="chart-card-title">${title}</div>
      <div style="overflow-x:auto;padding:4px 0">
        <svg width="${W}" height="${H}" xmlns="http://www.w3.org/2000/svg" style="font-family:Inter,sans-serif;display:block">
          ${hLabels}${dLabels}${cells}
          <text x="${LW + 12*(CELL+GAP)}" y="${H}" text-anchor="middle" font-size="9" fill="#3a4560">← UTC hour →</text>
        </svg>
      </div>
    </div>`;
}

/* ── ASN / ISP Clustering ─────────────────────────────────────────────────── */
function buildASNSection(ipEnrichment, events, homeCountry) {
  // Count events per foreign IP
  const ipEventCount = {};
  for (const e of events) {
    if (!e.ipAddress || !e.country || e.country.toUpperCase() === homeCountry) continue;
    ipEventCount[e.ipAddress] = (ipEventCount[e.ipAddress] || 0) + 1;
  }

  // Group by ASN/ISP
  const asnMap = {};
  for (const [ip, info] of Object.entries(ipEnrichment)) {
    if (!ipEventCount[ip]) continue;
    const key   = info.as || info.isp || 'Unknown';
    const label = (info.isp || info.org || info.as || 'Unknown')
      .replace(/^AS\d+\s*/, '').trim().slice(0, 36) || key;
    if (!asnMap[key]) asnMap[key] = { label, count: 0, ips: 0, proxy: false, hosting: false };
    asnMap[key].count += ipEventCount[ip];
    asnMap[key].ips++;
    if (info.proxy)   asnMap[key].proxy   = true;
    if (info.hosting) asnMap[key].hosting = true;
  }

  const top = Object.values(asnMap).sort((a, b) => b.count - a.count).slice(0, 8);
  if (top.length === 0) return '';

  const maxCount = top[0].count;
  const rows = top.map(a => {
    const pct   = Math.round((a.count / maxCount) * 100);
    const badge = a.hosting
      ? `<span class="asn-badge" style="background:rgba(241,96,96,0.15);color:#f16060">HOSTING</span>`
      : a.proxy
      ? `<span class="asn-badge" style="background:rgba(245,166,35,0.15);color:#f5a623">PROXY</span>`
      : '';
    return `
      <div class="asn-row">
        <div class="asn-label">${escHtml(a.label)} ${badge}</div>
        <div class="asn-bar-wrap"><div class="asn-bar" style="width:${pct}%"></div></div>
        <div class="asn-count">${a.count.toLocaleString()} <span style="color:var(--text3);font-size:10px">(${a.ips} IP${a.ips > 1 ? 's' : ''})</span></div>
      </div>`;
  }).join('');

  return `
    <div class="chart-card" style="grid-column:1/-1">
      <div class="chart-card-title">Top Attack Sources by ISP / ASN</div>
      <div class="asn-chart">${rows}</div>
    </div>`;
}

/* ── Tenant Health Score ──────────────────────────────────────────────────── */
function renderHealthScore(events, detections) {
  if (!events.length) return '';
  const homeCountry = (state.analysisData?.homeCountry || 'ID').toUpperCase();

  // CA Policy coverage
  const interactive = events.filter(e => e.signInType === 'interactive' || !e.signInType);
  const caApplied   = interactive.filter(e =>
    e.conditionalAccessStatus === 'success' || e.conditionalAccessStatus === 'enforced'
  ).length;
  const caRate = interactive.length > 0 ? caApplied / interactive.length : 0;

  // Legacy auth exposure
  const legacyRate = events.filter(e => e.appType === 'Legacy').length / events.length;

  // Foreign login prevention
  const foreignEvts    = events.filter(e => e.country && e.country.toUpperCase() !== homeCountry);
  const foreignSuccess = foreignEvts.filter(e => e.success).length;
  const foreignPrevent = foreignEvts.length > 0 ? 1 - foreignSuccess / foreignEvts.length : 1;

  // MFA enforcement on foreign failed attempts
  const MFA_ERRORS  = new Set([50076, 500121, 50074, 53003, 50158]);
  const foreignFail = foreignEvts.filter(e => !e.success);
  const mfaBlocked  = foreignFail.filter(e => MFA_ERRORS.has(e.errorCode)).length;
  const mfaRate     = foreignFail.length > 0 ? mfaBlocked / foreignFail.length : 1;

  // Weighted score (total = 100)
  const caScore      = Math.round(caRate * 35);
  const legacyScore  = Math.round((1 - Math.min(legacyRate * 5, 1)) * 25);
  const foreignScore = Math.round(foreignPrevent * 25);
  const mfaScore     = Math.round(mfaRate * 15);
  const total        = caScore + legacyScore + foreignScore + mfaScore;

  const scoreColor = total >= 75 ? 'var(--ok)' : total >= 45 ? 'var(--warn)' : 'var(--danger)';
  const scoreLabel = total >= 75 ? 'Good' : total >= 45 ? 'Fair' : 'At Risk';

  const metric = (label, rate, pts, maxPts, invert = false) => {
    const display = Math.round(rate * 100);
    const barPct  = invert ? Math.round((1 - Math.min(rate * 5, 1)) * 100) : display;
    const c = invert
      ? (display < 5 ? 'var(--ok)' : display < 20 ? 'var(--warn)' : 'var(--danger)')
      : (display > 70 ? 'var(--ok)' : display > 40 ? 'var(--warn)' : 'var(--danger)');
    return `
      <div class="health-metric">
        <div class="health-metric-top">
          <span>${escHtml(label)}</span>
          <span style="color:${c};font-weight:700">${display}%</span>
        </div>
        <div class="health-bar-bg"><div class="health-bar-fill" style="width:${barPct}%;background:${c}"></div></div>
        <div style="font-size:10px;color:var(--text3);margin-top:2px">+${pts}/${maxPts} pts</div>
      </div>`;
  };

  return `
    <div class="dash-panel health-panel">
      <div class="dash-panel-header">
        <span class="dash-panel-title"><i class="bi bi-shield-check"></i> Tenant Health</span>
        <span style="font-size:14px;font-weight:800;color:${scoreColor}">${total}/100</span>
      </div>
      <div class="dash-panel-body">
        <div class="health-gauge-bg">
          <div class="health-gauge-fill" style="width:${total}%;background:${scoreColor}"></div>
          <span class="health-gauge-label" style="color:${scoreColor}">${scoreLabel}</span>
        </div>
        ${metric('CA Policy Coverage', caRate, caScore, 35)}
        ${metric('Legacy Auth Exposure', legacyRate, legacyScore, 25, true)}
        ${metric('Foreign Login Prevention', foreignPrevent, foreignScore, 25)}
        ${metric('MFA on Foreign Fails', mfaRate, mfaScore, 15)}
      </div>
    </div>`;
}

/* ── Timeline panel ───────────────────────────────────────────────────────── */
function openTimeline(userPrincipal, page = 1) {
  if (!state.analysisData) return;
  state.timelineUser = userPrincipal;
  state.timelinePage = page;

  const events      = state.analysisData.events || [];
  const detections  = state.analysisData.detections || [];
  const homeCountry = (state.analysisData.homeCountry || 'ID').toUpperCase();

  const userEvents = events
    .filter(e => e.userPrincipal === userPrincipal)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));

  if (userEvents.length === 0) return;

  // Build a set of event timestamps that are flagged by a detection
  const flaggedTimes = new Set();
  for (const d of detections) {
    if (d.user !== userPrincipal) continue;
    if (d.time) flaggedTimes.add(d.time);
    if (d.from?.time) flaggedTimes.add(d.from.time);
    if (d.to?.time) flaggedTimes.add(d.to.time);
  }

  const totalEvents  = userEvents.length;
  const failedEvents = userEvents.filter(e => !e.success).length;
  const countries    = [...new Set(userEvents.map(e => e.country).filter(Boolean))];
  const foreignCount = userEvents.filter(e => e.success && e.country && e.country.toUpperCase() !== homeCountry).length;

  // Pagination
  const pageSize  = state.timelinePageSize;
  const pages     = Math.max(1, Math.ceil(userEvents.length / pageSize));
  const curPage   = Math.min(Math.max(page, 1), pages);
  const pageStart = (curPage - 1) * pageSize;
  const pageEvents = userEvents.slice(pageStart, pageStart + pageSize);

  const items = pageEvents.map(e => {
    const isForeign = e.country && e.country.toUpperCase() !== homeCountry;
    const isFlagged = flaggedTimes.has(e.createdAt);
    const dotClass  = !e.success ? 'fail' : (isFlagged || isForeign ? 'foreign' : '');

    const flags = [];
    if (!e.success) flags.push(`<span class="tl-flag flag-fail">FAIL</span>`);
    if (isForeign)  flags.push(`<span class="tl-flag flag-foreign">FOREIGN</span>`);
    if (isFlagged)  flags.push(`<span class="tl-flag flag-det">DETECTED</span>`);
    if (e.appType === 'Admin')          flags.push(`<span class="tl-flag flag-admin">ADMIN TOOL</span>`);
    if (e.appType === 'Legacy')         flags.push(`<span class="tl-flag flag-legacy">LEGACY AUTH</span>`);
    if (e.appType === 'Non-Interactive') flags.push(`<span class="tl-flag" style="background:rgba(100,116,139,0.2);color:#94a3b8;border:1px solid rgba(100,116,139,0.3)">NON-INTERACTIVE</span>`);

    return `
      <div class="tl-item">
        <div class="tl-line-wrap"><div class="tl-dot ${dotClass}"></div></div>
        <div class="tl-content">
          <div class="tl-time">${formatDate(e.createdAt)}</div>
          <div class="tl-row">
            <span class="${e.success ? 'tl-status-ok' : 'tl-status-fail'}">${e.success ? '<i class="bi bi-check-lg"></i> Success' : '<i class="bi bi-x-lg"></i> Failed'}</span>
            ${e.country ? `<span><i class="bi bi-geo-alt-fill"></i> ${escHtml(e.country)}${e.city ? ' / ' + escHtml(e.city) : ''}</span>` : ''}
            ${e.ipAddress ? `<span style="color:var(--text2)">${renderIPClickable(e.ipAddress)}</span>` : ''}
            ${flags.join('')}
          </div>
          <div class="tl-note">${escHtml(e.appName || '')}${e.appType ? ' · ' + e.appType : ''}${e.resourceName && e.resourceName !== e.appName ? ' → ' + escHtml(e.resourceName) : ''}${e.failureReason ? ' · ' + e.failureReason : ''}${e.userAgent && e.signInType === 'nonInteractive' ? ' · ' + escHtml(e.userAgent.slice(0, 60)) : ''}</div>
        </div>
      </div>`;
  }).join('');

  const paginationHtml = pages > 1 ? `
    <div class="tl-pagination">
      <button onclick="openTimeline('${escHtml(userPrincipal)}', ${curPage - 1})" ${curPage === 1 ? 'disabled' : ''}>← Prev</button>
      <span>Page ${curPage} of ${pages} · ${totalEvents} events</span>
      <button onclick="openTimeline('${escHtml(userPrincipal)}', ${curPage + 1})" ${curPage === pages ? 'disabled' : ''}>Next →</button>
    </div>` : '';

  // Re-use existing overlay if open (page navigation), else create new
  let overlay = document.getElementById('timeline-overlay');
  const isNew = !overlay;
  if (isNew) {
    overlay = document.createElement('div');
    overlay.id = 'timeline-overlay';
    overlay.addEventListener('click', e => { if (e.target === overlay) closeTimeline(); });
  }

  // Detections for this user
  const userDets = detections.filter(d =>
    d.user === userPrincipal ||
    (d.affectedUsers && d.affectedUsers.includes(userPrincipal))
  );
  const detBadges = userDets.map(d => `
    <div class="tl-det-badge sev-${d.severity}">
      <span class="det-badge badge-${d.severity}">${d.severity}</span>
      <span>${escHtml(d.type.replace(/_/g, ' '))}</span>
      <span class="tl-det-msg">${escHtml(d.message)}</span>
    </div>`).join('');

  overlay.innerHTML = `
    <div id="timeline-panel">
      <div class="timeline-header">
        <div>
          <h3>User Timeline</h3>
          <div class="tl-user">${escHtml(userPrincipal)}</div>
        </div>
        <div style="display:flex;align-items:center;gap:6px;flex-shrink:0">
          <button class="btn-secondary" style="font-size:11px;padding:3px 10px" onclick="exportSessionReplay('${escHtml(userPrincipal)}')"><i class="bi bi-clipboard"></i> Export Log</button>
          <button class="timeline-close" onclick="closeTimeline()"><i class="bi bi-x-lg"></i></button>
        </div>
      </div>
      <div class="timeline-body">
        <div class="tl-stats">
          <div class="tl-stat"><strong>${totalEvents}</strong><span>Total</span></div>
          <div class="tl-stat"><strong>${failedEvents}</strong><span>Failed</span></div>
          <div class="tl-stat"><strong>${foreignCount}</strong><span>Foreign</span></div>
          <div class="tl-stat"><strong>${countries.length}</strong><span>Countries</span></div>
        </div>
        ${detBadges ? `<div class="tl-dets-section">${detBadges}</div>` : ''}
        ${items}
      </div>
      ${paginationHtml}
      <div class="tl-notes-section">
        <div class="tl-notes-label"><i class="bi bi-journal-text"></i> Investigation Notes</div>
        <textarea id="tl-note-input" class="tl-note-textarea" placeholder="Write investigation notes for this user…" rows="3">${escHtml(state.userNotes[userPrincipal] || '')}</textarea>
        <div class="tl-notes-footer">
          <button class="btn-secondary" style="font-size:12px;padding:4px 12px" onclick="saveUserNote('${escHtml(userPrincipal)}')">Save Note</button>
          ${state.userNotes[userPrincipal] ? `<span class="tl-note-saved"><i class="bi bi-check-lg"></i> Note saved</span>` : ''}
        </div>
      </div>
    </div>`;

  if (isNew) document.body.appendChild(overlay);
}

function closeTimeline() {
  document.getElementById('timeline-overlay')?.remove();
  state.timelineUser = null;
  state.timelinePage = 1;
}

async function saveUserNote(userPrincipal) {
  const wsId = state.activeWorkspace?.id;
  if (!wsId) return;
  const note = document.getElementById('tl-note-input')?.value || '';
  try {
    await api('POST', `/api/workspaces/${wsId}/notes`, { user: userPrincipal, note });
    if (note.trim()) state.userNotes[userPrincipal] = note.trim();
    else delete state.userNotes[userPrincipal];
    const footer = document.querySelector('.tl-notes-footer');
    if (footer) {
      let saved = footer.querySelector('.tl-note-saved');
      if (!saved) { saved = document.createElement('span'); saved.className = 'tl-note-saved'; footer.appendChild(saved); }
      saved.innerHTML = note.trim() ? '<i class="bi bi-check-lg"></i> Note saved' : '';
    }
    toast('Note saved');
  } catch(e) { toast('Failed to save note', 'err'); }
}

/* ── Bulk Triage ───────────────────────────────────────────────────────────── */
function bulkToggle(key) {
  if (state.bulkSelected.has(key)) state.bulkSelected.delete(key);
  else state.bulkSelected.add(key);
  rerenderDetections();
}

async function bulkTriage(status) {
  const wsId = state.activeWorkspace?.id;
  if (!wsId || state.bulkSelected.size === 0) return;
  const triages = [...state.bulkSelected].map(key => ({ key, status }));
  try {
    const result = await api('POST', `/api/workspaces/${wsId}/triage/bulk`, { triages });
    state.triages = result.triages || state.triages;
    state.bulkSelected = new Set();
    rerenderDetections();
    toast(`${triages.length} detection(s) marked ${status}`);
  } catch(e) { toast('Bulk triage failed', 'err'); }
}

function clearBulkSelection() {
  state.bulkSelected = new Set();
  rerenderDetections();
}

/* ── Detection Comments ────────────────────────────────────────────────────── */
function toggleDetComment(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('open');
  if (el.classList.contains('open')) el.querySelector('textarea')?.focus();
}

async function saveDetectionComment(key, textareaId) {
  const wsId = state.activeWorkspace?.id;
  if (!wsId) return;
  const comment = document.getElementById(textareaId)?.value || '';
  try {
    await api('POST', `/api/workspaces/${wsId}/comments`, { key, comment });
    if (comment.trim()) state.detectionComments[key] = comment.trim();
    else delete state.detectionComments[key];
    rerenderDetections();
    toast('Comment saved');
  } catch(e) { toast('Failed to save comment', 'err'); }
}

/* ── Watch List ────────────────────────────────────────────────────────────── */
async function toggleWatchList(user) {
  const wsId = state.activeWorkspace?.id;
  if (!wsId) return;
  try {
    const result = await api('POST', `/api/workspaces/${wsId}/watchlist`, { user });
    state.watchList = new Set(result.watchList || []);
    // Re-render dashboard to reorder cards
    const dashEl = document.getElementById('tab-dashboard');
    if (dashEl) dashEl.innerHTML = renderDashboard(state.analysisData);
    toast(state.watchList.has(user) ? '<i class="bi bi-star-fill"></i> Added to Watch List' : '<i class="bi bi-star"></i> Removed from Watch List');
  } catch(e) { toast('Failed to update Watch List', 'err'); }
}

/* ── Workspace modal ──────────────────────────────────────────────────────── */
/* ── Trusted countries tag input ──────────────────────────────────────────── */
function getTrustedTags() {
  return [...document.querySelectorAll('#trusted-tags .tag-chip')].map(el => el.dataset.code);
}

function renderTrustedTags(codes) {
  const wrap  = document.getElementById('trusted-tags');
  const input = document.getElementById('trusted-input');
  // Remove existing chips (keep input)
  wrap.querySelectorAll('.tag-chip').forEach(el => el.remove());
  for (const code of codes) {
    const chip = document.createElement('span');
    chip.className = 'tag-chip';
    chip.dataset.code = code;
    chip.innerHTML = `${escHtml(code)}<button type="button" onclick="removeTag('${escHtml(code)}')" title="Remove">×</button>`;
    wrap.insertBefore(chip, input);
  }
}

function handleTagInput(e) {
  const input = e.target;
  if ((e.key === 'Enter' || e.key === ',') && input.value.trim()) {
    e.preventDefault();
    const code = input.value.trim().toUpperCase().slice(0, 2);
    if (code.length === 2) {
      const existing = getTrustedTags();
      if (!existing.includes(code)) renderTrustedTags([...existing, code]);
    }
    input.value = '';
  } else if (e.key === 'Backspace' && !input.value) {
    const tags = getTrustedTags();
    if (tags.length) renderTrustedTags(tags.slice(0, -1));
  }
}

function removeTag(code) {
  renderTrustedTags(getTrustedTags().filter(c => c !== code));
}

function setTuningFields(t = {}) {
  document.getElementById('tune-spray-window').value   = t.sprayWindowMin   ?? 10;
  document.getElementById('tune-spray-users').value    = t.sprayMinUsers    ?? 5;
  document.getElementById('tune-brute-attempts').value = t.bruteMinAttempts ?? 10;
  document.getElementById('tune-mfa-prompts').value    = t.mfaMinPrompts    ?? 5;
  document.getElementById('tune-enum-users').value     = t.enumMinUsers     ?? 10;
}

function getTuningFields() {
  return {
    sprayWindowMin:   parseInt(document.getElementById('tune-spray-window').value)   || 10,
    sprayMinUsers:    parseInt(document.getElementById('tune-spray-users').value)    || 5,
    bruteMinAttempts: parseInt(document.getElementById('tune-brute-attempts').value) || 10,
    mfaMinPrompts:    parseInt(document.getElementById('tune-mfa-prompts').value)    || 5,
    enumMinUsers:     parseInt(document.getElementById('tune-enum-users').value)     || 10,
  };
}

function ensureBreachListField() {
  if (document.getElementById('ws-breachlist')) return;
  const modal = document.querySelector('.modal');
  const actions = modal.querySelector('.modal-actions');
  const label = document.createElement('label');
  label.textContent = 'Breach List';
  label.style.cssText = 'display:block;margin-top:8px';
  const hint = document.createElement('span');
  hint.style.cssText = 'font-weight:400;color:var(--text3)';
  hint.textContent = ' (one email per line — users found here trigger a breach alert)';
  label.appendChild(hint);
  const ta = document.createElement('textarea');
  ta.id = 'ws-breachlist';
  ta.rows = 3;
  ta.placeholder = 'user@contoso.com\nother@domain.com';
  ta.style.cssText = 'font-family:monospace;font-size:12px;resize:vertical;width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:9px 12px;border-radius:var(--radius-sm);font-size:13px;font-family:inherit;outline:none;transition:border-color 0.15s;margin-top:4px';
  modal.insertBefore(label, actions);
  modal.insertBefore(ta, actions);
}

function showNewWorkspaceModal() {
  state.editingWorkspace = null;
  document.getElementById('modal-title').textContent = 'New Workspace';
  document.getElementById('ws-name').value = '';
  document.getElementById('ws-tenant').value = '';
  document.getElementById('ws-homecountry').value = 'ID';
  document.getElementById('ws-playbook').value = '';
  document.getElementById('ws-trustedips').value = '';
  document.getElementById('tuning-details').removeAttribute('open');
  setTuningFields();
  renderTrustedTags([]);
  ensureBreachListField();
  document.getElementById('ws-breachlist').value = '';
  document.querySelector('.modal .btn-primary').textContent = 'Create';
  document.querySelector('.modal .btn-primary').onclick = submitWorkspace;
  document.getElementById('modal-overlay').classList.remove('hidden');
  setTimeout(() => document.getElementById('ws-name').focus(), 50);
}

function editWorkspaceModal() {
  const ws = state.activeWorkspace;
  state.editingWorkspace = ws.id;
  document.getElementById('modal-title').textContent = 'Edit Workspace';
  document.getElementById('ws-name').value = ws.name;
  document.getElementById('ws-tenant').value = ws.tenant || '';
  document.getElementById('ws-homecountry').value = ws.homeCountry || 'ID';
  document.getElementById('ws-playbook').value = ws.playbook || '';
  document.getElementById('ws-trustedips').value = (ws.trustedIPs || []).join('\n');
  setTuningFields(ws.ruleThresholds || {});
  if (ws.ruleThresholds) document.getElementById('tuning-details').setAttribute('open', '');
  renderTrustedTags(ws.trustedCountries || []);
  ensureBreachListField();
  document.getElementById('ws-breachlist').value = ws.breachList?.join('\n') || '';
  document.querySelector('.modal .btn-primary').textContent = 'Save';
  document.querySelector('.modal .btn-primary').onclick = submitWorkspace;
  document.getElementById('modal-overlay').classList.remove('hidden');
}

function closeModal() {
  document.getElementById('modal-overlay').classList.add('hidden');
}

async function submitWorkspace() {
  const name             = document.getElementById('ws-name').value.trim();
  const tenant           = document.getElementById('ws-tenant').value.trim();
  const homeCountry      = document.getElementById('ws-homecountry').value.trim().toUpperCase() || 'ID';
  const playbook         = document.getElementById('ws-playbook').value.trim();
  const trustedCountries = getTrustedTags();
  const trustedIPs = document.getElementById('ws-trustedips').value
    .split(/[\n,]/).map(s => s.trim()).filter(Boolean);
  const breachList = (document.getElementById('ws-breachlist')?.value || '')
    .split('\n').map(s => s.trim()).filter(Boolean);
  const ruleThresholds = getTuningFields();
  if (!name) { document.getElementById('ws-name').focus(); return; }

  try {
    if (state.editingWorkspace) {
      await api('PATCH', `/api/workspaces/${state.editingWorkspace}`, { name, tenant, homeCountry, playbook, trustedCountries, trustedIPs, breachList, ruleThresholds });
      toast('Workspace updated');
      await loadWorkspaces();
      await selectWorkspace(state.editingWorkspace);
    } else {
      const ws = await api('POST', '/api/workspaces', { name, tenant, homeCountry, playbook, trustedCountries, trustedIPs, breachList, ruleThresholds });
      toast('Workspace created');
      await loadWorkspaces();
      await selectWorkspace(ws.id);
    }
    closeModal();
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function deleteWorkspace() {
  if (!confirm(`Delete workspace "${state.activeWorkspace.name}" and all its files?`)) return;
  try {
    await api('DELETE', `/api/workspaces/${state.activeWorkspace.id}`);
    toast('Workspace deleted');
    state.activeWorkspace = null;
    if (state.leafletMap) { state.leafletMap.remove(); state.leafletMap = null; }
    destroyCharts();
    await loadWorkspaces();
    document.getElementById('welcome').classList.remove('hidden');
    document.getElementById('workspace-view').classList.add('hidden');
  } catch (e) {
    toast(e.message, 'err');
  }
}

/* ── Background event loader ─────────────────────────────────────────────── */
async function bgLoadEvents(wsId, total) {
  const sig = state.analysisData?.filesSig;
  const idbKey = sig ? `${wsId}:${sig}` : null;

  // Try IndexedDB first — if we already fetched these exact events, load instantly
  if (idbKey) {
    const cached = await idb.get(idbKey);
    if (cached?.length > (state.analysisData?.events?.length || 0)) {
      if (state.activeWorkspace?.id !== wsId || !state.analysisData) return;
      state.analysisData.events = cached;
      state.eventsLoading = null;
      updateSidebarProgress();
      if (state.activeTab === 'events') rerenderTable();
      return;
    }
  }

  // Fetch from server in batches
  const BATCH = 5000;
  let offset = (state.analysisData?.events || []).length;
  state.eventsLoading = { loaded: offset, total };
  updateSidebarProgress();

  while (offset < total) {
    if (state.activeWorkspace?.id !== wsId || !state.analysisData) return;
    try {
      const res = await api('GET', `/api/workspaces/${wsId}/events?offset=${offset}&limit=${BATCH}`);
      if (!res.events?.length) break;
      if (state.activeWorkspace?.id !== wsId || !state.analysisData) return;
      state.analysisData.events = [...(state.analysisData.events || []), ...res.events];
      offset += res.events.length;
      state.eventsLoading = { loaded: offset, total };
      updateSidebarProgress();
      if (state.activeTab === 'events') rerenderTable();
    } catch (e) {
      break;
    }
  }

  // Save to IndexedDB so future loads are instant (no server round-trip needed)
  if (idbKey && state.analysisData?.events?.length > 0) {
    idb.set(idbKey, state.analysisData.events).catch(() => {});
  }

  state.eventsLoading = null;
  updateSidebarProgress();
  updateEventsProgress(null, null);
}

function updateSidebarProgress() {
  const item = document.querySelector('.ws-item.active');
  if (!item) return;
  let bar = item.querySelector('.ws-load-bar');
  if (!state.eventsLoading) {
    if (bar) bar.remove();
    return;
  }
  const pct = Math.round((state.eventsLoading.loaded / state.eventsLoading.total) * 100);
  if (!bar) {
    bar = document.createElement('div');
    bar.className = 'ws-load-bar';
    item.appendChild(bar);
  }
  bar.innerHTML = `<div class="ws-load-bar-fill" style="width:${pct}%"></div>`;
}

function updateEventsProgress(loaded, total) {
  const el = document.getElementById('events-load-progress');
  if (!el) return;
  if (loaded === null) { el.style.display = 'none'; return; }
  el.style.display = '';
  el.textContent = `Loading events… ${loaded.toLocaleString()} / ${total.toLocaleString()}`;
}

/* ── Cross-workspace IP correlation ──────────────────────────────────────── */
function renderCorrelationPanel() {
  const corr = state.correlationData;
  if (!corr || corr.correlations.length === 0) return;
  // Insert above the stats grid if not already there
  const container = document.getElementById('analysis-results');
  if (!container || document.getElementById('corr-panel')) return;
  const div = document.createElement('div');
  div.id = 'corr-panel';
  div.innerHTML = `
    <div class="corr-panel">
      <div class="corr-panel-header">
        <i class="bi bi-link-45deg"></i> Cross-workspace IP Correlation
        <span style="color:var(--danger)">${corr.correlations.length} workspace(s) share attacking IPs</span>
      </div>
      ${corr.correlations.map(c => `
        <div class="corr-item">
          <span class="corr-ws-name">${escHtml(c.workspaceName)}</span>
          <span class="corr-count">${c.sharedCount} shared IP${c.sharedCount > 1 ? 's' : ''}</span>
          <span class="corr-ips">${c.sharedIPs.slice(0, 3).join(', ')}${c.sharedIPs.length > 3 ? ` +${c.sharedIPs.length - 3} more` : ''}</span>
        </div>`).join('')}
    </div>`;
  // Insert before first child of analysis-results
  const statsGrid = container.querySelector('.stats-grid');
  if (statsGrid) container.insertBefore(div, statsGrid);
  else container.insertBefore(div, container.firstChild);
}

/* ── PDF Export ───────────────────────────────────────────────────────────── */
function exportPDF() {
  const data = state.analysisData;
  const ws   = state.activeWorkspace;
  if (!data || !ws) return;

  const events      = data.events      || [];
  const detections  = data.detections  || [];
  const summaries   = data.userSummaries || [];
  const timeline    = data.attackTimeline || [];
  const homeCountry = data.homeCountry || 'ID';

  const now          = new Date().toLocaleString('en-GB', { dateStyle: 'long', timeStyle: 'short' });
  const successes    = events.filter(e => e.success).length;
  const failures     = events.filter(e => !e.success).length;
  const foreignSucc  = events.filter(e => e.success && e.country && e.country.toUpperCase() !== homeCountry).length;
  const uniqueUsers  = new Set(events.map(e => e.userPrincipal)).size;
  const uniqueCtries = new Set(events.map(e => e.country).filter(Boolean)).size;
  const highFindings = detections.filter(d => d.severity === 'high').length;
  const critCount    = summaries.filter(s => s.riskLevel === 'CRITICAL').length;
  const highCount    = summaries.filter(s => s.riskLevel === 'HIGH').length;
  const medCount     = summaries.filter(s => s.riskLevel === 'MEDIUM').length;

  const sevColor  = s => s === 'high' ? '#dc2626' : '#d97706';
  const riskColor = r => r === 'CRITICAL' ? '#dc2626' : r === 'HIGH' ? '#d97706' : '#2563eb';
  const esc       = str => String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  const detRows = detections.map(d => {
    const m = MITRE_MAP[d.type];
    const mitrePdf = m ? `<span style="background:#f3f0ff;border:1px solid #c4b5fd;color:#7c3aed;border-radius:3px;padding:1px 5px;font-size:9.5px;font-weight:700;white-space:nowrap">ATT&amp;CK ${esc(m.id)}</span>` : '—';
    const rowCls = d.severity === 'high' ? 'row-high' : d.severity === 'medium' ? 'row-medium' : 'row-low';
    return `
    <tr class="${rowCls}">
      <td><span style="background:${sevColor(d.severity)};color:#fff;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.3px">${esc(d.severity.toUpperCase())}</span></td>
      <td style="font-weight:600;font-size:11px">${esc(d.type.replace(/_/g,' '))}</td>
      <td>${mitrePdf}</td>
      <td style="font-size:11px">${esc(d.message)}</td>
    </tr>`;
  }).join('');

  const summaryRows = summaries.map(s => {
    const cardCls = s.riskLevel === 'CRITICAL' ? 'crit' : s.riskLevel === 'HIGH' ? 'high' : 'med';
    const pillBg  = riskColor(s.riskLevel);
    return `
    <div class="user-card ${cardCls}">
      <div class="user-card-header">
        <span class="risk-pill" style="background:${pillBg}">${esc(s.riskLevel)}</span>
        <span class="user-name">${esc(s.displayName)}</span>
        <span class="user-email">${esc(s.user)}</span>
      </div>
      <div class="user-stats">
        <span>Threat: <strong>${esc(s.primaryThreat)}</strong></span>
        <span>Foreign Attempts: <strong>${s.foreignAttempts}</strong></span>
        <span>Successful Foreign: <strong style="color:${s.foreignSuccess>0?'#dc2626':'#16a34a'}">${s.foreignSuccess}</strong></span>
        <span>Countries: <strong>${s.uniqueAttackingCountries}</strong></span>
      </div>
      ${s.narrative ? `<div class="user-narrative" style="border-left-color:${pillBg}">${esc(s.narrative)}</div>` : ''}
      ${s.attackingCountries?.length ? `<div class="country-tags">${s.attackingCountries.slice(0,20).map(c=>`<span class="ctag">${esc(c)}</span>`).join('')}${s.attackingCountries.length>20?`<span style="font-size:10px;color:#94a3b8;padding:2px 4px"> +${s.attackingCountries.length-20} more</span>`:''}</div>` : ''}
    </div>`}).join('');

  const tlRows = timeline.map(e => {
    const ip = e.ip || '';
    const ipDisplay = ip.length > 20 ? ip.slice(0, 18) + '…' : ip;
    return `
    <tr>
      <td style="white-space:nowrap;font-size:10.5px">${esc(new Date(e.time).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'}))}</td>
      <td>${esc(e.displayName)}</td>
      <td>${esc(e.country)}${e.city ? ' / ' + esc(e.city.slice(0,18)) : ''}</td>
      <td style="font-family:monospace;font-size:10px" title="${esc(ip)}">${esc(ipDisplay)}</td>
      <td style="text-align:center">${e.errorCode || ''}</td>
    </tr>`}).join('');

  const riskLabel = critCount > 0 ? 'CRITICAL' : highCount > 0 ? 'HIGH' : medCount > 0 ? 'MEDIUM' : 'CLEAR';
  const riskHex   = critCount > 0 ? '#dc2626'  : highCount > 0 ? '#d97706' : medCount > 0 ? '#2563eb' : '#16a34a';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>EIDSA Report — ${esc(ws.name)}</title>
  <style>
    /* ── Reset & base ─────────────────────────────────── */
    @page { size: A4; margin: 0; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, Arial, sans-serif; font-size: 12.5px; color: #1e293b; background: #fff; }

    /* ── End-of-document footer ───────────────────────── */
    .doc-footer {
      margin-top: 40px; padding: 14px 0 0;
      border-top: 1px solid #e2e8f0;
      display: flex; justify-content: space-between; align-items: center;
      font-size: 9.5px; color: #94a3b8;
    }
    .doc-footer strong { color: #475569; }

    /* ── Cover ────────────────────────────────────────── */
    .cover {
      height: 100vh;
      background: linear-gradient(150deg, #0f172a 0%, #1a1040 60%, #0f2540 100%);
      color: #fff;
      display: flex; flex-direction: column;
      padding: 0;
      -webkit-print-color-adjust: exact; print-color-adjust: exact;
      page-break-after: always;
    }
    .cover-main {
      flex: 1; padding: 56px 56px 40px;
      display: flex; flex-direction: column; justify-content: center; gap: 0;
    }
    .cover-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 36px; }
    .cover-logo {
      font-size: 42px; font-weight: 900; letter-spacing: 4px;
      color: #7cb3ff; line-height: 1; font-style: italic;
    }
    .cover-risk-badge {
      border: 2px solid ${riskHex}; border-radius: 8px;
      padding: 10px 20px; text-align: center; min-width: 110px;
    }
    .cover-risk-label { font-size: 9px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1.5px; }
    .cover-risk-val { font-size: 16px; font-weight: 800; color: ${riskHex}; margin-top: 4px; }
    .cover-title { font-size: 22px; font-weight: 300; color: #cbd5e1; letter-spacing: 0.5px; margin-bottom: 4px; }
    .cover-subtitle { font-size: 13px; color: #64748b; letter-spacing: 0.3px; }
    .cover-divider { height: 1px; background: rgba(255,255,255,0.1); margin: 32px 0; }
    .cover-meta { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 20px 32px; }
    .cover-meta-item .lbl { font-size: 9px; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
    .cover-meta-item .val { font-size: 13px; font-weight: 600; color: #e2e8f0; }
    .cover-confidential {
      display: inline-flex; align-items: center; gap: 6px;
      border: 1px solid rgba(239,68,68,0.4); border-radius: 4px;
      padding: 3px 10px; font-size: 9px; font-weight: 700;
      color: #f87171; letter-spacing: 1.5px; text-transform: uppercase;
      margin-top: 20px; width: fit-content;
    }
    /* Company bar at bottom of cover */
    .cover-company {
      flex-shrink: 0;
      background: rgba(0,0,0,0.35);
      border-top: 1px solid rgba(255,255,255,0.08);
      padding: 16px 56px;
      display: flex; justify-content: space-between; align-items: center;
    }
    .cover-company-name { font-size: 12px; font-weight: 600; color: #94a3b8; }
    .cover-company-copy { font-size: 10px; color: #475569; }
    .cover-author { font-size: 11px; color: #6366f1; font-weight: 600; }

    /* ── Body ─────────────────────────────────────────── */
    .body { padding: 1.8cm 2cm 1.8cm; }
    h2 {
      font-size: 13px; font-weight: 700; color: #0f172a;
      margin: 24px 0 10px; padding-bottom: 5px;
      border-bottom: 2px solid #e2e8f0;
    }
    h2:first-child { margin-top: 0; }

    /* ── Stats grid ───────────────────────────────────── */
    .stats { display: grid; grid-template-columns: repeat(7, 1fr); gap: 8px; margin-bottom: 4px; }
    .stat-box {
      border: 1px solid #e2e8f0; border-radius: 8px;
      padding: 10px 10px;
    }
    .sv { font-size: 20px; font-weight: 700; line-height: 1.1; }
    .sl { font-size: 10px; color: #64748b; margin-top: 2px; }

    /* ── Risk boxes ───────────────────────────────────── */
    .risk-summary { display: flex; gap: 10px; margin-bottom: 14px; }
    .risk-box { border-radius: 8px; padding: 12px 16px; text-align: center; flex: 1; }
    .rv { font-size: 28px; font-weight: 800; }
    .rl { font-size: 10px; margin-top: 2px; font-weight: 700; letter-spacing: 0.5px; }

    /* ── Detection table ──────────────────────────────── */
    table { width: 100%; border-collapse: collapse; font-size: 11px; }
    th {
      background: #f1f5f9; text-align: left; padding: 6px 9px;
      font-size: 10px; font-weight: 700; color: #475569;
      border: 1px solid #e2e8f0; text-transform: uppercase; letter-spacing: 0.3px;
    }
    td { padding: 6px 9px; border: 1px solid #e2e8f0; vertical-align: middle; line-height: 1.4; }
    tr.row-high td { background: #fff9f9; }
    tr.row-medium td { background: #fffdf5; }
    tr.row-low td { background: #f8fff8; }

    /* ── User summary cards ───────────────────────────── */
    .user-card {
      border: 1px solid #e2e8f0; border-radius: 8px;
      padding: 12px 14px; margin-bottom: 10px;
      page-break-inside: avoid; border-left-width: 4px;
    }
    .user-card.crit { border-left-color: #dc2626; }
    .user-card.high { border-left-color: #d97706; }
    .user-card.med  { border-left-color: #2563eb; }
    .user-card-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
    .risk-pill {
      padding: 2px 8px; border-radius: 4px;
      font-size: 10px; font-weight: 700; color: #fff; flex-shrink: 0;
    }
    .user-name { font-size: 13px; font-weight: 700; }
    .user-email { font-size: 10px; color: #64748b; margin-left: 2px; }
    .user-stats { display: flex; gap: 20px; font-size: 11px; margin-bottom: 6px; flex-wrap: wrap; }
    .user-narrative {
      font-size: 11px; color: #334155; line-height: 1.5;
      background: #f8fafc; border-left: 3px solid #e2e8f0;
      padding: 6px 10px; border-radius: 0 4px 4px 0; margin-bottom: 6px;
    }
    .country-tags { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }
    .ctag {
      background: #f1f5f9; border: 1px solid #e2e8f0;
      padding: 1px 6px; border-radius: 3px; font-size: 10px;
    }
    @media print {
      .cover { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .risk-box, .user-card, .stat-box { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      h2 { page-break-after: avoid; }
    }
  </style>
</head>
<body>

  <!-- Cover page -->
  <div class="cover">
    <div class="cover-main">
      <div class="cover-top">
        <div class="cover-logo">EIDSA</div>
        <div class="cover-risk-badge">
          <div class="cover-risk-label">Overall Risk</div>
          <div class="cover-risk-val">${riskLabel}</div>
        </div>
      </div>
      <div class="cover-title">Entra ID Signin Analyzer</div>
      <div class="cover-subtitle">Security Analysis Report</div>
      <div class="cover-divider"></div>
      <div class="cover-meta">
        <div class="cover-meta-item"><div class="lbl">Workspace</div><div class="val">${esc(ws.name)}</div></div>
        ${ws.tenant ? `<div class="cover-meta-item"><div class="lbl">Tenant</div><div class="val">${esc(ws.tenant)}</div></div>` : ''}
        <div class="cover-meta-item"><div class="lbl">Home Country</div><div class="val">${esc(homeCountry)}</div></div>
        <div class="cover-meta-item"><div class="lbl">Events Analyzed</div><div class="val">${events.length.toLocaleString()}</div></div>
        <div class="cover-meta-item"><div class="lbl">Accounts at Risk</div><div class="val" style="color:${riskHex}">${summaries.length}</div></div>
        <div class="cover-meta-item"><div class="lbl">Generated</div><div class="val">${now}</div></div>
      </div>
      <div class="cover-confidential">⬛ Confidential</div>
    </div>
    <div class="cover-company">
      <div>
        <div class="cover-company-name">PT Sigma Cipta Caraka — Telkomsigma</div>
        <div class="cover-company-copy">©2025. PT Sigma Cipta Caraka - Telkomsigma. All Rights Reserved.</div>
      </div>
      <div class="cover-author">Developed by JoshuaDjuk</div>
    </div>
  </div>

  <!-- Body -->
  <div class="body">
    <h2>Executive Summary</h2>
    <div class="stats">
      <div class="stat-box"><div class="sv">${events.length.toLocaleString()}</div><div class="sl">Total Events</div></div>
      <div class="stat-box"><div class="sv" style="color:#16a34a">${successes.toLocaleString()}</div><div class="sl">Successful</div></div>
      <div class="stat-box"><div class="sv" style="color:#dc2626">${failures.toLocaleString()}</div><div class="sl">Failed</div></div>
      <div class="stat-box"><div class="sv" style="color:${foreignSucc>0?'#dc2626':'#16a34a'}">${foreignSucc}</div><div class="sl">Foreign Logins</div></div>
      <div class="stat-box"><div class="sv" style="color:#d97706">${highFindings}</div><div class="sl">High Findings</div></div>
      <div class="stat-box"><div class="sv">${uniqueUsers}</div><div class="sl">Unique Users</div></div>
      <div class="stat-box"><div class="sv">${uniqueCtries}</div><div class="sl">Countries</div></div>
    </div>

    <h2>Risk Overview</h2>
    <div class="risk-summary">
      <div class="risk-box" style="background:#fef2f2;border:1px solid #fecaca;-webkit-print-color-adjust:exact;print-color-adjust:exact">
        <div class="rv" style="color:#dc2626">${critCount}</div><div class="rl" style="color:#dc2626">CRITICAL</div>
      </div>
      <div class="risk-box" style="background:#fffbeb;border:1px solid #fde68a;-webkit-print-color-adjust:exact;print-color-adjust:exact">
        <div class="rv" style="color:#d97706">${highCount}</div><div class="rl" style="color:#d97706">HIGH</div>
      </div>
      <div class="risk-box" style="background:#eff6ff;border:1px solid #bfdbfe;-webkit-print-color-adjust:exact;print-color-adjust:exact">
        <div class="rv" style="color:#2563eb">${medCount}</div><div class="rl" style="color:#2563eb">MEDIUM</div>
      </div>
    </div>

    ${detections.length > 0 ? `
    <h2>Detections (${detections.length})</h2>
    <table>
      <thead><tr>
        <th style="width:68px">Severity</th>
        <th style="width:160px">Type</th>
        <th style="width:110px">MITRE</th>
        <th>Message</th>
      </tr></thead>
      <tbody>${detRows}</tbody>
    </table>` : `<h2>Detections</h2><p style="color:#64748b;font-style:italic;font-size:12px">No detections triggered.</p>`}

    ${summaries.length > 0 ? `
    <h2>User Risk Summaries (${summaries.length})</h2>
    ${summaryRows}` : ''}

    ${timeline.length > 0 ? `
    <h2>Attack Timeline (first ${timeline.length} events)</h2>
    <table>
      <thead><tr><th style="width:120px">Time</th><th style="width:120px">User</th><th style="width:130px">Location</th><th>IP Address</th><th style="width:70px">Error</th></tr></thead>
      <tbody>${tlRows}</tbody>
    </table>` : ''}

    <div class="doc-footer">
      <span>©2025 PT Sigma Cipta Caraka — Telkomsigma. All Rights Reserved.</span>
      <span><strong>EIDSA</strong> · Developed by JoshuaDjuk · ${now}</span>
    </div>
  </div>

  <script>window.onload = () => window.print();<\/script>
</body>
</html>`;

  const win = window.open('', '_blank');
  if (!win) { alert('Popup blocked — allow popups for this page.'); return; }
  win.document.write(html);
  win.document.close();
}

/* ── Executive Summary Export ─────────────────────────────────────────────── */
function exportExecutiveSummary() {
  const data = state.analysisData;
  const ws   = state.activeWorkspace;
  if (!data || !ws) return;

  const events     = data.events     || [];
  const detections = data.detections || [];
  const summaries  = data.userSummaries || [];
  const now = new Date().toLocaleString('en-GB', { dateStyle: 'long', timeStyle: 'short' });
  const homeCountry = data.homeCountry || 'ID';

  const critCount = summaries.filter(s => s.riskLevel === 'CRITICAL').length;
  const highCount = summaries.filter(s => s.riskLevel === 'HIGH').length;
  const medCount  = summaries.filter(s => s.riskLevel === 'MEDIUM').length;
  const riskLabel = critCount > 0 ? 'CRITICAL' : highCount > 0 ? 'HIGH' : medCount > 0 ? 'MEDIUM' : 'CLEAR';
  const riskHex   = critCount > 0 ? '#dc2626' : highCount > 0 ? '#d97706' : medCount > 0 ? '#2563eb' : '#16a34a';

  const foreignSucc = events.filter(e => e.success && e.country && e.country.toUpperCase() !== homeCountry).length;
  const highDets    = detections.filter(d => d.severity === 'high').length;

  // Top 3 threat types by count
  const threatCounts = {};
  for (const d of detections) {
    threatCounts[d.type] = (threatCounts[d.type] || 0) + 1;
  }
  const top3 = Object.entries(threatCounts).sort((a,b)=>b[1]-a[1]).slice(0,3);

  // 7-day daily event counts
  const byDay = {};
  for (const e of events) {
    const day = e.createdAt?.slice(0,10);
    if (!day) continue;
    byDay[day] = (byDay[day] || 0) + 1;
  }
  const last7 = Object.entries(byDay).sort((a,b)=>a[0].localeCompare(b[0])).slice(-7);
  const maxDay = Math.max(...last7.map(([,n])=>n), 1);

  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  const threatCards = top3.map(([type, count]) => {
    const m = {
      PASSWORD_SPRAY:'Password Spray Attack', BRUTE_FORCE:'Brute Force Attack',
      CREDENTIAL_STUFFING:'Credential Stuffing', MFA_EXHAUSTION:'MFA Fatigue Attack',
      IMPOSSIBLE_TRAVEL:'Impossible Travel', FOREIGN_LOGIN:'Unauthorized Foreign Access',
      TOKEN_REPLAY:'Session/Token Hijack', LEGACY_AUTH:'Legacy Auth Bypass',
      ADMIN_TOOL_ABUSE:'Admin Tool Abuse', ENUMERATION_ATTACK:'Account Enumeration',
      DISTRIBUTED_BRUTE_FORCE:'Distributed Brute Force', MFA_METHOD_DOWNGRADE:'MFA Bypass Detected',
      OAUTH_CONSENT_PHISHING:'OAuth Phishing Attempt', CONCURRENT_SESSIONS:'Simultaneous Sessions',
    };
    const label = m[type] || type.replace(/_/g,' ');
    return `<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px 20px;display:flex;justify-content:space-between;align-items:center">
      <div style="font-size:14px;font-weight:600;color:#1e293b">${esc(label)}</div>
      <div style="font-size:28px;font-weight:800;color:#dc2626">${count}</div>
    </div>`;
  }).join('');

  const trendBars = last7.map(([day, count]) => {
    const pct = Math.round((count / maxDay) * 100);
    const label = new Date(day).toLocaleDateString('en-GB',{day:'numeric',month:'short'});
    return `<div style="display:flex;flex-direction:column;align-items:center;gap:4px;flex:1">
      <div style="width:100%;background:#e2e8f0;border-radius:4px;height:80px;display:flex;align-items:flex-end">
        <div style="width:100%;height:${pct}%;background:#5b8def;border-radius:4px;-webkit-print-color-adjust:exact;print-color-adjust:exact"></div>
      </div>
      <div style="font-size:9px;color:#64748b;text-align:center">${esc(label)}</div>
      <div style="font-size:10px;font-weight:600;color:#334155">${count}</div>
    </div>`;
  }).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Executive Summary — ${esc(ws.name)}</title>
  <style>
    @page { size: A4 landscape; margin: 1.5cm 2cm; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, Arial, sans-serif; background: #fff; color: #1e293b; }
    @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
  </style>
</head>
<body>
  <!-- Header -->
  <div style="background:linear-gradient(135deg,#0f172a,#1e1b4b);color:#fff;padding:28px 40px;display:flex;justify-content:space-between;align-items:center;-webkit-print-color-adjust:exact;print-color-adjust:exact">
    <div>
      <div style="font-size:28px;font-weight:900;letter-spacing:4px;color:#7cb3ff;font-style:italic">EIDSA</div>
      <div style="font-size:13px;color:#94a3b8;margin-top:4px">Executive Security Summary — ${esc(ws.name)}</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:11px;color:#64748b">Generated ${esc(now)}</div>
      <div style="font-size:11px;color:#64748b;margin-top:2px">PT Sigma Cipta Caraka — Telkomsigma</div>
    </div>
  </div>

  <div style="padding:28px 40px">
    <!-- Overall Risk -->
    <div style="display:flex;gap:20px;margin-bottom:28px">
      <div style="flex:1;border:2px solid ${riskHex};border-radius:12px;padding:20px 24px;text-align:center;-webkit-print-color-adjust:exact;print-color-adjust:exact">
        <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Overall Risk Level</div>
        <div style="font-size:36px;font-weight:900;color:${riskHex}">${esc(riskLabel)}</div>
      </div>
      <div style="flex:1;background:#fef2f2;border:1px solid #fecaca;border-radius:12px;padding:20px 24px;text-align:center;-webkit-print-color-adjust:exact;print-color-adjust:exact">
        <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Critical Accounts</div>
        <div style="font-size:36px;font-weight:900;color:#dc2626">${critCount}</div>
      </div>
      <div style="flex:1;background:#fffbeb;border:1px solid #fde68a;border-radius:12px;padding:20px 24px;text-align:center;-webkit-print-color-adjust:exact;print-color-adjust:exact">
        <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">High-Risk Accounts</div>
        <div style="font-size:36px;font-weight:900;color:#d97706">${highCount}</div>
      </div>
      <div style="flex:1;background:#eff6ff;border:1px solid #bfdbfe;border-radius:12px;padding:20px 24px;text-align:center;-webkit-print-color-adjust:exact;print-color-adjust:exact">
        <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Foreign Access Events</div>
        <div style="font-size:36px;font-weight:900;color:#2563eb">${foreignSucc}</div>
      </div>
      <div style="flex:1;background:#fef2f2;border:1px solid #fecaca;border-radius:12px;padding:20px 24px;text-align:center;-webkit-print-color-adjust:exact;print-color-adjust:exact">
        <div style="font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">High-Severity Alerts</div>
        <div style="font-size:36px;font-weight:900;color:#dc2626">${highDets}</div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
      <!-- Top Threats -->
      <div>
        <div style="font-size:13px;font-weight:700;color:#0f172a;margin-bottom:10px;padding-bottom:6px;border-bottom:2px solid #e2e8f0">Top Threat Types Detected</div>
        <div style="display:flex;flex-direction:column;gap:8px">
          ${threatCards || '<div style="color:#64748b;font-size:12px;padding:16px 0">No detections triggered.</div>'}
        </div>
      </div>

      <!-- 7-day trend -->
      <div>
        <div style="font-size:13px;font-weight:700;color:#0f172a;margin-bottom:10px;padding-bottom:6px;border-bottom:2px solid #e2e8f0">Sign-in Activity — Last 7 Days</div>
        <div style="display:flex;gap:6px;align-items:flex-end;height:110px">
          ${trendBars || '<div style="color:#64748b;font-size:12px">No data</div>'}
        </div>
      </div>
    </div>

    <!-- Footer -->
    <div style="margin-top:28px;padding-top:12px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;font-size:9.5px;color:#94a3b8">
      <span>©2025 PT Sigma Cipta Caraka — Telkomsigma. All Rights Reserved. CONFIDENTIAL.</span>
      <span>EIDSA by JoshuaDjuk · This report is intended for executive review only.</span>
    </div>
  </div>
  <script>window.onload = () => window.print();<\/script>
</body>
</html>`;

  const win = window.open('', '_blank');
  if (!win) { alert('Popup blocked — allow popups for this page.'); return; }
  win.document.write(html);
  win.document.close();
}

/* ── Baseline Drift ───────────────────────────────────────────────────────── */
function setBaselineNow() {
  if (!state.analysisData || !state.activeWorkspace) return;
  saveBaseline(state.activeWorkspace.id, extractBaselineMetrics(state.analysisData));
  toast('<i class="bi bi-bar-chart-fill"></i> Baseline updated — future runs will compare against this snapshot', 'ok');
}

function renderDriftBanner(data) {
  if (!state.activeWorkspace) return '';
  const bl = loadBaseline(state.activeWorkspace.id);
  if (!bl) return '';
  const cur = extractBaselineMetrics(data);
  const blDate = new Date(bl.ts).toLocaleDateString('en-GB', { dateStyle: 'medium' });

  const LABELS = {
    foreignFailed:      { label: 'Foreign Failed',  bad: 'up' },
    foreignSuccess:     { label: 'Foreign Success',  bad: 'up' },
    detectionCount:     { label: 'Detections',       bad: 'up' },
    criticalCount:      { label: 'Critical Accounts',bad: 'up' },
    attackingCountries: { label: 'Attacking Countries', bad: 'up' },
  };

  const deltas = [];
  for (const [key, meta] of Object.entries(LABELS)) {
    const prev = bl.metrics[key] || 0;
    const curr = cur[key] || 0;
    if (prev === 0 && curr === 0) continue;
    const diff = curr - prev;
    const pct  = prev > 0 ? Math.round((diff / prev) * 100) : (curr > 0 ? 100 : 0);
    if (Math.abs(pct) < 5 && Math.abs(diff) < 2) continue; // ignore tiny changes
    const worse = meta.bad === 'up' ? diff > 0 : diff < 0;
    deltas.push({ key, label: meta.label, prev, curr, diff, pct, worse });
  }
  if (!deltas.length) return '';

  const chips = deltas.map(d => {
    const arrow = d.diff > 0 ? '↑' : '↓';
    const col   = d.worse ? 'var(--danger)' : 'var(--ok)';
    const bg    = d.worse ? 'rgba(209,64,64,0.08)' : 'rgba(33,168,108,0.08)';
    const bord  = d.worse ? 'rgba(209,64,64,0.25)' : 'rgba(33,168,108,0.25)';
    return `<span class="drift-chip" style="background:${bg};border-color:${bord};color:${col}">
      <span class="drift-arrow">${arrow}</span>
      <span class="drift-label">${escHtml(d.label)}</span>
      <span class="drift-val">${d.curr} <span style="font-size:10px;opacity:.8">(${d.diff > 0 ? '+' : ''}${d.pct}%)</span></span>
    </span>`;
  }).join('');

  return `<div class="drift-banner">
    <span class="drift-title"><i class="bi bi-bar-chart-fill"></i> Baseline Drift</span>
    <span style="font-size:10px;color:var(--text3);margin-right:8px">vs ${escHtml(blDate)}</span>
    ${chips}
    <button class="drift-update-btn" onclick="setBaselineNow()" title="Update baseline to current run">Update</button>
  </div>`;
}

/* ── Weekly Digest Export ─────────────────────────────────────────────────── */
function exportWeeklyDigest() {
  const data = state.analysisData;
  const ws   = state.activeWorkspace;
  if (!data || !ws) return;

  const events     = data.events     || [];
  const detections = data.detections || [];
  const summaries  = data.userSummaries || [];
  const homeCountry = data.homeCountry || 'ID';
  const home = homeCountry.toUpperCase();
  const now = new Date().toLocaleString('en-GB', { dateStyle: 'full', timeStyle: 'short' });
  const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const fmt = d => { try { return new Date(d).toLocaleString('en-GB',{dateStyle:'medium',timeStyle:'short'}); } catch { return d||''; } };

  const critUsers = summaries.filter(s => s.riskLevel === 'CRITICAL');
  const highUsers = summaries.filter(s => s.riskLevel === 'HIGH');
  const medUsers  = summaries.filter(s => s.riskLevel === 'MEDIUM');
  const foreignSucc = events.filter(e => e.success  && e.country && e.country.toUpperCase() !== home).length;
  const foreignFail = events.filter(e => !e.success && e.country && e.country.toUpperCase() !== home).length;

  // Top 5 attacking countries by event count
  const countryCounts = {};
  for (const e of events) {
    if (e.country && e.country.toUpperCase() !== home) countryCounts[e.country] = (countryCounts[e.country] || 0) + 1;
  }
  const topCountries = Object.entries(countryCounts).sort((a,b)=>b[1]-a[1]).slice(0, 5);

  // Detection type summary
  const detByType = {};
  for (const d of detections) detByType[d.type] = (detByType[d.type] || 0) + 1;
  const topDets = Object.entries(detByType).sort((a,b)=>b[1]-a[1]).slice(0, 6);

  // CA Remediation hits
  const detTypes = new Set(detections.map(d => d.type));
  const remHits = Object.entries(CA_RECS).filter(([t]) => detTypes.has(t)).slice(0, 4);

  // Campaigns
  const campaigns = groupIntoCampaigns(detections);

  const riskColor = { CRITICAL: '#dc2626', HIGH: '#d97706', MEDIUM: '#2563eb', LOW: '#16a34a' };
  const riskBg    = { CRITICAL: '#fef2f2', HIGH: '#fffbeb', MEDIUM: '#eff6ff', LOW: '#f0fdf4' };
  const riskBorder = { CRITICAL: '#fecaca', HIGH: '#fde68a', MEDIUM: '#bfdbfe', LOW: '#bbf7d0' };

  const userCards = [...critUsers, ...highUsers].slice(0, 8).map(s => `
    <div style="border:1px solid ${riskBorder[s.riskLevel]||'#e2e8f0'};border-left:4px solid ${riskColor[s.riskLevel]||'#94a3b8'};border-radius:8px;padding:14px 16px;margin-bottom:10px;background:${riskBg[s.riskLevel]||'#f8fafc'}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <div>
          <span style="font-weight:700;font-size:14px;color:#0f172a">${esc(s.displayName)}</span>
          <span style="font-size:11px;color:#64748b;margin-left:6px">${esc(s.user)}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          ${s.riskScore != null ? `<span style="font-size:13px;font-weight:800;color:${riskColor[s.riskLevel]}">${s.riskScore}/100</span>` : ''}
          <span style="font-size:11px;font-weight:700;padding:3px 8px;border-radius:4px;background:${riskColor[s.riskLevel]};color:#fff">${esc(s.riskLevel)}</span>
        </div>
      </div>
      <div style="font-size:12px;color:#334155;margin-bottom:6px">${esc(s.primaryThreat)} · ${s.foreignAttempts} foreign failed · ${s.uniqueAttackingCountries} countries</div>
      ${s.narrative ? `<div style="font-size:11.5px;color:#475569;font-style:italic;line-height:1.5">${esc(s.narrative)}</div>` : ''}
    </div>`).join('');

  const countryRows = topCountries.map(([c, n]) => `
    <tr style="border-bottom:1px solid #f1f5f9">
      <td style="padding:7px 12px;font-weight:600;color:#0f172a;font-size:12.5px">${esc(c)}</td>
      <td style="padding:7px 12px;text-align:right;font-weight:700;color:#dc2626;font-size:13px">${n}</td>
    </tr>`).join('');

  const detRows = topDets.map(([t, n]) => `
    <tr style="border-bottom:1px solid #f1f5f9">
      <td style="padding:7px 12px;font-size:12px;color:#334155">${esc(t.replace(/_/g,' '))}</td>
      <td style="padding:7px 12px;text-align:right;font-weight:700;color:#0f172a;font-size:13px">${n}</td>
    </tr>`).join('');

  const remRows = remHits.map(([t, r]) => `
    <div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid #f1f5f9">
      <span style="font-size:16px">${r.icon}</span>
      <div><div style="font-size:12.5px;font-weight:600;color:#0f172a">${esc(r.title)}</div><div style="font-size:11.5px;color:#64748b">${esc(r.action)}</div></div>
    </div>`).join('');

  const campaignSection = campaigns.length >= 2 ? `
    <div style="margin-bottom:28px">
      <div style="font-size:14px;font-weight:700;color:#0f172a;padding-bottom:8px;border-bottom:2px solid #e2e8f0;margin-bottom:12px">⚡ Attack Campaigns Detected</div>
      ${campaigns.slice(0, 3).map((c, i) => `
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:10px 14px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
          <div>
            <span style="font-size:11px;font-weight:700;color:#6366f1;margin-right:8px">CAMPAIGN ${i+1}</span>
            <span style="font-size:12px;color:#334155">${c.detections.length} detections · ${c.users.length} users · ${c.ips.length} IPs</span>
          </div>
          <div style="font-size:11px;color:#64748b">${c.types.slice(0,3).map(t=>t.replace(/_/g,' ')).join(' · ')}</div>
        </div>`).join('')}
    </div>` : '';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>EIDSA Security Digest — ${esc(ws.name)}</title>
  <style>
    * { box-sizing:border-box; margin:0; padding:0; }
    body { font-family:'Segoe UI',system-ui,Arial,sans-serif; background:#f1f5f9; color:#0f172a; }
    .container { max-width:760px; margin:0 auto; background:#fff; }
    @media print { body { background:#fff; } @page { margin:1.5cm 2cm; } }
  </style>
</head>
<body>
<div class="container">
  <!-- Header -->
  <div style="background:linear-gradient(135deg,#0f172a,#1e1b4b);color:#fff;padding:24px 32px;display:flex;justify-content:space-between;align-items:center">
    <div>
      <div style="font-size:24px;font-weight:900;letter-spacing:4px;color:#7cb3ff;font-style:italic">EIDSA</div>
      <div style="font-size:12px;color:#94a3b8;margin-top:2px">Security Digest — ${esc(ws.name)}</div>
    </div>
    <div style="text-align:right;font-size:11px;color:#64748b">
      <div>Generated ${esc(now)}</div>
      <div>PT Sigma Cipta Caraka — Telkomsigma</div>
    </div>
  </div>

  <div style="padding:28px 32px">
    <!-- KPI row -->
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:28px">
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:14px;text-align:center">
        <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Critical Accounts</div>
        <div style="font-size:32px;font-weight:900;color:#dc2626">${critUsers.length}</div>
      </div>
      <div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:14px;text-align:center">
        <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">High Risk</div>
        <div style="font-size:32px;font-weight:900;color:#d97706">${highUsers.length}</div>
      </div>
      <div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:14px;text-align:center">
        <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Foreign Success</div>
        <div style="font-size:32px;font-weight:900;color:#dc2626">${foreignSucc}</div>
      </div>
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;text-align:center">
        <div style="font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">Foreign Failed</div>
        <div style="font-size:32px;font-weight:900;color:#475569">${foreignFail}</div>
      </div>
    </div>

    <!-- User risk cards -->
    ${(critUsers.length + highUsers.length) > 0 ? `
    <div style="margin-bottom:28px">
      <div style="font-size:14px;font-weight:700;color:#0f172a;padding-bottom:8px;border-bottom:2px solid #e2e8f0;margin-bottom:12px">🚨 Accounts Requiring Immediate Action</div>
      ${userCards}
    </div>` : ''}

    ${campaignSection}

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-bottom:28px">
      <!-- Top attacking countries -->
      <div>
        <div style="font-size:13px;font-weight:700;color:#0f172a;margin-bottom:8px;padding-bottom:6px;border-bottom:2px solid #e2e8f0">📍 Top Attacking Countries</div>
        <table style="width:100%;border-collapse:collapse">
          <thead><tr style="background:#f8fafc"><th style="padding:6px 12px;text-align:left;font-size:10px;text-transform:uppercase;color:#64748b">Country</th><th style="padding:6px 12px;text-align:right;font-size:10px;text-transform:uppercase;color:#64748b">Events</th></tr></thead>
          <tbody>${countryRows || '<tr><td colspan="2" style="padding:10px 12px;color:#94a3b8;font-size:12px">No foreign events</td></tr>'}</tbody>
        </table>
      </div>
      <!-- Detection types -->
      <div>
        <div style="font-size:13px;font-weight:700;color:#0f172a;margin-bottom:8px;padding-bottom:6px;border-bottom:2px solid #e2e8f0">🔍 Top Threat Types</div>
        <table style="width:100%;border-collapse:collapse">
          <thead><tr style="background:#f8fafc"><th style="padding:6px 12px;text-align:left;font-size:10px;text-transform:uppercase;color:#64748b">Type</th><th style="padding:6px 12px;text-align:right;font-size:10px;text-transform:uppercase;color:#64748b">Count</th></tr></thead>
          <tbody>${detRows || '<tr><td colspan="2" style="padding:10px 12px;color:#94a3b8;font-size:12px">No detections</td></tr>'}</tbody>
        </table>
      </div>
    </div>

    <!-- CA Remediation hits -->
    ${remHits.length > 0 ? `
    <div style="margin-bottom:28px">
      <div style="font-size:13px;font-weight:700;color:#0f172a;margin-bottom:10px;padding-bottom:6px;border-bottom:2px solid #e2e8f0">🛡️ Recommended CA Policy Actions</div>
      ${remRows}
    </div>` : ''}

    <!-- Footer -->
    <div style="padding-top:16px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;font-size:9.5px;color:#94a3b8">
      <span>©2025 PT Sigma Cipta Caraka — Telkomsigma. CONFIDENTIAL.</span>
      <span>EIDSA by JoshuaDjuk · Workspace: ${esc(ws.name)}</span>
    </div>
  </div>
</div>
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `EIDSA_Digest_${ws.name.replace(/\W+/g,'_')}_${new Date().toISOString().slice(0,10)}.html`;
  a.click();
  URL.revokeObjectURL(url);
  toast('<i class="bi bi-envelope"></i> Weekly Digest exported', 'ok');
}

/* ── Sparkline helper ─────────────────────────────────────────────────────── */
function buildDetSparkline(det) {
  const events = state.analysisData?.events || [];
  const now = Date.now();
  const DAY = 86400000;
  // Collect events relevant to this detection
  let relevant = events;
  if (det.user) relevant = events.filter(e => e.userPrincipal === det.user);
  else if (det.ip) relevant = events.filter(e => e.ipAddress === det.ip);
  if (!relevant.length) return '';

  // Count events per day for last 7 days
  const buckets = Array(7).fill(0);
  relevant.forEach(e => {
    const t = new Date(e.createdAt).getTime();
    const daysAgo = Math.floor((now - t) / DAY);
    if (daysAgo >= 0 && daysAgo < 7) buckets[6 - daysAgo]++;
  });
  if (buckets.every(v => v === 0)) return '';

  const max = Math.max(...buckets, 1);
  const W = 70, H = 20, pad = 2;
  const pts = buckets.map((v, i) => {
    const x = pad + (i / 6) * (W - pad * 2);
    const y = H - pad - ((v / max) * (H - pad * 2));
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');

  return `<svg class="det-sparkline" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" title="Events last 7 days">
    <polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linejoin="round"/>
    ${buckets.map((v, i) => {
      const x = pad + (i / 6) * (W - pad * 2);
      const y = H - pad - ((v / max) * (H - pad * 2));
      return v > 0 ? `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2" fill="var(--accent)"/>` : '';
    }).join('')}
  </svg>`;
}

/* ── Radar Chart (per user risk card) ─────────────────────────────────────── */
function initAllRadarCharts() {
  const summaries = state.analysisData?.userSummaries || [];
  summaries.forEach(s => {
    // find canvas by looking at all rc-radar-canvas elements and matching data
    document.querySelectorAll('.rc-radar-canvas').forEach(canvas => {
      if (canvas.dataset.init) return;
      canvas.dataset.init = '1';
      const cardId = canvas.id.replace('radar-', '');

      // Compute 6 axes from detections and stats
      const dets = s.detections || [];
      // Only init the canvas that belongs to this summary — match by checking nearby rc-name text
      const card = canvas.closest('.risk-card');
      if (!card) return;
      const nameEl = card.querySelector('.rc-name');
      if (!nameEl || nameEl.textContent.trim() !== s.displayName) return;

      const hasType = (...types) => dets.some(d => types.includes(d.type)) ? 1 : 0;
      const geoRisk    = Math.min((s.uniqueAttackingCountries || 0) / 5, 1);
      const authFail   = Math.min((s.foreignAttempts || 0) / 50, 1);
      const sprayBrute = hasType('PASSWORD_SPRAY', 'BRUTE_FORCE', 'DISTRIBUTED_BRUTE_FORCE');
      const legacyMfa  = hasType('LEGACY_AUTH', 'MFA_EXHAUSTION', 'MFA_METHOD_DOWNGRADE', 'CA_GAP');
      const deviceGeo  = hasType('DEVICE_FINGERPRINT_ANOMALY', 'IMPOSSIBLE_TRAVEL', 'CONCURRENT_SESSIONS');
      const persistence = hasType('TOKEN_REPLAY', 'OAUTH_CONSENT_PHISHING', 'RARE_APP_ACCESS', 'FOREIGN_LOGIN') ? 1 : Math.min((s.foreignSuccess || 0) / 3, 1);

      const existing = Chart.getChart(canvas);
      if (existing) existing.destroy();

      new Chart(canvas, {
        type: 'radar',
        data: {
          labels: ['Geo', 'Auth Fail', 'Spray/Brute', 'Legacy/MFA', 'Device/Travel', 'Persistence'],
          datasets: [{
            data: [geoRisk, authFail, sprayBrute, legacyMfa, deviceGeo, persistence],
            backgroundColor: 'rgba(99,102,241,0.15)',
            borderColor: 'rgba(99,102,241,0.8)',
            borderWidth: 1.5,
            pointBackgroundColor: 'rgba(99,102,241,0.9)',
            pointRadius: 2,
          }]
        },
        options: {
          responsive: false,
          animation: false,
          scales: {
            r: {
              min: 0, max: 1,
              ticks: { display: false, stepSize: 0.5 },
              grid: { color: 'rgba(128,128,128,0.2)' },
              angleLines: { color: 'rgba(128,128,128,0.2)' },
              pointLabels: { font: { size: 8 }, color: 'var(--text2)' }
            }
          },
          plugins: { legend: { display: false } }
        }
      });
    });
  });
}

/* ── Timeline Swimlane ────────────────────────────────────────────────────── */
function initSwimlane() {
  const el = document.getElementById('swimlane-container');
  if (!el) return;
  const data = state.analysisData;
  if (!data) { el.innerHTML = '<p style="padding:20px;color:var(--text2)">No analysis data.</p>'; return; }

  const events  = data.events || [];
  const summaries = (data.userSummaries || []).slice(0, 20); // top 20 users
  if (!summaries.length) { el.innerHTML = '<p style="padding:20px;color:var(--text2)">No user data.</p>'; return; }

  // Time range
  const times = events.map(e => new Date(e.createdAt).getTime()).filter(t => !isNaN(t));
  if (!times.length) { el.innerHTML = '<p style="padding:20px;color:var(--text2)">No timestamped events.</p>'; return; }
  const tMin = Math.min(...times), tMax = Math.max(...times);
  const tRange = tMax - tMin || 1;

  const ROW_H = 32, PAD_LEFT = 180, PAD_RIGHT = 20, PAD_TOP = 40, DOT_R = 4;
  const W = Math.max(800, el.clientWidth || 900);
  const svgW = W - 4;
  const svgH = PAD_TOP + summaries.length * ROW_H + 20;

  // Build event index by user
  const byUser = {};
  events.forEach(e => {
    const u = e.userPrincipal;
    if (!byUser[u]) byUser[u] = [];
    byUser[u].push(e);
  });

  // Detection index by user
  const detByUser = {};
  (data.detections || []).forEach(d => {
    if (d.user) {
      if (!detByUser[d.user]) detByUser[d.user] = [];
      detByUser[d.user].push(d);
    }
  });

  const xOf = t => PAD_LEFT + ((t - tMin) / tRange) * (svgW - PAD_LEFT - PAD_RIGHT);

  // Time axis ticks
  const tickCount = 6;
  const ticks = Array.from({length: tickCount + 1}, (_, i) => {
    const t = tMin + (i / tickCount) * tRange;
    const x = xOf(t);
    const label = new Date(t).toLocaleDateString('en-GB', { month: 'short', day: 'numeric' });
    return `<line x1="${x.toFixed(1)}" y1="${PAD_TOP - 5}" x2="${x.toFixed(1)}" y2="${svgH - 10}" stroke="var(--border)" stroke-width="0.5"/>
      <text x="${x.toFixed(1)}" y="${PAD_TOP - 8}" text-anchor="middle" font-size="9" fill="var(--text2)">${label}</text>`;
  }).join('');

  const rows = summaries.map((s, i) => {
    const y = PAD_TOP + i * ROW_H + ROW_H / 2;
    const userEvents = byUser[s.user] || [];
    const userDets   = detByUser[s.user] || [];

    // Lane line
    const lane = `<line x1="${PAD_LEFT}" y1="${y}" x2="${svgW - PAD_RIGHT}" y2="${y}" stroke="var(--border)" stroke-width="0.5"/>`;

    // User label
    const label = `<text x="${PAD_LEFT - 8}" y="${y + 4}" text-anchor="end" font-size="10" fill="var(--text1)" font-weight="500">${escHtml(s.displayName.slice(0, 22))}</text>`;

    // Risk badge color
    const riskCol = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e' }[s.riskLevel] || '#6b7280';
    const badge = `<rect x="2" y="${y - 8}" width="8" height="16" rx="2" fill="${riskCol}"/>`;

    // Event dots
    const dots = userEvents.map(e => {
      const t = new Date(e.createdAt).getTime();
      if (isNaN(t)) return '';
      const x = xOf(t);
      const col = e.success ? '#22c55e' : '#ef4444';
      const tip = `${e.appName||''} ${e.country||''} ${e.success?'✓':'✗'}`.trim();
      return `<circle cx="${x.toFixed(1)}" cy="${y}" r="${DOT_R}" fill="${col}" fill-opacity="0.7" stroke="${col}" stroke-width="0.5">
        <title>${escHtml(tip)}</title></circle>`;
    }).join('');

    // Detection markers (diamond)
    const detMarks = userDets.map(d => {
      // Use first event time for detection
      const evs = byUser[d.user] || [];
      const firstT = evs.length ? Math.min(...evs.map(e => new Date(e.createdAt).getTime()).filter(t => !isNaN(t))) : tMin;
      const x = xOf(firstT);
      const size = 6;
      const pts = `${x},${y - size} ${x + size},${y} ${x},${y + size} ${x - size},${y}`;
      return `<polygon points="${pts}" fill="#f59e0b" fill-opacity="0.9" stroke="#d97706" stroke-width="0.5">
        <title>${escHtml(d.type.replace(/_/g,' '))}: ${escHtml(d.message?.slice(0,80)||'')}</title></polygon>`;
    }).join('');

    return badge + lane + label + dots + detMarks;
  }).join('');

  // Legend
  const legend = `
    <circle cx="${PAD_LEFT + 10}" cy="14" r="4" fill="#22c55e"/>
    <text x="${PAD_LEFT + 18}" y="18" font-size="9" fill="var(--text2)">Success</text>
    <circle cx="${PAD_LEFT + 70}" cy="14" r="4" fill="#ef4444"/>
    <text x="${PAD_LEFT + 78}" y="18" font-size="9" fill="var(--text2)">Failure</text>
    <polygon points="${PAD_LEFT + 134},10 ${PAD_LEFT + 140},14 ${PAD_LEFT + 134},18 ${PAD_LEFT + 128},14" fill="#f59e0b"/>
    <text x="${PAD_LEFT + 144}" y="18" font-size="9" fill="var(--text2)">Detection</text>`;

  el.innerHTML = `
    <div class="swimlane-wrap">
      <h3 style="margin:0 0 8px;font-size:14px;color:var(--text1)">User Activity Swimlane <span style="font-size:11px;color:var(--text2);font-weight:400">— top ${summaries.length} users by risk</span></h3>
      <div style="overflow-x:auto">
        <svg width="${svgW}" height="${svgH}" style="display:block;font-family:inherit">
          ${legend}
          ${ticks}
          ${rows}
        </svg>
      </div>
    </div>`;
}

/* ── Sankey Flow Diagram ──────────────────────────────────────────────────── */
function initSankey() {
  const el = document.getElementById('sankey-container');
  if (!el) return;
  const data = state.analysisData;
  if (!data) { el.innerHTML = '<p style="padding:20px;color:var(--text2)">No analysis data.</p>'; return; }

  const events = data.events || [];
  const homeCountry = (data.homeCountry || 'ID').toUpperCase();
  // Only foreign events
  const foreign = events.filter(e => e.country && e.country.toUpperCase() !== homeCountry);
  if (!foreign.length) { el.innerHTML = '<p style="padding:20px;color:var(--text2)">No foreign events to visualize.</p>'; return; }

  // Build flow: Country → App → Outcome
  // Count flows
  const flowCA = {}; // country → app
  const flowAO = {}; // app → outcome
  foreign.forEach(e => {
    const c = e.country || 'Unknown';
    const a = (e.appName || 'Unknown').slice(0, 30);
    const o = e.success ? 'Success' : 'Failure';
    const keyCA = `${c}||${a}`;
    const keyAO = `${a}||${o}`;
    flowCA[keyCA] = (flowCA[keyCA] || 0) + 1;
    flowAO[keyAO] = (flowAO[keyAO] || 0) + 1;
  });

  // Top 8 countries, top 8 apps
  const countryCounts = {};
  const appCounts = {};
  foreign.forEach(e => {
    const c = e.country || 'Unknown';
    const a = (e.appName || 'Unknown').slice(0, 30);
    countryCounts[c] = (countryCounts[c] || 0) + 1;
    appCounts[a] = (appCounts[a] || 0) + 1;
  });
  const topCountries = Object.entries(countryCounts).sort((a,b) => b[1]-a[1]).slice(0, 8).map(([k]) => k);
  const topApps      = Object.entries(appCounts).sort((a,b) => b[1]-a[1]).slice(0, 8).map(([k]) => k);
  const outcomes     = ['Success', 'Failure'];

  const W = Math.max(800, el.clientWidth || 900) - 4;
  const H = Math.max(topCountries.length, topApps.length) * 40 + 80;
  const COL1 = 20, COL2 = W * 0.38, COL3 = W * 0.68, COL4 = W - 80;
  const NODE_W = 120, NODE_H = 28;

  const colPalette = ['#6366f1','#8b5cf6','#ec4899','#f97316','#eab308','#22c55e','#06b6d4','#f43f5e'];

  // Layout nodes
  const cNodes = topCountries.map((c, i) => ({ label: c, x: COL1, y: 50 + i * 38, count: countryCounts[c] }));
  const aNodes = topApps.map((a, i) => ({ label: a, x: COL2, y: 50 + i * 38, count: appCounts[a] }));
  const oNodes = outcomes.map((o, i) => ({
    label: o, x: COL3, y: 50 + i * 80,
    count: foreign.filter(e => (e.success ? 'Success' : 'Failure') === o).length
  }));

  const totalForeign = foreign.length;
  const maxC = Math.max(...cNodes.map(n => n.count), 1);
  const maxA = Math.max(...aNodes.map(n => n.count), 1);
  const maxO = Math.max(...oNodes.map(n => n.count), 1);

  const barMaxW = 100;

  // Draw curves from countries to apps
  let curves = '';
  cNodes.forEach((cn, ci) => {
    aNodes.forEach((an, ai) => {
      const key = `${cn.label}||${an.label}`;
      const cnt = flowCA[key] || 0;
      if (!cnt) return;
      const w = Math.max(1, (cnt / totalForeign) * 12);
      const x1 = cn.x + NODE_W, y1 = cn.y + NODE_H / 2;
      const x2 = an.x,         y2 = an.y + NODE_H / 2;
      const cx = (x1 + x2) / 2;
      curves += `<path d="M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}"
        fill="none" stroke="${colPalette[ci % colPalette.length]}" stroke-width="${w.toFixed(1)}" stroke-opacity="0.35">
        <title>${escHtml(cn.label)} → ${escHtml(an.label)}: ${cnt}</title></path>`;
    });
  });

  // Draw curves from apps to outcomes
  aNodes.forEach((an, ai) => {
    oNodes.forEach((on) => {
      const key = `${an.label}||${on.label}`;
      const cnt = flowAO[key] || 0;
      if (!cnt) return;
      const w = Math.max(1, (cnt / totalForeign) * 12);
      const x1 = an.x + NODE_W, y1 = an.y + NODE_H / 2;
      const x2 = on.x,          y2 = on.y + NODE_H / 2;
      const cx = (x1 + x2) / 2;
      curves += `<path d="M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}"
        fill="none" stroke="${on.label === 'Success' ? '#22c55e' : '#ef4444'}" stroke-width="${w.toFixed(1)}" stroke-opacity="0.35">
        <title>${escHtml(an.label)} → ${on.label}: ${cnt}</title></path>`;
    });
  });

  // Draw nodes
  const drawNodes = (nodes, maxCount, colOffset) => nodes.map((n, i) => {
    const col = colPalette[i % colPalette.length];
    const barW = (n.count / maxCount) * barMaxW;
    const isOutcome = n.label === 'Success' || n.label === 'Failure';
    const nodeCol = n.label === 'Success' ? '#22c55e' : n.label === 'Failure' ? '#ef4444' : col;
    return `
      <rect x="${n.x}" y="${n.y}" width="${NODE_W}" height="${NODE_H}" rx="4"
        fill="${nodeCol}" fill-opacity="0.15" stroke="${nodeCol}" stroke-width="1"/>
      <text x="${n.x + 6}" y="${n.y + 18}" font-size="10" fill="var(--text1)" font-weight="500">${escHtml(n.label.slice(0,16))}</text>
      <text x="${n.x + NODE_W - 4}" y="${n.y + 18}" font-size="9" fill="${nodeCol}" text-anchor="end">${n.count}</text>`;
  }).join('');

  // Column headers
  const headers = `
    <text x="${COL1 + 60}" y="20" text-anchor="middle" font-size="11" font-weight="600" fill="var(--text2)">Country</text>
    <text x="${COL2 + 60}" y="20" text-anchor="middle" font-size="11" font-weight="600" fill="var(--text2)">Application</text>
    <text x="${COL3 + 60}" y="20" text-anchor="middle" font-size="11" font-weight="600" fill="var(--text2)">Outcome</text>`;

  el.innerHTML = `
    <div class="sankey-wrap">
      <h3 style="margin:0 0 8px;font-size:14px;color:var(--text1)">Foreign Login Flow <span style="font-size:11px;color:var(--text2);font-weight:400">— Country → App → Outcome</span></h3>
      <div style="overflow-x:auto">
        <svg width="${W}" height="${H}" style="display:block;font-family:inherit">
          ${curves}
          ${drawNodes(cNodes, maxC)}
          ${drawNodes(aNodes, maxA)}
          ${drawNodes(oNodes, maxO)}
          ${headers}
        </svg>
      </div>
    </div>`;
}

/* ── Country × App Heat Matrix ────────────────────────────────────────────── */
function initCountryApp() {
  const el = document.getElementById('countryapp-container');
  if (!el) return;
  const data = state.analysisData;
  if (!data) { el.innerHTML = '<p style="padding:20px;color:var(--text2)">No analysis data.</p>'; return; }

  const events = data.events || [];
  const homeCountry = (data.homeCountry || 'ID').toUpperCase();
  const foreign = events.filter(e => e.country && e.country.toUpperCase() !== homeCountry);
  if (!foreign.length) { el.innerHTML = '<p style="padding:20px;color:var(--text2)">No foreign events to display.</p>'; return; }

  // Count by country × app
  const matrix = {}; // matrix[country][app] = { total, success, fail }
  const countryCounts = {}, appCounts = {};
  foreign.forEach(e => {
    const c = e.country || 'Unknown';
    const a = (e.appName || 'Unknown').slice(0, 35);
    countryCounts[c] = (countryCounts[c] || 0) + 1;
    appCounts[a]     = (appCounts[a] || 0) + 1;
    if (!matrix[c]) matrix[c] = {};
    if (!matrix[c][a]) matrix[c][a] = { total: 0, success: 0, fail: 0 };
    matrix[c][a].total++;
    if (e.success) matrix[c][a].success++; else matrix[c][a].fail++;
  });

  const topCountries = Object.entries(countryCounts).sort((a,b) => b[1]-a[1]).slice(0, 15).map(([k]) => k);
  const topApps      = Object.entries(appCounts).sort((a,b) => b[1]-a[1]).slice(0, 12).map(([k]) => k);
  const maxCell = Math.max(1, ...topCountries.flatMap(c => topApps.map(a => (matrix[c]?.[a]?.total || 0))));

  const cellStyle = (c, a) => {
    const cell = matrix[c]?.[a];
    if (!cell) return 'background:transparent';
    const intensity = cell.total / maxCell;
    const successRate = cell.success / cell.total;
    // Color: red for mostly failed, green for mostly success, blended
    const r = Math.round(239 * (1 - successRate) * intensity + 30);
    const g = Math.round(197 * successRate * intensity + 30);
    const b = 30;
    const alpha = 0.15 + intensity * 0.7;
    return `background:rgba(${r},${g},${b},${alpha})`;
  };

  const header = `<tr><th class="cam-th cam-corner">Country \\ App</th>${topApps.map(a =>
    `<th class="cam-th" title="${escHtml(a)}">${escHtml(a.slice(0,14))}${a.length>14?'…':''}</th>`
  ).join('')}</tr>`;

  const bodyRows = topCountries.map(c => {
    const cells = topApps.map(a => {
      const cell = matrix[c]?.[a];
      const style = cellStyle(c, a);
      const tip = cell ? `${cell.total} events (✓${cell.success} ✗${cell.fail})` : '';
      return `<td class="cam-td" style="${style}" title="${escHtml(tip)}">${cell ? cell.total : ''}</td>`;
    }).join('');
    return `<tr><td class="cam-td cam-row-label">${escHtml(c)}<span class="cam-row-total">${countryCounts[c]}</span></td>${cells}</tr>`;
  }).join('');

  el.innerHTML = `
    <div class="countryapp-wrap">
      <h3 style="margin:0 0 8px;font-size:14px;color:var(--text1)">Country × Application Matrix
        <span style="font-size:11px;color:var(--text2);font-weight:400">— foreign login attempts, cell = event count, color = success ratio</span></h3>
      <div style="overflow-x:auto">
        <table class="cam-table">
          <thead>${header}</thead>
          <tbody>${bodyRows}</tbody>
        </table>
      </div>
      <div class="cam-legend">
        <span class="cam-leg-item" style="background:rgba(239,30,30,0.5)">High failure</span>
        <span class="cam-leg-item" style="background:rgba(30,197,30,0.5)">High success</span>
        <span class="cam-leg-item" style="background:rgba(150,150,50,0.35)">Mixed</span>
        <span style="font-size:10px;color:var(--text2)">Intensity = volume</span>
      </div>
    </div>`;
}

/* ── KQL Query Generator ──────────────────────────────────────────────────── */
function generateKQL(det) {
  const esc = s => String(s || '').replace(/"/g, '\\"');
  const dt  = s => s ? s.slice(0, 19).replace('T', ' ') : '';

  const timeFilter = det.windowStart
    ? `| where TimeGenerated between (datetime('${dt(det.windowStart)}') .. datetime('${dt(det.windowEnd || new Date().toISOString())}'))`
    : det.time
    ? `| where TimeGenerated >= datetime('${dt(det.time)}') and TimeGenerated <= datetime('${dt(new Date(new Date(det.time).getTime() + 3600000).toISOString())}')`
    : '';

  switch (det.type) {
    case 'PASSWORD_SPRAY':
      return `// Password Spray — Source IP: ${det.ip}
// Ref: MITRE T1110.003 · Credential Access
SigninLogs
| where IPAddress == "${esc(det.ip)}"
${timeFilter}
| where ResultType != 0
| summarize
    TargetedUsers  = dcount(UserPrincipalName),
    AttemptCount   = count(),
    UserList       = make_set(UserPrincipalName, 50),
    ErrorCodes     = make_set(ResultType, 10)
    by IPAddress, Location, bin(TimeGenerated, 5m)
| where TargetedUsers >= 5
| order by TimeGenerated asc`;

    case 'BRUTE_FORCE':
      return `// Brute Force — Target User: ${det.user}
// Ref: MITRE T1110.001 · Credential Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
${timeFilter}
| where ResultType != 0
| summarize
    AttemptCount = count(),
    UniqueIPs    = dcount(IPAddress),
    IPList       = make_set(IPAddress, 20),
    ErrorCodes   = make_set(ResultType, 10)
    by UserPrincipalName, bin(TimeGenerated, 10m)
| where AttemptCount >= 10
| order by TimeGenerated asc`;

    case 'IMPOSSIBLE_TRAVEL':
      return `// Impossible Travel — User: ${det.user}
// Ref: MITRE T1078 · Defense Evasion
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, AuthenticationRequirement, CorrelationId
| order by TimeGenerated asc
// Look for successive logins from: ${det.from?.country} → ${det.to?.country}`;

    case 'FOREIGN_LOGIN':
      return `// Foreign Login — User: ${det.user}
// Ref: MITRE T1078 · Initial Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| where Location != "${esc(det.homeCountry)}"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, ClientAppUsed, AuthenticationRequirement
| order by TimeGenerated asc`;

    case 'MFA_EXHAUSTION':
      return `// MFA Exhaustion / Fatigue — User: ${det.user}
// Ref: MITRE T1621 · Credential Access
let MFAErrors = dynamic([50076, 500121, 50074, 53003, 50158]);
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
${timeFilter}
| where ResultType in (MFAErrors)
| summarize
    PromptCount = count(),
    UniqueIPs   = dcount(IPAddress),
    IPList      = make_set(IPAddress, 10)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| order by TimeGenerated asc`;

    case 'TOKEN_REPLAY':
      return `// Token Replay / Session Hijack — User: ${det.user}
// Ref: MITRE T1550.001 · Lateral Movement
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
${timeFilter}
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, CorrelationId, UniqueTokenIdentifier
| order by TimeGenerated asc
// Pivot: check for same CorrelationId from multiple IPs`;

    case 'LEGACY_AUTH':
      return `// Legacy Authentication Bypass — User: ${det.user}
// Ref: MITRE T1078.004 · Persistence
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ClientAppUsed in~ ("Exchange ActiveSync", "IMAP", "POP3", "SMTP Auth", "MAPI", "AutoDiscover")
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          ClientAppUsed, AppDisplayName, ResultType
| order by TimeGenerated asc`;

    case 'CA_GAP':
      return `// Conditional Access Gap — User: ${det.user}
// Ref: MITRE T1556.006 · Defense Evasion
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| where ConditionalAccessStatus == "notApplied"
| where IsInteractive == true
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, ConditionalAccessStatus, AuthenticationRequirement
| order by TimeGenerated asc`;

    case 'ENUMERATION_ATTACK':
      return `// Account Enumeration (error 50034) — Source IP: ${det.ip}
// Ref: MITRE T1087.002 · Discovery
SigninLogs
| where IPAddress == "${esc(det.ip)}"
${timeFilter}
| where ResultType == 50034
| summarize
    EnumeratedUsers = dcount(UserPrincipalName),
    UserList        = make_set(UserPrincipalName, 50),
    AttemptCount    = count()
    by IPAddress, Location, bin(TimeGenerated, 1h)
| order by TimeGenerated asc`;

    case 'SERVICE_PRINCIPAL_ANOMALY':
      return `// Service Principal Anomaly — SP: ${det.user}
// Ref: MITRE T1528 · Credential Access
AADServicePrincipalSignInLogs
| where ServicePrincipalName == "${esc(det.user)}"
| where ResultType == 0
| project TimeGenerated, ServicePrincipalName, IPAddress, Location,
          AppDisplayName, ResourceDisplayName, CorrelationId
| order by TimeGenerated asc`;

    case 'ADMIN_TOOL_ABUSE':
      return `// Admin Tool Abuse — User: ${det.user}
// Ref: MITRE T1059.009 · Execution
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| where ClientAppUsed has_any ("PowerShell", "Azure CLI")
    or AppDisplayName has_any ("Azure CLI", "Azure PowerShell", "Graph Explorer", "Azure Portal")
| where Location != "${esc(det.homeCountry || '')}"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, ClientAppUsed, AuthenticationRequirement
| order by TimeGenerated asc`;

    case 'CONCURRENT_SESSIONS':
      return `// Concurrent Sessions — User: ${det.user}
// Ref: MITRE T1550 · Lateral Movement
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
${timeFilter}
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, CorrelationId
| order by TimeGenerated asc
// Flag if same user logged in from: ${(det.countries || []).join(', ')}`;

    case 'FIRST_SEEN_COUNTRY':
      return `// First-Seen Country — User: ${det.user}
// Ref: MITRE T1078 · Initial Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| where Location == "${esc(det.country)}"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, AuthenticationRequirement
| order by TimeGenerated asc`;

    case 'TIME_OF_DAY_ANOMALY':
      return `// Off-Hours Login — User: ${det.user}
// Ref: MITRE T1078 · Initial Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| extend HourUTC = hourofday(TimeGenerated)
| where HourUTC == ${det.anomalousHour ?? 'todynamic(null)'}
| project TimeGenerated, HourUTC, UserPrincipalName, IPAddress, Location,
          AppDisplayName, AuthenticationRequirement
| order by TimeGenerated asc`;

    case 'RARE_APP_ACCESS':
      return `// Rare App Access — User: ${det.user}, App: ${det.app}
// Ref: MITRE T1550.001 · Lateral Movement
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where AppDisplayName == "${esc(det.app)}"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, ClientAppUsed, AuthenticationRequirement
| order by TimeGenerated asc`;

    case 'CREDENTIAL_STUFFING':
      return `// Credential Stuffing — Source IP: ${det.ip}
// Ref: MITRE T1110.004 · Credential Access
SigninLogs
| where IPAddress == "${esc(det.ip)}"
${timeFilter}
| where ResultType != 0
| summarize
    TargetedAccounts = dcount(UserPrincipalName),
    AttemptCount     = count(),
    AccountList      = make_set(UserPrincipalName, 50),
    ErrorCodes       = make_set(ResultType, 10)
    by IPAddress, Location, bin(TimeGenerated, 1h)
| where TargetedAccounts >= 8
| order by TimeGenerated asc`;

    case 'DEVICE_FINGERPRINT_ANOMALY':
      return `// Device Fingerprint Anomaly — User: ${det.user}
// Ref: MITRE T1078.004 · Initial Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where UserAgent == "${esc(det.userAgent)}"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, UserAgent, AuthenticationRequirement
| order by TimeGenerated asc`;

    case 'OAUTH_CONSENT_PHISHING':
      return `// OAuth Consent Phishing — User: ${det.user}, App: ${det.app}
// Ref: MITRE T1528 · Credential Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where AppDisplayName == "${esc(det.app)}"
| where ResultType == 0
| where IsInteractive == true
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, ConditionalAccessStatus, AuthenticationRequirement
| order by TimeGenerated asc
// Also check: AuditLogs | where OperationName == "Consent to application"`;

    default:
      return `// ${det.type.replace(/_/g, ' ')}
SigninLogs
| where UserPrincipalName == "${esc(det.user || '')}"
${timeFilter}
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType
| order by TimeGenerated asc`;
  }
}

function showKQLPanel(detJson) {
  document.getElementById('kql-panel-overlay')?.remove();
  const det = JSON.parse(detJson);
  const kql = generateKQL(det);
  const mitre = MITRE_MAP[det.type];

  const overlay = document.createElement('div');
  overlay.id = 'kql-panel-overlay';
  overlay.innerHTML = `
    <div id="kql-panel">
      <div class="kql-header">
        <div>
          <div class="kql-title">${det.type.replace(/_/g, ' ')}</div>
          <div class="kql-subtitle">${mitre ? `ATT&CK ${mitre.id} · ${mitre.tactic}` : 'KQL Query'}</div>
        </div>
        <button class="kql-close" onclick="closeKQLPanel()"><i class="bi bi-x-lg"></i></button>
      </div>
      <div class="kql-context">${escHtml(det.message)}</div>
      <div class="kql-body">
        <div class="kql-toolbar">
          <span class="kql-label">Microsoft Sentinel · Log Analytics</span>
          <button class="kql-copy-btn" id="kql-copy-btn" onclick="copyKQL()"><i class="bi bi-clipboard"></i> Copy KQL</button>
        </div>
        <pre class="kql-code" id="kql-code-block">${escHtml(kql)}</pre>
      </div>
      <div class="kql-footer">
        Run in: <a href="https://portal.azure.com/#view/Microsoft_OperationsManagementSuite_Workspace" target="_blank" rel="noopener" style="color:var(--accent)">Azure Portal → Log Analytics</a>
      </div>
    </div>`;
  overlay.addEventListener('click', e => { if (e.target === overlay) closeKQLPanel(); });
  document.body.appendChild(overlay);
}

function closeKQLPanel() {
  document.getElementById('kql-panel-overlay')?.remove();
}

function copyKQL() {
  const code = document.getElementById('kql-code-block')?.textContent || '';
  navigator.clipboard.writeText(code).then(() => {
    const btn = document.getElementById('kql-copy-btn');
    if (btn) { btn.innerHTML = '<i class="bi bi-check-lg"></i> Copied!'; setTimeout(() => { btn.innerHTML = '<i class="bi bi-clipboard"></i> Copy KQL'; }, 2000); }
  });
}

/* ── Incident Summary Export ──────────────────────────────────────────────── */
function exportUserIncident(userPrincipal) {
  const data = state.analysisData;
  if (!data) return;

  const summary = (data.userSummaries || []).find(s => s.user === userPrincipal);
  if (!summary) return;

  const events     = data.events     || [];
  const detections = data.detections || [];
  const homeCountry = data.homeCountry || 'ID';
  const now = new Date().toLocaleString('en-GB', { dateStyle: 'long', timeStyle: 'short' });
  const ws  = state.activeWorkspace;

  // User's detections (where they're the primary user or in affectedUsers)
  const userDets = detections.filter(d =>
    d.user === userPrincipal ||
    (d.affectedUsers && d.affectedUsers.includes(userPrincipal))
  );

  // User's events
  const userEvents = events
    .filter(e => e.userPrincipal === userPrincipal)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  // IOCs
  const iocIPs = [...new Set(userEvents.map(e => e.ipAddress).filter(Boolean))].slice(0, 20);
  const iocCountries = [...new Set(userEvents.filter(e => e.country !== homeCountry).map(e => e.country).filter(Boolean))];

  // MITRE tactics triggered
  const tacticsMap = {};
  for (const d of userDets) {
    const m = MITRE_MAP[d.type];
    if (!m) continue;
    if (!tacticsMap[m.tactic]) tacticsMap[m.tactic] = { ids: new Set(), sev: 'low' };
    tacticsMap[m.tactic].ids.add(m.id);
    if (d.severity === 'high') tacticsMap[m.tactic].sev = 'high';
    else if (d.severity === 'medium' && tacticsMap[m.tactic].sev !== 'high') tacticsMap[m.tactic].sev = 'medium';
  }

  // Recommendations based on detection types
  const REC_MAP = {
    PASSWORD_SPRAY:            'Block source IP at firewall/CA. Enable Microsoft Entra Smart Lockout. Review account lockout threshold.',
    BRUTE_FORCE:               'Enable account lockout policy. Enforce MFA. Consider Conditional Access sign-in frequency limits.',
    CREDENTIAL_STUFFING:       'Block source IP range. Enable leaked credential detection in Identity Protection. Enforce MFA.',
    MFA_EXHAUSTION:            'Enable MFA number matching & additional context. Configure MFA fraud alert. Investigate MFA prompts for this user.',
    LEGACY_AUTH:               'Create Conditional Access policy to block legacy authentication protocols (IMAP, POP3, SMTP Auth, EAS).',
    CA_GAP:                    'Expand Conditional Access policies to cover all interactive sign-ins. Enforce MFA for all locations.',
    TOKEN_REPLAY:              'Revoke all active sessions via Entra ID. Enable Continuous Access Evaluation (CAE). Rotate refresh tokens.',
    IMPOSSIBLE_TRAVEL:         'Review session for legitimacy. Enable Impossible Travel risk policy in Identity Protection.',
    CONCURRENT_SESSIONS:       'Revoke sessions immediately. Investigate token theft. Enable Conditional Access token protection.',
    FOREIGN_LOGIN:             'Verify with user if login is legitimate. Create location-based CA policy for trusted locations.',
    ADMIN_TOOL_ABUSE:          'Require PIM/PAM activation for admin tools. Enable JIT access. Alert on PowerShell/CLI from untrusted locations.',
    ENUMERATION_ATTACK:        'Enable Smart Lockout. Block source IP. Consider rate limiting on authentication endpoint.',
    SERVICE_PRINCIPAL_ANOMALY: 'Audit service principal permissions. Rotate credentials. Check for unauthorized app registrations.',
    FIRST_SEEN_COUNTRY:        'Verify with user. Add trusted countries to workspace or create location-based CA policy.',
    TIME_OF_DAY_ANOMALY:       'Verify with user. Consider sign-in hour restrictions via CA policy or Identity Protection.',
    RARE_APP_ACCESS:           'Audit OAuth app permissions. Verify consent was legitimate. Review app in Entra ID Enterprise Apps.',
    DEVICE_FINGERPRINT_ANOMALY:'Verify with user if new device is legitimate. Require device compliance via Intune/CA.',
    OAUTH_CONSENT_PHISHING:    'Revoke consent for suspicious app in Entra ID. Audit OAuth permissions. Enable admin consent workflow.',
  };

  const uniqueRecKeys = [...new Set(userDets.map(d => d.type))];
  const recs = uniqueRecKeys.map(t => REC_MAP[t]).filter(Boolean);

  const riskColor = { CRITICAL: '#dc2626', HIGH: '#d97706', MEDIUM: '#2563eb', LOW: '#16a34a' };
  const sevColor  = s => s === 'high' ? '#dc2626' : s === 'medium' ? '#d97706' : '#2563eb';
  const esc = str => String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  const tacticPills = Object.entries(tacticsMap).map(([tac, info]) => {
    const col = sevColor(info.sev);
    return `<span style="background:${col}20;border:1px solid ${col}60;color:${col};
      border-radius:4px;padding:3px 10px;font-size:10px;font-weight:700;white-space:nowrap">
      ${esc(tac)} (${[...info.ids].join(', ')})
    </span>`;
  }).join('');

  const detRows = userDets.map(d => {
    const m = MITRE_MAP[d.type];
    return `<tr>
      <td><span style="background:${sevColor(d.severity)};color:#fff;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700">${esc(d.severity.toUpperCase())}</span></td>
      <td style="font-weight:600;font-size:11px">${esc(d.type.replace(/_/g,' '))}</td>
      <td>${m ? `<span style="background:#f3f0ff;border:1px solid #c4b5fd;color:#7c3aed;border-radius:3px;padding:1px 5px;font-size:9.5px;font-weight:700">${esc(m.id)}</span>` : '—'}</td>
      <td style="font-size:11px;color:#334155">${esc(d.message)}</td>
    </tr>`;
  }).join('');

  const evRows = userEvents.slice(0, 30).map(e => `<tr>
    <td style="white-space:nowrap;font-size:10px;color:#64748b">${esc(new Date(e.createdAt).toLocaleString('en-GB',{dateStyle:'short',timeStyle:'short'}))}</td>
    <td style="font-family:monospace;font-size:10px">${esc(e.ipAddress)}</td>
    <td>${esc(e.country)}${e.city ? ' / '+esc(e.city.slice(0,16)) : ''}</td>
    <td style="font-size:11px">${esc(e.appName)}</td>
    <td style="text-align:center"><span style="font-size:11px;font-weight:700;color:${e.success?'#16a34a':'#dc2626'}">${e.success ? '✓' : '✗'}</span></td>
    <td style="font-size:10px;color:#64748b">${e.errorCode || ''}</td>
  </tr>`).join('');

  const iocIPRows = iocIPs.map(ip =>
    `<div style="font-family:monospace;font-size:11px;padding:4px 8px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:4px;margin-bottom:4px">${esc(ip)}</div>`
  ).join('');

  const recRows = recs.map((r, i) =>
    `<div style="display:flex;gap:10px;padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:11px">
      <span style="background:#2563eb;color:#fff;border-radius:50%;width:18px;height:18px;display:inline-flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0">${i+1}</span>
      <span style="color:#334155;line-height:1.5">${esc(r)}</span>
    </div>`
  ).join('');

  const rc = riskColor[summary.riskLevel] || '#2563eb';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Incident: ${esc(summary.displayName)}</title>
  <style>
    @page { size: A4; margin: 1.5cm 2cm; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, Arial, sans-serif; font-size: 12px; color: #1e293b; background: #fff; }
    .cover {
      background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%);
      color: #fff; padding: 40px 48px 32px;
      -webkit-print-color-adjust: exact; print-color-adjust: exact;
      margin-bottom: 0;
    }
    .cover-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 28px; }
    .cover-logo { font-size: 32px; font-weight: 900; letter-spacing: 4px; color: #7cb3ff; font-style: italic; }
    .cover-badge { border: 2px solid ${rc}; border-radius: 8px; padding: 8px 18px; text-align: center; }
    .cover-badge-label { font-size: 9px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; }
    .cover-badge-val { font-size: 18px; font-weight: 800; color: ${rc}; margin-top: 3px; }
    .cover-name { font-size: 24px; font-weight: 700; color: #e2e8f0; margin-bottom: 4px; }
    .cover-email { font-size: 13px; color: #64748b; margin-bottom: 20px; }
    .cover-stats { display: flex; gap: 32px; }
    .cs-item .lbl { font-size: 9px; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 3px; }
    .cs-item .val { font-size: 15px; font-weight: 700; color: #e2e8f0; }
    .cover-company { background: rgba(0,0,0,0.3); border-top: 1px solid rgba(255,255,255,0.08); padding: 12px 48px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 32px; }
    .cover-company-name { font-size: 11px; color: #64748b; }
    .cover-company-copy { font-size: 10px; color: #475569; }
    h2 { font-size: 13px; font-weight: 700; color: #0f172a; margin: 24px 0 10px; padding-bottom: 5px; border-bottom: 2px solid #e2e8f0; page-break-after: avoid; }
    h2:first-child { margin-top: 0; }
    table { width: 100%; border-collapse: collapse; font-size: 11px; margin-bottom: 4px; }
    th { background: #f1f5f9; text-align: left; padding: 6px 9px; font-size: 10px; font-weight: 700; color: #475569; border: 1px solid #e2e8f0; text-transform: uppercase; }
    td { padding: 6px 9px; border: 1px solid #e2e8f0; vertical-align: middle; line-height: 1.4; }
    .tactic-pills { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 8px; }
    .section { margin-bottom: 8px; }
    @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
  </style>
</head>
<body>
  <div class="cover">
    <div class="cover-top">
      <div class="cover-logo">EIDSA</div>
      <div class="cover-badge">
        <div class="cover-badge-label">Risk Level</div>
        <div class="cover-badge-val">${esc(summary.riskLevel)}</div>
      </div>
    </div>
    <div class="cover-name">${esc(summary.displayName)}</div>
    <div class="cover-email">${esc(summary.user)}</div>
    <div class="cover-stats">
      <div class="cs-item"><div class="lbl">Foreign Attempts</div><div class="val">${summary.foreignAttempts}</div></div>
      <div class="cs-item"><div class="lbl">Successful Foreign</div><div class="val" style="color:${summary.foreignSuccess>0?'#f87171':'#4ade80'}">${summary.foreignSuccess}</div></div>
      <div class="cs-item"><div class="lbl">Countries</div><div class="val">${summary.uniqueAttackingCountries}</div></div>
      <div class="cs-item"><div class="lbl">Detections</div><div class="val" style="color:#f87171">${userDets.length}</div></div>
      <div class="cs-item"><div class="lbl">Total Events</div><div class="val">${userEvents.length}</div></div>
    </div>
  </div>
  <div class="cover-company">
    <div class="cover-company-name">PT Sigma Cipta Caraka — Telkomsigma</div>
    <div class="cover-company-copy">Incident Report · Generated ${esc(now)} · EIDSA by JoshuaDjuk</div>
  </div>

  <div style="padding: 0 0 32px">
    <h2>Primary Threat</h2>
    <div style="font-size:12px;color:#334155;line-height:1.6;margin-bottom:8px">${esc(summary.primaryThreat)}</div>
    ${summary.narrative ? `<div style="background:#f8fafc;border-left:3px solid ${rc};padding:8px 12px;font-size:11px;color:#334155;line-height:1.6;border-radius:0 4px 4px 0">${esc(summary.narrative)}</div>` : ''}

    ${Object.keys(tacticsMap).length > 0 ? `
    <h2>MITRE ATT&amp;CK Coverage</h2>
    <div class="tactic-pills">${tacticPills}</div>` : ''}

    ${userDets.length > 0 ? `
    <h2>Detections (${userDets.length})</h2>
    <table>
      <thead><tr><th style="width:68px">Sev</th><th style="width:150px">Type</th><th style="width:90px">MITRE</th><th>Message</th></tr></thead>
      <tbody>${detRows}</tbody>
    </table>` : ''}

    ${recs.length > 0 ? `
    <h2>Recommended Actions</h2>
    <div>${recRows}</div>` : ''}

    ${iocIPs.length > 0 ? `
    <h2>IOC — Source IPs (${iocIPs.length})</h2>
    <div style="display:flex;flex-wrap:wrap;gap:6px">${iocIPRows}</div>` : ''}

    ${iocCountries.length > 0 ? `
    <h2>IOC — Foreign Countries</h2>
    <div style="display:flex;flex-wrap:wrap;gap:6px">${iocCountries.map(c=>`<span style="background:#f1f5f9;border:1px solid #e2e8f0;padding:2px 8px;border-radius:4px;font-size:11px">${esc(c)}</span>`).join('')}</div>` : ''}

    ${userEvents.length > 0 ? `
    <h2>Sign-in Log (last ${Math.min(30, userEvents.length)} events)</h2>
    <table>
      <thead><tr><th>Time</th><th>IP Address</th><th>Location</th><th>App</th><th>Status</th><th>Error</th></tr></thead>
      <tbody>${evRows}</tbody>
    </table>` : ''}

    <div style="margin-top:32px;padding-top:12px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;font-size:9.5px;color:#94a3b8">
      <span>©2025 PT Sigma Cipta Caraka — Telkomsigma. All Rights Reserved.</span>
      <span>EIDSA · Developed by JoshuaDjuk · Workspace: ${esc(ws?.name || '')}</span>
    </div>
  </div>
  <script>window.onload = () => window.print();<\/script>
</body>
</html>`;

  const win = window.open('', '_blank');
  if (!win) { alert('Popup blocked — allow popups for this page.'); return; }
  win.document.write(html);
  win.document.close();
}

/* ── Session Replay Export ────────────────────────────────────────────────── */
function exportSessionReplay(userPrincipal) {
  const data = state.analysisData;
  if (!data) return;

  const events = (data.events || [])
    .filter(e => e.userPrincipal === userPrincipal)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));

  if (events.length === 0) { toast('No events for this user', 'err'); return; }

  const ws = state.activeWorkspace;
  const esc = s => String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  const lines = events.map(e => {
    const dt = new Date(e.createdAt).toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'medium' }).padEnd(20);
    const status = (e.success ? 'SUCCESS' : 'FAILED ').padEnd(8);
    const ip = (e.ipAddress || '—').padEnd(18);
    const loc = ((e.country || '') + (e.city ? '/' + e.city.slice(0, 14) : '')).padEnd(24);
    const app = (e.appName || '—').slice(0, 28).padEnd(28);
    const auth = e.authMethod ? e.authMethod.replace('multiFactorAuthentication','MFA').replace('singleFactorAuthentication','SFA') : '';
    const err  = e.errorCode && e.errorCode !== 0 ? ` err:${e.errorCode}` : '';
    return `[${dt}] ${status} | ${ip} | ${loc} | ${app} | ${auth}${err}`;
  }).join('\n');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>Session Replay — ${esc(userPrincipal)}</title>
  <style>
    @page { size: A4 landscape; margin: 1cm 1.5cm; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0d1117; color: #c9d1d9; font-family: 'Cascadia Code','Fira Code',Consolas,monospace; font-size: 11px; padding: 20px 24px; }
    pre { white-space: pre; line-height: 1.65; }
    .success { color: #3fb950; }
    .failed  { color: #f85149; }
    @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; background: #0d1117; color: #c9d1d9; } }
  </style>
</head>
<body>
<pre>${lines.split('\n').map(line => {
  const isSuccess = line.includes('] SUCCESS ');
  const isFailed  = line.includes('] FAILED  ');
  if (isSuccess) return `<span class="success">${esc(line)}</span>`;
  if (isFailed)  return `<span class="failed">${esc(line)}</span>`;
  return esc(line);
}).join('\n')}</pre>
<pre style="margin-top:16px;color:#6e7681;font-size:10px">Generated by EIDSA · Developed by JoshuaDjuk · PT Sigma Cipta Caraka — Telkomsigma · ${new Date().toLocaleString('en-GB')}</pre>
  <script>window.onload = () => window.print();<\/script>
</body>
</html>`;

  const win = window.open('', '_blank');
  if (!win) { alert('Popup blocked — allow popups for this page.'); return; }
  win.document.write(html);
  win.document.close();
}

/* ── IOC Search ───────────────────────────────────────────────────────────── */
function openIOCSearch() {
  if (document.getElementById('ioc-overlay')) {
    document.getElementById('ioc-input')?.focus();
    return;
  }
  const overlay = document.createElement('div');
  overlay.id = 'ioc-overlay';
  overlay.innerHTML = `
    <div id="ioc-panel">
      <div class="ioc-header">
        <span><i class="bi bi-search"></i> IOC Search</span>
        <button onclick="closeIOCSearch()"><i class="bi bi-x-lg"></i></button>
      </div>
      <input id="ioc-input" type="text" placeholder="Search IP, username, country, error code…"
        oninput="renderIOCResults(this.value)" autocomplete="off" spellcheck="false" />
      <div id="ioc-results">
        <div class="ioc-hint">Type to search across all events — IP, username, country, error code</div>
      </div>
    </div>`;
  overlay.addEventListener('click', e => { if (e.target === overlay) closeIOCSearch(); });
  document.body.appendChild(overlay);
  setTimeout(() => document.getElementById('ioc-input')?.focus(), 50);
}

function closeIOCSearch() {
  document.getElementById('ioc-overlay')?.remove();
}

function renderIOCResults(query) {
  const resultsEl = document.getElementById('ioc-results');
  if (!resultsEl || !state.analysisData) return;
  const q = query.trim().toLowerCase();
  if (!q) {
    resultsEl.innerHTML = '<div class="ioc-hint">Type to search across all events — IP, username, country, error code</div>';
    return;
  }

  const events   = state.analysisData.events || [];
  const ipEnrich = state.analysisData.ipEnrichment || {};

  const ipCounts    = {};
  const ipUsers     = {};
  const userCounts  = {};
  const ctryEvents  = {};

  for (const e of events) {
    if (e.ipAddress && e.ipAddress.toLowerCase().includes(q)) {
      ipCounts[e.ipAddress] = (ipCounts[e.ipAddress] || 0) + 1;
      if (!ipUsers[e.ipAddress]) ipUsers[e.ipAddress] = new Set();
      if (e.userPrincipal) ipUsers[e.ipAddress].add(e.userPrincipal);
    }
    if ((e.userPrincipal + (e.displayName || '')).toLowerCase().includes(q)) {
      userCounts[e.userPrincipal] = (userCounts[e.userPrincipal] || 0) + 1;
    }
    const locStr = ((e.country || '') + ' ' + (e.city || '')).toLowerCase();
    if (locStr.trim() && locStr.includes(q)) {
      const key = e.country + (e.city ? ' / ' + e.city : '');
      ctryEvents[key] = (ctryEvents[key] || 0) + 1;
    }
  }

  const hasAny = Object.keys(ipCounts).length + Object.keys(userCounts).length + Object.keys(ctryEvents).length > 0;
  if (!hasAny) { resultsEl.innerHTML = '<div class="ioc-hint">No matches found.</div>'; return; }

  let html = '';

  if (Object.keys(ipCounts).length > 0) {
    html += '<div class="ioc-section-label">IP Addresses</div>';
    html += Object.entries(ipCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ip, count]) => {
      const users = [...(ipUsers[ip] || [])].slice(0, 2).join(', ');
      const info  = ipEnrich[ip];
      const badge = info?.proxy ? ' <span class="ip-badge badge-proxy" style="font-size:9px;vertical-align:middle">PROXY</span>'
                  : info?.hosting ? ' <span class="ip-badge badge-hosting" style="font-size:9px;vertical-align:middle">VPS</span>' : '';
      return `<div class="ioc-result" onclick="filterEventsByIP('${escHtml(ip)}')">
        <span class="ioc-result-main">${escHtml(ip)}${badge}</span>
        <span class="ioc-result-meta">${count} events · ${users || 'no user data'}</span>
      </div>`;
    }).join('');
  }

  if (Object.keys(userCounts).length > 0) {
    html += '<div class="ioc-section-label">Users</div>';
    html += Object.entries(userCounts).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([user, count]) => {
      return `<div class="ioc-result" onclick="openTimeline('${escHtml(user)}');closeIOCSearch()">
        <span class="ioc-result-main">${escHtml(user)}</span>
        <span class="ioc-result-meta">${count} events · click to open timeline</span>
      </div>`;
    }).join('');
  }

  if (Object.keys(ctryEvents).length > 0) {
    html += '<div class="ioc-section-label">Locations</div>';
    html += Object.entries(ctryEvents).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([loc, count]) => {
      const ctry = loc.split(' / ')[0];
      return `<div class="ioc-result" onclick="filterEventsByCountry('${escHtml(ctry)}')">
        <span class="ioc-result-main"><i class="bi bi-geo-alt-fill"></i> ${escHtml(loc)}</span>
        <span class="ioc-result-meta">${count} events</span>
      </div>`;
    }).join('');
  }

  resultsEl.innerHTML = html;
}

function filterEventsByIP(ip) {
  switchTab('events');
  state.eventsFilter = ip;
  state.eventsPage   = 1;
  rerenderTable();
  closeIOCSearch();
}

function filterEventsByCountry(country) {
  switchTab('events');
  state.eventsFilter = country;
  state.eventsPage   = 1;
  rerenderTable();
  closeIOCSearch();
}

/* ── Attack Graph ─────────────────────────────────────────────────────────── */
function initAttackGraph() {
  const container = document.getElementById('graph-container');
  if (!container || !state.analysisData) return;
  if (container.dataset.built === '1') return;
  container.dataset.built = '1';

  const { detections = [], events = [], userSummaries = [], ipEnrichment = {} } = state.analysisData;
  const homeCountry = (state.analysisData.homeCountry || 'ID').toUpperCase();

  if (detections.length === 0) {
    container.innerHTML = '<div class="empty" style="padding:80px 0">No detections — attack graph requires sign-in data with flagged activity.</div>';
    return;
  }

  // ── Build node sets ──────────────────────────────────────────────────────
  const ipStats = {};
  for (const e of events) {
    if (!e.ipAddress || !e.country || e.country.toUpperCase() === homeCountry) continue;
    if (!ipStats[e.ipAddress]) ipStats[e.ipAddress] = { count: 0, users: new Set(), country: e.country };
    ipStats[e.ipAddress].count++;
    if (e.userPrincipal) ipStats[e.ipAddress].users.add(e.userPrincipal);
  }

  const detUserSet = new Set();
  for (const d of detections) {
    if (d.user) detUserSet.add(d.user);
    if (d.affectedUsers) d.affectedUsers.forEach(u => detUserSet.add(u));
  }

  const topIPs = Object.entries(ipStats)
    .filter(([, s]) => [...s.users].some(u => detUserSet.has(u)))
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 14);

  const atRiskUsers = userSummaries
    .filter(s => detUserSet.has(s.user))
    .slice(0, 14);

  const detTypeMap = {};
  for (const d of detections) {
    if (!detTypeMap[d.type]) detTypeMap[d.type] = { severity: d.severity, users: new Set() };
    if (d.user) detTypeMap[d.type].users.add(d.user);
    if (d.affectedUsers) d.affectedUsers.forEach(u => detTypeMap[d.type].users.add(u));
  }
  const detTypes = Object.entries(detTypeMap);

  if (topIPs.length === 0 && atRiskUsers.length === 0) {
    container.innerHTML = '<div class="empty" style="padding:80px 0">Not enough data to build attack graph — foreign-IP events and detections are needed.</div>';
    return;
  }

  // ── Edges ────────────────────────────────────────────────────────────────
  const edges1 = []; // IP → User
  const edges2 = []; // User → DetType
  for (const [ip, s] of topIPs) {
    for (const user of s.users) {
      if (atRiskUsers.some(u => u.user === user)) edges1.push({ from: ip, to: user });
    }
  }
  for (const [dt, info] of detTypes) {
    for (const user of info.users) {
      if (atRiskUsers.some(u => u.user === user)) edges2.push({ from: user, to: dt });
    }
  }

  // ── Layout ────────────────────────────────────────────────────────────────
  const W      = container.clientWidth || 880;
  const NH     = 38;
  const NW     = 170;
  const GAP    = 12;
  const colIPs = topIPs.length;
  const colU   = atRiskUsers.length;
  const colD   = detTypes.length;
  const SVG_H  = Math.max(colIPs, colU, colD) * (NH + GAP) + 60;

  const xIP   = 16;
  const xUser = (W - NW) / 2;
  const xDet  = W - NW - 16;

  const colY = (n, total) => {
    const totalH = total * (NH + GAP) - GAP;
    const start  = (SVG_H - totalH) / 2;
    return start + n * (NH + GAP);
  };

  const nodePos = {};
  topIPs.forEach(([ip], i)       => { nodePos['ip:'+ip]    = { x: xIP,   y: colY(i, colIPs), w: NW, h: NH }; });
  atRiskUsers.forEach((s, i)     => { nodePos['user:'+s.user] = { x: xUser, y: colY(i, colU),  w: NW, h: NH }; });
  detTypes.forEach(([dt], i)     => { nodePos['det:'+dt]   = { x: xDet,  y: colY(i, colD),  w: NW, h: NH }; });

  const sevColor  = s => s === 'high' ? '#f16060' : s === 'medium' ? '#f5a623' : '#5b8def';
  const riskColor = r => r === 'CRITICAL' ? '#f16060' : r === 'HIGH' ? '#f5a623' : '#5b8def';

  const bezier = (fk, tk, color, eid) => {
    const f = nodePos[fk]; const t = nodePos[tk];
    if (!f || !t) return '';
    const x1 = f.x + f.w, y1 = f.y + f.h / 2;
    const x2 = t.x,        y2 = t.y + t.h / 2;
    const cx = (x1 + x2) / 2;
    return `<path data-edgeid="${eid}" data-from="${fk}" data-to="${tk}" d="M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}" fill="none" stroke="${color}" stroke-width="1.5" opacity="0.45"/>`;
  };

  const ipBadge = ip => {
    const info = ipEnrichment[ip];
    if (!info) return '';
    if (info.proxy)   return ' [P]';
    if (info.hosting) return ' [H]';
    return '';
  };

  const ipNodesSVG = topIPs.map(([ip, s], i) => {
    const { x, y, w, h } = nodePos['ip:'+ip];
    const lbl = ip.length > 17 ? ip.slice(0, 15) + '…' : ip;
    return `<g data-nodeid="ip:${escHtml(ip)}" style="cursor:pointer" onclick="filterEventsByIP('${escHtml(ip)}')">
      <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="5" fill="#1d2438" stroke="#f16060" stroke-width="1.5" class="graph-node-rect"/>
      <text x="${x+8}" y="${y+14}" font-size="11" fill="#f16060" font-family="monospace,sans-serif">${escHtml(lbl)}${ipBadge(ip)}</text>
      <text x="${x+8}" y="${y+28}" font-size="10" fill="#8ba0bb">${escHtml(s.country)} · ${s.count} events</text>
    </g>`;
  });

  const userNodesSVG = atRiskUsers.map((s, i) => {
    const { x, y, w, h } = nodePos['user:'+s.user];
    const color = riskColor(s.riskLevel);
    const lbl   = (s.displayName || s.user).slice(0, 20);
    return `<g data-nodeid="user:${escHtml(s.user)}" style="cursor:pointer" onclick="openTimeline('${escHtml(s.user)}')">
      <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="5" fill="#1d2438" stroke="${color}" stroke-width="1.5" class="graph-node-rect"/>
      <text x="${x+8}" y="${y+14}" font-size="11" fill="${color}">${escHtml(lbl)}</text>
      <text x="${x+8}" y="${y+28}" font-size="10" fill="#8ba0bb">${s.riskLevel} · ${s.foreignAttempts} foreign</text>
    </g>`;
  });

  const detNodesSVG = detTypes.map(([dt, info], i) => {
    const { x, y, w, h } = nodePos['det:'+dt];
    const color = sevColor(info.severity);
    const lbl   = dt.replace(/_/g, ' ');
    const trunc = lbl.length > 19 ? lbl.slice(0, 17) + '…' : lbl;
    return `<g data-nodeid="det:${escHtml(dt)}">
      <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="5" fill="#1d2438" stroke="${color}" stroke-width="1.5" class="graph-node-rect"/>
      <text x="${x+8}" y="${y+14}" font-size="11" fill="${color}">${escHtml(trunc)}</text>
      <text x="${x+8}" y="${y+28}" font-size="10" fill="#8ba0bb">${info.severity} · ${info.users.size} user${info.users.size !== 1 ? 's' : ''}</text>
    </g>`;
  });

  const edgeSVG1 = edges1.map(({ from, to }, i) => bezier('ip:'+from, 'user:'+to, '#f16060', `e1_${i}`));
  const edgeSVG2 = edges2.map(({ from, to }, i) => bezier('user:'+from, 'det:'+to, '#f5a623', `e2_${i}`));

  const labels = [
    `<text x="${xIP+NW/2}" y="18" text-anchor="middle" font-size="10" fill="#617898" font-weight="600" letter-spacing="1">ATTACKER IPs</text>`,
    `<text x="${xUser+NW/2}" y="18" text-anchor="middle" font-size="10" fill="#617898" font-weight="600" letter-spacing="1">TARGETED USERS</text>`,
    `<text x="${xDet+NW/2}" y="18" text-anchor="middle" font-size="10" fill="#617898" font-weight="600" letter-spacing="1">DETECTIONS</text>`,
  ].join('');

  container.innerHTML = `
    <div class="graph-wrap">
      <svg width="${W}" height="${SVG_H}" xmlns="http://www.w3.org/2000/svg" style="font-family:Inter,sans-serif;display:block">
        ${labels}
        ${[...edgeSVG1, ...edgeSVG2].join('')}
        ${[...ipNodesSVG, ...userNodesSVG, ...detNodesSVG].join('')}
      </svg>
      <div class="graph-legend">
        <span><span class="graph-legend-dot" style="background:#f16060"></span>Attacker IPs (click → filter events)</span>
        <span><span class="graph-legend-dot" style="background:#f5a623"></span>At-risk users (click → timeline)</span>
        <span><span class="graph-legend-dot" style="background:#5b8def"></span>Detection types</span>
      </div>
    </div>`;

  // ── Hover highlighting ────────────────────────────────────────────────────
  const svg = container.querySelector('svg');
  if (!svg) return;
  const allNodes = [...svg.querySelectorAll('[data-nodeid]')];
  const allEdges = [...svg.querySelectorAll('[data-edgeid]')];

  const getConnected = nodeId => {
    const connNodes = new Set([nodeId]);
    const connEdges = new Set();
    const type = nodeId.split(':')[0];

    // 1-hop: direct edges in/out of this node
    for (const e of allEdges) {
      if (e.dataset.from === nodeId) { connEdges.add(e.dataset.edgeid); connNodes.add(e.dataset.to); }
      if (e.dataset.to   === nodeId) { connEdges.add(e.dataset.edgeid); connNodes.add(e.dataset.from); }
    }

    // 2nd hop: for IP follow forward through users to dets; for det follow backward through users to IPs
    if (type === 'ip') {
      for (const e of allEdges) {
        if (connNodes.has(e.dataset.from) && e.dataset.from.startsWith('user:')) {
          connEdges.add(e.dataset.edgeid); connNodes.add(e.dataset.to);
        }
      }
    } else if (type === 'det') {
      for (const e of allEdges) {
        if (connNodes.has(e.dataset.to) && e.dataset.to.startsWith('user:')) {
          connEdges.add(e.dataset.edgeid); connNodes.add(e.dataset.from);
        }
      }
    }
    return { connNodes, connEdges };
  };

  const applyHover = hoveredNode => {
    const { connNodes, connEdges } = getConnected(hoveredNode.dataset.nodeid);
    for (const n of allNodes) {
      const active = connNodes.has(n.dataset.nodeid);
      n.style.opacity = active ? '1' : '0.1';
      const rect = n.querySelector('rect');
      if (rect) rect.setAttribute('stroke-width', active && n === hoveredNode ? '2.5' : '1.5');
    }
    for (const e of allEdges) {
      if (connEdges.has(e.dataset.edgeid)) {
        e.style.opacity = '1';
        e.setAttribute('stroke-width', '2.5');
      } else {
        e.style.opacity = '0.04';
        e.setAttribute('stroke-width', '1.5');
      }
    }
  };

  const clearHover = () => {
    for (const n of allNodes) {
      n.style.opacity = '';
      const rect = n.querySelector('rect');
      if (rect) rect.setAttribute('stroke-width', '1.5');
    }
    for (const e of allEdges) {
      e.style.opacity = '';
      e.setAttribute('stroke-width', '1.5');
    }
  };

  for (const node of allNodes) {
    node.addEventListener('mouseenter', () => applyHover(node));
    node.addEventListener('mouseleave', clearHover);
  }
}

/* ── IP Enrichment ────────────────────────────────────────────────────────── */
// ─── Threat Intel (local static lookup) ──────────────────────────────────────
const THREAT_INTEL_PATTERNS = [
  // Tor
  { re: /\btor\b.*(exit|relay|node)|tor\b.*project|(exit|relay).*\btor\b/i, tag: 'TOR',          cls: 'ti-tor',     risk: 'HIGH' },
  // Named VPN providers (commonly abused for attack traffic)
  { re: /mullvad/i,                           tag: 'MULLVAD VPN',   cls: 'ti-vpn',     risk: 'MED' },
  { re: /nordvpn|nord\s+vpn/i,                tag: 'NORDVPN',       cls: 'ti-vpn',     risk: 'MED' },
  { re: /expressvpn|express\s+vpn/i,          tag: 'EXPRESSVPN',    cls: 'ti-vpn',     risk: 'MED' },
  { re: /protonvpn|proton\s+vpn/i,            tag: 'PROTONVPN',     cls: 'ti-vpn',     risk: 'MED' },
  { re: /cyberghost/i,                         tag: 'CYBERGHOST',    cls: 'ti-vpn',     risk: 'MED' },
  { re: /\bipvanish\b/i,                       tag: 'IPVANISH',      cls: 'ti-vpn',     risk: 'MED' },
  { re: /\btorguard\b/i,                       tag: 'TORGUARD',      cls: 'ti-vpn',     risk: 'MED' },
  { re: /hidemyass|hide\s*my\s*ass/i,          tag: 'HMA VPN',       cls: 'ti-vpn',     risk: 'MED' },
  { re: /private\s+internet\s+access|\bpia\b.*(vpn|network)/i, tag: 'PIA VPN', cls: 'ti-vpn', risk: 'MED' },
  { re: /surfshark/i,                          tag: 'SURFSHARK',     cls: 'ti-vpn',     risk: 'MED' },
  { re: /windscribe/i,                         tag: 'WINDSCRIBE',    cls: 'ti-vpn',     risk: 'MED' },
  { re: /\bvpnunlimited\b|vpn\s+unlimited/i,  tag: 'VPN',           cls: 'ti-vpn',     risk: 'MED' },
  { re: /anonymous.*vpn|vpn.*anonymous/i,      tag: 'ANON VPN',      cls: 'ti-vpn',     risk: 'MED' },
  // Bulletproof / botnet-friendly hosters
  { re: /\bm247\b/i,                           tag: 'M247 (Bulletproof)', cls: 'ti-botnet', risk: 'HIGH' },
  { re: /quadranet/i,                          tag: 'QuadraNet',     cls: 'ti-botnet',  risk: 'HIGH' },
  { re: /frantech|ponynet/i,                   tag: 'FranTech',      cls: 'ti-botnet',  risk: 'HIGH' },
  { re: /sharktech/i,                          tag: 'Sharktech',     cls: 'ti-botnet',  risk: 'HIGH' },
  { re: /serverius/i,                          tag: 'Serverius',     cls: 'ti-botnet',  risk: 'HIGH' },
  { re: /combahton|combahton/i,                tag: 'combahton',     cls: 'ti-botnet',  risk: 'HIGH' },
  { re: /leaseweb/i,                           tag: 'LeaseWeb',      cls: 'ti-botnet',  risk: 'MED' },
  // Proxy / anonymizer labels
  { re: /\bsocks\d?\b.*proxy|anonymous\s*proxy/i, tag: 'ANON PROXY', cls: 'ti-proxy', risk: 'HIGH' },
];

function lookupThreatIntel(info) {
  if (!info) return null;
  const haystack = `${info.isp || ''} ${info.org || ''}`;
  for (const entry of THREAT_INTEL_PATTERNS) {
    if (entry.re.test(haystack)) return entry;
  }
  return null;
}

function getIPInfo(ip) {
  return state.analysisData?.ipEnrichment?.[ip] || null;
}

function renderIPEnrich(ip) {
  const info = getIPInfo(ip);
  const badges = [];
  if (info) {
    const ti = lookupThreatIntel(info);
    if (ti) badges.push(`<span class="ip-badge ${ti.cls}" title="Threat Intel: ${escHtml(ti.tag)}">${escHtml(ti.tag)}</span>`);
    else {
      if (info.proxy)   badges.push('<span class="ip-badge badge-proxy">PROXY</span>');
      if (info.hosting) badges.push('<span class="ip-badge badge-hosting">VPS</span>');
      if (info.mobile)  badges.push('<span class="ip-badge badge-mobile">MOBILE</span>');
    }
  }
  const hist = state.activeWorkspace ? getIPHistory(state.activeWorkspace.id, ip) : null;
  if (hist && hist.count > 1) {
    badges.push(`<span class="ip-badge badge-repeat" title="Seen in ${hist.count} previous runs — first: ${new Date(hist.firstSeen).toLocaleDateString('en-GB')}">REPEAT ${hist.count}×</span>`);
  }
  const label = info ? (info.isp || info.org || '').replace(/^AS\d+\s*/, '').slice(0, 28) : '';
  if (!badges.length && !label) return '';
  return `<div class="ip-enrich">${badges.join('')}${label ? `<span class="ip-isp" title="${escHtml(info.isp || info.org || '')}">${escHtml(label)}</span>` : ''}</div>`;
}

function renderIPClickable(ip) {
  if (!ip) return '';
  return `<span class="ip-link" onclick="event.stopPropagation();openIPPivot('${escHtml(ip)}')">${escHtml(ip)}</span>${renderIPEnrich(ip)}`;
}

/* ── IP Pivot Panel ────────────────────────────────────────────────────────── */
function openIPPivot(ip) {
  if (!state.analysisData) return;
  const events     = state.analysisData.events     || [];
  const detections = state.analysisData.detections || [];

  const ipEvents   = events.filter(e => e.ipAddress === ip).sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const users      = [...new Set(ipEvents.map(e => e.userPrincipal).filter(Boolean))];
  const ipDets     = detections.filter(d => d.ip === ip || (d.ips && d.ips.includes(ip)));
  const successes  = ipEvents.filter(e => e.success).length;
  const info       = getIPInfo(ip);

  const ti = lookupThreatIntel(info);
  const tiRow = ti ? `<div class="ipp-enrich-row ipp-ti-row"><span class="ipp-el">Threat Intel</span><span class="ip-badge ${ti.cls}" style="font-size:11px">${escHtml(ti.tag)}</span><span class="ipp-ti-risk" data-risk="${ti.risk}">${ti.risk} RISK</span></div>` : '';
  const ipHist = state.activeWorkspace ? getIPHistory(state.activeWorkspace.id, ip) : null;
  const histRow = ipHist && ipHist.count > 1
    ? `<div class="ipp-enrich-row"><span class="ipp-el">Run History</span><span class="ip-badge badge-repeat" style="font-size:11px">REPEAT ${ipHist.count}×</span><span style="font-size:11px;color:var(--text2);margin-left:6px">first: ${new Date(ipHist.firstSeen).toLocaleDateString('en-GB')}</span></div>`
    : '';
  const enrichRows = info ? [
    tiRow,
    info.isp ? `<div class="ipp-enrich-row"><span class="ipp-el">ISP</span><span>${escHtml(info.isp)}</span></div>` : '',
    info.org && info.org !== info.isp ? `<div class="ipp-enrich-row"><span class="ipp-el">Org</span><span>${escHtml(info.org)}</span></div>` : '',
    info.as  ? `<div class="ipp-enrich-row"><span class="ipp-el">ASN</span><span>${escHtml(info.as)}</span></div>` : '',
    `<div class="ipp-enrich-row"><span class="ipp-el">Type</span><span>${[info.proxy ? 'Proxy' : '', info.hosting ? 'VPS/Hosting' : '', info.mobile ? 'Mobile' : ''].filter(Boolean).join(' · ') || 'Residential'}</span></div>`,
  ].filter(Boolean).join('') : '';

  const detHtml = ipDets.length ? ipDets.map(d => `
    <div class="ipp-det-row sev-${d.severity}">
      <span class="det-badge badge-${d.severity}">${d.severity}</span>
      <span class="ipp-det-type">${d.type.replace(/_/g, ' ')}</span>
      <span class="ipp-det-msg">${escHtml(d.message)}</span>
    </div>`).join('') : '<div class="ipp-empty">No direct detections for this IP</div>';

  const usersHtml = users.length ? users.map(u => `
    <div class="ipp-user-row" onclick="closeIPPivot();openTimeline('${escHtml(u)}')">
      <span class="ipp-user-name">${escHtml(u)}</span>
      <span class="ipp-user-count">${ipEvents.filter(e => e.userPrincipal === u).length} events</span>
    </div>`).join('') : '<div class="ipp-empty">No user data</div>';

  const eventsHtml = ipEvents.slice(0, 50).map(e => {
    const homeCountry = (state.analysisData.homeCountry || 'ID').toUpperCase();
    const isForeign = e.country && e.country.toUpperCase() !== homeCountry;
    return `
    <div class="ipp-event-row">
      <span class="ipp-ev-time">${formatDate(e.createdAt)}</span>
      <span class="${e.success ? 'tl-status-ok' : 'tl-status-fail'}">${e.success ? '<i class="bi bi-check-lg"></i>' : '<i class="bi bi-x-lg"></i>'}</span>
      <span class="ipp-ev-user" onclick="closeIPPivot();openTimeline('${escHtml(e.userPrincipal)}')">${escHtml(e.displayName || e.userPrincipal.split('@')[0])}</span>
      ${e.country ? `<span class="ipp-ev-loc">${isForeign ? '<i class="bi bi-exclamation-triangle"></i> ' : ''}${escHtml(e.country)}${e.city ? '/' + escHtml(e.city) : ''}</span>` : ''}
      <span class="ipp-ev-app">${escHtml(e.appType || '')}</span>
    </div>`;
  }).join('');
  const moreEvents = ipEvents.length > 50 ? `<div class="ipp-empty" style="margin-top:6px">… and ${ipEvents.length - 50} more events</div>` : '';

  let overlay = document.getElementById('ip-pivot-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'ip-pivot-overlay';
    overlay.addEventListener('click', e => { if (e.target === overlay) closeIPPivot(); });
    document.body.appendChild(overlay);
  }

  overlay.innerHTML = `
    <div id="ip-pivot-panel">
      <div class="ipp-header">
        <div>
          <div class="ipp-title" style="display:flex;align-items:center;gap:8px">
            ${escHtml(ip)}
            <span class="ioc-chip" style="font-size:10px;padding:1px 7px" onclick="copyIOC('${escHtml(ip)}',this)" title="Copy IP"><i class="bi bi-clipboard"></i> Copy</span>
          </div>
          <div class="ipp-subtitle">IP Pivot · ${ipEvents.length} events · ${users.length} users targeted</div>
        </div>
        <button class="timeline-close" onclick="closeIPPivot()"><i class="bi bi-x-lg"></i></button>
      </div>
      <div class="ipp-body">
        ${enrichRows || histRow ? `<div class="ipp-section"><div class="ipp-section-title">Enrichment</div>${enrichRows}${histRow}</div>` : ''}
        <div class="ipp-stats-row">
          <div class="ipp-stat"><strong>${ipEvents.length}</strong><span>Events</span></div>
          <div class="ipp-stat"><strong>${successes}</strong><span>Successful</span></div>
          <div class="ipp-stat"><strong>${users.length}</strong><span>Users</span></div>
          <div class="ipp-stat"><strong>${ipDets.length}</strong><span>Detections</span></div>
        </div>
        <div class="ipp-section">
          <div class="ipp-section-title">Detections</div>
          ${detHtml}
        </div>
        <div class="ipp-section">
          <div class="ipp-section-title">Users Targeted <span style="font-weight:400;color:var(--text3)">(click to open timeline)</span></div>
          ${usersHtml}
        </div>
        <div class="ipp-section">
          <div class="ipp-section-title">Event Log${ipEvents.length > 50 ? ' (showing 50 of ' + ipEvents.length + ')' : ''}</div>
          <div class="ipp-events-list">${eventsHtml}${moreEvents}</div>
        </div>
      </div>
    </div>`;
}

function closeIPPivot() {
  document.getElementById('ip-pivot-overlay')?.remove();
}

/* ── Theme ────────────────────────────────────────────────────────────────── */
function toggleTheme() {
  const isLight = document.body.classList.toggle('theme-light');
  localStorage.setItem('eidsa_theme', isLight ? 'light' : 'dark');
  const btn = document.getElementById('btn-theme-toggle');
  if (btn) btn.innerHTML = isLight ? '<i class="bi bi-moon-fill"></i>' : '<i class="bi bi-sun-fill"></i>';
  // Reinit map with correct tiles if open
  if (state.leafletMap) {
    state.leafletMap.eachLayer(l => { if (l._url) state.leafletMap.removeLayer(l); });
    const tileUrl = isLight
      ? 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png'
      : 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png';
    L.tileLayer(tileUrl, { attribution: '© OpenStreetMap, © CARTO', subdomains: 'abcd', maxZoom: 19 }).addTo(state.leafletMap);
  }
}

/* ── Keyboard shortcuts ───────────────────────────────────────────────────── */
function showShortcutPanel() {
  if (document.getElementById('shortcut-overlay')) return;
  const overlay = document.createElement('div');
  overlay.id = 'shortcut-overlay';
  overlay.innerHTML = `
    <div id="shortcut-panel">
      <h3>⌨ Keyboard Shortcuts</h3>
      <div class="shortcut-row"><span class="shortcut-key">R</span><span class="shortcut-desc">Run Analysis</span></div>
      <div class="shortcut-row"><span class="shortcut-key">E</span><span class="shortcut-desc">Export PDF</span></div>
      <div class="shortcut-row"><span class="shortcut-key">1</span><span class="shortcut-desc">Dashboard tab</span></div>
      <div class="shortcut-row"><span class="shortcut-key">2</span><span class="shortcut-desc">Events tab</span></div>
      <div class="shortcut-row"><span class="shortcut-key">3</span><span class="shortcut-desc">Map tab</span></div>
      <div class="shortcut-row"><span class="shortcut-key">4</span><span class="shortcut-desc">Charts tab</span></div>
      <div class="shortcut-row"><span class="shortcut-key">5</span><span class="shortcut-desc">Attack Graph tab</span></div>
      <div class="shortcut-row"><span class="shortcut-key">/</span><span class="shortcut-desc">IOC Search</span></div>
      <div class="shortcut-row"><span class="shortcut-key">?</span><span class="shortcut-desc">Show this panel</span></div>
      <div class="shortcut-row"><span class="shortcut-key">Esc</span><span class="shortcut-desc">Close panels / modals</span></div>
      <div style="margin-top:14px;text-align:right">
        <button class="btn-secondary" onclick="closeShortcutPanel()">Close</button>
      </div>
    </div>`;
  overlay.addEventListener('click', e => { if (e.target === overlay) closeShortcutPanel(); });
  document.body.appendChild(overlay);
}

function closeShortcutPanel() {
  document.getElementById('shortcut-overlay')?.remove();
}

/* ── Utilities ────────────────────────────────────────────────────────────── */
function copyIOC(text, el) {
  navigator.clipboard.writeText(text).then(() => {
    const orig = el.innerHTML;
    el.innerHTML = '<i class="bi bi-check-lg"></i> Copied';
    el.style.color = '#22c55e';
    el.style.borderColor = '#22c55e60';
    setTimeout(() => { el.innerHTML = orig; el.style.color = ''; el.style.borderColor = ''; }, 1600);
  }).catch(() => toast('Copy failed', 'err'));
}

function escHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatDate(str) {
  if (!str) return '';
  const d = new Date(str);
  if (isNaN(d)) return str;
  return d.toLocaleString('en-GB', { dateStyle: 'short', timeStyle: 'short' });
}

/* ── Cross-Run IP/User History ───────────────────────────────────────────── */
function histKey(wsId)    { return `eidsa_history_${wsId}`; }

function loadHistory(wsId) {
  try { return JSON.parse(localStorage.getItem(histKey(wsId))) || { ips: {}, users: {} }; }
  catch { return { ips: {}, users: {} }; }
}

function saveHistory(wsId, h) {
  localStorage.setItem(histKey(wsId), JSON.stringify(h));
}

function mergeRunHistory(wsId, data) {
  const h = loadHistory(wsId);
  const now = Date.now();
  const events = data.events || [];
  const detections = data.detections || [];
  const homeCountry = (data.homeCountry || '').toUpperCase();

  const attackIPs = new Set();
  for (const d of detections) {
    if (d.ip) attackIPs.add(d.ip);
    if (d.ips) d.ips.forEach(ip => attackIPs.add(ip));
  }
  for (const e of events) {
    if (e.ipAddress && e.country && e.country.toUpperCase() !== homeCountry) {
      attackIPs.add(e.ipAddress);
    }
  }
  for (const ip of attackIPs) {
    if (!h.ips[ip]) h.ips[ip] = { count: 0, firstSeen: now };
    h.ips[ip].count++;
    h.ips[ip].lastSeen = now;
  }

  const detUsers = new Set();
  for (const d of detections) {
    if (d.user) detUsers.add(d.user);
    if (d.affectedUsers) d.affectedUsers.forEach(u => detUsers.add(u));
  }
  for (const user of detUsers) {
    if (!h.users[user]) h.users[user] = { count: 0, firstSeen: now };
    h.users[user].count++;
    h.users[user].lastSeen = now;
  }
  saveHistory(wsId, h);
}

function getIPHistory(wsId, ip) {
  return loadHistory(wsId).ips[ip] || null;
}

function getUserHistory(wsId, user) {
  return loadHistory(wsId).users[user] || null;
}

/* ── Run Delta / Log Diff ─────────────────────────────────────────────────── */
function prevRunKey(wsId) { return `eidsa_prevrun_${wsId}`; }

function loadPrevRun(wsId) {
  try { return JSON.parse(localStorage.getItem(prevRunKey(wsId))); }
  catch { return null; }
}

function savePrevRun(wsId, data) {
  const snap = {
    ts: Date.now(),
    detectionCount: (data.detections || []).length,
    atRiskUsers: [...new Set((data.detections || [])
      .flatMap(d => [d.user, ...(d.affectedUsers || [])]).filter(Boolean))],
    detectionTypes: [...new Set((data.detections || []).map(d => d.type))],
    attackingIPs: [...new Set((data.detections || [])
      .flatMap(d => [d.ip, ...(d.ips || [])]).filter(Boolean))],
    attackingCountries: [...new Set((data.events || [])
      .filter(e => !e.success && e.country && e.country.toUpperCase() !== (data.homeCountry || '').toUpperCase())
      .map(e => e.country))],
    totalEvents: (data.events || []).length,
  };
  localStorage.setItem(prevRunKey(wsId), JSON.stringify(snap));
}

function renderDeltaPanel(data) {
  const prev = loadPrevRun(state.activeWorkspace?.id);
  if (!prev) return '';

  const curr = {
    atRiskUsers: [...new Set((data.detections || [])
      .flatMap(d => [d.user, ...(d.affectedUsers || [])]).filter(Boolean))],
    detectionTypes: [...new Set((data.detections || []).map(d => d.type))],
    attackingIPs: [...new Set((data.detections || [])
      .flatMap(d => [d.ip, ...(d.ips || [])]).filter(Boolean))],
    attackingCountries: [...new Set((data.events || [])
      .filter(e => !e.success && e.country && e.country.toUpperCase() !== (data.homeCountry || '').toUpperCase())
      .map(e => e.country))],
    detectionCount: (data.detections || []).length,
  };

  const newUsers       = curr.atRiskUsers.filter(u => !prev.atRiskUsers.includes(u));
  const resolvedUsers  = prev.atRiskUsers.filter(u => !curr.atRiskUsers.includes(u));
  const newTypes       = curr.detectionTypes.filter(t => !prev.detectionTypes.includes(t));
  const goneTypes      = prev.detectionTypes.filter(t => !curr.detectionTypes.includes(t));
  const newIPs         = curr.attackingIPs.filter(ip => !prev.attackingIPs.includes(ip));
  const newCountries   = curr.attackingCountries.filter(c => !prev.attackingCountries.includes(c));
  const goneCountries  = prev.attackingCountries.filter(c => !curr.attackingCountries.includes(c));
  const detDelta       = curr.detectionCount - prev.detectionCount;

  const unchanged = !newUsers.length && !resolvedUsers.length && !newTypes.length &&
    !goneTypes.length && !newIPs.length && !newCountries.length && !goneCountries.length && detDelta === 0;
  if (unchanged) return '';

  const prevMin = Math.round((Date.now() - prev.ts) / 60000);
  const prevAge = prevMin < 60 ? `${prevMin}m ago` : prevMin < 1440 ? `${Math.round(prevMin/60)}h ago` : `${Math.round(prevMin/1440)}d ago`;

  const chips = [];
  if (detDelta !== 0) chips.push(`<span class="delta-chip ${detDelta > 0 ? 'delta-up' : 'delta-down'}">${detDelta > 0 ? '↑' : '↓'} ${Math.abs(detDelta)} detections</span>`);
  newUsers.forEach(u     => chips.push(`<span class="delta-chip delta-new" title="${escHtml(u)}"><i class="bi bi-plus-circle"></i> ${escHtml(u.split('@')[0])}</span>`));
  resolvedUsers.forEach(u=> chips.push(`<span class="delta-chip delta-ok" title="${escHtml(u)}"><i class="bi bi-check-lg"></i> ${escHtml(u.split('@')[0])}</span>`));
  newTypes.forEach(t     => chips.push(`<span class="delta-chip delta-new"><i class="bi bi-plus-circle"></i> ${t.replace(/_/g,' ')}</span>`));
  goneTypes.forEach(t    => chips.push(`<span class="delta-chip delta-ok"><i class="bi bi-check-lg"></i> ${t.replace(/_/g,' ')}</span>`));
  newIPs.slice(0, 5).forEach(ip => chips.push(`<span class="delta-chip delta-new ip-link" onclick="event.stopPropagation();openIPPivot('${escHtml(ip)}')" style="cursor:pointer"><i class="bi bi-plus-circle"></i> ${escHtml(ip)}</span>`));
  if (newIPs.length > 5) chips.push(`<span class="delta-chip delta-neutral">+${newIPs.length - 5} new IPs</span>`);
  newCountries.forEach(c => chips.push(`<span class="delta-chip delta-new"><i class="bi bi-globe"></i> ${escHtml(c)}</span>`));
  goneCountries.forEach(c=> chips.push(`<span class="delta-chip delta-ok"><i class="bi bi-check-lg"></i> ${escHtml(c)}</span>`));

  return `<div class="delta-panel">
    <span class="delta-title"><i class="bi bi-arrow-clockwise"></i> vs Run <span style="opacity:0.6;font-weight:400">${prevAge}</span></span>
    <div class="delta-chips">${chips.join('')}</div>
  </div>`;
}

/* ── Per-User Behavior Profiles ──────────────────────────────────────────── */
function profilesKey(wsId) { return `eidsa_profiles_${wsId}`; }

function loadProfiles(wsId) {
  try { return JSON.parse(localStorage.getItem(profilesKey(wsId))) || {}; }
  catch { return {}; }
}

function saveProfiles(wsId, profiles) {
  localStorage.setItem(profilesKey(wsId), JSON.stringify(profiles));
}

function updateUserProfiles(wsId, events) {
  const profiles = loadProfiles(wsId);
  const successEvents = events.filter(e => e.success && e.userPrincipal);
  const seenUsers = new Set();

  for (const e of successEvents) {
    const u = e.userPrincipal;
    if (!profiles[u]) profiles[u] = { hours: {}, countries: {}, apps: {}, runCount: 0 };
    const p = profiles[u];
    if (e.createdAt) {
      const h = new Date(e.createdAt).getHours();
      if (!isNaN(h)) p.hours[h] = (p.hours[h] || 0) + 1;
    }
    if (e.country)         p.countries[e.country]         = (p.countries[e.country]         || 0) + 1;
    if (e.appDisplayName)  p.apps[e.appDisplayName]        = (p.apps[e.appDisplayName]        || 0) + 1;
    seenUsers.add(u);
  }
  for (const u of seenUsers) {
    if (profiles[u]) profiles[u].runCount = (profiles[u].runCount || 0) + 1;
  }
  saveProfiles(wsId, profiles);
}

function detectUserAnomalies(userPrincipal) {
  if (!state.activeWorkspace || !state.analysisData) return [];
  const profiles = loadProfiles(state.activeWorkspace.id);
  const p = profiles[userPrincipal];
  if (!p || (p.runCount || 0) < 2) return [];

  const events = (state.analysisData.events || []).filter(e => e.userPrincipal === userPrincipal && e.success);
  const anomalies = [];

  // Unusual hour — login outside their normal window (only flag late night/early morning deviations)
  const topHours = Object.entries(p.hours).sort(([,a],[,b]) => b-a).slice(0,8).map(([h]) => parseInt(h));
  const offHourEvts = events.filter(e => {
    if (!e.createdAt) return false;
    const h = new Date(e.createdAt).getHours();
    return !topHours.includes(h) && (h < 6 || h > 22);
  });
  if (offHourEvts.length) {
    const hrs = [...new Set(offHourEvts.map(e => new Date(e.createdAt).getHours()))];
    anomalies.push({ type: 'UNUSUAL_HOUR', label: `Unusual hour (${hrs.join(', ')}:00)`, risk: 'med' });
  }

  // New country not in profile history
  const knownCtry = new Set(Object.keys(p.countries));
  const newCtry = [...new Set(events.filter(e => e.country && !knownCtry.has(e.country)).map(e => e.country))];
  if (newCtry.length) {
    anomalies.push({ type: 'UNUSUAL_COUNTRY', label: `New country: ${newCtry.slice(0,3).join(', ')}`, risk: 'high' });
  }

  // Volume spike — 3× above average per run
  const totalSucc = Object.values(p.hours).reduce((a,b) => a+b, 0);
  const avgPerRun = totalSucc / Math.max(p.runCount, 1);
  if (events.length > avgPerRun * 3 && events.length > 10) {
    anomalies.push({ type: 'HIGH_VOLUME', label: `High volume (${events.length} vs avg ${Math.round(avgPerRun)})`, risk: 'med' });
  }

  return anomalies;
}

function renderUserAnomalyChips(userPrincipal) {
  const anomalies = detectUserAnomalies(userPrincipal);
  if (!anomalies.length) return '';
  return `<div class="user-anomalies">${anomalies.map(a =>
    `<span class="anomaly-chip anomaly-${a.risk}" title="Behavior deviation from baseline"><i class="bi bi-exclamation-triangle"></i> ${escHtml(a.label)}</span>`
  ).join('')}</div>`;
}

/* ── Global keyboard shortcuts ────────────────────────────────────────────── */
document.addEventListener('keydown', e => {
  // Don't fire when typing in inputs/textareas
  if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
  if (e.key === 'Escape') { closeTimeline(); closeModal(); closeShortcutPanel(); closeIPPivot(); closeKQLPanel(); return; }
  if (e.key === '?')      { showShortcutPanel(); return; }
  if (e.key === 'r' || e.key === 'R') { if (state.activeWorkspace) runAnalysis(); return; }
  if (e.key === 'e' || e.key === 'E') { if (state.analysisData) exportPDF(); return; }
  if (e.key === '1' && state.analysisData) { switchTab('dashboard'); return; }
  if (e.key === '2' && state.analysisData) { switchTab('events');    return; }
  if (e.key === '3' && state.analysisData) { switchTab('map');       return; }
  if (e.key === '4' && state.analysisData) { switchTab('charts');    return; }
  if (e.key === '5' && state.analysisData) { switchTab('graph');     return; }
  if (e.key === '/' && state.analysisData) { e.preventDefault(); openIOCSearch(); return; }
});

/* ── Init ─────────────────────────────────────────────────────────────────── */
loadWorkspaces();

// Init theme
(function initTheme() {
  const saved = localStorage.getItem('eidsa_theme');
  if (saved === 'light') {
    document.body.classList.add('theme-light');
    const btn = document.getElementById('btn-theme-toggle');
    if (btn) btn.innerHTML = '<i class="bi bi-moon-fill"></i>';
  }
})();
