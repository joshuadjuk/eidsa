/* ── Analysis ─────────────────────────────────────────────────────────────── */
async function runAnalysis() {
  const el = document.getElementById("analysis-results");
  el.innerHTML =
    '<div class="loading"><div class="spinner"></div><span>Analyzing sign-in logs…</span></div>';
  if (state.leafletMap) {
    state.leafletMap.remove();
    state.leafletMap = null;
  }
  destroyCharts();
  try {
    state.analysisData = await api(
      "GET",
      `/api/workspaces/${state.activeWorkspace.id}/analyze`,
    );
    const wsId = state.activeWorkspace.id;
    // Save current cache as prev-run snapshot before overwriting
    const oldCache = await loadCache(wsId);
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
    state.detectionsFilter = "";
    state.detectionsSevFilter = "all";
    state.activeTab = "dashboard";
    renderAnalysis();
    if (state.analysisData.eventsLimited) {
      console.log(
        `[runAnalysis] Events limited: total=${state.analysisData.total}, eventsLimited=${state.analysisData.eventsLimited}`,
      );
      bgLoadEvents(wsId, state.analysisData.total);
    } else {
      console.log(`[runAnalysis] All events received in first batch`);
    }
    // Fetch cross-workspace IP correlations in background
    api("GET", `/api/ip-correlation/${state.activeWorkspace.id}`)
      .then((corr) => {
        state.correlationData = corr;
        renderCorrelationPanel();
      })
      .catch(() => {});
    // Fetch IP enrichment in background (decoupled from main analysis so it doesn't block)
    const _wsIdEnrich = state.activeWorkspace.id;
    api("GET", `/api/workspaces/${_wsIdEnrich}/enrich`)
      .then((d) => {
        if (!d.ipEnrichment || !state.analysisData) return;
        state.analysisData.ipEnrichment = d.ipEnrichment;
        // Re-render any open IP pivots so they pick up the new data
        const pivotIp = document.querySelector(".ip-pivot-panel [data-ip]");
        if (pivotIp) openIPPivot(pivotIp.dataset.ip);
      })
      .catch(() => {});
    const btnExport = document.getElementById("btn-export-pdf");
    if (btnExport) btnExport.style.display = "";
    const btnExec = document.getElementById("btn-exec-summary");
    if (btnExec) btnExec.style.display = "";
    const btnDigest = document.getElementById("btn-weekly-digest");
    if (btnDigest) btnDigest.style.display = "";
    const btnBase = document.getElementById("btn-set-baseline");
    if (btnBase) btnBase.style.display = "";
    const btnIOC = document.getElementById("btn-ioc-search");
    if (btnIOC) btnIOC.style.display = "";
  } catch (e) {
    el.innerHTML = `<div class="empty">${e.message}</div>`;
  }
}

function renderCacheBar(ts) {
  const el = document.getElementById("cache-bar");
  if (el)
    el.outerHTML = `<div class="cache-bar" id="cache-bar">⏱ Cached · ${cacheAgeLabel(ts)} <button onclick="runAnalysis()">Refresh</button></div>`;
}

function renderAnalysis() {
  const data = state.analysisData;
  const el = document.getElementById("analysis-results");
  if (!data) return;

  const events = data.events || [];
  const detections = data.detections || [];
  const homeCountry = data.homeCountry || "ID";
  const s = data.stats || {};

  // Use server-computed stats (full dataset) — fall back to client-computed from partial events
  const totalEvCount   = s.total            ?? data.total ?? events.length;
  const successes      = s.successful       ?? events.filter((e) => e.success).length;
  const failures       = s.failed           ?? events.filter((e) => !e.success).length;
  const uniqueUsers    = s.uniqueUsers      ?? new Set(events.map((e) => e.userPrincipal)).size;
  const uniqueCountries= s.uniqueCountries  ?? new Set(events.map((e) => e.country).filter(Boolean)).size;
  const foreignLogins  = s.foreignLogins    ?? events.filter((e) => e.success && e.country && e.country.toUpperCase() !== homeCountry).length;
  const compromisedUsers = { size: s.compromisedUsers ?? (() => { const cs = new Set(); for (const d of detections) { if (d.user) cs.add(d.user); if (d.affectedUsers) d.affectedUsers.forEach(u => cs.add(u)); } return cs.size; })() };
  const highFindings   = s.highFindings     ?? detections.filter((d) => d.severity === "high").length;

  // Parse warnings banner (truncated files)
  const warnings = (data.parseWarnings || []).filter((w) => w.truncated);
  const warningBanner =
    warnings.length > 0
      ? `
    <div style="background:rgba(245,166,35,0.1);border:1px solid rgba(245,166,35,0.3);border-radius:var(--radius);padding:10px 14px;margin-bottom:12px;font-size:12px;color:var(--warn)">
      <i class="bi bi-exclamation-triangle"></i> ${warnings
        .map((w) =>
          w.error
            ? `<strong>${escHtml(w.file)}</strong> — failed to parse (${escHtml(w.error)})`
            : `<strong>${escHtml(w.file)}</strong> — file was truncated, recovered <strong>${w.recovered.toLocaleString()}</strong> events (partial data)`,
        )
        .join("<br>")}
    </div>`
      : "";

  const breachMatches = data.breachMatches || [];
  const breachBanner =
    breachMatches.length > 0
      ? `
    <div style="background:rgba(220,38,38,0.1);border:1px solid rgba(220,38,38,0.35);border-radius:var(--radius);padding:10px 14px;margin-bottom:12px;font-size:12px;color:#dc2626">
      <i class="bi bi-unlock-fill"></i> <strong>Breach Alert:</strong> ${breachMatches.length} user(s) found in uploaded breach list — credentials may be compromised:
      <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px">${breachMatches.map((u) => `<strong style="background:rgba(220,38,38,0.15);border:1px solid rgba(220,38,38,0.3);border-radius:4px;padding:1px 8px">${escHtml(u)}</strong>`).join("")}</div>
    </div>`
      : "";

  const uf = data.userFilter || {};
  const flaggedChips = (uf.flaggedUsers || []).slice(0, 50)
    .map((u) => `<span class="scope-chip scope-chip-hot" onclick="openTimeline('${escHtml(u)}')" title="Open timeline"><i class="bi bi-star-fill"></i> ${escHtml(u)}</span>`)
    .join("");
  const filterBanner = uf.mode === "filter" || uf.mode === "highlight"
    ? `
    <div class="scope-banner">
      ${
        uf.mode === "filter"
          ? `<i class="bi bi-funnel-fill"></i> <strong>Filtered view</strong> — analyzing sign-ins of users in <strong>${escHtml(uf.filename)}</strong>:
      <strong>${uf.matched.toLocaleString()}</strong> of ${uf.listed.toLocaleString()} listed users found ·
      <strong>${totalEvCount.toLocaleString()}</strong> of ${uf.totalAllEvents.toLocaleString()} events`
          : `<i class="bi bi-star-fill"></i> <strong>Highlight view</strong> — all logs analyzed, users in <strong>${escHtml(uf.filename)}</strong> are marked:
      <strong>${uf.matched.toLocaleString()}</strong> of ${uf.listed.toLocaleString()} listed users found ·
      <strong>${(uf.flaggedUsers || []).length.toLocaleString()}</strong> with detections`
      }
      ${flaggedChips ? `<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px">${flaggedChips}</div>` : ""}
      ${
        uf.unmatchedCount > 0
          ? `<details style="margin-top:6px">
        <summary style="cursor:pointer">${uf.unmatchedCount.toLocaleString()} listed user(s) not found in the logs</summary>
        <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:6px">${uf.unmatched.map((u) => `<span class="scope-chip">${escHtml(u)}</span>`).join("")}${uf.unmatchedCount > uf.unmatched.length ? `<span class="scope-chip">+${(uf.unmatchedCount - uf.unmatched.length).toLocaleString()} more</span>` : ""}</div>
      </details>`
          : ""
      }
    </div>`
    : "";

  el.innerHTML =
    filterBanner +
    warningBanner +
    breachBanner +
    `
    <!-- Tab panels — right nav controls which one shows; each panel is a full view -->
    <div class="tab-panels-wrap">
      <div id="tab-dashboard" class="tab-panel ${state.activeTab === "dashboard" ? "active" : ""}">
        <!-- Stats always shown inside dashboard -->
        <div class="stats-grid">
          <div class="stat-card info">
            <div class="stat-icon"><i class="bi bi-bar-chart-fill"></i></div>
            <div class="stat-label">Total Events</div>
            <div class="stat-value">${totalEvCount.toLocaleString()}</div>
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
            ${s.interrupted ? `<div class="stat-sub" title="MFA prompts, keep-me-signed-in and password-change interrupts — not counted as failed attempts">+${s.interrupted.toLocaleString()} interrupted</div>` : ""}
          </div>
          <div class="stat-card ${foreignLogins > 0 ? "warn" : "ok"}">
            <div class="stat-icon"><i class="bi bi-globe"></i></div>
            <div class="stat-label">Foreign Logins</div>
            <div class="stat-value">${foreignLogins.toLocaleString()}</div>
          </div>
          <div class="stat-card ${compromisedUsers.size > 0 ? "danger" : "ok"}">
            <div class="stat-icon"><i class="bi bi-exclamation-triangle-fill"></i></div>
            <div class="stat-label">Accounts at Risk</div>
            <div class="stat-value">${compromisedUsers.size}</div>
          </div>
          <div class="stat-card info">
            <div class="stat-icon"><i class="bi bi-geo-alt-fill"></i></div>
            <div class="stat-label">Countries</div>
            <div class="stat-value">${uniqueCountries}</div>
          </div>
          <div class="stat-card ${highFindings > 0 ? "danger" : "ok"}">
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
      <div id="tab-detections" class="tab-panel ${state.activeTab === "detections" ? "active" : ""}" data-lazy="1"></div>
      <div id="tab-remediation" class="tab-panel ${state.activeTab === "remediation" ? "active" : ""}" data-lazy="1"></div>
      <div id="tab-events" class="tab-panel ${state.activeTab === "events" ? "active" : ""}" data-lazy="1"></div>
      <div id="tab-map" class="tab-panel ${state.activeTab === "map" ? "active" : ""}">
        <div id="map-container"></div>
      </div>
      <div id="tab-charts" class="tab-panel ${state.activeTab === "charts" ? "active" : ""}">
        <div id="charts-container"></div>
      </div>
      <div id="tab-killchain" class="tab-panel ${state.activeTab === "killchain" ? "active" : ""}">
        <div id="killchain-container"></div>
      </div>
      <div id="tab-velocity" class="tab-panel ${state.activeTab === "velocity" ? "active" : ""}">
        <div id="velocity-container"></div>
      </div>
      <div id="tab-graph" class="tab-panel ${state.activeTab === "graph" ? "active" : ""}">
        <div id="graph-container"></div>
      </div>
      <div id="tab-swimlane" class="tab-panel ${state.activeTab === "swimlane" ? "active" : ""}">
        <div id="swimlane-container"></div>
      </div>
      <div id="tab-sankey" class="tab-panel ${state.activeTab === "sankey" ? "active" : ""}">
        <div id="sankey-container"></div>
      </div>
      <div id="tab-countryapp" class="tab-panel ${state.activeTab === "countryapp" ? "active" : ""}">
        <div id="countryapp-container"></div>
      </div>
    </div>
  `;

  buildRightNav();
  if (state.activeTab === "map") {
    setTimeout(() => {
      initMap();
      if (state.leafletMap) state.leafletMap.invalidateSize();
    }, 50);
  }
  if (state.activeTab === "charts") {
    setTimeout(() => initCharts(), 50);
  }
  if (state.activeTab === "killchain") {
    setTimeout(() => initKillChain(), 50);
  }
  if (state.activeTab === "velocity") {
    setTimeout(() => initVelocity(), 50);
  }
  if (state.activeTab === "graph") {
    setTimeout(() => initAttackGraph(), 50);
  }
  if (state.activeTab === "swimlane") {
    setTimeout(() => initSwimlane(), 50);
  }
  if (state.activeTab === "sankey") {
    setTimeout(() => initSankey(), 50);
  }
  if (state.activeTab === "countryapp") {
    setTimeout(() => initCountryApp(), 50);
  }
  setTimeout(() => initAllRadarCharts(), 80);
}

function loadMoreRiskCards(level, currentCount) {
  const data = state.analysisData;
  if (!data) return;
  const summaries = data.userSummaries || [];
  const wl = state.watchList;
  const nonWatching = summaries.filter(s => !wl.has(s.user));
  const BATCH = 15;
  let list;
  if (level === 'high') {
    list = [...nonWatching.filter(s => s.riskLevel === 'CRITICAL'), ...nonWatching.filter(s => s.riskLevel === 'HIGH')];
  } else if (level === 'medium') {
    list = nonWatching.filter(s => s.riskLevel === 'MEDIUM');
  } else {
    list = nonWatching.filter(s => s.riskLevel === 'LOW');
  }
  const container = document.getElementById(`risk-cards-${level}`);
  if (!container) return;
  const next = list.slice(currentCount, currentCount + BATCH);
  const frag = document.createElement('div');
  frag.innerHTML = next.map(s => renderRiskCard(s, level !== 'high')).join('');
  // Remove old "load more" button from container's parent if exists
  const btn = container.nextElementSibling;
  if (btn && btn.classList.contains('btn-load-more')) btn.remove();
  while (frag.firstChild) container.appendChild(frag.firstChild);
  const newLoaded = currentCount + next.length;
  if (newLoaded < list.length) {
    const newBtn = document.createElement('button');
    newBtn.className = 'btn-load-more';
    newBtn.textContent = `Show ${list.length - newLoaded} more`;
    newBtn.onclick = () => loadMoreRiskCards(level, newLoaded);
    container.parentNode.insertBefore(newBtn, container.nextSibling);
  }
}

function toggleLowRisk(btn) {
  const container = document.getElementById('risk-cards-low');
  if (!container) return;
  const isHidden = container.style.display === 'none';
  container.style.display = isHidden ? '' : 'none';
  btn.textContent = isHidden ? 'Hide' : 'Show';
}

/* ── Dashboard ────────────────────────────────────────────────────────────── */
function renderDashboard(data) {
  const summaries = data.userSummaries || [];
  const timeline = data.attackTimeline || [];
  const events = data.events || [];
  const homeCountry = data.homeCountry || "ID";

  const wl = state.watchList;
  const watching = summaries.filter((s) => wl.has(s.user));
  const nonWatching = summaries.filter((s) => !wl.has(s.user));
  const criticalUsers = nonWatching.filter((s) => s.riskLevel === "CRITICAL");
  const highUsers = nonWatching.filter((s) => s.riskLevel === "HIGH");
  const mediumUsers = nonWatching.filter((s) => s.riskLevel === "MEDIUM");
  const lowUsers = nonWatching.filter((s) => s.riskLevel === "LOW");

  // Successful foreign logins
  const foreignSuccEvents = events.filter(
    (e) => e.success && e.country && e.country.toUpperCase() !== homeCountry,
  );
  const foreignFailEvents = events.filter(
    (e) => !e.success && e.country && e.country.toUpperCase() !== homeCountry,
  );

  const alertBanners = summaries
    .filter((s) => s.foreignSuccess > 0)
    .map((s) => {
      const e = s.successfulForeignEvents[0];
      const dt = e ? formatDate(e.createdAt || e.time) : "";
      const apps = (s.successfulForeignApps || []).slice(0, 2).join(" & ");
      return `
        <div class="alert-banner">
          <div class="alert-banner-icon"><i class="bi bi-shield-exclamation"></i></div>
          <div class="alert-banner-body">
            <div class="alert-banner-title">Critical — Successful Foreign Login</div>
            <div class="alert-banner-text">
              <strong>${escHtml(s.displayName)}</strong> successfully signed in from
              <strong>${escHtml(e?.foreignCountry || e?.country || "?")}</strong>
              ${e?.foreignCity ? "(" + escHtml(e.foreignCity) + ")" : ""}
              on ${dt}${apps ? " to " + escHtml(apps) : ""}.
              Credentials may be compromised — investigate immediately.
              <a href="#" style="color:var(--accent);margin-left:6px" onclick="openTimeline('${escHtml(s.user)}');return false">View Timeline →</a>
            </div>
          </div>
        </div>`;
    })
    .join("");

  const CARD_BATCH = 15;
  const critHighList = [...criticalUsers, ...highUsers];

  const critSection =
    critHighList.length > 0
      ? `
    <div id="risk-group-high" class="risk-section">
      <div class="section-heading"><i class="bi bi-circle-fill" style="color:#ef4444"></i> High-Risk Accounts <span class="count-badge">${critHighList.length}</span></div>
      <div class="risk-cards" id="risk-cards-high">
        ${critHighList.slice(0, CARD_BATCH).map((s) => renderRiskCard(s)).join("")}
      </div>
      ${critHighList.length > CARD_BATCH ? `<button class="btn-load-more" onclick="loadMoreRiskCards('high',${CARD_BATCH})">Show ${critHighList.length - CARD_BATCH} more high-risk accounts</button>` : ''}
    </div>`
      : "";

  const medSection =
    mediumUsers.length > 0
      ? `
    <div id="risk-group-medium" class="risk-section">
      <div class="section-heading" style="margin-top:4px"><i class="bi bi-circle-fill" style="color:#f59e0b"></i> Medium-Risk Accounts <span class="count-badge">${mediumUsers.length}</span></div>
      <div class="risk-cards" id="risk-cards-medium">
        ${mediumUsers.slice(0, CARD_BATCH).map((s) => renderRiskCard(s, true)).join("")}
      </div>
      ${mediumUsers.length > CARD_BATCH ? `<button class="btn-load-more" onclick="loadMoreRiskCards('medium',${CARD_BATCH})">Show ${mediumUsers.length - CARD_BATCH} more medium-risk accounts</button>` : ''}
    </div>`
      : "";

  const lowSection =
    lowUsers.length > 0
      ? `
    <div id="risk-group-low" class="risk-section">
      <div class="section-heading" style="margin-top:4px"><i class="bi bi-circle-fill" style="color:#10b981"></i> Low-Risk Accounts <span class="count-badge">${lowUsers.length}</span>
        <button class="btn-section-toggle" style="font-size:11px;margin-left:8px;padding:2px 8px" onclick="toggleLowRisk(this)">Show</button>
      </div>
      <div class="risk-cards" id="risk-cards-low" style="display:none">
        ${lowUsers.slice(0, CARD_BATCH).map((s) => renderRiskCard(s, true)).join("")}
        ${lowUsers.length > CARD_BATCH ? `<button class="btn-load-more" onclick="loadMoreRiskCards('low',${CARD_BATCH})">Show ${lowUsers.length - CARD_BATCH} more low-risk accounts</button>` : ''}
      </div>
    </div>`
      : "";

  const watchSection =
    watching.length > 0
      ? `
    <div class="section-heading"><i class="bi bi-star-fill"></i> Watch List <span class="count-badge">${watching.length}</span></div>
    <div class="risk-cards">
      ${watching.map((s) => renderRiskCard(s)).join("")}
    </div>`
      : "";

  const noRisk =
    summaries.length === 0
      ? `
    <div class="empty" style="padding:48px 0">
      <i class="bi bi-check-circle-fill"></i> No suspicious accounts detected in this workspace.
    </div>`
      : "";

  const timelineSection =
    timeline.length > 0 ? renderAttackTimeline(timeline) : "";

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
  const totalEvents = events.length;
  const foreignFail = events.filter(
    (e) => !e.success && e.country && e.country.toUpperCase() !== home,
  ).length;
  const foreignSuccess = events.filter(
    (e) => e.success && e.country && e.country.toUpperCase() !== home,
  ).length;
  const atRisk = summaries.length;

  return `
    <div class="dash-panel">
      <div class="dash-panel-header">
        <span class="dash-panel-title">Summary</span>
      </div>
      <div class="dash-panel-body" style="display:flex;flex-direction:column;gap:10px">
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:12px;color:var(--text2)"><i class="bi bi-exclamation-triangle"></i> Accounts at Risk</span>
          <span style="font-size:18px;font-weight:700;color:${atRisk > 0 ? "var(--danger)" : "var(--ok)"}">${atRisk}</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:12px;color:var(--text2)"><i class="bi bi-bar-chart-fill"></i> Total Events</span>
          <span style="font-size:18px;font-weight:700;color:var(--accent)">${totalEvents.toLocaleString()}</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border)">
          <span style="font-size:12px;color:var(--text2)"><i class="bi bi-x-circle-fill"></i> Foreign Failed</span>
          <span style="font-size:18px;font-weight:700;color:${foreignFail > 0 ? "var(--warn)" : "var(--ok)"}">${foreignFail.toLocaleString()}</span>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0">
          <span style="font-size:12px;color:var(--text2)"><i class="bi bi-globe"></i> Foreign Success</span>
          <span style="font-size:18px;font-weight:700;color:${foreignSuccess > 0 ? "var(--danger)" : "var(--ok)"}">${foreignSuccess}</span>
        </div>
      </div>
    </div>`;
}

function renderRiskCard(s, collapsed = false) {
  const cls = "rc-" + s.riskLevel.toLowerCase();
  const rbCls = "rb-" + s.riskLevel.toLowerCase();
  const isPinned = state.watchList.has(s.user);
  const initials = s.displayName
    .split(" ")
    .map((w) => w[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();
  const cardId = `rc-${Math.random().toString(36).slice(2)}`;

  const timeRange =
    s.attackStart && s.attackEnd
      ? (() => {
          const s1 = formatDate(s.attackStart);
          const s2 = formatDate(s.attackEnd);
          return s1 === s2 ? s1 : `${s1} — ${s2}`;
        })()
      : "";

  const chips = s.attackingCountries
    .slice(0, 12)
    .map((c) => `<span class="country-chip">${escHtml(c)}</span>`)
    .join("");
  const moreChips =
    s.attackingCountries.length > 12
      ? `<span class="country-chip chip-more">+${s.attackingCountries.length - 12} more</span>`
      : "";

  const successColor = s.foreignSuccess > 0 ? "c-danger" : "c-ok";
  const attemptColor =
    s.foreignAttempts > 50
      ? "c-danger"
      : s.foreignAttempts > 10
        ? "c-warn"
        : "c-accent";

  const notePreview = state.userNotes[s.user]
    ? `<div class="rc-note-badge" title="${escHtml(state.userNotes[s.user])}"><i class="bi bi-pencil"></i> ${escHtml(state.userNotes[s.user].slice(0, 60))}${state.userNotes[s.user].length > 60 ? "…" : ""}</div>`
    : "";

  const userHist = state.activeWorkspace
    ? getUserHistory(state.activeWorkspace.id, s.user)
    : null;
  const repeatBadge =
    userHist && userHist.count > 1
      ? `<span class="repeat-badge" title="Seen in ${userHist.count} previous runs — first: ${new Date(userHist.firstSeen).toLocaleDateString("en-GB")}">REPEAT ${userHist.count}×</span>`
      : "";

  const anomalyChips = renderUserAnomalyChips(s.user);

  return `
    <div class="risk-card ${cls}" id="${cardId}">
      <div class="rc-header" onclick="toggleRiskCard('${cardId}')">
        <div class="rc-avatar">${initials}</div>
        <div class="rc-header-info">
          <div class="rc-name">${escHtml(s.displayName)}</div>
          <div class="rc-meta">
            <span class="risk-badge ${rbCls}">${s.riskLevel}</span>
            ${s.riskScore != null ? `<span class="risk-score-badge risk-score-${s.riskLevel.toLowerCase()}" title="Risk Score: ${s.riskScore}/100">${s.riskScore}<span style="font-size:9px;opacity:0.7">/100</span></span>` : ""}
            ${repeatBadge}
            ${highlightedUsers()?.has(s.user.toLowerCase()) ? '<span class="listed-badge" title="In the uploaded target user list"><i class="bi bi-star-fill"></i> LISTED</span>' : ""}
            <span class="rc-threat">${escHtml(s.primaryThreat)}</span>
          </div>
          ${anomalyChips}
        </div>
        <button class="rc-expand-btn${isPinned ? " rc-pin-active" : ""}" onclick="event.stopPropagation();toggleWatchList('${escHtml(s.user)}')" title="${isPinned ? "Unpin from Watch List" : "Pin to Watch List"}">${isPinned ? '<i class="bi bi-star-fill"></i>' : '<i class="bi bi-star"></i>'}</button>
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
          <div class="rc-stat-val" style="font-size:13px;padding-top:4px;color:var(--text2)">${timeRange || "—"}</div>
          <div class="rc-stat-label">Timeframe</div>
        </div>
      </div>
      <div class="rc-body ${collapsed ? "" : "open"}" id="body-${cardId}">
        ${chips || moreChips ? `<div class="country-chips">${chips}${moreChips}</div>` : ""}
        ${s.narrative ? `<div class="rc-narrative">${escHtml(s.narrative)}</div>` : ""}
        ${notePreview}
        <div class="rc-radar-wrap"><canvas class="rc-radar-canvas" id="radar-${cardId}" width="160" height="160"></canvas></div>
      </div>
    </div>`;
}

function toggleRiskCard(cardId) {
  document.getElementById(`body-${cardId}`)?.classList.toggle("open");
}

function renderAttackTimeline(timeline) {
  const items = timeline.map((e) => {
    const t = new Date(e.time);
    const timeStr = isNaN(t)
      ? ""
      : t.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
    const errLabel = e.errorCode
      ? `<span class="atl-err">${e.errorCode}</span>`
      : "";
    const loc = [e.country, e.city].filter(Boolean).join(" / ");
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
    const key = isNaN(d)
      ? "Unknown"
      : d.toLocaleDateString("en-GB", { day: "numeric", month: "short" });
    (byDate[key] = byDate[key] || []).push(items[i]);
  }

  const grouped = Object.entries(byDate)
    .map(
      ([date, rows]) => `
    <div class="atl-separator"><i class="bi bi-calendar"></i> ${date}</div>
    ${rows.join("")}
  `,
    )
    .join("");

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

