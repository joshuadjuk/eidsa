/* ── Events table ─────────────────────────────────────────────────────────── */
function renderEventsTable(allEvents) {
  const q = state.eventsFilter.toLowerCase();
  const homeCountry = (state.analysisData?.homeCountry || "ID").toUpperCase();

  let filtered = allEvents.filter((e) => {
    if (state.eventsStatusFilter === "success" && !e.success) return false;
    if (state.eventsStatusFilter === "fail" && e.success) return false;
    if (state.dateFrom && e.createdAt < state.dateFrom) return false;
    if (state.dateTo && e.createdAt.slice(0, 10) > state.dateTo) return false;
    if (!q) return true;
    return (
      e.userPrincipal +
      e.ipAddress +
      e.country +
      e.appName +
      e.city +
      e.appType
    )
      .toLowerCase()
      .includes(q);
  });

  const { col, dir } = state.eventsSort;
  filtered = filtered.sort((a, b) => {
    const av = a[col] ?? "";
    const bv = b[col] ?? "";
    if (av < bv) return dir === "asc" ? -1 : 1;
    if (av > bv) return dir === "asc" ? 1 : -1;
    return 0;
  });

  const total = filtered.length;
  const pages = Math.max(1, Math.ceil(total / state.eventsPageSize));
  state.eventsPage = Math.min(state.eventsPage, pages);
  const start = (state.eventsPage - 1) * state.eventsPageSize;
  const pageEvents = filtered.slice(start, start + state.eventsPageSize);

  const th = (label, col) => {
    const arrow =
      state.eventsSort.col === col
        ? state.eventsSort.dir === "asc"
          ? " ↑"
          : " ↓"
        : "";
    return `<th onclick="sortEvents('${col}')">${label}${arrow}</th>`;
  };

  const rows = pageEvents
    .map((e) => {
      const isForeign = e.country && e.country.toUpperCase() !== homeCountry;
      const rowClass =
        isForeign && e.success
          ? ' style="background:rgba(251,191,36,0.04)"'
          : "";
      const appTypeClass = `apptype apptype-${(e.appType || "Other").replace(/[\/ ]/g, "")}`;
      return `
      <tr${rowClass} onclick="openTimeline('${escHtml(e.userPrincipal)}')" style="cursor:pointer">
        <td>${formatDate(e.createdAt)}</td>
        <td title="${escHtml(e.userPrincipal)}">${escHtml(e.displayName || e.userPrincipal)}</td>
        <td>${e.success ? '<span class="status-ok"><i class="bi bi-check-lg"></i></span>' : '<span class="status-fail"><i class="bi bi-x-lg"></i></span>'}</td>
        <td>${renderIPClickable(e.ipAddress)}</td>
        <td>${isForeign ? '<i class="bi bi-exclamation-triangle"></i> ' : ""}${escHtml(e.country)}${e.city ? ` / ${escHtml(e.city)}` : ""}</td>
        <td><span class="${appTypeClass}">${escHtml(e.appType || "Other")}</span></td>
        <td title="${escHtml(e.appName)}">${escHtml(e.appName).slice(0, 28)}</td>
        <td title="${escHtml(e.failureReason)}">${e.errorCode !== null && e.errorCode !== 0 ? e.errorCode : ""}</td>
      </tr>`;
    })
    .join("");

  const totalAvailable = state.analysisData?.total || allEvents.length;
  const loadedCount = allEvents.length;
  const stillLoading =
    state.analysisData?.eventsLimited && loadedCount < totalAvailable;
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
        <option value="all"     ${state.eventsStatusFilter === "all" ? "selected" : ""}>All</option>
        <option value="success" ${state.eventsStatusFilter === "success" ? "selected" : ""}>Success only</option>
        <option value="fail"    ${state.eventsStatusFilter === "fail" ? "selected" : ""}>Failed only</option>
      </select>
      <div class="date-filter">
        <span>From</span>
        <input type="date" value="${escHtml(state.dateFrom)}" onchange="filterDateFrom(this.value)" />
        <span>To</span>
        <input type="date" value="${escHtml(state.dateTo)}" onchange="filterDateTo(this.value)" />
        ${state.dateFrom || state.dateTo ? `<button class="btn-secondary" style="font-size:11px;padding:3px 8px" onclick="clearDateFilter()"><i class="bi bi-x"></i> Clear</button>` : ""}
      </div>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr>
          ${th("Time", "createdAt")}
          ${th("User", "displayName")}
          ${th("Status", "success")}
          ${th("IP", "ipAddress")}
          ${th("Location", "country")}
          ${th("Type", "appType")}
          ${th("App", "appName")}
          ${th("Error", "errorCode")}
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="8" class="empty">No events match filter.</td></tr>'}</tbody>
      </table>
    </div>
    <div class="pagination">
      <button onclick="changePage(-1)" ${state.eventsPage === 1 ? "disabled" : ""}>← Prev</button>
      <span>Page ${state.eventsPage} of ${pages} (${total.toLocaleString()} shown${stillLoading ? ` · ${totalAvailable.toLocaleString()} total` : ""} — click row for timeline)</span>
      <button onclick="changePage(1)" ${state.eventsPage === pages ? "disabled" : ""}>Next →</button>
    </div>`;
}

function filterEvents(val) {
  state.eventsFilter = val;
  state.eventsPage = 1;
  rerenderTable();
}
function filterStatus(val) {
  state.eventsStatusFilter = val;
  state.eventsPage = 1;
  rerenderTable();
}
function filterDateFrom(val) {
  state.dateFrom = val;
  state.eventsPage = 1;
  rerenderTable();
}
function filterDateTo(val) {
  state.dateTo = val;
  state.eventsPage = 1;
  rerenderTable();
}
function clearDateFilter() {
  state.dateFrom = "";
  state.dateTo = "";
  state.eventsPage = 1;
  rerenderTable();
}

function sortEvents(col) {
  if (state.eventsSort.col === col) {
    state.eventsSort.dir = state.eventsSort.dir === "asc" ? "desc" : "asc";
  } else {
    state.eventsSort = { col, dir: "asc" };
  }
  rerenderTable();
}

function changePage(delta) {
  state.eventsPage += delta;
  rerenderTable();
}

function rerenderTable() {
  const panel = document.getElementById("tab-events");
  if (!panel || !state.analysisData) return;
  panel.innerHTML = renderEventsTable(state.analysisData.events);
}

/* ── GeoIP Map (Leaflet) ──────────────────────────────────────────────────── */
// Country centroid coords (subset — same as server-side)
const COUNTRY_COORDS = {
  ID: [-2.5, 118.0],
  US: [37.1, -95.7],
  CN: [35.0, 105.0],
  RU: [61.5, 105.3],
  IN: [20.6, 78.9],
  SG: [1.3, 103.8],
  AU: [-25.3, 133.8],
  GB: [55.4, -3.4],
  NL: [52.1, 5.3],
  DE: [51.2, 10.5],
  FR: [46.2, 2.2],
  JP: [36.2, 138.3],
  KR: [35.9, 127.8],
  BR: [-14.2, -51.9],
  CA: [56.1, -106.3],
  MY: [4.2, 109.5],
  PH: [12.9, 121.8],
  TH: [15.9, 100.9],
  VN: [14.1, 108.3],
  NG: [9.1, 8.7],
  PK: [30.4, 69.3],
  BD: [23.7, 90.4],
  UA: [48.4, 31.2],
  TR: [38.9, 35.2],
  IR: [32.4, 53.7],
  HK: [22.3, 114.2],
  TW: [23.7, 121.0],
  SA: [23.9, 45.1],
  AE: [23.4, 53.8],
  EG: [26.8, 30.8],
  ZA: [-30.6, 22.9],
  MX: [23.6, -102.6],
  AR: [-38.4, -63.6],
  IT: [41.9, 12.6],
  ES: [40.5, -3.7],
  PL: [51.9, 19.1],
  CZ: [49.8, 15.5],
  RO: [45.9, 24.9],
  SE: [60.1, 18.6],
  NO: [60.5, 8.5],
  FI: [61.9, 25.7],
  DK: [56.3, 9.5],
  CH: [46.8, 8.2],
  AT: [47.5, 14.6],
  BE: [50.5, 4.5],
  PT: [39.4, -8.2],
  GR: [39.1, 21.8],
  NZ: [-40.9, 174.9],
  IL: [31.0, 34.9],
  CL: [-35.7, -71.5],
  CO: [4.6, -74.1],
  PE: [-9.2, -75.0],
};

function initMap() {
  const container = document.getElementById("map-container");
  if (!container) return;
  if (state.leafletMap) return; // already initialized

  const data = state.analysisData;
  if (!data) return;

  const homeCountry = (data.homeCountry || "ID").toUpperCase();
  const geoSummary = data.geoSummary || {};

  const map = L.map("map-container", {
    center: [10, 20],
    zoom: 2,
    minZoom: 1,
    maxZoom: 8,
  });

  state.leafletMap = map;

  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
    attribution: "© OpenStreetMap, © CARTO",
    subdomains: "abcd",
    maxZoom: 19,
  }).addTo(map);

  for (const [country, stats] of Object.entries(geoSummary)) {
    const coords = COUNTRY_COORDS[country.toUpperCase()];
    if (!coords) continue;

    const isHome = country.toUpperCase() === homeCountry;
    const radius = Math.min(8 + Math.sqrt(stats.total) * 2.5, 40);
    const color = isHome ? "#4f8ef7" : stats.total > 10 ? "#f87171" : "#fbbf24";
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
    .map((c) => COUNTRY_COORDS[c.toUpperCase()])
    .filter(Boolean);
  if (points.length > 0) {
    map.fitBounds(L.latLngBounds(points), { padding: [30, 30], maxZoom: 5 });
  }
}

/* ── Charts ───────────────────────────────────────────────────────────────── */
function destroyCharts() {
  Object.values(state.chartInstances).forEach((c) => {
    try {
      c.destroy();
    } catch (e) {}
  });
  state.chartInstances = {};
}

function initCharts() {
  const container = document.getElementById("charts-container");
  if (!container || !state.analysisData) return;

  destroyCharts();

  const data = state.analysisData;
  const events = data.events || [];
  const homeCountry = (data.homeCountry || "ID").toUpperCase();

  // ── Data: events over time (daily) ──────────────────────────────────────
  const byDay = {};
  for (const e of events) {
    const day = e.createdAt?.slice(0, 10);
    if (!day) continue;
    if (!byDay[day]) byDay[day] = { success: 0, fail: 0 };
    if (e.success) byDay[day].success++;
    else byDay[day].fail++;
  }
  const days = Object.keys(byDay).sort();
  const daySuccess = days.map((d) => byDay[d].success);
  const dayFail = days.map((d) => byDay[d].fail);
  const dayLabels = days.map((d) => {
    const dt = new Date(d);
    return dt.toLocaleDateString("en-GB", { day: "numeric", month: "short" });
  });

  // ── Data: top 10 attacking countries ────────────────────────────────────
  const ctryCounts = {};
  for (const e of events) {
    if (!e.country || e.country.toUpperCase() === homeCountry) continue;
    ctryCounts[e.country] = (ctryCounts[e.country] || 0) + 1;
  }
  const topCtry = Object.entries(ctryCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // ── Data: error code breakdown ───────────────────────────────────────────
  const errLabels = {
    50126: "Invalid password",
    50053: "Account locked",
    50076: "MFA required",
    50057: "Disabled",
    50074: "MFA needed",
    500121: "Strong auth failed",
    53003: "Conditional Access",
  };
  const errCounts = {};
  for (const e of events) {
    if (e.success || !e.errorCode) continue;
    const label = errLabels[e.errorCode] || `Error ${e.errorCode}`;
    errCounts[label] = (errCounts[label] || 0) + 1;
  }
  const topErr = Object.entries(errCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  // ── Data: app type distribution ──────────────────────────────────────────
  const appTypeCounts = {};
  for (const e of events) {
    const t = e.appType || "Other";
    appTypeCounts[t] = (appTypeCounts[t] || 0) + 1;
  }

  const PALETTE = [
    "#5b8def",
    "#f16060",
    "#f5a623",
    "#2ec99a",
    "#a78bfa",
    "#fb923c",
    "#34d399",
    "#60a5fa",
  ];
  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: "#7a88a4", font: { size: 11 } } } },
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
  state.chartInstances.timeline = new Chart(
    document.getElementById("chart-timeline"),
    {
      type: "bar",
      data: {
        labels: dayLabels,
        datasets: [
          {
            label: "Success",
            data: daySuccess,
            backgroundColor: "rgba(46,201,154,0.7)",
            borderRadius: 3,
          },
          {
            label: "Failed",
            data: dayFail,
            backgroundColor: "rgba(241,96,96,0.7)",
            borderRadius: 3,
          },
        ],
      },
      options: {
        ...chartDefaults,
        scales: {
          x: {
            stacked: true,
            ticks: { color: "#7a88a4", maxRotation: 45, font: { size: 10 } },
            grid: { color: "#1d2438" },
          },
          y: {
            stacked: true,
            ticks: { color: "#7a88a4", font: { size: 10 } },
            grid: { color: "#1d2438" },
          },
        },
      },
    },
  );

  // Top attacking countries
  state.chartInstances.countries = new Chart(
    document.getElementById("chart-countries"),
    {
      type: "bar",
      data: {
        labels: topCtry.map(([c]) => c),
        datasets: [
          {
            label: "Events",
            data: topCtry.map(([, n]) => n),
            backgroundColor: PALETTE,
            borderRadius: 3,
          },
        ],
      },
      options: {
        ...chartDefaults,
        indexAxis: "y",
        scales: {
          x: {
            ticks: { color: "#7a88a4", font: { size: 10 } },
            grid: { color: "#1d2438" },
          },
          y: {
            ticks: { color: "#e4eaf6", font: { size: 11 } },
            grid: { display: false },
          },
        },
        plugins: { legend: { display: false } },
      },
    },
  );

  // Error codes
  if (topErr.length > 0) {
    state.chartInstances.errors = new Chart(
      document.getElementById("chart-errors"),
      {
        type: "doughnut",
        data: {
          labels: topErr.map(([l]) => l),
          datasets: [
            {
              data: topErr.map(([, n]) => n),
              backgroundColor: PALETTE,
              borderWidth: 2,
              borderColor: "#111520",
            },
          ],
        },
        options: { ...chartDefaults, cutout: "60%" },
      },
    );
  } else {
    document.getElementById("chart-errors").parentElement.innerHTML +=
      '<div style="text-align:center;color:var(--text3);padding-top:60px;font-size:12px">No failed events with error codes</div>';
  }

  // App types
  const appTypeEntries = Object.entries(appTypeCounts);
  state.chartInstances.apptypes = new Chart(
    document.getElementById("chart-apptypes"),
    {
      type: "doughnut",
      data: {
        labels: appTypeEntries.map(([t]) => t),
        datasets: [
          {
            data: appTypeEntries.map(([, n]) => n),
            backgroundColor: PALETTE,
            borderWidth: 2,
            borderColor: "#111520",
          },
        ],
      },
      options: { ...chartDefaults, cutout: "60%" },
    },
  );

  // ── Heatmap (hour × day-of-week) ─────────────────────────────────────────
  const grid = document.querySelector(".charts-grid");
  if (grid) {
    const heatAllHTML = buildHeatmapSVG(
      events,
      "Login Heatmap — All Events",
      "#5b8def",
    );
    const heatFailHTML = buildHeatmapSVG(
      events.filter((e) => !e.success),
      "Login Heatmap — Failed Attempts",
      "#f16060",
    );
    const heatDiv = document.createElement("div");
    heatDiv.style.cssText =
      "grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr;gap:14px";
    heatDiv.innerHTML = heatAllHTML + heatFailHTML;
    grid.appendChild(heatDiv);

    // ── ASN / ISP clustering ────────────────────────────────────────────────
    const asnHTML = buildASNSection(
      data.ipEnrichment || {},
      events,
      homeCountry,
    );
    if (asnHTML) {
      const asnDiv = document.createElement("div");
      asnDiv.style.cssText = "grid-column:1/-1";
      asnDiv.innerHTML = asnHTML;
      grid.appendChild(asnDiv);
    }
  }
}

/* ── Kill Chain Coverage Matrix ──────────────────────────────────────────── */
function initKillChain() {
  const container = document.getElementById("killchain-container");
  if (!container || !state.analysisData) return;

  const detections = state.analysisData.detections || [];
  if (detections.length === 0) {
    container.innerHTML =
      '<div style="padding:48px;text-align:center;color:var(--text3);font-size:13px">No detections — Kill Chain matrix is empty.</div>';
    return;
  }

  const TACTICS = [
    "Initial Access",
    "Credential Access",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Execution",
    "Discovery",
    "Lateral Movement",
  ];
  const SEV_COLOR = { high: "#dc2626", medium: "#d97706", low: "#2563eb" };
  const SEV_BG = {
    high: "rgba(220,38,38,0.13)",
    medium: "rgba(217,119,6,0.11)",
    low: "rgba(37,99,235,0.11)",
  };

  // Build matrix: user -> tactic -> { count, sev, types }
  const matrix = {};
  for (const det of detections) {
    const mitre = MITRE_MAP[det.type];
    if (!mitre || !TACTICS.includes(mitre.tactic)) continue;
    const tactic = mitre.tactic;

    const users = new Set();
    if (det.user) users.add(det.user);
    if (det.affectedUsers)
      det.affectedUsers.slice(0, 8).forEach((u) => users.add(u));
    if (users.size === 0 && det.ip) users.add(`[IP] ${det.ip}`);

    for (const user of users) {
      if (!matrix[user]) matrix[user] = {};
      if (!matrix[user][tactic])
        matrix[user][tactic] = { count: 0, sev: "low", types: [] };
      matrix[user][tactic].count++;
      matrix[user][tactic].types.push(det.type);
      if (det.severity === "high") matrix[user][tactic].sev = "high";
      else if (det.severity === "medium" && matrix[user][tactic].sev !== "high")
        matrix[user][tactic].sev = "medium";
    }
  }

  const users = Object.keys(matrix)
    .sort((a, b) => {
      const ca = Object.values(matrix[a]).reduce((s, v) => s + v.count, 0);
      const cb = Object.values(matrix[b]).reduce((s, v) => s + v.count, 0);
      return cb - ca;
    })
    .slice(0, 25);

  const f = state.killChainFilter;

  const headerCells = TACTICS.map(
    (t) => `<th class="kc-th">${t.replace(" ", "<br>")}</th>`,
  ).join("");

  const rows = users
    .map((user) => {
      const display = user.length > 34 ? user.slice(0, 32) + "…" : user;
      const cells = TACTICS.map((tactic) => {
        const cell = matrix[user]?.[tactic];
        if (!cell) return `<td class="kc-td kc-empty"></td>`;
        const sev = cell.sev;
        const isActive = f && f.user === user && f.tactic === tactic;
        const typeNames = [...new Set(cell.types)]
          .map((t) => t.replace(/_/g, " "))
          .join(", ");
        return `<td class="kc-td kc-hit${isActive ? " kc-active-cell" : ""}"
        style="background:${SEV_BG[sev]};border-color:${SEV_COLOR[sev]}40"
        onclick="killChainCellClick(${JSON.stringify(user)},${JSON.stringify(tactic)})"
        title="${escHtml(typeNames)}">
        <div class="kc-count" style="color:${SEV_COLOR[sev]}">${cell.count}</div>
        <div class="kc-sev" style="color:${SEV_COLOR[sev]}">${sev.toUpperCase()}</div>
      </td>`;
      }).join("");
      const total = Object.values(matrix[user]).reduce(
        (s, v) => s + v.count,
        0,
      );
      const isFilteredUser = f && f.user === user;
      return `<tr class="${isFilteredUser ? "kc-row-active" : ""}">
      <td class="kc-user" title="${escHtml(user)}">${escHtml(display)}</td>
      ${cells}
      <td class="kc-total">${total}</td>
    </tr>`;
    })
    .join("");

  const filterBar = f
    ? `
    <div class="kc-filter-bar">
      Highlighting: <strong>${escHtml(f.user)}</strong> — <em>${escHtml(f.tactic)}</em>
      <button class="btn-secondary" style="font-size:11px;padding:2px 10px;margin-left:12px" onclick="clearKillChainFilter()"><i class="bi bi-x"></i> Clear</button>
    </div>`
    : "";

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
  switchTab("detections");
}

function clearKillChainFilter() {
  state.killChainFilter = null;
  initKillChain();
  rerenderDetections();
}

/* ── Attack Velocity Timeline ─────────────────────────────────────────────── */
function initVelocity() {
  const container = document.getElementById("velocity-container");
  if (!container || !state.analysisData) return;

  const events = state.analysisData.events || [];
  const homeCountry = (state.analysisData.homeCountry || "ID").toUpperCase();

  // Top 5 foreign IPs by failed event count
  const ipCounts = {};
  for (const e of events) {
    if (!e.ipAddress || e.success) continue;
    if (e.country && e.country.toUpperCase() === homeCountry) continue;
    ipCounts[e.ipAddress] = (ipCounts[e.ipAddress] || 0) + 1;
  }
  const topIPs = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip]) => ip);

  if (topIPs.length === 0) {
    container.innerHTML =
      '<div style="padding:48px;text-align:center;color:var(--text3);font-size:13px">No foreign failed events to plot velocity for.</div>';
    return;
  }

  // Bucket events into 15-minute intervals
  const BUCKET_MS = 15 * 60 * 1000;
  const ipTimes = {};
  const allTs = [];

  for (const ip of topIPs) {
    const ts = events
      .filter((e) => e.ipAddress === ip && !e.success)
      .map((e) => new Date(e.createdAt).getTime())
      .filter((t) => !isNaN(t));
    ipTimes[ip] = ts.sort((a, b) => a - b);
    allTs.push(...ts);
  }

  if (allTs.length === 0) {
    container.innerHTML =
      '<div style="padding:48px;text-align:center;color:var(--text3)">No data.</div>';
    return;
  }

  const minT = Math.min(...allTs);
  const maxT = Math.max(...allTs);
  const numBuckets = Math.ceil((maxT - minT) / BUCKET_MS) + 1;

  const labels = Array.from({ length: numBuckets }, (_, i) => {
    const t = new Date(minT + i * BUCKET_MS);
    return t.toLocaleString("en-GB", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  });

  const COLORS = ["#f16060", "#f5a623", "#5b8def", "#2ec99a", "#a78bfa"];
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
      backgroundColor: COLORS[i] + "18",
      fill: true,
      tension: 0.35,
      pointRadius: 2,
      borderWidth: 2,
    };
  });

  container.innerHTML = `
    <div style="padding:16px 20px 24px">
      <div class="section-title" style="margin-bottom:4px">Attack Velocity Timeline</div>
      <div style="font-size:12px;color:var(--text3);margin-bottom:16px">Failed sign-in events per 15-minute bucket — top ${topIPs.length} foreign attacking IP${topIPs.length > 1 ? "s" : ""}</div>
      <div style="height:340px"><canvas id="chart-velocity"></canvas></div>
    </div>`;

  new Chart(document.getElementById("chart-velocity"), {
    type: "line",
    data: { labels, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { labels: { color: "#7a88a4", font: { size: 11 } } },
      },
      scales: {
        x: {
          ticks: {
            color: "#7a88a4",
            font: { size: 9 },
            maxRotation: 45,
            maxTicksLimit: 24,
          },
          grid: { color: "#1d2438" },
        },
        y: {
          beginAtZero: true,
          ticks: { color: "#7a88a4", font: { size: 10 }, precision: 0 },
          grid: { color: "#1d2438" },
          title: {
            display: true,
            text: "Events / 15 min",
            color: "#7a88a4",
            font: { size: 10 },
          },
        },
      },
    },
  });
}

/* ── Login Heatmap ────────────────────────────────────────────────────────── */
function buildHeatmapSVG(events, title, color) {
  const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const grid = Array.from({ length: 7 }, () => new Array(24).fill(0));
  for (const e of events) {
    if (!e.createdAt) continue;
    const d = new Date(e.createdAt);
    if (isNaN(d)) continue;
    grid[d.getUTCDay()][d.getUTCHours()]++;
  }
  const maxVal = Math.max(...grid.flat(), 1);

  const CELL = 17;
  const GAP = 2;
  const LW = 30;
  const LH = 18;
  const W = LW + 24 * (CELL + GAP);
  const H = LH + 7 * (CELL + GAP) + 14;

  const cells = grid
    .flatMap((row, d) =>
      row.map((count, h) => {
        const alpha = count === 0 ? 0.06 : 0.12 + (count / maxVal) * 0.88;
        const x = LW + h * (CELL + GAP);
        const y = LH + d * (CELL + GAP);
        return `<rect x="${x}" y="${y}" width="${CELL}" height="${CELL}" rx="2"
        fill="${color}" fill-opacity="${alpha.toFixed(2)}">
        <title>${DAYS[d]} ${String(h).padStart(2, "0")}:00 UTC — ${count} event${count !== 1 ? "s" : ""}</title>
      </rect>`;
      }),
    )
    .join("");

  const hLabels = [0, 3, 6, 9, 12, 15, 18, 21]
    .map(
      (h) =>
        `<text x="${LW + h * (CELL + GAP) + CELL / 2}" y="${LH - 4}" text-anchor="middle" font-size="9" fill="#4d5a72">${String(h).padStart(2, "0")}</text>`,
    )
    .join("");

  const dLabels = DAYS.map(
    (d, i) =>
      `<text x="${LW - 4}" y="${LH + i * (CELL + GAP) + CELL / 2 + 3}" text-anchor="end" font-size="9" fill="#7a88a4">${d}</text>`,
  ).join("");

  return `
    <div class="chart-card">
      <div class="chart-card-title">${title}</div>
      <div style="overflow-x:auto;padding:4px 0">
        <svg width="${W}" height="${H}" xmlns="http://www.w3.org/2000/svg" style="font-family:Inter,sans-serif;display:block">
          ${hLabels}${dLabels}${cells}
          <text x="${LW + 12 * (CELL + GAP)}" y="${H}" text-anchor="middle" font-size="9" fill="#3a4560">← UTC hour →</text>
        </svg>
      </div>
    </div>`;
}

/* ── ASN / ISP Clustering ─────────────────────────────────────────────────── */
function buildASNSection(ipEnrichment, events, homeCountry) {
  // Count events per foreign IP
  const ipEventCount = {};
  for (const e of events) {
    if (!e.ipAddress || !e.country || e.country.toUpperCase() === homeCountry)
      continue;
    ipEventCount[e.ipAddress] = (ipEventCount[e.ipAddress] || 0) + 1;
  }

  // Group by ASN/ISP
  const asnMap = {};
  for (const [ip, info] of Object.entries(ipEnrichment)) {
    if (!ipEventCount[ip]) continue;
    const key = info.as || info.isp || "Unknown";
    const label =
      (info.isp || info.org || info.as || "Unknown")
        .replace(/^AS\d+\s*/, "")
        .trim()
        .slice(0, 36) || key;
    if (!asnMap[key])
      asnMap[key] = { label, count: 0, ips: 0, proxy: false, hosting: false };
    asnMap[key].count += ipEventCount[ip];
    asnMap[key].ips++;
    if (info.proxy) asnMap[key].proxy = true;
    if (info.hosting) asnMap[key].hosting = true;
  }

  const top = Object.values(asnMap)
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
  if (top.length === 0) return "";

  const maxCount = top[0].count;
  const rows = top
    .map((a) => {
      const pct = Math.round((a.count / maxCount) * 100);
      const badge = a.hosting
        ? `<span class="asn-badge" style="background:rgba(241,96,96,0.15);color:#f16060">HOSTING</span>`
        : a.proxy
          ? `<span class="asn-badge" style="background:rgba(245,166,35,0.15);color:#f5a623">PROXY</span>`
          : "";
      return `
      <div class="asn-row">
        <div class="asn-label">${escHtml(a.label)} ${badge}</div>
        <div class="asn-bar-wrap"><div class="asn-bar" style="width:${pct}%"></div></div>
        <div class="asn-count">${a.count.toLocaleString()} <span style="color:var(--text3);font-size:10px">(${a.ips} IP${a.ips > 1 ? "s" : ""})</span></div>
      </div>`;
    })
    .join("");

  return `
    <div class="chart-card" style="grid-column:1/-1">
      <div class="chart-card-title">Top Attack Sources by ISP / ASN</div>
      <div class="asn-chart">${rows}</div>
    </div>`;
}

/* ── Tenant Health Score ──────────────────────────────────────────────────── */
function renderHealthScore(events, detections) {
  if (!events.length) return "";
  const homeCountry = (state.analysisData?.homeCountry || "ID").toUpperCase();

  // CA Policy coverage
  const interactive = events.filter(
    (e) => e.signInType === "interactive" || !e.signInType,
  );
  const caApplied = interactive.filter(
    (e) =>
      e.conditionalAccessStatus === "success" ||
      e.conditionalAccessStatus === "enforced",
  ).length;
  const caRate = interactive.length > 0 ? caApplied / interactive.length : 0;

  // Legacy auth exposure
  const legacyRate =
    events.filter((e) => e.appType === "Legacy").length / events.length;

  // Foreign login prevention
  const foreignEvts = events.filter(
    (e) => e.country && e.country.toUpperCase() !== homeCountry,
  );
  const foreignSuccess = foreignEvts.filter((e) => e.success).length;
  const foreignPrevent =
    foreignEvts.length > 0 ? 1 - foreignSuccess / foreignEvts.length : 1;

  // MFA enforcement on foreign failed attempts
  const MFA_ERRORS = new Set([50076, 500121, 50074, 53003, 50158]);
  const foreignFail = foreignEvts.filter((e) => !e.success);
  const mfaBlocked = foreignFail.filter((e) =>
    MFA_ERRORS.has(e.errorCode),
  ).length;
  const mfaRate = foreignFail.length > 0 ? mfaBlocked / foreignFail.length : 1;

  // Weighted score (total = 100)
  const caScore = Math.round(caRate * 35);
  const legacyScore = Math.round((1 - Math.min(legacyRate * 5, 1)) * 25);
  const foreignScore = Math.round(foreignPrevent * 25);
  const mfaScore = Math.round(mfaRate * 15);
  const total = caScore + legacyScore + foreignScore + mfaScore;

  const scoreColor =
    total >= 75 ? "var(--ok)" : total >= 45 ? "var(--warn)" : "var(--danger)";
  const scoreLabel = total >= 75 ? "Good" : total >= 45 ? "Fair" : "At Risk";

  const metric = (label, rate, pts, maxPts, invert = false) => {
    const display = Math.round(rate * 100);
    const barPct = invert
      ? Math.round((1 - Math.min(rate * 5, 1)) * 100)
      : display;
    const c = invert
      ? display < 5
        ? "var(--ok)"
        : display < 20
          ? "var(--warn)"
          : "var(--danger)"
      : display > 70
        ? "var(--ok)"
        : display > 40
          ? "var(--warn)"
          : "var(--danger)";
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
        ${metric("CA Policy Coverage", caRate, caScore, 35)}
        ${metric("Legacy Auth Exposure", legacyRate, legacyScore, 25, true)}
        ${metric("Foreign Login Prevention", foreignPrevent, foreignScore, 25)}
        ${metric("MFA on Foreign Fails", mfaRate, mfaScore, 15)}
      </div>
    </div>`;
}

