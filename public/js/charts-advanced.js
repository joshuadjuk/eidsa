/* ── Sparkline helper ─────────────────────────────────────────────────────── */
function buildDetSparkline(det) {
  const events = state.analysisData?.events || [];
  const now = Date.now();
  const DAY = 86400000;
  // Collect events relevant to this detection
  let relevant = events;
  if (det.user) relevant = events.filter((e) => e.userPrincipal === det.user);
  else if (det.ip) relevant = events.filter((e) => e.ipAddress === det.ip);
  if (!relevant.length) return "";

  // Count events per day for last 7 days
  const buckets = Array(7).fill(0);
  relevant.forEach((e) => {
    const t = new Date(e.createdAt).getTime();
    const daysAgo = Math.floor((now - t) / DAY);
    if (daysAgo >= 0 && daysAgo < 7) buckets[6 - daysAgo]++;
  });
  if (buckets.every((v) => v === 0)) return "";

  const max = Math.max(...buckets, 1);
  const W = 70,
    H = 20,
    pad = 2;
  const pts = buckets
    .map((v, i) => {
      const x = pad + (i / 6) * (W - pad * 2);
      const y = H - pad - (v / max) * (H - pad * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  return `<svg class="det-sparkline" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" title="Events last 7 days">
    <polyline points="${pts}" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-linejoin="round"/>
    ${buckets
      .map((v, i) => {
        const x = pad + (i / 6) * (W - pad * 2);
        const y = H - pad - (v / max) * (H - pad * 2);
        return v > 0
          ? `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2" fill="var(--accent)"/>`
          : "";
      })
      .join("")}
  </svg>`;
}

/* ── Radar Chart (per user risk card) ─────────────────────────────────────── */
function initAllRadarCharts() {
  const summaries = state.analysisData?.userSummaries || [];
  summaries.forEach((s) => {
    // find canvas by looking at all rc-radar-canvas elements and matching data
    document.querySelectorAll(".rc-radar-canvas").forEach((canvas) => {
      if (canvas.dataset.init) return;
      canvas.dataset.init = "1";
      const cardId = canvas.id.replace("radar-", "");

      // Compute 6 axes from detections and stats
      const dets = s.detections || [];
      // Only init the canvas that belongs to this summary — match by checking nearby rc-name text
      const card = canvas.closest(".risk-card");
      if (!card) return;
      const nameEl = card.querySelector(".rc-name");
      if (!nameEl || nameEl.textContent.trim() !== s.displayName) return;

      const hasType = (...types) =>
        dets.some((d) => types.includes(d.type)) ? 1 : 0;
      const geoRisk = Math.min((s.uniqueAttackingCountries || 0) / 5, 1);
      const authFail = Math.min((s.foreignAttempts || 0) / 50, 1);
      const sprayBrute = hasType(
        "PASSWORD_SPRAY",
        "BRUTE_FORCE",
        "DISTRIBUTED_BRUTE_FORCE",
      );
      const legacyMfa = hasType(
        "LEGACY_AUTH",
        "MFA_EXHAUSTION",
        "MFA_METHOD_DOWNGRADE",
        "CA_GAP",
        "ENTRA_RISKY_SIGNIN",
      );
      const deviceGeo = hasType(
        "DEVICE_FINGERPRINT_ANOMALY",
        "IMPOSSIBLE_TRAVEL",
        "CONCURRENT_SESSIONS",
      );
      const persistence = hasType(
        "TOKEN_REPLAY",
        "OAUTH_CONSENT_PHISHING",
        "RARE_APP_ACCESS",
        "FOREIGN_LOGIN",
        "MFA_REGISTRATION_AFTER_COMPROMISE",
        "OAUTH_CONSENT_GRANT",
        "PRIVILEGED_ROLE_ASSIGNMENT",
        "APP_CREDENTIAL_ADDED",
      )
        ? 1
        : Math.min((s.foreignSuccess || 0) / 3, 1);

      const existing = Chart.getChart(canvas);
      if (existing) existing.destroy();

      new Chart(canvas, {
        type: "radar",
        data: {
          labels: [
            "Geo",
            "Auth Fail",
            "Spray/Brute",
            "Legacy/MFA",
            "Device/Travel",
            "Persistence",
          ],
          datasets: [
            {
              data: [
                geoRisk,
                authFail,
                sprayBrute,
                legacyMfa,
                deviceGeo,
                persistence,
              ],
              backgroundColor: "rgba(99,102,241,0.15)",
              borderColor: "rgba(99,102,241,0.8)",
              borderWidth: 1.5,
              pointBackgroundColor: "rgba(99,102,241,0.9)",
              pointRadius: 2,
            },
          ],
        },
        options: {
          responsive: false,
          animation: false,
          scales: {
            r: {
              min: 0,
              max: 1,
              ticks: { display: false, stepSize: 0.5 },
              grid: { color: "rgba(128,128,128,0.2)" },
              angleLines: { color: "rgba(128,128,128,0.2)" },
              pointLabels: { font: { size: 8 }, color: "var(--text2)" },
            },
          },
          plugins: { legend: { display: false } },
        },
      });
    });
  });
}

/* ── Timeline Swimlane ────────────────────────────────────────────────────── */
function initSwimlane() {
  const el = document.getElementById("swimlane-container");
  if (!el) return;
  const data = state.analysisData;
  if (!data) {
    el.innerHTML =
      '<p style="padding:20px;color:var(--text2)">No analysis data.</p>';
    return;
  }

  const events = data.events || [];
  const summaries = (data.userSummaries || []).slice(0, 20); // top 20 users
  if (!summaries.length) {
    el.innerHTML =
      '<p style="padding:20px;color:var(--text2)">No user data.</p>';
    return;
  }

  // Time range
  const times = events
    .map((e) => new Date(e.createdAt).getTime())
    .filter((t) => !isNaN(t));
  if (!times.length) {
    el.innerHTML =
      '<p style="padding:20px;color:var(--text2)">No timestamped events.</p>';
    return;
  }
  const tMin = Math.min(...times),
    tMax = Math.max(...times);
  const tRange = tMax - tMin || 1;

  const ROW_H = 32,
    PAD_LEFT = 180,
    PAD_RIGHT = 20,
    PAD_TOP = 40,
    DOT_R = 4;
  const W = Math.max(800, el.clientWidth || 900);
  const svgW = W - 4;
  const svgH = PAD_TOP + summaries.length * ROW_H + 20;

  // Build event index by user
  const byUser = {};
  events.forEach((e) => {
    const u = e.userPrincipal;
    if (!byUser[u]) byUser[u] = [];
    byUser[u].push(e);
  });

  // Detection index by user
  const detByUser = {};
  (data.detections || []).forEach((d) => {
    if (d.user) {
      if (!detByUser[d.user]) detByUser[d.user] = [];
      detByUser[d.user].push(d);
    }
  });

  const xOf = (t) =>
    PAD_LEFT + ((t - tMin) / tRange) * (svgW - PAD_LEFT - PAD_RIGHT);

  // Time axis ticks
  const tickCount = 6;
  const ticks = Array.from({ length: tickCount + 1 }, (_, i) => {
    const t = tMin + (i / tickCount) * tRange;
    const x = xOf(t);
    const label = new Date(t).toLocaleDateString("en-GB", {
      month: "short",
      day: "numeric",
    });
    return `<line x1="${x.toFixed(1)}" y1="${PAD_TOP - 5}" x2="${x.toFixed(1)}" y2="${svgH - 10}" stroke="var(--border)" stroke-width="0.5"/>
      <text x="${x.toFixed(1)}" y="${PAD_TOP - 8}" text-anchor="middle" font-size="9" fill="var(--text2)">${label}</text>`;
  }).join("");

  const rows = summaries
    .map((s, i) => {
      const y = PAD_TOP + i * ROW_H + ROW_H / 2;
      const userEvents = byUser[s.user] || [];
      const userDets = detByUser[s.user] || [];

      // Lane line
      const lane = `<line x1="${PAD_LEFT}" y1="${y}" x2="${svgW - PAD_RIGHT}" y2="${y}" stroke="var(--border)" stroke-width="0.5"/>`;

      // User label
      const label = `<text x="${PAD_LEFT - 8}" y="${y + 4}" text-anchor="end" font-size="10" fill="var(--text1)" font-weight="500">${escHtml(s.displayName.slice(0, 22))}</text>`;

      // Risk badge color
      const riskCol =
        {
          CRITICAL: "#ef4444",
          HIGH: "#f97316",
          MEDIUM: "#eab308",
          LOW: "#22c55e",
        }[s.riskLevel] || "#6b7280";
      const badge = `<rect x="2" y="${y - 8}" width="8" height="16" rx="2" fill="${riskCol}"/>`;

      // Event dots
      const dots = userEvents
        .map((e) => {
          const t = new Date(e.createdAt).getTime();
          if (isNaN(t)) return "";
          const x = xOf(t);
          const col = e.success ? "#22c55e" : "#ef4444";
          const tip =
            `${e.appName || ""} ${e.country || ""} ${e.success ? "✓" : "✗"}`.trim();
          return `<circle cx="${x.toFixed(1)}" cy="${y}" r="${DOT_R}" fill="${col}" fill-opacity="0.7" stroke="${col}" stroke-width="0.5">
        <title>${escHtml(tip)}</title></circle>`;
        })
        .join("");

      // Detection markers (diamond)
      const detMarks = userDets
        .map((d) => {
          // Use first event time for detection
          const evs = byUser[d.user] || [];
          const firstT = evs.length
            ? Math.min(
                ...evs
                  .map((e) => new Date(e.createdAt).getTime())
                  .filter((t) => !isNaN(t)),
              )
            : tMin;
          const x = xOf(firstT);
          const size = 6;
          const pts = `${x},${y - size} ${x + size},${y} ${x},${y + size} ${x - size},${y}`;
          return `<polygon points="${pts}" fill="#f59e0b" fill-opacity="0.9" stroke="#d97706" stroke-width="0.5">
        <title>${escHtml(d.type.replace(/_/g, " "))}: ${escHtml(d.message?.slice(0, 80) || "")}</title></polygon>`;
        })
        .join("");

      return badge + lane + label + dots + detMarks;
    })
    .join("");

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
  const el = document.getElementById("sankey-container");
  if (!el) return;
  const data = state.analysisData;
  if (!data) {
    el.innerHTML =
      '<p style="padding:20px;color:var(--text2)">No analysis data.</p>';
    return;
  }

  const events = data.events || [];
  const homeCountry = (data.homeCountry || "ID").toUpperCase();
  // Only foreign events
  const foreign = events.filter(
    (e) => e.country && e.country.toUpperCase() !== homeCountry,
  );
  if (!foreign.length) {
    el.innerHTML =
      '<p style="padding:20px;color:var(--text2)">No foreign events to visualize.</p>';
    return;
  }

  // Build flow: Country → App → Outcome
  // Count flows
  const flowCA = {}; // country → app
  const flowAO = {}; // app → outcome
  foreign.forEach((e) => {
    const c = e.country || "Unknown";
    const a = (e.appName || "Unknown").slice(0, 30);
    const o = e.success ? "Success" : "Failure";
    const keyCA = `${c}||${a}`;
    const keyAO = `${a}||${o}`;
    flowCA[keyCA] = (flowCA[keyCA] || 0) + 1;
    flowAO[keyAO] = (flowAO[keyAO] || 0) + 1;
  });

  // Top 8 countries, top 8 apps
  const countryCounts = {};
  const appCounts = {};
  foreign.forEach((e) => {
    const c = e.country || "Unknown";
    const a = (e.appName || "Unknown").slice(0, 30);
    countryCounts[c] = (countryCounts[c] || 0) + 1;
    appCounts[a] = (appCounts[a] || 0) + 1;
  });
  const topCountries = Object.entries(countryCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([k]) => k);
  const topApps = Object.entries(appCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([k]) => k);
  const outcomes = ["Success", "Failure"];

  const W = Math.max(800, el.clientWidth || 900) - 4;
  const H = Math.max(topCountries.length, topApps.length) * 40 + 80;
  const COL1 = 20,
    COL2 = W * 0.38,
    COL3 = W * 0.68,
    COL4 = W - 80;
  const NODE_W = 120,
    NODE_H = 28;

  const colPalette = [
    "#6366f1",
    "#8b5cf6",
    "#ec4899",
    "#f97316",
    "#eab308",
    "#22c55e",
    "#06b6d4",
    "#f43f5e",
  ];

  // Layout nodes
  const cNodes = topCountries.map((c, i) => ({
    label: c,
    x: COL1,
    y: 50 + i * 38,
    count: countryCounts[c],
  }));
  const aNodes = topApps.map((a, i) => ({
    label: a,
    x: COL2,
    y: 50 + i * 38,
    count: appCounts[a],
  }));
  const oNodes = outcomes.map((o, i) => ({
    label: o,
    x: COL3,
    y: 50 + i * 80,
    count: foreign.filter((e) => (e.success ? "Success" : "Failure") === o)
      .length,
  }));

  const totalForeign = foreign.length;
  const maxC = Math.max(...cNodes.map((n) => n.count), 1);
  const maxA = Math.max(...aNodes.map((n) => n.count), 1);
  const maxO = Math.max(...oNodes.map((n) => n.count), 1);

  const barMaxW = 100;

  // Draw curves from countries to apps
  let curves = "";
  cNodes.forEach((cn, ci) => {
    aNodes.forEach((an, ai) => {
      const key = `${cn.label}||${an.label}`;
      const cnt = flowCA[key] || 0;
      if (!cnt) return;
      const w = Math.max(1, (cnt / totalForeign) * 12);
      const x1 = cn.x + NODE_W,
        y1 = cn.y + NODE_H / 2;
      const x2 = an.x,
        y2 = an.y + NODE_H / 2;
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
      const x1 = an.x + NODE_W,
        y1 = an.y + NODE_H / 2;
      const x2 = on.x,
        y2 = on.y + NODE_H / 2;
      const cx = (x1 + x2) / 2;
      curves += `<path d="M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}"
        fill="none" stroke="${on.label === "Success" ? "#22c55e" : "#ef4444"}" stroke-width="${w.toFixed(1)}" stroke-opacity="0.35">
        <title>${escHtml(an.label)} → ${on.label}: ${cnt}</title></path>`;
    });
  });

  // Draw nodes
  const drawNodes = (nodes, maxCount, colOffset) =>
    nodes
      .map((n, i) => {
        const col = colPalette[i % colPalette.length];
        const barW = (n.count / maxCount) * barMaxW;
        const isOutcome = n.label === "Success" || n.label === "Failure";
        const nodeCol =
          n.label === "Success"
            ? "#22c55e"
            : n.label === "Failure"
              ? "#ef4444"
              : col;
        return `
      <rect x="${n.x}" y="${n.y}" width="${NODE_W}" height="${NODE_H}" rx="4"
        fill="${nodeCol}" fill-opacity="0.15" stroke="${nodeCol}" stroke-width="1"/>
      <text x="${n.x + 6}" y="${n.y + 18}" font-size="10" fill="var(--text1)" font-weight="500">${escHtml(n.label.slice(0, 16))}</text>
      <text x="${n.x + NODE_W - 4}" y="${n.y + 18}" font-size="9" fill="${nodeCol}" text-anchor="end">${n.count}</text>`;
      })
      .join("");

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
  const el = document.getElementById("countryapp-container");
  if (!el) return;
  const data = state.analysisData;
  if (!data) {
    el.innerHTML =
      '<p style="padding:20px;color:var(--text2)">No analysis data.</p>';
    return;
  }

  const events = data.events || [];
  const homeCountry = (data.homeCountry || "ID").toUpperCase();
  const foreign = events.filter(
    (e) => e.country && e.country.toUpperCase() !== homeCountry,
  );
  if (!foreign.length) {
    el.innerHTML =
      '<p style="padding:20px;color:var(--text2)">No foreign events to display.</p>';
    return;
  }

  // Count by country × app
  const matrix = {}; // matrix[country][app] = { total, success, fail }
  const countryCounts = {},
    appCounts = {};
  foreign.forEach((e) => {
    const c = e.country || "Unknown";
    const a = (e.appName || "Unknown").slice(0, 35);
    countryCounts[c] = (countryCounts[c] || 0) + 1;
    appCounts[a] = (appCounts[a] || 0) + 1;
    if (!matrix[c]) matrix[c] = {};
    if (!matrix[c][a]) matrix[c][a] = { total: 0, success: 0, fail: 0 };
    matrix[c][a].total++;
    if (e.success) matrix[c][a].success++;
    else matrix[c][a].fail++;
  });

  const topCountries = Object.entries(countryCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 15)
    .map(([k]) => k);
  const topApps = Object.entries(appCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([k]) => k);
  const maxCell = Math.max(
    1,
    ...topCountries.flatMap((c) =>
      topApps.map((a) => matrix[c]?.[a]?.total || 0),
    ),
  );

  const cellStyle = (c, a) => {
    const cell = matrix[c]?.[a];
    if (!cell) return "background:transparent";
    const intensity = cell.total / maxCell;
    const successRate = cell.success / cell.total;
    // Color: red for mostly failed, green for mostly success, blended
    const r = Math.round(239 * (1 - successRate) * intensity + 30);
    const g = Math.round(197 * successRate * intensity + 30);
    const b = 30;
    const alpha = 0.15 + intensity * 0.7;
    return `background:rgba(${r},${g},${b},${alpha})`;
  };

  const header = `<tr><th class="cam-th cam-corner">Country \\ App</th>${topApps
    .map(
      (a) =>
        `<th class="cam-th" title="${escHtml(a)}">${escHtml(a.slice(0, 14))}${a.length > 14 ? "…" : ""}</th>`,
    )
    .join("")}</tr>`;

  const bodyRows = topCountries
    .map((c) => {
      const cells = topApps
        .map((a) => {
          const cell = matrix[c]?.[a];
          const style = cellStyle(c, a);
          const tip = cell
            ? `${cell.total} events (✓${cell.success} ✗${cell.fail})`
            : "";
          return `<td class="cam-td" style="${style}" title="${escHtml(tip)}">${cell ? cell.total : ""}</td>`;
        })
        .join("");
      return `<tr><td class="cam-td cam-row-label">${escHtml(c)}<span class="cam-row-total">${countryCounts[c]}</span></td>${cells}</tr>`;
    })
    .join("");

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

