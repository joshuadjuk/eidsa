/* ── Theme ────────────────────────────────────────────────────────────────── */
function toggleTheme() {
  const isLight = document.body.classList.toggle("theme-light");
  localStorage.setItem("eidsa_theme", isLight ? "light" : "dark");
  const btn = document.getElementById("btn-theme-toggle");
  if (btn)
    btn.innerHTML = isLight
      ? '<i class="bi bi-moon-fill"></i>'
      : '<i class="bi bi-sun-fill"></i>';
  // Reinit map with correct tiles if open
  if (state.leafletMap) {
    state.leafletMap.eachLayer((l) => {
      if (l._url) state.leafletMap.removeLayer(l);
    });
    const tileUrl = isLight
      ? "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png"
      : "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png";
    L.tileLayer(tileUrl, {
      attribution: "© OpenStreetMap, © CARTO",
      subdomains: "abcd",
      maxZoom: 19,
    }).addTo(state.leafletMap);
  }
}

/* ── Keyboard shortcuts ───────────────────────────────────────────────────── */
function showShortcutPanel() {
  if (document.getElementById("shortcut-overlay")) return;
  const overlay = document.createElement("div");
  overlay.id = "shortcut-overlay";
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
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeShortcutPanel();
  });
  document.body.appendChild(overlay);
}

function closeShortcutPanel() {
  document.getElementById("shortcut-overlay")?.remove();
}

/* ── Utilities ────────────────────────────────────────────────────────────── */
function copyIOC(text, el) {
  navigator.clipboard
    .writeText(text)
    .then(() => {
      const orig = el.innerHTML;
      el.innerHTML = '<i class="bi bi-check-lg"></i> Copied';
      el.style.color = "#22c55e";
      el.style.borderColor = "#22c55e60";
      setTimeout(() => {
        el.innerHTML = orig;
        el.style.color = "";
        el.style.borderColor = "";
      }, 1600);
    })
    .catch(() => toast("Copy failed", "err"));
}

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function formatDate(str) {
  if (!str) return "";
  const d = new Date(str);
  if (isNaN(d)) return str;
  return d.toLocaleString("en-GB", { dateStyle: "short", timeStyle: "short" });
}

/* ── Cross-Run IP/User History ───────────────────────────────────────────── */
function histKey(wsId) {
  return `eidsa_history_${wsId}`;
}

function loadHistory(wsId) {
  try {
    return (
      JSON.parse(localStorage.getItem(histKey(wsId))) || { ips: {}, users: {} }
    );
  } catch {
    return { ips: {}, users: {} };
  }
}

function saveHistory(wsId, h) {
  localStorage.setItem(histKey(wsId), JSON.stringify(h));
}

function mergeRunHistory(wsId, data) {
  const h = loadHistory(wsId);
  const now = Date.now();
  const events = data.events || [];
  const detections = data.detections || [];
  const homeCountry = (data.homeCountry || "").toUpperCase();

  const attackIPs = new Set();
  for (const d of detections) {
    if (d.ip) attackIPs.add(d.ip);
    if (d.ips) d.ips.forEach((ip) => attackIPs.add(ip));
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
    if (d.affectedUsers) d.affectedUsers.forEach((u) => detUsers.add(u));
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
function prevRunKey(wsId) {
  return `eidsa_prevrun_${wsId}`;
}

function loadPrevRun(wsId) {
  try {
    return JSON.parse(localStorage.getItem(prevRunKey(wsId)));
  } catch {
    return null;
  }
}

function savePrevRun(wsId, data) {
  const snap = {
    ts: Date.now(),
    detectionCount: (data.detections || []).length,
    atRiskUsers: [
      ...new Set(
        (data.detections || [])
          .flatMap((d) => [d.user, ...(d.affectedUsers || [])])
          .filter(Boolean),
      ),
    ],
    detectionTypes: [...new Set((data.detections || []).map((d) => d.type))],
    attackingIPs: [
      ...new Set(
        (data.detections || [])
          .flatMap((d) => [d.ip, ...(d.ips || [])])
          .filter(Boolean),
      ),
    ],
    attackingCountries: [
      ...new Set(
        (data.events || [])
          .filter(
            (e) =>
              !e.success &&
              e.country &&
              e.country.toUpperCase() !==
                (data.homeCountry || "").toUpperCase(),
          )
          .map((e) => e.country),
      ),
    ],
    totalEvents: (data.events || []).length,
  };
  localStorage.setItem(prevRunKey(wsId), JSON.stringify(snap));
}

function renderDeltaPanel(data) {
  const prev = loadPrevRun(state.activeWorkspace?.id);
  if (!prev) return "";

  const curr = {
    atRiskUsers: [
      ...new Set(
        (data.detections || [])
          .flatMap((d) => [d.user, ...(d.affectedUsers || [])])
          .filter(Boolean),
      ),
    ],
    detectionTypes: [...new Set((data.detections || []).map((d) => d.type))],
    attackingIPs: [
      ...new Set(
        (data.detections || [])
          .flatMap((d) => [d.ip, ...(d.ips || [])])
          .filter(Boolean),
      ),
    ],
    attackingCountries: [
      ...new Set(
        (data.events || [])
          .filter(
            (e) =>
              !e.success &&
              e.country &&
              e.country.toUpperCase() !==
                (data.homeCountry || "").toUpperCase(),
          )
          .map((e) => e.country),
      ),
    ],
    detectionCount: (data.detections || []).length,
  };

  const newUsers = curr.atRiskUsers.filter(
    (u) => !prev.atRiskUsers.includes(u),
  );
  const resolvedUsers = prev.atRiskUsers.filter(
    (u) => !curr.atRiskUsers.includes(u),
  );
  const newTypes = curr.detectionTypes.filter(
    (t) => !prev.detectionTypes.includes(t),
  );
  const goneTypes = prev.detectionTypes.filter(
    (t) => !curr.detectionTypes.includes(t),
  );
  const newIPs = curr.attackingIPs.filter(
    (ip) => !prev.attackingIPs.includes(ip),
  );
  const newCountries = curr.attackingCountries.filter(
    (c) => !prev.attackingCountries.includes(c),
  );
  const goneCountries = prev.attackingCountries.filter(
    (c) => !curr.attackingCountries.includes(c),
  );
  const detDelta = curr.detectionCount - prev.detectionCount;

  const unchanged =
    !newUsers.length &&
    !resolvedUsers.length &&
    !newTypes.length &&
    !goneTypes.length &&
    !newIPs.length &&
    !newCountries.length &&
    !goneCountries.length &&
    detDelta === 0;
  if (unchanged) return "";

  const prevMin = Math.round((Date.now() - prev.ts) / 60000);
  const prevAge =
    prevMin < 60
      ? `${prevMin}m ago`
      : prevMin < 1440
        ? `${Math.round(prevMin / 60)}h ago`
        : `${Math.round(prevMin / 1440)}d ago`;

  const chips = [];
  if (detDelta !== 0)
    chips.push(
      `<span class="delta-chip ${detDelta > 0 ? "delta-up" : "delta-down"}">${detDelta > 0 ? "↑" : "↓"} ${Math.abs(detDelta)} detections</span>`,
    );
  newUsers.forEach((u) =>
    chips.push(
      `<span class="delta-chip delta-new" title="${escHtml(u)}"><i class="bi bi-plus-circle"></i> ${escHtml(u.split("@")[0])}</span>`,
    ),
  );
  resolvedUsers.forEach((u) =>
    chips.push(
      `<span class="delta-chip delta-ok" title="${escHtml(u)}"><i class="bi bi-check-lg"></i> ${escHtml(u.split("@")[0])}</span>`,
    ),
  );
  newTypes.forEach((t) =>
    chips.push(
      `<span class="delta-chip delta-new"><i class="bi bi-plus-circle"></i> ${t.replace(/_/g, " ")}</span>`,
    ),
  );
  goneTypes.forEach((t) =>
    chips.push(
      `<span class="delta-chip delta-ok"><i class="bi bi-check-lg"></i> ${t.replace(/_/g, " ")}</span>`,
    ),
  );
  newIPs
    .slice(0, 5)
    .forEach((ip) =>
      chips.push(
        `<span class="delta-chip delta-new ip-link" onclick="event.stopPropagation();openIPPivot('${escHtml(ip)}')" style="cursor:pointer"><i class="bi bi-plus-circle"></i> ${escHtml(ip)}</span>`,
      ),
    );
  if (newIPs.length > 5)
    chips.push(
      `<span class="delta-chip delta-neutral">+${newIPs.length - 5} new IPs</span>`,
    );
  newCountries.forEach((c) =>
    chips.push(
      `<span class="delta-chip delta-new"><i class="bi bi-globe"></i> ${escHtml(c)}</span>`,
    ),
  );
  goneCountries.forEach((c) =>
    chips.push(
      `<span class="delta-chip delta-ok"><i class="bi bi-check-lg"></i> ${escHtml(c)}</span>`,
    ),
  );

  return `<div class="delta-panel">
    <span class="delta-title"><i class="bi bi-arrow-clockwise"></i> vs Run <span style="opacity:0.6;font-weight:400">${prevAge}</span></span>
    <div class="delta-chips">${chips.join("")}</div>
  </div>`;
}

/* ── Per-User Behavior Profiles ──────────────────────────────────────────── */
function profilesKey(wsId) {
  return `eidsa_profiles_${wsId}`;
}

function loadProfiles(wsId) {
  try {
    return JSON.parse(localStorage.getItem(profilesKey(wsId))) || {};
  } catch {
    return {};
  }
}

function saveProfiles(wsId, profiles) {
  localStorage.setItem(profilesKey(wsId), JSON.stringify(profiles));
}

function updateUserProfiles(wsId, events) {
  const profiles = loadProfiles(wsId);
  const successEvents = events.filter((e) => e.success && e.userPrincipal);
  const seenUsers = new Set();

  for (const e of successEvents) {
    const u = e.userPrincipal;
    if (!profiles[u])
      profiles[u] = { hours: {}, countries: {}, apps: {}, runCount: 0 };
    const p = profiles[u];
    if (e.createdAt) {
      const h = new Date(e.createdAt).getHours();
      if (!isNaN(h)) p.hours[h] = (p.hours[h] || 0) + 1;
    }
    if (e.country) p.countries[e.country] = (p.countries[e.country] || 0) + 1;
    if (e.appDisplayName)
      p.apps[e.appDisplayName] = (p.apps[e.appDisplayName] || 0) + 1;
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

  const events = (state.analysisData.events || []).filter(
    (e) => e.userPrincipal === userPrincipal && e.success,
  );
  const anomalies = [];

  // Unusual hour — login outside their normal window (only flag late night/early morning deviations)
  const topHours = Object.entries(p.hours)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 8)
    .map(([h]) => parseInt(h));
  const offHourEvts = events.filter((e) => {
    if (!e.createdAt) return false;
    const h = new Date(e.createdAt).getHours();
    return !topHours.includes(h) && (h < 6 || h > 22);
  });
  if (offHourEvts.length) {
    const hrs = [
      ...new Set(offHourEvts.map((e) => new Date(e.createdAt).getHours())),
    ];
    anomalies.push({
      type: "UNUSUAL_HOUR",
      label: `Unusual hour (${hrs.join(", ")}:00)`,
      risk: "med",
    });
  }

  // New country not in profile history
  const knownCtry = new Set(Object.keys(p.countries));
  const newCtry = [
    ...new Set(
      events
        .filter((e) => e.country && !knownCtry.has(e.country))
        .map((e) => e.country),
    ),
  ];
  if (newCtry.length) {
    anomalies.push({
      type: "UNUSUAL_COUNTRY",
      label: `New country: ${newCtry.slice(0, 3).join(", ")}`,
      risk: "high",
    });
  }

  // Volume spike — 3× above average per run
  const totalSucc = Object.values(p.hours).reduce((a, b) => a + b, 0);
  const avgPerRun = totalSucc / Math.max(p.runCount, 1);
  if (events.length > avgPerRun * 3 && events.length > 10) {
    anomalies.push({
      type: "HIGH_VOLUME",
      label: `High volume (${events.length} vs avg ${Math.round(avgPerRun)})`,
      risk: "med",
    });
  }

  return anomalies;
}

function renderUserAnomalyChips(userPrincipal) {
  const anomalies = detectUserAnomalies(userPrincipal);
  if (!anomalies.length) return "";
  return `<div class="user-anomalies">${anomalies
    .map(
      (a) =>
        `<span class="anomaly-chip anomaly-${a.risk}" title="Behavior deviation from baseline"><i class="bi bi-exclamation-triangle"></i> ${escHtml(a.label)}</span>`,
    )
    .join("")}</div>`;
}

/* ── Global keyboard shortcuts ────────────────────────────────────────────── */
document.addEventListener("keydown", (e) => {
  // Don't fire when typing in inputs/textareas
  if (["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName)) return;
  if (e.key === "Escape") {
    closeTimeline();
    closeModal();
    closeShortcutPanel();
    closeIPPivot();
    closeKQLPanel();
    return;
  }
  if (e.key === "?") {
    showShortcutPanel();
    return;
  }
  if (e.key === "r" || e.key === "R") {
    if (state.activeWorkspace) runAnalysis();
    return;
  }
  if (e.key === "e" || e.key === "E") {
    if (state.analysisData) exportPDF();
    return;
  }
  if (e.key === "1" && state.analysisData) {
    switchTab("dashboard");
    return;
  }
  if (e.key === "2" && state.analysisData) {
    switchTab("events");
    return;
  }
  if (e.key === "3" && state.analysisData) {
    switchTab("map");
    return;
  }
  if (e.key === "4" && state.analysisData) {
    switchTab("charts");
    return;
  }
  if (e.key === "5" && state.analysisData) {
    switchTab("graph");
    return;
  }
  if (e.key === "/" && state.analysisData) {
    e.preventDefault();
    openIOCSearch();
    return;
  }
});

