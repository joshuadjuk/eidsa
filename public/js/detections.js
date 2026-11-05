/* ── Detection cards ──────────────────────────────────────────────────────── */
/* ── MITRE ATT&CK mapping ─────────────────────────────────────────────────── */
const MITRE_MAP = {
  PASSWORD_SPRAY: {
    id: "T1110.003",
    name: "Password Spraying",
    tactic: "Credential Access",
  },
  BRUTE_FORCE: {
    id: "T1110.001",
    name: "Password Guessing",
    tactic: "Credential Access",
  },
  IMPOSSIBLE_TRAVEL: {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Defense Evasion",
  },
  FOREIGN_LOGIN: {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Defense Evasion",
  },
  TOKEN_REPLAY: {
    id: "T1550.001",
    name: "Application Access Token",
    tactic: "Lateral Movement",
  },
  LEGACY_AUTH: {
    id: "T1078.004",
    name: "Cloud Accounts",
    tactic: "Persistence",
  },
  ENUMERATION_ATTACK: {
    id: "T1087.002",
    name: "Domain Account",
    tactic: "Discovery",
  },
  MFA_EXHAUSTION: {
    id: "T1621",
    name: "MFA Request Generation",
    tactic: "Credential Access",
  },
  CA_GAP: {
    id: "T1556.006",
    name: "Multi-Factor Authentication",
    tactic: "Defense Evasion",
  },
  ADMIN_TOOL_ABUSE: { id: "T1059.009", name: "Cloud API", tactic: "Execution" },
  SERVICE_PRINCIPAL_ANOMALY: {
    id: "T1528",
    name: "Steal Application Token",
    tactic: "Credential Access",
  },
  CONCURRENT_SESSIONS: {
    id: "T1550",
    name: "Use Alternate Auth Material",
    tactic: "Lateral Movement",
  },
  FIRST_SEEN_COUNTRY: {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Initial Access",
  },
  TIME_OF_DAY_ANOMALY: {
    id: "T1078",
    name: "Valid Accounts",
    tactic: "Initial Access",
  },
  RARE_APP_ACCESS: {
    id: "T1550.001",
    name: "Application Access Token",
    tactic: "Lateral Movement",
  },
  CREDENTIAL_STUFFING: {
    id: "T1110.004",
    name: "Credential Stuffing",
    tactic: "Credential Access",
  },
  DEVICE_FINGERPRINT_ANOMALY: {
    id: "T1078.004",
    name: "Cloud Accounts",
    tactic: "Initial Access",
  },
  OAUTH_CONSENT_PHISHING: {
    id: "T1528",
    name: "Steal Application Access Token",
    tactic: "Credential Access",
  },
  DISTRIBUTED_BRUTE_FORCE: {
    id: "T1110.001",
    name: "Password Guessing",
    tactic: "Credential Access",
  },
  MFA_METHOD_DOWNGRADE: {
    id: "T1556.006",
    name: "Multi-Factor Authentication",
    tactic: "Defense Evasion",
  },
  ENTRA_RISKY_SIGNIN: {
    id: "T1078.004",
    name: "Cloud Accounts",
    tactic: "Initial Access",
  },
  MFA_REGISTRATION_AFTER_COMPROMISE: {
    id: "T1098.005",
    name: "Device Registration",
    tactic: "Persistence",
  },
  OAUTH_CONSENT_GRANT: {
    id: "T1528",
    name: "Steal Application Access Token",
    tactic: "Credential Access",
  },
  PRIVILEGED_ROLE_ASSIGNMENT: {
    id: "T1098.003",
    name: "Additional Cloud Roles",
    tactic: "Privilege Escalation",
  },
  APP_CREDENTIAL_ADDED: {
    id: "T1098.001",
    name: "Additional Cloud Credentials",
    tactic: "Persistence",
  },
};

function getMitreTag(type) {
  const m = MITRE_MAP[type];
  if (!m) return "";
  return `<a class="mitre-badge" href="https://attack.mitre.org/techniques/${m.id.replace(".", "/")}/" target="_blank" rel="noopener"
    onclick="event.stopPropagation()" title="${escHtml(m.name)} — ${escHtml(m.tactic)}">
    ATT&amp;CK ${escHtml(m.id)}
  </a>`;
}

function getTriageKey(det) {
  const who =
    det.user || det.ip || (det.affectedUsers && det.affectedUsers[0]) || "";
  return `${det.type}:${who}`;
}

async function setTriage(key, status) {
  const wsId = state.activeWorkspace?.id;
  if (!wsId) return;
  try {
    const result = await api("POST", `/api/workspaces/${wsId}/triage`, {
      key,
      status,
    });
    state.triages = result.triages || {};
    rerenderDetections();
  } catch (e) {
    toast("Failed to save triage", "err");
  }
}

function rerenderDetections() {
  const sec = document.getElementById("detections-section");
  if (!sec || !state.analysisData) return;
  sec.outerHTML = buildDetectionsSection(state.analysisData.detections || []);
}

function buildDetectionsSection(detections) {
  const nonFP = detections.filter(
    (d) => state.triages[getTriageKey(d)] !== "FP",
  );
  const fp = detections.filter((d) => state.triages[getTriageKey(d)] === "FP");

  // Filter bar
  const q = (state.detectionsFilter || "").toLowerCase();
  const sf = state.detectionsSevFilter || "all";
  let visible = nonFP;
  if (sf !== "all") visible = visible.filter((d) => d.severity === sf);
  if (q)
    visible = visible.filter((d) =>
      (
        d.type +
        " " +
        (d.user || "") +
        " " +
        (d.ip || "") +
        " " +
        (d.message || "")
      )
        .toLowerCase()
        .includes(q),
    );

  // Pagination
  const totalPages = Math.max(
    1,
    Math.ceil(visible.length / state.detectionsPageSize),
  );
  const page = Math.min(state.detectionsPage, totalPages);
  const start = (page - 1) * state.detectionsPageSize;
  const pageItems = visible.slice(start, start + state.detectionsPageSize);

  const fpHtml =
    fp.length > 0
      ? `
    <div class="fp-suppressed" onclick="this.classList.toggle('open');this.querySelector('.fp-toggle-arrow').textContent=this.classList.contains('open')?'▾':'▸'">
      <span><span class="fp-toggle-arrow">▸</span> ${fp.length} False Positive${fp.length > 1 ? "s" : ""} suppressed — click to show</span>
      <div class="fp-suppressed-list">${fp.map(renderDetectionCard).join("")}</div>
    </div>`
      : "";

  const bulkBar =
    state.bulkSelected.size > 0
      ? `
    <div class="bulk-action-bar">
      <span class="bulk-count">${state.bulkSelected.size} selected</span>
      <button class="bulk-btn bulk-tp"  onclick="bulkTriage('TP')"><i class="bi bi-check-lg"></i> Mark TP</button>
      <button class="bulk-btn bulk-fp"  onclick="bulkTriage('FP')"><i class="bi bi-x-lg"></i> Mark FP</button>
      <button class="bulk-btn bulk-inv" onclick="bulkTriage('INV')">? Investigating</button>
      <button class="bulk-btn bulk-clr" onclick="clearBulkSelection()"><i class="bi bi-x"></i> Clear</button>
    </div>`
      : "";

  const pagBar =
    totalPages > 1
      ? `
    <div class="det-pagination">
      <button class="det-pg-btn" onclick="changeDetPage(-1)" ${page <= 1 ? "disabled" : ""}>◀</button>
      <span class="det-pg-info">Page ${page} / ${totalPages} <span style="color:var(--text3)"> · ${visible.length} results</span></span>
      <button class="det-pg-btn" onclick="changeDetPage(1)" ${page >= totalPages ? "disabled" : ""}>▶</button>
    </div>`
      : "";

  const filterBar = `
    <div class="det-filter-bar">
      <input class="det-filter-input" type="text" placeholder="Filter by type, user, IP, message…"
        value="${escHtml(state.detectionsFilter || "")}"
        oninput="filterDetections(this.value)" />
      <select class="det-sev-select" onchange="filterDetectionsSev(this.value)">
        <option value="all"   ${sf === "all" ? "selected" : ""}>All severities</option>
        <option value="high"  ${sf === "high" ? "selected" : ""}>High</option>
        <option value="medium"${sf === "medium" ? "selected" : ""}>Medium</option>
        <option value="low"   ${sf === "low" ? "selected" : ""}>Low</option>
      </select>
    </div>`;

  return `<div id="detections-section">
    <div class="section-heading" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <i class="bi bi-search"></i> Detections
      <span class="count-badge">${detections.length}</span>
      ${nonFP.length !== detections.length ? `<span style="font-size:11px;color:var(--text3)">(${nonFP.length} active)</span>` : ""}
      ${detections.length > 0 ? `<span class="ioc-export-group"><button class="btn-ioc-export" onclick="exportIOC('csv')" title="Export IPs, users & countries as CSV for SIEM / firewall"><i class="bi bi-download"></i> IOC CSV</button><button class="btn-ioc-export" onclick="exportIOC('sentinel')" title="CSV with SearchKey column — upload as a Microsoft Sentinel watchlist"><i class="bi bi-shield-check"></i> Sentinel</button><button class="btn-ioc-export" onclick="exportIOC('stix')" title="STIX 2.1 bundle for threat-intel platforms (MISP, OpenCTI, Defender TI)"><i class="bi bi-diagram-3"></i> STIX</button></span>` : ""}
    </div>
    ${detections.length >= 2 ? renderCampaigns(detections) : ""}
    ${filterBar}
    ${bulkBar}
    ${pagBar}
    ${
      visible.length === 0 && fp.length === 0 && !q && sf === "all"
        ? '<div class="empty">No detections triggered — all clear.</div>'
        : visible.length === 0
          ? `<div class="empty">No detections match the current filter.</div>`
          : pageItems.map(renderDetectionCard).join("")
    }
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
  document
    .getElementById("detections-section")
    ?.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ── Attack Campaign Grouping ────────────────────────────────────────────── */
function groupIntoCampaigns(detections) {
  if (!detections.length) return [];
  const n = detections.length;
  const par = Array.from({ length: n }, (_, i) => i);
  const find = (i) => (par[i] === i ? i : (par[i] = find(par[i])));
  const union = (i, j) => {
    par[find(i)] = find(j);
  };

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
    const users = new Set(
      [detections[i].user, ...(detections[i].affectedUsers || [])].filter(
        Boolean,
      ),
    );
    for (const u of users) {
      if (byUser[u] !== undefined) union(i, byUser[u]);
      else byUser[u] = i;
    }
  }
  // Gather groups with ≥2 detections
  const groups = {};
  for (let i = 0; i < n; i++) {
    const r = find(i);
    (groups[r] = groups[r] || []).push(detections[i]);
  }
  const sevW = { critical: 4, high: 3, medium: 2, low: 1 };
  const maxSev = (g) =>
    Math.max(...g.map((d) => sevW[d.severity?.toLowerCase()] || 0));
  return Object.values(groups)
    .filter((g) => g.length >= 2)
    .sort((a, b) => maxSev(b) - maxSev(a) || b.length - a.length);
}

function renderCampaigns(detections) {
  const campaigns = groupIntoCampaigns(
    detections.filter((d) => state.triages[getTriageKey(d)] !== "FP"),
  );
  if (!campaigns.length) return "";

  const cards = campaigns
    .map((group, idx) => {
      const types = [...new Set(group.map((d) => d.type.replace(/_/g, " ")))];
      const ips = [...new Set(group.map((d) => d.ip).filter(Boolean))];
      const users = new Set(
        group.flatMap((d) =>
          [d.user, ...(d.affectedUsers || [])].filter(Boolean),
        ),
      );
      const countries = [
        ...new Set(group.map((d) => d.country).filter(Boolean)),
      ];
      const topSev = group.some((d) => d.severity === "critical")
        ? "critical"
        : group.some((d) => d.severity === "high")
          ? "high"
          : "medium";
      const sevColor = {
        critical: "#ef4444",
        high: "#f97316",
        medium: "#f59e0b",
      }[topSev];
      const sevBg = {
        critical: "rgba(209,52,56,0.08)",
        high: "rgba(249,115,22,0.07)",
        medium: "rgba(245,158,11,0.06)",
      }[topSev];
      const sevBorder = {
        critical: "rgba(209,52,56,0.25)",
        high: "rgba(249,115,22,0.22)",
        medium: "rgba(245,158,11,0.2)",
      }[topSev];

      return `
      <div class="campaign-card" style="background:${sevBg};border:1px solid ${sevBorder}">
        <div class="campaign-header">
          <span class="campaign-num" style="color:${sevColor}"><i class="bi bi-lightning-charge-fill"></i> Campaign #${idx + 1}</span>
          <div class="campaign-meta">
            <span class="campaign-stat"><i class="bi bi-search"></i> ${group.length} detections</span>
            ${users.size ? `<span class="campaign-stat"><i class="bi bi-person-fill"></i> ${users.size} user${users.size > 1 ? "s" : ""}</span>` : ""}
            ${ips.length ? `<span class="campaign-stat"><i class="bi bi-broadcast"></i> ${ips.length} IP${ips.length > 1 ? "s" : ""}: ${ips.slice(0, 2).map(escHtml).join(", ")}${ips.length > 2 ? "…" : ""}</span>` : ""}
            ${countries.length ? `<span class="campaign-stat"><i class="bi bi-geo-alt-fill"></i> ${countries.slice(0, 3).join(", ")}${countries.length > 3 ? "…" : ""}</span>` : ""}
          </div>
        </div>
        <div class="campaign-types">
          ${types
            .slice(0, 5)
            .map((t) => `<span class="campaign-type-tag">${t}</span>`)
            .join("")}
          ${types.length > 5 ? `<span class="campaign-type-tag">+${types.length - 5} more</span>` : ""}
        </div>
      </div>`;
    })
    .join("");

  return `
    <div style="margin-bottom:14px">
      <div class="section-heading" style="margin-bottom:8px"><i class="bi bi-lightning-charge-fill"></i> Attack Campaigns <span class="count-badge">${campaigns.length}</span> <span style="font-size:11px;color:var(--text3);font-weight:400;margin-left:4px">— correlated detections dari IP / user yang sama</span></div>
      ${cards}
    </div>
    <div style="height:1px;background:var(--border);margin-bottom:16px"></div>`;
}

/* ── IOC Export ───────────────────────────────────────────────────────────── */
// format: "csv" (generic), "sentinel" (watchlist CSV with SearchKey), "stix" (STIX 2.1 bundle)
function exportIOC(format = "csv") {
  const data = state.analysisData;
  if (!data) return;

  const detections = (data.detections || []).filter(
    (d) => state.triages[getTriageKey(d)] !== "FP",
  );
  const sevNum = { critical: 4, high: 3, medium: 2, low: 1 };
  const iocs = { IP: {}, USER: {}, COUNTRY: {} };

  const add = (type, val, det) => {
    if (!val) return;
    val = String(val).trim();
    if (!val || val === "null" || val === "undefined") return;
    if (!iocs[type][val])
      iocs[type][val] = { types: new Set(), sev: 0, sevLabel: "LOW" };
    iocs[type][val].types.add(det.type);
    const n = sevNum[det.severity?.toLowerCase()] || 0;
    if (n > iocs[type][val].sev) {
      iocs[type][val].sev = n;
      iocs[type][val].sevLabel = (det.severity || "LOW").toUpperCase();
    }
  };

  for (const d of detections) {
    if (d.ip) add("IP", d.ip, d);
    (d.uniqueIPs || d.ips || []).forEach((ip) => add("IP", ip, d));
    if (d.user) add("USER", d.user, d);
    (d.affectedUsers || []).forEach((u) => add("USER", u, d));
    if (d.country && !d.user) add("COUNTRY", d.country, d);
  }

  const rows = [
    [
      "IOC_TYPE",
      "VALUE",
      "SEVERITY",
      "DETECTION_TYPES",
      "DETECTION_COUNT",
      "WORKSPACE",
      "EXPORTED_AT",
    ],
  ];
  const ws = state.activeWorkspace?.name || "";
  const ts = new Date().toISOString();

  for (const [type, map] of Object.entries(iocs)) {
    Object.entries(map)
      .sort((a, b) => b[1].sev - a[1].sev || a[0].localeCompare(b[0]))
      .forEach(([val, info]) => {
        rows.push([
          type,
          val,
          info.sevLabel,
          [...info.types].join("|"),
          info.types.size,
          ws,
          ts,
        ]);
      });
  }

  if (rows.length <= 1) {
    toast("No IOCs to export", "warn");
    return;
  }
  const base = `EIDSA_IOC_${(ws || "export").replace(/\W+/g, "_")}_${ts.slice(0, 10)}`;

  if (format === "stix") {
    const bundle = buildStixBundle(iocs, ws, ts);
    downloadBlob(JSON.stringify(bundle, null, 2), "application/json", `${base}.stix.json`);
    toast(`<i class="bi bi-check-circle-fill"></i> Exported ${bundle.objects.length - 1} STIX indicators → ${base}.stix.json`);
    return;
  }
  if (format === "sentinel") {
    // Sentinel watchlist: first column is the SearchKey chosen at upload
    rows[0] = ["SearchKey", ...rows[0]];
    for (let i = 1; i < rows.length; i++) rows[i] = [rows[i][1], ...rows[i]];
  }

  const csv = rows
    .map((r) =>
      r
        .map((c) => {
          const s = String(c);
          return /[,"\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
        })
        .join(","),
    )
    .join("\r\n");

  const fname = `${base}${format === "sentinel" ? ".sentinel-watchlist" : ""}.csv`;
  downloadBlob(csv, "text/csv;charset=utf-8;", fname);
  toast(
    `<i class="bi bi-check-circle-fill"></i> Exported ${rows.length - 1} IOC indicators → ${fname}`,
    "ok",
  );
}

function matchesKillChainFilter(det) {
  const f = state.killChainFilter;
  if (!f) return null;
  const mitre = MITRE_MAP[det.type];
  const tacticMatch = mitre && mitre.tactic === f.tactic;
  const users = new Set();
  if (det.user) users.add(det.user);
  if (det.affectedUsers) det.affectedUsers.forEach((u) => users.add(u));
  if (det.ip && !det.user)
    users.add(`<i class="bi bi-broadcast"></i> ${det.ip}`);
  return tacticMatch && users.has(f.user);
}

function buildDetectionExplainer(det) {
  const TRIGGER = {
    PASSWORD_SPRAY: (d) =>
      `${d.userCount || d.affectedUsers?.length || "?"} accounts received failed logins from the same source within a short window — classic password spray: one password tried against many accounts to stay under lockout thresholds.`,
    BRUTE_FORCE: (d) =>
      `${d.attemptCount || "?"} failed login attempts for ${d.user ? d.user.split("@")[0] : "this user"} — exceeds the brute force threshold. Attacker is guessing passwords for a single account.`,
    IMPOSSIBLE_TRAVEL: (d) =>
      `Login from ${d.from?.country || "?"} at ${d.from?.time ? formatDate(d.from.time) : "?"}, then from ${d.to?.country || "?"} at ${d.to?.time ? formatDate(d.to.time) : "?"}. The physical distance cannot be covered in the elapsed time — at least one login is suspicious.`,
    MFA_EXHAUSTION: (d) =>
      `${d.promptCount || d.attemptCount || "?"} consecutive MFA push notifications sent to ${d.user ? d.user.split("@")[0] : "this user"}. Attacker already has the password and is flooding the user hoping for an accidental approval.`,
    ADMIN_TOOL_ABUSE: (d) =>
      `Admin/privileged application (${d.appName || d.app || "?"}) accessed from a foreign IP or country. Legitimate admin sessions rarely originate outside the home country.`,
    TOKEN_REPLAY: (d) =>
      `The same authentication token was used from multiple distinct IP addresses. A valid token was likely stolen and replayed from a different machine.`,
    CONCURRENT_SESSIONS: (d) =>
      `Active sessions detected from ${(d.uniqueIPs || []).length || d.ipCount || "multiple"} different IPs at the same time. A single user cannot authenticate from multiple locations simultaneously.`,
    SERVICE_PRINCIPAL_ANOMALY: (d) =>
      `Service principal signed in from an IP or location not previously seen for this application. May indicate compromised service account credentials or a new unauthorized app registration.`,
    LEGACY_AUTH: (d) =>
      `Authentication via a legacy protocol that bypasses modern Conditional Access policies. Legacy auth cannot enforce MFA, making it a common attacker entry point.`,
    CREDENTIAL_STUFFING: (d) =>
      `Multiple users targeted from distributed IPs using known breach credentials. Low per-IP attempt count combined with high breadth matches automated credential stuffing toolkits.`,
    DISTRIBUTED_BRUTE_FORCE: (d) =>
      `Brute force attack spread across ${(d.uniqueIPs || []).length || "?"} IPs to evade per-IP lockout policies. Rotating IP addresses while attacking the same target account.`,
    ENTRA_RISKY_SIGNIN: (d) =>
      `Microsoft Identity Protection scored ${d.eventCount || "these"} successful sign-in(s) as risky (${(d.riskEventTypes || []).join(", ") || (d.riskLevels || []).join("/")}). Microsoft's own signal — treat as likely compromise until the user confirms.`,
    MFA_REGISTRATION_AFTER_COMPROMISE: (d) =>
      `A new MFA / security-info method was registered for ${d.user ? d.user.split("@")[0] : "this user"} shortly after suspicious sign-in activity. Attackers register their own authenticator to keep access after a password reset.`,
    OAUTH_CONSENT_GRANT: (d) =>
      `Consent was granted to "${d.app || "an application"}"${(d.scopes || []).length ? ` with high-risk scopes (${d.scopes.join(", ")})` : ""}. The app can now read data on the user's behalf without their password.`,
    PRIVILEGED_ROLE_ASSIGNMENT: (d) =>
      `"${d.role || "A privileged role"}" was assigned to ${d.user || "an account"} by ${d.initiatedBy || "unknown"}. Verify it was a planned change — privilege escalation is a common post-compromise step.`,
    APP_CREDENTIAL_ADDED: (d) =>
      `A new secret or certificate was added to "${d.app || "an application"}". An attacker with an app credential keeps API access even after user passwords are reset.`,
    MFA_METHOD_DOWNGRADE: (d) =>
      d.downgrade === "weak-method"
        ? `Signed in with a weak second factor (${d.mfaMethod || "SMS/voice"}) although ${d.baselineMFAPct ?? "most"}% of earlier sign-ins used Authenticator/FIDO. Possible SIM swap or social-engineered fallback.`
        : `Signed in with single-factor authentication although ${d.baselineMFAPct ?? "most"}% of earlier sign-ins used MFA. Possible Conditional Access gap or token theft.`,
    OAUTH_CONSENT_PHISHING: (d) =>
      `OAuth consent request from an unfamiliar application attempting to access tenant data. User may have been tricked into granting delegated permissions to a malicious third-party app.`,
    ENUMERATION_ATTACK: (d) =>
      `${d.userCount || "?"} username probes detected. Attacker observes different error codes for valid vs. invalid accounts to build a list of existing users before launching a targeted attack.`,
    FIRST_SEEN_COUNTRY: (d) =>
      `Login from ${d.country || "?"} — this country has not appeared for this account in the entire analyzed log history.`,
    TIME_OF_DAY_ANOMALY: (d) =>
      `Login at an unusual hour outside this account's normal activity pattern — may indicate a different timezone (foreign attacker) or automated tooling.`,
    RARE_APP_ACCESS: (d) =>
      `${d.user ? d.user.split("@")[0] : "This user"} accessed ${d.appName || "an application"} that they have never or rarely used. A compromised account often explores available resources.`,
    CA_GAP: (d) =>
      `Successful authentication completed without any Conditional Access policy being enforced. This login bypassed MFA and device compliance checks entirely.`,
  };

  const explain = TRIGGER[det.type];
  const text = explain
    ? explain(det)
    : det.message || "No additional detail available.";

  const evid = [];
  if (det.windowStart && det.windowEnd)
    evid.push({
      i: '<i class="bi bi-clock"></i>',
      l: "Window",
      v: `${formatDate(det.windowStart)} → ${formatDate(det.windowEnd)}`,
    });
  else if (det.time)
    evid.push({
      i: '<i class="bi bi-clock"></i>',
      l: "Time",
      v: formatDate(det.time),
    });
  if (det.ip)
    evid.push({ i: '<i class="bi bi-broadcast"></i>', l: "IP", v: det.ip });
  if (det.country)
    evid.push({
      i: '<i class="bi bi-geo-alt-fill"></i>',
      l: "Country",
      v: det.country,
    });
  const uc = det.userCount || det.affectedUsers?.length;
  if (uc)
    evid.push({ i: '<i class="bi bi-people-fill"></i>', l: "Users", v: uc });
  if (det.attemptCount)
    evid.push({
      i: '<i class="bi bi-arrow-repeat"></i>',
      l: "Attempts",
      v: det.attemptCount,
    });
  if (det.promptCount)
    evid.push({
      i: '<i class="bi bi-phone-fill"></i>',
      l: "MFA prompts",
      v: det.promptCount,
    });
  const ipc = (det.uniqueIPs || []).length || det.ipCount;
  if (ipc)
    evid.push({ i: '<i class="bi bi-globe2"></i>', l: "Unique IPs", v: ipc });

  const evidHtml = evid.length
    ? `<div class="explainer-evidence">${evid
        .map(
          (e) =>
            `<div class="ev-chip"><span class="ev-icon">${e.i}</span><span class="ev-label">${escHtml(String(e.l))}</span><span class="ev-val">${escHtml(String(e.v))}</span></div>`,
        )
        .join("")}</div>`
    : "";

  const m = MITRE_MAP[det.type];
  const mitreHtml = m
    ? `<div class="explainer-mitre">
    <span class="explainer-mitre-tag">MITRE ${escHtml(m.id)}</span>
    <span class="explainer-mitre-name">${escHtml(m.name)}</span>
    <span style="color:var(--text3);font-size:10px">· ${escHtml(m.tactic)}</span>
  </div>`
    : "";

  return `<div class="det-explainer">
    <div class="explainer-title"><i class="bi bi-lightning-charge-fill"></i> Why did this fire?</div>
    <div class="explainer-text">${escHtml(text)}</div>
    ${evidHtml}${mitreHtml}
  </div>
  <details class="det-raw-toggle"><summary>Raw JSON</summary><pre>${escHtml(JSON.stringify(det, null, 2))}</pre></details>`;
}

function renderDetectionCard(det) {
  const id = `det-${Math.random().toString(36).slice(2)}`;
  const hasUser = det.user;
  const mitre = getMitreTag(det.type);
  const key = getTriageKey(det);
  const status = state.triages[key] || "";
  const kcMatch = matchesKillChainFilter(det);
  const kcClass =
    kcMatch === true ? " kc-highlight" : kcMatch === false ? " kc-dim" : "";
  const isBulkSel = state.bulkSelected.has(key);
  const existingComment = state.detectionComments[key] || "";
  const commentId = `dc-${id}`;

  const triageBtns = `
    <div class="triage-btns" onclick="event.stopPropagation()">
      <button class="triage-btn tp${status === "TP" ? " active" : ""}" title="Mark True Positive"
        onclick="setTriage('${escHtml(key)}', '${status === "TP" ? "" : "TP"}')">TP</button>
      <button class="triage-btn fp${status === "FP" ? " active" : ""}" title="Mark False Positive — suppresses this detection"
        onclick="setTriage('${escHtml(key)}', '${status === "FP" ? "" : "FP"}')">FP</button>
      <button class="triage-btn inv${status === "INV" ? " active" : ""}" title="Mark as Investigating"
        onclick="setTriage('${escHtml(key)}', '${status === "INV" ? "" : "INV"}')">?</button>
    </div>`;

  const iocChips = (() => {
    const chips = [];
    if (det.ip)
      chips.push(
        `<span class="ioc-chip" onclick="event.stopPropagation();copyIOC('${escHtml(det.ip)}',this)" title="Copy IP"><i class="bi bi-broadcast"></i> ${escHtml(det.ip)}</span>`,
      );
    if (det.user)
      chips.push(
        `<span class="ioc-chip" onclick="event.stopPropagation();copyIOC('${escHtml(det.user)}',this)" title="Copy user"><i class="bi bi-person-fill"></i> ${escHtml(det.user)}</span>`,
      );
    const listed = highlightedUsers();
    if (listed && [det.user, ...(det.affectedUsers || [])].some((u) => u && listed.has(u.toLowerCase())))
      chips.push('<span class="listed-badge" title="Involves a user from the target list"><i class="bi bi-star-fill"></i> LISTED</span>');
    if (det.country && !det.user)
      chips.push(
        `<span class="ioc-chip" onclick="event.stopPropagation();copyIOC('${escHtml(det.country)}',this)" title="Copy country"><i class="bi bi-geo-alt-fill"></i> ${escHtml(det.country)}</span>`,
      );
    const extraIPs = (det.uniqueIPs || det.ips || [])
      .filter((ip) => ip !== det.ip)
      .slice(0, 3);
    extraIPs.forEach((ip) =>
      chips.push(
        `<span class="ioc-chip" onclick="event.stopPropagation();copyIOC('${escHtml(ip)}',this)" title="Copy IP"><i class="bi bi-broadcast"></i> ${escHtml(ip)}</span>`,
      ),
    );
    return chips.length
      ? `<div class="det-ioc-row">${chips.join("")}</div>`
      : "";
  })();

  return `
    <div class="detection-card sev-${det.severity}${status === "TP" ? " triage-tp" : status === "INV" ? " triage-inv" : ""}${kcClass}" onclick="toggleDetDetail('${id}')">
      <div class="det-header">
        <label class="det-checkbox" onclick="event.stopPropagation()" title="Select for bulk triage">
          <input type="checkbox" ${isBulkSel ? "checked" : ""} onchange="bulkToggle('${escHtml(key)}')">
        </label>
        <span class="det-badge badge-${det.severity}">${det.severity}</span>
        <span class="det-type">${det.type.replace(/_/g, " ")}</span>
        ${mitre}
        ${
          hasUser
            ? `<button class="btn-secondary" style="font-size:11px;padding:2px 8px"
          onclick="event.stopPropagation();openTimeline('${escHtml(det.user)}')">Timeline</button>`
            : ""
        }
        <button class="btn-secondary kql-btn" style="font-size:11px;padding:2px 8px"
          onclick="event.stopPropagation();showKQLPanel(${JSON.stringify(JSON.stringify(det))})">KQL</button>
        ${triageBtns}
      </div>
      <div class="det-message">${escHtml(det.message)}</div>
      ${buildDetSparkline(det)}
      ${iocChips}
      <div class="det-comment-row" onclick="event.stopPropagation()">
        ${
          existingComment
            ? `<div class="det-comment-preview" onclick="toggleDetComment('${commentId}')"><i class="bi bi-chat-fill"></i> <em>${escHtml(existingComment.slice(0, 90))}${existingComment.length > 90 ? "…" : ""}</em></div>`
            : `<button class="det-comment-add" onclick="toggleDetComment('${commentId}')">+ Add comment</button>`
        }
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
  document.getElementById(id).classList.toggle("open");
}


function downloadBlob(content, mime, fname) {
  const a = Object.assign(document.createElement("a"), {
    href: URL.createObjectURL(new Blob([content], { type: mime })),
    download: fname,
  });
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// crypto.randomUUID only exists in secure contexts (https / localhost)
function uuid4() {
  if (crypto.randomUUID) return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function buildStixBundle(iocs, wsName, ts) {
  const identity = {
    type: "identity", spec_version: "2.1", id: `identity--${uuid4()}`,
    created: ts, modified: ts, name: `EIDSA · ${wsName}`, identity_class: "system",
  };
  const confidence = { CRITICAL: 90, HIGH: 80, MEDIUM: 60, LOW: 40 };
  // STIX pattern string literal: escape backslash and single quote
  const sq = (s) => s.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  const indicators = [];
  const push = (pattern, name, info, labelType) =>
    indicators.push({
      type: "indicator", spec_version: "2.1", id: `indicator--${uuid4()}`,
      created: ts, modified: ts, valid_from: ts, created_by_ref: identity.id,
      name, pattern, pattern_type: "stix",
      indicator_types: [labelType],
      description: `EIDSA detections: ${[...info.types].join(", ")}`,
      labels: [...info.types].map((t) => t.toLowerCase()),
      confidence: confidence[info.sevLabel] ?? 50,
    });
  for (const [ip, info] of Object.entries(iocs.IP)) {
    push(`[${ip.includes(":") ? "ipv6-addr" : "ipv4-addr"}:value = '${sq(ip)}']`, `Attacker IP ${ip}`, info, "malicious-activity");
  }
  for (const [u, info] of Object.entries(iocs.USER)) {
    push(`[user-account:user_id = '${sq(u)}']`, `Targeted / compromised account ${u}`, info, "compromised");
  }
  return { type: "bundle", id: `bundle--${uuid4()}`, objects: [identity, ...indicators] };
}
