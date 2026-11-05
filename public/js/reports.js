/* ── Executive Summary Export ─────────────────────────────────────────────── */
function exportExecutiveSummary() {
  const data = state.analysisData;
  const ws = state.activeWorkspace;
  if (!data || !ws) return;

  const events = data.events || [];
  const detections = data.detections || [];
  const summaries = data.userSummaries || [];
  const now = new Date().toLocaleString("en-GB", {
    dateStyle: "long",
    timeStyle: "short",
  });
  const homeCountry = data.homeCountry || "ID";

  const critCount = summaries.filter((s) => s.riskLevel === "CRITICAL").length;
  const highCount = summaries.filter((s) => s.riskLevel === "HIGH").length;
  const medCount = summaries.filter((s) => s.riskLevel === "MEDIUM").length;
  const riskLabel =
    critCount > 0
      ? "CRITICAL"
      : highCount > 0
        ? "HIGH"
        : medCount > 0
          ? "MEDIUM"
          : "CLEAR";
  const riskHex =
    critCount > 0
      ? "#dc2626"
      : highCount > 0
        ? "#d97706"
        : medCount > 0
          ? "#2563eb"
          : "#16a34a";

  const foreignSucc = events.filter(
    (e) => e.success && e.country && e.country.toUpperCase() !== homeCountry,
  ).length;
  const highDets = detections.filter((d) => d.severity === "high").length;

  // Top 3 threat types by count
  const threatCounts = {};
  for (const d of detections) {
    threatCounts[d.type] = (threatCounts[d.type] || 0) + 1;
  }
  const top3 = Object.entries(threatCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3);

  // 7-day daily event counts
  const byDay = {};
  for (const e of events) {
    const day = e.createdAt?.slice(0, 10);
    if (!day) continue;
    byDay[day] = (byDay[day] || 0) + 1;
  }
  const last7 = Object.entries(byDay)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(-7);
  const maxDay = Math.max(...last7.map(([, n]) => n), 1);

  const esc = (s) =>
    String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

  const threatCards = top3
    .map(([type, count]) => {
      const m = {
        PASSWORD_SPRAY: "Password Spray Attack",
        BRUTE_FORCE: "Brute Force Attack",
        CREDENTIAL_STUFFING: "Credential Stuffing",
        MFA_EXHAUSTION: "MFA Fatigue Attack",
        IMPOSSIBLE_TRAVEL: "Impossible Travel",
        FOREIGN_LOGIN: "Unauthorized Foreign Access",
        TOKEN_REPLAY: "Session/Token Hijack",
        LEGACY_AUTH: "Legacy Auth Bypass",
        ADMIN_TOOL_ABUSE: "Admin Tool Abuse",
        ENUMERATION_ATTACK: "Account Enumeration",
        DISTRIBUTED_BRUTE_FORCE: "Distributed Brute Force",
        MFA_METHOD_DOWNGRADE: "MFA Bypass Detected",
        ENTRA_RISKY_SIGNIN: "Microsoft-Flagged Risky Sign-in",
        MFA_REGISTRATION_AFTER_COMPROMISE: "Attacker MFA Persistence",
        OAUTH_CONSENT_GRANT: "Risky OAuth Consent",
        PRIVILEGED_ROLE_ASSIGNMENT: "Privileged Role Granted",
        APP_CREDENTIAL_ADDED: "App Credential Added",
        OAUTH_CONSENT_PHISHING: "OAuth Phishing Attempt",
        CONCURRENT_SESSIONS: "Simultaneous Sessions",
      };
      const label = m[type] || type.replace(/_/g, " ");
      return `<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:16px 20px;display:flex;justify-content:space-between;align-items:center">
      <div style="font-size:14px;font-weight:600;color:#1e293b">${esc(label)}</div>
      <div style="font-size:28px;font-weight:800;color:#dc2626">${count}</div>
    </div>`;
    })
    .join("");

  const trendBars = last7
    .map(([day, count]) => {
      const pct = Math.round((count / maxDay) * 100);
      const label = new Date(day).toLocaleDateString("en-GB", {
        day: "numeric",
        month: "short",
      });
      return `<div style="display:flex;flex-direction:column;align-items:center;gap:4px;flex:1">
      <div style="width:100%;background:#e2e8f0;border-radius:4px;height:80px;display:flex;align-items:flex-end">
        <div style="width:100%;height:${pct}%;background:#5b8def;border-radius:4px;-webkit-print-color-adjust:exact;print-color-adjust:exact"></div>
      </div>
      <div style="font-size:9px;color:#64748b;text-align:center">${esc(label)}</div>
      <div style="font-size:10px;font-weight:600;color:#334155">${count}</div>
    </div>`;
    })
    .join("");

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

  const win = window.open("", "_blank");
  if (!win) {
    alert("Popup blocked — allow popups for this page.");
    return;
  }
  win.document.write(html);
  win.document.close();
}

/* ── Baseline Drift ───────────────────────────────────────────────────────── */
function setBaselineNow() {
  if (!state.analysisData || !state.activeWorkspace) return;
  saveBaseline(
    state.activeWorkspace.id,
    extractBaselineMetrics(state.analysisData),
  );
  toast(
    '<i class="bi bi-bar-chart-fill"></i> Baseline updated — future runs will compare against this snapshot',
    "ok",
  );
}

function renderDriftBanner(data) {
  if (!state.activeWorkspace) return "";
  const bl = loadBaseline(state.activeWorkspace.id);
  if (!bl) return "";
  const cur = extractBaselineMetrics(data);
  const blDate = new Date(bl.ts).toLocaleDateString("en-GB", {
    dateStyle: "medium",
  });

  const LABELS = {
    foreignFailed: { label: "Foreign Failed", bad: "up" },
    foreignSuccess: { label: "Foreign Success", bad: "up" },
    detectionCount: { label: "Detections", bad: "up" },
    criticalCount: { label: "Critical Accounts", bad: "up" },
    attackingCountries: { label: "Attacking Countries", bad: "up" },
  };

  const deltas = [];
  for (const [key, meta] of Object.entries(LABELS)) {
    const prev = bl.metrics[key] || 0;
    const curr = cur[key] || 0;
    if (prev === 0 && curr === 0) continue;
    const diff = curr - prev;
    const pct = prev > 0 ? Math.round((diff / prev) * 100) : curr > 0 ? 100 : 0;
    if (Math.abs(pct) < 5 && Math.abs(diff) < 2) continue; // ignore tiny changes
    const worse = meta.bad === "up" ? diff > 0 : diff < 0;
    deltas.push({ key, label: meta.label, prev, curr, diff, pct, worse });
  }
  if (!deltas.length) return "";

  const chips = deltas
    .map((d) => {
      const arrow = d.diff > 0 ? "↑" : "↓";
      const col = d.worse ? "var(--danger)" : "var(--ok)";
      const bg = d.worse ? "rgba(209,64,64,0.08)" : "rgba(33,168,108,0.08)";
      const bord = d.worse ? "rgba(209,64,64,0.25)" : "rgba(33,168,108,0.25)";
      return `<span class="drift-chip" style="background:${bg};border-color:${bord};color:${col}">
      <span class="drift-arrow">${arrow}</span>
      <span class="drift-label">${escHtml(d.label)}</span>
      <span class="drift-val">${d.curr} <span style="font-size:10px;opacity:.8">(${d.diff > 0 ? "+" : ""}${d.pct}%)</span></span>
    </span>`;
    })
    .join("");

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
  const ws = state.activeWorkspace;
  if (!data || !ws) return;

  const events = data.events || [];
  const detections = data.detections || [];
  const summaries = data.userSummaries || [];
  const homeCountry = data.homeCountry || "ID";
  const home = homeCountry.toUpperCase();
  const now = new Date().toLocaleString("en-GB", {
    dateStyle: "full",
    timeStyle: "short",
  });
  const esc = (s) =>
    String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  const fmt = (d) => {
    try {
      return new Date(d).toLocaleString("en-GB", {
        dateStyle: "medium",
        timeStyle: "short",
      });
    } catch {
      return d || "";
    }
  };

  const critUsers = summaries.filter((s) => s.riskLevel === "CRITICAL");
  const highUsers = summaries.filter((s) => s.riskLevel === "HIGH");
  const medUsers = summaries.filter((s) => s.riskLevel === "MEDIUM");
  const foreignSucc = events.filter(
    (e) => e.success && e.country && e.country.toUpperCase() !== home,
  ).length;
  const foreignFail = events.filter(
    (e) => !e.success && e.country && e.country.toUpperCase() !== home,
  ).length;

  // Top 5 attacking countries by event count
  const countryCounts = {};
  for (const e of events) {
    if (e.country && e.country.toUpperCase() !== home)
      countryCounts[e.country] = (countryCounts[e.country] || 0) + 1;
  }
  const topCountries = Object.entries(countryCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  // Detection type summary
  const detByType = {};
  for (const d of detections) detByType[d.type] = (detByType[d.type] || 0) + 1;
  const topDets = Object.entries(detByType)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  // CA Remediation hits
  const detTypes = new Set(detections.map((d) => d.type));
  const remHits = Object.entries(CA_RECS)
    .filter(([t]) => detTypes.has(t))
    .slice(0, 4);

  // Campaigns
  const campaigns = groupIntoCampaigns(detections);

  const riskColor = {
    CRITICAL: "#dc2626",
    HIGH: "#d97706",
    MEDIUM: "#2563eb",
    LOW: "#16a34a",
  };
  const riskBg = {
    CRITICAL: "#fef2f2",
    HIGH: "#fffbeb",
    MEDIUM: "#eff6ff",
    LOW: "#f0fdf4",
  };
  const riskBorder = {
    CRITICAL: "#fecaca",
    HIGH: "#fde68a",
    MEDIUM: "#bfdbfe",
    LOW: "#bbf7d0",
  };

  const userCards = [...critUsers, ...highUsers]
    .slice(0, 8)
    .map(
      (s) => `
    <div style="border:1px solid ${riskBorder[s.riskLevel] || "#e2e8f0"};border-left:4px solid ${riskColor[s.riskLevel] || "#94a3b8"};border-radius:8px;padding:14px 16px;margin-bottom:10px;background:${riskBg[s.riskLevel] || "#f8fafc"}">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
        <div>
          <span style="font-weight:700;font-size:14px;color:#0f172a">${esc(s.displayName)}</span>
          <span style="font-size:11px;color:#64748b;margin-left:6px">${esc(s.user)}</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          ${s.riskScore != null ? `<span style="font-size:13px;font-weight:800;color:${riskColor[s.riskLevel]}">${s.riskScore}/100</span>` : ""}
          <span style="font-size:11px;font-weight:700;padding:3px 8px;border-radius:4px;background:${riskColor[s.riskLevel]};color:#fff">${esc(s.riskLevel)}</span>
        </div>
      </div>
      <div style="font-size:12px;color:#334155;margin-bottom:6px">${esc(s.primaryThreat)} · ${s.foreignAttempts} foreign failed · ${s.uniqueAttackingCountries} countries</div>
      ${s.narrative ? `<div style="font-size:11.5px;color:#475569;font-style:italic;line-height:1.5">${esc(s.narrative)}</div>` : ""}
    </div>`,
    )
    .join("");

  const countryRows = topCountries
    .map(
      ([c, n]) => `
    <tr style="border-bottom:1px solid #f1f5f9">
      <td style="padding:7px 12px;font-weight:600;color:#0f172a;font-size:12.5px">${esc(c)}</td>
      <td style="padding:7px 12px;text-align:right;font-weight:700;color:#dc2626;font-size:13px">${n}</td>
    </tr>`,
    )
    .join("");

  const detRows = topDets
    .map(
      ([t, n]) => `
    <tr style="border-bottom:1px solid #f1f5f9">
      <td style="padding:7px 12px;font-size:12px;color:#334155">${esc(t.replace(/_/g, " "))}</td>
      <td style="padding:7px 12px;text-align:right;font-weight:700;color:#0f172a;font-size:13px">${n}</td>
    </tr>`,
    )
    .join("");

  const remRows = remHits
    .map(
      ([t, r]) => `
    <div style="display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid #f1f5f9">
      <span style="font-size:16px">${r.icon}</span>
      <div><div style="font-size:12.5px;font-weight:600;color:#0f172a">${esc(r.title)}</div><div style="font-size:11.5px;color:#64748b">${esc(r.action)}</div></div>
    </div>`,
    )
    .join("");

  const campaignSection =
    campaigns.length >= 2
      ? `
    <div style="margin-bottom:28px">
      <div style="font-size:14px;font-weight:700;color:#0f172a;padding-bottom:8px;border-bottom:2px solid #e2e8f0;margin-bottom:12px">⚡ Attack Campaigns Detected</div>
      ${campaigns
        .slice(0, 3)
        .map(
          (c, i) => `
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:10px 14px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">
          <div>
            <span style="font-size:11px;font-weight:700;color:#6366f1;margin-right:8px">CAMPAIGN ${i + 1}</span>
            <span style="font-size:12px;color:#334155">${c.detections.length} detections · ${c.users.length} users · ${c.ips.length} IPs</span>
          </div>
          <div style="font-size:11px;color:#64748b">${c.types
            .slice(0, 3)
            .map((t) => t.replace(/_/g, " "))
            .join(" · ")}</div>
        </div>`,
        )
        .join("")}
    </div>`
      : "";

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
    ${
      critUsers.length + highUsers.length > 0
        ? `
    <div style="margin-bottom:28px">
      <div style="font-size:14px;font-weight:700;color:#0f172a;padding-bottom:8px;border-bottom:2px solid #e2e8f0;margin-bottom:12px">🚨 Accounts Requiring Immediate Action</div>
      ${userCards}
    </div>`
        : ""
    }

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
    ${
      remHits.length > 0
        ? `
    <div style="margin-bottom:28px">
      <div style="font-size:13px;font-weight:700;color:#0f172a;margin-bottom:10px;padding-bottom:6px;border-bottom:2px solid #e2e8f0">🛡️ Recommended CA Policy Actions</div>
      ${remRows}
    </div>`
        : ""
    }

    <!-- Footer -->
    <div style="padding-top:16px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;font-size:9.5px;color:#94a3b8">
      <span>©2025 PT Sigma Cipta Caraka — Telkomsigma. CONFIDENTIAL.</span>
      <span>EIDSA by JoshuaDjuk · Workspace: ${esc(ws.name)}</span>
    </div>
  </div>
</div>
</body>
</html>`;

  const blob = new Blob([html], { type: "text/html;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `EIDSA_Digest_${ws.name.replace(/\W+/g, "_")}_${new Date().toISOString().slice(0, 10)}.html`;
  a.click();
  URL.revokeObjectURL(url);
  toast('<i class="bi bi-envelope"></i> Weekly Digest exported', "ok");
}

