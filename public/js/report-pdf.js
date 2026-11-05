/* ── PDF Report (full investigation report) ──────────────────────────────── */
// Opens a print-ready HTML report in a new window; the browser's
// "Save as PDF" produces the file. All numbers come from the server-side
// analysis (stats / reportStats), not from the partially loaded event list.

function exportPDF() {
  const html = buildPdfReportHTML();
  if (!html) return;
  const win = window.open("", "_blank");
  if (!win) {
    toast("Popup blocked — allow popups for this page to export the PDF.", "err");
    return;
  }
  win.document.write(html);
  win.document.close();
}

const PDF_SEV_ORDER = { high: 0, medium: 1, low: 2 };
const PDF_PRIORITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function pdfDetTime(d) {
  return d.time || d.windowStart || d.firstSeen || d.from?.time || "";
}

function buildPdfReportHTML() {
  const data = state.analysisData;
  const ws = state.activeWorkspace;
  if (!data || !ws) return null;

  const esc = (str) =>
    String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  const fmt = (n) => (n ?? 0).toLocaleString("en-US");
  const fmtDT = (s) =>
    s ? new Date(s).toLocaleString("en-GB", { dateStyle: "medium", timeStyle: "short" }) : "—";
  // "a – b", collapsed to one value when both format the same
  const fmtRange = (a, b, sep = " – ") => {
    if (!a) return "";
    const x = fmtDT(a), y = fmtDT(b || a);
    return x === y ? x : `${x} ${sep}${y}`;
  };
  const fmtD = (s) => (s ? new Date(s).toLocaleDateString("en-GB", { dateStyle: "medium" }) : "—");
  const ACRONYMS = { MFA: "MFA", OAUTH: "OAuth", CA: "CA", IP: "IP", ENTRA: "Entra", SIGNIN: "Sign-in" };
  const typeLabel = (t) =>
    t.split("_").map((w) => ACRONYMS[w] || w.charAt(0) + w.slice(1).toLowerCase()).join(" ");

  const events = data.events || [];
  const allDetections = data.detections || [];
  const summaries = data.userSummaries || [];
  const timeline = data.attackTimeline || [];
  const enrichment = data.ipEnrichment || {};
  const homeCountry = (data.homeCountry || ws.homeCountry || "ID").toUpperCase();
  const uf = data.userFilter || {};

  // Analyst triage: false positives are excluded from the report body
  const triageOf = (d) => state.triages[getTriageKey(d)] || "";
  const detections = allDetections.filter((d) => triageOf(d) !== "FP");
  const fpCount = allDetections.length - detections.length;
  const tpCount = detections.filter((d) => triageOf(d) === "TP").length;

  // Server stats (full dataset); fall back to loaded events for old cached results
  const s = data.stats || {};
  const total = s.total ?? data.total ?? events.length;
  const successes = s.successful ?? events.filter((e) => e.success).length;
  const failures = s.failed ?? events.filter((e) => !e.success).length;
  const interrupted = s.interrupted ?? 0;
  const uniqueUsers = s.uniqueUsers ?? new Set(events.map((e) => e.userPrincipal)).size;
  const uniqueCtries = s.uniqueCountries ?? new Set(events.map((e) => e.country).filter(Boolean)).size;
  const foreignSucc = s.foreignLogins ?? events.filter((e) => e.success && e.country && e.country.toUpperCase() !== homeCountry).length;

  const rs = data.reportStats || (() => {
    const ts = events.map((e) => Date.parse(e.createdAt)).filter(Boolean).sort((a, b) => a - b);
    return {
      firstEvent: ts.length ? new Date(ts[0]).toISOString() : null,
      lastEvent: ts.length ? new Date(ts[ts.length - 1]).toISOString() : null,
      topAttackerIPs: [],
      topCountries: [],
    };
  })();
  const period = rs.firstEvent ? `${fmtDT(rs.firstEvent)} — ${fmtDT(rs.lastEvent)}` : "—";

  const highDets = detections.filter((d) => d.severity === "high").length;
  const medDets = detections.filter((d) => d.severity === "medium").length;
  const crit = summaries.filter((x) => x.riskLevel === "CRITICAL");
  const high = summaries.filter((x) => x.riskLevel === "HIGH");
  const med = summaries.filter((x) => x.riskLevel === "MEDIUM");

  const riskLabel = crit.length ? "CRITICAL" : high.length ? "HIGH" : med.length ? "MEDIUM" : "CLEAR";
  const RISK_HEX = { CRITICAL: "#dc2626", HIGH: "#d97706", MEDIUM: "#2563eb", CLEAR: "#16a34a" };
  const riskHex = RISK_HEX[riskLabel];
  const sevHex = (sev) => (sev === "high" ? "#dc2626" : sev === "medium" ? "#d97706" : "#2563eb");
  const now = new Date();
  const nowStr = now.toLocaleString("en-GB", { dateStyle: "long", timeStyle: "short" });

  // ── Detections grouped by type ───────────────────────────────────────────
  const byType = {};
  for (const d of detections) {
    const g = byType[d.type] || (byType[d.type] = { type: d.type, items: [], sev: "low", users: new Set(), ips: new Set() });
    g.items.push(d);
    if ((PDF_SEV_ORDER[d.severity] ?? 3) < (PDF_SEV_ORDER[g.sev] ?? 3)) g.sev = d.severity;
    [d.user, ...(d.affectedUsers || [])].filter(Boolean).forEach((u) => g.users.add(u));
    [d.ip, ...(d.uniqueIPs || d.ips || [])].filter(Boolean).forEach((ip) => g.ips.add(ip));
  }
  const groups = Object.values(byType).sort(
    (a, b) => (PDF_SEV_ORDER[a.sev] ?? 3) - (PDF_SEV_ORDER[b.sev] ?? 3) || b.items.length - a.items.length,
  );
  const maxGroup = Math.max(1, ...groups.map((g) => g.items.length));

  // ── Key findings (plain-language bullets) ────────────────────────────────
  const findings = [];
  if (crit.length) {
    findings.push({
      sev: "high",
      text: `<b>${crit.length} account${crit.length > 1 ? "s" : ""} likely compromised</b> — ${crit.slice(0, 5).map((x) => esc(x.user)).join(", ")}${crit.length > 5 ? ` and ${crit.length - 5} more` : ""}. Primary signal: ${esc(crit[0].primaryThreat)}.`,
    });
  }
  const breachIPs = (rs.topAttackerIPs || []).filter((a) => a.success > 0);
  if (breachIPs.length) {
    findings.push({
      sev: "high",
      text: `<b>${breachIPs.length} foreign IP${breachIPs.length > 1 ? "s" : ""} signed in successfully</b>: ${breachIPs.slice(0, 4).map((a) => `${esc(a.ip)} (${esc(a.country)})`).join(", ")}.`,
    });
  }
  const auditTypes = ["MFA_REGISTRATION_AFTER_COMPROMISE", "OAUTH_CONSENT_GRANT", "PRIVILEGED_ROLE_ASSIGNMENT", "APP_CREDENTIAL_ADDED"];
  const auditHits = groups.filter((g) => auditTypes.includes(g.type));
  if (auditHits.length) {
    findings.push({
      sev: "high",
      text: `<b>Post-compromise activity in audit logs</b>: ${auditHits.map((g) => `${typeLabel(g.type)} (${g.items.length})`).join(", ")} — attackers may have persistence that survives a password reset.`,
    });
  }
  const risky = byType.ENTRA_RISKY_SIGNIN;
  if (risky) {
    findings.push({ sev: "high", text: `<b>Microsoft Identity Protection</b> flagged risky successful sign-ins for ${risky.users.size} user${risky.users.size > 1 ? "s" : ""}.` });
  }
  const topAttacker = (rs.topAttackerIPs || [])[0];
  if (topAttacker && topAttacker.failed > 0) {
    const en = enrichment[topAttacker.ip];
    findings.push({
      sev: "medium",
      text: `<b>Most active attacker</b>: ${esc(topAttacker.ip)} (${esc(topAttacker.country)}${en?.isp ? ", " + esc(en.isp) : ""}) — ${fmt(topAttacker.failed)} failed attempts against ${fmt(topAttacker.users)} account${topAttacker.users > 1 ? "s" : ""}.`,
    });
  }
  const mfaGaps = ["MFA_METHOD_DOWNGRADE", "CA_GAP", "LEGACY_AUTH"].filter((t) => byType[t]);
  if (mfaGaps.length) {
    findings.push({ sev: "medium", text: `<b>MFA can be bypassed</b>: ${mfaGaps.map((t) => `${typeLabel(t)} (${byType[t].users.size} user${byType[t].users.size > 1 ? "s" : ""})`).join(", ")}.` });
  }
  if (groups.length) {
    findings.push({
      sev: "info",
      text: `Most frequent detections: ${[...groups].sort((a, b) => b.items.length - a.items.length).slice(0, 3).map((g) => `${typeLabel(g.type)} (${g.items.length})`).join(", ")}.`,
    });
  }
  if (!detections.length) findings.push({ sev: "ok", text: "No suspicious activity was detected in the analyzed period." });

  const narrative =
    `Between <b>${esc(period)}</b>, EIDSA analyzed <b>${fmt(total)}</b> sign-in events for <b>${fmt(uniqueUsers)}</b> users` +
    `${ws.tenant ? ` of <b>${esc(ws.tenant)}</b>` : ""} from <b>${fmt(uniqueCtries)}</b> countries` +
    `${s.auditEvents ? ` together with <b>${fmt(s.auditEvents)}</b> directory audit events` : ""}. ` +
    `The analysis produced <b>${fmt(detections.length)}</b> detections (${fmt(highDets)} high severity)` +
    `${fpCount ? `, after excluding ${fmt(fpCount)} marked as false positive` : ""}. ` +
    `<b>${fmt(summaries.length)}</b> account${summaries.length === 1 ? " is" : "s are"} at risk; overall tenant risk is assessed as <b style="color:${riskHex}">${riskLabel}</b>.`;

  // ── Recommendations ──────────────────────────────────────────────────────
  const recs = [];
  const seenRec = new Set();
  for (const g of groups) {
    const r = CA_RECS[g.type];
    if (!r || seenRec.has(r.title)) continue;
    seenRec.add(r.title);
    recs.push({ ...r, types: [g.type], count: g.items.length });
  }
  recs.sort((a, b) => (PDF_PRIORITY_ORDER[a.priority] ?? 9) - (PDF_PRIORITY_ORDER[b.priority] ?? 9));

  const immediate = [];
  if (crit.length) {
    immediate.push(`Reset passwords and revoke all sessions for: ${crit.map((x) => `<b>${esc(x.user)}</b>`).join(", ")} (Entra ID → Users → Revoke sessions, or <code>Revoke-MgUserSignInSession</code>).`);
    immediate.push("Review and remove unknown MFA methods, inbox rules / forwarding and OAuth app grants on those accounts.");
  }
  if (breachIPs.length) immediate.push(`Block the attacker IPs with successful sign-ins in a Conditional Access named location: ${breachIPs.slice(0, 8).map((a) => `<code>${esc(a.ip)}</code>`).join(" ")}.`);
  if (byType.PRIVILEGED_ROLE_ASSIGNMENT) immediate.push("Verify every new privileged role assignment listed in this report; remove any that were not change-approved.");
  if (byType.APP_CREDENTIAL_ADDED) immediate.push("Remove unrecognized secrets/certificates from the affected app registrations and rotate the legitimate ones.");
  if (byType.OAUTH_CONSENT_GRANT) immediate.push("Revoke consent for the flagged OAuth applications and disable their service principals if unknown.");

  // ── Sections ─────────────────────────────────────────────────────────────
  const statBox = (val, label, color = "#0f172a", sub = "") =>
    `<div class="stat-box"><div class="sv" style="color:${color}">${val}</div><div class="sl">${label}</div>${sub ? `<div class="ss">${sub}</div>` : ""}</div>`;

  const findingsHtml = findings
    .map((f) => `<li class="kf kf-${f.sev}">${f.text}</li>`)
    .join("");

  const typeTable = groups
    .map((g) => {
      const m = MITRE_MAP[g.type];
      return `<tr>
        <td><span class="sev" style="background:${sevHex(g.sev)}">${esc(g.sev.toUpperCase())}</span></td>
        <td><b>${esc(typeLabel(g.type))}</b></td>
        <td>${m ? `<span class="mitre">${esc(m.id)}</span> <span class="muted">${esc(m.tactic)}</span>` : "—"}</td>
        <td class="num">${g.items.length}</td>
        <td><div class="bar"><div style="width:${Math.round((g.items.length / maxGroup) * 100)}%;background:${sevHex(g.sev)}"></div></div></td>
        <td class="num">${g.users.size || "—"}</td>
        <td class="num">${g.ips.size || "—"}</td>
      </tr>`;
    })
    .join("");

  // MITRE ATT&CK coverage: tactic → techniques observed
  const tactics = {};
  for (const g of groups) {
    const m = MITRE_MAP[g.type];
    if (!m) continue;
    (tactics[m.tactic] = tactics[m.tactic] || new Map()).set(m.id, { name: m.name, count: (tactics[m.tactic].get(m.id)?.count || 0) + g.items.length });
  }
  const TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement"];
  const mitreHtml = TACTIC_ORDER.filter((t) => tactics[t])
    .map(
      (t) => `<div class="tactic">
        <div class="tactic-name">${esc(t)}</div>
        ${[...tactics[t]].map(([id, v]) => `<div class="tech"><span class="mitre">${esc(id)}</span> ${esc(v.name)} <span class="muted">×${v.count}</span></div>`).join("")}
      </div>`,
    )
    .join("");

  const recHtml = recs
    .map(
      (r) => `<div class="rec rec-${r.priority.toLowerCase()}">
        <div class="rec-head"><span class="prio prio-${r.priority.toLowerCase()}">${esc(r.priority)}</span><b>${esc(r.title)}</b><span class="muted"> — ${r.types.map(typeLabel).join(", ")} (${r.count})</span></div>
        <div class="rec-desc">${esc(r.desc)}</div>
        <div class="rec-path"><b>Where:</b> ${esc(r.action)}</div>
        <div class="rec-tip"><b>How:</b> ${esc(r.tip)}</div>
      </div>`,
    )
    .join("");

  // Accounts at risk — CRITICAL/HIGH in full, MEDIUM as a compact table
  const detsForUser = (u) => detections.filter((d) => d.user === u || (d.affectedUsers || []).includes(u));
  const userCard = (x) => {
    const dets = detsForUser(x.user);
    const note = state.userNotes?.[x.user];
    const foreign = (x.successfulForeignEvents || []).slice(0, 6);
    return `<div class="user-card uc-${x.riskLevel.toLowerCase()}">
      <div class="uc-head">
        <span class="risk-pill" style="background:${RISK_HEX[x.riskLevel]}">${esc(x.riskLevel)}</span>
        <span class="uc-score">${x.riskScore ?? "—"}<small>/100</small></span>
        <span class="uc-name">${esc(x.displayName)}</span>
        <span class="uc-mail">${esc(x.user)}</span>
        ${state.watchList?.has(x.user) ? '<span class="watch">★ WATCH LIST</span>' : ""}
      </div>
      <div class="uc-stats">
        <span>Primary threat: <b>${esc(x.primaryThreat)}</b></span>
        <span>Foreign failed: <b>${fmt(x.foreignAttempts)}</b></span>
        <span>Foreign success: <b style="color:${x.foreignSuccess ? "#dc2626" : "#16a34a"}">${fmt(x.foreignSuccess)}</b></span>
        <span>Attack window: <b>${fmtRange(x.attackStart, x.attackEnd) || "—"}</b></span>
      </div>
      ${x.narrative ? `<div class="uc-narr">${esc(x.narrative)}</div>` : ""}
      <div class="chips">${[...new Set(dets.map((d) => d.type))].map((t) => `<span class="chip">${esc(typeLabel(t))}${MITRE_MAP[t] ? ` · ${esc(MITRE_MAP[t].id)}` : ""}</span>`).join("")}</div>
      ${
        foreign.length
          ? `<table class="mini"><thead><tr><th>Successful foreign sign-in</th><th>Location</th><th>IP</th><th>Application</th></tr></thead><tbody>
          ${foreign.map((e) => `<tr><td>${fmtDT(e.createdAt)}</td><td>${esc(e.country)}${e.city ? " / " + esc(e.city) : ""}</td><td class="mono">${esc(e.ipAddress)}</td><td>${esc(e.appName)}</td></tr>`).join("")}
          </tbody></table>`
          : ""
      }
      ${x.attackingCountries?.length ? `<div class="muted small">Source countries: ${x.attackingCountries.slice(0, 25).map(esc).join(", ")}${x.attackingCountries.length > 25 ? ` +${x.attackingCountries.length - 25}` : ""}</div>` : ""}
      ${note ? `<div class="uc-note"><b>Analyst note:</b> ${esc(note)}</div>` : ""}
    </div>`;
  };
  const detailedUsers = [...crit, ...high];
  const medRows = med
    .map((x) => `<tr><td>${esc(x.user)}</td><td class="num">${x.riskScore ?? "—"}</td><td>${esc(x.primaryThreat)}</td><td class="num">${fmt(x.foreignAttempts)}</td><td>${(x.detectionTypes || []).map(typeLabel).join(", ")}</td></tr>`)
    .join("");

  // Detection details per type
  const ROWS_PER_TYPE = 40;
  const detDetails = groups
    .map((g) => {
      const m = MITRE_MAP[g.type];
      const rows = [...g.items]
        .sort((a, b) => (PDF_SEV_ORDER[a.severity] ?? 3) - (PDF_SEV_ORDER[b.severity] ?? 3) || String(pdfDetTime(b)).localeCompare(String(pdfDetTime(a))))
        .slice(0, ROWS_PER_TYPE)
        .map((d) => {
          const tri = triageOf(d);
          const comment = state.detectionComments?.[getTriageKey(d)];
          const when = fmtRange(d.windowStart || d.firstSeen, d.windowEnd || d.lastSeen, "–<br>") || fmtDT(pdfDetTime(d));
          return `<tr>
            <td><span class="sev" style="background:${sevHex(d.severity)}">${esc(d.severity.toUpperCase())}</span>${tri ? `<div class="tri tri-${tri.toLowerCase()}">${esc(tri)}</div>` : ""}</td>
            <td class="small">${when}</td>
            <td>${esc(d.message)}${comment ? `<div class="det-comment">💬 ${esc(comment)}</div>` : ""}</td>
          </tr>`;
        })
        .join("");
      return `<div class="det-group">
        <h3><span class="sev" style="background:${sevHex(g.sev)}">${esc(g.sev.toUpperCase())}</span> ${esc(typeLabel(g.type))} <span class="muted">(${g.items.length})</span>
          ${m ? `<span class="mitre">ATT&amp;CK ${esc(m.id)} · ${esc(m.name)}</span>` : ""}</h3>
        ${CA_RECS[g.type]?.desc ? `<div class="muted small" style="margin-bottom:6px">${esc(CA_RECS[g.type].desc)}</div>` : ""}
        <table><thead><tr><th style="width:74px">Severity</th><th style="width:118px">When</th><th>Finding</th></tr></thead><tbody>${rows}</tbody></table>
        ${g.items.length > ROWS_PER_TYPE ? `<div class="muted small">+${g.items.length - ROWS_PER_TYPE} more ${esc(typeLabel(g.type))} findings — see EIDSA for the full list.</div>` : ""}
      </div>`;
    })
    .join("");

  // Attacker infrastructure
  const ipFlags = (en) =>
    en
      ? [en.proxy && "PROXY", en.hosting && "VPS", en.mobile && "MOBILE", en.isTor && "TOR", en.abuseScore > 0 && `ABUSE ${en.abuseScore}%`].filter(Boolean).map((f) => `<span class="flag">${f}</span>`).join(" ")
      : "";
  const ipRows = (rs.topAttackerIPs || [])
    .map((a) => {
      const en = enrichment[a.ip];
      return `<tr${a.success ? ' class="row-breach"' : ""}>
        <td class="mono">${esc(a.ip)}</td>
        <td>${esc(a.country)}${a.city ? " / " + esc(a.city) : ""}</td>
        <td class="small">${en ? esc(en.isp || en.org || "") + (en.as ? `<div class="muted">${esc(en.as.split(" ")[0])}</div>` : "") : '<span class="muted">not enriched</span>'}</td>
        <td>${ipFlags(en)}</td>
        <td class="num">${fmt(a.failed)}</td>
        <td class="num" style="color:${a.success ? "#dc2626" : "inherit"};font-weight:${a.success ? 700 : 400}">${fmt(a.success)}</td>
        <td class="num">${fmt(a.users)}</td>
      </tr>`;
    })
    .join("");
  const maxCtry = Math.max(1, ...(rs.topCountries || []).map((c) => c.total));
  const ctryRows = (rs.topCountries || [])
    .map(
      (c) => `<tr>
        <td><b>${esc(c.country)}</b>${c.country.toUpperCase() === homeCountry ? ' <span class="muted">(home)</span>' : ""}</td>
        <td class="num">${fmt(c.total)}</td>
        <td><div class="bar"><div style="width:${Math.round((c.total / maxCtry) * 100)}%;background:${c.country.toUpperCase() === homeCountry ? "#94a3b8" : "#d97706"}"></div></div></td>
        <td class="num">${fmt(c.success)}</td>
        <td class="num">${fmt(c.failed)}</td>
      </tr>`,
    )
    .join("");

  const tlRows = timeline
    .map(
      (e) => `<tr>
      <td class="small">${fmtDT(e.time)}</td>
      <td>${esc(e.user || e.displayName)}</td>
      <td>${esc(e.country)}${e.city ? " / " + esc(e.city.slice(0, 18)) : ""}</td>
      <td class="mono">${esc(e.ip)}</td>
      <td class="small">${esc(e.appName || "")}</td>
      <td class="num">${e.errorCode || ""}</td>
    </tr>`,
    )
    .join("");

  // IOC appendix
  const iocIPs = new Map();
  const iocUsers = new Map();
  for (const d of detections) {
    for (const ip of [d.ip, ...(d.uniqueIPs || d.ips || [])].filter(Boolean)) {
      const cur = iocIPs.get(ip) || new Set();
      cur.add(d.type);
      iocIPs.set(ip, cur);
    }
    for (const u of [d.user, ...(d.affectedUsers || [])].filter(Boolean)) {
      const cur = iocUsers.get(u) || new Set();
      cur.add(d.type);
      iocUsers.set(u, cur);
    }
  }
  // IP → country, from the server's foreign-IP ranking and the loaded events
  const ipCountry = {};
  for (const e of events) if (e.ipAddress && e.country) ipCountry[e.ipAddress] = e.country;
  for (const a of rs.topAttackerIPs || []) ipCountry[a.ip] = a.country;
  const isHomeIP = (ip) => (ipCountry[ip] || "").toUpperCase() === homeCountry;
  const iocRows = (map, withLoc) =>
    [...map]
      .sort((a, b) => (withLoc ? isHomeIP(a[0]) - isHomeIP(b[0]) : 0) || b[1].size - a[1].size || a[0].localeCompare(b[0]))
      .map(([v, types]) => `<tr><td class="mono">${esc(v)}</td>${withLoc ? `<td>${esc(ipCountry[v] || "?")}${isHomeIP(v) ? ' <span class="muted">(home)</span>' : ""}</td>` : ""}<td class="small">${[...types].map(typeLabel).join(", ")}</td></tr>`)
      .join("");

  // Scope & methodology
  const th = ws.ruleThresholds || {};
  const files = ws.files || [];
  const warnings = (data.parseWarnings || []).filter((w) => w.truncated || w.error);
  const modeLabel = { filter: "Filtered — only users in the target list", highlight: "Highlight — all users, target list marked", all: "All users" }[uf.mode || "all"];
  const scopeRows = [
    ["Analysis period", esc(period)],
    ["Events analyzed", `${fmt(total)} sign-in events${s.auditEvents ? ` · ${fmt(s.auditEvents)} audit events` : ""}${s.duplicatesSkipped ? ` · ${fmt(s.duplicatesSkipped)} duplicates removed` : ""}`],
    ["Source files", files.length ? files.map((f) => `${esc(f.name)} <span class="muted">(${formatBytes(f.size)})</span>`).join("<br>") : "—"],
    ["User scope", `${esc(modeLabel)}${uf.filename ? ` · ${esc(uf.filename)}: ${fmt(uf.matched)} of ${fmt(uf.listed)} listed users found in logs` : ""}`],
    ["Home country / timezone", `${esc(homeCountry)} · ${esc(data.timezone || ws.timezone || "UTC")}`],
    ["Trusted locations", `${(ws.trustedCountries || []).length ? esc(ws.trustedCountries.join(", ")) : "no extra countries"} · ${fmt((ws.trustedIPs || []).length)} trusted IP ranges`],
    ["Detection thresholds", `Spray ≥${th.sprayMinUsers ?? 5} users / ${th.sprayWindowMin ?? 10} min · Brute force ≥${th.bruteMinAttempts ?? 10} attempts · MFA fatigue ≥${th.mfaMinPrompts ?? 5} prompts · Enumeration ≥${th.enumMinUsers ?? 10} users · Travel >${th.travelMaxSpeedKmh ?? 900} km/h`],
    ["Analyst triage", `${fmt(tpCount)} confirmed true positive · ${fmt(fpCount)} false positive (excluded from this report)`],
    ...(warnings.length ? [["Data quality", warnings.map((w) => `${esc(w.file)}: ${w.error ? esc(w.error) : `truncated, ${fmt(w.recovered)} events recovered`}`).join("<br>")]] : []),
  ]
    .map(([k, v]) => `<tr><th>${k}</th><td>${v}</td></tr>`)
    .join("");

  const sections = [
    ["summary", "Executive Summary"],
    ["actions", "Priority Actions"],
    ["accounts", "Accounts at Risk"],
    ["detections", "Detection Details"],
    ["infra", "Attacker Infrastructure"],
    ["timeline", "Attack Timeline"],
    ["scope", "Scope & Methodology"],
    ["ioc", "Appendix — Indicators of Compromise"],
  ];

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>EIDSA Report — ${esc(ws.name)} — ${now.toISOString().slice(0, 10)}</title>
<style>
  @page { size: A4; margin: 14mm 13mm 16mm; }
  @page :first { margin: 0; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, Arial, sans-serif; font-size: 11.5px; color: #1e293b; background: #fff; line-height: 1.45;
         -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  b { font-weight: 700; }
  code, .mono { font-family: Consolas, 'Courier New', monospace; font-size: 10.5px; }
  .muted { color: #64748b; font-weight: 400; }
  .small { font-size: 10.5px; }
  .num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }

  /* Cover */
  .cover { height: 297mm; background: linear-gradient(150deg, #0f172a 0%, #1a1040 60%, #0f2540 100%); color: #fff;
           display: flex; flex-direction: column; page-break-after: always; }
  .cover-main { flex: 1; padding: 56px; display: flex; flex-direction: column; justify-content: center; }
  .cover-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 36px; }
  .cover-logo { font-size: 42px; font-weight: 900; letter-spacing: 4px; color: #7cb3ff; font-style: italic; }
  .cover-risk { border: 2px solid ${riskHex}; border-radius: 8px; padding: 10px 20px; text-align: center; min-width: 120px; }
  .cover-risk .l { font-size: 9px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1.5px; }
  .cover-risk .v { font-size: 17px; font-weight: 800; color: ${riskHex}; margin-top: 4px; }
  .cover-title { font-size: 24px; font-weight: 300; color: #cbd5e1; }
  .cover-sub { font-size: 13px; color: #64748b; margin-top: 4px; }
  .cover-div { height: 1px; background: rgba(255,255,255,0.12); margin: 30px 0; }
  .cover-meta { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px 28px; }
  .cover-meta .l { font-size: 9px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
  .cover-meta .v { font-size: 13px; font-weight: 600; color: #e2e8f0; }
  .cover-conf { border: 1px solid rgba(239,68,68,0.45); border-radius: 4px; padding: 3px 10px; font-size: 9px; font-weight: 700;
                color: #f87171; letter-spacing: 1.5px; text-transform: uppercase; margin-top: 24px; width: fit-content; }
  .cover-company { background: rgba(0,0,0,0.35); border-top: 1px solid rgba(255,255,255,0.08); padding: 16px 56px;
                   display: flex; justify-content: space-between; align-items: center; }
  .cover-company .n { font-size: 12px; font-weight: 600; color: #94a3b8; }
  .cover-company .c { font-size: 10px; color: #475569; }
  .cover-company .a { font-size: 11px; color: #6366f1; font-weight: 600; }

  /* Layout */
  .page { page-break-before: always; }
  h2 { font-size: 15px; color: #0f172a; margin: 0 0 10px; padding-bottom: 6px; border-bottom: 2px solid #0f6cbd; page-break-after: avoid; }
  h2 .no { color: #0f6cbd; margin-right: 6px; }
  h3 { font-size: 12.5px; margin: 16px 0 6px; display: flex; align-items: center; gap: 6px; flex-wrap: wrap; page-break-after: avoid; }
  section + section { margin-top: 22px; }
  p { margin-bottom: 8px; }

  /* TOC */
  .toc { margin: 4px 0 18px; padding: 10px 14px; border: 1px solid #e2e8f0; border-radius: 8px; background: #f8fafc; columns: 2; column-gap: 28px; }
  .toc a { display: block; color: #1e293b; text-decoration: none; padding: 2px 0; font-size: 11px; }
  .toc a span { color: #0f6cbd; font-weight: 700; margin-right: 6px; }

  /* Stats */
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 10px 0; }
  .stat-box { border: 1px solid #e2e8f0; border-radius: 8px; padding: 9px 11px; }
  .sv { font-size: 19px; font-weight: 700; line-height: 1.15; }
  .sl { font-size: 9.5px; color: #64748b; text-transform: uppercase; letter-spacing: 0.4px; }
  .ss { font-size: 9.5px; color: #94a3b8; }
  .risk-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 10px 0 4px; }
  .risk-box { border-radius: 8px; padding: 10px; text-align: center; }
  .risk-box .rv { font-size: 24px; font-weight: 800; }
  .risk-box .rl { font-size: 9.5px; font-weight: 700; letter-spacing: 0.6px; }
  .narr { font-size: 12px; background: #f8fafc; border-left: 4px solid ${riskHex}; padding: 10px 14px; border-radius: 0 6px 6px 0; margin: 8px 0 12px; }

  /* Key findings */
  .kfs { list-style: none; margin: 6px 0 4px; }
  .kf { padding: 6px 10px 6px 28px; margin-bottom: 5px; border-radius: 6px; position: relative; font-size: 11.5px; }
  .kf::before { position: absolute; left: 10px; top: 6px; font-weight: 900; }
  .kf-high { background: #fef2f2; } .kf-high::before { content: "!"; color: #dc2626; }
  .kf-medium { background: #fffbeb; } .kf-medium::before { content: "!"; color: #d97706; }
  .kf-info { background: #eff6ff; } .kf-info::before { content: "i"; color: #2563eb; }
  .kf-ok { background: #f0fdf4; } .kf-ok::before { content: "✓"; color: #16a34a; }

  /* Tables */
  table { width: 100%; border-collapse: collapse; font-size: 10.5px; margin-bottom: 6px; }
  thead { display: table-header-group; }
  tr { page-break-inside: avoid; }
  th { background: #f1f5f9; text-align: left; padding: 5px 8px; font-size: 9.5px; font-weight: 700; color: #475569;
       border: 1px solid #e2e8f0; text-transform: uppercase; letter-spacing: 0.3px; }
  td { padding: 5px 8px; border: 1px solid #e2e8f0; vertical-align: top; }
  .kv th { width: 170px; text-transform: none; font-size: 10.5px; letter-spacing: 0; vertical-align: top; }
  tr.row-breach td { background: #fef2f2; }
  .sev { display: inline-block; color: #fff; padding: 1px 6px; border-radius: 3px; font-size: 9px; font-weight: 700; letter-spacing: 0.3px; }
  .mitre { display: inline-block; background: #f3f0ff; border: 1px solid #c4b5fd; color: #7c3aed; border-radius: 3px; padding: 0 5px; font-size: 9.5px; font-weight: 700; white-space: nowrap; }
  .bar { height: 8px; background: #f1f5f9; border-radius: 4px; min-width: 80px; overflow: hidden; }
  .bar div { height: 100%; border-radius: 4px; }
  .flag { display: inline-block; font-size: 8.5px; font-weight: 700; padding: 0 4px; border-radius: 3px; background: #fff7ed; color: #c2410c; border: 1px solid #fed7aa; margin: 1px 0; }
  .tri { font-size: 8.5px; font-weight: 700; margin-top: 3px; }
  .tri-tp { color: #dc2626; } .tri-inv { color: #d97706; }
  .det-comment { margin-top: 3px; font-size: 10px; color: #475569; font-style: italic; }
  .det-group { page-break-inside: auto; }

  /* MITRE coverage */
  .tactics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 8px 0; }
  .tactic { border: 1px solid #e2e8f0; border-radius: 6px; padding: 7px 9px; page-break-inside: avoid; }
  .tactic-name { font-size: 9.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; color: #7c3aed; margin-bottom: 4px; }
  .tech { font-size: 10px; margin-bottom: 3px; }

  /* Recommendations */
  .immediate { border: 1px solid #fecaca; background: #fef2f2; border-radius: 8px; padding: 10px 14px 10px 30px; margin-bottom: 12px; }
  .immediate li { margin-bottom: 4px; }
  .rec { border: 1px solid #e2e8f0; border-left-width: 4px; border-radius: 6px; padding: 8px 12px; margin-bottom: 8px; page-break-inside: avoid; }
  .rec-critical { border-left-color: #dc2626; } .rec-high { border-left-color: #d97706; } .rec-medium { border-left-color: #2563eb; } .rec-low { border-left-color: #94a3b8; }
  .rec-head { margin-bottom: 3px; }
  .prio { display: inline-block; font-size: 8.5px; font-weight: 800; padding: 1px 6px; border-radius: 3px; color: #fff; margin-right: 6px; }
  .prio-critical { background: #dc2626; } .prio-high { background: #d97706; } .prio-medium { background: #2563eb; } .prio-low { background: #94a3b8; }
  .rec-desc { color: #334155; margin-bottom: 3px; }
  .rec-path, .rec-tip { font-size: 10.5px; color: #475569; }

  /* User cards */
  .user-card { border: 1px solid #e2e8f0; border-left-width: 4px; border-radius: 8px; padding: 10px 13px; margin-bottom: 10px; page-break-inside: avoid; }
  .uc-critical { border-left-color: #dc2626; } .uc-high { border-left-color: #d97706; } .uc-medium { border-left-color: #2563eb; }
  .uc-head { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; margin-bottom: 5px; }
  .risk-pill { padding: 1px 7px; border-radius: 3px; font-size: 9.5px; font-weight: 700; color: #fff; }
  .uc-score { font-size: 15px; font-weight: 800; } .uc-score small { font-size: 9px; color: #94a3b8; }
  .uc-name { font-size: 13px; font-weight: 700; }
  .uc-mail { font-size: 10.5px; color: #64748b; }
  .watch { font-size: 9px; font-weight: 700; color: #b45309; }
  .uc-stats { display: flex; gap: 16px; flex-wrap: wrap; font-size: 10.5px; margin-bottom: 5px; }
  .uc-narr { background: #f8fafc; padding: 6px 10px; border-radius: 4px; font-size: 10.5px; margin-bottom: 6px; }
  .uc-note { background: #fffbeb; border: 1px solid #fde68a; padding: 5px 9px; border-radius: 4px; font-size: 10.5px; margin-top: 6px; }
  .chips { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 6px; }
  .chip { background: #f1f5f9; border: 1px solid #e2e8f0; border-radius: 3px; padding: 0 6px; font-size: 9.5px; }
  table.mini { margin: 4px 0; }

  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .doc-footer { margin-top: 30px; padding-top: 10px; border-top: 1px solid #e2e8f0; display: flex; justify-content: space-between; font-size: 9px; color: #94a3b8; }
</style>
</head>
<body>

<div class="cover">
  <div class="cover-main">
    <div class="cover-top">
      <div class="cover-logo">EIDSA</div>
      <div class="cover-risk"><div class="l">Overall Risk</div><div class="v">${riskLabel}</div></div>
    </div>
    <div class="cover-title">Identity Threat Analysis Report</div>
    <div class="cover-sub">Microsoft Entra ID sign-in${s.auditEvents ? " & audit" : ""} log investigation</div>
    <div class="cover-div"></div>
    <div class="cover-meta">
      <div><div class="l">Workspace</div><div class="v">${esc(ws.name)}</div></div>
      <div><div class="l">Tenant</div><div class="v">${esc(ws.tenant || "—")}</div></div>
      <div><div class="l">Analysis period</div><div class="v">${fmtD(rs.firstEvent)} – ${fmtD(rs.lastEvent)}</div></div>
      <div><div class="l">Events analyzed</div><div class="v">${fmt(total)}</div></div>
      <div><div class="l">Accounts at risk</div><div class="v" style="color:${riskHex}">${fmt(summaries.length)}</div></div>
      <div><div class="l">High-severity findings</div><div class="v">${fmt(highDets)}</div></div>
      <div><div class="l">Prepared by</div><div class="v">${esc(state.currentUser?.username || "—")}</div></div>
      <div><div class="l">Generated</div><div class="v">${esc(nowStr)}</div></div>
      ${uf.mode === "filter" ? `<div><div class="l">Scope</div><div class="v">${fmt(uf.matched)} listed users</div></div>` : ""}
    </div>
    <div class="cover-conf">Confidential — for authorized recipients only</div>
  </div>
  <div class="cover-company">
    <div>
      <div class="n">PT Sigma Cipta Caraka — Telkomsigma</div>
      <div class="c">©${now.getFullYear()}. PT Sigma Cipta Caraka - Telkomsigma. All Rights Reserved.</div>
    </div>
    <div class="a">Developed by JoshuaDjuk</div>
  </div>
</div>

<section id="summary">
  <h2><span class="no">1</span>Executive Summary</h2>
  <div class="toc">${sections.map(([id, t], i) => `<a href="#${id}"><span>${i + 1}</span>${t}</a>`).join("")}</div>
  <div class="narr">${narrative}</div>
  <h3>Key findings</h3>
  <ul class="kfs">${findingsHtml}</ul>

  <h3>Account risk</h3>
  <div class="risk-row">
    <div class="risk-box" style="background:#fef2f2;border:1px solid #fecaca"><div class="rv" style="color:#dc2626">${crit.length}</div><div class="rl" style="color:#dc2626">CRITICAL</div></div>
    <div class="risk-box" style="background:#fffbeb;border:1px solid #fde68a"><div class="rv" style="color:#d97706">${high.length}</div><div class="rl" style="color:#d97706">HIGH</div></div>
    <div class="risk-box" style="background:#eff6ff;border:1px solid #bfdbfe"><div class="rv" style="color:#2563eb">${med.length}</div><div class="rl" style="color:#2563eb">MEDIUM</div></div>
    <div class="risk-box" style="background:#f8fafc;border:1px solid #e2e8f0"><div class="rv">${fmt(Math.max(0, uniqueUsers - summaries.length))}</div><div class="rl" style="color:#64748b">NO FINDINGS</div></div>
  </div>

  <h3>Sign-in activity</h3>
  <div class="stats">
    ${statBox(fmt(total), "Total events")}
    ${statBox(fmt(successes), "Successful", "#16a34a", total ? `${Math.round((successes / total) * 100)}% of events` : "")}
    ${statBox(fmt(failures), "Failed attempts", "#dc2626", interrupted ? `+${fmt(interrupted)} MFA / interrupts` : "")}
    ${statBox(fmt(foreignSucc), "Successful foreign", foreignSucc ? "#dc2626" : "#16a34a", `outside ${esc(homeCountry)}`)}
    ${statBox(fmt(uniqueUsers), "Users")}
    ${statBox(fmt(uniqueCtries), "Countries")}
    ${statBox(fmt(detections.length), "Detections", "#0f172a", `${fmt(highDets)} high · ${fmt(medDets)} medium`)}
    ${statBox(fmt(groups.length), "Attack techniques", "#7c3aed", `${Object.keys(tactics).length} ATT&amp;CK tactics`)}
  </div>

  ${
    groups.length
      ? `<h3>Detections by type</h3>
  <table>
    <thead><tr><th style="width:64px">Severity</th><th>Detection</th><th>MITRE ATT&amp;CK</th><th class="num">Count</th><th style="width:110px"></th><th class="num">Users</th><th class="num">IPs</th></tr></thead>
    <tbody>${typeTable}</tbody>
  </table>
  <h3>MITRE ATT&amp;CK coverage</h3>
  <div class="tactics">${mitreHtml}</div>`
      : ""
  }
</section>

<section id="actions" class="page">
  <h2><span class="no">2</span>Priority Actions</h2>
  ${
    immediate.length
      ? `<h3 style="color:#dc2626">Immediate containment</h3><ol class="immediate">${immediate.map((t) => `<li>${t}</li>`).join("")}</ol>`
      : ""
  }
  ${recs.length ? `<h3>Hardening recommendations</h3>${recHtml}` : '<p class="muted">No hardening actions required based on the detected activity.</p>'}
</section>

<section id="accounts" class="page">
  <h2><span class="no">3</span>Accounts at Risk (${fmt(summaries.length)})</h2>
  ${detailedUsers.length ? detailedUsers.map(userCard).join("") : '<p class="muted">No critical or high-risk accounts.</p>'}
  ${
    med.length
      ? `<h3>Medium-risk accounts (${med.length})</h3>
  <table><thead><tr><th>Account</th><th class="num">Score</th><th>Primary threat</th><th class="num">Foreign failed</th><th>Detections</th></tr></thead><tbody>${medRows}</tbody></table>`
      : ""
  }
</section>

<section id="detections" class="page">
  <h2><span class="no">4</span>Detection Details (${fmt(detections.length)})</h2>
  ${fpCount ? `<p class="muted">${fmt(fpCount)} detection(s) triaged as false positive are excluded.</p>` : ""}
  ${detDetails || '<p class="muted">No detections triggered.</p>'}
</section>

<section id="infra" class="page">
  <h2><span class="no">5</span>Attacker Infrastructure</h2>
  ${
    ipRows
      ? `<h3>Top foreign source IPs</h3>
  <p class="muted small">Ranked by successful sign-ins, failed attempts and accounts targeted. Rows in red signed in successfully.</p>
  <table><thead><tr><th>IP address</th><th>Location</th><th>ISP / ASN</th><th>Flags</th><th class="num">Failed</th><th class="num">Success</th><th class="num">Users</th></tr></thead><tbody>${ipRows}</tbody></table>`
      : '<p class="muted">No foreign source IPs observed.</p>'
  }
  ${
    ctryRows
      ? `<h3>Sign-ins by country</h3>
  <table><thead><tr><th>Country</th><th class="num">Events</th><th style="width:150px"></th><th class="num">Success</th><th class="num">Failed</th></tr></thead><tbody>${ctryRows}</tbody></table>`
      : ""
  }
</section>

${
  timeline.length
    ? `<section id="timeline" class="page">
  <h2><span class="no">6</span>Attack Timeline</h2>
  <p class="muted small">First ${timeline.length} failed foreign sign-in attempts (one per user per hour).</p>
  <table><thead><tr><th style="width:110px">Time</th><th>User</th><th>Location</th><th>IP</th><th>Application</th><th class="num">Error</th></tr></thead><tbody>${tlRows}</tbody></table>
</section>`
    : `<section id="timeline"><h2><span class="no">6</span>Attack Timeline</h2><p class="muted">No failed foreign sign-ins.</p></section>`
}

<section id="scope" class="page">
  <h2><span class="no">7</span>Scope &amp; Methodology</h2>
  <table class="kv"><tbody>${scopeRows}</tbody></table>
  <p class="small" style="margin-top:8px">EIDSA applies ${Object.keys(CA_RECS).length} detection rules covering credential attacks (spray, brute force, stuffing, enumeration),
  anomalous access (impossible travel, concurrent sessions, new country/device/app, off-hours), MFA weaknesses (fatigue, downgrade, legacy auth,
  Conditional Access gaps), Microsoft Identity Protection risk and audit-log persistence (MFA registration, OAuth consent, role assignment, app credentials).
  Detections are mapped to MITRE ATT&amp;CK. Findings are indicators that require analyst validation; severity reflects potential impact, not confirmed compromise
  unless triaged as true positive.</p>
</section>

<section id="ioc" class="page">
  <h2><span class="no">8</span>Appendix — Indicators of Compromise</h2>
  <div class="two-col">
    <div>
      <h3>IP addresses (${iocIPs.size})</h3>
      <p class="muted small">Home-country IPs are listed last — usually the victim's own network, not attacker infrastructure.</p>
      ${iocIPs.size ? `<table><thead><tr><th>IP</th><th>Country</th><th>Detections</th></tr></thead><tbody>${iocRows(iocIPs, true)}</tbody></table>` : '<p class="muted">None</p>'}
    </div>
    <div>
      <h3>Accounts (${iocUsers.size})</h3>
      ${iocUsers.size ? `<table><thead><tr><th>Account</th><th>Detections</th></tr></thead><tbody>${iocRows(iocUsers)}</tbody></table>` : '<p class="muted">None</p>'}
    </div>
  </div>
  <div class="doc-footer">
    <span>©${now.getFullYear()} PT Sigma Cipta Caraka — Telkomsigma. Confidential.</span>
    <span><b>EIDSA</b> · ${esc(ws.name)} · ${esc(nowStr)}</span>
  </div>
</section>

<script>window.onload = () => setTimeout(() => window.print(), 300);<\/script>
</body>
</html>`;
}
