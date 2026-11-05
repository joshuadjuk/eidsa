/* ── KQL Query Generator ──────────────────────────────────────────────────── */
function generateKQL(det) {
  const esc = (s) => String(s || "").replace(/"/g, '\\"');
  const dt = (s) => (s ? s.slice(0, 19).replace("T", " ") : "");

  const timeFilter = det.windowStart
    ? `| where TimeGenerated between (datetime('${dt(det.windowStart)}') .. datetime('${dt(det.windowEnd || new Date().toISOString())}'))`
    : det.time
      ? `| where TimeGenerated >= datetime('${dt(det.time)}') and TimeGenerated <= datetime('${dt(new Date(new Date(det.time).getTime() + 3600000).toISOString())}')`
      : "";

  switch (det.type) {
    case "PASSWORD_SPRAY":
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

    case "BRUTE_FORCE":
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

    case "IMPOSSIBLE_TRAVEL":
      return `// Impossible Travel — User: ${det.user}
// Ref: MITRE T1078 · Defense Evasion
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, AuthenticationRequirement, CorrelationId
| order by TimeGenerated asc
// Look for successive logins from: ${det.from?.country} → ${det.to?.country}`;

    case "FOREIGN_LOGIN":
      return `// Foreign Login — User: ${det.user}
// Ref: MITRE T1078 · Initial Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| where Location != "${esc(det.homeCountry)}"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, ClientAppUsed, AuthenticationRequirement
| order by TimeGenerated asc`;

    case "MFA_EXHAUSTION":
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

    case "TOKEN_REPLAY":
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

    case "LEGACY_AUTH":
      return `// Legacy Authentication Bypass — User: ${det.user}
// Ref: MITRE T1078.004 · Persistence
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ClientAppUsed in~ ("Exchange ActiveSync", "IMAP", "POP3", "SMTP Auth", "MAPI", "AutoDiscover")
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          ClientAppUsed, AppDisplayName, ResultType
| order by TimeGenerated asc`;

    case "CA_GAP":
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

    case "ENUMERATION_ATTACK":
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

    case "SERVICE_PRINCIPAL_ANOMALY":
      return `// Service Principal Anomaly — SP: ${det.user}
// Ref: MITRE T1528 · Credential Access
AADServicePrincipalSignInLogs
| where ServicePrincipalName == "${esc(det.user)}"
| where ResultType == 0
| project TimeGenerated, ServicePrincipalName, IPAddress, Location,
          AppDisplayName, ResourceDisplayName, CorrelationId
| order by TimeGenerated asc`;

    case "ADMIN_TOOL_ABUSE":
      return `// Admin Tool Abuse — User: ${det.user}
// Ref: MITRE T1059.009 · Execution
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| where ClientAppUsed has_any ("PowerShell", "Azure CLI")
    or AppDisplayName has_any ("Azure CLI", "Azure PowerShell", "Graph Explorer", "Azure Portal")
| where Location != "${esc(det.homeCountry || "")}"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, ClientAppUsed, AuthenticationRequirement
| order by TimeGenerated asc`;

    case "CONCURRENT_SESSIONS":
      return `// Concurrent Sessions — User: ${det.user}
// Ref: MITRE T1550 · Lateral Movement
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
${timeFilter}
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, CorrelationId
| order by TimeGenerated asc
// Flag if same user logged in from: ${(det.countries || []).join(", ")}`;

    case "FIRST_SEEN_COUNTRY":
      return `// First-Seen Country — User: ${det.user}
// Ref: MITRE T1078 · Initial Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| where Location == "${esc(det.country)}"
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, AuthenticationRequirement
| order by TimeGenerated asc`;

    case "TIME_OF_DAY_ANOMALY":
      return `// Off-Hours Login — User: ${det.user}
// Ref: MITRE T1078 · Initial Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where ResultType == 0
| extend HourUTC = hourofday(TimeGenerated)
| where HourUTC == ${det.anomalousHour ?? "todynamic(null)"}
| project TimeGenerated, HourUTC, UserPrincipalName, IPAddress, Location,
          AppDisplayName, AuthenticationRequirement
| order by TimeGenerated asc`;

    case "RARE_APP_ACCESS":
      return `// Rare App Access — User: ${det.user}, App: ${det.app}
// Ref: MITRE T1550.001 · Lateral Movement
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where AppDisplayName == "${esc(det.app)}"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, ClientAppUsed, AuthenticationRequirement
| order by TimeGenerated asc`;

    case "CREDENTIAL_STUFFING":
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

    case "DEVICE_FINGERPRINT_ANOMALY":
      return `// Device Fingerprint Anomaly — User: ${det.user}
// Ref: MITRE T1078.004 · Initial Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
| where UserAgent == "${esc(det.userAgent)}"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, UserAgent, AuthenticationRequirement
| order by TimeGenerated asc`;

    case "OAUTH_CONSENT_PHISHING":
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

    case "ENTRA_RISKY_SIGNIN":
      return `// Risky sign-ins (Identity Protection) — ${det.user}
// Ref: MITRE T1078.004 · Initial Access
SigninLogs
| where UserPrincipalName == "${esc(det.user)}"
${timeFilter}
| where RiskLevelDuringSignIn in ("medium", "high") or RiskState in ("atRisk", "confirmedCompromised")
| project TimeGenerated, IPAddress, Location, AppDisplayName, RiskLevelDuringSignIn, RiskState, RiskEventTypes_V2, ResultType
| order by TimeGenerated asc
// Also: AADUserRiskEvents | where UserPrincipalName == "${esc(det.user)}"`;

    case "MFA_REGISTRATION_AFTER_COMPROMISE":
      return `// Security info registration — ${det.user}
// Ref: MITRE T1098.005 · Persistence
AuditLogs
| where TimeGenerated between (datetime('${dt(det.time)}') - 3d .. datetime('${dt(det.time)}') + 1d)
| where OperationName has_any ("security info", "StrongAuthentication")
| mv-expand Target = TargetResources
| where tostring(Target.userPrincipalName) =~ "${esc(det.user)}" or tostring(InitiatedBy.user.userPrincipalName) =~ "${esc(det.user)}"
| project TimeGenerated, OperationName, Result, InitiatedBy, TargetResources, AdditionalDetails
| order by TimeGenerated asc`;

    case "OAUTH_CONSENT_GRANT":
      return `// OAuth consent — app: ${det.app}
// Ref: MITRE T1528 · Credential Access
AuditLogs
| where OperationName == "Consent to application"
| where TimeGenerated between (datetime('${dt(det.time)}') - 1d .. datetime('${dt(det.time)}') + 1d)
| mv-expand Target = TargetResources
| where tostring(Target.displayName) == "${esc(det.app)}"
| extend Permissions = tostring(Target.modifiedProperties)
| project TimeGenerated, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), App = tostring(Target.displayName), Permissions
// Remediate: Enterprise apps → [app] → Permissions → Revoke`;

    case "PRIVILEGED_ROLE_ASSIGNMENT":
      return `// Privileged role assignment — ${det.role} → ${det.user}
// Ref: MITRE T1098.003 · Privilege Escalation
AuditLogs
| where OperationName has "member to role"
| where TimeGenerated >= datetime('${dt(det.time)}') - 7d
| mv-expand Target = TargetResources
| extend Role = tostring(parse_json(tostring(Target.modifiedProperties))[1].newValue)
| project TimeGenerated, OperationName, Actor = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(Target.userPrincipalName), Role
| order by TimeGenerated desc`;

    case "APP_CREDENTIAL_ADDED":
      return `// New app credential — ${det.app}
// Ref: MITRE T1098.001 · Persistence
AuditLogs
| where OperationName has_any ("Certificates and secrets management", "Add service principal credentials")
| where TimeGenerated >= datetime('${dt(det.time)}') - 7d
| mv-expand Target = TargetResources
| project TimeGenerated, OperationName, Actor = tostring(InitiatedBy.user.userPrincipalName), App = tostring(Target.displayName)
| order by TimeGenerated desc
// Then check what the app did: AADServicePrincipalSignInLogs | where ServicePrincipalName == "${esc(det.app)}"`;

    default:
      return `// ${det.type.replace(/_/g, " ")}
SigninLogs
| where UserPrincipalName == "${esc(det.user || "")}"
${timeFilter}
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType
| order by TimeGenerated asc`;
  }
}

function showKQLPanel(detJson) {
  document.getElementById("kql-panel-overlay")?.remove();
  const det = JSON.parse(detJson);
  const kql = generateKQL(det);
  const mitre = MITRE_MAP[det.type];

  const overlay = document.createElement("div");
  overlay.id = "kql-panel-overlay";
  overlay.innerHTML = `
    <div id="kql-panel">
      <div class="kql-header">
        <div>
          <div class="kql-title">${det.type.replace(/_/g, " ")}</div>
          <div class="kql-subtitle">${mitre ? `ATT&CK ${mitre.id} · ${mitre.tactic}` : "KQL Query"}</div>
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
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeKQLPanel();
  });
  document.body.appendChild(overlay);
}

function closeKQLPanel() {
  document.getElementById("kql-panel-overlay")?.remove();
}

function copyKQL() {
  const code = document.getElementById("kql-code-block")?.textContent || "";
  navigator.clipboard.writeText(code).then(() => {
    const btn = document.getElementById("kql-copy-btn");
    if (btn) {
      btn.innerHTML = '<i class="bi bi-check-lg"></i> Copied!';
      setTimeout(() => {
        btn.innerHTML = '<i class="bi bi-clipboard"></i> Copy KQL';
      }, 2000);
    }
  });
}

/* ── Incident Summary Export ──────────────────────────────────────────────── */
function exportUserIncident(userPrincipal) {
  const data = state.analysisData;
  if (!data) return;

  const summary = (data.userSummaries || []).find(
    (s) => s.user === userPrincipal,
  );
  if (!summary) return;

  const events = data.events || [];
  const detections = data.detections || [];
  const homeCountry = data.homeCountry || "ID";
  const now = new Date().toLocaleString("en-GB", {
    dateStyle: "long",
    timeStyle: "short",
  });
  const ws = state.activeWorkspace;

  // User's detections (where they're the primary user or in affectedUsers)
  const userDets = detections.filter(
    (d) =>
      d.user === userPrincipal ||
      (d.affectedUsers && d.affectedUsers.includes(userPrincipal)),
  );

  // User's events
  const userEvents = events
    .filter((e) => e.userPrincipal === userPrincipal)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  // IOCs
  const iocIPs = [
    ...new Set(userEvents.map((e) => e.ipAddress).filter(Boolean)),
  ].slice(0, 20);
  const iocCountries = [
    ...new Set(
      userEvents
        .filter((e) => e.country !== homeCountry)
        .map((e) => e.country)
        .filter(Boolean),
    ),
  ];

  // MITRE tactics triggered
  const tacticsMap = {};
  for (const d of userDets) {
    const m = MITRE_MAP[d.type];
    if (!m) continue;
    if (!tacticsMap[m.tactic])
      tacticsMap[m.tactic] = { ids: new Set(), sev: "low" };
    tacticsMap[m.tactic].ids.add(m.id);
    if (d.severity === "high") tacticsMap[m.tactic].sev = "high";
    else if (d.severity === "medium" && tacticsMap[m.tactic].sev !== "high")
      tacticsMap[m.tactic].sev = "medium";
  }

  // Recommendations based on detection types
  const REC_MAP = {
    PASSWORD_SPRAY:
      "Block source IP at firewall/CA. Enable Microsoft Entra Smart Lockout. Review account lockout threshold.",
    BRUTE_FORCE:
      "Enable account lockout policy. Enforce MFA. Consider Conditional Access sign-in frequency limits.",
    CREDENTIAL_STUFFING:
      "Block source IP range. Enable leaked credential detection in Identity Protection. Enforce MFA.",
    MFA_EXHAUSTION:
      "Enable MFA number matching & additional context. Configure MFA fraud alert. Investigate MFA prompts for this user.",
    LEGACY_AUTH:
      "Create Conditional Access policy to block legacy authentication protocols (IMAP, POP3, SMTP Auth, EAS).",
    CA_GAP:
      "Expand Conditional Access policies to cover all interactive sign-ins. Enforce MFA for all locations.",
    TOKEN_REPLAY:
      "Revoke all active sessions via Entra ID. Enable Continuous Access Evaluation (CAE). Rotate refresh tokens.",
    IMPOSSIBLE_TRAVEL:
      "Review session for legitimacy. Enable Impossible Travel risk policy in Identity Protection.",
    CONCURRENT_SESSIONS:
      "Revoke sessions immediately. Investigate token theft. Enable Conditional Access token protection.",
    FOREIGN_LOGIN:
      "Verify with user if login is legitimate. Create location-based CA policy for trusted locations.",
    ADMIN_TOOL_ABUSE:
      "Require PIM/PAM activation for admin tools. Enable JIT access. Alert on PowerShell/CLI from untrusted locations.",
    ENUMERATION_ATTACK:
      "Enable Smart Lockout. Block source IP. Consider rate limiting on authentication endpoint.",
    SERVICE_PRINCIPAL_ANOMALY:
      "Audit service principal permissions. Rotate credentials. Check for unauthorized app registrations.",
    FIRST_SEEN_COUNTRY:
      "Verify with user. Add trusted countries to workspace or create location-based CA policy.",
    TIME_OF_DAY_ANOMALY:
      "Verify with user. Consider sign-in hour restrictions via CA policy or Identity Protection.",
    RARE_APP_ACCESS:
      "Audit OAuth app permissions. Verify consent was legitimate. Review app in Entra ID Enterprise Apps.",
    DEVICE_FINGERPRINT_ANOMALY:
      "Verify with user if new device is legitimate. Require device compliance via Intune/CA.",
    OAUTH_CONSENT_PHISHING:
      "Revoke consent for suspicious app in Entra ID. Audit OAuth permissions. Enable admin consent workflow.",
  };

  const uniqueRecKeys = [...new Set(userDets.map((d) => d.type))];
  const recs = uniqueRecKeys.map((t) => REC_MAP[t]).filter(Boolean);

  const riskColor = {
    CRITICAL: "#dc2626",
    HIGH: "#d97706",
    MEDIUM: "#2563eb",
    LOW: "#16a34a",
  };
  const sevColor = (s) =>
    s === "high" ? "#dc2626" : s === "medium" ? "#d97706" : "#2563eb";
  const esc = (str) =>
    String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

  const tacticPills = Object.entries(tacticsMap)
    .map(([tac, info]) => {
      const col = sevColor(info.sev);
      return `<span style="background:${col}20;border:1px solid ${col}60;color:${col};
      border-radius:4px;padding:3px 10px;font-size:10px;font-weight:700;white-space:nowrap">
      ${esc(tac)} (${[...info.ids].join(", ")})
    </span>`;
    })
    .join("");

  const detRows = userDets
    .map((d) => {
      const m = MITRE_MAP[d.type];
      return `<tr>
      <td><span style="background:${sevColor(d.severity)};color:#fff;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700">${esc(d.severity.toUpperCase())}</span></td>
      <td style="font-weight:600;font-size:11px">${esc(d.type.replace(/_/g, " "))}</td>
      <td>${m ? `<span style="background:#f3f0ff;border:1px solid #c4b5fd;color:#7c3aed;border-radius:3px;padding:1px 5px;font-size:9.5px;font-weight:700">${esc(m.id)}</span>` : "—"}</td>
      <td style="font-size:11px;color:#334155">${esc(d.message)}</td>
    </tr>`;
    })
    .join("");

  const evRows = userEvents
    .slice(0, 30)
    .map(
      (e) => `<tr>
    <td style="white-space:nowrap;font-size:10px;color:#64748b">${esc(new Date(e.createdAt).toLocaleString("en-GB", { dateStyle: "short", timeStyle: "short" }))}</td>
    <td style="font-family:monospace;font-size:10px">${esc(e.ipAddress)}</td>
    <td>${esc(e.country)}${e.city ? " / " + esc(e.city.slice(0, 16)) : ""}</td>
    <td style="font-size:11px">${esc(e.appName)}</td>
    <td style="text-align:center"><span style="font-size:11px;font-weight:700;color:${e.success ? "#16a34a" : "#dc2626"}">${e.success ? "✓" : "✗"}</span></td>
    <td style="font-size:10px;color:#64748b">${e.errorCode || ""}</td>
  </tr>`,
    )
    .join("");

  const iocIPRows = iocIPs
    .map(
      (ip) =>
        `<div style="font-family:monospace;font-size:11px;padding:4px 8px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:4px;margin-bottom:4px">${esc(ip)}</div>`,
    )
    .join("");

  const recRows = recs
    .map(
      (r, i) =>
        `<div style="display:flex;gap:10px;padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:11px">
      <span style="background:#2563eb;color:#fff;border-radius:50%;width:18px;height:18px;display:inline-flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;flex-shrink:0">${i + 1}</span>
      <span style="color:#334155;line-height:1.5">${esc(r)}</span>
    </div>`,
    )
    .join("");

  const rc = riskColor[summary.riskLevel] || "#2563eb";

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
      <div class="cs-item"><div class="lbl">Successful Foreign</div><div class="val" style="color:${summary.foreignSuccess > 0 ? "#f87171" : "#4ade80"}">${summary.foreignSuccess}</div></div>
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
    ${summary.narrative ? `<div style="background:#f8fafc;border-left:3px solid ${rc};padding:8px 12px;font-size:11px;color:#334155;line-height:1.6;border-radius:0 4px 4px 0">${esc(summary.narrative)}</div>` : ""}

    ${
      Object.keys(tacticsMap).length > 0
        ? `
    <h2>MITRE ATT&amp;CK Coverage</h2>
    <div class="tactic-pills">${tacticPills}</div>`
        : ""
    }

    ${
      userDets.length > 0
        ? `
    <h2>Detections (${userDets.length})</h2>
    <table>
      <thead><tr><th style="width:68px">Sev</th><th style="width:150px">Type</th><th style="width:90px">MITRE</th><th>Message</th></tr></thead>
      <tbody>${detRows}</tbody>
    </table>`
        : ""
    }

    ${
      recs.length > 0
        ? `
    <h2>Recommended Actions</h2>
    <div>${recRows}</div>`
        : ""
    }

    ${
      iocIPs.length > 0
        ? `
    <h2>IOC — Source IPs (${iocIPs.length})</h2>
    <div style="display:flex;flex-wrap:wrap;gap:6px">${iocIPRows}</div>`
        : ""
    }

    ${
      iocCountries.length > 0
        ? `
    <h2>IOC — Foreign Countries</h2>
    <div style="display:flex;flex-wrap:wrap;gap:6px">${iocCountries.map((c) => `<span style="background:#f1f5f9;border:1px solid #e2e8f0;padding:2px 8px;border-radius:4px;font-size:11px">${esc(c)}</span>`).join("")}</div>`
        : ""
    }

    ${
      userEvents.length > 0
        ? `
    <h2>Sign-in Log (last ${Math.min(30, userEvents.length)} events)</h2>
    <table>
      <thead><tr><th>Time</th><th>IP Address</th><th>Location</th><th>App</th><th>Status</th><th>Error</th></tr></thead>
      <tbody>${evRows}</tbody>
    </table>`
        : ""
    }

    <div style="margin-top:32px;padding-top:12px;border-top:1px solid #e2e8f0;display:flex;justify-content:space-between;font-size:9.5px;color:#94a3b8">
      <span>©2025 PT Sigma Cipta Caraka — Telkomsigma. All Rights Reserved.</span>
      <span>EIDSA · Developed by JoshuaDjuk · Workspace: ${esc(ws?.name || "")}</span>
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

/* ── Session Replay Export ────────────────────────────────────────────────── */
function exportSessionReplay(userPrincipal) {
  const data = state.analysisData;
  if (!data) return;

  const events = (data.events || [])
    .filter((e) => e.userPrincipal === userPrincipal)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));

  if (events.length === 0) {
    toast("No events for this user", "err");
    return;
  }

  const ws = state.activeWorkspace;
  const esc = (s) =>
    String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

  const lines = events
    .map((e) => {
      const dt = new Date(e.createdAt)
        .toLocaleString("en-GB", { dateStyle: "short", timeStyle: "medium" })
        .padEnd(20);
      const status = (e.success ? "SUCCESS" : "FAILED ").padEnd(8);
      const ip = (e.ipAddress || "—").padEnd(18);
      const loc = (
        (e.country || "") + (e.city ? "/" + e.city.slice(0, 14) : "")
      ).padEnd(24);
      const app = (e.appName || "—").slice(0, 28).padEnd(28);
      const auth = e.authMethod
        ? e.authMethod
            .replace("multiFactorAuthentication", "MFA")
            .replace("singleFactorAuthentication", "SFA")
        : "";
      const err = e.errorCode && e.errorCode !== 0 ? ` err:${e.errorCode}` : "";
      return `[${dt}] ${status} | ${ip} | ${loc} | ${app} | ${auth}${err}`;
    })
    .join("\n");

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
<pre>${lines
    .split("\n")
    .map((line) => {
      const isSuccess = line.includes("] SUCCESS ");
      const isFailed = line.includes("] FAILED  ");
      if (isSuccess) return `<span class="success">${esc(line)}</span>`;
      if (isFailed) return `<span class="failed">${esc(line)}</span>`;
      return esc(line);
    })
    .join("\n")}</pre>
<pre style="margin-top:16px;color:#6e7681;font-size:10px">Generated by EIDSA · Developed by JoshuaDjuk · PT Sigma Cipta Caraka — Telkomsigma · ${new Date().toLocaleString("en-GB")}</pre>
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

