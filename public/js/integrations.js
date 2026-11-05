/* ── Integrations: Microsoft Graph sync + alert webhook ───────────────────── */

const GRAPH_STREAMS = [
  ["interactive", "Interactive sign-ins"],
  ["nonInteractive", "Non-interactive sign-ins"],
  ["servicePrincipal", "Service principal sign-ins"],
  ["audit", "Directory audit logs"],
];

function openIntegrations() {
  const ws = state.activeWorkspace;
  const g = ws.graph || {};
  const a = ws.alerts || {};
  const streams = g.streams || ["interactive"];
  const last = g.lastSyncResult;

  showDialog(
    "Integrations",
    `
    <div class="section-label"><i class="bi bi-microsoft"></i> Microsoft Graph — automatic log pull</div>
    <p class="hint">App registration in the customer tenant with <b>application</b> permissions
      <code>AuditLog.Read.All</code> + <code>Directory.Read.All</code> (admin consent). Requires Entra ID P1/P2.</p>
    <div class="form-grid">
      <label>Tenant ID / domain<input id="ig-tenant" value="${escHtml(g.tenantId || ws.tenant || "")}" placeholder="contoso.onmicrosoft.com" /></label>
      <label>Client (app) ID<input id="ig-client" value="${escHtml(g.clientId || "")}" placeholder="00000000-0000-…" /></label>
      <label>Client secret
        <input id="ig-secret" type="password" autocomplete="new-password" placeholder="${g.hasSecret ? "•••••••• stored — leave empty to keep" : "secret value"}" />
      </label>
      <label>First sync range (days)<input id="ig-days" type="number" min="1" max="30" value="${g.days || 7}" /></label>
      <label>Auto-sync every (hours, 0 = off)<input id="ig-auto" type="number" min="0" max="168" value="${g.autoSyncHours || 0}" /></label>
      <label>Keep pulled files (days)<input id="ig-retention" type="number" min="1" max="365" value="${g.retentionDays || 30}" /></label>
    </div>
    <div class="check-row">
      ${GRAPH_STREAMS.map(([k, label]) => `<label class="check"><input type="checkbox" class="ig-stream" value="${k}" ${streams.includes(k) ? "checked" : ""} /> ${label}</label>`).join("")}
    </div>
    ${last ? `<div class="hint" style="margin-top:6px">Last sync: ${g.lastSync ? formatDate(g.lastSync) : ""} ${last.ok ? `— ${last.results.map((r) => `${r.stream}: ${r.count.toLocaleString()}`).join(", ")}` : `<span style="color:var(--danger)">failed: ${escHtml(last.error || "")}</span>`}</div>` : ""}
    <div class="inline-actions">
      <button class="btn-secondary btn-xs" onclick="testGraphConnection()"><i class="bi bi-plug"></i> Save & test connection</button>
      ${g.hasSecret ? `<button class="btn-secondary btn-xs" onclick="saveIntegrations({ graph: { clearSecret: true } })">Remove secret</button>` : ""}
    </div>

    <div class="section-label" style="margin-top:18px"><i class="bi bi-bell"></i> Alert webhook</div>
    <p class="hint">After each analysis, new detections at or above the chosen severity are posted once (deduplicated).</p>
    <div class="form-grid">
      <label>Format
        <select id="al-format">
          ${[["teams", "Microsoft Teams (Workflows)"], ["slack", "Slack"], ["generic", "Generic JSON"]].map(([v, l]) => `<option value="${v}" ${(a.format || "teams") === v ? "selected" : ""}>${l}</option>`).join("")}
        </select>
      </label>
      <label>Minimum severity
        <select id="al-sev">
          <option value="high" ${(a.minSeverity || "high") === "high" ? "selected" : ""}>High</option>
          <option value="medium" ${a.minSeverity === "medium" ? "selected" : ""}>Medium + High</option>
        </select>
      </label>
      <label style="grid-column:1/-1">Webhook URL (https)
        <input id="al-url" type="password" autocomplete="off" placeholder="${a.hasWebhook ? "•••••••• stored — leave empty to keep" : "https://…"}" />
      </label>
    </div>
    <label class="check"><input type="checkbox" id="al-enabled" ${a.enabled ? "checked" : ""} /> Send alerts</label>
    ${a.lastAlert ? `<div class="hint">Last alert: ${formatDate(new Date(a.lastAlert.ts).toISOString())} (${a.lastAlert.count})</div>` : ""}
    <div class="inline-actions">
      <button class="btn-secondary btn-xs" onclick="testAlertWebhook()"><i class="bi bi-send"></i> Save & send test</button>
      ${a.hasWebhook ? `<button class="btn-secondary btn-xs" onclick="saveIntegrations({ alerts: { clearWebhook: true, enabled: false } })">Remove webhook</button>` : ""}
    </div>

    <div class="modal-actions">
      <button class="btn-secondary" onclick="closeDialog()">Cancel</button>
      <button class="btn-primary" onclick="saveIntegrations().then((ok) => ok && closeDialog())">Save</button>
    </div>`,
    { wide: true },
  );
}

function readIntegrationForm() {
  return {
    graph: {
      tenantId: document.getElementById("ig-tenant").value.trim(),
      clientId: document.getElementById("ig-client").value.trim(),
      clientSecret: document.getElementById("ig-secret").value,
      days: document.getElementById("ig-days").value,
      autoSyncHours: document.getElementById("ig-auto").value,
      retentionDays: document.getElementById("ig-retention").value,
      streams: [...document.querySelectorAll(".ig-stream:checked")].map((c) => c.value),
    },
    alerts: {
      enabled: document.getElementById("al-enabled").checked,
      format: document.getElementById("al-format").value,
      minSeverity: document.getElementById("al-sev").value,
      webhookUrl: document.getElementById("al-url").value.trim(),
    },
  };
}

// overrides: partial body merged over the form (e.g. clear a secret)
async function saveIntegrations(overrides) {
  const body = readIntegrationForm();
  if (overrides?.graph) Object.assign(body.graph, overrides.graph);
  if (overrides?.alerts) Object.assign(body.alerts, overrides.alerts);
  try {
    const meta = await api("PUT", `/api/workspaces/${state.activeWorkspace.id}/integrations`, body);
    Object.assign(state.activeWorkspace, { graph: meta.graph, alerts: meta.alerts });
    renderWorkspaceViewKeepResults();
    if (overrides) openIntegrations();
    toast("Integrations saved");
    return true;
  } catch (e) {
    toast(escHtml(e.message), "err");
    return false;
  }
}

async function testGraphConnection() {
  if (!(await saveIntegrations())) return;
  try {
    await api("POST", `/api/workspaces/${state.activeWorkspace.id}/graph/test`);
    toast('<i class="bi bi-check-circle-fill"></i> Graph connection OK — sign-in logs readable');
  } catch (e) {
    toast(`Graph test failed: ${escHtml(e.message)}`, "err");
  }
}

async function testAlertWebhook() {
  if (!(await saveIntegrations())) return;
  try {
    await api("POST", `/api/workspaces/${state.activeWorkspace.id}/alerts/test`);
    toast('<i class="bi bi-check-circle-fill"></i> Test alert sent');
  } catch (e) {
    toast(`Webhook test failed: ${escHtml(e.message)}`, "err");
  }
}

// Re-render the header/sections without losing the analysis results on screen
function renderWorkspaceViewKeepResults() {
  const results = document.getElementById("analysis-results");
  const keep = results ? [...results.childNodes] : [];
  renderWorkspaceView();
  const fresh = document.getElementById("analysis-results");
  keep.forEach((n) => fresh.appendChild(n));
  if (state.analysisData) {
    ["btn-export-pdf", "btn-exec-summary", "btn-weekly-digest", "btn-set-baseline", "btn-ioc-search"].forEach((id) => {
      const b = document.getElementById(id);
      if (b) b.style.display = "";
    });
  }
}

/* ── Graph sync ───────────────────────────────────────────────────────────── */
async function startGraphSync() {
  const wsId = state.activeWorkspace.id;
  const btn = document.getElementById("btn-graph-sync");
  try {
    await api("POST", `/api/workspaces/${wsId}/graph/sync`, { analyze: true });
  } catch (e) {
    toast(escHtml(e.message), "err");
    return;
  }
  if (btn) btn.disabled = true;

  // Poll job status until done
  for (;;) {
    await new Promise((r) => setTimeout(r, 2000));
    let job;
    try {
      job = await api("GET", `/api/workspaces/${wsId}/graph/sync`);
    } catch (e) {
      break;
    }
    const b = document.getElementById("btn-graph-sync");
    const pulled = Object.values(job.progress || {}).reduce((a, n) => a + n, 0);
    if (b) b.innerHTML = job.status === "analyzing"
      ? '<i class="bi bi-hourglass-split"></i> Analyzing…'
      : `<i class="bi bi-cloud-arrow-down"></i> ${pulled.toLocaleString()} pulled…`;
    if (job.status === "running" || job.status === "analyzing") continue;

    if (job.status === "error") {
      toast(`Graph sync failed: ${escHtml(job.error)}`, "err");
    } else {
      const total = (job.results || []).reduce((a, r) => a + r.count, 0);
      toast(`<i class="bi bi-check-circle-fill"></i> Synced ${total.toLocaleString()} new events from Microsoft Graph`);
    }
    if (state.activeWorkspace?.id === wsId) {
      await selectWorkspace(wsId);
      if (job.status === "done") runAnalysis(); // served from the server cache the sync just built
    }
    break;
  }
}
