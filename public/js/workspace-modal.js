/* ── Workspace modal ──────────────────────────────────────────────────────── */
/* ── Trusted countries tag input ──────────────────────────────────────────── */
function getTrustedTags() {
  return [...document.querySelectorAll("#trusted-tags .tag-chip")].map(
    (el) => el.dataset.code,
  );
}

function renderTrustedTags(codes) {
  const wrap = document.getElementById("trusted-tags");
  const input = document.getElementById("trusted-input");
  // Remove existing chips (keep input)
  wrap.querySelectorAll(".tag-chip").forEach((el) => el.remove());
  for (const code of codes) {
    const chip = document.createElement("span");
    chip.className = "tag-chip";
    chip.dataset.code = code;
    chip.innerHTML = `${escHtml(code)}<button type="button" onclick="removeTag('${escHtml(code)}')" title="Remove">×</button>`;
    wrap.insertBefore(chip, input);
  }
}

function handleTagInput(e) {
  const input = e.target;
  if ((e.key === "Enter" || e.key === ",") && input.value.trim()) {
    e.preventDefault();
    const code = input.value.trim().toUpperCase().slice(0, 2);
    if (code.length === 2) {
      const existing = getTrustedTags();
      if (!existing.includes(code)) renderTrustedTags([...existing, code]);
    }
    input.value = "";
  } else if (e.key === "Backspace" && !input.value) {
    const tags = getTrustedTags();
    if (tags.length) renderTrustedTags(tags.slice(0, -1));
  }
}

function removeTag(code) {
  renderTrustedTags(getTrustedTags().filter((c) => c !== code));
}

function setTuningFields(t = {}) {
  document.getElementById("tune-spray-window").value = t.sprayWindowMin ?? 10;
  document.getElementById("tune-spray-users").value = t.sprayMinUsers ?? 5;
  document.getElementById("tune-brute-attempts").value =
    t.bruteMinAttempts ?? 10;
  document.getElementById("tune-mfa-prompts").value = t.mfaMinPrompts ?? 5;
  document.getElementById("tune-enum-users").value = t.enumMinUsers ?? 10;
  document.getElementById("tune-travel-speed").value = t.travelMaxSpeedKmh ?? 900;
}

function fillTimezoneList() {
  const dl = document.getElementById("tz-list");
  if (!dl || dl.childElementCount) return;
  const zones = Intl.supportedValuesOf ? Intl.supportedValuesOf("timeZone") : [];
  dl.innerHTML = ["UTC", ...zones].map((z) => `<option value="${z}"></option>`).join("");
}

function getTuningFields() {
  return {
    sprayWindowMin:
      parseInt(document.getElementById("tune-spray-window").value) || 10,
    sprayMinUsers:
      parseInt(document.getElementById("tune-spray-users").value) || 5,
    bruteMinAttempts:
      parseInt(document.getElementById("tune-brute-attempts").value) || 10,
    mfaMinPrompts:
      parseInt(document.getElementById("tune-mfa-prompts").value) || 5,
    enumMinUsers:
      parseInt(document.getElementById("tune-enum-users").value) || 10,
    travelMaxSpeedKmh:
      parseInt(document.getElementById("tune-travel-speed").value) || 900,
  };
}

function ensureBreachListField() {
  if (document.getElementById("ws-breachlist")) return;
  const modal = document.querySelector(".modal");
  const actions = modal.querySelector(".modal-actions");
  const label = document.createElement("label");
  label.textContent = "Breach List";
  label.style.cssText = "display:block;margin-top:8px";
  const hint = document.createElement("span");
  hint.style.cssText = "font-weight:400;color:var(--text3)";
  hint.textContent =
    " (one email per line — users found here trigger a breach alert)";
  label.appendChild(hint);
  const ta = document.createElement("textarea");
  ta.id = "ws-breachlist";
  ta.rows = 3;
  ta.placeholder = "user@contoso.com\nother@domain.com";
  ta.style.cssText =
    "font-family:monospace;font-size:12px;resize:vertical;width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:9px 12px;border-radius:var(--radius-sm);font-size:13px;font-family:inherit;outline:none;transition:border-color 0.15s;margin-top:4px";
  modal.insertBefore(label, actions);
  modal.insertBefore(ta, actions);
}

function showNewWorkspaceModal() {
  state.editingWorkspace = null;
  document.getElementById("modal-title").textContent = "New Workspace";
  document.getElementById("ws-name").value = "";
  document.getElementById("ws-tenant").value = "";
  document.getElementById("ws-homecountry").value = "ID";
  document.getElementById("ws-timezone").value = "";
  fillTimezoneList();
  document.getElementById("ws-playbook").value = "";
  document.getElementById("ws-trustedips").value = "";
  document.getElementById("tuning-details").removeAttribute("open");
  setTuningFields();
  renderTrustedTags([]);
  ensureBreachListField();
  document.getElementById("ws-breachlist").value = "";
  document.querySelector(".modal .btn-primary").textContent = "Create";
  document.querySelector(".modal .btn-primary").onclick = submitWorkspace;
  document.getElementById("modal-overlay").classList.remove("hidden");
  setTimeout(() => document.getElementById("ws-name").focus(), 50);
}

function editWorkspaceModal() {
  const ws = state.activeWorkspace;
  state.editingWorkspace = ws.id;
  document.getElementById("modal-title").textContent = "Edit Workspace";
  document.getElementById("ws-name").value = ws.name;
  document.getElementById("ws-tenant").value = ws.tenant || "";
  document.getElementById("ws-homecountry").value = ws.homeCountry || "ID";
  document.getElementById("ws-timezone").value = ws.timezone || "";
  fillTimezoneList();
  document.getElementById("ws-playbook").value = ws.playbook || "";
  document.getElementById("ws-trustedips").value = (ws.trustedIPs || []).join(
    "\n",
  );
  setTuningFields(ws.ruleThresholds || {});
  if (ws.ruleThresholds)
    document.getElementById("tuning-details").setAttribute("open", "");
  renderTrustedTags(ws.trustedCountries || []);
  ensureBreachListField();
  document.getElementById("ws-breachlist").value =
    ws.breachList?.join("\n") || "";
  document.querySelector(".modal .btn-primary").textContent = "Save";
  document.querySelector(".modal .btn-primary").onclick = submitWorkspace;
  document.getElementById("modal-overlay").classList.remove("hidden");
}

function closeModal() {
  document.getElementById("modal-overlay").classList.add("hidden");
}

async function submitWorkspace() {
  const name = document.getElementById("ws-name").value.trim();
  const tenant = document.getElementById("ws-tenant").value.trim();
  const homeCountry =
    document.getElementById("ws-homecountry").value.trim().toUpperCase() ||
    "ID";
  const playbook = document.getElementById("ws-playbook").value.trim();
  const timezone = document.getElementById("ws-timezone").value.trim() || undefined;
  const trustedCountries = getTrustedTags();
  const trustedIPs = document
    .getElementById("ws-trustedips")
    .value.split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
  const breachList = (document.getElementById("ws-breachlist")?.value || "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  const ruleThresholds = getTuningFields();
  if (!name) {
    document.getElementById("ws-name").focus();
    return;
  }

  try {
    if (state.editingWorkspace) {
      await api("PATCH", `/api/workspaces/${state.editingWorkspace}`, {
        name,
        tenant,
        homeCountry,
        playbook,
        timezone,
        trustedCountries,
        trustedIPs,
        breachList,
        ruleThresholds,
      });
      toast("Workspace updated");
      await loadWorkspaces();
      await selectWorkspace(state.editingWorkspace);
    } else {
      const ws = await api("POST", "/api/workspaces", {
        name,
        tenant,
        homeCountry,
        playbook,
        timezone,
        trustedCountries,
        trustedIPs,
        breachList,
        ruleThresholds,
      });
      toast("Workspace created");
      await loadWorkspaces();
      await selectWorkspace(ws.id);
    }
    closeModal();
  } catch (e) {
    toast(e.message, "err");
  }
}

async function deleteWorkspace() {
  if (
    !confirm(
      `Delete workspace "${state.activeWorkspace.name}" and all its files?`,
    )
  )
    return;
  try {
    await api("DELETE", `/api/workspaces/${state.activeWorkspace.id}`);
    toast("Workspace deleted");
    state.activeWorkspace = null;
    if (state.leafletMap) {
      state.leafletMap.remove();
      state.leafletMap = null;
    }
    destroyCharts();
    await loadWorkspaces();
    document.getElementById("welcome").classList.remove("hidden");
    document.getElementById("workspace-view").classList.add("hidden");
  } catch (e) {
    toast(e.message, "err");
  }
}

/* ── Background event loader ─────────────────────────────────────────────── */
async function bgLoadEvents(wsId, total) {
  console.log(
    `[bgLoadEvents] Starting: wsId=${wsId}, total=${total}, current=${(state.analysisData?.events || []).length}`,
  );
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
      if (state.activeTab === "events") rerenderTable();
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
      const res = await api(
        "GET",
        `/api/workspaces/${wsId}/events?offset=${offset}&limit=${BATCH}`,
      );
      console.log(
        `[bgLoadEvents] Batch offset=${offset}: got ${res.events?.length || 0} events`,
      );
      if (!res.events?.length) {
        console.warn(
          `[bgLoadEvents] Empty response at offset ${offset}, breaking`,
        );
        break;
      }
      if (state.activeWorkspace?.id !== wsId || !state.analysisData) return;
      state.analysisData.events = [
        ...(state.analysisData.events || []),
        ...res.events,
      ];
      offset += res.events.length;
      state.eventsLoading = { loaded: offset, total };
      updateSidebarProgress();
      if (state.activeTab === "events") rerenderTable();
    } catch (e) {
      console.error(`[bgLoadEvents] Error at offset ${offset}:`, e.message);
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
  console.log(
    `[bgLoadEvents] Done: loaded ${state.analysisData?.events?.length || 0} total events`,
  );
}

function updateSidebarProgress() {
  const item = document.querySelector(".ws-item.active");
  if (!item) return;
  let bar = item.querySelector(".ws-load-bar");
  if (!state.eventsLoading) {
    if (bar) bar.remove();
    return;
  }
  const pct = Math.round(
    (state.eventsLoading.loaded / state.eventsLoading.total) * 100,
  );
  if (!bar) {
    bar = document.createElement("div");
    bar.className = "ws-load-bar";
    item.appendChild(bar);
  }
  bar.innerHTML = `<div class="ws-load-bar-fill" style="width:${pct}%"></div>`;
}

function updateEventsProgress(loaded, total) {
  const el = document.getElementById("events-load-progress");
  if (!el) return;
  if (loaded === null) {
    el.style.display = "none";
    return;
  }
  el.style.display = "";
  el.textContent = `Loading events… ${loaded.toLocaleString()} / ${total.toLocaleString()}`;
}

/* ── Cross-workspace IP correlation ──────────────────────────────────────── */
function renderCorrelationPanel() {
  const corr = state.correlationData;
  if (!corr || corr.correlations.length === 0) return;
  // Insert above the stats grid if not already there
  const container = document.getElementById("analysis-results");
  if (!container || document.getElementById("corr-panel")) return;
  const div = document.createElement("div");
  div.id = "corr-panel";
  div.innerHTML = `
    <div class="corr-panel">
      <div class="corr-panel-header">
        <i class="bi bi-link-45deg"></i> Cross-workspace IP Correlation
        <span style="color:var(--danger)">${corr.correlations.length} workspace(s) share attacking IPs</span>
      </div>
      ${corr.correlations
        .map(
          (c) => `
        <div class="corr-item">
          <span class="corr-ws-name">${escHtml(c.workspaceName)}</span>
          <span class="corr-count">${c.sharedCount} shared IP${c.sharedCount > 1 ? "s" : ""}</span>
          <span class="corr-ips">${c.sharedIPs.slice(0, 3).join(", ")}${c.sharedIPs.length > 3 ? ` +${c.sharedIPs.length - 3} more` : ""}</span>
        </div>`,
        )
        .join("")}
    </div>`;
  // Insert before first child of analysis-results
  const statsGrid = container.querySelector(".stats-grid");
  if (statsGrid) container.insertBefore(div, statsGrid);
  else container.insertBefore(div, container.firstChild);
}

