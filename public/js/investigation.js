/* ── Timeline panel ───────────────────────────────────────────────────────── */
function openTimeline(userPrincipal, page = 1) {
  if (!state.analysisData) return;
  state.timelineUser = userPrincipal;
  state.timelinePage = page;

  const events = state.analysisData.events || [];
  const detections = state.analysisData.detections || [];
  const homeCountry = (state.analysisData.homeCountry || "ID").toUpperCase();

  const userEvents = events
    .filter((e) => e.userPrincipal === userPrincipal)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));

  if (userEvents.length === 0) return;

  // Build a set of event timestamps that are flagged by a detection
  const flaggedTimes = new Set();
  for (const d of detections) {
    if (d.user !== userPrincipal) continue;
    if (d.time) flaggedTimes.add(d.time);
    if (d.from?.time) flaggedTimes.add(d.from.time);
    if (d.to?.time) flaggedTimes.add(d.to.time);
  }

  const totalEvents = userEvents.length;
  const failedEvents = userEvents.filter((e) => !e.success).length;
  const countries = [
    ...new Set(userEvents.map((e) => e.country).filter(Boolean)),
  ];
  const foreignCount = userEvents.filter(
    (e) => e.success && e.country && e.country.toUpperCase() !== homeCountry,
  ).length;

  // Pagination
  const pageSize = state.timelinePageSize;
  const pages = Math.max(1, Math.ceil(userEvents.length / pageSize));
  const curPage = Math.min(Math.max(page, 1), pages);
  const pageStart = (curPage - 1) * pageSize;
  const pageEvents = userEvents.slice(pageStart, pageStart + pageSize);

  const items = pageEvents
    .map((e) => {
      const isForeign = e.country && e.country.toUpperCase() !== homeCountry;
      const isFlagged = flaggedTimes.has(e.createdAt);
      const dotClass = !e.success
        ? "fail"
        : isFlagged || isForeign
          ? "foreign"
          : "";

      const flags = [];
      if (!e.success) flags.push(`<span class="tl-flag flag-fail">FAIL</span>`);
      if (isForeign)
        flags.push(`<span class="tl-flag flag-foreign">FOREIGN</span>`);
      if (isFlagged)
        flags.push(`<span class="tl-flag flag-det">DETECTED</span>`);
      if (e.appType === "Admin")
        flags.push(`<span class="tl-flag flag-admin">ADMIN TOOL</span>`);
      if (e.appType === "Legacy")
        flags.push(`<span class="tl-flag flag-legacy">LEGACY AUTH</span>`);
      if (e.appType === "Non-Interactive")
        flags.push(
          `<span class="tl-flag" style="background:rgba(100,116,139,0.2);color:#94a3b8;border:1px solid rgba(100,116,139,0.3)">NON-INTERACTIVE</span>`,
        );

      return `
      <div class="tl-item">
        <div class="tl-line-wrap"><div class="tl-dot ${dotClass}"></div></div>
        <div class="tl-content">
          <div class="tl-time">${formatDate(e.createdAt)}</div>
          <div class="tl-row">
            <span class="${e.success ? "tl-status-ok" : "tl-status-fail"}">${e.success ? '<i class="bi bi-check-lg"></i> Success' : '<i class="bi bi-x-lg"></i> Failed'}</span>
            ${e.country ? `<span><i class="bi bi-geo-alt-fill"></i> ${escHtml(e.country)}${e.city ? " / " + escHtml(e.city) : ""}</span>` : ""}
            ${e.ipAddress ? `<span style="color:var(--text2)">${renderIPClickable(e.ipAddress)}</span>` : ""}
            ${flags.join("")}
          </div>
          <div class="tl-note">${escHtml(e.appName || "")}${e.appType ? " · " + e.appType : ""}${e.resourceName && e.resourceName !== e.appName ? " → " + escHtml(e.resourceName) : ""}${e.failureReason ? " · " + e.failureReason : ""}${e.userAgent && e.signInType === "nonInteractive" ? " · " + escHtml(e.userAgent.slice(0, 60)) : ""}</div>
        </div>
      </div>`;
    })
    .join("");

  const paginationHtml =
    pages > 1
      ? `
    <div class="tl-pagination">
      <button onclick="openTimeline('${escHtml(userPrincipal)}', ${curPage - 1})" ${curPage === 1 ? "disabled" : ""}>← Prev</button>
      <span>Page ${curPage} of ${pages} · ${totalEvents} events</span>
      <button onclick="openTimeline('${escHtml(userPrincipal)}', ${curPage + 1})" ${curPage === pages ? "disabled" : ""}>Next →</button>
    </div>`
      : "";

  // Re-use existing overlay if open (page navigation), else create new
  let overlay = document.getElementById("timeline-overlay");
  const isNew = !overlay;
  if (isNew) {
    overlay = document.createElement("div");
    overlay.id = "timeline-overlay";
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) closeTimeline();
    });
  }

  // Detections for this user
  const userDets = detections.filter(
    (d) =>
      d.user === userPrincipal ||
      (d.affectedUsers && d.affectedUsers.includes(userPrincipal)),
  );
  const detBadges = userDets
    .map(
      (d) => `
    <div class="tl-det-badge sev-${d.severity}">
      <span class="det-badge badge-${d.severity}">${d.severity}</span>
      <span>${escHtml(d.type.replace(/_/g, " "))}</span>
      <span class="tl-det-msg">${escHtml(d.message)}</span>
    </div>`,
    )
    .join("");

  overlay.innerHTML = `
    <div id="timeline-panel">
      <div class="timeline-header">
        <div>
          <h3>User Timeline</h3>
          <div class="tl-user">${escHtml(userPrincipal)}</div>
        </div>
        <div style="display:flex;align-items:center;gap:6px;flex-shrink:0">
          <button class="btn-secondary" style="font-size:11px;padding:3px 10px" onclick="exportSessionReplay('${escHtml(userPrincipal)}')"><i class="bi bi-clipboard"></i> Export Log</button>
          <button class="timeline-close" onclick="closeTimeline()"><i class="bi bi-x-lg"></i></button>
        </div>
      </div>
      <div class="timeline-body">
        <div class="tl-stats">
          <div class="tl-stat"><strong>${totalEvents}</strong><span>Total</span></div>
          <div class="tl-stat"><strong>${failedEvents}</strong><span>Failed</span></div>
          <div class="tl-stat"><strong>${foreignCount}</strong><span>Foreign</span></div>
          <div class="tl-stat"><strong>${countries.length}</strong><span>Countries</span></div>
        </div>
        ${detBadges ? `<div class="tl-dets-section">${detBadges}</div>` : ""}
        ${items}
      </div>
      ${paginationHtml}
      <div class="tl-notes-section">
        <div class="tl-notes-label"><i class="bi bi-journal-text"></i> Investigation Notes</div>
        <textarea id="tl-note-input" class="tl-note-textarea" placeholder="Write investigation notes for this user…" rows="3">${escHtml(state.userNotes[userPrincipal] || "")}</textarea>
        <div class="tl-notes-footer">
          <button class="btn-secondary" style="font-size:12px;padding:4px 12px" onclick="saveUserNote('${escHtml(userPrincipal)}')">Save Note</button>
          ${state.userNotes[userPrincipal] ? `<span class="tl-note-saved"><i class="bi bi-check-lg"></i> Note saved</span>` : ""}
        </div>
      </div>
    </div>`;

  if (isNew) document.body.appendChild(overlay);
}

function closeTimeline() {
  document.getElementById("timeline-overlay")?.remove();
  state.timelineUser = null;
  state.timelinePage = 1;
}

async function saveUserNote(userPrincipal) {
  const wsId = state.activeWorkspace?.id;
  if (!wsId) return;
  const note = document.getElementById("tl-note-input")?.value || "";
  try {
    await api("POST", `/api/workspaces/${wsId}/notes`, {
      user: userPrincipal,
      note,
    });
    if (note.trim()) state.userNotes[userPrincipal] = note.trim();
    else delete state.userNotes[userPrincipal];
    const footer = document.querySelector(".tl-notes-footer");
    if (footer) {
      let saved = footer.querySelector(".tl-note-saved");
      if (!saved) {
        saved = document.createElement("span");
        saved.className = "tl-note-saved";
        footer.appendChild(saved);
      }
      saved.innerHTML = note.trim()
        ? '<i class="bi bi-check-lg"></i> Note saved'
        : "";
    }
    toast("Note saved");
  } catch (e) {
    toast("Failed to save note", "err");
  }
}

/* ── Bulk Triage ───────────────────────────────────────────────────────────── */
function bulkToggle(key) {
  if (state.bulkSelected.has(key)) state.bulkSelected.delete(key);
  else state.bulkSelected.add(key);
  rerenderDetections();
}

async function bulkTriage(status) {
  const wsId = state.activeWorkspace?.id;
  if (!wsId || state.bulkSelected.size === 0) return;
  const triages = [...state.bulkSelected].map((key) => ({ key, status }));
  try {
    const result = await api("POST", `/api/workspaces/${wsId}/triage/bulk`, {
      triages,
    });
    state.triages = result.triages || state.triages;
    state.bulkSelected = new Set();
    rerenderDetections();
    toast(`${triages.length} detection(s) marked ${status}`);
  } catch (e) {
    toast("Bulk triage failed", "err");
  }
}

function clearBulkSelection() {
  state.bulkSelected = new Set();
  rerenderDetections();
}

/* ── Detection Comments ────────────────────────────────────────────────────── */
function toggleDetComment(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle("open");
  if (el.classList.contains("open")) el.querySelector("textarea")?.focus();
}

async function saveDetectionComment(key, textareaId) {
  const wsId = state.activeWorkspace?.id;
  if (!wsId) return;
  const comment = document.getElementById(textareaId)?.value || "";
  try {
    await api("POST", `/api/workspaces/${wsId}/comments`, { key, comment });
    if (comment.trim()) state.detectionComments[key] = comment.trim();
    else delete state.detectionComments[key];
    rerenderDetections();
    toast("Comment saved");
  } catch (e) {
    toast("Failed to save comment", "err");
  }
}

/* ── Watch List ────────────────────────────────────────────────────────────── */
async function toggleWatchList(user) {
  const wsId = state.activeWorkspace?.id;
  if (!wsId) return;
  try {
    const result = await api("POST", `/api/workspaces/${wsId}/watchlist`, {
      user,
    });
    state.watchList = new Set(result.watchList || []);
    // Re-render dashboard to reorder cards
    const dashEl = document.getElementById("tab-dashboard");
    if (dashEl) dashEl.innerHTML = renderDashboard(state.analysisData);
    toast(
      state.watchList.has(user)
        ? '<i class="bi bi-star-fill"></i> Added to Watch List'
        : '<i class="bi bi-star"></i> Removed from Watch List',
    );
  } catch (e) {
    toast("Failed to update Watch List", "err");
  }
}

