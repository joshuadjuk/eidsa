/* ── IndexedDB events cache ─────────────────────────────────────────────────
   Stores full sorted events arrays keyed by "wsId:filesSig".
   Survives page refresh; cleared automatically when files change (new sig).  */
const idb = (() => {
  let _db = null;
  function open() {
    return new Promise((res, rej) => {
      if (_db) return res(_db);
      const req = indexedDB.open("eidsa_events", 1);
      req.onupgradeneeded = (e) => e.target.result.createObjectStore("ev");
      req.onsuccess = (e) => {
        _db = e.target.result;
        res(_db);
      };
      req.onerror = (e) => rej(e.target.error);
    });
  }
  const tx = (mode, fn) =>
    open()
      .then(
        (db) =>
          new Promise((res, rej) => {
            const t = db.transaction("ev", mode);
            const r = fn(t.objectStore("ev"));
            r.onsuccess = () => res(r.result);
            r.onerror = () => res(null);
          }),
      )
      .catch(() => null);
  return {
    get: (key) => tx("readonly", (s) => s.get(key)),
    set: (key, val) => tx("readwrite", (s) => s.put(val, key)),
    del: (key) => tx("readwrite", (s) => s.delete(key)),
  };
})();

/* ── State ────────────────────────────────────────────────────────────────── */
const state = {
  workspaces: [],
  activeWorkspace: null,
  analysisData: null,
  eventsPage: 1,
  eventsPageSize: 50,
  eventsFilter: "",
  eventsStatusFilter: "all",
  eventsSort: { col: "createdAt", dir: "desc" },
  editingWorkspace: null,
  activeTab: "events",
  leafletMap: null,
  chartInstances: {},
  timelinePage: 1,
  timelinePageSize: 50,
  timelineUser: null,
  dateFrom: "",
  dateTo: "",
  correlationData: null,
  triages: {},
  userNotes: {},
  killChainFilter: null,
  detectionsPage: 1,
  detectionsPageSize: 30,
  detectionsFilter: "",
  detectionsSevFilter: "all",
  watchList: new Set(),
  detectionComments: {},
  bulkSelected: new Set(),
  rnavOpenGroups: new Set(["accounts"]),
  eventsLoading: null, // { loaded, total } while bgLoadEvents is running, null when idle
  currentUser: null, // { username, role } — set by initAuth()
  authEnabled: true,
};

// Role helpers — the server enforces these; the UI only hides what can't be used
const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2 };
function hasRole(role) {
  return (ROLE_RANK[state.currentUser?.role] ?? -1) >= ROLE_RANK[role];
}

/* ── API helpers ──────────────────────────────────────────────────────────── */
async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body instanceof FormData) {
    opts.body = body;
  } else if (body) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    location.href = "/login.html";
    throw new Error("Session expired — please sign in again");
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

/* ── Toast ────────────────────────────────────────────────────────────────── */
function toast(msg, type = "ok") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.innerHTML = msg;
  document.body.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    setTimeout(() => el.remove(), 300);
  }, 3000);
}

