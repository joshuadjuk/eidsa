/* ── Generic dialog ───────────────────────────────────────────────────────── */
function showDialog(title, bodyHtml, { wide = false } = {}) {
  closeDialog();
  const overlay = document.createElement("div");
  overlay.id = "dialog-overlay";
  overlay.className = "dialog-overlay";
  overlay.onclick = (e) => {
    if (e.target === overlay) closeDialog();
  };
  overlay.innerHTML = `
    <div class="modal dialog ${wide ? "dialog-wide" : ""}">
      <div class="modal-header">
        <h3>${escHtml(title)}</h3>
        <button class="dialog-close" onclick="closeDialog()" title="Close"><i class="bi bi-x-lg"></i></button>
      </div>
      <div class="dialog-body">${bodyHtml}</div>
    </div>`;
  document.body.appendChild(overlay);
  return overlay;
}

function closeDialog() {
  document.getElementById("dialog-overlay")?.remove();
}

/* ── Auth ─────────────────────────────────────────────────────────────────── */
// Returns false when the browser is being redirected to the login page
async function initAuth() {
  let status;
  try {
    status = await fetch("/api/auth/status").then((r) => r.json());
  } catch (e) {
    toast("Cannot reach EIDSA server", "err");
    return false;
  }
  state.authEnabled = status.enabled;
  if (status.enabled && !status.user) {
    location.href = "/login.html";
    return false;
  }
  state.currentUser = status.user;
  document.body.classList.add(`role-${status.user.role}`);
  renderUserBox();
  return true;
}

function renderUserBox() {
  const el = document.getElementById("user-box");
  if (!el || !state.currentUser) return;
  const u = state.currentUser;
  if (!state.authEnabled) {
    el.innerHTML = `<div class="user-box-warn" title="Set EIDSA_AUTH=on (default) to require sign-in"><i class="bi bi-unlock"></i> Auth disabled</div>`;
    return;
  }
  el.innerHTML = `
    <div class="user-box-row">
      <div class="user-box-avatar">${escHtml(u.username.slice(0, 2).toUpperCase())}</div>
      <div class="user-box-info">
        <div class="user-box-name">${escHtml(u.username)}</div>
        <div class="user-box-role">${escHtml(u.role)}</div>
      </div>
      ${u.role === "admin" ? `<button class="user-box-btn" onclick="openUserManager()" title="Manage users"><i class="bi bi-people"></i></button>` : ""}
      <button class="user-box-btn" onclick="openChangePassword()" title="Change password"><i class="bi bi-key"></i></button>
      <button class="user-box-btn" onclick="logout()" title="Sign out"><i class="bi bi-box-arrow-right"></i></button>
    </div>`;
}

async function logout() {
  await fetch("/api/auth/logout", { method: "POST" }).catch(() => {});
  location.href = "/login.html";
}

function openChangePassword() {
  showDialog(
    "Change Password",
    `
    <label>Current password</label>
    <input id="pw-current" type="password" autocomplete="current-password" />
    <label>New password <span class="hint">(min. 10 characters)</span></label>
    <input id="pw-new" type="password" autocomplete="new-password" />
    <div class="modal-actions">
      <button class="btn-secondary" onclick="closeDialog()">Cancel</button>
      <button class="btn-primary" onclick="submitChangePassword()">Save</button>
    </div>`,
  );
  document.getElementById("pw-current").focus();
}

async function submitChangePassword() {
  try {
    await api("POST", "/api/auth/password", {
      currentPassword: document.getElementById("pw-current").value,
      newPassword: document.getElementById("pw-new").value,
    });
    closeDialog();
    toast("Password changed");
  } catch (e) {
    toast(escHtml(e.message), "err");
  }
}

/* ── User management (admin) ──────────────────────────────────────────────── */
async function openUserManager() {
  let users;
  try {
    users = await api("GET", "/api/users");
  } catch (e) {
    toast(escHtml(e.message), "err");
    return;
  }
  const roleSelect = (u) =>
    `<select onchange="updateUserRole('${escHtml(u.username)}', this.value)" ${u.username === state.currentUser.username ? "disabled" : ""}>
      ${["viewer", "analyst", "admin"].map((r) => `<option value="${r}" ${r === u.role ? "selected" : ""}>${r}</option>`).join("")}
    </select>`;
  const rows = users
    .map(
      (u) => `
    <tr>
      <td>${escHtml(u.username)}${u.username === state.currentUser.username ? ' <span class="hint">(you)</span>' : ""}</td>
      <td>${roleSelect(u)}</td>
      <td class="hint">${u.createdAt ? formatDate(u.createdAt) : ""}</td>
      <td style="text-align:right;white-space:nowrap">
        <button class="btn-secondary btn-xs" onclick="resetUserPassword('${escHtml(u.username)}')" title="Reset password"><i class="bi bi-key"></i></button>
        ${u.username !== state.currentUser.username ? `<button class="btn-danger btn-xs" onclick="deleteUser('${escHtml(u.username)}')" title="Delete"><i class="bi bi-trash3"></i></button>` : ""}
      </td>
    </tr>`,
    )
    .join("");

  showDialog(
    "Users",
    `
    <div class="dialog-scroll">
      <table class="simple-table">
        <thead><tr><th>Username</th><th>Role</th><th>Created</th><th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="hint" style="margin-top:8px"><b>viewer</b> read-only · <b>analyst</b> upload, analyze, triage, Graph sync · <b>admin</b> workspaces, integrations, users</p>
    <div class="section-label" style="margin-top:14px">Add user</div>
    <div class="inline-form">
      <input id="nu-name" placeholder="username" />
      <input id="nu-pass" type="password" placeholder="password (min. 10)" autocomplete="new-password" />
      <select id="nu-role"><option value="analyst">analyst</option><option value="viewer">viewer</option><option value="admin">admin</option></select>
      <button class="btn-primary" onclick="createUser()">Add</button>
    </div>`,
    { wide: true },
  );
}

async function createUser() {
  try {
    await api("POST", "/api/users", {
      username: document.getElementById("nu-name").value.trim(),
      password: document.getElementById("nu-pass").value,
      role: document.getElementById("nu-role").value,
    });
    toast("User created");
    openUserManager();
  } catch (e) {
    toast(escHtml(e.message), "err");
  }
}

async function updateUserRole(username, role) {
  try {
    await api("PATCH", `/api/users/${encodeURIComponent(username)}`, { role });
    toast(`${escHtml(username)} is now ${role}`);
  } catch (e) {
    toast(escHtml(e.message), "err");
    openUserManager();
  }
}

async function resetUserPassword(username) {
  const pw = window.prompt(`New password for ${username} (min. 10 characters):`);
  if (!pw) return;
  try {
    await api("PATCH", `/api/users/${encodeURIComponent(username)}`, { password: pw });
    toast(`Password reset for ${escHtml(username)} — their sessions were signed out`);
  } catch (e) {
    toast(escHtml(e.message), "err");
  }
}

async function deleteUser(username) {
  if (!confirm(`Delete user ${username}?`)) return;
  try {
    await api("DELETE", `/api/users/${encodeURIComponent(username)}`);
    toast("User deleted");
    openUserManager();
  } catch (e) {
    toast(escHtml(e.message), "err");
  }
}
