/* ── Conditional Access Recommendations ──────────────────────────────────── */
const CA_RECS = {
  PASSWORD_SPRAY: {
    priority: "HIGH",
    icon: '<i class="bi bi-shield-lock-fill"></i>',
    title: "Aktifkan Smart Lockout & Password Protection",
    desc: "Password spray terdeteksi. Smart Lockout mengunci akun setelah gagal berulang kali dari IP yang sama.",
    action:
      "Entra ID → Security → Authentication Methods → Password Protection",
    tip: "Set lockout threshold ≤5, lockout duration ≥60 detik. Aktifkan juga custom banned passwords.",
  },
  BRUTE_FORCE: {
    priority: "HIGH",
    icon: '<i class="bi bi-hammer"></i>',
    title: "Blokir Legacy Authentication Protocols",
    desc: "Brute force terdeteksi. Legacy auth (IMAP, POP3, SMTP AUTH) tidak mendukung MFA sehingga rentan.",
    action:
      "Entra ID → Security → Conditional Access → New Policy → Block legacy authentication",
    tip: "Target: Exchange ActiveSync + Other clients. Apply to All Users. Monitor 14 hari sebelum enforce.",
  },
  MFA_EXHAUSTION: {
    priority: "CRITICAL",
    icon: '<i class="bi bi-phone-fill"></i>',
    title: "Aktifkan MFA Number Matching + Additional Context",
    desc: "MFA Fatigue Attack terdeteksi. Attacker membombardir notifikasi push MFA sampai user approve by reflex.",
    action:
      "Entra ID → Security → Authentication Methods → Microsoft Authenticator → Configure",
    tip: "Aktifkan Number Matching DAN Additional Context (tampilkan lokasi + app). Disable simple push approval.",
  },
  IMPOSSIBLE_TRAVEL: {
    priority: "CRITICAL",
    icon: '<i class="bi bi-airplane-fill"></i>',
    title: "Terapkan Sign-in Risk Policy (Identity Protection)",
    desc: "Login dari lokasi yang tidak mungkin terdeteksi — indikasi credential compromise atau VPN abuse.",
    action: "Entra ID → Protection → Identity Protection → Sign-in risk policy",
    tip: "High risk → Require MFA atau Block. Medium risk → Require MFA. Butuh Entra ID P2 — pertimbangkan untuk akun kritis.",
  },
  FOREIGN_LOGIN: {
    priority: "HIGH",
    icon: '<i class="bi bi-globe"></i>',
    title: "Buat Named Location & Country Block CA Policy",
    desc: "Login sukses dari negara asing terdeteksi. Batasi akses dari negara yang tidak dioperasikan klien.",
    action:
      "Entra ID → Security → Conditional Access → Named Locations → Country/Region",
    tip: "Buat allowlist negara yang sah. Block sign-in dari semua negara lain, atau require MFA untuk negara baru.",
  },
  LEGACY_AUTH: {
    priority: "HIGH",
    icon: '<i class="bi bi-plug-fill"></i>',
    title: "Blokir Legacy Authentication (Policy Dedicated)",
    desc: "Login via protokol legacy terdeteksi. Protocol ini bypass MFA dan merupakan vektor serangan utama.",
    action:
      "Entra ID → Security → Conditional Access → New Policy → Conditions → Client apps",
    tip: 'Buat CA policy khusus: kondisi "Other clients" dan "Exchange ActiveSync" → Grant "Block access".',
  },
  CA_GAP: {
    priority: "MEDIUM",
    icon: '<i class="bi bi-shield-slash"></i>',
    title: "Audit Coverage Conditional Access Policies",
    desc: "Gap dalam coverage CA terdeteksi — ada user atau app yang tidak ter-cover policy apapun.",
    action: "Entra ID → Security → Conditional Access → Insights and Reporting",
    tip: 'Gunakan CA "What If" tool untuk test coverage. Pastikan tidak ada user yang lolos semua policy.',
  },
  TOKEN_REPLAY: {
    priority: "CRITICAL",
    icon: '<i class="bi bi-masks-theater"></i>',
    title: "Aktifkan Continuous Access Evaluation (CAE)",
    desc: "Token replay attack terdeteksi. Attacker menggunakan access token yang dicuri dari session lain.",
    action: "Entra ID → Security → Continuous Access Evaluation → Enable",
    tip: "CAE merevoke token secara real-time saat kondisi berubah. Aktifkan juga Token Protection di CA policy.",
  },
  ENUMERATION_ATTACK: {
    priority: "MEDIUM",
    icon: '<i class="bi bi-list-check"></i>',
    title: "Sembunyikan User Existence & Aktifkan SSPR Lockout",
    desc: "User enumeration terdeteksi. Attacker sedang memetakan akun valid untuk serangan berikutnya.",
    action: "Entra ID → Security → Authentication Methods → Password Reset",
    tip: 'Pastikan error message login tidak membedakan "user tidak ada" vs "password salah". Enable SSPR lockout.',
  },
  CREDENTIAL_STUFFING: {
    priority: "HIGH",
    icon: '<i class="bi bi-unlock-fill"></i>',
    title: "Aktifkan User Risk Policy & Leaked Credential Detection",
    desc: "Credential stuffing terdeteksi — attacker menggunakan credential dari breach database pihak ketiga.",
    action: "Entra ID → Protection → Identity Protection → User risk policy",
    tip: "High user risk → Require password change. Aktifkan Password Hash Sync untuk leaked credential detection.",
  },
  ADMIN_TOOL_ABUSE: {
    priority: "CRITICAL",
    icon: '<i class="bi bi-award-fill"></i>',
    title: "Terapkan Privileged Identity Management (PIM)",
    desc: "Admin tool abuse terdeteksi. Akses privileged tanpa oversight memudahkan lateral movement.",
    action:
      "Entra ID → Identity Governance → Privileged Identity Management → Roles",
    tip: "Terapkan just-in-time access dengan approval workflow + time limit untuk semua admin roles.",
  },
  SERVICE_PRINCIPAL_ANOMALY: {
    priority: "HIGH",
    icon: '<i class="bi bi-robot"></i>',
    title: "Audit Service Principal Permissions",
    desc: "Anomali activity dari Service Principal/App terdeteksi — bisa indikasi compromised app credential.",
    action:
      "Entra ID → App Registrations → [App] → API Permissions + Certificates & Secrets",
    tip: "Review permission scope. Rotate client secrets. Terapkan least-privilege principle per service principal.",
  },
  TIME_OF_DAY_ANOMALY: {
    priority: "MEDIUM",
    icon: '<i class="bi bi-moon-fill"></i>',
    title: "Terapkan Business Hours Access Policy",
    desc: "Login di jam tidak wajar terdeteksi secara konsisten — anomali dari baseline normal user.",
    action:
      "Entra ID → Security → Conditional Access → New Policy → Conditions → Time (preview)",
    tip: "Require MFA tambahan atau block akses diluar jam kerja untuk user atau group berisiko tinggi.",
  },
  FIRST_SEEN_COUNTRY: {
    priority: "MEDIUM",
    icon: '<i class="bi bi-map"></i>',
    title: "Require MFA untuk Lokasi Baru (Named Locations)",
    desc: "Login dari negara yang belum pernah digunakan user sebelumnya terdeteksi.",
    action: "Entra ID → Security → Conditional Access → Named Locations",
    tip: "Buat policy: jika login dari lokasi di luar trusted countries → Require MFA. Log dan alert semua kasus.",
  },
  CONCURRENT_SESSIONS: {
    priority: "HIGH",
    icon: '<i class="bi bi-people-fill"></i>',
    title: "Konfigurasi Session Controls & Token Lifetime",
    desc: "Sesi concurrent mencurigakan terdeteksi — bisa indikasi token sharing atau session hijacking.",
    action:
      "Entra ID → Security → Conditional Access → Session controls → Sign-in frequency",
    tip: "Set sign-in frequency yang pendek untuk app sensitif. Disable persistent browser session untuk unmanaged devices.",
  },
  OAUTH_CONSENT_PHISHING: {
    priority: "CRITICAL",
    icon: '<i class="bi bi-bug-fill"></i>',
    title: "Batasi User Consent untuk OAuth Applications",
    desc: "OAuth consent phishing terdeteksi — attacker membuat app berbahaya untuk mencuri token OAuth.",
    action:
      "Entra ID → Enterprise Applications → Consent and permissions → User consent settings",
    tip: 'Set ke "Allow for verified publishers only" atau "Do not allow". Aktifkan admin consent workflow.',
  },
  DISTRIBUTED_BRUTE_FORCE: {
    priority: "HIGH",
    icon: '<i class="bi bi-globe2"></i>',
    title: "Aktifkan Risk-Based CA untuk Distributed Attack",
    desc: "Distributed brute force dari banyak IP terdeteksi — menghindari IP-based lockout tradisional.",
    action: "Entra ID → Protection → Identity Protection → Sign-in risk policy",
    tip: "IP-based lockout tidak efektif untuk distributed attack. Gunakan sign-in risk score untuk block/require MFA.",
  },
  MFA_METHOD_DOWNGRADE: {
    priority: "HIGH",
    icon: '<i class="bi bi-graph-down-arrow"></i>',
    title: "Require Phishing-Resistant MFA (Authentication Strength)",
    desc: "MFA method downgrade terdeteksi — attacker memaksa user ke metode MFA yang lebih mudah di-phish.",
    action:
      "Entra ID → Security → Authentication Methods → Authentication strengths",
    tip: "Buat custom Authentication Strength yang hanya izinkan FIDO2 Security Key atau Certificate-Based Auth.",
  },
  ENTRA_RISKY_SIGNIN: {
    priority: "HIGH",
    icon: '<i class="bi bi-shield-exclamation"></i>',
    title: "Aktifkan Sign-in & User Risk Policy",
    desc: "Microsoft Identity Protection menilai sign-in berisiko tapi tetap berhasil — policy risiko belum memblokir.",
    action: "Entra ID → Protection → Conditional Access → New policy → Conditions → Sign-in risk / User risk",
    tip: "Sign-in risk Medium+ → require MFA; User risk High → require secure password change. Review Risky users dan konfirmasi compromised/safe.",
  },
  MFA_REGISTRATION_AFTER_COMPROMISE: {
    priority: "CRITICAL",
    icon: '<i class="bi bi-phone-vibrate"></i>',
    title: "Lindungi Registrasi Security Info",
    desc: "Metode MFA baru didaftarkan setelah aktivitas login mencurigakan — attacker kemungkinan memasang authenticator miliknya.",
    action: "Entra ID → Conditional Access → New policy → User actions → Register security information",
    tip: "Wajibkan registrasi hanya dari trusted location / compliant device. Segera hapus metode MFA asing dari user terdampak dan revoke sessions.",
  },
  OAUTH_CONSENT_GRANT: {
    priority: "CRITICAL",
    icon: '<i class="bi bi-key-fill"></i>',
    title: "Cabut Consent & Batasi User Consent",
    desc: "Consent diberikan ke aplikasi dengan scope berisiko (mail/files/directory).",
    action: "Entra ID → Enterprise Applications → [App] → Permissions → Review; Consent and permissions → User consent settings",
    tip: "Revoke grant dan disable service principal jika tidak dikenal. Set user consent ke verified publishers + low-impact permissions saja.",
  },
  PRIVILEGED_ROLE_ASSIGNMENT: {
    priority: "CRITICAL",
    icon: '<i class="bi bi-person-badge-fill"></i>',
    title: "Gunakan PIM untuk Role Privileged",
    desc: "Role admin privileged diberikan — verifikasi apakah perubahan ini terencana.",
    action: "Entra ID → Identity Governance → Privileged Identity Management → Roles",
    tip: "Jadikan role eligible (just-in-time) dengan approval + MFA. Aktifkan alert PIM untuk assignment di luar PIM.",
  },
  APP_CREDENTIAL_ADDED: {
    priority: "HIGH",
    icon: '<i class="bi bi-file-earmark-lock"></i>',
    title: "Batasi Siapa yang Bisa Menambah App Credential",
    desc: "Secret/certificate baru ditambahkan ke app registration — attacker bisa memakai app untuk akses API persisten.",
    action: "Entra ID → App registrations → [App] → Certificates & secrets; Roles → Application Administrator",
    tip: "Hapus credential yang tidak dikenal, review owner app, dan terapkan app management policy (credential lifetime, larang password credentials).",
  },
  RARE_APP_ACCESS: {
    priority: "LOW",
    icon: '<i class="bi bi-box-seam"></i>',
    title: "Review App Permissions & Terapkan App-Based CA",
    desc: "Akses ke aplikasi yang jarang digunakan terdeteksi — perlu validasi apakah akses ini legitimate.",
    action: "Entra ID → Enterprise Applications → Usage & insights",
    tip: "Terapkan CA policy yang require MFA atau compliant device untuk apps sensitif atau jarang diakses.",
  },
  DEVICE_FINGERPRINT_ANOMALY: {
    priority: "MEDIUM",
    icon: '<i class="bi bi-laptop"></i>',
    title: "Terapkan Device Compliance CA Policy",
    desc: "Login dari device baru atau tidak dikenal secara konsisten terdeteksi.",
    action:
      "Entra ID → Security → Conditional Access → Require compliant device",
    tip: "Require Intune device compliance atau Hybrid AD Join untuk akses ke corporate resources.",
  },
};

function renderRemediationTab(data) {
  const detections = data.detections || [];
  const foundTypes = new Set(detections.map((d) => d.type));
  const priorityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const colors = {
    CRITICAL: {
      bg: "rgba(209,52,56,0.09)",
      border: "rgba(209,52,56,0.28)",
      dot: "#ef4444",
      text: "#ff6b6b",
    },
    HIGH: {
      bg: "rgba(249,115,22,0.08)",
      border: "rgba(249,115,22,0.25)",
      dot: "#f97316",
      text: "#fb923c",
    },
    MEDIUM: {
      bg: "rgba(245,158,11,0.07)",
      border: "rgba(245,158,11,0.22)",
      dot: "#f59e0b",
      text: "#fbbf24",
    },
    LOW: {
      bg: "rgba(0,120,212,0.07)",
      border: "rgba(0,120,212,0.22)",
      dot: "#0078d4",
      text: "#60a5fa",
    },
  };

  const activeRecs = Object.entries(CA_RECS)
    .filter(([type]) => foundTypes.has(type))
    .sort(
      (a, b) =>
        (priorityOrder[a[1].priority] ?? 4) -
        (priorityOrder[b[1].priority] ?? 4),
    );

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  activeRecs.forEach(([, r]) => {
    if (counts[r.priority] !== undefined) counts[r.priority]++;
  });

  if (activeRecs.length === 0) {
    return `<div class="empty" style="padding:60px 0"><i class="bi bi-check-circle-fill"></i> Tidak ada rekomendasi aktif — tidak ada deteksi yang memerlukan CA policy change.</div>`;
  }

  return `
    <div class="rem-header">
      <div>
        <div style="font-size:15px;font-weight:700;color:#fff;margin-bottom:4px">Rekomendasi Conditional Access Policy</div>
        <div style="font-size:12px;color:var(--text3)">${activeRecs.length} rekomendasi aktif berdasarkan ${foundTypes.size} tipe deteksi yang ditemukan</div>
      </div>
      <div class="rem-counts">
        ${Object.entries(counts)
          .filter(([, v]) => v > 0)
          .map(
            ([k, v]) => `
          <div class="rem-count-chip" style="background:${colors[k].bg};border:1px solid ${colors[k].border}">
            <span class="rem-count-dot" style="background:${colors[k].dot}"></span>
            <span style="color:${colors[k].text};font-weight:700">${v}</span>
            <span style="color:var(--text3)">${k}</span>
          </div>`,
          )
          .join("")}
      </div>
    </div>
    <div class="rem-list">
      ${activeRecs
        .map(([type, rec]) => {
          const c = colors[rec.priority] || colors.LOW;
          return `
          <div class="rem-card" style="background:${c.bg};border:1px solid ${c.border}">
            <div class="rem-card-top">
              <span class="rem-card-icon">${rec.icon}</span>
              <div style="flex:1;min-width:0">
                <div class="rem-card-title">${rec.title}</div>
                <div class="rem-card-desc">${rec.desc}</div>
              </div>
              <span class="rem-badge" style="background:${c.bg};border:1px solid ${c.border};color:${c.text}">${rec.priority}</span>
            </div>
            <div class="rem-card-path">
              <span style="opacity:.5;font-size:11px"><i class="bi bi-geo-alt-fill"></i></span>
              <span class="rem-path-text">${escHtml(rec.action)}</span>
            </div>
            <div class="rem-card-tip"><i class="bi bi-lightbulb-fill"></i> ${escHtml(rec.tip)}</div>
          </div>`;
        })
        .join("")}
    </div>`;
}

/* ── Right nav ────────────────────────────────────────────────────────────── */
const RNAV_TABS = [
  { id: "dashboard", icon: "◈", label: "Dashboard" },
  {
    id: "accounts",
    icon: '<i class="bi bi-person-fill"></i>',
    label: "Accounts",
    children: [
      { id: "accounts-high", label: "High Risk", dot: "#ef4444" },
      { id: "accounts-medium", label: "Medium Risk", dot: "#f59e0b" },
      { id: "accounts-low", label: "Low Risk", dot: "#10b981" },
    ],
  },
  {
    id: "detections",
    icon: '<i class="bi bi-search"></i>',
    label: "Detections",
  },
  {
    id: "remediation",
    icon: '<i class="bi bi-shield-check"></i>',
    label: "CA Remediation",
  },
  { id: "events", icon: "≡", label: "Events" },
  { id: "map", icon: "◉", label: "Map" },
  { id: "charts", icon: "▦", label: "Charts" },
  { id: "killchain", icon: "⊕", label: "Kill Chain" },
  {
    id: "velocity",
    icon: '<i class="bi bi-lightning-charge-fill"></i>',
    label: "Velocity",
  },
  { id: "graph", icon: "⬡", label: "Attack Graph" },
  { id: "swimlane", icon: "⊟", label: "Swimlane" },
  { id: "sankey", icon: "⊧", label: "Sankey" },
  { id: "countryapp", icon: "⊞", label: "Country×App" },
];

function buildRightNav() {
  const items = document.getElementById("right-nav-items");
  if (!items) return;
  document.getElementById("app").classList.add("rnav-visible");
  items.innerHTML = RNAV_TABS.map((t) => {
    if (t.children) {
      const open = state.rnavOpenGroups.has(t.id);
      return `
        <div class="rnav-group${open ? " open" : ""}" id="rnav-group-${t.id}">
          <button class="rnav-item rnav-group-parent" onclick="toggleRnavGroup('${t.id}')" title="${t.label}">
            <span class="rnav-icon">${t.icon}</span>
            <span class="rnav-label">${t.label}</span>
            <svg class="rnav-arrow" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>
          </button>
          <div class="rnav-group-children">
            ${t.children
              .map(
                (c) => `
              <button class="rnav-item rnav-sub-item" onclick="gotoRiskSection('${c.id.replace("accounts-", "")}')" title="${c.label}">
                <span class="rnav-sub-dot" style="background:${c.dot}"></span>
                <span class="rnav-label">${c.label}</span>
              </button>
            `,
              )
              .join("")}
          </div>
        </div>`;
    }
    return `
      <button class="rnav-item${state.activeTab === t.id ? " active" : ""}"
              data-tab="${t.id}"
              onclick="switchTab('${t.id}')"
              title="${t.label}">
        <span class="rnav-icon">${t.icon}</span>
        <span class="rnav-label">${t.label}</span>
      </button>`;
  }).join("");
}

function toggleRightNav() {
  document.getElementById("app").classList.toggle("rnav-collapsed");
}

function toggleRnavGroup(id) {
  const grp = document.getElementById(`rnav-group-${id}`);
  if (!grp) return;
  grp.classList.toggle("open");
  if (grp.classList.contains("open")) {
    state.rnavOpenGroups.add(id);
  } else {
    state.rnavOpenGroups.delete(id);
  }
}

function gotoRiskSection(level) {
  switchTab("dashboard");
  setTimeout(() => {
    const el = document.getElementById(`risk-group-${level}`);
    if (el) el.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 80);
}

/* ── Tabs ─────────────────────────────────────────────────────────────────── */
function switchTab(tab) {
  state.activeTab = tab;
  document
    .querySelectorAll(".rnav-item")
    .forEach((b) => b.classList.remove("active"));
  document
    .querySelectorAll(".tab-panel")
    .forEach((p) => p.classList.remove("active"));
  const btn = document.querySelector(`.rnav-item[data-tab="${tab}"]`);
  if (btn) btn.classList.add("active");
  const panel = document.getElementById(`tab-${tab}`);
  if (panel) {
    panel.classList.add("active");
    // Lazy-render tabs that were skipped during initial renderAnalysis
    if (panel.dataset.lazy === '1' && state.analysisData) {
      panel.removeAttribute('data-lazy');
      const _d = state.analysisData;
      if (tab === 'detections')  panel.innerHTML = buildDetectionsSection(_d.detections || []);
      else if (tab === 'remediation') panel.innerHTML = renderRemediationTab(_d);
      else if (tab === 'events')      panel.innerHTML = renderEventsTable(_d.events || []);
    }
  }
  // Scroll main panel to top when switching views
  const main = document.getElementById("main");
  if (main) main.scrollTop = 0;
  if (tab === "map") {
    setTimeout(() => {
      initMap();
      if (state.leafletMap) state.leafletMap.invalidateSize();
    }, 50);
  }
  if (tab === "charts") {
    setTimeout(() => initCharts(), 50);
  }
  if (tab === "killchain") {
    setTimeout(() => initKillChain(), 50);
  }
  if (tab === "velocity") {
    setTimeout(() => initVelocity(), 50);
  }
  if (tab === "graph") {
    const gc = document.getElementById("graph-container");
    if (gc) gc.dataset.built = "";
    setTimeout(() => initAttackGraph(), 50);
  }
  if (tab === "swimlane") {
    setTimeout(() => initSwimlane(), 50);
  }
  if (tab === "sankey") {
    setTimeout(() => initSankey(), 50);
  }
  if (tab === "countryapp") {
    setTimeout(() => initCountryApp(), 50);
  }
}

