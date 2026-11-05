/* ── IOC Search ───────────────────────────────────────────────────────────── */
function openIOCSearch() {
  if (document.getElementById("ioc-overlay")) {
    document.getElementById("ioc-input")?.focus();
    return;
  }
  const overlay = document.createElement("div");
  overlay.id = "ioc-overlay";
  overlay.innerHTML = `
    <div id="ioc-panel">
      <div class="ioc-header">
        <span><i class="bi bi-search"></i> IOC Search</span>
        <button onclick="closeIOCSearch()"><i class="bi bi-x-lg"></i></button>
      </div>
      <input id="ioc-input" type="text" placeholder="Search IP, username, country, error code…"
        oninput="renderIOCResults(this.value)" autocomplete="off" spellcheck="false" />
      <div id="ioc-results">
        <div class="ioc-hint">Type to search across all events — IP, username, country, error code</div>
      </div>
    </div>`;
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeIOCSearch();
  });
  document.body.appendChild(overlay);
  setTimeout(() => document.getElementById("ioc-input")?.focus(), 50);
}

function closeIOCSearch() {
  document.getElementById("ioc-overlay")?.remove();
}

function renderIOCResults(query) {
  const resultsEl = document.getElementById("ioc-results");
  if (!resultsEl || !state.analysisData) return;
  const q = query.trim().toLowerCase();
  if (!q) {
    resultsEl.innerHTML =
      '<div class="ioc-hint">Type to search across all events — IP, username, country, error code</div>';
    return;
  }

  const events = state.analysisData.events || [];
  const ipEnrich = state.analysisData.ipEnrichment || {};

  const ipCounts = {};
  const ipUsers = {};
  const userCounts = {};
  const ctryEvents = {};

  for (const e of events) {
    if (e.ipAddress && e.ipAddress.toLowerCase().includes(q)) {
      ipCounts[e.ipAddress] = (ipCounts[e.ipAddress] || 0) + 1;
      if (!ipUsers[e.ipAddress]) ipUsers[e.ipAddress] = new Set();
      if (e.userPrincipal) ipUsers[e.ipAddress].add(e.userPrincipal);
    }
    if ((e.userPrincipal + (e.displayName || "")).toLowerCase().includes(q)) {
      userCounts[e.userPrincipal] = (userCounts[e.userPrincipal] || 0) + 1;
    }
    const locStr = ((e.country || "") + " " + (e.city || "")).toLowerCase();
    if (locStr.trim() && locStr.includes(q)) {
      const key = e.country + (e.city ? " / " + e.city : "");
      ctryEvents[key] = (ctryEvents[key] || 0) + 1;
    }
  }

  const hasAny =
    Object.keys(ipCounts).length +
      Object.keys(userCounts).length +
      Object.keys(ctryEvents).length >
    0;
  if (!hasAny) {
    resultsEl.innerHTML = '<div class="ioc-hint">No matches found.</div>';
    return;
  }

  let html = "";

  if (Object.keys(ipCounts).length > 0) {
    html += '<div class="ioc-section-label">IP Addresses</div>';
    html += Object.entries(ipCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => {
        const users = [...(ipUsers[ip] || [])].slice(0, 2).join(", ");
        const info = ipEnrich[ip];
        const badge = info?.proxy
          ? ' <span class="ip-badge badge-proxy" style="font-size:9px;vertical-align:middle">PROXY</span>'
          : info?.hosting
            ? ' <span class="ip-badge badge-hosting" style="font-size:9px;vertical-align:middle">VPS</span>'
            : "";
        return `<div class="ioc-result" onclick="filterEventsByIP('${escHtml(ip)}')">
        <span class="ioc-result-main">${escHtml(ip)}${badge}</span>
        <span class="ioc-result-meta">${count} events · ${users || "no user data"}</span>
      </div>`;
      })
      .join("");
  }

  if (Object.keys(userCounts).length > 0) {
    html += '<div class="ioc-section-label">Users</div>';
    html += Object.entries(userCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([user, count]) => {
        return `<div class="ioc-result" onclick="openTimeline('${escHtml(user)}');closeIOCSearch()">
        <span class="ioc-result-main">${escHtml(user)}</span>
        <span class="ioc-result-meta">${count} events · click to open timeline</span>
      </div>`;
      })
      .join("");
  }

  if (Object.keys(ctryEvents).length > 0) {
    html += '<div class="ioc-section-label">Locations</div>';
    html += Object.entries(ctryEvents)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([loc, count]) => {
        const ctry = loc.split(" / ")[0];
        return `<div class="ioc-result" onclick="filterEventsByCountry('${escHtml(ctry)}')">
        <span class="ioc-result-main"><i class="bi bi-geo-alt-fill"></i> ${escHtml(loc)}</span>
        <span class="ioc-result-meta">${count} events</span>
      </div>`;
      })
      .join("");
  }

  resultsEl.innerHTML = html;
}

function filterEventsByIP(ip) {
  switchTab("events");
  state.eventsFilter = ip;
  state.eventsPage = 1;
  rerenderTable();
  closeIOCSearch();
}

function filterEventsByCountry(country) {
  switchTab("events");
  state.eventsFilter = country;
  state.eventsPage = 1;
  rerenderTable();
  closeIOCSearch();
}

/* ── Attack Graph ─────────────────────────────────────────────────────────── */
function initAttackGraph() {
  const container = document.getElementById("graph-container");
  if (!container || !state.analysisData) return;
  if (container.dataset.built === "1") return;
  container.dataset.built = "1";

  const {
    detections = [],
    events = [],
    userSummaries = [],
    ipEnrichment = {},
  } = state.analysisData;
  const homeCountry = (state.analysisData.homeCountry || "ID").toUpperCase();

  if (detections.length === 0) {
    container.innerHTML =
      '<div class="empty" style="padding:80px 0">No detections — attack graph requires sign-in data with flagged activity.</div>';
    return;
  }

  // ── Build node sets ──────────────────────────────────────────────────────
  const ipStats = {};
  for (const e of events) {
    if (!e.ipAddress || !e.country || e.country.toUpperCase() === homeCountry)
      continue;
    if (!ipStats[e.ipAddress])
      ipStats[e.ipAddress] = { count: 0, users: new Set(), country: e.country };
    ipStats[e.ipAddress].count++;
    if (e.userPrincipal) ipStats[e.ipAddress].users.add(e.userPrincipal);
  }

  const detUserSet = new Set();
  for (const d of detections) {
    if (d.user) detUserSet.add(d.user);
    if (d.affectedUsers) d.affectedUsers.forEach((u) => detUserSet.add(u));
  }

  const topIPs = Object.entries(ipStats)
    .filter(([, s]) => [...s.users].some((u) => detUserSet.has(u)))
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 14);

  const atRiskUsers = userSummaries
    .filter((s) => detUserSet.has(s.user))
    .slice(0, 14);

  const detTypeMap = {};
  for (const d of detections) {
    if (!detTypeMap[d.type])
      detTypeMap[d.type] = { severity: d.severity, users: new Set() };
    if (d.user) detTypeMap[d.type].users.add(d.user);
    if (d.affectedUsers)
      d.affectedUsers.forEach((u) => detTypeMap[d.type].users.add(u));
  }
  const detTypes = Object.entries(detTypeMap);

  if (topIPs.length === 0 && atRiskUsers.length === 0) {
    container.innerHTML =
      '<div class="empty" style="padding:80px 0">Not enough data to build attack graph — foreign-IP events and detections are needed.</div>';
    return;
  }

  // ── Edges ────────────────────────────────────────────────────────────────
  const edges1 = []; // IP → User
  const edges2 = []; // User → DetType
  for (const [ip, s] of topIPs) {
    for (const user of s.users) {
      if (atRiskUsers.some((u) => u.user === user))
        edges1.push({ from: ip, to: user });
    }
  }
  for (const [dt, info] of detTypes) {
    for (const user of info.users) {
      if (atRiskUsers.some((u) => u.user === user))
        edges2.push({ from: user, to: dt });
    }
  }

  // ── Layout ────────────────────────────────────────────────────────────────
  const W = container.clientWidth || 880;
  const NH = 38;
  const NW = 170;
  const GAP = 12;
  const colIPs = topIPs.length;
  const colU = atRiskUsers.length;
  const colD = detTypes.length;
  const SVG_H = Math.max(colIPs, colU, colD) * (NH + GAP) + 60;

  const xIP = 16;
  const xUser = (W - NW) / 2;
  const xDet = W - NW - 16;

  const colY = (n, total) => {
    const totalH = total * (NH + GAP) - GAP;
    const start = (SVG_H - totalH) / 2;
    return start + n * (NH + GAP);
  };

  const nodePos = {};
  topIPs.forEach(([ip], i) => {
    nodePos["ip:" + ip] = { x: xIP, y: colY(i, colIPs), w: NW, h: NH };
  });
  atRiskUsers.forEach((s, i) => {
    nodePos["user:" + s.user] = { x: xUser, y: colY(i, colU), w: NW, h: NH };
  });
  detTypes.forEach(([dt], i) => {
    nodePos["det:" + dt] = { x: xDet, y: colY(i, colD), w: NW, h: NH };
  });

  const sevColor = (s) =>
    s === "high" ? "#f16060" : s === "medium" ? "#f5a623" : "#5b8def";
  const riskColor = (r) =>
    r === "CRITICAL" ? "#f16060" : r === "HIGH" ? "#f5a623" : "#5b8def";

  const bezier = (fk, tk, color, eid) => {
    const f = nodePos[fk];
    const t = nodePos[tk];
    if (!f || !t) return "";
    const x1 = f.x + f.w,
      y1 = f.y + f.h / 2;
    const x2 = t.x,
      y2 = t.y + t.h / 2;
    const cx = (x1 + x2) / 2;
    return `<path data-edgeid="${eid}" data-from="${fk}" data-to="${tk}" d="M${x1},${y1} C${cx},${y1} ${cx},${y2} ${x2},${y2}" fill="none" stroke="${color}" stroke-width="1.5" opacity="0.45"/>`;
  };

  const ipBadge = (ip) => {
    const info = ipEnrichment[ip];
    if (!info) return "";
    if (info.proxy) return " [P]";
    if (info.hosting) return " [H]";
    return "";
  };

  const ipNodesSVG = topIPs.map(([ip, s], i) => {
    const { x, y, w, h } = nodePos["ip:" + ip];
    const lbl = ip.length > 17 ? ip.slice(0, 15) + "…" : ip;
    return `<g data-nodeid="ip:${escHtml(ip)}" style="cursor:pointer" onclick="filterEventsByIP('${escHtml(ip)}')">
      <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="5" fill="#1d2438" stroke="#f16060" stroke-width="1.5" class="graph-node-rect"/>
      <text x="${x + 8}" y="${y + 14}" font-size="11" fill="#f16060" font-family="monospace,sans-serif">${escHtml(lbl)}${ipBadge(ip)}</text>
      <text x="${x + 8}" y="${y + 28}" font-size="10" fill="#8ba0bb">${escHtml(s.country)} · ${s.count} events</text>
    </g>`;
  });

  const userNodesSVG = atRiskUsers.map((s, i) => {
    const { x, y, w, h } = nodePos["user:" + s.user];
    const color = riskColor(s.riskLevel);
    const lbl = (s.displayName || s.user).slice(0, 20);
    return `<g data-nodeid="user:${escHtml(s.user)}" style="cursor:pointer" onclick="openTimeline('${escHtml(s.user)}')">
      <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="5" fill="#1d2438" stroke="${color}" stroke-width="1.5" class="graph-node-rect"/>
      <text x="${x + 8}" y="${y + 14}" font-size="11" fill="${color}">${escHtml(lbl)}</text>
      <text x="${x + 8}" y="${y + 28}" font-size="10" fill="#8ba0bb">${s.riskLevel} · ${s.foreignAttempts} foreign</text>
    </g>`;
  });

  const detNodesSVG = detTypes.map(([dt, info], i) => {
    const { x, y, w, h } = nodePos["det:" + dt];
    const color = sevColor(info.severity);
    const lbl = dt.replace(/_/g, " ");
    const trunc = lbl.length > 19 ? lbl.slice(0, 17) + "…" : lbl;
    return `<g data-nodeid="det:${escHtml(dt)}">
      <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="5" fill="#1d2438" stroke="${color}" stroke-width="1.5" class="graph-node-rect"/>
      <text x="${x + 8}" y="${y + 14}" font-size="11" fill="${color}">${escHtml(trunc)}</text>
      <text x="${x + 8}" y="${y + 28}" font-size="10" fill="#8ba0bb">${info.severity} · ${info.users.size} user${info.users.size !== 1 ? "s" : ""}</text>
    </g>`;
  });

  const edgeSVG1 = edges1.map(({ from, to }, i) =>
    bezier("ip:" + from, "user:" + to, "#f16060", `e1_${i}`),
  );
  const edgeSVG2 = edges2.map(({ from, to }, i) =>
    bezier("user:" + from, "det:" + to, "#f5a623", `e2_${i}`),
  );

  const labels = [
    `<text x="${xIP + NW / 2}" y="18" text-anchor="middle" font-size="10" fill="#617898" font-weight="600" letter-spacing="1">ATTACKER IPs</text>`,
    `<text x="${xUser + NW / 2}" y="18" text-anchor="middle" font-size="10" fill="#617898" font-weight="600" letter-spacing="1">TARGETED USERS</text>`,
    `<text x="${xDet + NW / 2}" y="18" text-anchor="middle" font-size="10" fill="#617898" font-weight="600" letter-spacing="1">DETECTIONS</text>`,
  ].join("");

  container.innerHTML = `
    <div class="graph-wrap">
      <svg width="${W}" height="${SVG_H}" xmlns="http://www.w3.org/2000/svg" style="font-family:Inter,sans-serif;display:block">
        ${labels}
        ${[...edgeSVG1, ...edgeSVG2].join("")}
        ${[...ipNodesSVG, ...userNodesSVG, ...detNodesSVG].join("")}
      </svg>
      <div class="graph-legend">
        <span><span class="graph-legend-dot" style="background:#f16060"></span>Attacker IPs (click → filter events)</span>
        <span><span class="graph-legend-dot" style="background:#f5a623"></span>At-risk users (click → timeline)</span>
        <span><span class="graph-legend-dot" style="background:#5b8def"></span>Detection types</span>
      </div>
    </div>`;

  // ── Hover highlighting ────────────────────────────────────────────────────
  const svg = container.querySelector("svg");
  if (!svg) return;
  const allNodes = [...svg.querySelectorAll("[data-nodeid]")];
  const allEdges = [...svg.querySelectorAll("[data-edgeid]")];

  const getConnected = (nodeId) => {
    const connNodes = new Set([nodeId]);
    const connEdges = new Set();
    const type = nodeId.split(":")[0];

    // 1-hop: direct edges in/out of this node
    for (const e of allEdges) {
      if (e.dataset.from === nodeId) {
        connEdges.add(e.dataset.edgeid);
        connNodes.add(e.dataset.to);
      }
      if (e.dataset.to === nodeId) {
        connEdges.add(e.dataset.edgeid);
        connNodes.add(e.dataset.from);
      }
    }

    // 2nd hop: for IP follow forward through users to dets; for det follow backward through users to IPs
    if (type === "ip") {
      for (const e of allEdges) {
        if (
          connNodes.has(e.dataset.from) &&
          e.dataset.from.startsWith("user:")
        ) {
          connEdges.add(e.dataset.edgeid);
          connNodes.add(e.dataset.to);
        }
      }
    } else if (type === "det") {
      for (const e of allEdges) {
        if (connNodes.has(e.dataset.to) && e.dataset.to.startsWith("user:")) {
          connEdges.add(e.dataset.edgeid);
          connNodes.add(e.dataset.from);
        }
      }
    }
    return { connNodes, connEdges };
  };

  const applyHover = (hoveredNode) => {
    const { connNodes, connEdges } = getConnected(hoveredNode.dataset.nodeid);
    for (const n of allNodes) {
      const active = connNodes.has(n.dataset.nodeid);
      n.style.opacity = active ? "1" : "0.1";
      const rect = n.querySelector("rect");
      if (rect)
        rect.setAttribute(
          "stroke-width",
          active && n === hoveredNode ? "2.5" : "1.5",
        );
    }
    for (const e of allEdges) {
      if (connEdges.has(e.dataset.edgeid)) {
        e.style.opacity = "1";
        e.setAttribute("stroke-width", "2.5");
      } else {
        e.style.opacity = "0.04";
        e.setAttribute("stroke-width", "1.5");
      }
    }
  };

  const clearHover = () => {
    for (const n of allNodes) {
      n.style.opacity = "";
      const rect = n.querySelector("rect");
      if (rect) rect.setAttribute("stroke-width", "1.5");
    }
    for (const e of allEdges) {
      e.style.opacity = "";
      e.setAttribute("stroke-width", "1.5");
    }
  };

  for (const node of allNodes) {
    node.addEventListener("mouseenter", () => applyHover(node));
    node.addEventListener("mouseleave", clearHover);
  }
}

/* ── IP Enrichment ────────────────────────────────────────────────────────── */
// ─── Threat Intel (local static lookup) ──────────────────────────────────────
const THREAT_INTEL_PATTERNS = [
  // Tor
  {
    re: /\btor\b.*(exit|relay|node)|tor\b.*project|(exit|relay).*\btor\b/i,
    tag: "TOR",
    cls: "ti-tor",
    risk: "HIGH",
  },
  // Named VPN providers (commonly abused for attack traffic)
  { re: /mullvad/i, tag: "MULLVAD VPN", cls: "ti-vpn", risk: "MED" },
  { re: /nordvpn|nord\s+vpn/i, tag: "NORDVPN", cls: "ti-vpn", risk: "MED" },
  {
    re: /expressvpn|express\s+vpn/i,
    tag: "EXPRESSVPN",
    cls: "ti-vpn",
    risk: "MED",
  },
  {
    re: /protonvpn|proton\s+vpn/i,
    tag: "PROTONVPN",
    cls: "ti-vpn",
    risk: "MED",
  },
  { re: /cyberghost/i, tag: "CYBERGHOST", cls: "ti-vpn", risk: "MED" },
  { re: /\bipvanish\b/i, tag: "IPVANISH", cls: "ti-vpn", risk: "MED" },
  { re: /\btorguard\b/i, tag: "TORGUARD", cls: "ti-vpn", risk: "MED" },
  {
    re: /hidemyass|hide\s*my\s*ass/i,
    tag: "HMA VPN",
    cls: "ti-vpn",
    risk: "MED",
  },
  {
    re: /private\s+internet\s+access|\bpia\b.*(vpn|network)/i,
    tag: "PIA VPN",
    cls: "ti-vpn",
    risk: "MED",
  },
  { re: /surfshark/i, tag: "SURFSHARK", cls: "ti-vpn", risk: "MED" },
  { re: /windscribe/i, tag: "WINDSCRIBE", cls: "ti-vpn", risk: "MED" },
  {
    re: /\bvpnunlimited\b|vpn\s+unlimited/i,
    tag: "VPN",
    cls: "ti-vpn",
    risk: "MED",
  },
  {
    re: /anonymous.*vpn|vpn.*anonymous/i,
    tag: "ANON VPN",
    cls: "ti-vpn",
    risk: "MED",
  },
  // Bulletproof / botnet-friendly hosters
  {
    re: /\bm247\b/i,
    tag: "M247 (Bulletproof)",
    cls: "ti-botnet",
    risk: "HIGH",
  },
  { re: /quadranet/i, tag: "QuadraNet", cls: "ti-botnet", risk: "HIGH" },
  { re: /frantech|ponynet/i, tag: "FranTech", cls: "ti-botnet", risk: "HIGH" },
  { re: /sharktech/i, tag: "Sharktech", cls: "ti-botnet", risk: "HIGH" },
  { re: /serverius/i, tag: "Serverius", cls: "ti-botnet", risk: "HIGH" },
  {
    re: /combahton|combahton/i,
    tag: "combahton",
    cls: "ti-botnet",
    risk: "HIGH",
  },
  { re: /leaseweb/i, tag: "LeaseWeb", cls: "ti-botnet", risk: "MED" },
  // Proxy / anonymizer labels
  {
    re: /\bsocks\d?\b.*proxy|anonymous\s*proxy/i,
    tag: "ANON PROXY",
    cls: "ti-proxy",
    risk: "HIGH",
  },
];

function lookupThreatIntel(info) {
  if (!info) return null;
  const haystack = `${info.isp || ""} ${info.org || ""}`;
  for (const entry of THREAT_INTEL_PATTERNS) {
    if (entry.re.test(haystack)) return entry;
  }
  return null;
}

function getIPInfo(ip) {
  return state.analysisData?.ipEnrichment?.[ip] || null;
}

function renderIPEnrich(ip) {
  const info = getIPInfo(ip);
  const badges = [];
  if (info) {
    const ti = lookupThreatIntel(info);
    if (ti)
      badges.push(
        `<span class="ip-badge ${ti.cls}" title="Threat Intel: ${escHtml(ti.tag)}">${escHtml(ti.tag)}</span>`,
      );
    else {
      if (info.proxy)
        badges.push('<span class="ip-badge badge-proxy">PROXY</span>');
      if (info.hosting)
        badges.push('<span class="ip-badge badge-hosting">VPS</span>');
      if (info.mobile)
        badges.push('<span class="ip-badge badge-mobile">MOBILE</span>');
    }
    if (info.isTor) badges.push('<span class="ip-badge badge-hosting" title="Tor exit node (AbuseIPDB)">TOR</span>');
    if (info.abuseScore != null && info.abuseScore > 0)
      badges.push(
        `<span class="ip-badge ${info.abuseScore >= 50 ? "badge-abuse-high" : "badge-abuse"}" title="AbuseIPDB confidence ${info.abuseScore}% · ${info.abuseReports || 0} reports (90 days)">ABUSE ${info.abuseScore}%</span>`,
      );
  }
  const hist = state.activeWorkspace
    ? getIPHistory(state.activeWorkspace.id, ip)
    : null;
  if (hist && hist.count > 1) {
    badges.push(
      `<span class="ip-badge badge-repeat" title="Seen in ${hist.count} previous runs — first: ${new Date(hist.firstSeen).toLocaleDateString("en-GB")}">REPEAT ${hist.count}×</span>`,
    );
  }
  const label = info
    ? (info.isp || info.org || "").replace(/^AS\d+\s*/, "").slice(0, 28)
    : "";
  if (!badges.length && !label) return "";
  return `<div class="ip-enrich">${badges.join("")}${label ? `<span class="ip-isp" title="${escHtml(info.isp || info.org || "")}">${escHtml(label)}</span>` : ""}</div>`;
}

function renderIPClickable(ip) {
  if (!ip) return "";
  return `<span class="ip-link" onclick="event.stopPropagation();openIPPivot('${escHtml(ip)}')">${escHtml(ip)}</span>${renderIPEnrich(ip)}`;
}

/* ── IP Pivot Panel ────────────────────────────────────────────────────────── */
function openIPPivot(ip) {
  if (!state.analysisData) return;
  const events = state.analysisData.events || [];
  const detections = state.analysisData.detections || [];

  const ipEvents = events
    .filter((e) => e.ipAddress === ip)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const users = [
    ...new Set(ipEvents.map((e) => e.userPrincipal).filter(Boolean)),
  ];
  const ipDets = detections.filter(
    (d) => d.ip === ip || (d.ips && d.ips.includes(ip)),
  );
  const successes = ipEvents.filter((e) => e.success).length;
  const info = getIPInfo(ip);

  const ti = lookupThreatIntel(info);
  const tiRow = ti
    ? `<div class="ipp-enrich-row ipp-ti-row"><span class="ipp-el">Threat Intel</span><span class="ip-badge ${ti.cls}" style="font-size:11px">${escHtml(ti.tag)}</span><span class="ipp-ti-risk" data-risk="${ti.risk}">${ti.risk} RISK</span></div>`
    : "";
  const ipHist = state.activeWorkspace
    ? getIPHistory(state.activeWorkspace.id, ip)
    : null;
  const histRow =
    ipHist && ipHist.count > 1
      ? `<div class="ipp-enrich-row"><span class="ipp-el">Run History</span><span class="ip-badge badge-repeat" style="font-size:11px">REPEAT ${ipHist.count}×</span><span style="font-size:11px;color:var(--text2);margin-left:6px">first: ${new Date(ipHist.firstSeen).toLocaleDateString("en-GB")}</span></div>`
      : "";
  const enrichRows = info
    ? [
        tiRow,
        info.isp
          ? `<div class="ipp-enrich-row"><span class="ipp-el">ISP</span><span>${escHtml(info.isp)}</span></div>`
          : "",
        info.org && info.org !== info.isp
          ? `<div class="ipp-enrich-row"><span class="ipp-el">Org</span><span>${escHtml(info.org)}</span></div>`
          : "",
        info.as
          ? `<div class="ipp-enrich-row"><span class="ipp-el">ASN</span><span>${escHtml(info.as)}</span></div>`
          : "",
        `<div class="ipp-enrich-row"><span class="ipp-el">Type</span><span>${[info.proxy ? "Proxy" : "", info.hosting ? "VPS/Hosting" : "", info.mobile ? "Mobile" : ""].filter(Boolean).join(" · ") || "Residential"}</span></div>`,
      ]
        .filter(Boolean)
        .join("")
    : "";

  const detHtml = ipDets.length
    ? ipDets
        .map(
          (d) => `
    <div class="ipp-det-row sev-${d.severity}">
      <span class="det-badge badge-${d.severity}">${d.severity}</span>
      <span class="ipp-det-type">${d.type.replace(/_/g, " ")}</span>
      <span class="ipp-det-msg">${escHtml(d.message)}</span>
    </div>`,
        )
        .join("")
    : '<div class="ipp-empty">No direct detections for this IP</div>';

  const usersHtml = users.length
    ? users
        .map(
          (u) => `
    <div class="ipp-user-row" onclick="closeIPPivot();openTimeline('${escHtml(u)}')">
      <span class="ipp-user-name">${escHtml(u)}</span>
      <span class="ipp-user-count">${ipEvents.filter((e) => e.userPrincipal === u).length} events</span>
    </div>`,
        )
        .join("")
    : '<div class="ipp-empty">No user data</div>';

  const eventsHtml = ipEvents
    .slice(0, 50)
    .map((e) => {
      const homeCountry = (
        state.analysisData.homeCountry || "ID"
      ).toUpperCase();
      const isForeign = e.country && e.country.toUpperCase() !== homeCountry;
      return `
    <div class="ipp-event-row">
      <span class="ipp-ev-time">${formatDate(e.createdAt)}</span>
      <span class="${e.success ? "tl-status-ok" : "tl-status-fail"}">${e.success ? '<i class="bi bi-check-lg"></i>' : '<i class="bi bi-x-lg"></i>'}</span>
      <span class="ipp-ev-user" onclick="closeIPPivot();openTimeline('${escHtml(e.userPrincipal)}')">${escHtml(e.displayName || e.userPrincipal.split("@")[0])}</span>
      ${e.country ? `<span class="ipp-ev-loc">${isForeign ? '<i class="bi bi-exclamation-triangle"></i> ' : ""}${escHtml(e.country)}${e.city ? "/" + escHtml(e.city) : ""}</span>` : ""}
      <span class="ipp-ev-app">${escHtml(e.appType || "")}</span>
    </div>`;
    })
    .join("");
  const moreEvents =
    ipEvents.length > 50
      ? `<div class="ipp-empty" style="margin-top:6px">… and ${ipEvents.length - 50} more events</div>`
      : "";

  let overlay = document.getElementById("ip-pivot-overlay");
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.id = "ip-pivot-overlay";
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) closeIPPivot();
    });
    document.body.appendChild(overlay);
  }

  overlay.innerHTML = `
    <div id="ip-pivot-panel">
      <div class="ipp-header">
        <div>
          <div class="ipp-title" style="display:flex;align-items:center;gap:8px">
            ${escHtml(ip)}
            <span class="ioc-chip" style="font-size:10px;padding:1px 7px" onclick="copyIOC('${escHtml(ip)}',this)" title="Copy IP"><i class="bi bi-clipboard"></i> Copy</span>
          </div>
          <div class="ipp-subtitle">IP Pivot · ${ipEvents.length} events · ${users.length} users targeted</div>
        </div>
        <button class="timeline-close" onclick="closeIPPivot()"><i class="bi bi-x-lg"></i></button>
      </div>
      <div class="ipp-body">
        ${enrichRows || histRow ? `<div class="ipp-section"><div class="ipp-section-title">Enrichment</div>${enrichRows}${histRow}</div>` : ""}
        <div class="ipp-stats-row">
          <div class="ipp-stat"><strong>${ipEvents.length}</strong><span>Events</span></div>
          <div class="ipp-stat"><strong>${successes}</strong><span>Successful</span></div>
          <div class="ipp-stat"><strong>${users.length}</strong><span>Users</span></div>
          <div class="ipp-stat"><strong>${ipDets.length}</strong><span>Detections</span></div>
        </div>
        <div class="ipp-section">
          <div class="ipp-section-title">Detections</div>
          ${detHtml}
        </div>
        <div class="ipp-section">
          <div class="ipp-section-title">Users Targeted <span style="font-weight:400;color:var(--text3)">(click to open timeline)</span></div>
          ${usersHtml}
        </div>
        <div class="ipp-section">
          <div class="ipp-section-title">Event Log${ipEvents.length > 50 ? " (showing 50 of " + ipEvents.length + ")" : ""}</div>
          <div class="ipp-events-list">${eventsHtml}${moreEvents}</div>
        </div>
      </div>
    </div>`;
}

function closeIPPivot() {
  document.getElementById("ip-pivot-overlay")?.remove();
}

