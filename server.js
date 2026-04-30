const express = require('express');
const multer  = require('multer');
const http    = require('http');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs   = require('fs');

// ─── IP enrichment (ip-api.com, free, no key) ─────────────────────────────────
const ipCache  = {};                          // ip → { data, ts }
const IP_TTL   = 24 * 60 * 60 * 1000;        // 24 h

const HTTP_TIMEOUT_MS = 6000; // per-request timeout for external calls

function httpPost(host, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req  = http.request(
      { host, path: urlPath, method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } },
      res => {
        let raw = '';
        res.on('data', c => raw += c);
        res.on('end', () => { try { resolve(JSON.parse(raw)); } catch(e) { reject(e); } });
      }
    );
    req.setTimeout(HTTP_TIMEOUT_MS, () => req.destroy(new Error('ip-api timeout')));
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

const ENRICH_DEADLINE_MS = 10000; // max total time for all enrichment batches

async function enrichIPs(ips) {
  const now      = Date.now();
  const deadline = now + ENRICH_DEADLINE_MS;
  const toFetch  = ips.filter(ip => !ipCache[ip] || now - ipCache[ip].ts > IP_TTL);

  for (let i = 0; i < toFetch.length; i += 100) {
    if (Date.now() >= deadline) {
      console.warn('IP enrichment deadline reached, skipping remaining batches');
      break;
    }
    const chunk = toFetch.slice(i, i + 100);
    try {
      const fields  = 'status,message,query,isp,org,as,proxy,hosting,mobile';
      const results = await httpPost('ip-api.com', `/batch?fields=${fields}`, chunk);
      for (const r of results) {
        if (r.status === 'success' && r.query) ipCache[r.query] = { data: r, ts: now };
      }
    } catch (e) {
      console.warn('IP enrichment batch failed:', e.message);
      break;
    }
  }

  const out = {};
  for (const ip of ips) { if (ipCache[ip]) out[ip] = ipCache[ip].data; }
  return out;
}

const app = express();
const PORT = process.env.PORT || 3000;

// Ensure directories exist
const WORKSPACES_DIR = path.join(__dirname, 'workspaces');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
[WORKSPACES_DIR, UPLOADS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Multer: store files in uploads/<workspaceId>/
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(UPLOADS_DIR, req.params.workspaceId);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/json' || file.originalname.endsWith('.json')) {
      cb(null, true);
    } else {
      cb(new Error('Only JSON files allowed'));
    }
  }
});

// ─── Workspace helpers ────────────────────────────────────────────────────────

function getWorkspaceMeta(id) {
  const metaPath = path.join(WORKSPACES_DIR, `${id}.json`);
  if (!fs.existsSync(metaPath)) return null;
  return JSON.parse(fs.readFileSync(metaPath, 'utf8'));
}

function saveWorkspaceMeta(meta) {
  fs.writeFileSync(
    path.join(WORKSPACES_DIR, `${meta.id}.json`),
    JSON.stringify(meta, null, 2)
  );
}

function listWorkspaces() {
  if (!fs.existsSync(WORKSPACES_DIR)) return [];
  return fs.readdirSync(WORKSPACES_DIR)
    .filter(f => f.endsWith('.json') && !f.endsWith('.ips.json'))
    .map(f => JSON.parse(fs.readFileSync(path.join(WORKSPACES_DIR, f), 'utf8')));
}

function getWorkspaceFiles(workspaceId) {
  const dir = path.join(UPLOADS_DIR, workspaceId);
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .map(f => {
      const stat = fs.statSync(path.join(dir, f));
      return { name: f, size: stat.size, uploaded: stat.mtime };
    });
}

// ─── Workspace routes ─────────────────────────────────────────────────────────

// List all workspaces
app.get('/api/workspaces', (req, res) => {
  res.json(listWorkspaces());
});

// Create workspace
app.post('/api/workspaces', (req, res) => {
  const { name, tenant, playbook, homeCountry } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  const meta = {
    id: uuidv4(),
    name,
    tenant: tenant || '',
    playbook: playbook || '',
    homeCountry: (homeCountry || 'ID').toUpperCase(),
    trustedCountries: req.body.trustedCountries || [],
    trustedIPs: req.body.trustedIPs || [],
    ruleThresholds: req.body.ruleThresholds || {},
    createdAt: new Date().toISOString()
  };
  saveWorkspaceMeta(meta);
  res.status(201).json(meta);
});

// Get workspace
app.get('/api/workspaces/:id', (req, res) => {
  const meta = getWorkspaceMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json({ ...meta, files: getWorkspaceFiles(req.params.id) });
});

// Update workspace (name, tenant, playbook)
app.patch('/api/workspaces/:id', (req, res) => {
  const meta = getWorkspaceMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });

  const { name, tenant, playbook, homeCountry, trustedCountries, trustedIPs, ruleThresholds } = req.body;
  if (name) meta.name = name;
  if (tenant !== undefined) meta.tenant = tenant;
  if (playbook !== undefined) meta.playbook = playbook;
  if (homeCountry !== undefined) meta.homeCountry = homeCountry.toUpperCase();
  if (trustedCountries !== undefined) meta.trustedCountries = trustedCountries;
  if (trustedIPs !== undefined) meta.trustedIPs = trustedIPs;
  if (ruleThresholds !== undefined) meta.ruleThresholds = ruleThresholds;
  saveWorkspaceMeta(meta);
  res.json(meta);
});

// Delete workspace
app.delete('/api/workspaces/:id', (req, res) => {
  const metaPath = path.join(WORKSPACES_DIR, `${req.params.id}.json`);
  const uploadsDir = path.join(UPLOADS_DIR, req.params.id);
  if (!fs.existsSync(metaPath)) return res.status(404).json({ error: 'Workspace not found' });

  fs.rmSync(metaPath);
  if (fs.existsSync(uploadsDir)) fs.rmSync(uploadsDir, { recursive: true });
  res.json({ ok: true });
});

// Save detection triage label (TP / FP / INV)
app.post('/api/workspaces/:id/triage', (req, res) => {
  const meta = getWorkspaceMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  const { key, status } = req.body;
  if (!meta.detectionTriages) meta.detectionTriages = {};
  if (!status) delete meta.detectionTriages[key];
  else meta.detectionTriages[key] = status;
  saveWorkspaceMeta(meta);
  res.json({ ok: true, triages: meta.detectionTriages });
});

// Bulk triage — apply multiple triage labels at once
app.post('/api/workspaces/:id/triage/bulk', (req, res) => {
  const meta = getWorkspaceMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  const { triages } = req.body; // array of { key, status }
  if (!Array.isArray(triages)) return res.status(400).json({ error: 'triages must be an array' });
  if (!meta.detectionTriages) meta.detectionTriages = {};
  for (const { key, status } of triages) {
    if (!key) continue;
    if (!status) delete meta.detectionTriages[key];
    else meta.detectionTriages[key] = status;
  }
  saveWorkspaceMeta(meta);
  res.json({ ok: true, triages: meta.detectionTriages });
});

// Save user investigation note
app.post('/api/workspaces/:id/notes', (req, res) => {
  const meta = getWorkspaceMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  const { user, note } = req.body;
  if (!meta.userNotes) meta.userNotes = {};
  if (!note?.trim()) delete meta.userNotes[user];
  else meta.userNotes[user] = note.trim();
  saveWorkspaceMeta(meta);
  res.json({ ok: true });
});

// Save detection investigation comment
app.post('/api/workspaces/:id/comments', (req, res) => {
  const meta = getWorkspaceMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  const { key, comment } = req.body;
  if (!meta.detectionComments) meta.detectionComments = {};
  if (!comment?.trim()) delete meta.detectionComments[key];
  else meta.detectionComments[key] = comment.trim();
  saveWorkspaceMeta(meta);
  res.json({ ok: true });
});

// Toggle user in watch list
app.post('/api/workspaces/:id/watchlist', (req, res) => {
  const meta = getWorkspaceMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  const { user } = req.body;
  if (!meta.watchList) meta.watchList = [];
  const idx = meta.watchList.indexOf(user);
  if (idx === -1) meta.watchList.push(user);
  else meta.watchList.splice(idx, 1);
  saveWorkspaceMeta(meta);
  res.json({ ok: true, watchList: meta.watchList });
});

// ─── File routes ──────────────────────────────────────────────────────────────

// Upload files to workspace
app.post('/api/workspaces/:workspaceId/files', upload.array('files'), (req, res) => {
  const meta = getWorkspaceMeta(req.params.workspaceId);
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json({ uploaded: req.files.map(f => f.originalname) });
});

// Delete a file from workspace
app.delete('/api/workspaces/:workspaceId/files/:filename', (req, res) => {
  const filePath = path.join(UPLOADS_DIR, req.params.workspaceId, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  fs.rmSync(filePath);
  res.json({ ok: true });
});

// ─── JSON partial recovery ────────────────────────────────────────────────────
// Handles truncated JSON arrays (e.g. Entra ID exports cut off mid-file)

function parseJSONSafe(str, filename) {
  // 1. Normal parse
  try { return JSON.parse(str); } catch (e) {
    if (!e.message.includes('Unterminated') && !e.message.includes('Unexpected end')) throw e;
  }

  // 2. File is truncated — recover complete objects up to the last valid '}'
  const trimmed = str.trimEnd();
  if (!trimmed.startsWith('[')) {
    // { value: [...] } format — try to close it
    const lastBrace = trimmed.lastIndexOf('}');
    if (lastBrace > 0) {
      try { return JSON.parse(trimmed.slice(0, lastBrace + 1) + ']}'); } catch(e2) {}
    }
    throw new Error(`Unterminated JSON (non-array root) in ${filename}`);
  }

  // Array root: try appending ']' first (file ended right after last object)
  try { return JSON.parse(trimmed + ']'); } catch(e) {}

  // Find the last top-level object boundary using },{  pattern in a tail window.
  // This is more reliable than lastIndexOf('}') which can land inside a nested object.
  const WINDOW = 65536; // 64 KB tail window
  const tail   = trimmed.length > WINDOW ? trimmed.slice(-WINDOW) : trimmed;
  const tailOffset = trimmed.length - tail.length;

  // Search tail backwards for },{  (top-level array element boundary)
  let cutAt = -1;
  for (let i = tail.length - 1; i >= 1; i--) {
    if (tail[i] === '{' && tail[i - 1] === ',') {
      // Candidate: everything up to (but not including) the ',' before this '{'
      const abs = tailOffset + i - 1; // position of the ',' in trimmed
      const candidate = trimmed.slice(0, abs) + ']';
      try {
        const recovered = JSON.parse(candidate);
        if (Array.isArray(recovered) && recovered.length > 0) {
          console.warn(`[${filename}] Truncated — recovered ${recovered.length} events (},{  boundary)`);
          return recovered;
        }
      } catch(_) {}
    }
  }

  // Last-resort: walk backwards over '}' positions
  let pos = trimmed.length - 1;
  while (pos > 0) {
    pos = trimmed.lastIndexOf('}', pos - 1);
    if (pos === -1) break;
    try {
      const recovered = JSON.parse(trimmed.slice(0, pos + 1) + ']');
      if (Array.isArray(recovered) && recovered.length > 0) {
        console.warn(`[${filename}] Truncated — recovered ${recovered.length} events (} fallback)`);
        return recovered;
      }
    } catch(_) {}
  }

  throw new Error(`Could not recover truncated JSON from ${filename}`);
}

// ─── Analysis route ───────────────────────────────────────────────────────────

// First batch of events returned in the analyze response.
// Detections run on ALL events. Remaining events are fetched via /events endpoint.
const EVENTS_FIRST_BATCH = 5_000;

// Priority order: interactive first, then app, then non-interactive/MSI last
const APPTYPE_PRIORITY = { Interactive: 0, 'Mobile/Desktop': 1, Admin: 2, Legacy: 3, Other: 4, 'Non-Interactive': 5, Service: 6 };
function eventPriority(e) { return APPTYPE_PRIORITY[e.appType] ?? 4; }

// In-memory cache — keyed by workspaceId.
// Stores sorted events + full analysis so unchanged files are served instantly.
const eventsCache = {}; // wsId → { events: [], ts: number, filesSig: string, result: {} }

function getFilesSig(dir) {
  if (!fs.existsSync(dir)) return '';
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .map(f => { const s = fs.statSync(path.join(dir, f)); return `${f}:${s.size}:${s.mtimeMs}`; })
    .join('|');
}

app.get('/api/workspaces/:id/analyze', async (req, res) => {
  try {
    const meta = getWorkspaceMeta(req.params.id);
    if (!meta) return res.status(404).json({ error: 'Workspace not found' });

    const dir = path.join(UPLOADS_DIR, req.params.id);
    if (!fs.existsSync(dir)) return res.json({ events: [], detections: [] });

    // Return cached result instantly if files haven't changed since last analysis
    const filesSig = getFilesSig(dir);
    const hit = eventsCache[req.params.id];
    if (hit && hit.filesSig === filesSig && hit.result) {
      console.log(`[analyze] ${req.params.id}: cache hit — serving instantly`);
      return res.json({ ...hit.result, events: hit.events.slice(0, EVENTS_FIRST_BATCH) });
    }

    const { runDetections } = require('./lib/detections');
    const { normalizeEvents } = require('./lib/parser');
    const { buildUserSummaries, buildAttackTimeline } = require('./lib/summary');

    // Load and merge all JSON files — mutate _sourceFile in-place, no spread copy
    const allEvents     = [];
    const parseWarnings = [];
    for (const filename of fs.readdirSync(dir).filter(f => f.endsWith('.json'))) {
      const filepath = path.join(dir, filename);
      try {
        // Peek at the first 8 KB to detect managedIdentity files before full parse.
        // managedIdentity (MSI) sign-ins are machine-to-machine within Azure infrastructure
        // and provide zero signal for any of the current 18 detection rules — safe to skip.
        const buf = Buffer.allocUnsafe(8192);
        const fd  = fs.openSync(filepath, 'r');
        const n   = fs.readSync(fd, buf, 0, 8192, 0);
        fs.closeSync(fd);
        if (buf.slice(0, n).toString().includes('"managedIdentity"')) {
          console.log(`[analyze] Skipping ${filename} (managedIdentity — not used in current detection rules)`);
          parseWarnings.push({ file: filename, skipped: true, reason: 'managedIdentity' });
          continue;
        }

        const raw    = fs.readFileSync(filepath, 'utf8');
        const parsed = parseJSONSafe(raw, filename);
        const events = Array.isArray(parsed) ? parsed : (parsed.value || []);
        for (const e of events) {
          e._sourceFile = filename;
          allEvents.push(e);
        }
        if (raw.trimEnd().slice(-1) !== ']') {
          parseWarnings.push({ file: filename, recovered: events.length, truncated: true });
        }
      } catch (err) {
        console.error(`Failed to parse ${filename}:`, err.message);
        parseWarnings.push({ file: filename, error: err.message, truncated: true });
      }
    }

    const normalized       = normalizeEvents(allEvents);
    const homeCountry      = meta.homeCountry || 'ID';
    const trustedCountries = (meta.trustedCountries || []).map(c => c.toUpperCase());
    const trustedIPs       = (meta.trustedIPs || []);
    const thresholds       = meta.ruleThresholds || {};

    // Run detections on ALL normalized events
    const detections = runDetections(normalized, { homeCountry, trustedCountries, trustedIPs, thresholds });

    // Geo summary for map
    const geoSummary = {};
    for (const e of normalized) {
      if (!e.country) continue;
      if (!geoSummary[e.country]) geoSummary[e.country] = { total: 0, success: 0, foreign: false };
      geoSummary[e.country].total++;
      if (e.success) geoSummary[e.country].success++;
      if (e.country.toUpperCase() !== homeCountry) geoSummary[e.country].foreign = true;
    }

    // Save attacking IP index for cross-workspace correlation
    const ipIndex = {};
    for (const e of normalized) {
      if (!e.success && e.ipAddress && e.country && e.country.toUpperCase() !== homeCountry) {
        ipIndex[e.ipAddress] = (ipIndex[e.ipAddress] || 0) + 1;
      }
    }
    fs.writeFileSync(
      path.join(WORKSPACES_DIR, `${req.params.id}.ips.json`),
      JSON.stringify({ ips: ipIndex, ts: Date.now(), workspaceName: meta.name })
    );

    // Dashboard summaries
    const userSummaries  = buildUserSummaries(normalized, detections, homeCountry);
    const attackTimeline = buildAttackTimeline(normalized, homeCountry);

    // Breach list cross-match
    const breachList = (meta.breachList || []).map(e => e.toLowerCase().trim()).filter(Boolean);
    const breachMatches = breachList.length > 0
      ? [...new Set(normalized.map(e => e.userPrincipal).filter(Boolean))]
          .filter(u => breachList.includes(u.toLowerCase()))
      : [];

    // Sort ALL events by priority and cache them for paginated /events requests
    const totalEvents = normalized.length;
    const sortedEvents = [...normalized].sort((a, b) => eventPriority(a) - eventPriority(b));

    const eventsLimited = totalEvents > EVENTS_FIRST_BATCH;
    if (eventsLimited) {
      console.warn(`[analyze] ${req.params.id}: ${totalEvents} events — sending first ${EVENTS_FIRST_BATCH}, rest via /events`);
    }

    const analysisResult = {
      total: totalEvents,
      eventsLimited,
      detections,
      homeCountry,
      geoSummary,
      userSummaries,
      attackTimeline,
      ipEnrichment: {},   // loaded separately via /enrich
      parseWarnings,
      breachMatches,
    };

    // Store in cache so repeated requests with unchanged files are instant
    eventsCache[req.params.id] = { events: sortedEvents, ts: Date.now(), filesSig, result: analysisResult };

    res.json({ ...analysisResult, events: sortedEvents.slice(0, EVENTS_FIRST_BATCH) });
  } catch (err) {
    console.error('[analyze] Error:', err.message, err.stack);
    res.status(500).json({ error: `Analysis failed: ${err.message}` });
  }
});

// Cross-workspace IP correlation
app.get('/api/ip-correlation/:workspaceId', (req, res) => {
  const currentId   = req.params.workspaceId;
  const currentFile = path.join(WORKSPACES_DIR, `${currentId}.ips.json`);
  if (!fs.existsSync(currentFile)) return res.json({ correlations: [] });

  const currentData = JSON.parse(fs.readFileSync(currentFile, 'utf8'));
  const currentIPs  = new Set(Object.keys(currentData.ips));
  if (currentIPs.size === 0) return res.json({ correlations: [] });

  const correlations = [];
  for (const ws of listWorkspaces()) {
    if (ws.id === currentId) continue;
    const wsFile = path.join(WORKSPACES_DIR, `${ws.id}.ips.json`);
    if (!fs.existsSync(wsFile)) continue;
    const wsData   = JSON.parse(fs.readFileSync(wsFile, 'utf8'));
    const shared   = Object.keys(wsData.ips).filter(ip => currentIPs.has(ip));
    if (shared.length > 0) {
      correlations.push({
        workspaceId:   ws.id,
        workspaceName: ws.name,
        sharedIPs:     shared.slice(0, 30),
        sharedCount:   shared.length,
      });
    }
  }
  correlations.sort((a, b) => b.sharedCount - a.sharedCount);
  res.json({ correlations, analyzedAt: currentData.ts });
});

// Paginated events — returns cached sorted events in batches after analysis
app.get('/api/workspaces/:id/events', (req, res) => {
  const cache = eventsCache[req.params.id];
  if (!cache) return res.status(404).json({ error: 'No cached events — run analysis first' });
  const offset = Math.max(0, parseInt(req.query.offset) || 0);
  const limit  = Math.min(Math.max(1, parseInt(req.query.limit)  || 5000), 10000);
  res.json({
    events: cache.events.slice(offset, offset + limit),
    total:  cache.events.length,
    offset,
    limit,
  });
});

// IP enrichment — separate async endpoint so analyze responds immediately
app.get('/api/workspaces/:id/enrich', async (req, res) => {
  try {
    const ipsFile = path.join(WORKSPACES_DIR, `${req.params.id}.ips.json`);
    if (!fs.existsSync(ipsFile)) return res.json({ ipEnrichment: {} });
    const { ips } = JSON.parse(fs.readFileSync(ipsFile, 'utf8'));
    const attackingIPs = Object.keys(ips).slice(0, 200);
    const ipEnrichment = await enrichIPs(attackingIPs).catch(() => ({}));
    res.json({ ipEnrichment });
  } catch (err) {
    console.error('[enrich] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`EIDSA running at http://localhost:${PORT}`);
});
