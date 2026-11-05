const express = require('express');
const multer  = require('multer');
const crypto  = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs   = require('fs');

const auth    = require('./lib/auth');
const secrets = require('./lib/secrets');
const enrich  = require('./lib/enrich');
const graph   = require('./lib/graph');
const alerts  = require('./lib/alerts');
const { streamEvents } = require('./lib/jsonstream');
const { runDetections } = require('./lib/detections');
const { runAuditDetections } = require('./lib/audit');
const { normalizeEvent, normalizeAuditEvents, isAuditEvent } = require('./lib/parser');
const { buildUserSummaries, buildAttackTimeline } = require('./lib/summary');

const app = express();
const PORT = process.env.PORT || 3000;

// Ensure directories exist (EIDSA_HOME relocates all state, e.g. for tests)
const HOME_DIR       = process.env.EIDSA_HOME || __dirname;
const WORKSPACES_DIR = path.join(HOME_DIR, 'workspaces');
const UPLOADS_DIR    = path.join(HOME_DIR, 'uploads');
const DATA_DIR       = path.join(HOME_DIR, 'data');   // users, secret key, IP cache
[WORKSPACES_DIR, UPLOADS_DIR, DATA_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

auth.init(DATA_DIR);
secrets.init(DATA_DIR);
enrich.init(DATA_DIR);

app.set('trust proxy', 'loopback');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});
app.use(express.json({ limit: '10mb' })); // user list .txt uploads can be large
app.use(express.static(path.join(__dirname, 'public')));
app.use('/bootstrap-icons', express.static(path.join(__dirname, 'node_modules/bootstrap-icons/font')));

auth.mountRoutes(app);
// Everything else under /api requires a session (viewers are limited to GET)
app.use('/api', auth.requireAuth);
const adminOnly = auth.requireRole('admin');

// Workspace IDs are always UUIDs — reject anything else so params can't escape
// WORKSPACES_DIR / UPLOADS_DIR via path traversal (e.g. "..%2F..").
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function validateWorkspaceId(req, res, next, id) {
  if (!UUID_RE.test(id)) return res.status(400).json({ error: 'Invalid workspace id' });
  next();
}
app.param('id', validateWorkspaceId);
app.param('workspaceId', validateWorkspaceId);

// Uploaded file names must be plain names inside the workspace folder
function isSafeFilename(name) {
  return !!name && name === path.basename(name) && name !== '.' && name !== '..';
}

// Multer: store files in uploads/<workspaceId>/
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(UPLOADS_DIR, req.params.workspaceId);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, path.basename(file.originalname));
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (!getWorkspaceMeta(req.params.workspaceId)) return cb(new Error('Workspace not found'));
    if (!isSafeFilename(path.basename(file.originalname))) return cb(new Error('Invalid file name'));
    if (file.mimetype === 'application/json' || file.originalname.endsWith('.json')) {
      cb(null, true);
    } else {
      cb(new Error('Only JSON files allowed'));
    }
  }
});

// ─── Workspace helpers ────────────────────────────────────────────────────────

const metaPath = id => path.join(WORKSPACES_DIR, `${id}.json`);

// Write via temp file + rename so a crash mid-write never leaves corrupt JSON
function writeJSONAtomic(file, obj, pretty = false) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, pretty ? 2 : 0));
  fs.renameSync(tmp, file);
}

function getWorkspaceMeta(id) {
  if (!fs.existsSync(metaPath(id))) return null;
  const meta = JSON.parse(fs.readFileSync(metaPath(id), 'utf8'));
  // Migrate the old boolean user-filter switch to the 3-state mode
  if (meta.userListMode === undefined && meta.userFilterEnabled !== undefined) {
    meta.userListMode = meta.userFilterEnabled ? 'filter' : 'all';
    delete meta.userFilterEnabled;
  }
  return meta;
}

function saveWorkspaceMeta(meta) {
  writeJSONAtomic(metaPath(meta.id), meta, true);
}

// Re-read, apply a change, save — keeps concurrent background writers from clobbering each other
function updateWorkspaceMeta(id, fn) {
  const meta = getWorkspaceMeta(id);
  if (!meta) return null;
  fn(meta);
  saveWorkspaceMeta(meta);
  return meta;
}

function listWorkspaces() {
  if (!fs.existsSync(WORKSPACES_DIR)) return [];
  return fs.readdirSync(WORKSPACES_DIR)
    .filter(f => UUID_RE.test(f.replace(/\.json$/, '')) && f.endsWith('.json'))
    .map(f => getWorkspaceMeta(f.replace(/\.json$/, '')))
    .filter(Boolean);
}

// Meta as sent to the browser — secrets are never returned, only whether they're set
function publicMeta(meta) {
  const { graph: g, alerts: a, alertedKeys, ...rest } = meta;
  return {
    ...rest,
    timezone: meta.timezone || defaultTimezone(meta.homeCountry),
    userListMode: meta.userListMode || 'all',
    graph: g ? {
      tenantId: g.tenantId || '', clientId: g.clientId || '', hasSecret: !!g.clientSecret,
      streams: g.streams || ['interactive'], days: g.days || 7,
      autoSyncHours: g.autoSyncHours || 0, retentionDays: g.retentionDays || 30,
      lastSync: g.lastSync || null, lastSyncResult: g.lastSyncResult || null,
    } : null,
    alerts: a ? {
      enabled: !!a.enabled, hasWebhook: !!a.webhookUrl,
      format: a.format || 'teams', minSeverity: a.minSeverity || 'high',
      lastAlert: a.lastAlert || null,
    } : null,
  };
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

const TZ_BY_COUNTRY = {
  ID: 'Asia/Jakarta', SG: 'Asia/Singapore', MY: 'Asia/Kuala_Lumpur', PH: 'Asia/Manila',
  TH: 'Asia/Bangkok', VN: 'Asia/Ho_Chi_Minh', IN: 'Asia/Kolkata', JP: 'Asia/Tokyo',
  KR: 'Asia/Seoul', CN: 'Asia/Shanghai', HK: 'Asia/Hong_Kong', AU: 'Australia/Sydney',
  NZ: 'Pacific/Auckland', GB: 'Europe/London', NL: 'Europe/Amsterdam', DE: 'Europe/Berlin',
  FR: 'Europe/Paris', US: 'America/New_York', CA: 'America/Toronto', BR: 'America/Sao_Paulo',
  AE: 'Asia/Dubai', SA: 'Asia/Riyadh',
};
function defaultTimezone(homeCountry) {
  return TZ_BY_COUNTRY[(homeCountry || 'ID').toUpperCase()] || 'UTC';
}
function isValidTimezone(tz) {
  try { new Intl.DateTimeFormat('en-US', { timeZone: tz }); return true; } catch (_) { return false; }
}

// ─── Workspace routes ─────────────────────────────────────────────────────────

// List all workspaces
app.get('/api/workspaces', (req, res) => {
  res.json(listWorkspaces().map(publicMeta));
});

// Create workspace
app.post('/api/workspaces', adminOnly, (req, res) => {
  const { name, tenant, playbook, homeCountry, timezone } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  if (timezone && !isValidTimezone(timezone)) return res.status(400).json({ error: `Unknown timezone "${timezone}"` });

  const meta = {
    id: uuidv4(),
    name,
    tenant: tenant || '',
    playbook: playbook || '',
    homeCountry: (homeCountry || 'ID').toUpperCase(),
    timezone: timezone || defaultTimezone(homeCountry),
    trustedCountries: req.body.trustedCountries || [],
    trustedIPs: req.body.trustedIPs || [],
    ruleThresholds: req.body.ruleThresholds || {},
    breachList: Array.isArray(req.body.breachList) ? req.body.breachList : [],
    createdAt: new Date().toISOString()
  };
  saveWorkspaceMeta(meta);
  res.status(201).json(publicMeta(meta));
});

// Get workspace
app.get('/api/workspaces/:id', (req, res) => {
  const meta = getWorkspaceMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json({ ...publicMeta(meta), files: getWorkspaceFiles(req.params.id) });
});

// Update workspace settings
app.patch('/api/workspaces/:id', (req, res) => {
  const { name, tenant, playbook, homeCountry, timezone, trustedCountries, trustedIPs, ruleThresholds, breachList, userListMode } = req.body;
  if (timezone !== undefined && !isValidTimezone(timezone)) return res.status(400).json({ error: `Unknown timezone "${timezone}"` });
  if (userListMode !== undefined && !['all', 'highlight', 'filter'].includes(userListMode)) {
    return res.status(400).json({ error: 'userListMode must be all, highlight or filter' });
  }
  const meta = updateWorkspaceMeta(req.params.id, m => {
    if (name) m.name = name;
    if (tenant !== undefined) m.tenant = tenant;
    if (playbook !== undefined) m.playbook = playbook;
    if (homeCountry !== undefined) m.homeCountry = homeCountry.toUpperCase();
    if (timezone !== undefined) m.timezone = timezone;
    if (trustedCountries !== undefined) m.trustedCountries = trustedCountries;
    if (trustedIPs !== undefined) m.trustedIPs = trustedIPs;
    if (ruleThresholds !== undefined) m.ruleThresholds = ruleThresholds;
    if (Array.isArray(breachList)) m.breachList = breachList;
    if (userListMode !== undefined) m.userListMode = userListMode;
  });
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json(publicMeta(meta));
});

// Upload target user list (.txt, one userPrincipalName per line).
// userListMode: 'filter' → analyze only these users, 'highlight' → analyze all but mark them.
app.put('/api/workspaces/:id/userlist', (req, res) => {
  const { filename, content } = req.body;
  if (typeof content !== 'string') return res.status(400).json({ error: 'content must be a string' });

  const users = [...new Set(
    content.replace(/^﻿/, '')
      .split(/[\r\n,;]+/)
      .map(s => s.trim().toLowerCase())
      .filter(s => s && !s.startsWith('#'))
  )];
  if (users.length === 0) return res.status(400).json({ error: 'No user principal names found in file' });

  const meta = updateWorkspaceMeta(req.params.id, m => {
    m.userList = { filename: path.basename(filename || 'users.txt'), users, uploadedAt: new Date().toISOString() };
    if (!m.userListMode || m.userListMode === 'all') m.userListMode = 'filter';
  });
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json(publicMeta(meta));
});

app.delete('/api/workspaces/:id/userlist', (req, res) => {
  const meta = updateWorkspaceMeta(req.params.id, m => {
    delete m.userList;
    m.userListMode = 'all';
  });
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json(publicMeta(meta));
});

// Delete workspace
app.delete('/api/workspaces/:id', adminOnly, (req, res) => {
  const uploadsDir = path.join(UPLOADS_DIR, req.params.id);
  if (!fs.existsSync(metaPath(req.params.id))) return res.status(404).json({ error: 'Workspace not found' });

  fs.rmSync(metaPath(req.params.id));
  for (const ext of ['ips', 'summary']) {
    fs.rmSync(path.join(WORKSPACES_DIR, `${req.params.id}.${ext}.json`), { force: true });
  }
  eventsCache.delete(req.params.id);
  if (fs.existsSync(uploadsDir)) fs.rmSync(uploadsDir, { recursive: true });
  res.json({ ok: true });
});

// Save detection triage label (TP / FP / INV)
app.post('/api/workspaces/:id/triage', (req, res) => {
  const { key, status } = req.body;
  const meta = updateWorkspaceMeta(req.params.id, m => {
    if (!m.detectionTriages) m.detectionTriages = {};
    if (!status) delete m.detectionTriages[key];
    else m.detectionTriages[key] = status;
  });
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json({ ok: true, triages: meta.detectionTriages });
});

// Bulk triage — apply multiple triage labels at once
app.post('/api/workspaces/:id/triage/bulk', (req, res) => {
  const { triages } = req.body; // array of { key, status }
  if (!Array.isArray(triages)) return res.status(400).json({ error: 'triages must be an array' });
  const meta = updateWorkspaceMeta(req.params.id, m => {
    if (!m.detectionTriages) m.detectionTriages = {};
    for (const { key, status } of triages) {
      if (!key) continue;
      if (!status) delete m.detectionTriages[key];
      else m.detectionTriages[key] = status;
    }
  });
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json({ ok: true, triages: meta.detectionTriages });
});

// Save user investigation note
app.post('/api/workspaces/:id/notes', (req, res) => {
  const { user, note } = req.body;
  const meta = updateWorkspaceMeta(req.params.id, m => {
    if (!m.userNotes) m.userNotes = {};
    if (!note?.trim()) delete m.userNotes[user];
    else m.userNotes[user] = note.trim();
  });
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json({ ok: true });
});

// Save detection investigation comment
app.post('/api/workspaces/:id/comments', (req, res) => {
  const { key, comment } = req.body;
  const meta = updateWorkspaceMeta(req.params.id, m => {
    if (!m.detectionComments) m.detectionComments = {};
    if (!comment?.trim()) delete m.detectionComments[key];
    else m.detectionComments[key] = comment.trim();
  });
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json({ ok: true });
});

// Toggle user in watch list
app.post('/api/workspaces/:id/watchlist', (req, res) => {
  const { user } = req.body;
  const meta = updateWorkspaceMeta(req.params.id, m => {
    if (!m.watchList) m.watchList = [];
    const idx = m.watchList.indexOf(user);
    if (idx === -1) m.watchList.push(user);
    else m.watchList.splice(idx, 1);
  });
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json({ ok: true, watchList: meta.watchList });
});

// Drift baseline — shared by everyone on the team (was per-browser localStorage)
app.post('/api/workspaces/:id/baseline', (req, res) => {
  const { metrics } = req.body;
  if (!metrics || typeof metrics !== 'object') return res.status(400).json({ error: 'metrics required' });
  const meta = updateWorkspaceMeta(req.params.id, m => { m.baseline = { ts: Date.now(), metrics, by: req.user.username }; });
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json({ ok: true, baseline: meta.baseline });
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
  if (!isSafeFilename(req.params.filename)) return res.status(400).json({ error: 'Invalid file name' });
  const filePath = path.join(UPLOADS_DIR, req.params.workspaceId, req.params.filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  fs.rmSync(filePath);
  res.json({ ok: true });
});

// ─── Analysis ─────────────────────────────────────────────────────────────────

// First batch of events returned in the analyze response.
// Detections run on ALL events. Remaining events are fetched via /events endpoint.
const EVENTS_FIRST_BATCH = 5_000;

// Priority order: interactive first, then app, then non-interactive/MSI last
const APPTYPE_PRIORITY = { Interactive: 0, 'Mobile/Desktop': 1, Admin: 2, Legacy: 3, Other: 4, 'Non-Interactive': 5, Service: 6 };
function eventPriority(e) { return APPTYPE_PRIORITY[e.appType] ?? 4; }

// In-memory LRU cache of sorted events + full analysis per workspace, so
// unchanged files are served instantly. Bounded so memory doesn't grow with
// every workspace ever analyzed.
const CACHE_MAX_WORKSPACES = parseInt(process.env.EIDSA_CACHE_WORKSPACES, 10) || 3;
const CACHE_TTL_MS = 2 * 3600000;
const eventsCache = new Map(); // wsId → { events, ts, filesSig, result }

function cacheGet(id) {
  const hit = eventsCache.get(id);
  if (!hit) return null;
  if (Date.now() - hit.ts > CACHE_TTL_MS) { eventsCache.delete(id); return null; }
  eventsCache.delete(id); eventsCache.set(id, hit); // mark most recently used
  return hit;
}
function cacheSet(id, entry) {
  eventsCache.delete(id);
  eventsCache.set(id, entry);
  while (eventsCache.size > CACHE_MAX_WORKSPACES) eventsCache.delete(eventsCache.keys().next().value);
}
setInterval(() => {
  for (const [id, hit] of eventsCache) if (Date.now() - hit.ts > CACHE_TTL_MS) eventsCache.delete(id);
}, 10 * 60000).unref();

function getFilesSig(dir) {
  if (!fs.existsSync(dir)) return '';
  return fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .map(f => { const s = fs.statSync(path.join(dir, f)); return `${f}:${s.size}:${s.mtimeMs}`; })
    .join('|');
}

// Settings that change detection output — part of the cache key so edits take effect
function configSig(meta) {
  const relevant = {
    h: meta.homeCountry, tz: meta.timezone, tc: meta.trustedCountries, ti: meta.trustedIPs,
    th: meta.ruleThresholds, b: meta.breachList,
  };
  return crypto.createHash('sha1').update(JSON.stringify(relevant)).digest('hex').slice(0, 12);
}

const analysisInFlight = new Map(); // wsId → Promise (dedupe concurrent runs)

/**
 * Load every file of a workspace, run all detections and build the dashboard data.
 * @returns { result, events } or null if the workspace has no upload folder
 */
async function analyzeWorkspace(id) {
  if (analysisInFlight.has(id)) return analysisInFlight.get(id);
  const p = doAnalyze(id).finally(() => analysisInFlight.delete(id));
  analysisInFlight.set(id, p);
  return p;
}

async function doAnalyze(id) {
  const meta = getWorkspaceMeta(id);
  if (!meta) throw Object.assign(new Error('Workspace not found'), { status: 404 });

  const dir = path.join(UPLOADS_DIR, id);
  if (!fs.existsSync(dir)) return null;

  // Target user list — 'filter' restricts analysis, 'highlight' only marks the users
  const mode        = meta.userListMode || 'all';
  const listedUsers = mode !== 'all' ? (meta.userList?.users || []) : [];
  const listSet     = listedUsers.length > 0 ? new Set(listedUsers) : null;
  const filtering   = !!listSet && mode === 'filter';

  // Return cached result instantly if files, settings and user filter haven't changed
  const filesSig = getFilesSig(dir) + `|cfg:${configSig(meta)}` +
    (listSet ? `|users:${mode}:${listedUsers.length}:${meta.userList.uploadedAt}` : '');
  const hit = cacheGet(id);
  if (hit && hit.filesSig === filesSig && hit.result) {
    console.log(`[analyze] ${id}: cache hit — serving instantly`);
    return { result: hit.result, events: hit.events, cached: true };
  }

  // Stream every JSON file, normalizing sign-ins on the fly (raw objects are
  // dropped immediately), splitting out audit events and de-duplicating by id
  // (overlapping manual exports / Graph syncs).
  const allNormalized = [];
  const rawAudit      = [];
  const seenIds       = new Set();
  const parseWarnings = [];
  let duplicates = 0;

  for (const filename of fs.readdirSync(dir).filter(f => f.endsWith('.json'))) {
    let msi = 0;
    try {
      const { count, truncated, badObjects } = await streamEvents(path.join(dir, filename), raw => {
        if (raw.id) {
          if (seenIds.has(raw.id)) { duplicates++; return; }
          seenIds.add(raw.id);
        }
        raw._sourceFile = filename;
        if (isAuditEvent(raw)) { rawAudit.push(raw); return; }
        // managedIdentity (MSI) sign-ins are machine-to-machine within Azure
        // infrastructure and provide no signal for the detection rules
        if ((raw.signInEventTypes || []).includes('managedIdentity')) { msi++; return; }
        const n = normalizeEvent(raw);
        if (n.userPrincipal || n.createdAt) allNormalized.push(n);
      });
      if (count === 0 && !truncated) {
        parseWarnings.push({ file: filename, error: 'No events array found in file', truncated: true });
      } else if (truncated) {
        parseWarnings.push({ file: filename, recovered: count, truncated: true });
      }
      if (badObjects) parseWarnings.push({ file: filename, error: `${badObjects} malformed event(s) skipped`, truncated: true });
      if (msi) parseWarnings.push({ file: filename, skipped: true, reason: 'managedIdentity', count: msi });
    } catch (err) {
      console.error(`Failed to read ${filename}:`, err.message);
      parseWarnings.push({ file: filename, error: err.message, truncated: true });
    }
  }

  const inList = u => listSet.has((u || '').toLowerCase());
  const normalized = filtering ? allNormalized.filter(e => inList(e.userPrincipal)) : allNormalized;
  let auditEvents  = normalizeAuditEvents(rawAudit);
  if (filtering) auditEvents = auditEvents.filter(e => inList(e.initiatorUser) || e.targets.some(t => inList(t.userPrincipal)));

  const homeCountry      = meta.homeCountry || 'ID';
  const trustedCountries = (meta.trustedCountries || []).map(c => c.toUpperCase());
  const trustedIPs       = (meta.trustedIPs || []);
  const thresholds       = meta.ruleThresholds || {};
  const timezone         = meta.timezone || defaultTimezone(homeCountry);

  // Run detections on ALL normalized events, then correlate audit logs with them
  const signinDetections = runDetections(normalized, {
    homeCountry, trustedCountries, trustedIPs, thresholds, timezone, asnLookup: enrich.asnOf,
  });
  const auditDetections = runAuditDetections(auditEvents, {
    signins: normalized, signinDetections, homeCountry, trustedCountries,
  });
  const detections = [...signinDetections, ...auditDetections];

  const home = homeCountry.toUpperCase();

  // Geo summary for map
  const geoSummary = {};
  for (const e of normalized) {
    if (!e.country) continue;
    if (!geoSummary[e.country]) geoSummary[e.country] = { total: 0, success: 0, foreign: false };
    geoSummary[e.country].total++;
    if (e.success) geoSummary[e.country].success++;
    if (e.country.toUpperCase() !== home) geoSummary[e.country].foreign = true;
  }

  // Save attacking IP index for cross-workspace correlation
  // (always from all events, so correlation doesn't depend on the user filter)
  const ipIndex = {};
  for (const e of allNormalized) {
    if (!e.success && !e.interrupted && e.ipAddress && e.country && e.country.toUpperCase() !== home) {
      ipIndex[e.ipAddress] = (ipIndex[e.ipAddress] || 0) + 1;
    }
  }
  writeJSONAtomic(path.join(WORKSPACES_DIR, `${id}.ips.json`), { ips: ipIndex, ts: Date.now(), workspaceName: meta.name });

  // Dashboard summaries
  const userSummaries  = buildUserSummaries(normalized, detections, homeCountry);
  const attackTimeline = buildAttackTimeline(normalized, homeCountry);

  // Breach list cross-match
  const breachList = new Set((meta.breachList || []).map(e => e.toLowerCase().trim()).filter(Boolean));
  const breachMatches = breachList.size > 0
    ? [...new Set(normalized.map(e => e.userPrincipal).filter(Boolean))].filter(u => breachList.has(u.toLowerCase()))
    : [];

  // Which listed users actually appear in the logs
  let userFilterInfo = { enabled: false, mode: 'all' };
  if (listSet) {
    const seen = new Set(normalized.map(e => e.userPrincipal.toLowerCase()));
    const unmatched = listedUsers.filter(u => !seen.has(u));
    const flagged = new Set();
    for (const d of detections) {
      for (const u of [d.user, ...(d.affectedUsers || [])]) if (u && inList(u)) flagged.add(u);
    }
    userFilterInfo = {
      enabled:        filtering,
      mode,
      filename:       meta.userList.filename,
      listed:         listedUsers.length,
      matched:        listedUsers.length - unmatched.length,
      unmatched:      unmatched.slice(0, 500),
      unmatchedCount: unmatched.length,
      users:          mode === 'highlight' ? listedUsers : undefined,
      flaggedUsers:   [...flagged],
      totalAllEvents: allNormalized.length,
    };
  }

  // Sort ALL events by priority and cache them for paginated /events requests
  const totalEvents  = normalized.length;
  const sortedEvents = [...normalized].sort((a, b) => eventPriority(a) - eventPriority(b));

  const eventsLimited = totalEvents > EVENTS_FIRST_BATCH;
  if (eventsLimited) {
    console.warn(`[analyze] ${id}: ${totalEvents} events — sending first ${EVENTS_FIRST_BATCH}, rest via /events`);
  }

  const compromisedSet = new Set();
  for (const d of detections) {
    if (d.user) compromisedSet.add(d.user);
    if (d.affectedUsers) d.affectedUsers.forEach(u => compromisedSet.add(u));
  }
  let successful = 0, failed = 0, interrupted = 0, foreignLogins = 0;
  let firstTs = Infinity, lastTs = 0;
  const ipAgg = {}, ctryAgg = {};
  for (const e of normalized) {
    if (e.success) {
      successful++;
      if (e.country && e.country.toUpperCase() !== home) foreignLogins++;
    } else if (e.interrupted) interrupted++;
    else failed++;

    if (e.ts) { if (e.ts < firstTs) firstTs = e.ts; if (e.ts > lastTs) lastTs = e.ts; }
    if (e.country) {
      const c = ctryAgg[e.country] || (ctryAgg[e.country] = { country: e.country, total: 0, success: 0, failed: 0 });
      c.total++;
      if (e.success) c.success++; else if (!e.interrupted) c.failed++;
    }
    // Foreign source IPs — the attacker infrastructure section of the report
    if (e.ipAddress && e.country && e.country.toUpperCase() !== home) {
      const a = ipAgg[e.ipAddress] || (ipAgg[e.ipAddress] = { ip: e.ipAddress, country: e.country, city: e.city, failed: 0, success: 0, users: new Set() });
      if (e.success) a.success++; else if (!e.interrupted) a.failed++;
      if (e.userPrincipal) a.users.add(e.userPrincipal);
    }
  }
  const reportStats = {
    firstEvent: firstTs === Infinity ? null : new Date(firstTs).toISOString(),
    lastEvent:  lastTs ? new Date(lastTs).toISOString() : null,
    topAttackerIPs: Object.values(ipAgg)
      .sort((a, b) => (b.success * 50 + b.failed + b.users.size * 5) - (a.success * 50 + a.failed + a.users.size * 5))
      .slice(0, 20)
      .map(a => ({ ip: a.ip, country: a.country, city: a.city, failed: a.failed, success: a.success, users: a.users.size })),
    topCountries: Object.values(ctryAgg).sort((a, b) => b.total - a.total).slice(0, 15),
  };
  const stats = {
    total:            totalEvents,
    successful,
    failed,                     // real credential failures (interrupts excluded)
    interrupted,                // MFA prompts, KMSI, password-change interrupts
    uniqueUsers:      new Set(normalized.map(e => e.userPrincipal).filter(Boolean)).size,
    uniqueCountries:  new Set(normalized.map(e => e.country).filter(Boolean)).size,
    foreignLogins,
    compromisedUsers: compromisedSet.size,
    highFindings:     detections.filter(d => d.severity === 'high').length,
    auditEvents:      auditEvents.length,
    duplicatesSkipped: duplicates,
  };

  const result = {
    total: totalEvents,
    eventsLimited,
    filesSig,           // client uses this as IndexedDB cache key
    stats,
    detections,
    homeCountry,
    timezone,
    geoSummary,
    userSummaries,
    attackTimeline,
    ipEnrichment: {},   // loaded separately via /enrich
    parseWarnings,
    breachMatches,
    userFilter: userFilterInfo,
    reportStats,
  };

  cacheSet(id, { events: sortedEvents, ts: Date.now(), filesSig, result });
  writeSummary(meta, result);
  sendAlerts(id, detections, userSummaries).catch(e => console.warn(`[alerts] ${meta.name}:`, e.message));

  return { result, events: sortedEvents, cached: false };
}

// Compact per-workspace snapshot for the cross-tenant overview dashboard
function writeSummary(meta, result) {
  const riskCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0 };
  for (const s of result.userSummaries) riskCounts[s.riskLevel] = (riskCounts[s.riskLevel] || 0) + 1;
  const detectionCounts = {};
  for (const d of result.detections) detectionCounts[d.type] = (detectionCounts[d.type] || 0) + 1;
  writeJSONAtomic(path.join(WORKSPACES_DIR, `${meta.id}.summary.json`), {
    ts: Date.now(),
    workspaceName: meta.name,
    filtered: result.userFilter.enabled,
    stats: result.stats,
    riskCounts,
    detectionCounts,
    topUsers: result.userSummaries.slice(0, 5).map(s => ({ user: s.user, riskLevel: s.riskLevel, riskScore: s.riskScore, primaryThreat: s.primaryThreat })),
  });
}

async function sendAlerts(id, detections, userSummaries) {
  const meta = getWorkspaceMeta(id);
  const cfg = meta?.alerts;
  if (!cfg?.enabled || !cfg.webhookUrl) return;
  const sentKeys = await alerts.dispatch({
    url: secrets.decrypt(cfg.webhookUrl),
    format: cfg.format,
    minSeverity: cfg.minSeverity,
    alertedKeys: meta.alertedKeys || [],
    workspaceName: meta.name,
    detections,
    userSummaries,
    appUrl: process.env.EIDSA_PUBLIC_URL || '',
  });
  if (sentKeys.length === 0) return;
  console.log(`[alerts] ${meta.name}: sent ${sentKeys.length} alert(s)`);
  updateWorkspaceMeta(id, m => {
    m.alertedKeys = alerts.mergeKeys(m.alertedKeys, sentKeys);
    m.alerts.lastAlert = { ts: Date.now(), count: sentKeys.length };
  });
}

app.get('/api/workspaces/:id/analyze', async (req, res) => {
  try {
    const out = await analyzeWorkspace(req.params.id);
    if (!out) return res.json({ events: [], detections: [] });
    res.json({ ...out.result, events: out.events.slice(0, EVENTS_FIRST_BATCH) });
  } catch (err) {
    console.error('[analyze] Error:', err.message, err.stack);
    res.status(err.status || 500).json({ error: err.status ? err.message : `Analysis failed: ${err.message}` });
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
  const cache = cacheGet(req.params.id);
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
    // Most active attacking IPs first
    const attackingIPs = Object.entries(ips).sort((a, b) => b[1] - a[1]).slice(0, 200).map(([ip]) => ip);
    const ipEnrichment = await enrich.enrichIPs(attackingIPs).catch(() => ({}));
    res.json({ ipEnrichment });
  } catch (err) {
    console.error('[enrich] Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── Cross-tenant overview ────────────────────────────────────────────────────

app.get('/api/overview', (req, res) => {
  const rows = listWorkspaces().map(ws => {
    const f = path.join(WORKSPACES_DIR, `${ws.id}.summary.json`);
    const summary = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : null;
    return {
      id: ws.id, name: ws.name, tenant: ws.tenant, homeCountry: ws.homeCountry,
      files: getWorkspaceFiles(ws.id).length,
      lastSync: ws.graph?.lastSync || null,
      autoSync: !!ws.graph?.autoSyncHours,
      summary,
    };
  });
  res.json(rows);
});

// ─── Integrations: Microsoft Graph + alert webhook (admin) ────────────────────

app.put('/api/workspaces/:id/integrations', adminOnly, (req, res) => {
  const { graph: g, alerts: a } = req.body || {};
  if (g?.tenantId && !/^[0-9a-zA-Z.-]{3,}$/.test(g.tenantId)) return res.status(400).json({ error: 'Invalid tenant id' });
  if (g?.streams && !g.streams.every(s => graph.STREAMS.includes(s))) return res.status(400).json({ error: `streams must be within ${graph.STREAMS.join(', ')}` });
  if (a?.webhookUrl && !/^https:\/\//i.test(a.webhookUrl)) return res.status(400).json({ error: 'Webhook URL must use https://' });

  const meta = updateWorkspaceMeta(req.params.id, m => {
    if (g) {
      const cur = m.graph || {};
      m.graph = {
        ...cur,
        tenantId:      g.tenantId ?? cur.tenantId ?? '',
        clientId:      g.clientId ?? cur.clientId ?? '',
        // empty / missing secret keeps the stored one
        clientSecret:  g.clientSecret ? secrets.encrypt(g.clientSecret) : cur.clientSecret || '',
        streams:       g.streams || cur.streams || ['interactive'],
        days:          Math.min(Math.max(parseInt(g.days) || cur.days || 7, 1), 30),
        autoSyncHours: Math.max(parseInt(g.autoSyncHours) || 0, 0),
        retentionDays: Math.max(parseInt(g.retentionDays) || cur.retentionDays || 30, 1),
      };
      if (g.clearSecret) m.graph.clientSecret = '';
    }
    if (a) {
      const cur = m.alerts || {};
      m.alerts = {
        ...cur,
        enabled:     !!a.enabled,
        format:      ['teams', 'slack', 'generic'].includes(a.format) ? a.format : cur.format || 'teams',
        minSeverity: ['medium', 'high'].includes(a.minSeverity) ? a.minSeverity : cur.minSeverity || 'high',
        webhookUrl:  a.webhookUrl ? secrets.encrypt(a.webhookUrl) : cur.webhookUrl || '',
      };
      if (a.clearWebhook) m.alerts.webhookUrl = '';
    }
  });
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  res.json(publicMeta(meta));
});

function graphCreds(meta) {
  const g = meta.graph || {};
  if (!g.tenantId || !g.clientId || !g.clientSecret) return null;
  return { tenantId: g.tenantId, clientId: g.clientId, clientSecret: secrets.decrypt(g.clientSecret) };
}

app.post('/api/workspaces/:id/graph/test', adminOnly, async (req, res) => {
  const meta = getWorkspaceMeta(req.params.id);
  if (!meta) return res.status(404).json({ error: 'Workspace not found' });
  const creds = graphCreds(meta);
  if (!creds) return res.status(400).json({ error: 'Tenant ID, Client ID and Client Secret are required' });
  try {
    await graph.testConnection(creds);
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

const syncJobs = {}; // wsId → { status, startedAt, progress, results, error }

async function runGraphSync(id, { analyze = true } = {}) {
  if (syncJobs[id]?.status === 'running') return syncJobs[id];
  const meta = getWorkspaceMeta(id);
  const creds = meta && graphCreds(meta);
  if (!creds) throw Object.assign(new Error('Microsoft Graph is not configured for this workspace'), { status: 400 });

  const job = syncJobs[id] = { status: 'running', startedAt: Date.now(), progress: {}, results: null, error: null };
  (async () => {
    try {
      const g = meta.graph;
      const dir = path.join(UPLOADS_DIR, id);
      fs.mkdirSync(dir, { recursive: true });
      // Incremental after the first sync (10 min overlap; duplicates are removed by id)
      const since = g.lastSync
        ? new Date(Math.max(Date.parse(g.lastSync) - 10 * 60000, Date.now() - g.days * 86400000))
        : new Date(Date.now() - (g.days || 7) * 86400000);
      const startedIso = new Date().toISOString();
      job.results = await graph.sync(creds, {
        since, streams: g.streams || ['interactive'], dir,
        onProgress: (stream, n) => { job.progress[stream] = n; },
      });

      // Retention: drop old Graph pulls (manual uploads are never touched)
      const cutoff = Date.now() - (g.retentionDays || 30) * 86400000;
      for (const f of fs.readdirSync(dir)) {
        if (f.startsWith('graph-') && fs.statSync(path.join(dir, f)).mtimeMs < cutoff) fs.rmSync(path.join(dir, f));
      }

      updateWorkspaceMeta(id, m => {
        m.graph.lastSync = startedIso;
        m.graph.lastSyncResult = { ok: true, results: job.results };
      });
      if (analyze) { job.status = 'analyzing'; await analyzeWorkspace(id); }
      job.status = 'done';
    } catch (e) {
      console.error(`[graph] sync ${id} failed:`, e.message);
      job.status = 'error';
      job.error = e.message;
      updateWorkspaceMeta(id, m => { if (m.graph) m.graph.lastSyncResult = { ok: false, error: e.message, ts: Date.now() }; });
    } finally {
      job.finishedAt = Date.now();
    }
  })();
  return job;
}

app.post('/api/workspaces/:id/graph/sync', async (req, res) => {
  try {
    res.json(await runGraphSync(req.params.id, { analyze: req.body?.analyze !== false }));
  } catch (e) {
    res.status(e.status || 500).json({ error: e.message });
  }
});

app.get('/api/workspaces/:id/graph/sync', (req, res) => {
  res.json(syncJobs[req.params.id] || { status: 'idle' });
});

app.post('/api/workspaces/:id/alerts/test', adminOnly, async (req, res) => {
  const meta = getWorkspaceMeta(req.params.id);
  if (!meta?.alerts?.webhookUrl) return res.status(400).json({ error: 'No webhook configured' });
  try {
    const sample = [{ type: 'TEST', severity: 'high', message: `Test alert from EIDSA workspace "${meta.name}"` }];
    await alerts.send(secrets.decrypt(meta.alerts.webhookUrl), alerts.buildPayload(meta.alerts.format, {
      workspaceName: meta.name, detections: sample, criticalUsers: [], appUrl: process.env.EIDSA_PUBLIC_URL || '',
    }));
    res.json({ ok: true });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

// Auto-sync scheduler: every 5 min, sync workspaces whose interval has elapsed
setInterval(() => {
  for (const ws of listWorkspaces()) {
    const g = ws.graph;
    if (!g?.autoSyncHours || !g.clientSecret) continue;
    const last = g.lastSync ? Date.parse(g.lastSync) : 0;
    if (Date.now() - last < g.autoSyncHours * 3600000) continue;
    console.log(`[graph] auto-sync ${ws.name}`);
    runGraphSync(ws.id).catch(e => console.warn(`[graph] auto-sync ${ws.name}:`, e.message));
  }
}, 5 * 60000).unref();

// ─── Errors ───────────────────────────────────────────────────────────────────

// Multer / body-parser errors → JSON instead of an HTML stack page
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res.status(err.status || 400).json({ error: err.message || 'Request failed' });
});

// ─── Start ────────────────────────────────────────────────────────────────────

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`EIDSA running at http://localhost:${PORT}`);
    if (!auth.enabled()) console.warn('⚠ Authentication is DISABLED (EIDSA_AUTH=off) — do not expose this port.');
  });
}

module.exports = { app, analyzeWorkspace };
