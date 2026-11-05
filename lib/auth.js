/**
 * Local user accounts + session cookies + role-based access.
 *
 * Roles:
 *   viewer  — read-only (GET)
 *   analyst — investigate: upload, analyze, triage, notes, sync
 *   admin   — everything, incl. workspace create/delete, integrations, users
 *
 * Users live in data/users.json (scrypt password hashes). Sessions are kept in
 * memory, so a server restart signs everyone out. Set EIDSA_AUTH=off to disable
 * authentication entirely (single-user local use only).
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const ROLES        = ['viewer', 'analyst', 'admin'];
const SESSION_TTL  = 12 * 3600000;
const COOKIE       = 'eidsa_session';
const MAX_ATTEMPTS = 10;           // failed logins per IP per window
const LOCK_WINDOW  = 15 * 60000;

let usersPath = '';
const sessions = new Map();         // token → { username, role, expires }
const loginFails = new Map();       // ip → { count, first }

const enabled = () => (process.env.EIDSA_AUTH || 'on').toLowerCase() !== 'off';

function init(dataDir) {
  usersPath = path.join(dataDir, 'users.json');
}

function loadUsers() {
  if (!fs.existsSync(usersPath)) return [];
  return JSON.parse(fs.readFileSync(usersPath, 'utf8'));
}

function saveUsers(users) {
  const tmp = usersPath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, usersPath);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt:${salt.toString('hex')}:${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  const [, saltHex, hashHex] = (stored || '').split(':');
  if (!saltHex || !hashHex) return false;
  const hash = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), 64);
  return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

function validateNewUser({ username, password, role }) {
  if (!username || !/^[a-zA-Z0-9._@-]{3,64}$/.test(username)) return 'Username must be 3–64 chars (letters, digits, . _ @ -)';
  if (!password || password.length < 10) return 'Password must be at least 10 characters';
  if (role && !ROLES.includes(role)) return `Role must be one of ${ROLES.join(', ')}`;
  return null;
}

function publicUser(u) {
  return { username: u.username, role: u.role, createdAt: u.createdAt };
}

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function setSessionCookie(req, res, token, maxAgeMs) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(maxAgeMs / 1000)}${secure}`);
}

function getSession(req) {
  const token = parseCookies(req)[COOKIE];
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (s.expires < Date.now()) { sessions.delete(token); return null; }
  return { ...s, token };
}

// ─── Middleware ───────────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (!enabled()) { req.user = { username: 'local', role: 'admin' }; return next(); }
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: 'Authentication required' });
  req.user = { username: s.username, role: s.role };
  // viewers are read-only
  if (s.role === 'viewer' && req.method !== 'GET') return res.status(403).json({ error: 'Read-only account' });
  next();
}

function requireRole(role) {
  const need = ROLES.indexOf(role);
  return (req, res, next) => {
    if (ROLES.indexOf(req.user?.role) < need) return res.status(403).json({ error: `Requires ${role} role` });
    next();
  };
}

// ─── Routes ───────────────────────────────────────────────────────────────────

function mountRoutes(app) {
  app.get('/api/auth/status', (req, res) => {
    if (!enabled()) return res.json({ enabled: false, user: { username: 'local', role: 'admin' } });
    const s = getSession(req);
    res.json({ enabled: true, needsSetup: loadUsers().length === 0, user: s ? { username: s.username, role: s.role } : null });
  });

  // First-run: create the initial admin (only while no users exist)
  app.post('/api/auth/setup', (req, res) => {
    if (!enabled()) return res.status(400).json({ error: 'Authentication is disabled' });
    const users = loadUsers();
    if (users.length > 0) return res.status(409).json({ error: 'Setup already completed' });
    const { username, password } = req.body || {};
    const err = validateNewUser({ username, password });
    if (err) return res.status(400).json({ error: err });
    users.push({ username, role: 'admin', passwordHash: hashPassword(password), createdAt: new Date().toISOString() });
    saveUsers(users);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { username, role: 'admin', expires: Date.now() + SESSION_TTL });
    setSessionCookie(req, res, token, SESSION_TTL);
    res.json({ ok: true, user: { username, role: 'admin' } });
  });

  app.post('/api/auth/login', (req, res) => {
    const ip = req.ip;
    const f = loginFails.get(ip);
    if (f && Date.now() - f.first < LOCK_WINDOW && f.count >= MAX_ATTEMPTS) {
      return res.status(429).json({ error: 'Too many failed attempts — try again later' });
    }
    const { username, password } = req.body || {};
    const user = loadUsers().find(u => u.username === username);
    if (!user || !verifyPassword(String(password || ''), user.passwordHash)) {
      const cur = f && Date.now() - f.first < LOCK_WINDOW ? f : { count: 0, first: Date.now() };
      cur.count++;
      loginFails.set(ip, cur);
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    loginFails.delete(ip);
    const token = crypto.randomBytes(32).toString('hex');
    sessions.set(token, { username: user.username, role: user.role, expires: Date.now() + SESSION_TTL });
    setSessionCookie(req, res, token, SESSION_TTL);
    res.json({ ok: true, user: publicUser(user) });
  });

  app.post('/api/auth/logout', (req, res) => {
    const s = getSession(req);
    if (s) sessions.delete(s.token);
    setSessionCookie(req, res, '', 0);
    res.json({ ok: true });
  });

  app.post('/api/auth/password', requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    const users = loadUsers();
    const user = users.find(u => u.username === req.user.username);
    if (!user || !verifyPassword(String(currentPassword || ''), user.passwordHash)) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    const err = validateNewUser({ username: user.username, password: newPassword });
    if (err) return res.status(400).json({ error: err });
    user.passwordHash = hashPassword(newPassword);
    saveUsers(users);
    res.json({ ok: true });
  });

  // ── User management (admin) ────────────────────────────────────────────────
  app.get('/api/users', requireAuth, requireRole('admin'), (req, res) => {
    res.json(loadUsers().map(publicUser));
  });

  app.post('/api/users', requireAuth, requireRole('admin'), (req, res) => {
    const { username, password, role = 'analyst' } = req.body || {};
    const err = validateNewUser({ username, password, role });
    if (err) return res.status(400).json({ error: err });
    const users = loadUsers();
    if (users.some(u => u.username === username)) return res.status(409).json({ error: 'User already exists' });
    users.push({ username, role, passwordHash: hashPassword(password), createdAt: new Date().toISOString() });
    saveUsers(users);
    res.status(201).json({ ok: true });
  });

  app.patch('/api/users/:username', requireAuth, requireRole('admin'), (req, res) => {
    const users = loadUsers();
    const user = users.find(u => u.username === req.params.username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { role, password } = req.body || {};
    if (role !== undefined) {
      if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
      if (user.role === 'admin' && role !== 'admin' && users.filter(u => u.role === 'admin').length === 1) {
        return res.status(400).json({ error: 'Cannot demote the last admin' });
      }
      user.role = role;
    }
    if (password !== undefined) {
      const err = validateNewUser({ username: user.username, password });
      if (err) return res.status(400).json({ error: err });
      user.passwordHash = hashPassword(password);
    }
    saveUsers(users);
    // Apply role changes / revoke on password reset
    for (const [t, s] of sessions) {
      if (s.username !== user.username) continue;
      if (password !== undefined) sessions.delete(t); else s.role = user.role;
    }
    res.json({ ok: true });
  });

  app.delete('/api/users/:username', requireAuth, requireRole('admin'), (req, res) => {
    const users = loadUsers();
    const user = users.find(u => u.username === req.params.username);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.username === req.user.username) return res.status(400).json({ error: 'You cannot delete yourself' });
    saveUsers(users.filter(u => u !== user));
    for (const [t, s] of sessions) if (s.username === user.username) sessions.delete(t);
    res.json({ ok: true });
  });
}

module.exports = { init, enabled, requireAuth, requireRole, mountRoutes, ROLES };
