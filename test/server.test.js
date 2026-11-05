const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Isolated state dir + no outbound enrichment
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'eidsa-srv-'));
process.env.EIDSA_HOME = HOME;
process.env.ENRICH_PROVIDER = 'none';
delete process.env.EIDSA_AUTH;

const { app } = require('../server');

let server, base;
const jars = {}; // per-user cookie

async function call(who, method, url, body) {
  const headers = {};
  if (jars[who]) headers.Cookie = jars[who];
  let payload;
  if (body instanceof FormData) payload = body;
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  const res = await fetch(base + url, { method, headers, body: payload });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) jars[who] = setCookie.split(';')[0];
  return { status: res.status, body: await res.json().catch(() => null) };
}

test.before(async () => {
  await new Promise(r => { server = app.listen(0, r); });
  base = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => {
  server.close();
  fs.rmSync(HOME, { recursive: true, force: true });
});

const sampleLog = () => {
  const ev = [];
  const users = ['alice@contoso.com', 'Bob@contoso.com', 'carol@contoso.com'];
  for (let i = 0; i < 30; i++) {
    ev.push({
      id: `e${i}`, userPrincipalName: users[i % 3], ipAddress: `5.5.5.${i % 4}`,
      createdDateTime: new Date(Date.UTC(2026, 9, 1, 0, i)).toISOString(), appDisplayName: 'Office',
      status: { errorCode: i % 3 === 0 ? 0 : 50126 }, location: { countryOrRegion: i % 5 ? 'ID' : 'RU' },
      clientAppUsed: 'Browser', signInEventTypes: ['interactiveUser'],
    });
  }
  ev.push({ ...ev[0] }); // duplicate id → skipped
  ev.push({ id: 'msi1', signInEventTypes: ['managedIdentity'], createdDateTime: ev[0].createdDateTime });
  return ev;
};

test('end-to-end: setup, RBAC, analysis, user list, integrations', async () => {
  // Unauthenticated access is rejected
  assert.equal((await call('anon', 'GET', '/api/workspaces')).status, 401);
  const st = await call('anon', 'GET', '/api/auth/status');
  assert.equal(st.body.needsSetup, true);

  // First-run admin setup; second setup is refused
  assert.equal((await call('admin', 'POST', '/api/auth/setup', { username: 'admin', password: 'short' })).status, 400);
  assert.equal((await call('admin', 'POST', '/api/auth/setup', { username: 'admin', password: 'correct-horse-1' })).status, 200);
  assert.equal((await call('anon', 'POST', '/api/auth/setup', { username: 'x', password: 'correct-horse-1' })).status, 409);

  // Admin creates analyst + viewer
  assert.equal((await call('admin', 'POST', '/api/users', { username: 'ana', password: 'analyst-pass-1', role: 'analyst' })).status, 201);
  assert.equal((await call('admin', 'POST', '/api/users', { username: 'vic', password: 'viewer-pass-1', role: 'viewer' })).status, 201);
  assert.equal((await call('ana', 'POST', '/api/auth/login', { username: 'ana', password: 'wrong' })).status, 401);
  assert.equal((await call('ana', 'POST', '/api/auth/login', { username: 'ana', password: 'analyst-pass-1' })).status, 200);
  assert.equal((await call('vic', 'POST', '/api/auth/login', { username: 'vic', password: 'viewer-pass-1' })).status, 200);

  // Only admins create workspaces
  assert.equal((await call('ana', 'POST', '/api/workspaces', { name: 'nope' })).status, 403);
  const ws = (await call('admin', 'POST', '/api/workspaces', { name: 'Test', homeCountry: 'ID' })).body;
  assert.equal(ws.timezone, 'Asia/Jakarta');

  // Analyst uploads + analyzes; viewer can read but not write
  const fd = new FormData();
  fd.append('files', new Blob([JSON.stringify(sampleLog())], { type: 'application/json' }), 'log.json');
  assert.equal((await call('ana', 'POST', `/api/workspaces/${ws.id}/files`, fd)).status, 200);
  assert.equal((await call('vic', 'POST', `/api/workspaces/${ws.id}/notes`, { user: 'a', note: 'x' })).status, 403);

  const all = (await call('vic', 'GET', `/api/workspaces/${ws.id}/analyze`)).body;
  assert.equal(all.total, 30);
  assert.equal(all.stats.duplicatesSkipped, 1);
  assert.ok(all.parseWarnings.some(w => w.reason === 'managedIdentity'));

  // Settings change invalidates the cache (trusted country RU removes foreign logins)
  await call('ana', 'PATCH', `/api/workspaces/${ws.id}`, { trustedCountries: ['RU'] });
  const trusted = (await call('ana', 'GET', `/api/workspaces/${ws.id}/analyze`)).body;
  assert.equal(trusted.detections.filter(d => d.type === 'FOREIGN_LOGIN').length, 0);
  assert.ok(all.detections.some(d => d.type === 'FOREIGN_LOGIN'));

  // User list: filter → highlight → remove
  const ul = (await call('ana', 'PUT', `/api/workspaces/${ws.id}/userlist`, { filename: 'u.txt', content: '﻿BOB@contoso.com\nghost@x.com' })).body;
  assert.equal(ul.userListMode, 'filter');
  const filtered = (await call('ana', 'GET', `/api/workspaces/${ws.id}/analyze`)).body;
  assert.equal(filtered.total, 10);
  assert.equal(filtered.userFilter.matched, 1);
  assert.deepEqual(filtered.userFilter.unmatched, ['ghost@x.com']);

  await call('ana', 'PATCH', `/api/workspaces/${ws.id}`, { userListMode: 'highlight' });
  const hl = (await call('ana', 'GET', `/api/workspaces/${ws.id}/analyze`)).body;
  assert.equal(hl.total, 30);
  assert.equal(hl.userFilter.mode, 'highlight');
  assert.deepEqual(hl.userFilter.users, ['bob@contoso.com', 'ghost@x.com']);

  // Integrations: admin only, secrets encrypted at rest and never returned
  assert.equal((await call('ana', 'PUT', `/api/workspaces/${ws.id}/integrations`, { graph: { tenantId: 'x' } })).status, 403);
  const integ = await call('admin', 'PUT', `/api/workspaces/${ws.id}/integrations`, {
    graph: { tenantId: 'contoso.onmicrosoft.com', clientId: 'abc', clientSecret: 'TOP-SECRET', autoSyncHours: 0 },
    alerts: { enabled: true, format: 'slack', webhookUrl: 'https://hooks.example.com/x' },
  });
  assert.equal(integ.status, 200);
  assert.equal(integ.body.graph.hasSecret, true);
  assert.equal(JSON.stringify(integ.body).includes('TOP-SECRET'), false);
  const onDisk = fs.readFileSync(path.join(HOME, 'workspaces', `${ws.id}.json`), 'utf8');
  assert.equal(onDisk.includes('TOP-SECRET'), false);
  assert.equal(onDisk.includes('hooks.example.com'), false);
  assert.equal((await call('admin', 'PUT', `/api/workspaces/${ws.id}/integrations`, { alerts: { webhookUrl: 'http://insecure' } })).status, 400);

  // Overview + baseline
  const ov = (await call('vic', 'GET', '/api/overview')).body;
  assert.equal(ov[0].summary.stats.total, 30);
  assert.equal((await call('ana', 'POST', `/api/workspaces/${ws.id}/baseline`, { metrics: { totalEvents: 30 } })).body.baseline.metrics.totalEvents, 30);

  // Path traversal still blocked
  assert.equal((await call('admin', 'DELETE', `/api/workspaces/${ws.id}/files/..%2F..%2Fpackage.json`)).status, 400);

  // Only admins delete; delete removes side files
  assert.equal((await call('ana', 'DELETE', `/api/workspaces/${ws.id}`)).status, 403);
  assert.equal((await call('admin', 'DELETE', `/api/workspaces/${ws.id}`)).status, 200);
  assert.deepEqual(fs.readdirSync(path.join(HOME, 'workspaces')), []);

  // Logout ends the session
  await call('ana', 'POST', '/api/auth/logout');
  assert.equal((await call('ana', 'GET', '/api/workspaces')).status, 401);
});
