const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const alerts = require('../lib/alerts');
const graph = require('../lib/graph');

test('alerts: posts only new high detections, in Slack / Teams format', async () => {
  const received = [];
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', c => (body += c));
    req.on('end', () => { received.push(JSON.parse(body)); res.end('ok'); });
  });
  await new Promise(r => srv.listen(0, r));
  const url = `http://127.0.0.1:${srv.address().port}/hook`;

  const detections = [
    { type: 'PASSWORD_SPRAY', severity: 'high', ip: '6.6.6.6', windowStart: 't1', message: 'spray' },
    { type: 'FOREIGN_LOGIN', severity: 'medium', user: 'a@x', time: 't2', message: 'foreign' },
  ];
  const keys = await alerts.dispatch({ url, format: 'slack', workspaceName: 'W', detections, userSummaries: [{ user: 'a@x', riskLevel: 'CRITICAL' }] });
  assert.equal(keys.length, 1);
  assert.match(received[0].text, /spray/);
  assert.match(received[0].text, /CRITICAL users: a@x/);

  // Same detections again → nothing sent
  const again = await alerts.dispatch({ url, format: 'slack', workspaceName: 'W', detections, alertedKeys: keys });
  assert.equal(again.length, 0);
  assert.equal(received.length, 1);

  // Teams adaptive card, medium threshold includes both
  await alerts.dispatch({ url, format: 'teams', minSeverity: 'medium', workspaceName: 'W', detections });
  assert.equal(received[1].attachments[0].contentType, 'application/vnd.microsoft.card.adaptive');
  assert.equal(received[1].attachments[0].content.body.length, 3);
  srv.close();
});

test('graph: token + paging + 429 retry, written as a JSON array file', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eidsa-graph-'));
  const realFetch = global.fetch;
  const calls = [];
  let throttled = false;
  global.fetch = async (url, opts) => {
    calls.push(String(url));
    const json = (status, body, headers = {}) => ({ ok: status < 400, status, statusText: '', headers: { get: k => headers[k.toLowerCase()] }, json: async () => body });
    if (String(url).includes('login.microsoftonline.com')) {
      assert.match(opts.body.toString(), /grant_type=client_credentials/);
      return json(200, { access_token: 'tok' });
    }
    assert.equal(opts.headers.Authorization, 'Bearer tok');
    if (String(url).includes('page2')) {
      if (!throttled) { throttled = true; return json(429, {}, { 'retry-after': '0' }); }
      return json(200, { value: [{ id: 3 }] });
    }
    return json(200, { value: [{ id: 1 }, { id: 2 }], '@odata.nextLink': 'https://graph.microsoft.com/v1.0/page2' });
  };
  try {
    const res = await graph.sync({ tenantId: 't', clientId: 'c', clientSecret: 's' }, { since: new Date(Date.UTC(2026, 9, 1)), streams: ['interactive'], dir });
    assert.equal(res[0].count, 3);
    const items = JSON.parse(fs.readFileSync(path.join(dir, res[0].file), 'utf8'));
    assert.deepEqual(items.map(i => i.id), [1, 2, 3]);
    assert.ok(calls.some(u => u.includes('createdDateTime%20ge%202026-10-01T00%3A00%3A00Z')));
    assert.equal(calls.filter(u => u.includes('page2')).length, 2); // retried once after 429
  } finally {
    global.fetch = realFetch;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('graph: empty result writes no file', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'eidsa-graph-'));
  const realFetch = global.fetch;
  global.fetch = async (url) => ({
    ok: true, status: 200, headers: { get: () => null },
    json: async () => (String(url).includes('login.') ? { access_token: 't' } : { value: [] }),
  });
  try {
    const res = await graph.sync({ tenantId: 't', clientId: 'c', clientSecret: 's' }, { since: new Date(), streams: ['audit'], dir });
    assert.equal(res[0].file, null);
    assert.deepEqual(fs.readdirSync(dir), []);
  } finally {
    global.fetch = realFetch;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
