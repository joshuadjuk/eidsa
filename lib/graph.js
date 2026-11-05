/**
 * Pull sign-in and audit logs directly from Microsoft Graph (client-credentials).
 *
 * App registration in the customer tenant needs APPLICATION permissions:
 *   AuditLog.Read.All + Directory.Read.All   (admin consent)
 * and the tenant needs Entra ID P1/P2 for sign-in logs to be available via API.
 *
 * Each sync writes JSON array files into the workspace upload folder, so the
 * normal analysis pipeline picks them up exactly like manual portal exports.
 */

const fs   = require('fs');
const path = require('path');

const GRAPH = 'https://graph.microsoft.com';
const MAX_EVENTS = parseInt(process.env.GRAPH_MAX_EVENTS, 10) || 200_000; // per stream
const REQUEST_TIMEOUT_MS = 60000;

async function getToken({ tenantId, clientId, clientSecret }) {
  const res = await fetch(`https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      scope: `${GRAPH}/.default`,
      grant_type: 'client_credentials',
    }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Token request failed: ${body.error_description?.split('\n')[0] || body.error || res.status}`);
  return body.access_token;
}

// GET with retry on throttling (429) / transient errors (503, 504)
async function graphGet(url, token, attempt = 0) {
  const res = await fetch(url, {
    headers: { Authorization: `Bearer ${token}`, ConsistencyLevel: 'eventual' },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if ([429, 503, 504].includes(res.status) && attempt < 5) {
    const wait = (parseInt(res.headers.get('retry-after'), 10) || 2 ** attempt * 2) * 1000;
    await new Promise(r => setTimeout(r, wait));
    return graphGet(url, token, attempt + 1);
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`Graph ${res.status}: ${body.error?.message || res.statusText}`);
  return body;
}

/**
 * Page through a Graph collection and stream items into a JSON array file.
 * @returns number of items written
 */
async function pullToFile(url, token, filePath, onProgress) {
  const tmp = filePath + '.partial';
  const out = fs.createWriteStream(tmp, { encoding: 'utf8' });
  const write = s => new Promise((res, rej) => out.write(s, err => (err ? rej(err) : res())));
  let count = 0;
  try {
    await write('[');
    let next = url;
    while (next && count < MAX_EVENTS) {
      const page = await graphGet(next, token);
      for (const item of page.value || []) {
        await write((count ? ',' : '') + JSON.stringify(item));
        if (++count >= MAX_EVENTS) break;
      }
      onProgress?.(count);
      next = page['@odata.nextLink'];
    }
    await write(']');
  } finally {
    await new Promise(r => out.end(r));
  }
  if (count === 0) { fs.rmSync(tmp, { force: true }); return 0; }
  fs.renameSync(tmp, filePath);
  return count;
}

const STREAMS = {
  interactive: since =>
    `${GRAPH}/v1.0/auditLogs/signIns?$top=1000&$filter=${encodeURIComponent(`createdDateTime ge ${since}`)}`,
  nonInteractive: since =>
    `${GRAPH}/beta/auditLogs/signIns?$top=1000&$filter=${encodeURIComponent(`createdDateTime ge ${since} and signInEventTypes/any(t: t eq 'nonInteractiveUser')`)}`,
  servicePrincipal: since =>
    `${GRAPH}/beta/auditLogs/signIns?$top=1000&$filter=${encodeURIComponent(`createdDateTime ge ${since} and signInEventTypes/any(t: t eq 'servicePrincipal')`)}`,
  audit: since =>
    `${GRAPH}/v1.0/auditLogs/directoryAudits?$top=999&$filter=${encodeURIComponent(`activityDateTime ge ${since}`)}`,
};

/** Quick credential + permission check: fetch a single sign-in. */
async function testConnection(creds) {
  const token = await getToken(creds);
  await graphGet(`${GRAPH}/v1.0/auditLogs/signIns?$top=1`, token);
  return true;
}

/**
 * @param creds    { tenantId, clientId, clientSecret }
 * @param opts     { since: Date, streams: ['interactive', ...], dir, onProgress(stream, count) }
 * @returns        [{ stream, file, count }]
 */
async function sync(creds, { since: sinceDate, streams = ['interactive'], dir, onProgress }) {
  const token = await getToken(creds);
  const since = sinceDate.toISOString().replace(/\.\d+Z$/, 'Z');
  const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
  const results = [];
  for (const stream of streams) {
    if (!STREAMS[stream]) continue;
    const file = path.join(dir, `graph-${stream}-${stamp}.json`);
    const count = await pullToFile(STREAMS[stream](since), token, file, n => onProgress?.(stream, n));
    results.push({ stream, file: count ? path.basename(file) : null, count });
  }
  return results;
}

module.exports = { sync, testConnection, STREAMS: Object.keys(STREAMS) };
