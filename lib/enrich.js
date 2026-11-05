/**
 * IP enrichment.
 *
 * Providers (configured by environment variables):
 *   ip-api.com   ISP / ASN / proxy / hosting / mobile
 *                IPAPI_KEY set   → https://pro.ip-api.com (encrypted)
 *                IPAPI_KEY unset → free endpoint, plain HTTP, 45 req/min
 *   AbuseIPDB    ABUSEIPDB_KEY set → abuse confidence score, report count, Tor
 * ENRICH_PROVIDER=none disables all outbound lookups (attacker IPs never leave the host).
 *
 * Results are cached for 24 h in memory and persisted to data/ipcache.json.
 */

const fs   = require('fs');
const path = require('path');

const IP_TTL            = 24 * 60 * 60 * 1000;
const HTTP_TIMEOUT_MS   = 6000;
const ENRICH_DEADLINE   = 10000;   // max total time for ip-api batches
const ABUSE_MAX_LOOKUPS = 50;      // per request — free tier is 1000/day

let cachePath = '';
let cache = {};                    // ip → { data, ts }
let saveTimer = null;
let warnedPlainHttp = false;

function init(dataDir) {
  cachePath = path.join(dataDir, 'ipcache.json');
  try {
    if (fs.existsSync(cachePath)) cache = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
  } catch (e) {
    console.warn('[enrich] ipcache.json unreadable, starting empty:', e.message);
    cache = {};
  }
}

function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    const now = Date.now();
    for (const ip of Object.keys(cache)) if (now - cache[ip].ts > IP_TTL * 7) delete cache[ip];
    const tmp = cachePath + '.tmp';
    fs.writeFile(tmp, JSON.stringify(cache), err => {
      if (!err) fs.rename(tmp, cachePath, () => {});
    });
  }, 2000);
}

const disabled = () => (process.env.ENRICH_PROVIDER || '').toLowerCase() === 'none';

async function fetchJSON(url, opts = {}) {
  const res = await fetch(url, { ...opts, signal: AbortSignal.timeout(HTTP_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function ipApiBatch(chunk) {
  const fields = 'status,message,query,isp,org,as,proxy,hosting,mobile';
  const key = process.env.IPAPI_KEY;
  if (!key && !warnedPlainHttp) {
    warnedPlainHttp = true;
    console.warn('[enrich] IPAPI_KEY not set — using free ip-api.com over plain HTTP. Set IPAPI_KEY for HTTPS or ENRICH_PROVIDER=none to disable.');
  }
  const url = key
    ? `https://pro.ip-api.com/batch?fields=${fields}&key=${encodeURIComponent(key)}`
    : `http://ip-api.com/batch?fields=${fields}`;
  return fetchJSON(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(chunk) });
}

async function abuseCheck(ip) {
  const r = await fetchJSON(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
    { headers: { Key: process.env.ABUSEIPDB_KEY, Accept: 'application/json' } }
  );
  const d = r.data || {};
  return { abuseScore: d.abuseConfidenceScore ?? null, abuseReports: d.totalReports ?? 0, isTor: !!d.isTor, usageType: d.usageType || '' };
}

/** @param ips ordered by priority (most relevant first) */
async function enrichIPs(ips) {
  if (disabled()) return {};
  const now      = Date.now();
  const deadline = now + ENRICH_DEADLINE;
  const toFetch  = ips.filter(ip => !cache[ip] || now - cache[ip].ts > IP_TTL);

  for (let i = 0; i < toFetch.length; i += 100) {
    if (Date.now() >= deadline) {
      console.warn('[enrich] deadline reached, skipping remaining batches');
      break;
    }
    try {
      const results = await ipApiBatch(toFetch.slice(i, i + 100));
      for (const r of results) {
        if (r.status === 'success' && r.query) cache[r.query] = { data: { ...(cache[r.query]?.data || {}), ...r }, ts: now };
      }
    } catch (e) {
      console.warn('[enrich] ip-api batch failed:', e.message);
      break;
    }
  }

  if (process.env.ABUSEIPDB_KEY) {
    const needAbuse = ips.filter(ip => cache[ip]?.data && cache[ip].data.abuseScore === undefined).slice(0, ABUSE_MAX_LOOKUPS);
    await Promise.all(needAbuse.map(async ip => {
      try { Object.assign(cache[ip].data, await abuseCheck(ip)); }
      catch (e) { console.warn(`[enrich] AbuseIPDB ${ip}:`, e.message); }
    }));
  }

  scheduleSave();
  const out = {};
  for (const ip of ips) if (cache[ip]) out[ip] = cache[ip].data;
  return out;
}

// "AS7713 PT Telkom…" → "7713" (only for IPs already enriched; no network call)
function asnOf(ip) {
  const as = cache[ip]?.data?.as;
  const m = as && /^AS(\d+)/.exec(as);
  return m ? m[1] : null;
}

module.exports = { init, enrichIPs, asnOf };
