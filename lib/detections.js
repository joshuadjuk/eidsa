/**
 * Detection rules for Entra ID sign-in logs.
 *
 * All rules expect events sorted ascending by `ts` (runDetections sorts once),
 * so grouped arrays are already chronological and never re-sorted per rule.
 */

// ─── Helpers ──────────────────────────────────────────────────────────────────

function groupBy(arr, keyFn) {
  const acc = {};
  for (const item of arr) {
    const k = keyFn(item);
    (acc[k] = acc[k] || []).push(item);
  }
  return acc;
}

function tsOf(e) {
  return e.ts ?? (Date.parse(e.createdAt) || 0);
}

function byTime(a, b) {
  return tsOf(a) - tsOf(b);
}

// A real failed credential attempt — interrupts (MFA prompt, KMSI…) don't count
function isFailedAttempt(e) {
  return !e.success && !e.interrupted;
}

function haversineKm(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

const COUNTRY_COORDS = {
  ID: [-2.5, 118.0],  US: [37.1, -95.7],  CN: [35.0, 105.0],
  RU: [61.5, 105.3],  IN: [20.6, 78.9],   SG: [1.3, 103.8],
  AU: [-25.3, 133.8], GB: [55.4, -3.4],   NL: [52.1, 5.3],
  DE: [51.2, 10.5],   FR: [46.2, 2.2],    JP: [36.2, 138.3],
  KR: [35.9, 127.8],  BR: [-14.2, -51.9], CA: [56.1, -106.3],
  MY: [4.2, 109.5],   PH: [12.9, 121.8],  TH: [15.9, 100.9],
  VN: [14.1, 108.3],  NG: [9.1, 8.7],     PK: [30.4, 69.3],
  BD: [23.7, 90.4],   UA: [48.4, 31.2],   TR: [38.9, 35.2],
  IR: [32.4, 53.7],   HK: [22.3, 114.2],  TW: [23.7, 121.0],
  SA: [23.9, 45.1],   AE: [23.4, 53.8],   EG: [26.8, 30.8],
  ZA: [-30.6, 22.9],  MX: [23.6, -102.6], AR: [-38.4, -63.6],
  IT: [41.9, 12.6],   ES: [40.5, -3.7],   PL: [51.9, 19.1],
  CZ: [49.8, 15.5],   RO: [45.9, 24.9],   SE: [60.1, 18.6],
  NO: [60.5, 8.5],    FI: [61.9, 25.7],   DK: [56.3, 9.5],
  CH: [46.8, 8.2],    AT: [47.5, 14.6],   BE: [50.5, 4.5],
  PT: [39.4, -8.2],   GR: [39.1, 21.8],   HU: [47.2, 19.5],
  BG: [42.7, 25.5],   HR: [45.1, 15.2],   SK: [48.7, 19.7],
  NZ: [-40.9, 174.9], IL: [31.0, 34.9],   CL: [-35.7, -71.5],
  CO: [4.6, -74.1],   PE: [-9.2, -75.0],  VE: [6.4, -66.6],
  IE: [53.4, -8.2],   LU: [49.8, 6.1],    LT: [55.2, 23.9],
  LV: [56.9, 24.6],   EE: [58.6, 25.0],   BY: [53.7, 28.0],
  KZ: [48.0, 66.9],   UZ: [41.4, 64.6],   GE: [42.3, 43.4],
  AM: [40.1, 45.0],   AZ: [40.1, 47.6],   IQ: [33.2, 43.7],
  SY: [34.8, 39.0],   JO: [30.6, 36.2],   LB: [33.9, 35.9],
  KW: [29.3, 47.5],   QA: [25.4, 51.2],   BH: [26.0, 50.6],
  OM: [21.5, 55.9],   YE: [15.6, 48.5],   AF: [33.9, 67.7],
  NP: [28.4, 84.1],   LK: [7.9, 80.8],    MM: [21.9, 95.9],
  KH: [12.6, 104.9],  LA: [19.9, 102.5],  MN: [46.9, 103.8],
  KP: [40.3, 127.5],  MO: [22.2, 113.5],  BN: [4.5, 114.7],
  TL: [-8.9, 125.7],  PG: [-6.3, 143.9],  FJ: [-17.7, 178.1],
  MA: [31.8, -7.1],   DZ: [28.0, 1.7],    TN: [33.9, 9.5],
  LY: [26.3, 17.2],   SD: [12.9, 30.2],   ET: [9.1, 40.5],
  KE: [-0.02, 37.9],  TZ: [-6.4, 34.9],   UG: [1.4, 32.3],
  GH: [7.9, -1.0],    CI: [7.5, -5.5],    SN: [14.5, -14.5],
  CM: [7.4, 12.4],    AO: [-11.2, 17.9],  ZW: [-19.0, 29.2],
  ZM: [-13.1, 27.8],  MZ: [-18.7, 35.5],  MG: [-18.8, 46.9],
  EC: [-1.8, -78.2],  BO: [-16.3, -63.6], PY: [-23.4, -58.4],
  UY: [-32.5, -55.8], PA: [8.5, -80.8],   CR: [9.7, -83.8],
  GT: [15.8, -90.2],  HN: [15.2, -86.2],  SV: [13.8, -88.9],
  NI: [12.9, -85.2],  DO: [18.7, -70.2],  CU: [21.5, -77.8],
  JM: [18.1, -77.3],  PR: [18.2, -66.6],  TT: [10.7, -61.2],
  IS: [64.96, -19.0], RS: [44.0, 21.0],   SI: [46.2, 14.995],
  BA: [43.9, 17.7],   MK: [41.6, 21.7],   AL: [41.2, 20.2],
  MD: [47.4, 28.4],   CY: [35.1, 33.4],   MT: [35.9, 14.4],
};

function getCountryCoords(code) {
  return COUNTRY_COORDS[(code || '').toUpperCase()] || null;
}

// Best available position: city-level coordinates from the log, else country centroid
function positionOf(e) {
  if (e.lat != null && e.lon != null) return [e.lat, e.lon];
  return getCountryCoords(e.country);
}

function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = parseInt(p, 10);
    if (isNaN(v) || v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0; // unsigned 32-bit
}

function matchesCIDR(ip, cidr) {
  const [network, prefix] = cidr.split('/');
  const bits = parseInt(prefix, 10);
  if (isNaN(bits) || bits < 0 || bits > 32) return false;
  const mask    = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  const ipInt   = ipToInt(ip);
  const netInt  = ipToInt(network);
  if (ipInt === null || netInt === null) return false;
  return (ipInt & mask) === (netInt & mask);
}

function isTrustedIP(ip, trustedIPs) {
  if (!ip || !trustedIPs || trustedIPs.length === 0) return false;
  return trustedIPs.some(entry => {
    if (entry.includes('/')) return matchesCIDR(ip, entry);
    return ip === entry || ip.startsWith(entry);
  });
}

function trustedSet(homeCountry = 'ID', trustedCountries = []) {
  return new Set([homeCountry.toUpperCase(), ...trustedCountries.map(c => c.toUpperCase())]);
}

/**
 * Sliding-window burst finder, O(n) per group.
 * Opens an incident when the window holds ≥ minDistinct distinct keyFn values,
 * then extends it while events keep arriving within windowMs of each other
 * (capped at maxSpanMs) so the whole campaign is reported, not just the first
 * N events. Scanning resumes after the incident, so repeated campaigns against
 * the same target are each reported (up to maxIncidents).
 */
function findBursts(sorted, { windowMs, minDistinct, keyFn = e => e, maxIncidents = 10, maxSpanMs = 24 * 3600000 }) {
  const incidents = [];
  const counts = new Map();
  const add = k => counts.set(k, (counts.get(k) || 0) + 1);
  const remove = k => {
    const c = counts.get(k) - 1;
    if (c <= 0) counts.delete(k); else counts.set(k, c);
  };

  let left = 0;
  for (let right = 0; right < sorted.length; right++) {
    add(keyFn(sorted[right]));
    while (tsOf(sorted[right]) - tsOf(sorted[left]) > windowMs) remove(keyFn(sorted[left++]));

    if (counts.size >= minDistinct) {
      const startTs = tsOf(sorted[left]);
      let end = right;
      while (
        end + 1 < sorted.length &&
        tsOf(sorted[end + 1]) - tsOf(sorted[end]) <= windowMs &&
        tsOf(sorted[end + 1]) - startTs <= maxSpanMs
      ) end++;
      incidents.push(sorted.slice(left, end + 1));
      if (incidents.length >= maxIncidents) break;
      counts.clear();
      left = end + 1;
      right = end;
    }
  }
  return incidents;
}

const uniq = arr => [...new Set(arr.filter(Boolean))];

// ─── Rules ────────────────────────────────────────────────────────────────────

function detectPasswordSpray(events, { windowMs = 10 * 60 * 1000, minUsers = 5 } = {}) {
  const findings = [];
  const byIp = groupBy(events.filter(e => isFailedAttempt(e) && e.ipAddress), e => e.ipAddress);

  for (const [ip, ipEvents] of Object.entries(byIp)) {
    for (const win of findBursts(ipEvents, { windowMs, minDistinct: minUsers, keyFn: e => e.userPrincipal })) {
      const users = uniq(win.map(e => e.userPrincipal));
      findings.push({
        type: 'PASSWORD_SPRAY',
        severity: 'high',
        ip,
        country: win[0].country,
        affectedUsers: users,
        eventCount: win.length,
        windowStart: win[0].createdAt,
        windowEnd: win[win.length - 1].createdAt,
        message: `Password spray from ${ip}: ${users.length} users targeted (≥${minUsers} within ${Math.round(windowMs / 60000)} min)`
      });
    }
  }
  return findings;
}

function detectImpossibleTravel(events, { maxSpeedKmh = 900, minDistanceKm = 300, maxPerUser = 5 } = {}) {
  const findings = [];
  const byUser = groupBy(events.filter(e => e.success && positionOf(e)), e => e.userPrincipal);

  for (const [user, sorted] of Object.entries(byUser)) {
    let count = 0;
    for (let i = 1; i < sorted.length && count < maxPerUser; i++) {
      const prev = sorted[i - 1];
      const curr = sorted[i];
      const p1 = positionOf(prev);
      const p2 = positionOf(curr);

      const distKm = haversineKm(...p1, ...p2);
      // Below this, IP geolocation noise (mobile carriers, ISP egress) dominates
      if (distKm < minDistanceKm) continue;

      // Simultaneous far-apart sign-ins count as at least one minute apart
      const timeDiffH = Math.max(tsOf(curr) - tsOf(prev), 60000) / 3_600_000;
      const speedKmh = distKm / timeDiffH;
      if (speedKmh > maxSpeedKmh) {
        count++;
        const place = e => `${e.country}${e.city ? '/' + e.city : ''}`;
        findings.push({
          type: 'IMPOSSIBLE_TRAVEL',
          severity: 'high',
          user,
          from: { country: prev.country, city: prev.city, ip: prev.ipAddress, time: prev.createdAt },
          to:   { country: curr.country, city: curr.city, ip: curr.ipAddress, time: curr.createdAt },
          distanceKm: Math.round(distKm),
          speedKmh: Math.round(speedKmh),
          precision: prev.lat != null && curr.lat != null ? 'city' : 'country',
          message: `Impossible travel for ${user}: ${place(prev)}→${place(curr)} (${Math.round(distKm)} km in ${timeDiffH.toFixed(2)}h)`
        });
      }
    }
  }
  return findings;
}

/**
 * Foreign Login: successful login from a country that is NOT the home country.
 * homeCountry defaults to 'ID' (Indonesia) but is configurable per workspace.
 */
function detectForeignLogins(events, { homeCountry = 'ID', trustedCountries = [], trustedIPs = [] } = {}) {
  const home    = homeCountry.toUpperCase();
  const trusted = trustedSet(homeCountry, trustedCountries);
  const findings = [];
  const seen = new Set(); // one per user+country

  for (const e of events) {
    if (!e.success) continue;
    if (!e.country) continue;
    if (trusted.has(e.country.toUpperCase())) continue;
    if (isTrustedIP(e.ipAddress, trustedIPs)) continue;
    const key = `${e.userPrincipal}|${e.country}`;
    if (seen.has(key)) continue;
    seen.add(key);

    findings.push({
      type: 'FOREIGN_LOGIN',
      severity: 'medium',
      user: e.userPrincipal,
      homeCountry: home,
      foreignCountry: e.country,
      foreignCity: e.city,
      ip: e.ipAddress,
      time: e.createdAt,
      app: e.appName,
      appType: e.appType,
      message: `Foreign login for ${e.userPrincipal}: ${e.country}${e.city ? ' / ' + e.city : ''} (home: ${home})`
    });
  }
  return findings;
}

function detectBruteForce(events, { windowMs = 10 * 60 * 1000, minAttempts = 10 } = {}) {
  const findings = [];
  const byUser = groupBy(events.filter(e => isFailedAttempt(e) && e.userPrincipal), e => e.userPrincipal);

  for (const [user, userEvents] of Object.entries(byUser)) {
    for (const win of findBursts(userEvents, { windowMs, minDistinct: minAttempts })) {
      findings.push({
        type: 'BRUTE_FORCE',
        severity: 'high',
        user,
        attemptCount: win.length,
        uniqueIPs: uniq(win.map(e => e.ipAddress)),
        windowStart: win[0].createdAt,
        windowEnd: win[win.length - 1].createdAt,
        message: `Brute force against ${user}: ${win.length} failed attempts (≥${minAttempts} within ${Math.round(windowMs / 60000)} min)`
      });
    }
  }
  return findings;
}

/**
 * Admin Tool Abuse: use of Azure CLI, PowerShell, Graph Explorer, etc.
 * from a country that is not the home country — indicates lateral movement.
 */
function detectAdminToolAbuse(events, { homeCountry = 'ID', trustedCountries = [], trustedIPs = [] } = {}) {
  const trusted = trustedSet(homeCountry, trustedCountries);

  const ADMIN_APP_PATTERNS = [
    'azure cli', 'microsoft azure cli', 'azure powershell',
    'microsoft azure powershell', 'azure ad powershell',
    'graph explorer', 'microsoft graph explorer',
    'azure portal', 'azure management',
  ];

  const ADMIN_CLIENT_PATTERNS = [
    'windows powershell', 'azure cli',
  ];

  const isAdminApp = e => {
    const app = (e.appName || '').toLowerCase();
    const client = (e.clientAppUsed || '').toLowerCase();
    return ADMIN_APP_PATTERNS.some(p => app.includes(p)) ||
           ADMIN_CLIENT_PATTERNS.some(p => client.includes(p)) ||
           e.appType === 'Admin';
  };

  const findings = [];
  const seen = new Set(); // one per user+app+country
  for (const e of events) {
    if (!isAdminApp(e)) continue;
    if (!e.country || trusted.has(e.country.toUpperCase())) continue;
    if (isTrustedIP(e.ipAddress, trustedIPs)) continue;
    const key = `${e.userPrincipal}|${e.appName}|${e.country}`;
    if (seen.has(key)) continue;
    seen.add(key);

    findings.push({
      type: 'ADMIN_TOOL_ABUSE',
      severity: 'high',
      user: e.userPrincipal,
      app: e.appName,
      clientApp: e.clientAppUsed,
      ip: e.ipAddress,
      country: e.country,
      city: e.city,
      time: e.createdAt,
      success: e.success,
      message: `Admin tool from foreign location: ${e.userPrincipal} used "${e.appName || e.clientAppUsed}" from ${e.country}${e.city ? ' / ' + e.city : ''}`
    });
  }
  return findings;
}

/**
 * MFA Exhaustion / MFA Fatigue: repeated MFA challenges in a short window.
 * Attackers flood users with MFA prompts hoping they accept one by mistake.
 */
function detectMFAExhaustion(events, { windowMs = 60 * 60 * 1000, minPrompts = 5 } = {}) {
  // Error codes related to MFA challenges/failures (interrupts included on purpose)
  const MFA_ERRORS = new Set([50076, 500121, 50074, 53003, 50158]);
  const findings   = [];

  const byUser = groupBy(
    events.filter(e => !e.success && MFA_ERRORS.has(e.errorCode) && e.userPrincipal),
    e => e.userPrincipal
  );

  for (const [user, userEvents] of Object.entries(byUser)) {
    for (const win of findBursts(userEvents, { windowMs, minDistinct: minPrompts })) {
      findings.push({
        type:        'MFA_EXHAUSTION',
        severity:    win.length >= 15 ? 'high' : 'medium',
        user,
        promptCount: win.length,
        uniqueIPs:   uniq(win.map(e => e.ipAddress)),
        windowStart: win[0].createdAt,
        windowEnd:   win[win.length - 1].createdAt,
        message:     `MFA exhaustion attempt against ${user}: ${win.length} MFA challenges (≥${minPrompts} within ${Math.round(windowMs / 60000)} min) — possible MFA fatigue attack`,
      });
    }
  }
  return findings;
}

/**
 * Legacy Auth: successful sign-ins via protocols that bypass MFA
 * (IMAP, POP3, SMTP AUTH, Exchange ActiveSync, MAPI, etc.)
 */
function detectLegacyAuth(events) {
  const findings = [];
  const byUser = groupBy(
    events.filter(e => e.appType === 'Legacy'),
    e => e.userPrincipal
  );

  for (const [user, userEvents] of Object.entries(byUser)) {
    const successEvents = userEvents.filter(e => e.success);
    if (successEvents.length === 0) continue;

    const protocols = uniq(userEvents.map(e => e.clientAppUsed));
    const apps      = uniq(userEvents.map(e => e.appName));

    findings.push({
      type:         'LEGACY_AUTH',
      severity:     'medium',
      user,
      protocols,
      apps,
      successCount: successEvents.length,
      totalCount:   userEvents.length,
      firstSeen:    successEvents[0].createdAt,
      lastSeen:     successEvents[successEvents.length - 1].createdAt,
      message:      `Legacy auth for ${user}: ${protocols.join(', ') || 'unknown protocol'} — ${successEvents.length} successful sign-in(s), MFA likely bypassed`,
    });
  }
  return findings;
}

/**
 * CA Gap: successful interactive sign-ins where Conditional Access was not applied,
 * from a foreign country and IP not in trusted lists.
 */
function detectCAGap(events, { homeCountry = 'ID', trustedCountries = [], trustedIPs = [] } = {}) {
  const trusted = trustedSet(homeCountry, trustedCountries);

  const relevant = events.filter(e =>
    e.signInType === 'interactive' &&
    e.conditionalAccessStatus === 'notApplied' &&
    e.success &&
    e.country &&
    !trusted.has(e.country.toUpperCase()) &&
    !isTrustedIP(e.ipAddress, trustedIPs)
  );

  const findings = [];
  for (const [user, userEvents] of Object.entries(groupBy(relevant, e => e.userPrincipal))) {
    const countries = uniq(userEvents.map(e => e.country));
    const apps      = uniq(userEvents.map(e => e.appName));

    findings.push({
      type:       'CA_GAP',
      severity:   'medium',
      user,
      countries,
      apps,
      eventCount: userEvents.length,
      firstSeen:  userEvents[0].createdAt,
      lastSeen:   userEvents[userEvents.length - 1].createdAt,
      message:    `CA policy not applied for ${user}: interactive sign-in(s) from ${countries.join(', ')} without Conditional Access (${userEvents.length} event${userEvents.length > 1 ? 's' : ''})`,
    });
  }
  return findings;
}

/**
 * Network identity of an IP for token-replay grouping. Uses the ASN when the IP
 * has been enriched, else a /16 (IPv4) or /48 (IPv6) prefix — so a user hopping
 * between addresses of the same carrier isn't treated as two attackers.
 */
function networkKey(ip, asnLookup) {
  const asn = asnLookup?.(ip);
  if (asn) return `AS:${asn}`;
  if (ip.includes(':')) return `v6:${ip.toLowerCase().split(':').slice(0, 3).join(':')}`;
  return `v4:${ip.split('.').slice(0, 2).join('.')}`;
}

/**
 * Token Replay / Session Hijack:
 * Same user has successful sign-ins from 2+ different networks within 30 seconds.
 * Indicates a stolen token being replayed from a different location.
 * Dual-stack devices (one IPv4 + one IPv6 network in the same country) are ignored.
 */
function detectTokenReplay(events, { windowMs = 30 * 1000, asnLookup = null } = {}) {
  const findings = [];
  const byUser = groupBy(
    events.filter(e => e.success && e.ipAddress && e.userPrincipal),
    e => e.userPrincipal
  );

  for (const [user, userEvents] of Object.entries(byUser)) {
    const keyFn = e => networkKey(e.ipAddress, asnLookup);
    for (const win of findBursts(userEvents, { windowMs, minDistinct: 2, keyFn, maxIncidents: 5, maxSpanMs: windowMs })) {
      const nets = uniq(win.map(keyFn));
      const countries = uniq(win.map(e => e.country));
      const isDualStack = nets.length === 2 && countries.length <= 1 &&
        nets.some(n => n.startsWith('v4:')) && nets.some(n => n.startsWith('v6:'));
      if (isDualStack) continue;

      const ips = uniq(win.map(e => e.ipAddress));
      findings.push({
        type:        'TOKEN_REPLAY',
        severity:    'high',
        user,
        ips,
        networks:    nets,
        windowStart: win[0].createdAt,
        windowEnd:   win[win.length - 1].createdAt,
        message:     `Token replay suspected for ${user}: successful sign-ins from ${nets.length} different networks (${ips.join(', ')}) within ${windowMs / 1000}s — possible session hijack`,
      });
    }
  }
  return findings;
}

/**
 * Enumeration Attack:
 * Many different non-existent usernames tried from the same IP (error 50034).
 * Indicates directory enumeration / username harvesting.
 */
function detectEnumerationAttack(events, { windowMs = 60 * 60 * 1000, minUsers = 10 } = {}) {
  const findings = [];
  const relevant = events.filter(e => !e.success && e.errorCode === 50034 && e.ipAddress && e.userPrincipal);

  for (const [ip, ipEvents] of Object.entries(groupBy(relevant, e => e.ipAddress))) {
    for (const win of findBursts(ipEvents, { windowMs, minDistinct: minUsers, keyFn: e => e.userPrincipal })) {
      const users = uniq(win.map(e => e.userPrincipal));
      findings.push({
        type:        'ENUMERATION_ATTACK',
        severity:    'high',
        ip,
        country:     win[0].country,
        uniqueUsers: users.length,
        sampleUsers: users.slice(0, 5),
        eventCount:  win.length,
        windowStart: win[0].createdAt,
        windowEnd:   win[win.length - 1].createdAt,
        message:     `Account enumeration from ${ip}: ${users.length} non-existent usernames probed (≥${minUsers} within ${Math.round(windowMs / 60000)} min, error 50034)`,
      });
    }
  }
  return findings;
}

/**
 * Service Principal Anomaly:
 * A service principal successfully authenticated from a foreign country.
 * SPs are automated — geographic movement is always suspicious.
 */
function detectServicePrincipalAnomaly(events, { homeCountry = 'ID', trustedCountries = [], trustedIPs = [] } = {}) {
  const trusted = trustedSet(homeCountry, trustedCountries);

  const relevant = events.filter(e =>
    e.signInType === 'servicePrincipal' &&
    e.success &&
    e.country &&
    !trusted.has(e.country.toUpperCase()) &&
    !isTrustedIP(e.ipAddress, trustedIPs)
  );

  const findings = [];
  for (const [sp, spEvents] of Object.entries(groupBy(relevant, e => e.userPrincipal))) {
    const countries = uniq(spEvents.map(e => e.country));
    const ips       = uniq(spEvents.map(e => e.ipAddress));
    const apps      = uniq(spEvents.map(e => e.appName || e.resourceName));

    findings.push({
      type:       'SERVICE_PRINCIPAL_ANOMALY',
      severity:   'high',
      user:       sp,
      countries,
      ips,
      apps,
      eventCount: spEvents.length,
      firstSeen:  spEvents[0].createdAt,
      lastSeen:   spEvents[spEvents.length - 1].createdAt,
      message:    `Service principal anomaly: "${sp}" authenticated from foreign location${countries.length > 1 ? 's' : ''} (${countries.join(', ')}) — ${spEvents.length} event${spEvents.length > 1 ? 's' : ''}`,
    });
  }
  return findings;
}

// Hour-of-day in the workspace timezone (cached formatter per tz)
const hourFormatters = {};
function hourIn(ts, timezone) {
  if (!timezone || timezone === 'UTC') return new Date(ts).getUTCHours();
  let fmt = hourFormatters[timezone];
  if (!fmt) {
    try {
      fmt = hourFormatters[timezone] = new Intl.DateTimeFormat('en-US', { timeZone: timezone, hour: 'numeric', hourCycle: 'h23' });
    } catch (_) {
      return new Date(ts).getUTCHours(); // unknown tz → UTC
    }
  }
  return parseInt(fmt.format(new Date(ts)), 10) % 24;
}

/**
 * Time-of-Day Anomaly:
 * Successful login at an hour significantly outside the user's normal schedule.
 * Baseline = P10–P90 of their interactive login hours in the workspace timezone.
 * Requires ≥10 events.
 */
function detectTimeOfDayAnomaly(events, { minBaseline = 10, timezone = 'UTC' } = {}) {
  const findings = [];
  const tzLabel  = timezone || 'UTC';

  // Only interactive successful sign-ins for baseline
  const relevant = events.filter(e =>
    e.success && e.userPrincipal &&
    (e.signInType === 'interactive' || !e.signInType)
  );

  for (const [user, sorted] of Object.entries(groupBy(relevant, e => e.userPrincipal))) {
    if (sorted.length < minBaseline) continue;

    const hours     = sorted.map(e => hourIn(tsOf(e), timezone));
    const sortedHrs = [...hours].sort((a, b) => a - b);

    const p10 = sortedHrs[Math.floor(sortedHrs.length * 0.10)];
    const p90 = sortedHrs[Math.floor(sortedHrs.length * 0.90)];

    // Only flag users with a tight schedule (≤12h spread)
    if (p90 - p10 > 12) continue;

    const lower = p10 - 1;   // 1h buffer
    const upper = p90 + 1;

    let worst = -1;
    let worstDiff = 0;
    hours.forEach((h, i) => {
      const diff = h < lower ? lower - h : h > upper ? h - upper : 0;
      if (diff > 2 && diff > worstDiff) { worst = i; worstDiff = diff; }
    });

    if (worst >= 0) {
      const e   = sorted[worst];
      const h   = hours[worst];
      const pad = n => String(n).padStart(2, '0');
      findings.push({
        type:          'TIME_OF_DAY_ANOMALY',
        severity:      'medium',
        user,
        anomalousHour: h,
        normalWindow:  `${pad(p10)}:00–${pad(p90)}:00 ${tzLabel}`,
        timezone:      tzLabel,
        time:          e.createdAt,
        ip:            e.ipAddress,
        country:       e.country,
        app:           e.appName,
        message:       `Off-hours login for ${user}: signed in at ${pad(h)}:00 ${tzLabel} (typical window: ${pad(p10)}:00–${pad(p90)}:00)`,
      });
    }
  }
  return findings;
}

/**
 * First-Seen Country:
 * User's first successful sign-in from a country not seen in any prior event.
 * More precise than Foreign Login — detects genuinely new geography.
 */
function detectFirstSeenCountry(events, { homeCountry = 'ID', trustedCountries = [], trustedIPs = [], minBaseline = 5 } = {}) {
  const trusted = trustedSet(homeCountry, trustedCountries);
  const findings = [];

  const byUser = groupBy(events.filter(e => e.userPrincipal && e.country), e => e.userPrincipal);

  for (const [user, sorted] of Object.entries(byUser)) {
    if (sorted.length < minBaseline) continue;
    const seenCountries = new Set();

    for (const e of sorted) {
      const ctry  = e.country.toUpperCase();
      const isNew = !seenCountries.has(ctry);
      seenCountries.add(ctry);

      if (!isNew) continue;
      if (!e.success) continue;
      if (trusted.has(ctry)) continue;
      if (isTrustedIP(e.ipAddress, trustedIPs)) continue;
      if (seenCountries.size <= 1) continue; // need at least one prior country for baseline

      findings.push({
        type:          'FIRST_SEEN_COUNTRY',
        severity:      'medium',
        user,
        country:       e.country,
        city:          e.city,
        ip:            e.ipAddress,
        time:          e.createdAt,
        app:           e.appName,
        knownCountries: [...seenCountries].filter(c => c !== ctry && !trusted.has(c)).slice(0, 5),
        message:       `First-seen country for ${user}: successful sign-in from ${e.country}${e.city ? ' / ' + e.city : ''} — not observed in prior sign-in history`,
      });
      break; // one per user
    }
  }
  return findings;
}

/**
 * Concurrent Sessions:
 * Same user has successful sign-ins from 2+ different countries within 5 minutes.
 * Unlike Impossible Travel (sequential speed check), this is simultaneous — very
 * strong indicator of token theft or account sharing.
 */
function detectConcurrentSessions(events, { windowMs = 5 * 60 * 1000 } = {}) {
  const findings = [];
  const byUser = groupBy(events.filter(e => e.success && e.country && e.userPrincipal), e => e.userPrincipal);

  for (const [user, userEvents] of Object.entries(byUser)) {
    const keyFn = e => e.country.toUpperCase();
    for (const win of findBursts(userEvents, { windowMs, minDistinct: 2, keyFn, maxIncidents: 5, maxSpanMs: windowMs })) {
      const ctryList = uniq(win.map(keyFn));
      findings.push({
        type:        'CONCURRENT_SESSIONS',
        severity:    'high',
        user,
        countries:   ctryList,
        ips:         uniq(win.map(e => e.ipAddress)),
        windowStart: win[0].createdAt,
        windowEnd:   win[win.length - 1].createdAt,
        message:     `Concurrent sessions for ${user}: active from ${ctryList.join(' + ')} simultaneously within ${Math.round(windowMs / 60000)} min — possible token theft or account sharing`,
      });
    }
  }
  return findings;
}

/**
 * Rare App Access:
 * User accesses an app from a foreign location that they've never used from outside
 * their home country before. Baseline = apps accessed from home/trusted countries.
 */
function detectRareAppAccess(events, { homeCountry = 'ID', trustedCountries = [], trustedIPs = [], minBaseline = 5 } = {}) {
  const trusted = trustedSet(homeCountry, trustedCountries);
  const findings = [];

  const byUser = groupBy(events.filter(e => e.userPrincipal && e.appName), e => e.userPrincipal);

  for (const [user, sorted] of Object.entries(byUser)) {
    if (sorted.length < minBaseline) continue;

    // Apps used from home/trusted locations = known baseline
    const homeApps = new Set(
      sorted
        .filter(e => e.success && e.country && trusted.has(e.country.toUpperCase()))
        .map(e => e.appName.toLowerCase())
    );
    if (homeApps.size === 0) continue; // no baseline from home

    for (const e of sorted) {
      if (!e.success || !e.country) continue;
      if (trusted.has(e.country.toUpperCase())) continue;
      if (isTrustedIP(e.ipAddress, trustedIPs)) continue;
      if (homeApps.has(e.appName.toLowerCase())) continue;

      findings.push({
        type:     'RARE_APP_ACCESS',
        severity: 'medium',
        user,
        app:      e.appName,
        ip:       e.ipAddress,
        country:  e.country,
        city:     e.city,
        time:     e.createdAt,
        homeApps: [...homeApps].slice(0, 5),
        message:  `Rare app access for ${user}: first-time access to "${e.appName}" from foreign location (${e.country}${e.city ? ' / ' + e.city : ''}) — app not in home-country baseline`,
      });
      break; // one finding per user
    }
  }
  return findings;
}

/**
 * Credential Stuffing:
 * Same IP targets many different accounts with failures over a wide multi-hour window.
 * Unlike Password Spray (tight burst), stuffing campaigns are slow and spread across hours/days
 * using automated credential lists.
 */
function detectCredentialStuffing(events, { windowMs = 24 * 60 * 60 * 1000, minUsers = 8 } = {}) {
  const findings = [];
  const relevant = events.filter(e => isFailedAttempt(e) && e.ipAddress && e.userPrincipal);

  for (const [ip, ipEvents] of Object.entries(groupBy(relevant, e => e.ipAddress))) {
    for (const win of findBursts(ipEvents, { windowMs, minDistinct: minUsers, keyFn: e => e.userPrincipal, maxSpanMs: 7 * 24 * 3600000 })) {
      const users = uniq(win.map(e => e.userPrincipal));
      const hours = Math.max(1, Math.round((tsOf(win[win.length - 1]) - tsOf(win[0])) / 3600000));
      findings.push({
        type:          'CREDENTIAL_STUFFING',
        severity:      'high',
        ip,
        country:       win[0].country,
        affectedUsers: users,
        eventCount:    win.length,
        windowStart:   win[0].createdAt,
        windowEnd:     win[win.length - 1].createdAt,
        message:       `Credential stuffing from ${ip}: ${users.length} distinct accounts targeted over ~${hours}h — likely automated list-based attack`,
      });
    }
  }
  return findings;
}

/**
 * Device Fingerprint Anomaly:
 * A user successfully logs in with a User-Agent string never seen before in their
 * sign-in history, from a foreign/untrusted country. Indicates a new device or
 * tool being used by an attacker who obtained valid credentials.
 */
function detectDeviceFingerprintAnomaly(events, { homeCountry = 'ID', trustedCountries = [], trustedIPs = [], minBaseline = 5 } = {}) {
  const trusted = trustedSet(homeCountry, trustedCountries);
  const findings = [];

  const byUser = groupBy(events.filter(e => e.userPrincipal && e.userAgent), e => e.userPrincipal);

  for (const [user, sorted] of Object.entries(byUser)) {
    if (sorted.length < minBaseline) continue;
    const seenUAs = new Set();

    for (const e of sorted) {
      const ua = e.userAgent;
      const isNew = !seenUAs.has(ua);
      seenUAs.add(ua);

      if (!isNew) continue;
      if (!e.success) continue;
      if (!e.country) continue;
      if (trusted.has(e.country.toUpperCase())) continue;
      if (isTrustedIP(e.ipAddress, trustedIPs)) continue;
      if (seenUAs.size <= 1) continue; // need at least one prior UA for baseline

      findings.push({
        type:       'DEVICE_FINGERPRINT_ANOMALY',
        severity:   'medium',
        user,
        userAgent:  ua,
        country:    e.country,
        city:       e.city,
        ip:         e.ipAddress,
        time:       e.createdAt,
        app:        e.appName,
        isManaged:  e.isManaged,
        isCompliant: e.isCompliant,
        message:    `Device fingerprint anomaly for ${user}: new User-Agent first seen from foreign location ${e.country}${e.city ? ' / ' + e.city : ''}${e.isManaged === false ? ' on an unmanaged device' : ''} — possible new attacker device`,
      });
      break; // one finding per user
    }
  }
  return findings;
}

/**
 * OAuth Consent Phishing:
 * A user successfully authenticates to an application for the very first time
 * from a foreign/untrusted location via interactive browser sign-in.
 * Attackers register malicious OAuth apps and phish users into consenting —
 * the consent + first-access appear as a new interactive sign-in from abroad.
 * Maps to MITRE T1528 (Steal Application Access Token).
 * (The audit-log rule OAUTH_CONSENT_GRANT confirms actual consent grants.)
 */
function detectOAuthConsentPhishing(events, { homeCountry = 'ID', trustedCountries = [], trustedIPs = [], minBaseline = 3 } = {}) {
  const trusted = trustedSet(homeCountry, trustedCountries);
  const findings = [];

  // Only look at interactive/browser events
  const relevant = events.filter(e =>
    e.userPrincipal && e.appName &&
    (e.signInType === 'interactive' || e.clientAppUsed?.toLowerCase() === 'browser')
  );

  for (const [user, sorted] of Object.entries(groupBy(relevant, e => e.userPrincipal))) {
    if (sorted.length < minBaseline) continue;
    const seenApps = new Set();

    for (const e of sorted) {
      const appKey = e.appName.toLowerCase();
      const isNew = !seenApps.has(appKey);
      seenApps.add(appKey);

      if (!isNew) continue;
      if (!e.success) continue;
      if (!e.country) continue;
      if (trusted.has(e.country.toUpperCase())) continue;
      if (isTrustedIP(e.ipAddress, trustedIPs)) continue;
      if (seenApps.size <= 1) continue; // need at least one prior app for baseline

      findings.push({
        type:    'OAUTH_CONSENT_PHISHING',
        severity: 'high',
        user,
        app:     e.appName,
        country: e.country,
        city:    e.city,
        ip:      e.ipAddress,
        time:    e.createdAt,
        message: `OAuth consent phishing suspected for ${user}: first-ever access to "${e.appName}" from foreign location ${e.country}${e.city ? ' / ' + e.city : ''} — possible malicious app consent grant (T1528)`,
      });
      break; // one finding per user
    }
  }
  return findings;
}

/**
 * Distributed Brute Force:
 * Many different IPs (10+) all fail authentication against the same user within 1 hour.
 * Bypasses per-IP brute force detection because each individual IP has low attempt count,
 * but total volume against one target is high. Classic botnet/distributed attack pattern.
 */
function detectDistributedBruteForce(events, { windowMs = 60 * 60 * 1000, minIPs = 10 } = {}) {
  const findings = [];
  const byUser = groupBy(
    events.filter(e => isFailedAttempt(e) && e.userPrincipal && e.ipAddress),
    e => e.userPrincipal
  );

  for (const [user, userEvents] of Object.entries(byUser)) {
    for (const win of findBursts(userEvents, { windowMs, minDistinct: minIPs, keyFn: e => e.ipAddress })) {
      const ips = uniq(win.map(e => e.ipAddress));
      findings.push({
        type:        'DISTRIBUTED_BRUTE_FORCE',
        severity:    'high',
        user,
        ipCount:     ips.length,
        uniqueIPs:   ips.slice(0, 20),
        attemptCount: win.length,
        countries:   uniq(win.map(e => e.country)),
        windowStart: win[0].createdAt,
        windowEnd:   win[win.length - 1].createdAt,
        message:     `Distributed brute force against ${user}: ${ips.length} source IPs, ${win.length} attempts (≥${minIPs} IPs within ${Math.round(windowMs / 3600000)}h) — possible botnet attack`,
      });
    }
  }
  return findings;
}

/**
 * MFA Method Downgrade:
 * A user with a consistent MFA baseline suddenly signs in with
 *   (a) single-factor authentication only, or
 *   (b) a weak second factor (SMS / voice call) after a baseline of
 *       Authenticator app / FIDO2 / Windows Hello.
 * May indicate session token theft, a Conditional Access gap, or an attacker
 * who SIM-swapped / social-engineered the weaker method.
 * Requires ≥10 prior baseline events with ≥70% consistency.
 */
function detectMFAMethodDowngrade(events, { minBaseline = 10, mfaThreshold = 0.70, trustedIPs = [] } = {}) {
  const findings = [];

  const relevant = events.filter(e =>
    e.success && e.userPrincipal && (e.authMethod || e.mfaMethod) &&
    (e.signInType === 'interactive' || !e.signInType)
  );

  const isMFA = e => {
    const m = (e.authMethod || '').toLowerCase();
    return !!e.mfaMethod || m.includes('multifactor') || m.includes('mfa');
  };
  const isSingleFactor = e => (e.authMethod || '').toLowerCase().includes('singlefactor');

  for (const [user, sorted] of Object.entries(groupBy(relevant, e => e.userPrincipal))) {
    if (sorted.length <= minBaseline) continue;

    // Walk chronologically: once a baseline of ≥minBaseline prior sign-ins exists,
    // flag the first downgrade that follows it.
    let mfaCount = 0, withMethod = 0, strongMethod = 0;
    let worst = null, reason = '', pct = 0;
    for (let i = 0; i < sorted.length; i++) {
      const e = sorted[i];
      if (i >= minBaseline && !isTrustedIP(e.ipAddress, trustedIPs)) {
        if (isSingleFactor(e) && mfaCount / i >= mfaThreshold) {
          worst = e; reason = 'single-factor'; pct = mfaCount / i; break;
        }
        if (e.mfaStrength === 'weak' && withMethod >= minBaseline / 2 && strongMethod / withMethod >= mfaThreshold) {
          worst = e; reason = 'weak-method'; pct = strongMethod / withMethod; break;
        }
      }
      if (isMFA(e)) mfaCount++;
      if (e.mfaStrength) {
        withMethod++;
        if (e.mfaStrength !== 'weak') strongMethod++;
      }
    }

    if (!worst) continue;
    const pctLabel = Math.round(pct * 100);
    findings.push({
      type:          'MFA_METHOD_DOWNGRADE',
      severity:      'high',
      user,
      authMethod:    worst.authMethod,
      mfaMethod:     worst.mfaMethod,
      downgrade:     reason,
      baselineMFAPct: pctLabel,
      ip:            worst.ipAddress,
      country:       worst.country,
      city:          worst.city,
      time:          worst.createdAt,
      app:           worst.appName,
      message: reason === 'single-factor'
        ? `MFA method downgrade for ${user}: signed in with single-factor auth — baseline shows ${pctLabel}% MFA usage. Possible CA bypass or token theft.`
        : `MFA method downgrade for ${user}: signed in with weak method "${worst.mfaMethod}" — baseline shows ${pctLabel}% Authenticator/FIDO usage. Possible SIM swap or social engineering.`,
    });
  }
  return findings;
}

/**
 * Entra ID Risky Sign-in:
 * Microsoft Identity Protection already scored the sign-in as risky
 * (riskLevelDuringSignIn medium/high or riskState atRisk/confirmedCompromised)
 * and it still succeeded. Requires Entra ID P2 for the risk fields to be populated.
 */
function detectEntraRiskySignin(events) {
  const findings = [];
  const RISKY_LEVELS = new Set(['medium', 'high']);
  const RISKY_STATES = new Set(['atrisk', 'confirmedcompromised']);

  const relevant = events.filter(e =>
    e.success && e.userPrincipal &&
    (RISKY_LEVELS.has((e.riskLevelDuringSignIn || '').toLowerCase()) ||
     RISKY_STATES.has((e.riskState || '').toLowerCase()))
  );

  for (const [user, userEvents] of Object.entries(groupBy(relevant, e => e.userPrincipal))) {
    const levels = uniq(userEvents.map(e => (e.riskLevelDuringSignIn || '').toLowerCase()));
    const states = uniq(userEvents.map(e => (e.riskState || '').toLowerCase()));
    const riskEventTypes = uniq(userEvents.flatMap(e => e.riskEventTypes || []));
    const high = levels.includes('high') || states.includes('confirmedcompromised');

    findings.push({
      type:           'ENTRA_RISKY_SIGNIN',
      severity:       high ? 'high' : 'medium',
      user,
      riskLevels:     levels,
      riskStates:     states,
      riskEventTypes,
      ips:            uniq(userEvents.map(e => e.ipAddress)).slice(0, 20),
      countries:      uniq(userEvents.map(e => e.country)),
      eventCount:     userEvents.length,
      firstSeen:      userEvents[0].createdAt,
      lastSeen:       userEvents[userEvents.length - 1].createdAt,
      message:        `Microsoft Identity Protection flagged ${userEvents.length} successful sign-in(s) for ${user} as risky (${levels.filter(Boolean).join('/') || states.join('/')})${riskEventTypes.length ? ': ' + riskEventTypes.slice(0, 4).join(', ') : ''}`,
    });
  }
  return findings;
}

// ─── Main runner ──────────────────────────────────────────────────────────────

function runDetections(events, opts = {}) {
  const { homeCountry, trustedCountries, trustedIPs, thresholds = {}, timezone, asnLookup } = opts;
  const base = { homeCountry, trustedCountries, trustedIPs };

  // Sort once — every rule relies on chronological order within its groups
  const sorted = events.every((e, i) => i === 0 || tsOf(events[i - 1]) <= tsOf(e))
    ? events
    : [...events].sort(byTime);

  return [
    ...detectPasswordSpray(sorted, { ...base,
      windowMs:   (thresholds.sprayWindowMin   || 10) * 60000,
      minUsers:    thresholds.sprayMinUsers    || 5 }),
    ...detectImpossibleTravel(sorted, { ...base,
      maxSpeedKmh: thresholds.travelMaxSpeedKmh || 900 }),
    ...detectForeignLogins(sorted, base),
    ...detectBruteForce(sorted, { ...base,
      windowMs:     (thresholds.bruteWindowMin   || 10) * 60000,
      minAttempts:   thresholds.bruteMinAttempts || 10 }),
    ...detectAdminToolAbuse(sorted, base),
    ...detectMFAExhaustion(sorted, { ...base,
      minPrompts: thresholds.mfaMinPrompts || 5 }),
    ...detectLegacyAuth(sorted),
    ...detectCAGap(sorted, base),
    ...detectTokenReplay(sorted, { ...base, asnLookup }),
    ...detectEnumerationAttack(sorted, { ...base,
      minUsers: thresholds.enumMinUsers || 10 }),
    ...detectServicePrincipalAnomaly(sorted, base),
    ...detectTimeOfDayAnomaly(sorted, { ...base, timezone }),
    ...detectFirstSeenCountry(sorted, base),
    ...detectConcurrentSessions(sorted, base),
    ...detectRareAppAccess(sorted, base),
    ...detectCredentialStuffing(sorted, { ...base,
      windowMs:  (thresholds.stuffingWindowHr || 24) * 3600000,
      minUsers:   thresholds.stuffingMinUsers || 8 }),
    ...detectDeviceFingerprintAnomaly(sorted, base),
    ...detectOAuthConsentPhishing(sorted, base),
    ...detectDistributedBruteForce(sorted, { ...base,
      windowMs:  (thresholds.distBruteWindowHr || 1) * 3600000,
      minIPs:     thresholds.distBruteMinIPs   || 10 }),
    ...detectMFAMethodDowngrade(sorted, { ...base }),
    ...detectEntraRiskySignin(sorted),
  ];
}

module.exports = {
  runDetections,
  findBursts,
  detectPasswordSpray,
  detectImpossibleTravel,
  detectForeignLogins,
  detectBruteForce,
  detectAdminToolAbuse,
  detectMFAExhaustion,
  detectLegacyAuth,
  detectCAGap,
  detectTokenReplay,
  detectEnumerationAttack,
  detectServicePrincipalAnomaly,
  detectTimeOfDayAnomaly,
  detectFirstSeenCountry,
  detectConcurrentSessions,
  detectRareAppAccess,
  detectCredentialStuffing,
  detectDeviceFingerprintAnomaly,
  detectOAuthConsentPhishing,
  detectDistributedBruteForce,
  detectMFAMethodDowngrade,
  detectEntraRiskySignin,
  isTrustedIP,
  networkKey,
  hourIn,
  COUNTRY_COORDS,
};
