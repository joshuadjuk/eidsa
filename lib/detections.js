/**
 * Detection rules for Entra ID sign-in logs.
 */

// ─── Helpers ──────────────────────────────────────────────────────────────────

function groupBy(arr, keyFn) {
  return arr.reduce((acc, item) => {
    const k = keyFn(item);
    (acc[k] = acc[k] || []).push(item);
    return acc;
  }, {});
}

function toMs(dateStr) {
  return new Date(dateStr).getTime();
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
};

function getCountryCoords(code) {
  return COUNTRY_COORDS[(code || '').toUpperCase()] || null;
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

// ─── Rules ────────────────────────────────────────────────────────────────────

function detectPasswordSpray(events, { windowMs = 10 * 60 * 1000, minUsers = 5 } = {}) {
  const findings = [];
  const byIp = groupBy(events.filter(e => !e.success && e.ipAddress), e => e.ipAddress);

  for (const [ip, ipEvents] of Object.entries(byIp)) {
    const sorted = [...ipEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    let left = 0;
    for (let right = 0; right < sorted.length; right++) {
      while (toMs(sorted[right].createdAt) - toMs(sorted[left].createdAt) > windowMs) left++;
      const window = sorted.slice(left, right + 1);
      const users = new Set(window.map(e => e.userPrincipal));
      if (users.size >= minUsers) {
        findings.push({
          type: 'PASSWORD_SPRAY',
          severity: 'high',
          ip,
          country: sorted[left].country,
          affectedUsers: [...users],
          eventCount: window.length,
          windowStart: sorted[left].createdAt,
          windowEnd: sorted[right].createdAt,
          message: `Password spray from ${ip}: ${users.size} users targeted in ${Math.round(windowMs / 60000)} min window`
        });
        break;
      }
    }
  }
  return findings;
}

function detectImpossibleTravel(events, { maxSpeedKmh = 500 } = {}) {
  const findings = [];
  const byUser = groupBy(events.filter(e => e.success && e.country), e => e.userPrincipal);

  for (const [user, userEvents] of Object.entries(byUser)) {
    const sorted = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    for (let i = 1; i < sorted.length; i++) {
      const prev = sorted[i - 1];
      const curr = sorted[i];
      if (prev.country === curr.country) continue;

      const prevCoords = getCountryCoords(prev.country);
      const currCoords = getCountryCoords(curr.country);
      if (!prevCoords || !currCoords) continue;

      const distKm = haversineKm(...prevCoords, ...currCoords);
      const timeDiffH = (toMs(curr.createdAt) - toMs(prev.createdAt)) / 3_600_000;
      if (timeDiffH <= 0) continue;

      const speedKmh = distKm / timeDiffH;
      if (speedKmh > maxSpeedKmh) {
        findings.push({
          type: 'IMPOSSIBLE_TRAVEL',
          severity: 'high',
          user,
          from: { country: prev.country, city: prev.city, ip: prev.ipAddress, time: prev.createdAt },
          to:   { country: curr.country, city: curr.city, ip: curr.ipAddress, time: curr.createdAt },
          distanceKm: Math.round(distKm),
          speedKmh: Math.round(speedKmh),
          message: `Impossible travel for ${user}: ${prev.country}→${curr.country} (${Math.round(distKm)} km in ${timeDiffH.toFixed(2)}h)`
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
  const trusted = new Set([home, ...trustedCountries.map(c => c.toUpperCase())]);
  const findings = [];

  for (const e of events) {
    if (!e.success) continue;
    if (!e.country) continue;
    if (trusted.has(e.country.toUpperCase())) continue;
    if (isTrustedIP(e.ipAddress, trustedIPs)) continue;

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

  // Deduplicate per user+country
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.user}|${f.foreignCountry}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function detectBruteForce(events, { windowMs = 10 * 60 * 1000, minAttempts = 10 } = {}) {
  const findings = [];
  const byUser = groupBy(events.filter(e => !e.success && e.userPrincipal), e => e.userPrincipal);

  for (const [user, userEvents] of Object.entries(byUser)) {
    const sorted = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    let left = 0;
    for (let right = 0; right < sorted.length; right++) {
      while (toMs(sorted[right].createdAt) - toMs(sorted[left].createdAt) > windowMs) left++;
      const count = right - left + 1;
      if (count >= minAttempts) {
        const ips = new Set(sorted.slice(left, right + 1).map(e => e.ipAddress));
        findings.push({
          type: 'BRUTE_FORCE',
          severity: 'high',
          user,
          attemptCount: count,
          uniqueIPs: [...ips],
          windowStart: sorted[left].createdAt,
          windowEnd: sorted[right].createdAt,
          message: `Brute force against ${user}: ${count} failures in ${Math.round(windowMs / 60000)} min`
        });
        break;
      }
    }
  }
  return findings;
}

/**
 * Admin Tool Abuse: use of Azure CLI, PowerShell, Graph Explorer, etc.
 * from a country that is not the home country — indicates lateral movement.
 */
function detectAdminToolAbuse(events, { homeCountry = 'ID', trustedCountries = [], trustedIPs = [] } = {}) {
  const home    = homeCountry.toUpperCase();
  const trusted = new Set([home, ...trustedCountries.map(c => c.toUpperCase())]);

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
  for (const e of events) {
    if (!isAdminApp(e)) continue;
    if (!e.country || trusted.has(e.country.toUpperCase())) continue;
    if (isTrustedIP(e.ipAddress, trustedIPs)) continue;

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

  // Deduplicate per user+app+country
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.user}|${f.app}|${f.country}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * MFA Exhaustion / MFA Fatigue: repeated MFA challenges in a short window.
 * Attackers flood users with MFA prompts hoping they accept one by mistake.
 */
function detectMFAExhaustion(events, { windowMs = 60 * 60 * 1000, minPrompts = 5 } = {}) {
  // Error codes related to MFA challenges/failures
  const MFA_ERRORS = new Set([50076, 500121, 50074, 53003, 50158]);
  const findings   = [];

  const byUser = groupBy(
    events.filter(e => !e.success && MFA_ERRORS.has(e.errorCode) && e.userPrincipal),
    e => e.userPrincipal
  );

  for (const [user, userEvents] of Object.entries(byUser)) {
    const sorted = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    let left = 0;
    for (let right = 0; right < sorted.length; right++) {
      while (toMs(sorted[right].createdAt) - toMs(sorted[left].createdAt) > windowMs) left++;
      const count = right - left + 1;
      if (count >= minPrompts) {
        const ips = [...new Set(sorted.slice(left, right + 1).map(e => e.ipAddress).filter(Boolean))];
        findings.push({
          type:        'MFA_EXHAUSTION',
          severity:    count >= 15 ? 'high' : 'medium',
          user,
          promptCount: count,
          uniqueIPs:   ips,
          windowStart: sorted[left].createdAt,
          windowEnd:   sorted[right].createdAt,
          message:     `MFA exhaustion attempt against ${user}: ${count} MFA challenges in ${Math.round(windowMs / 60000)} min — possible MFA fatigue attack`,
        });
        break;
      }
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

    const protocols = [...new Set(userEvents.map(e => e.clientAppUsed).filter(Boolean))];
    const apps      = [...new Set(userEvents.map(e => e.appName).filter(Boolean))];
    const sorted    = [...successEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));

    findings.push({
      type:         'LEGACY_AUTH',
      severity:     'medium',
      user,
      protocols,
      apps,
      successCount: successEvents.length,
      totalCount:   userEvents.length,
      firstSeen:    sorted[0]?.createdAt,
      lastSeen:     sorted[sorted.length - 1]?.createdAt,
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
  const home    = homeCountry.toUpperCase();
  const trusted = new Set([home, ...trustedCountries.map(c => c.toUpperCase())]);

  const relevant = events.filter(e =>
    e.signInType === 'interactive' &&
    e.conditionalAccessStatus === 'notApplied' &&
    e.success &&
    e.country &&
    !trusted.has(e.country.toUpperCase()) &&
    !isTrustedIP(e.ipAddress, trustedIPs)
  );

  const byUser = groupBy(relevant, e => e.userPrincipal);
  const findings = [];

  for (const [user, userEvents] of Object.entries(byUser)) {
    // Deduplicate per user+country
    const seen = new Set();
    const countries = [];
    for (const e of userEvents) {
      const key = `${user}|${e.country}`;
      if (!seen.has(key)) { seen.add(key); countries.push(e.country); }
    }
    const apps = [...new Set(userEvents.map(e => e.appName).filter(Boolean))];

    findings.push({
      type:       'CA_GAP',
      severity:   'medium',
      user,
      countries,
      apps,
      eventCount: userEvents.length,
      message:    `CA policy not applied for ${user}: interactive sign-in(s) from ${countries.join(', ')} without Conditional Access (${userEvents.length} event${userEvents.length > 1 ? 's' : ''})`,
    });
  }

  return findings;
}

/**
 * Token Replay / Session Hijack:
 * Same user has successful sign-ins from 2+ different IPs within 30 seconds.
 * Indicates a stolen token being replayed from a different location.
 */
function detectTokenReplay(events, { windowMs = 30 * 1000 } = {}) {
  const findings = [];
  const byUser = groupBy(
    events.filter(e => e.success && e.ipAddress && e.userPrincipal),
    e => e.userPrincipal
  );

  for (const [user, userEvents] of Object.entries(byUser)) {
    const sorted = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    let left = 0;
    for (let right = 1; right < sorted.length; right++) {
      while (toMs(sorted[right].createdAt) - toMs(sorted[left].createdAt) > windowMs) left++;
      const window = sorted.slice(left, right + 1);
      const ips = new Set(window.map(e => e.ipAddress));
      if (ips.size >= 2) {
        const ipList = [...ips];
        findings.push({
          type:        'TOKEN_REPLAY',
          severity:    'high',
          user,
          ips:         ipList,
          windowStart: sorted[left].createdAt,
          windowEnd:   sorted[right].createdAt,
          message:     `Token replay suspected for ${user}: ${ips.size} different IPs with successful sign-ins within ${windowMs / 1000}s — possible session hijack`,
        });
        break;
      }
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
  const relevant = events.filter(e =>
    !e.success && e.errorCode === 50034 && e.ipAddress
  );

  const byIp = groupBy(relevant, e => e.ipAddress);

  for (const [ip, ipEvents] of Object.entries(byIp)) {
    const sorted = [...ipEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    let left = 0;
    for (let right = 0; right < sorted.length; right++) {
      while (toMs(sorted[right].createdAt) - toMs(sorted[left].createdAt) > windowMs) left++;
      const window = sorted.slice(left, right + 1);
      const users = new Set(window.map(e => e.userPrincipal).filter(Boolean));
      if (users.size >= minUsers) {
        findings.push({
          type:        'ENUMERATION_ATTACK',
          severity:    'high',
          ip,
          country:     sorted[left].country,
          uniqueUsers: users.size,
          sampleUsers: [...users].slice(0, 5),
          eventCount:  window.length,
          windowStart: sorted[left].createdAt,
          windowEnd:   sorted[right].createdAt,
          message:     `Account enumeration from ${ip}: ${users.size} non-existent usernames probed in ${Math.round(windowMs / 60000)} min (error 50034)`,
        });
        break;
      }
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
  const home    = homeCountry.toUpperCase();
  const trusted = new Set([home, ...trustedCountries.map(c => c.toUpperCase())]);

  const relevant = events.filter(e =>
    e.signInType === 'servicePrincipal' &&
    e.success &&
    e.country &&
    !trusted.has(e.country.toUpperCase()) &&
    !isTrustedIP(e.ipAddress, trustedIPs)
  );

  const bySP = groupBy(relevant, e => e.userPrincipal);
  const findings = [];

  for (const [sp, spEvents] of Object.entries(bySP)) {
    const countries = [...new Set(spEvents.map(e => e.country).filter(Boolean))];
    const ips       = [...new Set(spEvents.map(e => e.ipAddress).filter(Boolean))];
    const apps      = [...new Set(spEvents.map(e => e.appName || e.resourceName).filter(Boolean))];
    const sorted    = [...spEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));

    findings.push({
      type:       'SERVICE_PRINCIPAL_ANOMALY',
      severity:   'high',
      user:       sp,
      countries,
      ips,
      apps,
      eventCount: spEvents.length,
      firstSeen:  sorted[0]?.createdAt,
      lastSeen:   sorted[sorted.length - 1]?.createdAt,
      message:    `Service principal anomaly: "${sp}" authenticated from foreign location${countries.length > 1 ? 's' : ''} (${countries.join(', ')}) — ${spEvents.length} event${spEvents.length > 1 ? 's' : ''}`,
    });
  }
  return findings;
}

/**
 * Time-of-Day Anomaly:
 * Successful login at an hour significantly outside the user's normal schedule.
 * Baseline = P10–P90 of their interactive login hours. Requires ≥10 events.
 */
function detectTimeOfDayAnomaly(events, { minBaseline = 10 } = {}) {
  const findings = [];

  // Only interactive successful sign-ins for baseline
  const relevant = events.filter(e =>
    e.success && e.userPrincipal &&
    (e.signInType === 'interactive' || !e.signInType)
  );

  const byUser = groupBy(relevant, e => e.userPrincipal);

  for (const [user, userEvents] of Object.entries(byUser)) {
    if (userEvents.length < minBaseline) continue;

    const sorted     = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    const sortedHrs  = sorted.map(e => new Date(e.createdAt).getUTCHours()).sort((a, b) => a - b);

    const p10 = sortedHrs[Math.floor(sortedHrs.length * 0.10)];
    const p90 = sortedHrs[Math.floor(sortedHrs.length * 0.90)];

    // Only flag users with a tight schedule (≤12h spread)
    if (p90 - p10 > 12) continue;

    const lower = p10 - 1;   // 1h buffer
    const upper = p90 + 1;

    let worst = null;
    let worstDiff = 0;

    for (const e of sorted) {
      const h    = new Date(e.createdAt).getUTCHours();
      const diff = h < lower ? lower - h : h > upper ? h - upper : 0;
      if (diff > 2 && diff > worstDiff) { worst = e; worstDiff = diff; }
    }

    if (worst) {
      const h = new Date(worst.createdAt).getUTCHours();
      findings.push({
        type:         'TIME_OF_DAY_ANOMALY',
        severity:     'medium',
        user,
        anomalousHour: h,
        normalWindow:  `${String(p10).padStart(2, '0')}:00–${String(p90).padStart(2, '0')}:00 UTC`,
        time:          worst.createdAt,
        ip:            worst.ipAddress,
        country:       worst.country,
        app:           worst.appName,
        message:       `Off-hours login for ${user}: signed in at ${String(h).padStart(2, '0')}:00 UTC (typical window: ${String(p10).padStart(2, '0')}:00–${String(p90).padStart(2, '0')}:00 UTC)`,
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
  const home    = homeCountry.toUpperCase();
  const trusted = new Set([home, ...trustedCountries.map(c => c.toUpperCase())]);
  const findings = [];

  const byUser = groupBy(
    events.filter(e => e.userPrincipal && e.country),
    e => e.userPrincipal
  );

  for (const [user, userEvents] of Object.entries(byUser)) {
    if (userEvents.length < minBaseline) continue;

    const sorted       = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    const seenCountries = new Set();

    for (const e of sorted) {
      const ctry  = e.country?.toUpperCase();
      if (!ctry) continue;

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

  const byUser = groupBy(
    events.filter(e => e.success && e.country && e.userPrincipal),
    e => e.userPrincipal
  );

  for (const [user, userEvents] of Object.entries(byUser)) {
    const sorted = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    let left = 0;

    for (let right = 1; right < sorted.length; right++) {
      while (toMs(sorted[right].createdAt) - toMs(sorted[left].createdAt) > windowMs) left++;
      const win       = sorted.slice(left, right + 1);
      const countries = new Set(win.map(e => e.country?.toUpperCase()).filter(Boolean));

      if (countries.size >= 2) {
        const ctryList = [...countries];
        const ips      = [...new Set(win.map(e => e.ipAddress).filter(Boolean))];
        findings.push({
          type:        'CONCURRENT_SESSIONS',
          severity:    'high',
          user,
          countries:   ctryList,
          ips,
          windowStart: sorted[left].createdAt,
          windowEnd:   sorted[right].createdAt,
          message:     `Concurrent sessions for ${user}: active from ${ctryList.join(' + ')} simultaneously within ${Math.round(windowMs / 60000)} min — possible token theft or account sharing`,
        });
        break;
      }
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
  const home    = homeCountry.toUpperCase();
  const trusted = new Set([home, ...trustedCountries.map(c => c.toUpperCase())]);
  const findings = [];

  const byUser = groupBy(
    events.filter(e => e.userPrincipal && e.appName),
    e => e.userPrincipal
  );

  for (const [user, userEvents] of Object.entries(byUser)) {
    if (userEvents.length < minBaseline) continue;

    const sorted = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));

    // Apps used from home/trusted locations = known baseline
    const homeApps = new Set(
      sorted
        .filter(e => e.success && e.country && trusted.has(e.country.toUpperCase()))
        .map(e => e.appName?.toLowerCase())
        .filter(Boolean)
    );

    if (homeApps.size === 0) continue; // no baseline from home

    const alreadyFlagged = new Set();

    for (const e of sorted) {
      if (!e.success || !e.appName || !e.country) continue;
      if (trusted.has(e.country.toUpperCase())) continue;
      if (isTrustedIP(e.ipAddress, trustedIPs)) continue;

      const appKey = e.appName.toLowerCase();
      if (homeApps.has(appKey) || alreadyFlagged.has(appKey)) continue;
      alreadyFlagged.add(appKey);

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
  const relevant = events.filter(e => !e.success && e.ipAddress && e.userPrincipal);
  const byIp = groupBy(relevant, e => e.ipAddress);

  for (const [ip, ipEvents] of Object.entries(byIp)) {
    const sorted = [...ipEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    let left = 0;
    for (let right = 0; right < sorted.length; right++) {
      while (toMs(sorted[right].createdAt) - toMs(sorted[left].createdAt) > windowMs) left++;
      const win = sorted.slice(left, right + 1);
      const users = new Set(win.map(e => e.userPrincipal));
      if (users.size >= minUsers) {
        const hours = Math.round(windowMs / 3600000);
        findings.push({
          type:          'CREDENTIAL_STUFFING',
          severity:      'high',
          ip,
          country:       sorted[left].country,
          affectedUsers: [...users],
          eventCount:    win.length,
          windowStart:   sorted[left].createdAt,
          windowEnd:     sorted[right].createdAt,
          message:       `Credential stuffing from ${ip}: ${users.size} distinct accounts targeted over ${hours}h — likely automated list-based attack`,
        });
        break;
      }
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
  const home    = homeCountry.toUpperCase();
  const trusted = new Set([home, ...trustedCountries.map(c => c.toUpperCase())]);
  const findings = [];

  const relevant = events.filter(e => e.userPrincipal && e.userAgent);
  const byUser = groupBy(relevant, e => e.userPrincipal);

  for (const [user, userEvents] of Object.entries(byUser)) {
    if (userEvents.length < minBaseline) continue;

    const sorted = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
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
        message:    `Device fingerprint anomaly for ${user}: new User-Agent first seen from foreign location ${e.country}${e.city ? ' / ' + e.city : ''} — possible new attacker device`,
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
 */
function detectOAuthConsentPhishing(events, { homeCountry = 'ID', trustedCountries = [], trustedIPs = [], minBaseline = 3 } = {}) {
  const home    = homeCountry.toUpperCase();
  const trusted = new Set([home, ...trustedCountries.map(c => c.toUpperCase())]);
  const findings = [];

  // Only look at interactive/browser events
  const relevant = events.filter(e =>
    e.userPrincipal && e.appName &&
    (e.signInType === 'interactive' || e.clientAppUsed?.toLowerCase() === 'browser')
  );

  const byUser = groupBy(relevant, e => e.userPrincipal);

  for (const [user, userEvents] of Object.entries(byUser)) {
    if (userEvents.length < minBaseline) continue;

    const sorted = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
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
function detectDistributedBruteForce(events, { windowMs = 60 * 60 * 1000, minIPs = 10, minAttempts = 5 } = {}) {
  const findings = [];
  const byUser = groupBy(
    events.filter(e => !e.success && e.userPrincipal && e.ipAddress),
    e => e.userPrincipal
  );

  for (const [user, userEvents] of Object.entries(byUser)) {
    const sorted = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));
    let left = 0;
    for (let right = 0; right < sorted.length; right++) {
      while (toMs(sorted[right].createdAt) - toMs(sorted[left].createdAt) > windowMs) left++;
      const win = sorted.slice(left, right + 1);
      const ips = new Set(win.map(e => e.ipAddress));
      if (ips.size >= minIPs) {
        const countries = [...new Set(win.map(e => e.country).filter(Boolean))];
        findings.push({
          type:        'DISTRIBUTED_BRUTE_FORCE',
          severity:    'high',
          user,
          ipCount:     ips.size,
          uniqueIPs:   [...ips].slice(0, 20),
          attemptCount: win.length,
          countries,
          windowStart: sorted[left].createdAt,
          windowEnd:   sorted[right].createdAt,
          message:     `Distributed brute force against ${user}: ${ips.size} source IPs, ${win.length} attempts in ${Math.round(windowMs / 3600000)}h — possible botnet attack`,
        });
        break;
      }
    }
  }
  return findings;
}

/**
 * MFA Method Downgrade:
 * A user who consistently authenticates with MFA (multiFactorAuthentication) suddenly
 * has a successful sign-in with only single-factor authentication (singleFactorAuthentication).
 * This may indicate session token theft, a Conditional Access gap, or attacker-controlled
 * sign-in bypassing MFA enforcement.
 * Requires ≥10 baseline events with consistent MFA usage (≥70% MFA).
 */
function detectMFAMethodDowngrade(events, { minBaseline = 10, mfaThreshold = 0.70, trustedIPs = [] } = {}) {
  const findings = [];

  const relevant = events.filter(e =>
    e.success && e.userPrincipal && e.authMethod &&
    (e.signInType === 'interactive' || !e.signInType)
  );

  const byUser = groupBy(relevant, e => e.userPrincipal);

  for (const [user, userEvents] of Object.entries(byUser)) {
    if (userEvents.length < minBaseline) continue;

    const sorted = [...userEvents].sort((a, b) => toMs(a.createdAt) - toMs(b.createdAt));

    // Build baseline from all but the most recent events
    const baselineEvents = sorted.slice(0, -1);
    if (baselineEvents.length < minBaseline - 1) continue;

    const mfaCount = baselineEvents.filter(e =>
      e.authMethod?.toLowerCase().includes('multifactor') ||
      e.authMethod?.toLowerCase().includes('mfa')
    ).length;
    const mfaRatio = mfaCount / baselineEvents.length;

    if (mfaRatio < mfaThreshold) continue; // baseline doesn't show consistent MFA

    // Check if recent events have single-factor
    const recentDowngrades = sorted.filter((e, idx) => {
      if (idx === 0) return false; // need baseline
      const isSingleFactor = e.authMethod?.toLowerCase().includes('singlefactor') ||
                             e.authMethod === 'singleFactorAuthentication';
      return isSingleFactor;
    });

    if (recentDowngrades.length === 0) continue;
    if (isTrustedIP(recentDowngrades[0].ipAddress, trustedIPs)) continue;

    const worst = recentDowngrades[0];
    findings.push({
      type:          'MFA_METHOD_DOWNGRADE',
      severity:      'high',
      user,
      authMethod:    worst.authMethod,
      baselineMFAPct: Math.round(mfaRatio * 100),
      ip:            worst.ipAddress,
      country:       worst.country,
      city:          worst.city,
      time:          worst.createdAt,
      app:           worst.appName,
      message:       `MFA method downgrade for ${user}: signed in with single-factor auth — baseline shows ${Math.round(mfaRatio * 100)}% MFA usage. Possible CA bypass or token theft.`,
    });
  }
  return findings;
}

// ─── Main runner ──────────────────────────────────────────────────────────────

function runDetections(events, opts = {}) {
  const { homeCountry, trustedCountries, trustedIPs, thresholds = {} } = opts;
  const base = { homeCountry, trustedCountries, trustedIPs };
  return [
    ...detectPasswordSpray(events, { ...base,
      windowMs:   (thresholds.sprayWindowMin   || 10) * 60000,
      minUsers:    thresholds.sprayMinUsers    || 5 }),
    ...detectImpossibleTravel(events, base),
    ...detectForeignLogins(events, base),
    ...detectBruteForce(events, { ...base,
      windowMs:     (thresholds.bruteWindowMin   || 10) * 60000,
      minAttempts:   thresholds.bruteMinAttempts || 10 }),
    ...detectAdminToolAbuse(events, base),
    ...detectMFAExhaustion(events, { ...base,
      minPrompts: thresholds.mfaMinPrompts || 5 }),
    ...detectLegacyAuth(events),
    ...detectCAGap(events, base),
    ...detectTokenReplay(events, base),
    ...detectEnumerationAttack(events, { ...base,
      minUsers: thresholds.enumMinUsers || 10 }),
    ...detectServicePrincipalAnomaly(events, base),
    ...detectTimeOfDayAnomaly(events, base),
    ...detectFirstSeenCountry(events, base),
    ...detectConcurrentSessions(events, base),
    ...detectRareAppAccess(events, base),
    ...detectCredentialStuffing(events, { ...base,
      windowMs:  (thresholds.stuffingWindowHr || 24) * 3600000,
      minUsers:   thresholds.stuffingMinUsers || 8 }),
    ...detectDeviceFingerprintAnomaly(events, base),
    ...detectOAuthConsentPhishing(events, base),
    ...detectDistributedBruteForce(events, { ...base,
      windowMs:  (thresholds.distBruteWindowHr || 1) * 3600000,
      minIPs:     thresholds.distBruteMinIPs   || 10 }),
    ...detectMFAMethodDowngrade(events, { ...base }),
  ];
}

module.exports = {
  runDetections,
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
  isTrustedIP,
  COUNTRY_COORDS,
};
