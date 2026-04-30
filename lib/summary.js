/**
 * Build per-user risk summaries and attack timeline for the dashboard.
 */

function groupBy(arr, keyFn) {
  return arr.reduce((acc, item) => {
    const k = keyFn(item);
    (acc[k] = acc[k] || []).push(item);
    return acc;
  }, {});
}

// ─── Risk level ───────────────────────────────────────────────────────────────

function computeRiskScore(dets, foreignSuccess, attackingCountries) {
  const types = new Set(dets.map(d => d.type));
  const riskLabel = getRiskLevel(dets, foreignSuccess, attackingCountries);
  // Base score anchored to risk level
  let score = { CRITICAL: 72, HIGH: 48, MEDIUM: 22, LOW: 8 }[riskLabel] || 10;
  // Foreign successful logins — strongest compromise signal
  score += Math.min(foreignSuccess * 9, 18);
  // High-impact detection type bonuses (stacking)
  const bonuses = {
    MFA_EXHAUSTION: 8, TOKEN_REPLAY: 8, OAUTH_CONSENT_PHISHING: 8,
    IMPOSSIBLE_TRAVEL: 6, ADMIN_TOOL_ABUSE: 6, CREDENTIAL_STUFFING: 5,
    DISTRIBUTED_BRUTE_FORCE: 5, PASSWORD_SPRAY: 4, CONCURRENT_SESSIONS: 4,
    BRUTE_FORCE: 3, SERVICE_PRINCIPAL_ANOMALY: 3, MFA_METHOD_DOWNGRADE: 3,
  };
  for (const [t, pts] of Object.entries(bonuses)) { if (types.has(t)) score += pts; }
  // Breadth: each unique detection type adds 2 pts (cap at 10)
  score += Math.min(types.size * 2, 10);
  // Geo spread: attacking countries (cap at 6)
  score += Math.min((attackingCountries?.length || 0), 6);
  return Math.min(Math.round(score), 100);
}

function getRiskLevel(dets, foreignSuccess, attackingCountries) {
  const types = new Set(dets.map(d => d.type));
  if (foreignSuccess > 0)                               return 'CRITICAL';
  if (types.has('PASSWORD_SPRAY') && attackingCountries.length >= 20) return 'CRITICAL';
  if (types.has('PASSWORD_SPRAY') || types.has('IMPOSSIBLE_TRAVEL'))  return 'HIGH';
  if (types.has('ADMIN_TOOL_ABUSE') && attackingCountries.length >= 3) return 'HIGH';
  if (types.has('TOKEN_REPLAY') || types.has('CONCURRENT_SESSIONS') || types.has('SERVICE_PRINCIPAL_ANOMALY')) return 'HIGH';
  return 'MEDIUM';
}

function getPrimaryThreat(dets, foreignSuccessCount) {
  const types = new Set(dets.map(d => d.type));
  if (foreignSuccessCount > 0 && types.has('PASSWORD_SPRAY'))  return 'Successful Foreign Login + Spray';
  if (foreignSuccessCount > 0)                                  return 'Successful Foreign Login';
  if (types.has('PASSWORD_SPRAY') && types.has('ADMIN_TOOL_ABUSE')) return 'Multi-vector Attack';
  if (types.has('PASSWORD_SPRAY'))   return 'Password Spray';
  if (types.has('IMPOSSIBLE_TRAVEL')) return 'Impossible Travel';
  if (types.has('ADMIN_TOOL_ABUSE')) return 'Admin Tool Abuse';
  if (types.has('BRUTE_FORCE'))      return 'Brute Force';
  if (types.has('MFA_EXHAUSTION'))           return 'MFA Exhaustion Attack';
  if (types.has('LEGACY_AUTH'))              return 'Legacy Auth Usage';
  if (types.has('CA_GAP'))                   return 'CA Policy Gap';
  if (types.has('TOKEN_REPLAY'))             return 'Token Replay / Session Hijack';
  if (types.has('ENUMERATION_ATTACK'))       return 'Account Enumeration';
  if (types.has('SERVICE_PRINCIPAL_ANOMALY')) return 'Service Principal Anomaly';
  if (types.has('CONCURRENT_SESSIONS'))       return 'Concurrent Sessions';
  if (types.has('FIRST_SEEN_COUNTRY'))        return 'First-Seen Country Login';
  if (types.has('TIME_OF_DAY_ANOMALY'))       return 'Off-Hours Login';
  if (types.has('RARE_APP_ACCESS'))           return 'Rare Application Access';
  return 'Foreign Login';
}

// ─── Narrative generator ──────────────────────────────────────────────────────

function generateNarrative(s) {
  const parts = [];

  if (s.successfulForeignEvents.length > 0) {
    const e  = s.successfulForeignEvents[0];
    const dt = new Date(e.time || e.createdAt).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
    const apps = s.successfulForeignApps.slice(0, 2).join(' & ');
    parts.push(
      `Successfully signed in from ${e.foreignCountry || e.country}${e.foreignCity ? ' / ' + e.foreignCity : ''} on ${dt}` +
      (apps ? ` to ${apps}` : '') +
      ` — credentials may be compromised. Immediate password reset recommended.`
    );
  }

  if (s.foreignAttempts > 0 && s.errorCodes.length > 0) {
    const errDesc = s.errorCodes.map(c => {
      if (c === 50126) return '50126 (invalid password)';
      if (c === 50053) return '50053 (account locked)';
      if (c === 50076) return '50076 (MFA required)';
      if (c === 50057) return '50057 (account disabled)';
      return String(c);
    }).join(' & ');
    parts.push(`${s.foreignAttempts} failed attempts from ${s.uniqueAttackingCountries} countries. Errors: ${errDesc}.`);
  } else if (s.foreignAttempts > 0) {
    parts.push(`${s.foreignAttempts} failed attempts from ${s.uniqueAttackingCountries} countries.`);
  }

  if (s.hasAdminAbuse && s.adminApps.length > 0) {
    parts.push(
      `Admin tools used from foreign location (${s.adminApps.slice(0, 2).join(', ')}) — indicates attempted lateral movement.`
    );
  }

  if (s.uniqueAttackingCountries >= 20) {
    parts.push('Wide geographic spread indicates distributed botnet or global proxy network.');
  } else if (s.uniqueAttackingCountries >= 10) {
    parts.push('Multiple continents involved — likely coordinated attack.');
  }

  return parts.join(' ');
}

// ─── Build user summaries ─────────────────────────────────────────────────────

function buildUserSummaries(events, detections, homeCountry) {
  const home = homeCountry.toUpperCase();

  // Map users → detections
  const userDets = {};
  for (const d of detections) {
    const users = [];
    if (d.user) users.push(d.user);
    if (d.affectedUsers) d.affectedUsers.forEach(u => users.push(u));
    for (const u of users) {
      (userDets[u] = userDets[u] || []).push(d);
    }
  }

  const byUser = groupBy(events, e => e.userPrincipal);
  const summaries = [];

  for (const [user, userEvents] of Object.entries(byUser)) {
    const dets = userDets[user];
    if (!dets || dets.length === 0) continue;

    const foreignEvents   = userEvents.filter(e => e.country && e.country.toUpperCase() !== home);
    const foreignFailed   = foreignEvents.filter(e => !e.success);
    const foreignSucc     = foreignEvents.filter(e => e.success);
    const attackCountries = [...new Set(foreignEvents.map(e => e.country).filter(Boolean))];
    const errorCodes      = [...new Set(foreignFailed.map(e => e.errorCode).filter(c => c !== null && c !== 0))];
    const adminEvents     = userEvents.filter(e => e.appType === 'Admin' && e.country && e.country.toUpperCase() !== home);

    // Time range of foreign attack events
    const attackTimes = foreignEvents.map(e => new Date(e.createdAt)).filter(d => !isNaN(d)).sort((a,b) => a-b);
    const attackStart = attackTimes[0]?.toISOString();
    const attackEnd   = attackTimes[attackTimes.length-1]?.toISOString();

    const riskLevel     = getRiskLevel(dets, foreignSucc.length, attackCountries);
    const riskScore     = computeRiskScore(dets, foreignSucc.length, attackCountries);
    const primaryThreat = getPrimaryThreat(dets, foreignSucc.length);

    const successfulForeignApps = [...new Set(foreignSucc.map(e => e.appName).filter(Boolean))];

    const summary = {
      user,
      displayName:            userEvents[0]?.displayName || user.split('@')[0],
      riskLevel,
      riskScore,
      primaryThreat,
      foreignAttempts:        foreignFailed.length,
      foreignSuccess:         foreignSucc.length,
      successfulForeignEvents: foreignSucc.map(e => ({ ...e, foreignCountry: e.country, foreignCity: e.city })),
      successfulForeignApps,
      attackingCountries:     attackCountries,
      uniqueAttackingCountries: attackCountries.length,
      attackStart,
      attackEnd,
      errorCodes,
      hasAdminAbuse: dets.some(d => d.type === 'ADMIN_TOOL_ABUSE'),
      adminApps:     [...new Set(adminEvents.map(e => e.appName || e.clientAppUsed).filter(Boolean))],
      totalUserEvents: userEvents.length,
      detectionTypes: [...new Set(dets.map(d => d.type))],
    };

    summary.narrative = generateNarrative(summary);
    summaries.push(summary);
  }

  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2 };
  return summaries.sort((a, b) => {
    const lvlDiff = order[a.riskLevel] - order[b.riskLevel];
    if (lvlDiff !== 0) return lvlDiff;
    return b.foreignAttempts - a.foreignAttempts; // more attempts = higher priority
  });
}

// ─── Attack timeline ──────────────────────────────────────────────────────────

function buildAttackTimeline(events, homeCountry) {
  const home = homeCountry.toUpperCase();

  // First foreign failed events, ordered by time
  const foreign = events
    .filter(e => !e.success && e.country && e.country.toUpperCase() !== home && e.createdAt)
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));

  // Keep first 30 events, deduplicate by user+hour (to avoid spam)
  const seen  = new Set();
  const timeline = [];
  for (const e of foreign) {
    const hour = new Date(e.createdAt).toISOString().slice(0, 13);
    const key  = `${e.userPrincipal}|${hour}`;
    if (seen.has(key)) continue;
    seen.add(key);
    timeline.push({
      time:        e.createdAt,
      displayName: e.displayName || e.userPrincipal.split('@')[0],
      user:        e.userPrincipal,
      country:     e.country,
      city:        e.city,
      errorCode:   e.errorCode,
      ip:          e.ipAddress,
      appName:     e.appName,
    });
    if (timeline.length >= 30) break;
  }

  return timeline;
}

module.exports = { buildUserSummaries, buildAttackTimeline };
