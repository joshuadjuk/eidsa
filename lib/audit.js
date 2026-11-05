/**
 * Detection rules for Entra ID directory audit logs — the post-compromise
 * persistence / privilege actions that sign-in logs alone cannot show.
 *
 * Audit events are correlated with sign-in results: an action is escalated to
 * high severity when the actor is a user already flagged by sign-in detections,
 * or when it came from an IP that sign-in logs place outside trusted countries.
 */

const HOUR = 3600000;

const PRIVILEGED_ROLES = [
  'global administrator', 'company administrator', 'privileged role administrator',
  'privileged authentication administrator', 'security administrator',
  'exchange administrator', 'sharepoint administrator', 'user administrator',
  'application administrator', 'cloud application administrator',
  'authentication administrator', 'conditional access administrator',
  'intune administrator', 'hybrid identity administrator', 'billing administrator',
  'helpdesk administrator', 'groups administrator',
];

// Delegated scopes that give mailbox / file / directory takeover
const RISKY_SCOPES = [
  'mail.read', 'mail.readwrite', 'mail.send', 'mailboxsettings.readwrite',
  'files.read.all', 'files.readwrite.all', 'sites.readwrite.all',
  'directory.readwrite.all', 'user.readwrite.all', 'full_access_as_user',
  'ews.accessasuser.all', 'contacts.read', 'notes.read.all',
  'application.readwrite.all', 'approleassignment.readwrite.all',
];

const lower = s => (s || '').toLowerCase();
const tsOf = s => Date.parse(s) || 0;

function propValue(event, name) {
  for (const t of event.targets) {
    for (const p of t.modifiedProperties) {
      if (lower(p.name) === lower(name)) return String(p.newValue || '').replace(/^"|"$/g, '');
    }
  }
  return '';
}

/**
 * @param auditEvents  normalized audit events (parser.normalizeAuditEvents)
 * @param ctx.signins  normalized sign-in events
 * @param ctx.signinDetections  output of runDetections
 */
function runAuditDetections(auditEvents, { signins = [], signinDetections = [], homeCountry = 'ID', trustedCountries = [] } = {}) {
  const trusted = new Set([homeCountry.toUpperCase(), ...trustedCountries.map(c => c.toUpperCase())]);

  // IP → country from sign-in logs (audit logs carry the IP but not the location)
  const ipCountry = {};
  for (const e of signins) if (e.ipAddress && e.country) ipCountry[e.ipAddress] = e.country;
  const isForeignIP = ip => !!ip && !!ipCountry[ip] && !trusted.has(ipCountry[ip].toUpperCase());

  // User → earliest time they were flagged by a high-severity sign-in detection
  const suspiciousSince = {};
  for (const d of signinDetections) {
    if (d.severity !== 'high' && d.type !== 'FOREIGN_LOGIN') continue;
    const t = tsOf(d.time || d.windowStart || d.firstSeen || d.to?.time || d.lastSeen) || 0;
    for (const u of [d.user, ...(d.affectedUsers || [])].filter(Boolean)) {
      const k = lower(u);
      if (suspiciousSince[k] === undefined || t < suspiciousSince[k]) suspiciousSince[k] = t;
    }
  }
  const isSuspiciousUser = (u, atTs) =>
    !!u && suspiciousSince[lower(u)] !== undefined && atTs >= suspiciousSince[lower(u)] - HOUR;

  const findings = [];
  const sorted = [...auditEvents].filter(e => e.result !== 'failure').sort((a, b) => tsOf(a.time) - tsOf(b.time));

  for (const e of sorted) {
    const act = lower(e.activity);
    const t   = tsOf(e.time);
    const actor = e.initiatorUser;
    const ip    = e.initiatorIP;
    const actorFlag = isSuspiciousUser(actor, t);
    const foreign   = isForeignIP(ip);
    const base = { time: e.time, ip, country: ipCountry[ip] || '', initiatedBy: actor || e.initiatorApp, activity: e.activity };

    // ── MFA / security-info registration (persistence) ─────────────────────
    if (/security info|strongauthentication|authentication method/.test(act) &&
        /regist|added|changed|update/.test(act) && !/deleted|removed/.test(act)) {
      const target = e.targets.find(x => x.userPrincipal)?.userPrincipal || actor;
      const targetFlag = isSuspiciousUser(target, t) && t - suspiciousSince[lower(target)] <= 72 * HOUR;
      if (!targetFlag && !foreign) continue;
      findings.push({
        type: 'MFA_REGISTRATION_AFTER_COMPROMISE',
        severity: targetFlag ? 'high' : 'medium',
        user: target,
        ...base,
        message: targetFlag
          ? `MFA method registered for ${target} shortly after suspicious sign-in activity ("${e.activity}") — attacker may be establishing persistence`
          : `MFA method registered for ${target} from foreign IP ${ip} (${ipCountry[ip]}) — "${e.activity}"`,
      });
      continue;
    }

    // ── OAuth consent grant ──────────────────────────────────────────────────
    if (act.startsWith('consent to application')) {
      const app = e.targets.find(x => lower(x.type) === 'serviceprincipal')?.displayName || e.targets[0]?.displayName || '';
      const perms = propValue(e, 'ConsentAction.Permissions');
      const isAdmin = lower(propValue(e, 'ConsentContext.IsAdminConsent')) === 'true';
      // Exact scope tokens — substring matching would report Mail.Read for Mail.ReadWrite
      const granted = new Set(lower(perms).split(/[\s,;"]+/));
      const scopes = RISKY_SCOPES.filter(s => granted.has(s));
      if (!scopes.length && !actorFlag && !foreign) continue;
      findings.push({
        type: 'OAUTH_CONSENT_GRANT',
        severity: actorFlag || foreign || (scopes.length && isAdmin) ? 'high' : 'medium',
        user: actor,
        app,
        scopes,
        adminConsent: isAdmin,
        ...base,
        message: `${isAdmin ? 'Admin' : 'User'} consent granted to "${app}" by ${actor || 'unknown'}${scopes.length ? ` with high-risk scopes (${scopes.join(', ')})` : ''}${actorFlag ? ' — actor was flagged by sign-in detections' : ''}${foreign ? ` — from foreign IP ${ip}` : ''}`,
      });
      continue;
    }

    // ── Privileged role assignment ───────────────────────────────────────────
    if (/add (eligible )?member to role/.test(act)) {
      const role = propValue(e, 'Role.DisplayName') || e.targets.find(x => lower(x.type) === 'role')?.displayName || '';
      if (!PRIVILEGED_ROLES.includes(lower(role))) continue;
      const target = e.targets.find(x => x.userPrincipal)?.userPrincipal || e.targets[0]?.displayName || '';
      const targetFlag = isSuspiciousUser(target, t);
      findings.push({
        type: 'PRIVILEGED_ROLE_ASSIGNMENT',
        severity: actorFlag || targetFlag || foreign ? 'high' : 'medium',
        user: target,
        role,
        ...base,
        message: `"${role}" assigned to ${target} by ${actor || e.initiatorApp || 'unknown'}${actorFlag || targetFlag ? ' — involves a user flagged by sign-in detections' : ''}${foreign ? ` — from foreign IP ${ip}` : ''}`,
      });
      continue;
    }

    // ── New credential on an app / service principal ─────────────────────────
    if (/certificates and secrets management|add service principal credentials/.test(act)) {
      const app = e.targets[0]?.displayName || '';
      findings.push({
        type: 'APP_CREDENTIAL_ADDED',
        severity: actorFlag || foreign ? 'high' : 'medium',
        user: actor || e.initiatorApp,
        app,
        ...base,
        message: `New credential (secret/certificate) added to "${app}" by ${actor || e.initiatorApp || 'unknown'}${actorFlag ? ' — actor was flagged by sign-in detections' : ''}${foreign ? ` — from foreign IP ${ip}` : ''}`,
      });
    }
  }
  return findings;
}

module.exports = { runAuditDetections, PRIVILEGED_ROLES, RISKY_SCOPES };
