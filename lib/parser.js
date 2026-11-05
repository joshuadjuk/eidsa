/**
 * Normalize Azure AD / Entra ID sign-in log events.
 * Supports both the Graph API export format and the portal CSV-to-JSON format.
 * Also normalizes Entra ID directory audit log events (see normalizeAuditEvents).
 */

// Error codes that are an interruption in the sign-in flow (MFA prompt, KMSI,
// password-change prompt, device auth…), not a wrong credential. They must not
// count as "failed attempts" in brute-force / spray style detections.
const INTERRUPT_CODES = new Set([
  50055, // password expired → change prompt
  50072, // MFA enrollment required
  50074, // strong auth required
  50076, // MFA required (location / CA)
  50079, // MFA registration required
  50097, // device authentication required
  50125, // sign-in interrupted by password reset / registration
  50140, // "keep me signed in" interrupt
  50158, // external security challenge
  16000, // account selection required
  16001, // account selection interrupt
  81010, // seamless SSO interrupt
]);

// signInEventTypes[0] → normalized sign-in type
function classifySignInType(signInEventTypes, isInteractive) {
  const types = signInEventTypes || [];
  if (types.includes('servicePrincipal'))   return 'servicePrincipal';
  if (types.includes('managedIdentity'))    return 'managedIdentity';
  if (types.includes('nonInteractiveUser')) return 'nonInteractive';
  if (types.includes('interactiveUser'))    return 'interactive';
  // Fallback: infer from isInteractive field
  if (isInteractive === false) return 'nonInteractive';
  if (isInteractive === true)  return 'interactive';
  return 'interactive';
}

// clientAppUsed + signInType → app category
function classifyAppType(clientAppUsed, appName, signInType) {
  const c = (clientAppUsed || '').toLowerCase();
  const a = (appName || '').toLowerCase();

  // Service / managed identity sign-ins
  if (signInType === 'servicePrincipal' || signInType === 'managedIdentity') return 'Service';
  if (c === 'service principal') return 'Service';

  // Legacy auth protocols (bypass MFA)
  if (['exchange activesync', 'imap', 'pop3', 'smtp auth', 'mapi'].some(x => c.includes(x))) return 'Legacy';

  // Admin tools
  if (c.includes('windows powershell') || c.includes('powershell')) return 'Admin';
  if (c.includes('azure cli') || a.includes('azure cli') || a.includes('azure powershell')) return 'Admin';
  if (c === 'other clients' || c === '') {
    if (a.includes('powershell') || a.includes('azure cli')) return 'Admin';
    if (a.includes('graph explorer')) return 'Admin';
  }

  // Non-interactive user sign-ins (background token refresh, ROPC, etc.)
  if (signInType === 'nonInteractive') return 'Non-Interactive';

  if (c === 'browser') return 'Interactive';
  if (c.includes('mobile apps') || c.includes('desktop')) return 'Mobile/Desktop';
  return 'Other';
}

// authenticationDetails[] → the second-factor method actually used (if any)
const NON_MFA_METHODS = new Set(['password', 'previously satisfied', 'single-factor', '']);
function extractMfaMethod(authDetails) {
  for (const d of authDetails || []) {
    const m = (d.authenticationMethod || '').trim();
    if (d.succeeded === false) continue;
    if (!NON_MFA_METHODS.has(m.toLowerCase())) return m;
  }
  return '';
}

// Weak (phishable / SIM-swappable) second factors
function classifyMfaStrength(method) {
  const m = (method || '').toLowerCase();
  if (!m) return '';
  if (m.includes('text message') || m.includes('sms') || m.includes('phone call') || m.includes('voice')) return 'weak';
  if (m.includes('fido') || m.includes('windows hello') || m.includes('certificate') || m.includes('passkey')) return 'phishing-resistant';
  return 'strong'; // Authenticator push / OTP / OATH token
}

function num(v) {
  const n = typeof v === 'string' ? parseFloat(v) : v;
  return typeof n === 'number' && isFinite(n) ? n : null;
}

function normalizeEvent(e) {
  const userPrincipal = e.userPrincipalName || e.UserPrincipalName || e.user_principal_name || '';
  const displayName   = e.userDisplayName   || e.UserDisplayName   || userPrincipal.split('@')[0] || '';
  const ipAddress     = e.ipAddress         || e.IpAddress         || e.ip_address         || '';
  const createdAt     = e.createdDateTime   || e.CreatedDateTime   || e.created_at         || '';
  const appName       = e.appDisplayName    || e.AppDisplayName    || e.app_display_name   || '';
  const status        = e.status            || e.Status            || {};
  const location      = e.location          || e.Location          || {};
  const deviceDetail  = e.deviceDetail      || e.DeviceDetail      || {};
  const clientAppUsed = e.clientAppUsed     || e.ClientAppUsed     || '';

  // Non-interactive / service principal fields
  const isInteractive     = e.isInteractive ?? null;
  const signInEventTypes  = e.signInEventTypes || [];
  const resourceName      = e.resourceDisplayName || '';
  const userAgent         = e.userAgent || '';
  const servicePrincipal  = e.servicePrincipalName || '';

  const errorCode     = status.errorCode     ?? status.ErrorCode     ?? null;
  const failureReason = status.failureReason || status.FailureReason || '';
  const success       = errorCode === 0 || errorCode === null
    ? (failureReason === '' || failureReason === 'Other.')
    : false;

  const country = location.countryOrRegion || location.CountryOrRegion || '';
  const city    = location.city            || location.City            || '';
  const state   = location.state           || location.State           || '';
  const geo     = location.geoCoordinates  || location.GeoCoordinates  || {};
  const lat     = num(geo.latitude ?? geo.Latitude);
  const lon     = num(geo.longitude ?? geo.Longitude);

  const os      = deviceDetail.operatingSystem || deviceDetail.OperatingSystem || '';
  const browser = deviceDetail.browser         || deviceDetail.Browser         || '';

  const signInType = classifySignInType(signInEventTypes, isInteractive);
  const mfaMethod  = extractMfaMethod(e.authenticationDetails);

  return {
    id:             e.id || e.Id || '',
    userPrincipal,
    displayName,
    ipAddress,
    createdAt,
    ts:             Date.parse(createdAt) || 0,
    appName,
    success,
    interrupted:    !success && INTERRUPT_CODES.has(errorCode),
    errorCode,
    failureReason,
    country,
    city,
    state,
    lat:            lat !== null && lon !== null && !(lat === 0 && lon === 0) ? lat : null,
    lon:            lat !== null && lon !== null && !(lat === 0 && lon === 0) ? lon : null,
    os,
    browser,
    isCompliant:    deviceDetail.isCompliant ?? null,
    isManaged:      deviceDetail.isManaged ?? null,
    clientAppUsed,
    appType:        classifyAppType(clientAppUsed, appName, signInType),
    signInType,
    isInteractive,
    resourceName,
    userAgent,
    servicePrincipal,
    authMethod:     e.authenticationRequirement || '',
    mfaMethod,
    mfaStrength:    classifyMfaStrength(mfaMethod),
    riskLevel:      e.riskLevelAggregated || e.riskLevelDuringSignIn || 'none',
    riskLevelDuringSignIn: e.riskLevelDuringSignIn || 'none',
    riskState:      e.riskState || 'none',
    riskEventTypes: e.riskEventTypes_v2 || e.riskEventTypes || [],
    conditionalAccessStatus: e.conditionalAccessStatus || '',
    _sourceFile:    e._sourceFile || ''
  };
}

function normalizeEvents(rawEvents) {
  const out = [];
  for (const e of rawEvents) {
    const n = normalizeEvent(e);
    if (n.userPrincipal || n.createdAt) out.push(n);
  }
  return out;
}

// ─── Audit logs ───────────────────────────────────────────────────────────────

// Directory audit events carry activityDisplayName; sign-in events never do.
function isAuditEvent(e) {
  return !!(e && (e.activityDisplayName || e.ActivityDisplayName) && (e.activityDateTime || e.ActivityDateTime));
}

function normalizeAuditEvent(e) {
  const initiatedBy = e.initiatedBy || e.InitiatedBy || {};
  const initUser    = initiatedBy.user || {};
  const initApp     = initiatedBy.app || {};
  const targets     = (e.targetResources || e.TargetResources || []).map(t => ({
    type:          t.type || '',
    displayName:   t.displayName || '',
    userPrincipal: t.userPrincipalName || '',
    modifiedProperties: (t.modifiedProperties || []).map(p => ({
      name:     p.displayName || '',
      oldValue: p.oldValue ?? '',
      newValue: p.newValue ?? '',
    })),
  }));
  const details = {};
  for (const d of e.additionalDetails || []) if (d.key) details[d.key] = d.value;

  return {
    id:            e.id || '',
    activity:      e.activityDisplayName || e.ActivityDisplayName || '',
    category:      e.category || '',
    time:          e.activityDateTime || e.ActivityDateTime || '',
    result:        (e.result || '').toLowerCase(),
    resultReason:  e.resultReason || '',
    service:       e.loggedByService || '',
    initiatorUser: initUser.userPrincipalName || '',
    initiatorIP:   initUser.ipAddress || '',
    initiatorApp:  initApp.displayName || '',
    targets,
    details,
    _sourceFile:   e._sourceFile || '',
  };
}

function normalizeAuditEvents(rawEvents) {
  return rawEvents.map(normalizeAuditEvent).filter(e => e.activity && e.time);
}

module.exports = {
  normalizeEvents,
  normalizeEvent,
  normalizeAuditEvents,
  isAuditEvent,
  classifyMfaStrength,
  INTERRUPT_CODES,
};
