/**
 * Normalize Azure AD / Entra ID sign-in log events.
 * Supports both the Graph API export format and the portal CSV-to-JSON format.
 */

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

function normalizeEvents(rawEvents) {
  return rawEvents.map(e => {
    const userPrincipal = e.userPrincipalName || e.UserPrincipalName || e.user_principal_name || '';
    const displayName   = e.userDisplayName   || e.UserDisplayName   || userPrincipal.split('@')[0] || '';
    const ipAddress     = e.ipAddress         || e.IpAddress         || e.ip_address         || '';
    const createdAt     = e.createdDateTime   || e.CreatedDateTime   || e.created_at         || '';
    const appName       = e.appDisplayName    || e.AppDisplayName    || e.app_display_name   || '';
    const status        = e.status            || e.Status            || {};
    const location      = e.location          || e.Location          || {};
    const deviceDetail  = e.deviceDetail      || e.DeviceDetail      || {};
    const conditionalAccessPolicies = e.appliedConditionalAccessPolicies || [];
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

    const os      = deviceDetail.operatingSystem || deviceDetail.OperatingSystem || '';
    const browser = deviceDetail.browser         || deviceDetail.Browser         || '';

    const signInType = classifySignInType(signInEventTypes, isInteractive);

    return {
      id:             e.id || e.Id || '',
      userPrincipal,
      displayName,
      ipAddress,
      createdAt,
      appName,
      success,
      errorCode,
      failureReason,
      country,
      city,
      state,
      os,
      browser,
      clientAppUsed,
      appType:        classifyAppType(clientAppUsed, appName, signInType),
      signInType,
      isInteractive,
      resourceName,
      userAgent,
      servicePrincipal,
      authMethod:     e.authenticationRequirement || '',
      riskLevel:      e.riskLevelAggregated || e.riskLevelDuringSignIn || 'none',
      conditionalAccessStatus: e.conditionalAccessStatus || '',
      _sourceFile:    e._sourceFile || ''
    };
  }).filter(e => e.userPrincipal || e.createdAt);
}

module.exports = { normalizeEvents };
