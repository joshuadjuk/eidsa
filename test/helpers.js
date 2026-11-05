const { normalizeEvent } = require('../lib/parser');

const BASE = Date.UTC(2026, 9, 1, 0, 0, 0);
const min = n => n * 60000;

/** Build a normalized sign-in event from a compact spec. */
function ev({
  user = 'alice@contoso.com', ip = '10.0.0.1', t = 0, ok = true, code, country = 'ID', city = '',
  lat, lon, app = 'Office 365', client = 'Browser', type = 'interactiveUser', authReq,
  mfa, ua, risk, riskState, id,
} = {}) {
  return normalizeEvent({
    id,
    userPrincipalName: user,
    ipAddress: ip,
    createdDateTime: new Date(BASE + t).toISOString(),
    appDisplayName: app,
    clientAppUsed: client,
    signInEventTypes: [type],
    status: { errorCode: code ?? (ok ? 0 : 50126) },
    location: { countryOrRegion: country, city, geoCoordinates: lat != null ? { latitude: lat, longitude: lon } : {} },
    authenticationRequirement: authReq,
    authenticationDetails: mfa ? [{ authenticationMethod: 'Password', succeeded: true }, { authenticationMethod: mfa, succeeded: true }] : [],
    userAgent: ua,
    riskLevelDuringSignIn: risk,
    riskState,
  });
}

module.exports = { ev, min, BASE };
