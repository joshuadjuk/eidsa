const test = require('node:test');
const assert = require('node:assert/strict');
const d = require('../lib/detections');
const { ev, min } = require('./helpers');

const range = n => Array.from({ length: n }, (_, i) => i);

test('findBursts reports separate incidents and the full extent of each', () => {
  const events = [
    ...range(12).map(i => ev({ t: min(i), ok: false })),            // burst 1: 12 events
    ...range(10).map(i => ev({ t: min(300 + i), ok: false })),      // burst 2, 5h later
  ];
  const bursts = d.findBursts(events, { windowMs: min(10), minDistinct: 10 });
  assert.equal(bursts.length, 2);
  assert.equal(bursts[0].length, 12);
  assert.equal(bursts[1].length, 10);
});

test('brute force ignores MFA / KMSI interrupts', () => {
  const interrupts = range(20).map(i => ev({ t: min(i % 5), code: 50076 }));
  assert.equal(interrupts[0].interrupted, true);
  assert.equal(d.detectBruteForce(interrupts).length, 0);

  const failures = range(12).map(i => ev({ t: min(i % 5), ok: false }));
  const f = d.detectBruteForce(failures);
  assert.equal(f.length, 1);
  assert.equal(f[0].attemptCount, 12);
});

test('password spray reports all targeted users and repeated campaigns', () => {
  const spray = t0 => range(8).map(i => ev({ user: `u${i}@x.com`, ip: '6.6.6.6', t: t0 + min(i), ok: false, country: 'RU' }));
  const f = d.detectPasswordSpray([...spray(0), ...spray(min(600))]);
  assert.equal(f.length, 2);
  assert.equal(f[0].affectedUsers.length, 8);
});

test('impossible travel uses city coordinates within the same country', () => {
  const events = [
    ev({ t: 0, city: 'Jakarta', lat: -6.2, lon: 106.8 }),
    ev({ t: min(30), city: 'Jayapura', lat: -2.53, lon: 140.7 }),   // ~3,700 km in 30 min
  ];
  const f = d.detectImpossibleTravel(events);
  assert.equal(f.length, 1);
  assert.equal(f[0].precision, 'city');
});

test('impossible travel ignores short hops (geolocation noise)', () => {
  const events = [
    ev({ t: 0, lat: -6.2, lon: 106.8 }),
    ev({ t: min(5), lat: -6.9, lon: 107.6 }),   // Jakarta → Bandung ~120 km
  ];
  assert.equal(d.detectImpossibleTravel(events).length, 0);
});

test('impossible travel falls back to country centroid for countries in the extended table', () => {
  const events = [ev({ t: 0, country: 'ID' }), ev({ t: min(60), country: 'KE' })];
  assert.equal(d.detectImpossibleTravel(events).length, 1);
});

test('time-of-day anomaly uses the workspace timezone', () => {
  // Normal day 09:00–16:00 WIB (02–09 UTC), one sign-in at 03:00 WIB (20 UTC)
  const day = h => ev({ t: Date.UTC(2026, 9, 1, h - 7) - Date.UTC(2026, 9, 1) });
  const events = [...range(12).map(i => day(9 + (i % 8))), ev({ t: Date.UTC(2026, 9, 1, 20) - Date.UTC(2026, 9, 1) })];
  const f = d.detectTimeOfDayAnomaly(events, { timezone: 'Asia/Jakarta' });
  assert.equal(f.length, 1);
  assert.equal(f[0].anomalousHour, 3);
  assert.match(f[0].normalWindow, /Asia\/Jakarta/);
});

test('token replay ignores dual-stack IPv4/IPv6 in the same country', () => {
  const events = [ev({ t: 0, ip: '36.80.1.1' }), ev({ t: 5000, ip: '2001:448a:1::5' })];
  assert.equal(d.detectTokenReplay(events).length, 0);
});

test('token replay ignores address changes inside the same /16', () => {
  const events = [ev({ t: 0, ip: '36.80.1.1' }), ev({ t: 5000, ip: '36.80.200.7' })];
  assert.equal(d.detectTokenReplay(events).length, 0);
});

test('token replay flags two unrelated networks within 30s', () => {
  const events = [ev({ t: 0, ip: '36.80.1.1' }), ev({ t: 5000, ip: '185.220.101.4', country: 'DE' })];
  assert.equal(d.detectTokenReplay(events).length, 1);
});

test('token replay treats IPs of the same ASN as one network', () => {
  const events = [ev({ t: 0, ip: '36.80.1.1' }), ev({ t: 5000, ip: '114.4.1.1' })];
  assert.equal(d.detectTokenReplay(events).length, 1);
  assert.equal(d.detectTokenReplay(events, { asnLookup: () => '7713' }).length, 0);
});

test('MFA downgrade: single-factor after an MFA baseline', () => {
  const events = [
    ev({ t: 0, authReq: 'singleFactorAuthentication' }),                         // before baseline — ignored
    ...range(10).map(i => ev({ t: min(i + 1), authReq: 'multiFactorAuthentication' })),
    ev({ t: min(20), authReq: 'singleFactorAuthentication', ip: '8.8.8.8' }),
  ];
  const f = d.detectMFAMethodDowngrade(events);
  assert.equal(f.length, 1);
  assert.equal(f[0].downgrade, 'single-factor');
  assert.equal(f[0].ip, '8.8.8.8');
});

test('MFA downgrade: SMS after an Authenticator baseline', () => {
  const events = [
    ...range(10).map(i => ev({ t: min(i), authReq: 'multiFactorAuthentication', mfa: 'Mobile app notification' })),
    ev({ t: min(20), authReq: 'multiFactorAuthentication', mfa: 'Text message' }),
  ];
  const f = d.detectMFAMethodDowngrade(events);
  assert.equal(f.length, 1);
  assert.equal(f[0].downgrade, 'weak-method');
  assert.equal(f[0].mfaMethod, 'Text message');
});

test('MFA downgrade: skips trusted IP but flags a later untrusted one', () => {
  const events = [
    ...range(10).map(i => ev({ t: min(i), authReq: 'multiFactorAuthentication' })),
    ev({ t: min(20), authReq: 'singleFactorAuthentication', ip: '10.1.1.1' }),
    ev({ t: min(21), authReq: 'singleFactorAuthentication', ip: '8.8.8.8' }),
  ];
  const f = d.detectMFAMethodDowngrade(events, { trustedIPs: ['10.0.0.0/8'] });
  assert.equal(f.length, 1);
  assert.equal(f[0].ip, '8.8.8.8');
});

test('Entra risky sign-in surfaces Identity Protection signals', () => {
  const f = d.detectEntraRiskySignin([
    ev({ t: 0, risk: 'high', riskState: 'atRisk' }),
    ev({ t: min(1), user: 'bob@x.com', risk: 'low' }),
    ev({ t: min(2), user: 'carol@x.com', risk: 'medium', riskState: 'remediated' }),
  ]);
  assert.equal(f.length, 2);
  assert.equal(f.find(x => x.user === 'alice@contoso.com').severity, 'high');
});

test('runDetections sorts unsorted input before applying rules', () => {
  const events = range(12).map(i => ev({ t: min(11 - i), ok: false }));
  const out = d.runDetections(events, { homeCountry: 'ID' });
  assert.ok(out.some(x => x.type === 'BRUTE_FORCE'));
});

test('sliding windows stay fast on large single-IP groups', () => {
  const events = range(60000).map(i => ev({ user: `u${i % 5000}@x.com`, ip: '6.6.6.6', t: i * 1000, ok: false }));
  const t0 = Date.now();
  d.detectPasswordSpray(events);
  d.detectCredentialStuffing(events);
  assert.ok(Date.now() - t0 < 3000, `took ${Date.now() - t0}ms`);
});
