const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeAuditEvents, isAuditEvent } = require('../lib/parser');
const { runAuditDetections } = require('../lib/audit');
const { ev, BASE } = require('./helpers');

const at = h => new Date(BASE + h * 3600000).toISOString();

function audit(activity, { h = 1, actor = 'alice@contoso.com', ip = '6.6.6.6', target = 'alice@contoso.com', props = [], targetType = 'User' } = {}) {
  return {
    id: Math.random().toString(36).slice(2),
    activityDisplayName: activity,
    activityDateTime: at(h),
    category: 'UserManagement',
    result: 'success',
    initiatedBy: { user: { userPrincipalName: actor, ipAddress: ip } },
    targetResources: [{ type: targetType, displayName: target, userPrincipalName: target, modifiedProperties: props }],
  };
}

const signins = [ev({ ip: '6.6.6.6', country: 'RU' })];
const flagged = [{ type: 'PASSWORD_SPRAY', severity: 'high', affectedUsers: ['alice@contoso.com'], windowStart: at(0) }];

test('isAuditEvent distinguishes audit from sign-in records', () => {
  assert.equal(isAuditEvent(audit('Add member to role')), true);
  assert.equal(isAuditEvent({ userPrincipalName: 'a', createdDateTime: at(0) }), false);
});

test('MFA registration shortly after a flagged sign-in is high severity', () => {
  const out = runAuditDetections(normalizeAuditEvents([audit('User registered security info', { h: 2 })]), { signins, signinDetections: flagged });
  assert.equal(out.length, 1);
  assert.equal(out[0].type, 'MFA_REGISTRATION_AFTER_COMPROMISE');
  assert.equal(out[0].severity, 'high');
});

test('routine MFA registration from home country is ignored', () => {
  const out = runAuditDetections(
    normalizeAuditEvents([audit('User registered security info', { actor: 'bob@contoso.com', target: 'bob@contoso.com', ip: '10.0.0.1' })]),
    { signins: [ev({ ip: '10.0.0.1' })], signinDetections: [] }
  );
  assert.equal(out.length, 0);
});

test('consent with mailbox scopes is flagged', () => {
  const out = runAuditDetections(normalizeAuditEvents([audit('Consent to application', {
    actor: 'bob@contoso.com', ip: '10.0.0.1', target: 'Evil Mail App', targetType: 'ServicePrincipal',
    props: [{ displayName: 'ConsentAction.Permissions', newValue: '"Scope: Mail.Read offline_access"' }],
  })]), { signins: [ev({ ip: '10.0.0.1' })], signinDetections: [] });
  assert.equal(out.length, 1);
  assert.equal(out[0].type, 'OAUTH_CONSENT_GRANT');
  assert.deepEqual(out[0].scopes, ['mail.read']);
});

test('Global Administrator assignment by a flagged actor is high severity', () => {
  const out = runAuditDetections(normalizeAuditEvents([audit('Add member to role', {
    target: 'mallory@contoso.com',
    props: [{ displayName: 'Role.DisplayName', newValue: '"Global Administrator"' }],
  })]), { signins, signinDetections: flagged });
  assert.equal(out.length, 1);
  assert.equal(out[0].type, 'PRIVILEGED_ROLE_ASSIGNMENT');
  assert.equal(out[0].severity, 'high');
});

test('non-privileged role assignment is ignored', () => {
  const out = runAuditDetections(normalizeAuditEvents([audit('Add member to role', {
    props: [{ displayName: 'Role.DisplayName', newValue: '"Reports Reader"' }],
  })]), { signins, signinDetections: flagged });
  assert.equal(out.length, 0);
});

test('new app secret is reported', () => {
  const out = runAuditDetections(normalizeAuditEvents([audit('Update application – Certificates and secrets management ', {
    target: 'Payroll App', targetType: 'Application',
  })]), { signins, signinDetections: flagged });
  assert.equal(out[0].type, 'APP_CREDENTIAL_ADDED');
  assert.equal(out[0].severity, 'high');
});
