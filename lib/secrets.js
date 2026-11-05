/**
 * At-rest encryption for workspace secrets (Graph client secret, webhook URL).
 * AES-256-GCM with a key from EIDSA_SECRET_KEY, or a random key generated once
 * into data/secret.key. Losing that key means re-entering the secrets.
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const PREFIX = 'enc:v1:';
let key = null;

function init(dataDir) {
  if (process.env.EIDSA_SECRET_KEY) {
    key = crypto.scryptSync(process.env.EIDSA_SECRET_KEY, 'eidsa-secrets', 32);
    return;
  }
  const keyPath = path.join(dataDir, 'secret.key');
  if (!fs.existsSync(keyPath)) {
    fs.writeFileSync(keyPath, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
  }
  key = Buffer.from(fs.readFileSync(keyPath, 'utf8').trim(), 'hex');
}

function encrypt(plain) {
  if (!plain) return '';
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return PREFIX + Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}

function decrypt(value) {
  if (!value) return '';
  if (!value.startsWith(PREFIX)) return value; // legacy plaintext
  const buf = Buffer.from(value.slice(PREFIX.length), 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8');
}

module.exports = { init, encrypt, decrypt };
