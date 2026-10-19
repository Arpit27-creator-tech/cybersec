const crypto = require('crypto');

const ENCRYPTION_ALGORITHM = 'aes-256-gcm';

function getEncryptionKey() {
  const secret = process.env.SESSION_SECRET || 'cybersec-secret-super-key-2026';
  return crypto.createHash('sha256').update(secret).digest();
}

function encryptToken(plainText) {
  if (!plainText) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `enc:${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decryptToken(cipherText) {
  if (!cipherText) return null;
  if (!cipherText.startsWith('enc:')) {
    return cipherText;
  }
  try {
    const parts = cipherText.split(':');
    const iv = Buffer.from(parts[1], 'hex');
    const authTag = Buffer.from(parts[2], 'hex');
    const encrypted = parts[3];
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, getEncryptionKey(), iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    console.error('Decryption failed:', e.message);
    return null;
  }
}

module.exports = {
  encryptToken,
  decryptToken
};
