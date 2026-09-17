import mongoose from 'mongoose';

export const USERNAME_RE = /^[a-zA-Z0-9._-]{3,32}$/;
export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 200;
export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;

export const isValidObjectId = (id) => mongoose.isValidObjectId(id);

export function validateUsername(username) {
  if (typeof username !== 'string' || username.length === 0) return 'Username is required';
  if (!USERNAME_RE.test(username)) {
    return 'Username must be 3-32 characters, using only letters, numbers, dot, underscore or hyphen';
  }
  return null;
}

export function validatePassword(password) {
  if (typeof password !== 'string' || password.length === 0) return 'Password is required';
  if (password.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  if (password.length > MAX_PASSWORD_LENGTH) return 'Password is too long';
  return null;
}

export function validatePublicKey(publicKey) {
  if (typeof publicKey !== 'string' || publicKey.length === 0) return 'Public key is required';
  const decoded = Buffer.from(publicKey, 'base64');
  if (decoded.length !== ML_KEM_768_PUBLIC_KEY_BYTES) {
    return `Public key must decode to ${ML_KEM_768_PUBLIC_KEY_BYTES} bytes (ML-KEM-768)`;
  }
  return null;
}

// Rough byte size of an encrypted payload object, used to reject oversized
// attachments before they reach MongoDB.
export function approximateSize(value) {
  if (!value) return 0;
  try {
    return Buffer.byteLength(JSON.stringify(value), 'utf8');
  } catch {
    return Infinity;
  }
}

export const MAX_KEY_BACKUP_BYTES = 16 * 1024;

/**
 * The backup is ciphertext the server can't inspect, so validation is limited
 * to shape and size — enough to reject junk without pretending to understand it.
 */
export function validateKeyBackup(backup) {
  if (backup === null || backup === undefined) return null;   // optional
  if (typeof backup !== 'object' || Array.isArray(backup)) return 'Key backup must be an object';
  if (backup.v !== 1) return 'Unsupported key backup version';

  for (const field of ['salt', 'nonce', 'ciphertext', 'authTag']) {
    if (typeof backup[field] !== 'string' || backup[field].length === 0) {
      return `Key backup is missing ${field}`;
    }
  }
  if (!Number.isInteger(backup.iterations) || backup.iterations < 100000) {
    return 'Key backup KDF iteration count is too low';
  }
  if (approximateSize(backup) > MAX_KEY_BACKUP_BYTES) return 'Key backup is too large';
  return null;
}
