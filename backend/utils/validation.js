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
