import crypto from 'crypto';

// Crockford-style alphabet: no 0/O/1/I, so a code read aloud or copied by hand
// can't land on the wrong account.
const ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
const BODY_LENGTH = 8;
const BODY_RE = new RegExp(`^[${ALPHABET}]{${BODY_LENGTH}}$`);

/** Generate a candidate id, e.g. "QC-4F7A-2B9C". ~1.1e12 possibilities. */
export function generateQChatId() {
  const bytes = crypto.randomBytes(BODY_LENGTH);
  let body = '';
  for (let i = 0; i < BODY_LENGTH; i++) body += ALPHABET[bytes[i] % ALPHABET.length];
  return `QC-${body.slice(0, 4)}-${body.slice(4)}`;
}

/**
 * Accept what a human actually pastes — lower case, missing dashes, missing the
 * QC prefix, stray whitespace — and return the canonical form, or null if it
 * could not possibly be an id.
 */
export function normalizeQChatId(input) {
  if (typeof input !== 'string') return null;

  const trimmed = input.trim().toUpperCase();
  const compact = trimmed.replace(/[\s-]/g, '');
  const hasPrefix = compact.startsWith('QC');
  // A bare run of 8 letters is indistinguishable from a username (every letter
  // in "SHASHANK" is in the alphabet), so require some marker that this was
  // meant as an id: either the QC prefix or the 4-4 dashed shape.
  const isDashed = /^[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(trimmed);
  if (!hasPrefix && !isDashed) return null;

  const body = hasPrefix ? compact.slice(2) : compact;
  if (!BODY_RE.test(body)) return null;
  return `QC-${body.slice(0, 4)}-${body.slice(4)}`;
}

/** Allocate an id that isn't already taken. */
export async function allocateQChatId(User, attempts = 6) {
  for (let i = 0; i < attempts; i++) {
    const candidate = generateQChatId();
    if (!(await User.exists({ qchat_id: candidate }))) return candidate;
  }
  throw new Error('Could not allocate a unique QChat ID');
}
