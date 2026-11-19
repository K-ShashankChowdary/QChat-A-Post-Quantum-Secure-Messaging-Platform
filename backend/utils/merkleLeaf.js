import crypto from 'crypto';

/**
 * Server half of the transcript Merkle tree. Mirrors leafForMessage in
 * frontend/src/crypto/merkle.js byte for byte — backend/test/merkleLeaf.test.js
 * runs both on the same inputs and fails if they ever drift apart.
 *
 * The leaf is built from ciphertext and metadata only, so the server can keep
 * it current without being able to read a single message:
 *
 *   SHA-256( 0x00 ‖ JSON["qchat.leaf.v1", from, id, ISO time,
 *                        SHA-256(canonical JSON payload) | "deleted"] )
 */
export const LEAF_VERSION = 'qchat.leaf.v1';

export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort()
    .filter(k => value[k] !== undefined)
    .map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
    .join(',')}}`;
}

const sha256hex = (...parts) => {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest('hex');
};

/** Leaf hash (hex) for a stored Message document or plain object. */
export function leafForMessage(msg) {
  const deleted = Boolean(msg.deleted);
  const payloadDigest = deleted ? null : sha256hex(canonicalJson(msg.payload ?? null));
  const record = JSON.stringify([
    LEAF_VERSION,
    String(msg.from_user_id ?? msg.fromId),
    String(msg._id ?? msg.id),
    new Date(msg.timestamp).toISOString(),
    deleted ? 'deleted' : payloadDigest,
  ]);
  return sha256hex(Buffer.from([0x00]), Buffer.from(record, 'utf8'));
}
