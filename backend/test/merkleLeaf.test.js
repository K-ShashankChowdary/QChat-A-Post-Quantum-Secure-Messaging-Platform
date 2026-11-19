// `npm test`. The server and the browser compute Merkle leaves independently;
// if the two ever disagree on a single byte, every client would report the
// whole conversation as tampered. This pins them together.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { leafForMessage as serverLeaf, canonicalJson as serverCanon } from '../utils/merkleLeaf.js';
import { leafForMessage as clientLeaf, canonicalJson as clientCanon } from '../../frontend/src/crypto/merkle.js';

const samples = [
  { _id: '6aff05bb30c95ef6b9ad5f2c', from_user_id: '6aff05b430c95ef6b9ad5f06', timestamp: new Date('2026-11-19T14:19:13.566Z'),
    payload: { v: 2, keys: { '6aff05b430c95ef6b9ad5f06': { encapsulatedKey: 'AAA=', salt: 'c2FsdA==', nonce: 'bg==', ciphertext: 'Yw==', authTag: 'dA==' } },
               nonce: 'bm9uY2U=', ciphertext: 'aGVsbG8=', authTag: 'dGFn', timestamp: 1795098000000 } },
  { _id: '6aff05bb30c95ef6b9ad5f2d', from_user_id: 'u2', timestamp: new Date(0), payload: { encapsulatedKey: 'x', nonce: 'y', ciphertext: 'z', authTag: 'w' } },
  { _id: '6aff05bb30c95ef6b9ad5f2e', from_user_id: 'u1', timestamp: new Date('2030-01-01T00:00:00Z'), payload: {}, deleted: true },
  { _id: 'unicode', from_user_id: 'u1', timestamp: new Date('2026-05-05T05:05:05.005Z'), payload: { note: 'ünïcødé ✓ 🔐', n: [1, 2.5, -3], ok: true, nil: null } },
];

test('server and client compute identical leaves', async () => {
  for (const m of samples) {
    const fromClient = await clientLeaf({ fromId: m.from_user_id, id: m._id, timestamp: m.timestamp, payload: m.payload, deleted: m.deleted });
    assert.equal(serverLeaf(m), fromClient, `leaf for ${m._id}`);
  }
});

test('server and client agree on canonical JSON', () => {
  for (const m of samples) assert.equal(serverCanon(m.payload), clientCanon(m.payload));
});
