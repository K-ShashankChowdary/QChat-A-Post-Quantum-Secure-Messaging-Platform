import { Message } from '../db/database.js';
import { leafForMessage } from './merkleLeaf.js';

/**
 * The attacks the Merkle tree is meant to catch, applied the way a malicious
 * server (or anyone with database access) would: straight to MongoDB, with
 * the message's stored leaf recomputed afterwards so the server's own leaf
 * list stays self-consistent. Detection therefore has to come from the
 * clients' checkpoints — which is the point being demonstrated.
 *
 * Shared by scripts/tamper.js and the demo-mode attack simulator
 * (routes/demo.js). Each attack returns an undo record.
 */
export const ATTACKS = {
  time:    'Rewrite its timestamp (+10 minutes)',
  payload: 'Corrupt one byte of its ciphertext',
  remove:  'Delete it from the database',
  insert:  'Replay a copy of it into the past',
};

export async function applyAttack(msg, mode) {
  if (!ATTACKS[mode]) throw new Error(`Unknown attack "${mode}"`);
  if (msg.deleted && mode !== 'remove') throw new Error('Pick a message that has not been deleted');
  const original = msg.toObject();

  if (mode === 'remove') {
    await msg.deleteOne();
    return { kind: 'reinsert', doc: original };
  }

  if (mode === 'insert') {
    // A copy of a real message — it decrypts perfectly — slipped in a minute
    // before the original, as if it had always been there.
    const forged = new Message({
      from_user_id:   msg.from_user_id,
      to_user_id:     msg.to_user_id,
      payload:        structuredClone(msg.payload),
      sender_payload: msg.sender_payload ? structuredClone(msg.sender_payload) : null,
      type:           msg.type,
      timestamp:      new Date(msg.timestamp.getTime() - 60 * 1000),
      delivered:      true,
      read:           true,
    });
    forged.leaf = leafForMessage(forged);
    await forged.save();
    return { kind: 'delete', id: forged._id };
  }

  if (mode === 'time') {
    msg.timestamp = new Date(msg.timestamp.getTime() + 10 * 60 * 1000);
  } else {
    const payload = structuredClone(msg.payload);
    const bytes = Buffer.from(payload?.ciphertext || '', 'base64');
    if (bytes.length === 0) throw new Error('That message has no ciphertext to alter');
    bytes[0] ^= 0x01;
    payload.ciphertext = bytes.toString('base64');
    msg.payload = payload;
    msg.markModified('payload');
  }
  msg.leaf = leafForMessage(msg);
  await msg.save();
  return { kind: 'replace', doc: original };
}

/** Put the database back exactly as it was before an attack. */
export async function undoAttack(record) {
  if (record.kind === 'delete') {
    await Message.deleteOne({ _id: record.id });
  } else if (record.kind === 'reinsert') {
    await Message.collection.insertOne(record.doc);
  } else {
    await Message.collection.replaceOne({ _id: record.doc._id }, record.doc);
  }
}
