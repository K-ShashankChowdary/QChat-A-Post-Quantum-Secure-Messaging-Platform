/**
 * Demonstrate what the transcript Merkle tree catches, by doing what a
 * malicious server or a database intruder could do — directly in MongoDB.
 *
 *   node scripts/tamper.js <messageId> time      shift the timestamp by 10 minutes
 *   node scripts/tamper.js <messageId> payload   flip one byte of the ciphertext
 *   node scripts/tamper.js <messageId> remove    delete the message row
 *
 * The leaf is recomputed afterwards, as a careful attacker would, so the
 * server's own leaf list stays self-consistent. Detection then comes from the
 * clients: each device's checkpoint (and the other participant's root) still
 * remembers the original. `time` is the interesting one — AES-GCM does not
 * authenticate the timestamp, so the message still opens normally and only
 * the tree notices that history was rewritten.
 *
 * Demo: open the chat on both devices (that saves a checkpoint), run this,
 * then reload. The header turns red and names the message.
 */
import mongoose from 'mongoose';
import { connectDB, Message } from '../db/database.js';
import { leafForMessage } from '../utils/merkleLeaf.js';

const [id, mode = 'time'] = process.argv.slice(2);
if (!id || !mongoose.isValidObjectId(id) || !['time', 'payload', 'remove'].includes(mode)) {
  console.error('Usage: node scripts/tamper.js <messageId> [time|payload|remove]');
  process.exit(1);
}

await connectDB();
const msg = await Message.findById(id);
if (!msg) { console.error('No message with that id'); process.exit(1); }

if (mode === 'remove') {
  await msg.deleteOne();
  console.log(`Removed message ${id}`);
} else {
  if (mode === 'time') {
    msg.timestamp = new Date(msg.timestamp.getTime() + 10 * 60 * 1000);
  } else {
    const payload = structuredClone(msg.payload);
    const bytes = Buffer.from(payload.ciphertext || '', 'base64');
    if (bytes.length === 0) { console.error('That message has no ciphertext to alter'); process.exit(1); }
    bytes[0] ^= 0x01;
    payload.ciphertext = bytes.toString('base64');
    msg.payload = payload;
    msg.markModified('payload');
  }
  msg.leaf = leafForMessage(msg);
  await msg.save();
  console.log(`Tampered with message ${id} (${mode}); its leaf was recomputed to stay self-consistent`);
}
await mongoose.disconnect();
