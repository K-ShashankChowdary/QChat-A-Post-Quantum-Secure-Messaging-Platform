/**
 * Demonstrate what the transcript Merkle tree catches, by doing what a
 * malicious server or a database intruder could do — directly in MongoDB.
 *
 *   node scripts/tamper.js list <userA> <userB>   list the conversation, with ids
 *   node scripts/tamper.js <messageId> time       shift its timestamp by 10 minutes
 *   node scripts/tamper.js <messageId> payload    flip one byte of its ciphertext
 *   node scripts/tamper.js <messageId> remove     delete the message row
 *   node scripts/tamper.js <messageId> insert     replay a copy of it a minute earlier
 *
 * The same attacks are one click away in the app when DEMO_MODE=true.
 *
 * The leaf is recomputed afterwards, as a careful attacker would, so the
 * server's own leaf list stays self-consistent. Detection comes from the
 * clients: each device's checkpoint (and the other participant's root) still
 * remembers the original. `time` is the interesting one — AES-GCM does not
 * authenticate the timestamp, so the message still opens normally and only
 * the tree notices that history was rewritten.
 *
 * Demo: open the chat on both devices (that saves a checkpoint), run this,
 * then reload. The header turns red and names the message by the same #n
 * that `list` prints.
 */
import mongoose from 'mongoose';
import { connectDB, Message, User } from '../db/database.js';
import { ATTACKS, applyAttack } from '../utils/attacks.js';

const MODES = Object.keys(ATTACKS);
const args = process.argv.slice(2);

function usage(problem) {
  if (problem) console.error(`${problem}\n`);
  console.error('Usage:');
  console.error('  node scripts/tamper.js list <userA> <userB>');
  console.error('  node scripts/tamper.js <messageId> [time|payload|remove|insert]');
  process.exit(1);
}

async function list(nameA, nameB) {
  const [a, b] = await Promise.all([
    User.findOne({ username: nameA }).select('_id username').lean(),
    User.findOne({ username: nameB }).select('_id username').lean(),
  ]);
  if (!a || !b) usage(`No account named "${!a ? nameA : nameB}".`);

  const rows = await Message.find({
    $or: [{ from_user_id: a._id, to_user_id: b._id }, { from_user_id: b._id, to_user_id: a._id }],
  }).sort({ timestamp: 1, _id: 1 }).select('from_user_id timestamp deleted type').lean();

  if (rows.length === 0) { console.log('No messages between them yet.'); return; }
  const names = { [String(a._id)]: a.username, [String(b._id)]: b.username };
  console.log(`${rows.length} message(s) between ${a.username} and ${b.username} (tree order):\n`);
  rows.forEach((r, i) => {
    const flags = [r.type !== 'text' ? r.type : '', r.deleted ? 'deleted' : ''].filter(Boolean).join(', ');
    console.log(`  #${String(i + 1).padEnd(4)} ${r._id}  ${r.timestamp.toISOString()}  ${names[String(r.from_user_id)].padEnd(16)} ${flags}`);
  });
  console.log('\nThen: node scripts/tamper.js <id> time');
}

async function tamper(id, mode) {
  const msg = await Message.findById(id);
  if (!msg) usage('No message with that id.');
  try {
    await applyAttack(msg, mode);
  } catch (err) {
    usage(err.message);
  }
  console.log(`${ATTACKS[mode]} — done for message ${id}. Its leaf was recomputed to stay self-consistent.`);
  console.log('Reload the chat on a device that had opened it before — the header will name the message.');
}

if (args[0] === 'list') {
  if (args.length !== 3) usage();
  await connectDB();
  await list(args[1], args[2]);
} else {
  const [id, mode = 'time'] = args;
  if (!id || !mongoose.isValidObjectId(id)) usage('Give a message id (run `list` first to find one).');
  if (!MODES.includes(mode)) usage(`Unknown mode "${mode}".`);
  await connectDB();
  await tamper(id, mode);
}
await mongoose.disconnect();
