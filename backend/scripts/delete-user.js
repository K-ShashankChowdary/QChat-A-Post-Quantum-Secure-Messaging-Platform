/**
 * Permanently delete accounts by username, along with their messages and any
 * references to them in other people's contact lists.
 *
 *   node scripts/delete-user.js user user1
 *
 * Exact usernames only — no patterns or wildcards, by design.
 */
import mongoose from 'mongoose';
import { connectDB, User, Message } from '../db/database.js';
import { logger } from '../utils/logger.js';

const usernames = process.argv.slice(2).filter(Boolean);

if (usernames.length === 0) {
  console.error('Usage: node scripts/delete-user.js <username> [username...]');
  process.exit(1);
}

await connectDB();

let deleted = 0;
for (const username of usernames) {
  const user = await User.findOne({ username }).select('_id username qchat_id');
  if (!user) {
    logger.warn(`No account named "${username}" — skipping`, null, 'Cleanup');
    continue;
  }

  const messages = await Message.deleteMany({
    $or: [{ from_user_id: user._id }, { to_user_id: user._id }],
  });
  const contactRefs = await User.updateMany(
    { contacts: user._id },
    { $pull: { contacts: user._id } }
  );
  await User.deleteOne({ _id: user._id });

  deleted++;
  logger.info(`Deleted "${username}"`, {
    qchatId: user.qchat_id,
    messagesRemoved: messages.deletedCount,
    contactListsCleaned: contactRefs.modifiedCount,
  }, 'Cleanup');
}

logger.info(`Done — ${deleted} account(s) deleted`, null, 'Cleanup');
await mongoose.connection.close();
process.exit(0);
