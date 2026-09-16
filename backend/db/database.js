import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import config from '../config/env.js';
import { allocateQChatId } from '../utils/qchatId.js';

const MONGO_URI = config.mongoUri;

export const connectDB = async () => {
  try {
    await mongoose.connect(MONGO_URI);
    logger.db('MongoDB connected', { uri: MONGO_URI.replace(/\/\/.*@/, '//<credentials>@') });
  } catch (err) {
    logger.error('MongoDB connection failed', { message: err.message }, 'DB');
    process.exit(1);
  }
};

// Mongoose connection events
mongoose.connection.on('disconnected', () => logger.warn('MongoDB disconnected', null, 'DB'));
mongoose.connection.on('reconnected',  () => logger.db('MongoDB reconnected'));

// User Schema
const userSchema = new mongoose.Schema({
  username:      { type: String, required: true, unique: true },
  password_hash: { type: String, required: true },
  public_key:    { type: String },
  // Shareable handle (QC-XXXX-XXXX). Random rather than derived from the
  // username, so accounts can't be found by guessing names.
  qchat_id:      { type: String, unique: true, sparse: true, index: true },
  // People this user explicitly added. The contact list also surfaces anyone
  // they've exchanged messages with, so a first message reveals the sender
  // without needing a friend-request round trip.
  contacts:      [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  created_at:    { type: Date, default: Date.now },
  last_seen:     { type: Date, default: Date.now },
  is_online:     { type: Boolean, default: false }
});

export const User = mongoose.model('User', userSchema);

/** Give any pre-existing account a QChat ID. Runs once at boot; no-op after. */
export const backfillQChatIds = async () => {
  const missing = await User.find({ $or: [{ qchat_id: { $exists: false } }, { qchat_id: null }] }).select('_id username');
  if (missing.length === 0) return;

  logger.db(`Backfilling QChat IDs for ${missing.length} existing user(s)`);
  for (const user of missing) {
    try {
      user.qchat_id = await allocateQChatId(User);
      await user.save();
      logger.db(`Assigned ${user.qchat_id}`, { username: user.username });
    } catch (err) {
      logger.error('QChat ID backfill failed', { username: user.username, message: err.message }, 'DB');
    }
  }
};

// Message Schema
const messageSchema = new mongoose.Schema({
  from_user_id:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  to_user_id:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  payload:        { type: Object, required: true },           // encrypted for recipient
  sender_payload: { type: Object, default: null },           // encrypted for sender (so they can read their own messages)
  timestamp:      { type: Date, default: Date.now, index: true },
  delivered:      { type: Boolean, default: false },
  read:           { type: Boolean, default: false },
  reply_to_id:    { type: mongoose.Schema.Types.ObjectId, ref: 'Message', default: null },
  deleted:        { type: Boolean, default: false },
  type:           { type: String, default: 'text', enum: ['text', 'image', 'audio', 'file'] },
  // One entry per reacting user. `payload` is their whole emoji set, encrypted
  // to both participants, so the server stores it blind — it can upsert and
  // delete but never learns which emoji was used. `emoji` is the pre-v2
  // plaintext field, kept only so old reactions still render.
  reactions:      [{
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    emoji:   { type: String },
    payload: { type: Object }
  }]
});

messageSchema.index({ from_user_id: 1, to_user_id: 1, timestamp: -1 });

export const Message = mongoose.model('Message', messageSchema);
