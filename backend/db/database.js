import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { logger } from '../utils/logger.js';

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/qchat';

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
  created_at:    { type: Date, default: Date.now },
  last_seen:     { type: Date, default: Date.now },
  is_online:     { type: Boolean, default: false }
});

export const User = mongoose.model('User', userSchema);

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
  reactions:      [{ 
    emoji: { type: String },
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  }]
});

messageSchema.index({ from_user_id: 1, to_user_id: 1, timestamp: -1 });

export const Message = mongoose.model('Message', messageSchema);
