import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import config from './config/env.js';
import { connectDB, backfillQChatIds, User, Message } from './db/database.js';
import authRoutes from './routes/auth.js';
import messageRoutes from './routes/messages.js';
import userRoutes from './routes/users.js';
import { authenticateSocket } from './middleware/auth.js';
import { logger } from './utils/logger.js';
import { isValidObjectId, approximateSize } from './utils/validation.js';

// ── Connect to MongoDB ──
connectDB()
  .then(backfillQChatIds)
  .catch(err => logger.error('Startup database work failed', { message: err.message }, 'DB'));

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: { origin: config.corsOrigin, methods: ['GET', 'POST'] },
  // Default is 1MB, which silently drops the connection as soon as an
  // encrypted attachment is attached to a message.
  maxHttpBufferSize: config.maxMessageBytes,
});

const ALLOWED_MESSAGE_TYPES = ['text', 'image', 'audio', 'file'];

/**
 * Presence is derived from socket.io rooms: every socket joins a room named
 * after its user id, so a user with several tabs open is still one "user", and
 * every tab receives their messages.
 */
const isUserOnline = (userId) => (io.sockets.adapter.rooms.get(String(userId))?.size ?? 0) > 0;

// ── Security headers ──
app.use(helmet());

// ── HTTP request logger (Morgan → our logger) ──
app.use((req, _res, next) => { req._startTime = Date.now(); next(); });
app.use(morgan((tokens, req, res) => {
  const ms     = Date.now() - (req._startTime || Date.now());
  const status = parseInt(tokens.status(req, res)) || 0;
  logger.http(req, status, ms);
  return null; // morgan itself writes nothing; we handle output
}));

app.use(cors({ origin: config.corsOrigin }));
app.use(express.json({ limit: '1mb' }));

// ── Expose Socket.io to routes ──
app.use((req, res, next) => {
  req.io = io;
  next();
});

// ── Routes ──
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many attempts from this address, please try again later' },
});

// Looking someone up by id is the one endpoint that reveals whether an account
// exists, so it gets its own tighter budget to stop id-space probing.
const lookupLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many lookups, slow down a moment' },
});

app.use('/api/auth',         authLimiter, authRoutes);
app.use('/api/messages',     messageRoutes);
app.use('/api/users/lookup', lookupLimiter);
app.use('/api/users',        userRoutes);

// ── Socket.io ──

/** Flush anything that arrived while this user had no socket connected. */
async function deliverPendingMessages(socket, userId) {
  const pending = await Message.find({ to_user_id: userId, delivered: false }).sort({ timestamp: 1 });
  if (pending.length === 0) return;

  logger.info(`Delivering ${pending.length} offline message(s)`, { userId }, 'Socket');
  for (const msg of pending) {
    socket.emit('new_message', {
      id:        msg._id,
      fromId:    msg.from_user_id,
      payload:   msg.payload,
      timestamp: msg.timestamp,
      type:      msg.type,
      replyToId: msg.reply_to_id,
      deleted:   msg.deleted,
      reactions: msg.reactions,
    });
  }

  await Message.updateMany(
    { _id: { $in: pending.map(m => m._id) } },
    { $set: { delivered: true } }
  );

  // Notify senders that their messages were delivered
  const senderIds = [...new Set(pending.map(m => String(m.from_user_id)))];
  for (const sId of senderIds) {
    const deliveredIds = pending.filter(m => String(m.from_user_id) === sId).map(m => m._id);
    io.to(sId).emit('message_delivered', { messageIds: deliveredIds, toUserId: userId });
  }
}

// Reject unauthenticated sockets at the handshake, before any event can run.
io.use(authenticateSocket);

io.on('connection', async (socket) => {
  // Identity comes from the verified handshake token only. Nothing below reads
  // an actor id out of an event payload.
  const userId = socket.user.id;
  socket.join(userId);

  logger.event('Socket connected', { socketId: socket.id, userId, username: socket.user.username }, 'Socket');

  try {
    await User.findByIdAndUpdate(userId, { is_online: true, last_seen: new Date() });
    io.emit('user_status', { userId, status: 'online', lastSeen: new Date() });
    await deliverPendingMessages(socket, userId);
  } catch (err) {
    logger.error('Connection setup failed', { message: err.message, userId }, 'Socket');
  }

  socket.on('send_message', async ({ tempId, toId, payload, senderPayload, type, replyToId }) => {
    logger.event('Relay message', { fromId: userId, toId }, 'Socket');
    try {
      if (!isValidObjectId(toId)) {
        return socket.emit('message_error', { tempId, error: 'INVALID_RECIPIENT' });
      }
      if (!payload || typeof payload !== 'object') {
        return socket.emit('message_error', { tempId, error: 'INVALID_PAYLOAD' });
      }

      const size = approximateSize(payload) + approximateSize(senderPayload);
      if (size > config.maxMessageBytes) {
        logger.warn('Rejected oversized message', { fromId: userId, size }, 'Socket');
        return socket.emit('message_error', { tempId, error: 'PAYLOAD_TOO_LARGE' });
      }

      const safeType    = ALLOWED_MESSAGE_TYPES.includes(type) ? type : 'text';
      // A non-ObjectId reply target (e.g. a client-side temp id) would throw on
      // save and lose the message entirely, so drop it instead.
      const safeReplyTo = isValidObjectId(replyToId) ? replyToId : null;
      const recipientOnline = isUserOnline(toId);

      const msg = new Message({
        from_user_id:   userId,
        to_user_id:     toId,
        payload,
        sender_payload: senderPayload || null,
        type:           safeType,
        reply_to_id:    safeReplyTo,
        delivered:      recipientOnline,
      });
      await msg.save();
      logger.info('Message saved', { id: msg._id, fromId: userId, toId }, 'Socket');

      // Hand the real id back so the sender's optimistic bubble stops carrying a
      // temporary one — receipts, deletes, reactions and replies all key off it.
      socket.emit('message_sent', {
        tempId,
        id:        msg._id,
        timestamp: msg.timestamp,
        delivered: recipientOnline,
      });

      if (recipientOnline) {
        io.to(String(toId)).emit('new_message', {
          id: msg._id, fromId: userId, payload, timestamp: msg.timestamp,
          type: msg.type, replyToId: msg.reply_to_id, deleted: msg.deleted, reactions: msg.reactions,
        });
        logger.event('Message delivered', { toId }, 'Socket');
      } else {
        logger.warn('Recipient offline — message persisted for delivery on reconnect', { toId }, 'Socket');
      }
    } catch (error) {
      logger.error('send_message failed', { message: error.message }, 'Socket');
      socket.emit('message_error', { tempId, error: 'SEND_FAILED' });
    }
  });

  socket.on('webrtc_signal', ({ toId, signalPayload }) => {
    if (!isValidObjectId(toId)) return;
    logger.event('Relay WebRTC signal', { fromId: userId, toId }, 'Socket');
    io.to(String(toId)).emit('webrtc_signal', { fromId: userId, signalPayload });
  });

  socket.on('typing', ({ toId }) => {
    if (!isValidObjectId(toId)) return;
    io.to(String(toId)).emit('typing', { fromId: userId });
  });

  socket.on('stop_typing', ({ toId }) => {
    if (!isValidObjectId(toId)) return;
    io.to(String(toId)).emit('stop_typing', { fromId: userId });
  });

  socket.on('message_read', async ({ messageIds, toId }) => {
    try {
      const ids = (Array.isArray(messageIds) ? messageIds : []).filter(isValidObjectId);
      if (ids.length === 0) return;

      // Scoped to messages addressed to this user, so nobody can mark someone
      // else's conversation as read.
      await Message.updateMany(
        { _id: { $in: ids }, to_user_id: userId },
        { $set: { read: true } }
      );

      if (isValidObjectId(toId)) {
        io.to(String(toId)).emit('message_read', { messageIds: ids, byUserId: userId });
      }
    } catch (err) {
      logger.error('Failed to update message read status', { message: err.message }, 'Socket');
    }
  });

  socket.on('delete_message', async ({ messageId }) => {
    try {
      if (!isValidObjectId(messageId)) return;

      // Ownership is enforced in the query: only the sender can delete.
      const msg = await Message.findOneAndUpdate(
        { _id: messageId, from_user_id: userId },
        { $set: { deleted: true, payload: {}, sender_payload: {} } },
        { new: true }
      );
      if (!msg) {
        return logger.warn('delete_message: not found or not owned', { messageId, userId }, 'Socket');
      }

      io.to(String(msg.to_user_id)).emit('message_deleted', { messageId });
      io.to(String(msg.from_user_id)).emit('message_deleted', { messageId });
    } catch (err) {
      logger.error('Failed to delete message', { message: err.message }, 'Socket');
    }
  });

  socket.on('message_reaction', async ({ messageId, emoji }) => {
    try {
      if (!isValidObjectId(messageId)) return;
      if (typeof emoji !== 'string' || emoji.length === 0 || emoji.length > 16) return;

      const msg = await Message.findById(messageId);
      if (!msg) return;

      const participants = [String(msg.from_user_id), String(msg.to_user_id)];
      if (!participants.includes(userId)) {
        return logger.warn('message_reaction: not a participant', { messageId, userId }, 'Socket');
      }

      // Toggle rather than push, so repeat taps don't inflate the count.
      const existing = msg.reactions.findIndex(
        r => String(r.user_id) === userId && r.emoji === emoji
      );
      if (existing >= 0) msg.reactions.splice(existing, 1);
      else msg.reactions.push({ emoji, user_id: userId });
      await msg.save();

      // Broadcast the authoritative array; clients replace rather than append,
      // which is what stops a reaction being counted twice on the sender's side.
      const payload = { messageId, reactions: msg.reactions };
      for (const participant of new Set(participants)) {
        io.to(participant).emit('message_reaction', payload);
      }
    } catch (err) {
      logger.error('Failed to add reaction', { message: err.message }, 'Socket');
    }
  });

  socket.on('disconnect', async (reason) => {
    // Rooms are left before 'disconnect' fires, so this reflects the user's
    // other tabs (if any) rather than the socket that just went away.
    const stillOnline = isUserOnline(userId);
    logger.event('User disconnected', { userId, reason, stillOnline }, 'Socket');
    if (stillOnline) return;

    try {
      const lastSeen = new Date();
      await User.findByIdAndUpdate(userId, { is_online: false, last_seen: lastSeen });
      io.emit('user_status', { userId, status: 'offline', lastSeen });
    } catch (err) {
      logger.error('Failed to record disconnect', { message: err.message, userId }, 'Socket');
    }
  });
});

io.engine.on('connection_error', (err) => {
  logger.warn('Socket handshake rejected', { code: err.code, message: err.message }, 'Socket');
});

// ── Global error handler ──
app.use((err, req, res, _next) => {
  logger.error('Unhandled express error', { message: err.message, stack: err.stack }, 'Express');
  res.status(500).json({ error: 'Internal server error' });
});

httpServer.listen(config.port, () => {
  logger.info(`QChat backend running`, { port: config.port, env: config.nodeEnv, cors: config.corsOrigin }, 'Server');
});
