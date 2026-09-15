import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import dotenv from 'dotenv';
import morgan from 'morgan';
import { connectDB, User, Message } from './db/database.js';
import authRoutes from './routes/auth.js';
import messageRoutes from './routes/messages.js';
import { authenticateToken } from './middleware/auth.js';
import { logger } from './utils/logger.js';

dotenv.config();

// ── Connect to MongoDB ──
connectDB();

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: { origin: 'http://localhost:5173', methods: ['GET', 'POST'] }
});

// ── HTTP request logger (Morgan → our logger) ──
app.use((req, _res, next) => { req._startTime = Date.now(); next(); });
app.use(morgan((tokens, req, res) => {
  const ms     = Date.now() - (req._startTime || Date.now());
  const status = parseInt(tokens.status(req, res)) || 0;
  logger.http(req, status, ms);
  return null; // morgan itself writes nothing; we handle output
}));

app.use(cors());
app.use(express.json());

// ── Expose Socket.io to routes ──
const onlineUsers = new Map(); // userId → socketId
app.use((req, res, next) => {
  req.io = io;
  req.onlineUsers = onlineUsers;
  next();
});

// ── Routes ──
app.use('/api/auth',     authRoutes);
app.use('/api/messages', messageRoutes);

// ── Users endpoint ──
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({ _id: { $ne: req.user.id } }).select('username public_key last_seen is_online');
    const formatted = users.map(u => ({ id: u._id, username: u.username, public_key: u.public_key, lastSeen: u.last_seen, isOnline: u.is_online }));
    logger.info(`Users listed`, { count: formatted.length, requestor: req.user.username }, 'Users');
    res.json(formatted);
  } catch (error) {
    logger.error('Failed to fetch users', { message: error.message }, 'Users');
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ── Socket.io ──

io.on('connection', (socket) => {
  logger.event(`Socket connected`, { socketId: socket.id }, 'Socket');

  socket.on('register_socket', async (userId) => {
    socket.userId = String(userId); // store for O(1) disconnect cleanup
    onlineUsers.set(String(userId), socket.id);
    logger.event('User registered socket', { userId, socketId: socket.id, online: onlineUsers.size }, 'Socket');
    
    await User.findByIdAndUpdate(userId, { is_online: true, last_seen: new Date() });
    io.emit('user_status', { userId, status: 'online', lastSeen: new Date() });

    // ── Deliver any messages that arrived while this user was offline ──
    try {
      const pending = await Message.find({
        to_user_id: userId,
        delivered:  false
      }).sort({ timestamp: 1 });

      if (pending.length > 0) {
        logger.info(`Delivering ${pending.length} offline message(s)`, { userId }, 'Socket');
        for (const msg of pending) {
          socket.emit('new_message', {
            id:       msg._id,
            fromId:   msg.from_user_id,
            payload:  msg.payload,
            timestamp: msg.timestamp,
            type:      msg.type,
            replyToId: msg.reply_to_id,
            deleted:   msg.deleted,
            reactions: msg.reactions
          });
        }
        // Mark all as delivered
        await Message.updateMany(
          { _id: { $in: pending.map(m => m._id) } },
          { $set: { delivered: true } }
        );

        // Notify senders that their messages were delivered
        const senderIds = [...new Set(pending.map(m => String(m.from_user_id)))];
        for (const sId of senderIds) {
          const sSocket = onlineUsers.get(sId);
          if (sSocket) {
            const deliveredIds = pending.filter(m => String(m.from_user_id) === sId).map(m => m._id);
            io.to(sSocket).emit('message_delivered', { messageIds: deliveredIds, toUserId: userId });
          }
        }
      }
    } catch (err) {
      logger.error('Offline delivery failed', { message: err.message }, 'Socket');
    }
  });

  socket.on('send_message', async ({ toId, fromId, payload, senderPayload, type, replyToId }) => {
    logger.event('Relay message', { fromId, toId }, 'Socket');
    try {
      // Check if recipient is currently connected
      const toSocket = onlineUsers.get(String(toId));
      
      // Save message, mark as delivered immediately if they are online
      const msg = new Message({
        from_user_id:   fromId,
        to_user_id:     toId,
        payload,
        sender_payload: senderPayload || null,
        type:           type || 'text',
        reply_to_id:    replyToId || null,
        delivered:      !!toSocket 
      });
      await msg.save();
      logger.info('Message saved', { id: msg._id, fromId, toId }, 'Socket');

      if (toSocket) {
        io.to(toSocket).emit('new_message', {
          id: msg._id, fromId, payload, timestamp: msg.timestamp,
          type: msg.type, replyToId: msg.reply_to_id, deleted: msg.deleted, reactions: msg.reactions
        });
        logger.event('Message delivered', { toId, socketId: toSocket }, 'Socket');
        // Notify sender it was delivered immediately
        socket.emit('message_delivered', { messageIds: [msg._id], toUserId: toId });
      } else {
        logger.warn('Recipient offline — message persisted for delivery on reconnect', { toId }, 'Socket');
      }
    } catch (error) {
      logger.error('send_message failed', { message: error.message }, 'Socket');
    }
  });

  socket.on('webrtc_signal', ({ toId, fromId, signalPayload }) => {
    logger.event('Relay WebRTC signal', { fromId, toId }, 'Socket');
    const toSocket = onlineUsers.get(String(toId));
    if (toSocket) {
      io.to(toSocket).emit('webrtc_signal', { fromId, signalPayload });
    }
  });

  socket.on('typing', ({ toId, fromId }) => {
    const toSocket = onlineUsers.get(String(toId));
    if (toSocket) io.to(toSocket).emit('typing', { fromId });
  });

  socket.on('stop_typing', ({ toId, fromId }) => {
    const toSocket = onlineUsers.get(String(toId));
    if (toSocket) io.to(toSocket).emit('stop_typing', { fromId });
  });

  socket.on('message_read', async ({ messageIds, fromId, toId }) => {
    try {
      await Message.updateMany(
        { _id: { $in: messageIds } },
        { $set: { read: true } }
      );
      const toSocket = onlineUsers.get(String(toId));
      if (toSocket) {
        io.to(toSocket).emit('message_read', { messageIds, byUserId: fromId });
      }
    } catch (err) {
      logger.error('Failed to update message read status', { message: err.message }, 'Socket');
    }
  });

  socket.on('delete_message', async ({ messageId, fromId, toId }) => {
    try {
      await Message.findOneAndUpdate(
        { _id: messageId, from_user_id: fromId },
        { $set: { deleted: true, payload: {}, sender_payload: {} } }
      );
      const toSocket = onlineUsers.get(String(toId));
      if (toSocket) io.to(toSocket).emit('message_deleted', { messageId });
      
      const senderSocket = onlineUsers.get(String(fromId));
      if (senderSocket) io.to(senderSocket).emit('message_deleted', { messageId });
    } catch (err) {
      logger.error('Failed to delete message', { message: err.message }, 'Socket');
    }
  });

  socket.on('message_reaction', async ({ messageId, emoji, fromId, toId }) => {
    try {
      await Message.updateOne(
        { _id: messageId },
        { $push: { reactions: { emoji, user_id: fromId } } }
      );
      const payload = { messageId, reaction: { emoji, user_id: fromId } };
      const toSocket = onlineUsers.get(String(toId));
      if (toSocket) io.to(toSocket).emit('message_reaction', payload);
      
      const senderSocket = onlineUsers.get(String(fromId));
      if (senderSocket) io.to(senderSocket).emit('message_reaction', payload);
    } catch (err) {
      logger.error('Failed to add reaction', { message: err.message }, 'Socket');
    }
  });

  socket.on('disconnect', async (reason) => {
    if (socket.userId) {
      if (onlineUsers.get(socket.userId) === socket.id) {
        onlineUsers.delete(socket.userId);
      }
      logger.event('User disconnected', { userId: socket.userId, reason, remaining: onlineUsers.size }, 'Socket');
      
      const lastSeen = new Date();
      await User.findByIdAndUpdate(socket.userId, { is_online: false, last_seen: lastSeen });
      io.emit('user_status', { userId: socket.userId, status: 'offline', lastSeen });
    }
  });

  socket.on('connect_error', (err) => {
    logger.error('Socket connect_error', { message: err.message }, 'Socket');
  });
});

// ── Global error handler ──
app.use((err, req, res, _next) => {
  logger.error('Unhandled express error', { message: err.message, stack: err.stack }, 'Express');
  res.status(500).json({ error: 'Internal server error' });
});

const PORT = process.env.PORT || 5000;
httpServer.listen(PORT, () => {
  logger.info(`QChat backend running`, { port: PORT, env: process.env.NODE_ENV || 'development' }, 'Server');
});
