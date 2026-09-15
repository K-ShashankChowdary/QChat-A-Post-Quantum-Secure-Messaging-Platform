import express from 'express';
import { Message } from '../db/database.js';
import { authenticateToken } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';

const router = express.Router();
const CTX = 'Messages';

router.get('/:peerId', authenticateToken, async (req, res) => {
  const currentUserId = req.user.id;
  const peerId  = req.params.peerId;
  const limit   = parseInt(req.query.limit)  || 50;
  const offset  = parseInt(req.query.offset) || 0;

  logger.info('Fetch history', { currentUserId, peerId, limit, offset }, CTX);

  try {
    const messages = await Message.find({
      $or: [
        { from_user_id: currentUserId, to_user_id: peerId },
        { from_user_id: peerId, to_user_id: currentUserId }
      ]
    }).sort({ timestamp: -1 }).skip(offset).limit(limit);

    // Re-order messages back to chronological order
    messages.reverse();

    logger.info(`Returned ${messages.length} messages`, { peerId }, CTX);

    res.json(messages.map(msg => ({
      id:             msg._id,
      fromId:         msg.from_user_id,
      toId:           msg.to_user_id,
      payload:        msg.payload,
      senderPayload:  msg.sender_payload,
      timestamp:      msg.timestamp,
      delivered:      msg.delivered,
      read:           msg.read,
      replyToId:      msg.reply_to_id,
      deleted:        msg.deleted,
      type:           msg.type,
      reactions:      msg.reactions
    })));
  } catch (error) {
    logger.error('Fetch history failed', { message: error.message }, CTX);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// DELETE /api/messages/:peerId — clear conversation between current user and peer
router.delete('/:peerId', authenticateToken, async (req, res) => {
  const currentUserId = req.user.id;
  const peerId = req.params.peerId;

  logger.info('Clear conversation', { currentUserId, peerId }, CTX);

  try {
    const result = await Message.deleteMany({
      $or: [
        { from_user_id: currentUserId, to_user_id: peerId },
        { from_user_id: peerId, to_user_id: currentUserId }
      ]
    });

    logger.info(`Cleared ${result.deletedCount} messages`, { peerId }, CTX);

    // Notify the peer if they are online so their UI syncs
    if (req.io && req.onlineUsers) {
      const peerSocketId = req.onlineUsers.get(String(peerId));
      if (peerSocketId) {
        req.io.to(peerSocketId).emit('chat_cleared', { byUserId: currentUserId });
        logger.info(`Emitted chat_cleared to peer`, { peerId, socketId: peerSocketId }, CTX);
      }
    }

    res.json({ deleted: result.deletedCount });
  } catch (error) {
    logger.error('Clear conversation failed', { message: error.message }, CTX);
    res.status(500).json({ error: 'Failed to clear conversation' });
  }
});

export default router;
