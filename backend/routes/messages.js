import express from 'express';
import { Message } from '../db/database.js';
import { authenticateToken } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';
import { isValidObjectId } from '../utils/validation.js';

const router = express.Router();
const CTX = 'Messages';

const MAX_PAGE_SIZE = 100;
const DEFAULT_PAGE_SIZE = 50;

router.get('/:peerId', authenticateToken, async (req, res) => {
  const currentUserId = req.user.id;
  const peerId = req.params.peerId;

  // Without this an unparseable id becomes a Mongoose CastError and a 500.
  if (!isValidObjectId(peerId)) {
    return res.status(400).json({ error: 'Invalid peer id' });
  }

  const parsedLimit = parseInt(req.query.limit, 10);
  const parsedOffset = parseInt(req.query.offset, 10);
  const limit = Math.min(Number.isNaN(parsedLimit) ? DEFAULT_PAGE_SIZE : Math.max(parsedLimit, 1), MAX_PAGE_SIZE);
  const offset = Number.isNaN(parsedOffset) ? 0 : Math.max(parsedOffset, 0);

  // Paging backwards by offset skews when live messages arrive mid-scroll (they
  // shift the window and a page gets skipped), so prefer a timestamp cursor and
  // keep offset only as a fallback.
  const filter = {
    $or: [
      { from_user_id: currentUserId, to_user_id: peerId },
      { from_user_id: peerId, to_user_id: currentUserId },
    ],
  };

  let before = null;
  if (req.query.before) {
    const parsed = new Date(req.query.before);
    if (Number.isNaN(parsed.getTime())) {
      return res.status(400).json({ error: 'Invalid "before" cursor' });
    }
    before = parsed;
    filter.timestamp = { $lt: parsed };
  }

  logger.info('Fetch history', { currentUserId, peerId, limit, offset, before }, CTX);

  try {
    const messages = await Message.find(filter)
      .sort({ timestamp: -1 })
      .skip(before ? 0 : offset)
      .limit(limit);

    // Re-order messages back to chronological order
    messages.reverse();

    logger.info(`Returned ${messages.length} messages`, { peerId }, CTX);

    res.json(
      messages.map((msg) => ({
        id: msg._id,
        fromId: msg.from_user_id,
        toId: msg.to_user_id,
        payload: msg.payload,
        senderPayload: msg.sender_payload,
        timestamp: msg.timestamp,
        delivered: msg.delivered,
        read: msg.read,
        replyToId: msg.reply_to_id,
        deleted: msg.deleted,
        type: msg.type,
        reactions: msg.reactions,
      }))
    );
  } catch (error) {
    logger.error('Fetch history failed', { message: error.message }, CTX);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// DELETE /api/messages/:peerId — clear conversation between current user and peer
router.delete('/:peerId', authenticateToken, async (req, res) => {
  const currentUserId = req.user.id;
  const peerId = req.params.peerId;

  if (!isValidObjectId(peerId)) {
    return res.status(400).json({ error: 'Invalid peer id' });
  }

  logger.info('Clear conversation', { currentUserId, peerId }, CTX);

  try {
    const result = await Message.deleteMany({
      $or: [
        { from_user_id: currentUserId, to_user_id: peerId },
        { from_user_id: peerId, to_user_id: currentUserId },
      ],
    });

    logger.info(`Cleared ${result.deletedCount} messages`, { peerId }, CTX);

    // Notify the peer so their UI syncs. Each user has a socket.io room keyed by
    // their own id, so this reaches every tab they have open.
    if (req.io) {
      req.io.to(String(peerId)).emit('chat_cleared', { byUserId: currentUserId });
    }

    res.json({ deleted: result.deletedCount });
  } catch (error) {
    logger.error('Clear conversation failed', { message: error.message }, CTX);
    res.status(500).json({ error: 'Failed to clear conversation' });
  }
});

export default router;
