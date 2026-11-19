import express from 'express';
import { Message } from '../db/database.js';
import { authenticateToken } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';
import { isValidObjectId } from '../utils/validation.js';
import { serializeMessage } from '../utils/serialize.js';
import { leafForMessage } from '../utils/merkleLeaf.js';

const router = express.Router();
const CTX = 'Messages';

const MAX_PAGE_SIZE = 100;
const DEFAULT_PAGE_SIZE = 50;

/* ── GET /api/messages/:peerId/leaves ──
   Every Merkle leaf in the conversation, oldest first — 32 bytes a message,
   so a client can rebuild the root over the whole history, not just the page
   it has loaded. Order is (timestamp, _id), the same canonical order the
   client sorts into. */
const MAX_LEAVES = 50_000;

router.get('/:peerId/leaves', authenticateToken, async (req, res) => {
  const currentUserId = req.user.id;
  const { peerId } = req.params;
  if (!isValidObjectId(peerId)) return res.status(400).json({ error: 'Invalid peer id' });

  try {
    const rows = await Message.find({
      $or: [
        { from_user_id: currentUserId, to_user_id: peerId },
        { from_user_id: peerId, to_user_id: currentUserId },
      ],
    })
      .sort({ timestamp: 1, _id: 1 })
      .limit(MAX_LEAVES)
      .select('from_user_id timestamp deleted leaf')
      .lean();

    // A message saved without a leaf (by an older server, before the boot-time
    // backfill ran) would leave a hole the client can't hash. Fill it now.
    const missing = rows.filter(r => !r.leaf);
    if (missing.length > 0) {
      const full = await Message.find({ _id: { $in: missing.map(r => r._id) } })
        .select('from_user_id timestamp deleted payload').lean();
      const ops = full.map(m => ({ updateOne: { filter: { _id: m._id }, update: { $set: { leaf: leafForMessage(m) } } } }));
      const byId = new Map(full.map(m => [String(m._id), leafForMessage(m)]));
      for (const r of missing) r.leaf = byId.get(String(r._id)) || null;
      if (ops.length) await Message.bulkWrite(ops);
    }

    res.json({
      leaves: rows.map(r => ({
        id: r._id, fromId: r.from_user_id, timestamp: r.timestamp, deleted: !!r.deleted, leaf: r.leaf,
      })),
      truncated: rows.length === MAX_LEAVES,
    });
  } catch (error) {
    logger.error('Fetch leaves failed', { message: error.message }, CTX);
    res.status(500).json({ error: 'Failed to fetch transcript leaves' });
  }
});

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
  const conversation = {
    $or: [
      { from_user_id: currentUserId, to_user_id: peerId },
      { from_user_id: peerId, to_user_id: currentUserId },
    ],
  };
  let filter = conversation;

  let before = null;
  if (req.query.before) {
    const parsed = new Date(req.query.before);
    if (Number.isNaN(parsed.getTime())) {
      return res.status(400).json({ error: 'Invalid "before" cursor' });
    }
    const { beforeId } = req.query;
    if (beforeId !== undefined && !isValidObjectId(beforeId)) {
      return res.status(400).json({ error: 'Invalid "beforeId" cursor' });
    }
    before = parsed;
    // Two messages can share a millisecond, and a bare "timestamp < cursor"
    // skipped whichever of them fell on the far side of a page boundary. The
    // cursor is (timestamp, _id): strictly older, or the same instant with a
    // smaller id — matching the sort below exactly.
    const older = beforeId
      ? { $or: [{ timestamp: { $lt: parsed } }, { timestamp: parsed, _id: { $lt: beforeId } }] }
      : { timestamp: { $lt: parsed } };
    filter = { $and: [conversation, older] };
  }

  logger.info('Fetch history', { currentUserId, peerId, limit, offset, before }, CTX);

  try {
    const messages = await Message.find(filter)
      .sort({ timestamp: -1, _id: -1 })
      .skip(before ? 0 : offset)
      .limit(limit);

    // Re-order messages back to chronological order
    messages.reverse();

    logger.info(`Returned ${messages.length} messages`, { peerId }, CTX);

    res.json(messages.map((msg) => serializeMessage(msg, { includeSenderPayload: true })));
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
