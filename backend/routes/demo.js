import express from 'express';
import { Message } from '../db/database.js';
import { authenticateToken } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';
import { isValidObjectId } from '../utils/validation.js';
import { ATTACKS, applyAttack, undoAttack } from '../utils/attacks.js';
import config from '../config/env.js';

/* ── Attack simulator (demo mode only) ──
   One-click versions of scripts/tamper.js, for presenting the Merkle tree:
   the server attacks its own database and both participants' devices are
   told to re-verify, so the detection appears live on both screens. Every
   attack can be undone, so the demo can be repeated.

   Off unless DEMO_MODE=true, and never in production: with it off, every
   route here is a 404. Even when on, a user can only attack a conversation
   they are part of. */
const router = express.Router();
const CTX = 'Demo';

router.use((req, res, next) => {
  if (!config.demoMode) return res.status(404).json({ error: 'Not found' });
  next();
});

// Undo records per conversation, newest last. In memory: a restart forgets
// them, which only matters mid-demo.
const undo = new Map();
const conversationKey = (a, b) => [String(a), String(b)].sort().join(':');

/** Tell both participants to reload and re-verify this conversation. */
function refresh(io, a, b) {
  io.to(String(a)).emit('transcript_refresh', { peerId: String(b) });
  io.to(String(b)).emit('transcript_refresh', { peerId: String(a) });
}

router.get('/', authenticateToken, (_req, res) => {
  res.json({ enabled: true, attacks: ATTACKS });
});

router.post('/tamper', authenticateToken, async (req, res) => {
  const { messageId, mode } = req.body || {};
  if (!isValidObjectId(messageId)) return res.status(400).json({ error: 'Invalid message id' });
  if (!ATTACKS[mode]) return res.status(400).json({ error: 'Unknown attack' });

  try {
    const msg = await Message.findById(messageId);
    const me = String(req.user.id);
    if (!msg || ![String(msg.from_user_id), String(msg.to_user_id)].includes(me)) {
      return res.status(404).json({ error: 'Message not found in your conversations' });
    }

    const record = await applyAttack(msg, mode);
    const key = conversationKey(msg.from_user_id, msg.to_user_id);
    undo.set(key, [...(undo.get(key) || []), record]);
    logger.warn(`Simulated attack: ${mode}`, { messageId, by: req.user.username }, CTX);

    refresh(req.io, msg.from_user_id, msg.to_user_id);
    res.json({ ok: true, mode, messageId, forgedId: record.kind === 'delete' ? record.id : null });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

router.post('/restore', authenticateToken, async (req, res) => {
  const { peerId } = req.body || {};
  if (!isValidObjectId(peerId)) return res.status(400).json({ error: 'Invalid peer id' });

  try {
    const key = conversationKey(req.user.id, peerId);
    const records = undo.get(key) || [];
    for (const record of [...records].reverse()) await undoAttack(record);
    undo.delete(key);
    logger.info(`Restored ${records.length} simulated attack(s)`, { by: req.user.username }, CTX);

    refresh(req.io, req.user.id, peerId);
    res.json({ restored: records.length });
  } catch (error) {
    logger.error('Demo restore failed', { message: error.message }, CTX);
    res.status(500).json({ error: 'Could not restore the conversation' });
  }
});

export default router;
