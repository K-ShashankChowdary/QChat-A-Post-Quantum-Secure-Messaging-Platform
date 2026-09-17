import express from 'express';
import { User, Message } from '../db/database.js';
import { authenticateToken } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';
import { isValidObjectId } from '../utils/validation.js';
import { normalizeQChatId } from '../utils/qchatId.js';

const router = express.Router();
const CTX = 'Users';

const PUBLIC_FIELDS = 'username public_key last_seen is_online qchat_id';

const shape = (u) => ({
  id: u._id,
  username: u.username,
  qchatId: u.qchat_id,
  public_key: u.public_key,
  lastSeen: u.last_seen,
  isOnline: u.is_online,
});

/* ── GET /api/users/me — own profile, including the id to share ── */
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const me = await User.findById(req.user.id).select(PUBLIC_FIELDS);
    if (!me) return res.status(404).json({ error: 'User not found' });
    res.json(shape(me));
  } catch (error) {
    logger.error('Failed to load own profile', { message: error.message }, CTX);
    res.status(500).json({ error: 'Failed to load profile' });
  }
});

/* ── GET /api/users/lookup?q=QC-XXXX-XXXX — exact match only ──
   Deliberately exact: no partial or fuzzy matching, so the endpoint can't be
   used to walk the user list. */
router.get('/lookup', authenticateToken, async (req, res) => {
  const qchatId = normalizeQChatId(req.query.q);
  if (!qchatId) {
    return res.status(400).json({ error: 'That does not look like a QChat ID (expected QC-XXXX-XXXX)' });
  }

  try {
    const found = await User.findOne({ qchat_id: qchatId }).select(PUBLIC_FIELDS);
    if (!found) {
      logger.info('Lookup miss', { qchatId, by: req.user.username }, CTX);
      return res.status(404).json({ error: 'No account with that QChat ID' });
    }
    if (String(found._id) === String(req.user.id)) {
      return res.status(400).json({ error: 'That is your own QChat ID' });
    }

    logger.info('Lookup hit', { qchatId, by: req.user.username }, CTX);
    res.json(shape(found));
  } catch (error) {
    logger.error('Lookup failed', { message: error.message }, CTX);
    res.status(500).json({ error: 'Lookup failed' });
  }
});

/* ── GET /api/users — this user's contact list ──
   Contacts they added, plus anyone they've exchanged messages with, so an
   incoming message from a stranger still shows up. */
router.get('/', authenticateToken, async (req, res) => {
  const meId = String(req.user.id);
  try {
    const me = await User.findById(meId).select('contacts hidden_contacts');
    const [receivedFrom, sentTo] = await Promise.all([
      Message.distinct('from_user_id', { to_user_id: meId }),
      Message.distinct('to_user_id', { from_user_id: meId }),
    ]);

    const ids = new Set([
      ...(me?.contacts || []).map(String),
      ...receivedFrom.map(String),
      ...sentTo.map(String),
    ]);
    ids.delete(meId);

    // A hidden contact stays hidden until they say something new.
    const hidden = me?.hidden_contacts || [];
    if (hidden.length > 0) {
      const stillHidden = await Promise.all(hidden.map(async (h) => {
        const uid = String(h.user);
        if (!ids.has(uid)) return null;
        const newer = await Message.exists({
          from_user_id: uid,
          to_user_id: meId,
          timestamp: { $gt: h.hidden_at },
        });
        return newer ? null : uid;
      }));
      for (const uid of stillHidden) if (uid) ids.delete(uid);
    }

    if (ids.size === 0) return res.json([]);

    const users = await User.find({ _id: { $in: [...ids] } }).select(PUBLIC_FIELDS);
    logger.info('Contacts listed', { count: users.length, requestor: req.user.username }, CTX);
    res.json(users.map(shape));
  } catch (error) {
    logger.error('Failed to fetch contacts', { message: error.message }, CTX);
    res.status(500).json({ error: 'Failed to fetch contacts' });
  }
});

/* ── POST /api/users/contacts { userId } ── */
router.post('/contacts', authenticateToken, async (req, res) => {
  const { userId } = req.body;
  if (!isValidObjectId(userId)) return res.status(400).json({ error: 'Invalid user id' });
  if (String(userId) === String(req.user.id)) return res.status(400).json({ error: 'You cannot add yourself' });

  try {
    const target = await User.findById(userId).select(PUBLIC_FIELDS);
    if (!target) return res.status(404).json({ error: 'User not found' });

    // Adding someone back clears any previous hide.
    await User.findByIdAndUpdate(req.user.id, {
      $addToSet: { contacts: userId },
      $pull: { hidden_contacts: { user: userId } },
    });
    logger.info('Contact added', { by: req.user.username, added: target.username }, CTX);
    res.json(shape(target));
  } catch (error) {
    logger.error('Failed to add contact', { message: error.message }, CTX);
    res.status(500).json({ error: 'Failed to add contact' });
  }
});

/* ── DELETE /api/users/contacts/:id ──
   Only drops the explicit contact link. If there's message history the person
   still appears, because hiding a live conversation would be worse. */
router.delete('/contacts/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  if (!isValidObjectId(id)) return res.status(400).json({ error: 'Invalid user id' });

  try {
    // Drop the contact link and record the hide, so message history alone no
    // longer keeps them in the list.
    await User.findByIdAndUpdate(req.user.id, {
      $pull: { contacts: id, hidden_contacts: { user: id } },
    });
    await User.findByIdAndUpdate(req.user.id, {
      $push: { hidden_contacts: { user: id, hidden_at: new Date() } },
    });

    logger.info('Contact removed', { by: req.user.username, removed: id }, CTX);
    res.json({ removed: true });
  } catch (error) {
    logger.error('Failed to remove contact', { message: error.message }, CTX);
    res.status(500).json({ error: 'Failed to remove contact' });
  }
});

export default router;
