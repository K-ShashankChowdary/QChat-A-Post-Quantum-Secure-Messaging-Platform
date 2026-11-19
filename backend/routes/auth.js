import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { User } from '../db/database.js';
import { authenticateToken } from '../middleware/auth.js';
import { logger } from '../utils/logger.js';
import config from '../config/env.js';
import { validateUsername, validatePassword, validatePublicKey, validateKeyBackup } from '../utils/validation.js';
import { allocateQChatId } from '../utils/qchatId.js';

const router = express.Router();
const CTX = 'Auth';

/* ── Per-account throttle ──
   The IP limiter alone lets a guesser spread attempts across addresses and
   hammer one account. This caps failures per username wherever they come from.
   In-memory is enough for a single-node deployment. */
const MAX_FAILURES = 5;
const LOCK_WINDOW_MS = 15 * 60 * 1000;
const failures = new Map();   // lower-cased username -> { count, first }

const expired = (entry) => Date.now() - entry.first > LOCK_WINDOW_MS;

function isLocked(key) {
  const entry = failures.get(key);
  if (!entry) return false;
  if (expired(entry)) { failures.delete(key); return false; }
  return entry.count >= MAX_FAILURES;
}

function recordFailure(key) {
  const entry = failures.get(key);
  if (!entry || expired(entry)) failures.set(key, { count: 1, first: Date.now() });
  else entry.count++;
  // Keep the map from growing without bound under a spray of random names.
  if (failures.size > 10_000) {
    for (const [k, v] of failures) if (expired(v)) failures.delete(k);
  }
}

// Compared against when the username doesn't exist, so a miss costs the same
// bcrypt time as a wrong password and timing can't reveal which it was.
const DUMMY_HASH = bcrypt.hashSync('qchat-timing-equaliser', 10);

const issueToken = (user) =>
  jwt.sign({ id: user._id, username: user.username }, config.jwtSecret, { expiresIn: config.jwtExpiresIn });

/* ── POST /api/auth/register ── */
router.post('/register', async (req, res) => {
  const { password, publicKey, keyBackup } = req.body;
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : req.body.username;
  logger.info('Register attempt', { username }, CTX);

  // Validated server-side: the React form's rules are advisory only, since the
  // API can be called directly (see improve.txt SEC-3).
  const invalid = validateUsername(username) || validatePassword(password)
    || validatePublicKey(publicKey) || validateKeyBackup(keyBackup);
  if (invalid) {
    logger.warn('Register: validation failed', { username, reason: invalid }, CTX);
    return res.status(400).json({ error: invalid });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const qchatId = await allocateQChatId(User);
    const user = new User({
      username, password_hash: passwordHash, public_key: publicKey,
      qchat_id: qchatId, key_backup: keyBackup || null,
    });
    await user.save();
    logger.info('Registered new user', { username, id: user._id, qchatId }, CTX);

    res.json({ token: issueToken(user), user: { id: user._id, username, publicKey, qchatId } });
  } catch (error) {
    if (error.code === 11000) {
      logger.warn('Register: duplicate username', { username }, CTX);
      return res.status(400).json({ error: 'Username already exists' });
    }
    logger.error('Register: unexpected error', { message: error.message }, CTX);
    res.status(500).json({ error: 'Registration failed' });
  }
});

/* ── POST /api/auth/login ── */
router.post('/login', async (req, res) => {
  const { password } = req.body;
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : req.body.username;
  logger.info('Login attempt', { username }, CTX);

  if (typeof username !== 'string' || !username || typeof password !== 'string' || !password) {
    logger.warn('Login: missing fields', null, CTX);
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const key = username.toLowerCase();
  if (isLocked(key)) {
    logger.warn('Login: account temporarily locked', { username }, CTX);
    return res.status(429).json({ error: 'Too many failed attempts for this account. Try again in 15 minutes.' });
  }

  try {
    const user = await User.findOne({ username });
    const valid = await bcrypt.compare(password, user?.password_hash || DUMMY_HASH);

    // One answer for both failures: separate messages told anyone which
    // usernames exist.
    if (!user || !valid) {
      recordFailure(key);
      logger.warn(user ? 'Login: wrong password' : 'Login: user not found', { username }, CTX);
      return res.status(401).json({ error: 'Incorrect username or password' });
    }
    failures.delete(key);

    logger.info('Login success', { username, id: user._id }, CTX);
    res.json({
      token: issueToken(user),
      user: { id: user._id, username: user.username, publicKey: user.public_key, qchatId: user.qchat_id },
      // Returned so a device with no stored key can recover the account's
      // original private key rather than generating a replacement.
      keyBackup: user.key_backup || null,
    });
  } catch (error) {
    logger.error('Login: unexpected error', { message: error.message }, CTX);
    res.status(500).json({ error: 'Login failed' });
  }
});

/* ── POST /api/auth/key-backup ──
   Stores (or replaces) the encrypted private key. Used at first sign-in for
   accounts created before backups existed, and after a password change. */
router.post('/key-backup', authenticateToken, async (req, res) => {
  const { keyBackup } = req.body;

  const invalid = validateKeyBackup(keyBackup);
  if (invalid) return res.status(400).json({ error: invalid });
  if (!keyBackup) return res.status(400).json({ error: 'Key backup is required' });

  try {
    await User.findByIdAndUpdate(req.user.id, { key_backup: keyBackup });
    logger.info('Key backup stored', { userId: req.user.id }, CTX);
    res.json({ stored: true });
  } catch (error) {
    logger.error('Key backup failed', { message: error.message }, CTX);
    res.status(500).json({ error: 'Could not store key backup' });
  }
});

/* ── POST /api/auth/update-key ── */
router.post('/update-key', authenticateToken, async (req, res) => {
  const { userId, publicKey } = req.body;
  logger.info('Update-key request', { userId }, CTX);

  // Authenticated but acting on someone else's record -> 403 (not 401, which the
  // frontend treats as "session is dead, log out").
  if (String(req.user.id) !== String(userId)) {
    logger.warn('Update-key: unauthorized', { tokenUser: req.user.id, requested: userId }, CTX);
    return res.status(403).json({ error: 'Unauthorized to modify this user' });
  }

  const invalid = validatePublicKey(publicKey);
  if (invalid) {
    logger.warn('Update-key: invalid key', { userId, reason: invalid }, CTX);
    return res.status(400).json({ error: invalid });
  }

  try {
    await User.findByIdAndUpdate(userId, { public_key: publicKey });
    logger.info('Public key updated', { userId }, CTX);
    res.json({ success: true });
  } catch (error) {
    logger.error('Update-key: error', { message: error.message }, CTX);
    res.status(500).json({ error: 'Key update failed' });
  }
});

export default router;
