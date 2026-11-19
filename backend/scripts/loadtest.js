/**
 * Load test for the relay — the measurement behind the "scalable architecture"
 * objective (report §1.2 obj. 5, §3.2.2).
 *
 *   node scripts/loadtest.js                     # 100 users, 20 messages each
 *   node scripts/loadtest.js --users 500 --messages 20 --rate 2
 *
 * The backend must be running (npm run dev). The script creates throw-away
 * accounts straight in MongoDB — the sign-up endpoint is rate-limited per IP,
 * on purpose — signs each one a JWT, opens one authenticated Socket.io
 * connection per user, pairs them up, and has every user send messages to its
 * partner at `rate` per second. Payloads are shaped and sized like real
 * ML-KEM-768 v2 envelopes (two 1088-byte encapsulations plus AES-GCM fields),
 * so the server does exactly the work it does in production: validate, store,
 * relay. Latency is measured end to end — sender's emit to recipient's
 * new_message — on one clock, because both ends live in this process.
 *
 * Everything it creates is deleted afterwards (pass --keep to inspect it).
 */
import crypto from 'crypto';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { io } from 'socket.io-client';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import config from '../config/env.js';
import { connectDB, User, Message } from '../db/database.js';
import { allocateQChatId } from '../utils/qchatId.js';

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? Number(process.argv[i + 1]) : fallback;
};
const USERS = Math.max(2, arg('users', 100) & ~1);   // even, so everyone has a partner
const MESSAGES = arg('messages', 20);
const RATE = arg('rate', 2);                         // messages per second, per user
const KEEP = process.argv.includes('--keep');
const URL = `http://localhost:${config.port}`;
const run = crypto.randomBytes(3).toString('hex');

const b64 = (n) => crypto.randomBytes(n).toString('base64');
function envelope(fromId, toId, probe) {
  const slot = () => ({ encapsulatedKey: b64(1088), salt: b64(16), nonce: b64(12), ciphertext: b64(32), authTag: b64(16) });
  return { v: 2, keys: { [toId]: slot(), [fromId]: slot() }, nonce: b64(12), ciphertext: b64(64), authTag: b64(16), timestamp: Date.now(), probe };
}

const quantile = (sorted, q) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))] ?? 0;

console.log(`Load test: ${USERS} users × ${MESSAGES} messages at ${RATE}/s each → ${URL}`);
await connectDB();

// ── accounts ──
const passwordHash = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 10);
const users = [];
for (let i = 0; i < USERS; i++) {
  const user = await User.create({
    username: `lt_${run}_${i}`,
    password_hash: passwordHash,
    public_key: Buffer.from(ml_kem768.keygen().publicKey).toString('base64'),
    qchat_id: await allocateQChatId(User),
  });
  users.push({ id: String(user._id), token: jwt.sign({ id: user._id, username: user.username }, config.jwtSecret, { expiresIn: '1h' }) });
}
// Pairs are contacts of each other, like real conversations.
for (let i = 0; i < USERS; i += 2) {
  await User.updateOne({ _id: users[i].id }, { $addToSet: { contacts: users[i + 1].id } });
  await User.updateOne({ _id: users[i + 1].id }, { $addToSet: { contacts: users[i].id } });
}

// ── connections ──
const latencies = [];
const ackLatencies = [];
const sentAt = new Map();
let received = 0, errors = 0;
const tConnect = performance.now();
const sockets = await Promise.all(users.map(u => new Promise((resolve, reject) => {
  const s = io(URL, { auth: { token: u.token }, transports: ['websocket'], reconnection: false });
  s.on('connect', () => resolve(s));
  s.on('connect_error', reject);
  s.on('new_message', (m) => {
    const t = sentAt.get(m.payload?.probe);
    if (t !== undefined) { latencies.push(performance.now() - t); received++; }
  });
  s.on('message_sent', ({ tempId }) => {
    const t = sentAt.get(tempId);
    if (t !== undefined) ackLatencies.push(performance.now() - t);
  });
  s.on('message_error', () => { errors++; });
})));
const connectMs = performance.now() - tConnect;
console.log(`Connected ${sockets.length} authenticated sockets in ${connectMs.toFixed(0)} ms`);

// ── traffic ──
const total = USERS * MESSAGES;
const tStart = performance.now();
await Promise.all(users.map((u, i) => new Promise((resolve) => {
  const partner = users[i ^ 1];
  let n = 0;
  // Stagger start times so the users don't fire in lock-step.
  setTimeout(() => {
    const timer = setInterval(() => {
      const probe = `${run}-${i}-${n}`;
      sentAt.set(probe, performance.now());
      sockets[i].emit('send_message', { tempId: probe, toId: partner.id, payload: envelope(u.id, partner.id, probe), type: 'text' });
      if (++n >= MESSAGES) { clearInterval(timer); resolve(); }
    }, 1000 / RATE);
  }, Math.random() * (1000 / RATE));
})));

// Wait for stragglers.
const deadline = performance.now() + 15_000;
while (received < total && performance.now() < deadline) await new Promise(r => setTimeout(r, 100));
const elapsed = (performance.now() - tStart) / 1000;

latencies.sort((a, b) => a - b);
ackLatencies.sort((a, b) => a - b);
const result = {
  users: USERS,
  messagesSent: total,
  messagesDelivered: received,
  errors,
  connectAllMs: Math.round(connectMs),
  throughputPerSec: +(received / elapsed).toFixed(1),
  deliveryMs: {
    p50: +quantile(latencies, 0.5).toFixed(1),
    p95: +quantile(latencies, 0.95).toFixed(1),
    p99: +quantile(latencies, 0.99).toFixed(1),
    max: +(latencies[latencies.length - 1] ?? 0).toFixed(1),
  },
  serverAckMs: { p50: +quantile(ackLatencies, 0.5).toFixed(1), p95: +quantile(ackLatencies, 0.95).toFixed(1) },
};
console.log(JSON.stringify(result, null, 2));
console.log(`| ${USERS} | ${total} | ${received} | ${result.throughputPerSec}/s | ${result.deliveryMs.p50} ms | ${result.deliveryMs.p95} ms | ${result.deliveryMs.p99} ms | ${errors} |`);

// ── cleanup ──
for (const s of sockets) s.close();
if (!KEEP) {
  const ids = users.map(u => u.id);
  await Message.deleteMany({ $or: [{ from_user_id: { $in: ids } }, { to_user_id: { $in: ids } }] });
  await User.deleteMany({ _id: { $in: ids } });
  console.log('Removed the test accounts and their messages.');
}
await mongoose.disconnect();
process.exit(received === total && errors === 0 ? 0 : 1);
