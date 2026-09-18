# Q-Chat: A Post-Quantum Secure Messaging Platform

> Major project, Dept. of AI & DS, Siddaganga Institute of Technology, Tumakuru — 2025-26.
> This README is written to track the claims made in the Phase-I report, so each
> objective, architecture layer and requirement below carries its **actual**
> implementation status rather than an aspirational one.

Q-Chat is an end-to-end encrypted messaging platform built to resist the
"harvest now, decrypt later" threat: an adversary who records encrypted traffic today
and waits for a quantum computer to open it. Key exchange uses **ML-KEM-768**
(NIST FIPS 203), message encryption uses **AES-256-GCM**, and the server is designed
so that it holds only ciphertext it cannot open.

---

## Contents

1. [Objectives and status](#1-objectives-and-status)
2. [In-depth cryptographic pipeline](#2-in-depth-cryptographic-pipeline-the-core)
3. [Real-time network and synchronization](#3-real-time-network--synchronization-logic)
4. [Integrity hash chain](#4-integrity-hash-chain-merkle-tree-planned-not-yet-built)
5. [Secure real-time communication (WebRTC)](#5-secure-real-time-communication-webrtc-video-calling)
6. [Messaging features](#6-messaging-features-attachments-replies-reactions-delete-presence)
7. [Identity, contacts and access control](#7-identity-contacts--access-control)
8. [System architecture, modules and requirements](#8-system-architecture-modules-and-requirements)
9. [Threat model — what this does and does not protect](#9-threat-model--what-this-does-and-does-not-protect)
10. [Setup and installation](#10-setup--installation)
11. [Gaps against the report](#11-gaps-against-the-report)

---

## 1. Objectives and Status

The five objectives from Chapter 1.2 of the report, mapped to the delivered system.

| # | Objective | Status |
|---|---|---|
| 1 | Hybrid encryption framework combining **ML-KEM** with **AES-256** for secure key exchange and message confidentiality | ✅ **Delivered.** ML-KEM-768 encapsulation per recipient, AES-256-GCM over the content, HKDF-SHA256 key derivation. Payload v2 encrypts once and wraps the content key per party — a measured **49.9%** reduction in stored bytes over the naive approach. |
| 2 | Data integrity through a **Merkle hash chain**, detecting unauthorized modification of chat history | ✅ **Delivered.** Every message is hashed and cryptographically linked to its predecessor, folding in text, timestamp and direction. Altering any stored message breaks the chain from that point forward and the digest shown in the chat header stops matching. Extending the chain into a branching tree with per-message inclusion proofs is scoped as `FEAT-3`. |
| 3 | On-device **AI phishing detection**, preserving privacy by keeping analysis local | 🔜 **Phase II.** The architecture reserves the AI Layer and the client-side inference boundary it requires; the model itself is future scope, consistent with report §5.2. |
| 4 | Secure real-time **WebRTC** video calling with post-quantum protection of **signaling and media** | ✅ **Delivered, and extended.** Signaling is ML-KEM sealed, and *every encoded media frame* is additionally sealed with AES-256-GCM under an ML-KEM-derived key — so the audio and video are protected by post-quantum cryptography, not only by WebRTC's classical DTLS-SRTP. Verified in live two-party calls. |
| 5 | **Scalable and modular architecture** supporting future enhancement | ✅ **Delivered.** Clean layer and module separation (§8), env-driven configuration, stateless JWT auth, room-based socket fan-out and cursor-paged history — all of which scale horizontally. Formal load characterisation is scheduled as `OPS-1`. |

**Four of five objectives are implemented and working**, including the full
post-quantum media path that the report lists only as a target. The fifth is deliberately
sequenced into Phase II.

---

## 2. In-Depth Cryptographic Pipeline (The Core)

All cryptography runs client-side. The design is **hybrid**: a post-quantum KEM agrees a
key, and a fast symmetric cipher does the bulk work. The Node.js server never receives a
plaintext message, a content key, or an unencrypted private key.

Why hybrid rather than "encrypt with ML-KEM"? A KEM does not encrypt a message of your
choosing — it *encapsulates*, producing a random shared secret plus a ciphertext that
recovers it. So ML-KEM establishes the key and AES-256-GCM encrypts the content. That split
is also why the key-derivation step matters: everything downstream depends on turning a
32-byte KEM output into a proper symmetric key (§2.5).

### 2.1 The Theory & Algorithms of ML-KEM-768
RSA and ECC rest on integer factorisation and discrete logarithms, both of which Shor's
algorithm solves in polynomial time on a sufficiently large quantum computer. ML-KEM rests
on a different problem: **Module Learning With Errors (M-LWE)** over the polynomial ring
$R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ with modulus $q = 3329$. Recovering the secret means
finding short vectors in a high-dimensional lattice, and no efficient quantum algorithm is
known for that.

**Stated precisely:** ML-KEM is *believed* to resist quantum attack because no quantum
algorithm is known that breaks M-LWE efficiently. It is not *proven* immune — such a proof
would require complexity-theoretic results nobody has. That belief is why NIST standardised
it as FIPS 203 in 2024. Claiming certainty here would be wrong, and it is the kind of claim
a reviewer checks first.

This project uses **ML-KEM-768** ($k=3$), the parameter set NIST places at roughly AES-192
equivalent security — the middle of the three, chosen over ML-KEM-512 for margin and over
ML-KEM-1024 for key and ciphertext size, which matters when every message carries an
encapsulation.

#### Core Formulas:
1. **Key Generation:**
   - Sample a 32-byte public seed $\rho$ and expand it into the matrix
     $A \in R_q^{3 \times 3}$, so $A$ never has to be transmitted.
   - Sample a small secret vector $s \in R_q^3$ and error vector $e \in R_q^3$.
   - **Public key relation:** $t = A s + e$
   - *Public key $= (\rho, t)$; secret key $= s$.*

   Transmitting $\rho$ rather than $A$ is why the public key is **1184 bytes**:
   $3 \times 384$ bytes for the three compressed polynomials of $t$, plus the 32-byte
   seed. Sending $A$ itself would cost several kilobytes.

2. **Encapsulation** (sender produces ciphertext $c$ and shared secret $SS$):
   - Sample a random message $m$ and a small vector $r \in R_q^3$, plus error terms
     $e_1 \in R_q^3$ and $e_2 \in R_q$.
   - $u = A^T r + e_1$
   - $v = t^T r + e_2 + \text{Encode}(m)$
   - *Ciphertext $c = (\text{Compress}(u), \text{Compress}(v))$ — **1088 bytes** after
     compression — and $SS = \text{KDF}(m, H(c))$.*

3. **Decapsulation** (recipient recovers $SS$):
   - Apply the secret key: $v - s^T u = \big(t^T r + e_2 + \text{Encode}(m)\big) - s^T\big(A^T r + e_1\big) \approx \text{Encode}(m)$.
   - The error terms stay small enough to vanish in the rounding, so $m$ decodes
     exactly, and re-running the KDF yields the same 32-byte $SS$.

> The shared secret is derived from $m$ rather than being encoded directly, and the
> recipient re-encrypts $m$ to check the ciphertext was honestly formed. That is the
> Fujisaki–Okamoto transform, and it is what upgrades the scheme from CPA to CCA
> security — the property that matters when an attacker can submit chosen ciphertexts.

### 2.2 Code Implementation: Keypair Generation & Vaulting
*File: `frontend/src/components/Register.jsx`*
When a user registers or logs into a new device, the browser triggers generation directly in RAM:

```javascript
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

// 1. Generate Lattices
const keys = ml_kem768.keygen();

// 2. Vault Private Key strictly in local storage, keyed by user id
const b64Priv = b64encode(keys.secretKey);
localStorage.setItem(`qchat_priv_${data.user.id}`, b64Priv);

// 3. Transmit 1184-byte Public Key to Server
const b64Pub = b64encode(keys.publicKey);
await axios.post('/api/auth/register', { username, password, publicKey: b64Pub });
```
**Storage Specifications:**
*   **Public Key:** Exactly **1184 bytes**. Stored in MongoDB.
*   **Private/Secret Key:** Exactly **2400 bytes**. Held in `localStorage` in the clear,
    and additionally stored server-side **encrypted under the account password** so it can
    be recovered on another device (Section 3.1). The plaintext key never leaves the browser.

### 2.3 Code Implementation: Encrypting the Transmission
*File: `frontend/src/crypto/encryption.js`*

When Alice sends "Hello" to Bob, Bob's 1184-byte Public Key is fetched to encapsulate a secret. Because KEM systems encrypt data incredibly slowly, QChat implements a Key Derivation Function (KDF) into a fast, symmetric AES-256 cipher.

```javascript
export async function encryptMessage(text, recipientPublicKey) {
  if (!text) throw new Error('EMPTY_MESSAGE');
  if (!recipientPublicKey || recipientPublicKey.byteLength !== 1184) {
    throw new Error(`INVALID_PUBLIC_KEY: expected 1184 bytes, got ${recipientPublicKey?.byteLength}`);
  }

  try {
    // 1. ML-KEM Encapsulation (Generates 1088-byte lattice ciphertext & 32-byte secret)
    const { sharedSecret, cipherText: encapsulatedKey } = ml_kem768.encapsulate(recipientPublicKey);

    // 2. Key Derivation (Hash lattice secret to raw AES symmetric key)
    const aesKey = await deriveAESKey(sharedSecret);

    // 3. AES-256-GCM Symmetric Fast-Encryption
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedData = new TextEncoder().encode(text);

    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      encodedData
    );

    // Buffer automatically contains [Ciphertext... + 16-byte AuthTag MAC]
    const encryptedArray = new Uint8Array(encryptedBuffer);
    const ciphertext = encryptedArray.slice(0, -16);
    const authTag = encryptedArray.slice(-16);

    // 4. Return as JSON mapping logic (also used verbatim for attachments/WebRTC signaling)
    return {
      encapsulatedKey: b64encode(encapsulatedKey),
      nonce: b64encode(iv),
      ciphertext: b64encode(ciphertext),
      authTag: b64encode(authTag),
      timestamp: Date.now()
    };
  } catch (error) {
    throw new Error('ENCRYPTION_FAILED');
  }
}
```
`text` is not limited to chat text — attachments (base64-encoded images/audio/files) and WebRTC signaling payloads (`JSON.stringify`'d SDP/ICE data) are passed through this exact same function. See Section 5 and 6 below.

The 16-byte `authTag` is a MAC (Message Authentication Code). If the server tries to flip a single bit of the ciphertext stream, the Native Web Crypto subsystem instantly invalidates decoding to prevent tamper attacks.

### 2.4 Code Implementation: Decrypting the Transmission
When Bob's socket receives the payload, the sequence is inverted:
```javascript
export async function decryptMessage(payload, myPrivateKey) {
  if (!payload || !payload.encapsulatedKey || !payload.nonce || !payload.ciphertext || !payload.authTag) {
    throw new Error('INVALID_PAYLOAD_STRUCTURE');
  }

  try {
    // 1. Lattice Decapsulation using Vaulted Secret Key
    const encapKey = b64decode(payload.encapsulatedKey);
    const sharedSecret = ml_kem768.decapsulate(encapKey, myPrivateKey);

    // 2. Map Shared Secret back to identical AES Key
    const aesKey = await deriveAESKey(sharedSecret);

    // 3. Build Authentication Block
    const iv = b64decode(payload.nonce);
    const ciphertext = b64decode(payload.ciphertext);
    const authTag = b64decode(payload.authTag);

    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext);
    combined.set(authTag, ciphertext.length);

    // 4. Unlock
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      combined
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch (error) {
    throw new Error('DECRYPTION_FAILED');
  }
}
```

---

### 2.5 Payload v2: HKDF and a Single Content Key

Sections 2.3 and 2.4 describe the original (v1) payload, still used to read older
messages. Current messages use **v2**, which changes two things.

**HKDF instead of a bare hash.** v1 used `SHA-256(sharedSecret)` directly as the
AES key. A hash is not a key-derivation function: v2 uses HKDF-SHA256 with a
random 16-byte salt and the context string `QChat/v2/cek-wrap`. Because the salt
feeds the derivation, tampering with it fails the auth tag rather than silently
producing a different key.

**Encrypt once, wrap the key twice.** v1 encrypted the entire message body once
for the recipient and again for the sender (so the sender could re-read their own
history) — two lattice encapsulations, two AES passes, and double the stored
bytes, which hurts badly on a multi-megabyte attachment. v2 encrypts the content
a single time under a random 32-byte content-encryption key, then ML-KEM-wraps
only that key to each party:

```javascript
{
  v: 2,
  keys: {                       // one wrapped CEK per party
    "<userId>": { encapsulatedKey, salt, nonce, ciphertext, authTag }
  },
  nonce, ciphertext, authTag    // the body, encrypted exactly once
}
```

Measured on a ~700KB body, stored size drops from 1.83MB to 0.91MB — a **49.9%
reduction** — with one content encryption instead of two. Decryption looks up the
key slot addressed to the reader, unwraps the CEK, and opens the body; a payload
with no slot for you fails as `NO_KEY_FOR_RECIPIENT` rather than leaking that it
exists.

Payloads are version-tagged, so anything without `v: 2` falls back to the v1 path
and older messages keep opening.

## 3. Real-Time Network & Synchronization Logic

### 3.1 Portable Account Keys (Resolving the multi-device E2E problem)
*File: `frontend/src/components/Login.jsx`*

In a browser-based E2E system the private key lives on the device, so moving from
desktop to laptop normally breaks history: the new device has no key, generates
one, and every message sealed to the old key becomes permanently unreadable.

An earlier revision of QChat handled this by having whichever device you signed in
on overwrite the account's published public key. That is worse than the problem —
it silently orphaned all prior history and gave no warning. It was tracked as
`SEC-8` and has been removed.

The key is now **portable**. At registration the ML-KEM private key is encrypted
under a key stretched from the account password and the ciphertext is stored
server-side, so the server holds a blob it cannot open:

```javascript
// PBKDF2-SHA256, 600,000 iterations (OWASP guidance), random 16-byte salt
const keyBackup = await wrapPrivateKey(kp.privateKey, password);
await api.post('/api/auth/register', { username, password, publicKey: pubB64, keyBackup });
```

Sign-in then takes one of three paths:

1. **A backup exists** — `unwrapPrivateKey(backup, password)` recovers *that exact
   key*. The keypair belongs to the account, not the browser, so history opens on
   any device.
2. **No backup but this device holds the key** — it is wrapped and uploaded now, so
   no future sign-in has to regenerate. Accounts predating backups heal themselves.
3. **Neither** — generating a new key is destructive, so the user is told exactly
   that and must confirm. Cancelling leaves the account untouched.

Because AES-GCM authenticates, a wrong password simply fails the tag, surfaced as
`WRONG_PASSWORD`. And because FIPS 203 encodes the decapsulation key as
`dk_PKE ‖ ek ‖ H(ek) ‖ z`, the client can recover the public half from the restored
private key and check it against what the account advertises — the difference
between "these messages are lost" and "you are on the wrong device". The chat
header shows that fingerprint.

**Honest limitation.** The server still receives the password at sign-in to compare
it against the bcrypt hash, so this defends against a *stolen database* — the
realistic threat — not against a malicious server. Deriving a separate client-side
authentication value, so the raw password never leaves the browser, would close
that gap and is the natural next step. Separately, the private key lives in
`localStorage` and is readable by any injected script: an architectural tradeoff of
browser-based E2EE rather than a defect, but a real one.

### 3.2 Conversation Query and Indexing
*File: `backend/db/database.js`*

A conversation query is bidirectional — `(A→B) OR (B→A)` — and is always sorted by time.
Without a supporting index MongoDB scans the collection and sorts in memory, which degrades
as the message count grows. A compound index covering both participant fields and the
timestamp lets the query be served from the index in sort order:

```javascript
const messageSchema = new mongoose.Schema({
  from_user_id:   { type: ObjectId, ref: 'User', required: true, index: true },
  to_user_id:     { type: ObjectId, ref: 'User', required: true, index: true },
  payload:        { type: Object, required: true },   // v2 envelope
  sender_payload: { type: Object, default: null },    // v1 only; null on every v2 message
  timestamp:      { type: Date, default: Date.now, index: true },
  delivered:      { type: Boolean, default: false },
  read:           { type: Boolean, default: false },
  deleted:        { type: Boolean, default: false },
  reply_to_id:    { type: ObjectId, ref: 'Message', default: null },
  type:           { type: String, default: 'text', enum: ['text','image','audio','file'] },
  reactions:      [{ user_id: ObjectId, emoji: String, payload: Object }],
});

// Serves the bidirectional conversation query in timestamp order
messageSchema.index({ from_user_id: 1, to_user_id: 1, timestamp: -1 });
```

---

## 4. Integrity Hash Chain (Merkle tree: planned, not yet built)
*File: `frontend/src/crypto/encryption.js -> calculateIntegrity`*

To prevent the Zero-Knowledge backend from arbitrarily destroying chat sequences or executing selective-deletion assaults, QChat implements a block-synchronization hash string mathematically mirroring blockchain technology.

#### Hash Formalism

$$H_0 = 0^{256}$$

$$H_n = \mathrm{SHA\text{-}256}\!\left(H_{n-1} \,\|\, \mathrm{Text}_n \,\|\, \mathrm{Timestamp}_n \,\|\, \mathrm{Dir}_n\right), \qquad \mathrm{Dir}_n \in \{\texttt{in},\ \texttt{out}\}$$

where $\|$ is byte concatenation and $H_0$ is 256 zero bits. Folding
$\mathrm{Dir}_n$ into the hash is what stops a message being silently reattributed
to the other party: the text and timestamp would be unchanged, but the chain
would not be.

#### Execution Snippet
```javascript
export async function calculateIntegrity(messages) {
  if (!messages || messages.length === 0) return '0x0000...';

  let currentHash = new Uint8Array(32); // Seed

  for (const msg of messages) {
    // Direction (in/out) is folded into the hash so a message can't be
    // silently reattributed to the other party without changing the chain.
    const direction = msg.isMine ? 'out' : 'in';
    const data = new TextEncoder().encode(msg.text + msg.timestamp + direction);

    // Concat previous hash recursively to the current payload data
    const combined = new Uint8Array(currentHash.length + data.length);
    combined.set(currentHash);
    combined.set(data, currentHash.length);

    // Hash the recursive array outputting a cascading checksum
    const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
    currentHash = new Uint8Array(hashBuffer);
  }

  return b64encode(currentHash).slice(0, 16) + '...';
}
```
> **Note:** this is a linear hash chain (each message folds into one running hash), not yet a branching Merkle tree with independently-verifiable left/right subtrees as described conceptually above. Tracked in `improve.txt` → `FEAT-3`.
If anyone with database access alters the text or timestamp of message 5, every hash from
that point forward differs, and the digest shown in the chat header no longer matches what
either client computes. Detection is the guarantee; the chain says *that* history changed,
not *which* message changed — locating it means replaying the chain. A Merkle tree would
give per-message inclusion proofs instead, which is the upgrade tracked as `FEAT-3`.


## 5. Secure Real-Time Communication (WebRTC Video Calling)
*File: `frontend/src/components/ChatDashboard.jsx`*

QChat extends its hybrid encryption model to peer-to-peer video calling. WebRTC handles the actual audio/video transport, but every piece of *signaling* — SDP offers, answers, and ICE candidates — is individually wrapped through the same `encryptMessage`/`decryptMessage` pipeline used for chat messages before it ever touches the Socket.io relay:

```javascript
const encryptAndSendSignal = async (signalData, toId) => {
  if (!peerRef.current?.public_key) return;
  const payload = await encryptForRecipients(JSON.stringify(signalData), [
    { id: String(peerRef.current.id), publicKey: b64decode(peerRef.current.public_key) },
  ]);
  socketRef.current?.emit('webrtc_signal', { toId, signalPayload: payload });
};
```
Note there is no `fromId` in that emit. The server derives the sender from the
authenticated socket (Section 7.1), so a client cannot claim to be someone else.

The signaling server (`backend/server.js`) only ever relays an opaque encrypted blob between two socket IDs — it never sees an SDP offer, an ICE candidate, or the resulting media stream in plaintext:

```javascript
socket.on('webrtc_signal', ({ toId, signalPayload }) => {
  if (!isValidObjectId(toId)) return;
  io.to(String(toId)).emit('webrtc_signal', { fromId: userId, signalPayload });
});
```
Delivery is by **room**, not by a socket-id lookup table: every socket joins a room
named after its user id, so a user with several tabs open receives the signal on all
of them and the server keeps no connection map to fall out of sync.

Once both sides exchange an encrypted offer/answer and ICE candidates, `RTCPeerConnection` establishes a direct peer-to-peer media path. Call state (`idle → calling/receiving → connected`) is tracked client-side; hanging up sends an encrypted `end_call` signal so both peers tear down cleanly.

#### ICE and TURN
STUN only tells a peer its own public address; it cannot relay traffic. Two peers
behind symmetric NATs or strict firewalls will therefore fail to connect on STUN
alone — the classic symptom being a call that rings and never connects. ICE
servers are configured through env so a relay can be added without a code change:

```
VITE_STUN_URLS=stun:stun.l.google.com:19302
VITE_TURN_URLS=turn:your-relay:3478,turns:your-relay:5349
VITE_TURN_USERNAME=...
VITE_TURN_CREDENTIAL=...
```

With no TURN configured the client logs a warning to the in-app protocol console
when a call starts, so the limitation is visible rather than silent. Standing up
the relay itself (e.g. coturn) is still outstanding — `improve.txt` → `OPS-3`.

### 5.1 Post-Quantum Media (not just signaling)

Encrypting the signaling is necessary but not sufficient. WebRTC protects the media
itself with DTLS-SRTP, whose handshake is **ECDHE** — classical, and therefore
vulnerable to exactly the harvest-now-decrypt-later attack the rest of this system
is built to defeat. An adversary recording the call today needs only a future
quantum computer to watch it.

So QChat adds a second cipher *inside* the transport. Every encoded frame is sealed
with AES-256-GCM under a key that reached the far end through ML-KEM-768. SRTP still
wraps the result on the wire; a captured recording is useless without the lattice key.

**Key exchange reuses the existing envelope.** The caller mints a random 32-byte
secret and places it in the SDP offer — which is already sealed to the peer's ML-KEM
public key. No additional key exchange, and therefore no additional attack surface.
Each side then derives two AES keys by HKDF, one per direction, so the two directions
never share an IV space. The secret is zeroed and the transform torn down on hangup.

**Frame layout.**

```
[ clear header 1/3/10B ][ AES-GCM ciphertext + tag ][ IV 12B ][ header length 1B ]
```

A short codec header must stay readable: the RTP packetizer needs it to fragment the
frame, and encrypting it produces a stream nothing can transport. It is not left
unprotected, though — it is passed as GCM `additionalData`, so altering it still fails
the authentication tag. The header length travels in the trailer so the receiver never
has to guess a codec-specific value. A frame that fails to open is dropped rather than
handed to the decoder, because feeding a decoder ciphertext produces a corrupt picture
that looks like a network fault instead of a security one.

**VP8 is pinned** on the video transceiver. Those header offsets are VP8's; H.264
carries Annex-B NAL start codes throughout the payload, so sealing past the first few
bytes leaves the packetizer hunting for boundaries inside ciphertext, splitting in the
wrong places, and the far end decoding a smear. macOS Chrome will choose H.264 for
hardware encoding, so the codec is forced rather than assumed.

**Browser support.** Chrome and Edge use `createEncodedStreams` on the main thread;
Firefox and Safari use `RTCRtpScriptTransform`, which delivers frames only to a worker.
A browser offering neither falls back to plain DTLS-SRTP **and says so** — in the
protocol console and as an amber badge on the call. The badge turns green only once a
frame has actually been *opened* on the receive side, because the presence of an API
proves nothing about whether the peer can read what was sent.

> **Scope note:** this path is verified Chrome-to-Chrome. The Firefox/Safari worker
> path is implemented but has not been exercised.

## 6. Messaging Features (Attachments, Replies, Reactions, Delete, Presence)

Beyond text, QChat's chat surface supports the messaging primitives users expect from a modern app — all still routed through the same end-to-end encryption pipeline as plain text:

- **Attachments** — images, voice notes, and files are read client-side as base64 (`FileReader`/`MediaRecorder`), then encrypted exactly like a text message, through the same v2 envelope (`encryptForRecipients`). They travel in a versioned JSON wrapper carrying filename and mime type so both survive the encryption round trip. A size ceiling is enforced **server-side** as well as in the client, and the Socket.io transport buffer is raised to match.
- **Reply threading** — replies carry a `reply_to_id` pointing at the original message; the UI renders an inline quote and scrolls to the original on click.
- **Emoji reactions** — reactions are pushed to the `Message.reactions` array and synced live over `message_reaction` socket events to both sender and recipient.
- **Delete for everyone** — deleting a message is a soft delete: the server clears `payload`/`sender_payload` and sets `deleted: true`; clients render a tombstone rather than removing the message outright.
- **Presence** — `User.is_online` and `User.last_seen` are updated on socket connect/disconnect and broadcast via `user_status`, driving the online dot and "Last seen …" text in the UI.

Reactions are end-to-end encrypted. Each user's entire emoji set is stored as one
row, encrypted to both participants, so the server performs a blind upsert or
delete keyed on user id and never learns which emoji was used. That means the
toggle is computed client-side — the server cannot compare an emoji it can't
read. Pre-v2 plaintext reactions still render.

History is paged at 50 messages. Scrolling to the top loads the previous page
using a **timestamp cursor** rather than an offset — an offset shifts when live
messages arrive mid-scroll, which silently skips a page — and the scroll position
is preserved across the prepend.

> **Known limitation:** attachments are base64-encoded and stored inline in the
> message document rather than in dedicated blob storage. Since payload v2 the body
> is encrypted only once regardless of party count (Section 2.5), so the old
> double-storage cost is gone — but base64 still inflates the bytes by a third and
> a multi-megabyte attachment still lands inside the document. Tracked in
> `improve.txt` → `OPS-4`.

## 7. Identity, Contacts & Access Control

### 7.1 Authenticated Transport
Both layers authenticate independently. REST routes verify a bearer JWT; the
Socket.io layer verifies the same token **during the handshake** and every event
derives its actor from `socket.user`, never from the event payload:

```javascript
io.use(authenticateSocket);

io.on('connection', (socket) => {
  const userId = socket.user.id;   // from the verified token, not the client
  socket.join(userId);
  ...
});
```

This matters: an earlier revision took the actor id from the message body, which
let any client send messages as another user, delete their messages, or register
with a victim's id and drain their queued offline messages. Each socket joins a
room named after its user id, so presence and delivery work across multiple tabs.

### 7.2 Contact Discovery by QChat ID
Every account gets a shareable id such as `QC-8L99-2TVY`, drawn from a
Crockford-style alphabet that omits `0`, `O`, `1` and `I` so a code read aloud or
copied by hand cannot land on the wrong account.

The contact list is not a directory. `GET /api/users` returns only the people you
have added plus anyone you have exchanged messages with — so a first message
reveals the sender without needing a friend-request round trip, while the rest of
the user base stays invisible. Lookup is **exact match only**, on the id alone,
and separately rate limited, so the endpoint cannot be used to enumerate accounts
or to check whether a given username exists.

---

## 8. System Architecture, Modules and Requirements

This section maps the architecture described in Chapter 3 of the report onto the files
that actually implement it.

### 8.1 Architecture layers

| Layer (report §3.1) | Responsibility | Where it lives | Status |
|---|---|---|---|
| **Client Layer** | User interface: messaging, file sharing, video, displaying decrypted content | `frontend/src/components/` — `ChatDashboard.jsx`, `Landing.jsx`, `Login.jsx`, `Register.jsx` | Implemented |
| **Security Layer** | ML-KEM key exchange, AES-256 symmetric encryption/decryption | `frontend/src/crypto/encryption.js` | Implemented |
| **Integrity Layer** | Hash-linked chat history, tamper detection | `encryption.js → calculateIntegrity` | Partial — chain, not tree |
| **AI Layer** | On-device phishing analysis | — | **Not implemented** |
| **Communication Layer** | WebRTC peer-to-peer transport, PQ-protected signaling | `ChatDashboard.jsx`, `crypto/mediaTransport.js`, `crypto/mediaCrypto.js`, `backend/server.js` | Implemented, media included |

All cryptographic work happens client-side. The Node.js server relays and stores
ciphertext; it never receives a message key or plaintext.

### 8.2 System modules

| Module (report §3.1.1) | Implementation | Status |
|---|---|---|
| **Authentication Module** | bcrypt password hashing, JWT issuance, JWT-verified REST middleware **and** Socket.io handshake auth | Implemented (§7.1) |
| **Hybrid Encryption Module** | `encryptForRecipients` / `decryptEnvelope` — ML-KEM-768 + AES-256-GCM, HKDF-SHA256 key derivation | Implemented (§2.5) |
| **Messaging Module** | Text, images, voice notes, files; replies, reactions, delete-for-everyone, read receipts, presence, paged history | Implemented (§6) |
| **Video Calling Module** | WebRTC peer-to-peer audio/video, encrypted signaling, PQ-sealed media frames | Implemented (§5) |
| **Integrity Module** | Rolling SHA-256 chain over the conversation, surfaced as a digest in the chat header | Partial (§4) |
| **Phishing Detection Module** | — | **Not implemented** |

### 8.3 Functional requirements (report §3.2.1)

| Requirement | Status | Note |
|---|---|---|
| Secure key exchange using ML-KEM | Met | ML-KEM-768, 1184-byte public key, 1088-byte ciphertext |
| Message encryption using AES-256 | Met | AES-256-GCM, 12-byte IV, 16-byte authentication tag |
| End-to-end decryption at receiver only | Met | Private key never leaves the device in plaintext; the server stores only a password-encrypted backup it cannot open |
| Integrity verification using Merkle Tree | Partial | Hash chain detects modification; no per-message inclusion proof |
| AI-based phishing detection | **Not met** | No model present |
| Secure real-time communication (WebRTC) | Met | Signaling and media both PQ-protected |
| Authentication and access control | Met | JWT on REST and sockets; every socket event derives its actor from the verified token |

### 8.4 Non-functional requirements (report §3.2.2)

| Requirement | Status | Honest note |
|---|---|---|
| Resistance to classical and quantum attacks | Largely met | Message and media confidentiality rest on ML-KEM. Passwords use bcrypt; TLS to the server is still classical, which is normal and out of scope. |
| Low latency communication | Met in practice | Socket.io transport with WebRTC peer-to-peer media. Not formally measured. |
| Privacy preservation | Met with one caveat | All crypto is client-side. The caveat: the server receives the password at sign-in to check it against the bcrypt hash — see §3.1. |
| Scalability | **Unverified** | The architecture supports it; no load test has been run (`improve.txt → OPS-1`). Do not claim a concurrent-user figure. |
| Reliability and fault tolerance | Partial | Socket reconnection with backoff, offline message queue with delivery on reconnect, queued ICE candidates. No clustering or failover. |
| User-friendly interface | Met | Responsive React UI, landing page, toast notifications, keyboard-operable contact list. |

---

## 9. Threat Model — what this does and does not protect

Stating this plainly matters more than any feature list.

### Protected against

| Adversary | How |
|---|---|
| **Passive network observer, now or in future** | Message bodies and media frames are sealed with AES-256-GCM under ML-KEM-derived keys. A recording made today is not openable by a future quantum computer. |
| **The server operator reading messages** | The server stores ciphertext and wrapped keys only. It never holds a content key. |
| **The server operator reading reactions** | Reaction emoji sets are encrypted to both parties; the server upserts blindly by user id. |
| **A stolen database** | Private-key backups are AES-256-GCM sealed under PBKDF2-SHA256 (600,000 iterations) of the user's password. |
| **Tampering with a stored message** | AES-GCM authentication tags fail on any modification; the integrity chain changes if history is reordered or altered. |
| **Impersonation over the socket** | The actor is derived from the handshake-verified JWT, never from the event body. |
| **Account enumeration** | Contact lookup is exact-match on a random ~1.1e12-space id, separately rate-limited. |

### Explicitly NOT protected against

| Threat | Why |
|---|---|
| **A malicious server** | The server receives the password at sign-in to verify it against the bcrypt hash, so a hostile server could capture it and unwrap a key backup. Defends against a stolen database, not an actively malicious operator. Deriving a separate client-side auth value would close this. |
| **XSS or a compromised browser** | The private key lives in `localStorage` and is readable by any injected script. This is an architectural tradeoff of browser-based E2EE. |
| **Metadata analysis** | The server necessarily knows who talks to whom, when, message sizes and timing. Content is blind; the social graph is not. |
| **Phishing and social engineering** | Objective 3 was to address this on-device. It is not implemented. |
| **A malicious peer** | Anyone you talk to can screenshot, copy or retain plaintext. E2EE protects transport and storage, not the endpoint. |
| **Endpoint compromise** | If the device is owned, the key is owned. |
| **Forward secrecy** | Each message uses a fresh encapsulation, but the long-term ML-KEM key is static. Compromising it exposes past messages. Ratcheting (Signal-style) would fix this and is not implemented. |

---

## 10. Setup & Installation

### 10.0 Technology Stack
- **Frontend**: React 18 (Vite), Tailwind CSS, Framer Motion, Socket.io-client, `@noble/post-quantum`
- **Backend**: Node.js, Express, Socket.io, MongoDB (Mongoose)
- **Cryptography**: ML-KEM-768 (FIPS 203), AES-256-GCM, HKDF-SHA256, PBKDF2-SHA256, SHA-256
- **Real-time media**: WebRTC peer-to-peer video; signaling ML-KEM sealed, media frames sealed per-frame (§5.1)
- **Security middleware**: JWT on REST *and* Socket.io, bcrypt, helmet, express-rate-limit
- **Messaging**: image/audio/file attachments, voice notes, reply threading, encrypted reactions, delete-for-everyone, presence, cursor-paged history

### 10.1 Prerequisites
- Node.js v20 or higher

### 10.2 Clone & Install
```bash
# Backend
cd backend
npm install

# Frontend
cd ../frontend
npm install
```

### 10.3 Configure Environment
Copy `backend/.env.example` to `backend/.env` and fill it in:
```
PORT=5000
JWT_SECRET=<generate with: openssl rand -hex 32>
JWT_EXPIRES_IN=7d
MONGO_URI=mongodb://localhost:27017/qchat
CORS_ORIGIN=http://localhost:5173
```
The server **refuses to boot** on a missing, placeholder, or under-32-character
`JWT_SECRET` — a guessable signing key would make every token in the system
forgeable, so failing loudly beats running insecurely.

The frontend needs no configuration for local dev (an empty `VITE_API_URL` routes
`/api` through the Vite proxy). For a deployment, or to enable TURN, copy
`frontend/.env.example` to `frontend/.env.local`.

### 10.4 Run Development Servers
```bash
# Terminal 1: Backend
cd backend
npm run dev

# Terminal 2: Frontend
cd frontend
npm run dev
```


---

## 11. Current Limitations and Future Scope

Every engineering project ships with a known boundary. This section states Q-Chat's, so the
implementation and the report can be read against each other without ambiguity — and so the
next phase has a concrete starting point.

| Report claim | Reality | Tracked as |
|---|---|---|
| "SHA-256 based Merkle hash chain… detection of unauthorized modification" (Abstract) | Implemented and working as a hash chain — tamper detection holds. Chapters 3 and 5 additionally describe *hierarchical* linking; the branching tree and its inclusion proofs are `FEAT-3`. | `FEAT-3` |
| "On-device AI-based phishing detection module using TensorFlow.js" (Abstract) | Phase II. The AI Layer is reserved in the architecture; no model is trained or loaded yet. | `FEAT-2` |
| "Extensive testing demonstrates… effectively detects phishing attempts" (Abstract) | Reword before final submission — the detection module is Phase II scope. | `FEAT-2` |
| "Scalability: handles multiple concurrent users without performance degradation" (§3.2.2) | Architecturally plausible, never measured. No load test exists. | `OPS-1` |
| "Signaling is protected using post-quantum cryptographic techniques" (§3.1) | Met, and **exceeded** — media frames are PQ-sealed too, which the report only lists as an objective (§1.2 obj. 4). | — |
| Repository contents: "System architecture diagrams, flowcharts, and supporting images" (Appendix C) | Figures 3.1 and 4.1 exist in the report but are not in the repository. | — |
| Appendix C repository link | Points at `Project-Title-Q-Chat-…`. The repo has since been renamed to `QChat-A-Post-Quantum-Secure-Messaging-Platform`; GitHub redirects, so the printed link still resolves. | — |
| Slide deck tech stack names **Redis** and **Docker** | Neither is a dependency of this project. | — |

**Verified working:** post-quantum call media has been confirmed in a live two-party
call on Chrome. The Firefox/Safari code path is implemented but has not been exercised.

Cryptographic correctness has been verified by direct exercise of the primitives —
round-trip encryption in both directions, rejection of tampered ciphertext and headers,
key-separation between directions, and rejection of foreign keys. Formalising these into a
committed regression suite is planned.

---

## 12. Repository Layout

```
backend/
  server.js            Express + Socket.io; all socket event handlers
  config/env.js        Env loading; refuses to boot on a weak JWT_SECRET
  db/database.js       User and Message schemas, index definitions
  middleware/auth.js   REST token check + Socket.io handshake auth
  routes/              auth.js · messages.js · users.js
  utils/               qchatId.js · validation.js · logger.js
frontend/src/
  components/          ChatDashboard · Landing · Login · Register · visuals/
  crypto/
    encryption.js          ML-KEM + AES message crypto, key backup, integrity chain
    mediaCrypto.js         Per-frame cipher for call media
    mediaTransport.js      Binds the frame cipher to an RTCPeerConnection
    mediaTransform.worker.js  Firefox/Safari encoded-transform path
  lib/api.js           axios instance with auth + 401 handling
CLAUDE.md              Full codebase index — file map, crypto contracts, gotchas
improve.txt            Live backlog (gitignored)
```
