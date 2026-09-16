# QChat: Post-Quantum Secure Messaging & Cryptographic Whitepaper

QChat is a next-generation End-to-End Encrypted (E2EE) messaging platform built to resist the "Harvest Now, Decrypt Later" threat of quantum computing. It implements a Zero-Knowledge backend architecture and a highly optimized Hybrid Cryptographic strategy.

## 🛠 Technology Stack
- **Frontend**: React (Vite), Socket.io-client, `@noble/post-quantum`, Framer Motion.
- **Backend**: Node.js, Express, Socket.io, MongoDB (Mongoose).
- **Cryptography**: ML-KEM-768, AES-256-GCM, SHA-256.
- **Real-Time Media**: WebRTC peer-to-peer video calling, with signaling encrypted per-message via ML-KEM/AES-256-GCM.
- **Messaging Features**: image/audio/file attachments, voice notes, reply threading, emoji reactions, delete-for-everyone, online/last-seen presence, paged history.
- **Identity & Access**: JWT-authenticated REST *and* Socket.io layers, contact discovery by shareable QChat ID, rate limiting, helmet.

---

## 🏗 Setup & Installation

### Prerequisites
- Node.js v20 or higher

### 1. Clone & Install
```bash
# Backend
cd backend
npm install

# Frontend
cd ../frontend
npm install
```

### 2. Configure Environment
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

### 3. Run Development Servers
```bash
# Terminal 1: Backend
cd backend
npm run dev

# Terminal 2: Frontend
cd frontend
npm run dev
```

---

## 2. In-Depth Cryptographic Pipeline (The Core)

QChat employs a completely local, client-side, **Hybrid Encryption Strategy** combining Lattice Math and Symmetric Advanced Encryption Standards. The Node.js server sees absolutely zero plaintext.

### 2.1 The Theory & Algorithms of ML-KEM-768
Traditional RSA/ECC math relies on Integer Factorization, which is solved easily by Shor's Algorithm on quantum hardware. ML-KEM operates differently: it constructs a hyper-dimensional lattice problem over a polynomial ring $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ with modulus $q = 3329$. Because it's mathematically chaotic to find "short vectors" in this multi-dimensional lattice space (The Module Learning With Errors problem), it is completely immune to quantum hardware. We use **ML-KEM-768** ($k=3$), perfectly balancing security and speed.

#### Core Formulas:
1. **Key Generation:**
   - Generate random square matrix $A \in R_q^{3 \times 3}$.
   - Generate small secret vector $s \in R_q^3$ and error vector $e \in R_q^3$.
   - **Public Key Formula:** $t = A s + e$
   - *Public Key = $(A, t)$, Secret Key = $(s)$.*

2. **Encapsulation (Sender generates ciphertext $c$ and Shared Secret $SS$ for Recipient):**
   - Generate error vectors $e_1 \in R_q^3, e_2 \in R_q$.
   - Compute polynomial $u = A^T r + e_1$.
   - Compute scalar polynomial $v = t^T r + e_2 + \text{Encode}(SS)$.
   - *Ciphertext $c = (u, v)$ is sent across the wire.*

3. **Decapsulation (Recipient unlocks $SS$):**
   - Recipient applies their Secret Key $(s)$.
   - $v - s^T u = (t^T r + e_2 + \text{Encode}(SS)) - s^T(A^T r + e_1) \approx \text{Encode}(SS)$.
   - The microscopic errors successfully cancel out, decoding back to the exact $SS$.

### 2.2 Code Implementation: Keypair Generation & Vaulting
*File: `frontend/src/components/Register.jsx`*
When a user registers or logs into a new device, the browser triggers generation directly in RAM:

```javascript
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

// 1. Generate Lattices
const keys = ml_kem768.keygen();

// 2. Vault Private Key strictly in local storage
const b64Priv = b64encode(keys.secretKey); 
localStorage.setItem(`qchat_priv_${username}`, b64Priv);

// 3. Transmit 1184-byte Public Key to Server
const b64Pub = b64encode(keys.publicKey);
await axios.post('/api/auth/register', { username, password, publicKey: b64Pub });
```
**Storage Specifications:** 
*   **Public Key:** Exactly **1184 bytes**. Stored in MongoDB.
*   **Private/Secret Key:** Exactly **2400 bytes**. Stored exclusively in local `localStorage`. **It never touches a network request.**

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

## 3. Real-Time Network & Synchronization Logic

### 3.1 Active Key Assertion (Resolving the multi-device E2E Flaw)
*File: `frontend/src/components/Login.jsx`*

In traditional E2E architectures, moving from Desktop to Laptop permanently breaks encryption workflows if the backend doesn't know you switched matrices. 
QChat solves this definitively. When you click Login, the browser forcefully assesses local storage. If a valid Post-Quantum keypair exists, it physically forces the backend to obey the active device:

```javascript
// Active Key Assertion Protocol check
const existingPub = localStorage.getItem(`qchat_pub_${data.user.username}`);

if (existingPub) {
  // Sync the backend DB to THIS exact browser tab
  await axios.post('/api/auth/update-key', 
    { userId: data.user.id, publicKey: existingPub },
    { headers: { Authorization: `Bearer ${data.token}` } }
  );
}
```

### 3.2 MongoDB Optimization Matrix
*File: `backend/db/database.js`*

Fetching real-time chat blocks is inherently heavy because it probes massive intersection paths: `(from A to B) OR (from B to A)`. Without structural intervention, querying 100,000 messages triggers $O(N)$ CPU sweeps. We resolve this precisely using MongoDB compound Multi-Key schemas:

```javascript
const messageSchema = new mongoose.Schema({
  from_user_id:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  to_user_id:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  payload:        { type: Object, required: true }, 
  timestamp:      { type: Date, default: Date.now, index: true },
  delivered:      { type: Boolean, default: false }
});

// Explicit Native Compound Indexer for $or acceleration
messageSchema.index({ from_user_id: 1, to_user_id: 1, timestamp: -1 });
```

---

## 4. Merkle-Tree Integrity Hash Chain
*File: `frontend/src/crypto/encryption.js -> calculateIntegrity`*

To prevent the Zero-Knowledge backend from arbitrarily destroying chat sequences or executing selective-deletion assaults, QChat implements a block-synchronization hash string mathematically mirroring blockchain technology.

#### Hash Formalism
$H_n = \text{SHA256}_{digest}(H_{n-1} + \text{Text}_n + \text{Timestamp}_n + \text{Direction}_n)$

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
If a database administrator shifts the `timestamp` or `payload` of arbitrary Message number 5, the microscopic data corruption heavily magnifies the ensuing hash derivatives across `combined.set(currentHash)`, instantly voiding the UI integrity string mapping at Message 50.


## 5. Secure Real-Time Communication (WebRTC Video Calling)
*File: `frontend/src/components/ChatDashboard.jsx`*

QChat extends its hybrid encryption model to peer-to-peer video calling. WebRTC handles the actual audio/video transport, but every piece of *signaling* — SDP offers, answers, and ICE candidates — is individually wrapped through the same `encryptMessage`/`decryptMessage` pipeline used for chat messages before it ever touches the Socket.io relay:

```javascript
const encryptAndSendSignal = async (signalData, toId) => {
  const recipientPubKey = b64decode(peerRef.current.public_key);
  const payload = await encryptMessage(JSON.stringify(signalData), recipientPubKey);
  socketRef.current?.emit('webrtc_signal', { toId, fromId: currentUser.id, signalPayload: payload });
};
```

The signaling server (`backend/server.js`) only ever relays an opaque encrypted blob between two socket IDs — it never sees an SDP offer, an ICE candidate, or the resulting media stream in plaintext:

```javascript
socket.on('webrtc_signal', ({ toId, fromId, signalPayload }) => {
  const toSocket = onlineUsers.get(String(toId));
  if (toSocket) io.to(toSocket).emit('webrtc_signal', { fromId, signalPayload });
});
```

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

## 6. Messaging Features (Attachments, Replies, Reactions, Delete, Presence)

Beyond text, QChat's chat surface supports the messaging primitives users expect from a modern app — all still routed through the same end-to-end encryption pipeline as plain text:

- **Attachments** — images, voice notes, and files are read client-side as base64 (`FileReader`/`MediaRecorder`), then encrypted exactly like a text message (`encryptMessage(base64Data, recipientPublicKey)`). Capped at 2MB client-side for the MVP.
- **Reply threading** — replies carry a `reply_to_id` pointing at the original message; the UI renders an inline quote and scrolls to the original on click.
- **Emoji reactions** — reactions are pushed to the `Message.reactions` array and synced live over `message_reaction` socket events to both sender and recipient.
- **Delete for everyone** — deleting a message is a soft delete: the server clears `payload`/`sender_payload` and sets `deleted: true`; clients render a tombstone rather than removing the message outright.
- **Presence** — `User.is_online` and `User.last_seen` are updated on socket connect/disconnect and broadcast via `user_status`, driving the online dot and "Last seen …" text in the UI.

Reactions toggle per (message, user, emoji): the server holds the authoritative
array and clients replace rather than append, so a reaction can't be double
counted by the sender's own echo.

History is paged at 50 messages. Scrolling to the top loads the previous page
using a **timestamp cursor** rather than an offset — an offset shifts when live
messages arrive mid-scroll, which silently skips a page — and the scroll position
is preserved across the prepend.

> **Known limitation:** attachments are base64-encoded, encrypted twice (once for
> each party) and stored inline in the message document rather than in dedicated
> blob storage. Tracked in `improve.txt` → `OPS-4`.

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
