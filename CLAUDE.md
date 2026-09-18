# QChat — codebase index

Post-quantum secure messaging platform. Final-year major project (SIT, B.E. AI&DS).
Repo: `K-ShashankChowdary/QChat-A-Post-Quantum-Secure-Messaging-Platform`.

**Stack.** React 18.3 + Vite 5.3 + Tailwind 3.4 + framer-motion 11 · Express 4.19 +
Socket.io 4.7 + Mongoose 8.4 · `@noble/post-quantum` 0.6.1 (`ml_kem768`) + WebCrypto
(AES-GCM, HKDF, PBKDF2, SHA-256) · bcrypt, jsonwebtoken, helmet, express-rate-limit, morgan.
ESM throughout (`"type": "module"` both sides). Node 20+.

~2,900 lines of own source. `ChatDashboard.jsx` alone is ~2,100 of them.

---

## 1. Objectives vs. reality

| # | Synopsis objective | Status |
|---|---|---|
| 1 | Hybrid ML-KEM + AES-256 for messages and key exchange | **done** |
| 2 | Merkle tree so chat records are tamper-proof | **partial** — linear SHA-256 hash chain, not a branching tree (`FEAT-3`) |
| 3 | On-device AI phishing detection, no server exposure | **not started** (`FEAT-2`) |
| 4 | WebRTC video with PQ protection on signalling **and** media | **done** (`7e71230`), verified Chrome↔Chrome |

Objectives 2 and 3 were explicitly parked. Say this plainly rather than letting the
README's phrasing imply otherwise.

---

## 2. File map

### Backend (`backend/`, ~800 lines)
| File | Role |
|---|---|
| `server.js` (318) | Express + Socket.io wiring. **Every socket handler lives here.** |
| `config/env.js` (38) | Env loading. Hard-fails on bad `JWT_SECRET`. |
| `db/database.js` (95) | `User` + `Message` schemas, `backfillQChatIds`. |
| `middleware/auth.js` (41) | `authenticateToken` (REST), `authenticateSocket` (handshake). |
| `routes/auth.js` (139) | register · login · key-backup · update-key. |
| `routes/messages.js` (116) | history (cursor paged) · clear conversation. |
| `routes/users.js` (155) | `/me` · `/lookup` · contact list · add/remove contact. |
| `utils/qchatId.js` (46) | `QC-XXXX-XXXX` generate / normalise / allocate. |
| `utils/validation.js` (66) | Username, password, public key, key-backup shape. |
| `utils/logger.js` (48) | Structured console logger with contexts. |
| `scripts/delete-user.js` (49) | Deletes an account + its messages + contact refs. |

### Frontend (`frontend/src/`, ~2,100 lines)
| File | Role |
|---|---|
| `components/ChatDashboard.jsx` (2108) | Sockets, WebRTC, history paging, all chat state and render. |
| `components/Landing.jsx` (399) | Explainer page: threat model, pipeline, spec table, server-knowledge split. |
| `components/Login.jsx` (178) | **Key recovery lives here** — three branches (§5). |
| `components/Register.jsx` (178) | Keygen + wrap + register. |
| `crypto/encryption.js` (407) | v1, v2, key backup, key identity, integrity chain, b64 helpers. |
| `crypto/mediaCrypto.js` (160) | Per-frame cipher for call media. |
| `crypto/mediaTransport.js` (83) | Wires the frame cipher into an `RTCPeerConnection`. |
| `crypto/mediaTransform.worker.js` (31) | Firefox/Safari path. **Never actually executed.** |
| `lib/api.js` (42) | axios instance; 401 → clear session + redirect (skipped on auth pages). |
| `components/visuals/Toast.jsx` (151) | `ToastProvider` / `useToast()` → `{success, error, info, confirm}`. |
| `components/visuals/LatticeField.jsx` (187) | Animated lattice canvas, used as backdrop everywhere. |
| `App.jsx` | Routes: `/` Landing · `/login` · `/register` · `/chat` (PrivateRoute) · `*` → `/`. |

---

## 3. Data model

```js
User {
  username        // unique
  password_hash   // bcrypt, cost 10
  public_key      // base64, decodes to exactly 1184 bytes
  qchat_id        // "QC-XXXX-XXXX", unique + sparse + indexed
  key_backup      // Object — AES-GCM ciphertext of the ML-KEM secret key. Opaque to the server.
  contacts        // [ObjectId] — explicitly added
  hidden_contacts // [{ user, hidden_at }] — see §7
  created_at, last_seen, is_online
}

Message {
  from_user_id, to_user_id   // both indexed
  payload         // v2 envelope (or v1)
  sender_payload  // v1 only; null on every v2 message
  timestamp       // indexed
  delivered, read, deleted
  reply_to_id     // ObjectId | null
  type            // 'text' | 'image' | 'audio' | 'file'
  reactions       // [{ user_id, emoji?, payload? }] — see §6
}
messageSchema.index({ from_user_id: 1, to_user_id: 1, timestamp: -1 })
```

That compound index is what makes the `$or` conversation query (`A→B OR B→A`) sorted by
time not degrade into a collection scan.

---

## 4. Message crypto

ML-KEM-768 (`k=3`, ring `R_q = Z_q[X]/(X^256+1)`, `q = 3329`). Byte sizes, all load-bearing:

| Thing | Bytes |
|---|---|
| Public key (`ek`) | 1184 |
| Secret key (`dk`) | 2400 |
| KEM ciphertext | 1088 |
| Shared secret | 32 |
| AES-GCM IV | 12 |
| AES-GCM tag | 16 |
| HKDF salt | 16 |
| CEK | 32 |

### Payload v2 — current
Content encrypted **once** under a random 32-byte CEK. Only the CEK is ML-KEM-wrapped,
once per recipient. Wrap key = `HKDF-SHA256(sharedSecret, salt=random 16B, info="QChat/v2/cek-wrap")`.

```js
{
  v: 2,
  keys: { "<userId>": { encapsulatedKey, salt, nonce, ciphertext, authTag } },
  nonce, ciphertext, authTag,     // the body, sealed exactly once
  timestamp
}
```

`encryptForRecipients(text, recipients)` where `recipients = [{ id, publicKey: Uint8Array }]` —
normally the peer **and yourself**, which is how you read your own history without a second copy.

`decryptEnvelope(payload, myUserId, myPrivateKey)`:
- `payload.v !== 2` → falls through to `decryptMessage` (v1). This is the whole migration story.
- no `keys[myUserId]` → throws `NO_KEY_FOR_RECIPIENT`.

### Payload v1 — legacy, still readable
Encrypted the body twice, once per party (`payload` + `sender_payload`), and used a bare
`SHA-256(sharedSecret)` as the AES key. **A hash is not a KDF** — that's the v1→v2 argument
in one line. Measured v2 gain on a ~700KB body: 1.83MB → 0.91MB stored, **49.9%**.

### Why a KEM at all
KEM encapsulation produces a shared secret, not a ciphertext of your choosing. You cannot
encrypt a message *with* ML-KEM; you use it to agree a symmetric key and let AES do the work.
That is what "hybrid" means here — and it is also why the KDF step matters: everything
downstream depends on turning a 32-byte KEM output into a proper key.

### Integrity chain (`calculateIntegrity`)
```
H_0 = 32 zero bytes
H_n = SHA-256( H_{n-1} ‖ text_n ‖ timestamp_n ‖ direction_n )
```
`direction` is `'out'`/`'in'`, folded in so a message cannot be silently reattributed to the
other party. Displayed as the first 16 base64 chars in the chat header.

**This is a hash chain, not a Merkle tree.** It detects that *something* changed; it cannot
prove *which* message is intact without replaying the whole chain, and it has no branching
structure or inclusion proofs. Know the difference cold — it is objective 2.

---

## 5. Key management

The private key is wrapped with AES-256-GCM under
`PBKDF2-SHA256(password, random 16B salt, 600,000 iterations)` (OWASP guidance), and the
ciphertext is stored server-side in `User.key_backup`. **The keypair belongs to the user, not
the browser.**

`Login.jsx` has exactly three branches:
1. **`data.keyBackup` exists** → `unwrapPrivateKey(backup, password)` recovers the account key.
   This is the normal path and the reason multi-device works.
2. **No backup, but a local key** → wrap it and `POST /api/auth/key-backup`. Self-healing
   migration for accounts created before backups existed.
3. **Neither** → `toast.confirm` warns that a new key permanently orphans old messages.
   Cancel aborts cleanly and clears the half-made session.

`unwrapPrivateKey` throws `WRONG_PASSWORD` on any failure — because a failed GCM tag *is*
what a wrong password looks like. Note the subtle case handled in `Login.jsx`: if login
itself succeeded then the password is right, so a `WRONG_PASSWORD` from the unwrap means the
**blob is corrupt**, and the error message says so.

### Key identity
FIPS 203 encodes the decapsulation key as `dk = dk_PKE ‖ ek ‖ H(ek) ‖ z`, so `ek` sits at
bytes **1152..2336** of the 2400-byte secret key. `publicKeyFromSecretKey` slices it out.
That lets the client answer "is the key on this device the one the account advertises?" —
the difference between *"these messages are lost"* and *"you are on the wrong device."*
`keyFingerprint` renders the first 8 bytes of SHA-256 as `06E3 E4D4 F3A2 09D9`.

### The honest limitation (in the code comments, and worth stating in the report)
The server still receives the password at sign-in to check it against the bcrypt hash. So
the backup defends against a **stolen database** — the realistic threat — **not a malicious
server**. Deriving a separate client-side auth value so the raw password never leaves the
browser is the named next step. Also: the private key lives in `localStorage`, readable by
any injected script. That is an architectural tradeoff of browser E2EE, not a bug.

---

## 6. Encrypted reactions

One row per reacting user, holding that user's **entire emoji set**, encrypted to both
participants. The server does a blind upsert/delete keyed on `user_id`.

The consequence people miss: the server **cannot toggle** a reaction, because it cannot
compare an emoji it cannot read. So the toggle is computed client-side and the complete new
set is sent. The server broadcasts the authoritative array and clients **replace** rather
than append — that is what stops your own reaction counting twice (optimistic + echo).

Pre-v2 plaintext reactions (`emoji` field) still render.

---

## 7. Server, transport, access control

- **Handshake auth.** `io.use(authenticateSocket)` verifies the JWT during the Socket.io
  handshake. Every handler derives its actor from `socket.user.id`; **no event carries an
  actor id.** An earlier revision took it from the message body — meaning any client could
  send as another user, delete their messages, or drain their offline queue.
- **Presence via rooms.** Each socket joins a room named after its user id. Several tabs are
  one online user; `isUserOnline` reads the room size. On `disconnect`, rooms are already
  left, so the check reflects the user's *other* tabs.
- **Offline queue.** `deliverPendingMessages` flushes `delivered: false` messages on connect,
  then notifies each original sender via `message_delivered`.
- **`maxHttpBufferSize` = 12MB.** Socket.io's 1MB default silently killed the connection on
  attachments — measured: a 900KB image was 3.13MB on the wire under v1's double encryption.
  Transport ceiling and enforced per-message ceiling are kept in sync.
- **Rate limits.** `/api/auth/*` 20 req / 15 min / IP. `/api/users/lookup` 30 req / min — its
  own tighter budget because it is the one endpoint that reveals whether an account exists.
- **Contact discovery.** `QC-XXXX-XXXX`, Crockford alphabet (no `0`/`O`/`1`/`I`), ~1.1e12
  space. Lookup is **exact match only** — no partial, no fuzzy — so it cannot walk the user
  list. `normalizeQChatId` requires either the `QC` prefix or the dashed 4-4 shape, because a
  bare run of 8 letters is indistinguishable from a username.
- **Contact list** = explicit contacts ∪ anyone messaged − `hidden_contacts`. A removal
  records a timestamp; the person reappears only if they send something **newer** than it.
  Without this, removing someone you had history with silently un-removed them on reload.
- **History paging.** Timestamp cursor (`before=`), 50/page, max 100. Offset paging is kept
  only as a fallback because it skews when live messages arrive mid-scroll and skips a page.
  The client holds scroll position across the prepend by shifting `scrollTop` by exactly the
  height the prepended block added.
- **Deletes are soft.** Server clears `payload`/`sender_payload`, sets `deleted: true`.
  Ownership is enforced *in the query* (`{ _id, from_user_id: userId }`), not after the fetch.
- **Boot guard.** `config/env.js` refuses to start on a missing, placeholder or <32-char
  `JWT_SECRET`. Note `backend/.env.example` ships `change-me-to-a-long-random-secret`, which
  is itself on the rejected list — copying the example verbatim fails loudly by design.

---

## 8. WebRTC and post-quantum media (objective 4)

**Signalling** — SDP offers/answers and every ICE candidate go through `encryptForRecipients`
before touching the relay. The server sees an opaque blob and relays by room.

**Media** — WebRTC's own DTLS-SRTP negotiates keys with **ECDHE**, which is classical, so a
recording made today is breakable later. Same harvest-now-decrypt-later problem the messages
solve. So a second cipher runs *inside* the transport.

- Caller mints a random 32-byte secret and puts it in the **offer**, which is already sealed
  to the peer's ML-KEM public key. No new key exchange, no new attack surface.
- Each side derives **two** AES keys by HKDF (`info: "QChat/v1/media-frame/a"` and `/b`), one
  per direction, so the directions never share an IV space. Caller writes `a`, reads `b`.
- Secret is zeroed (`.fill(0)`) and the worker terminated on hangup.

Frame layout:
```
[ clear header 1/3/10B ][ AES-GCM ciphertext+tag ][ IV 12B ][ header length 1B ]
```
- Header sizes: video key frame 10, video delta 3, audio 1. Identified by `frame.type`
  (`'key'`/`'delta'`/undefined) — **not** `instanceof RTCEncodedAudioFrame`, which is not a
  global in every context and would throw, silently dropping every frame.
- The clear header must stay readable: the packetizer needs it to fragment the frame, and
  encrypting it yields a stream nothing can transport. It is passed as GCM `additionalData`,
  so tampering with it still fails the tag.
- Header length rides in the trailer so the receiver never guesses a codec-specific value.
- A frame that fails to open is **dropped, not passed through** — handing ciphertext to the
  decoder produces a corrupt picture that looks like a network fault rather than a security
  one. Dropping shows a freeze, which is the honest signal.

**VP8 is pinned** on the video transceiver via `setCodecPreferences`. The offsets above are
VP8-shaped; H.264 carries Annex-B NAL start codes throughout the payload, so sealing past the
first bytes leaves the packetizer splitting inside ciphertext and the far end decodes a smear.
macOS Chrome picks H.264 for hardware encoding, so it must be forced, not hoped for.

**Browser paths.** `createEncodedStreams` (main thread) is checked **first**; Chrome supports
both APIs and the `RTCRtpScriptTransform` path needs a worker module to load before any frame
moves — one more failure mode, no upside. That flag also gates
`encodedInsertableStreams: true` on the `RTCPeerConnection` constructor, which cannot be set
later. No API at all → the call proceeds on DTLS-SRTP and **says so**, in the log and as an
amber badge.

The in-call badge turns green only once a frame has been **opened on the receive side**.
API presence proves nothing about whether the peer can read what was sent — an earlier
version went green on presence alone and lied for two whole test calls.

---

## 9. Frontend architecture notes

- `currentUser` and `privateKey` are read from `localStorage` **on every render** and must
  stay `useMemo`'d. An unmemoised `privateKey` is a fresh `Uint8Array` each render; any effect
  listing it as a dependency re-fires forever. This froze the app once.
- Socket handlers bind once in a `[]`-dep effect, so anything they touch during teardown must
  live in a **ref**, not state — `localStreamRef` exists because `cleanupCall` closed over a
  `null` stream and left the camera on after a remote hangup.
- `isRealId(id)` — optimistic bubbles carry `l-<ts>-<rand>` until the server acks with
  `message_sent`. Delete, react and reply all require a real id. A temp id in `reply_to_id`
  used to fail the ObjectId cast and drop the entire message with no visible error.
- Attachments travel as a versioned JSON envelope `{__tag: 'qchat.attachment.v1', name, mime,
  data}` so filename and mime survive the encryption round trip. Bare data URLs (pre-envelope)
  still render via a fallback.
- `renderRows` flattens messages into render rows, inserting day separators and **collapsing
  runs of undecryptable messages into one line** — twenty red bubbles read as twenty failures
  when it is one fact stated once.
- `keyStatus` compares this device's derived fingerprint against the server's and reports
  `ok` / `mismatch` / `missing` / `invalid`.
- Toast system replaces all `alert()`/`confirm()`. `toast.confirm` is promise-based; Escape
  cancels, Enter confirms.

---

## 10. Documentation state

The README, `improve.txt` and `PLAN.md` were reconciled against the code in Sep 2026.
What changed, so you know what to expect if you remember the old text:

- **README §3.1** was "Active Key Assertion" — it documented the *superseded* design where
  whichever device signed in last overwrote the account's published key. That was `SEC-8`,
  the bug that orphaned history. Rewritten as "Portable Account Keys", covering the three
  sign-in branches and stating the password-reaches-the-server limitation openly.
- **README §5.1 is new** — post-quantum media. The README previously described only encrypted
  *signalling*, which understated objective 4.
- **README §4** retitled: "Integrity Hash Chain (Merkle tree: planned, not yet built)". The
  old title claimed a structure the code does not implement.
- **README §2.2 / §5 / §6** snippets corrected to match the code: key storage is by user id,
  signalling uses `encryptForRecipients` (v2) and room-based relay with no client `fromId`,
  and the double-encryption claim is gone (v2 ended it).
- **`improve.txt`** — OPS-1's premise and OPS-4's description both still claimed every message
  is encrypted twice; corrected. FEAT-1 extended to record the media work.
- **`PLAN.md`** — carries a SUPERSEDED banner. It is a pre-Phase-II snapshot; plan from
  `CLAUDE.md` and `improve.txt` instead.

**Still worth knowing:** the slide deck (`Major_Project_Presentation.pptx`) names **Redis and
Docker** in its tech stack; neither appears in any dependency list. The README never did, so
this is a slides-only correction. There are also **no tests committed** anywhere in the repo —
the 13 media-cipher tests were run ad hoc, so do not cite them as repo-verifiable.

## 11. Gotchas that already cost real time

- **Vite does not re-read `tailwind.config.js`** without a restart. Never `@apply` a
  config-defined utility; declare custom animations as plain CSS with their own `@keyframes`.
- **A `const` shadowing a function parameter** inside the same block puts every earlier read
  of that parameter in the TDZ. This silently broke reaction persistence for the project's
  entire life (`a7bed11`) — the handler threw on its first line, the `catch` logged a generic
  message, and the optimistic UI hid it until reload.
- **Hook dependency arrays are evaluated during render**, so any `const` named in one must be
  declared *above* the hook. Declaring it below blanked the whole chat screen.
- **framer-motion writes `transform` inline**, silently overriding a CSS `-translate-x-1/2`.
  Centre such elements with a flex wrapper instead.
- **A flex `gap` is a floor, not a suggestion.** `gap-3` on the message column made every
  per-row grouping margin meaningless.
- **`position: sticky` inside a `min-h-full justify-end` column** can pin anywhere in the tall
  empty box. Sticky day separators need one sticky element per day group.
- **A positioned `z-0` sibling paints over an unpositioned one.** The protocol console
  vanished behind the backdrop until it got `relative z-10`.
- **Canvas backing stores do not follow layout.** `LatticeField` needed a `ResizeObserver`;
  a window-resize listener only suffices for a viewport-sized element.
- **esbuild parses JSX that renders wrong.** It will not catch a destroyed `return`, a
  self-referencing variable, or mismatched nesting. Check div balance separately.

---

## 12. Open backlog (`improve.txt`)

- **OPS-1** — load-test the WebSocket handshake. Open. Its premise still claims every message
  is encrypted twice; v2 fixed that, so rewrite the ticket before measuring anything.
- **OPS-3** — TURN relay. ICE config is env-driven (`VITE_TURN_*`) but no relay is
  provisioned, so **calls only work on a single LAN**. Do this before demoing.
- **OPS-4** — attachments are base64, inline in the `Message` document. Blob storage with a
  reference + key material in the payload would roughly halve storage and bandwidth.
- **FEAT-2** — on-device AI phishing detection. Objective 3. No code exists.
- **FEAT-3** — true branching Merkle tree. Objective 2. The hash chain is the foundation.

---

## 13. Conventions

- Commits: `type(scope): subject`, blank line, then a body explaining **why**, not what.
  Author is Shashank; no AI attribution trailers.
- `backend/.env` is gitignored and must stay so.
- No `alert()` / `window.confirm()` anywhere — use the toast system.
- Never `git push --force` without `--with-lease`, and never amend a commit that is already
  pushed unless the tree is identical.
