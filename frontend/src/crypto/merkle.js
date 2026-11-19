/**
 * Merkle tree over a conversation — RFC 6962 (Certificate Transparency) style.
 *
 *   leaf hash   = SHA-256(0x00 ‖ record)
 *   node hash   = SHA-256(0x01 ‖ left ‖ right)
 *   empty tree  = SHA-256("")
 *
 * The 0x00 / 0x01 prefixes are domain separation: without them an internal
 * node (64 bytes of child hashes) could be passed off as a leaf whose record
 * happens to be those 64 bytes — a second-preimage attack on the tree.
 *
 * An odd node at the end of a level is promoted unchanged, never paired with a
 * copy of itself. Bitcoin's tree duplicated it, so [a, b, c] and [a, b, c, c]
 * had the same root (CVE-2012-2459). This construction is exactly RFC 6962's
 * "split at the largest power of two smaller than n".
 *
 * Everything here runs in both the browser and Node (WebCrypto), so the same
 * file is exercised by `npm test`.
 */

const enc = new TextEncoder();
export const LEAF_VERSION = 'qchat.leaf.v1';

export const toHex = (bytes) => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
export const fromHex = (hex) => Uint8Array.from(hex.match(/../g) || [], h => parseInt(h, 16));

async function sha256(...parts) {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { buf.set(p, o); o += p.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
}

const LEAF = Uint8Array.of(0x00);
const NODE = Uint8Array.of(0x01);

export const hashLeaf = (data) => sha256(LEAF, data);
export const hashNode = (left, right) => sha256(NODE, left, right);

/* ─── What a leaf commits to ───
   A message's leaf is built only from values both participants — and the
   server — hold identically, and none of it needs the plaintext:

     record = JSON[ "qchat.leaf.v1", sender id, message id, ISO timestamp,
                    SHA-256(canonical JSON of the encrypted payload) | "deleted" ]

   Because it is over ciphertext, the server can compute and serve every leaf,
   so the tree covers the whole conversation rather than the page on screen,
   while each device still recomputes the leaves of the messages it holds.
   The timestamp is in the leaf on purpose: AES-GCM authenticates the payload
   but not the time the server says it was sent, and only the tree notices if
   that is rewritten. backend/utils/merkleLeaf.js mirrors this byte for byte. */

/** JSON with object keys sorted, so the same object always encodes the same way. */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  return `{${Object.keys(value).sort()
    .filter(k => value[k] !== undefined)
    .map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
    .join(',')}}`;
}

export function leafRecord({ fromId, id, timestamp, payloadDigest, deleted }) {
  return JSON.stringify([
    LEAF_VERSION,
    String(fromId),
    String(id),
    new Date(timestamp).toISOString(),
    deleted ? 'deleted' : payloadDigest,
  ]);
}

/** Leaf hash (hex) for a message as the client holds it. */
export async function leafForMessage({ fromId, id, timestamp, payload, deleted }) {
  const payloadDigest = deleted ? null : toHex(await sha256(enc.encode(canonicalJson(payload ?? null))));
  return toHex(await hashLeaf(enc.encode(leafRecord({ fromId, id, timestamp, payloadDigest, deleted }))));
}

/** Canonical leaf order: oldest first, ties broken by id. Matches the server. */
export function sortEntries(entries) {
  return [...entries].sort((a, b) => {
    const ta = new Date(a.timestamp).getTime();
    const tb = new Date(b.timestamp).getTime();
    if (ta !== tb) return ta - tb;
    return String(a.id) < String(b.id) ? -1 : String(a.id) > String(b.id) ? 1 : 0;
  });
}

/* ─── The tree ─── */

/**
 * Build every level, bottom (leaves) to top (root). Keeping the levels makes
 * inclusion proofs a lookup and lets the UI draw the path.
 * `leaves` are hex leaf hashes, in canonical order.
 */
export async function buildTree(leaves) {
  if (leaves.length === 0) {
    return { size: 0, levels: [[]], root: toHex(await sha256()) };
  }
  const levels = [leaves.map(fromHex)];
  while (levels[levels.length - 1].length > 1) {
    const below = levels[levels.length - 1];
    const above = [];
    for (let i = 0; i < below.length; i += 2) {
      above.push(i + 1 < below.length ? await hashNode(below[i], below[i + 1]) : below[i]);
    }
    levels.push(above);
  }
  return { size: leaves.length, levels, root: toHex(levels[levels.length - 1][0]) };
}

export async function merkleRoot(leaves) {
  return (await buildTree(leaves)).root;
}

/**
 * Audit path for leaf `index`: the sibling hash at each level, bottom up, and
 * which side it sits on. A promoted odd node has no sibling at that level, so
 * the path is at most ⌈log2 n⌉ hashes — 10 for a thousand messages.
 */
export function inclusionProof(tree, index) {
  if (index < 0 || index >= tree.size) throw new RangeError('leaf index out of range');
  const path = [];
  let i = index;
  for (let level = 0; level < tree.levels.length - 1; level++) {
    const row = tree.levels[level];
    if (i % 2 === 1) path.push({ side: 'left', hash: toHex(row[i - 1]) });
    else if (i + 1 < row.length) path.push({ side: 'right', hash: toHex(row[i + 1]) });
    i = Math.floor(i / 2);
  }
  return path;
}

/**
 * Check an audit path the way RFC 9162 §2.1.3.2 specifies. It takes only the
 * leaf, its index, the tree size and the sibling hashes — no `side` hints — so
 * it is an independent check on whoever produced the proof.
 */
export async function verifyInclusion({ leaf, index, size, path, root }) {
  if (index < 0 || index >= size) return false;
  let fn = index;
  let sn = size - 1;
  let r = fromHex(leaf);
  for (const step of path) {
    const p = fromHex(typeof step === 'string' ? step : step.hash);
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      r = await hashNode(p, r);
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
      }
    } else {
      r = await hashNode(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && toHex(r) === root;
}

/* ─── Checkpoints ───
   Each device remembers the leaves it last verified. Re-opening the chat
   compares the server's current history against that memory, and because each
   message is its own leaf, a difference names the message instead of only
   saying "something changed". */

/**
 * Compare a saved checkpoint (old entries) with the current history.
 * Returns { status, findings, appended, prefixRoot }:
 *   status: 'first' | 'ok' | 'benign' | 'tampered'
 *   findings: [{ kind: 'modified' | 'removed' | 'inserted' | 'deleted', id, index, timestamp }]
 */
export async function compareWithCheckpoint(checkpoint, current) {
  if (!checkpoint || !Array.isArray(checkpoint.entries) || checkpoint.entries.length === 0) {
    return { status: 'first', findings: [], appended: current.length };
  }

  const old = checkpoint.entries;
  const now = new Map(current.map((e, i) => [String(e.id), { ...e, index: i }]));
  const oldIds = new Set(old.map(e => String(e.id)));
  const findings = [];

  old.forEach((e, index) => {
    const cur = now.get(String(e.id));
    if (!cur) {
      findings.push({ kind: 'removed', id: e.id, index, timestamp: e.timestamp });
    } else if (cur.leaf !== e.leaf) {
      // A delete by the sender is expected to change the leaf. Anything else
      // — text, sender or timestamp — is a modification of verified history.
      findings.push({ kind: cur.deleted && !e.deleted ? 'deleted' : 'modified', id: e.id, index, timestamp: cur.timestamp });
    }
  });

  // A message that wasn't there before but sorts *inside* the verified range
  // was slipped into the past. One that sorts after it is simply new.
  const lastOld = new Date(old[old.length - 1].timestamp).getTime();
  let appended = 0;
  current.forEach((e, index) => {
    if (oldIds.has(String(e.id))) return;
    if (new Date(e.timestamp).getTime() <= lastOld) {
      findings.push({ kind: 'inserted', id: e.id, index, timestamp: e.timestamp });
    } else {
      appended++;
    }
  });

  const prefixRoot = await merkleRoot(current.slice(0, old.length).map(e => e.leaf));
  const serious = findings.some(f => f.kind !== 'deleted');
  const status = serious ? 'tampered' : findings.length ? 'benign' : 'ok';
  return { status, findings, appended, prefixRoot, checkpointRoot: checkpoint.root };
}
