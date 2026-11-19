import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import api from '../lib/api';
import {
  buildTree, inclusionProof, verifyInclusion, merkleRoot, leafForMessage,
  sortEntries, compareWithCheckpoint,
} from '../crypto/merkle';
import { checkpointKey, loadCheckpoint, saveCheckpoint, clearCheckpoint } from '../lib/checkpointStore';

const isServerId = (id) => !!id && !String(id).startsWith('l-');
const LEAF_CACHE_LIMIT = 5000;

/** Root over the first `size` messages of a conversation, straight from the server's leaves. */
export async function fetchTranscriptRoot(peerId, size) {
  const { data } = await api.get(`/api/messages/${peerId}/leaves`);
  const entries = sortEntries(data.leaves || []);
  const n = Math.min(size ?? entries.length, entries.length);
  return { size: n, root: await merkleRoot(entries.slice(0, n).map(e => e.leaf)) };
}

/**
 * The Merkle tree for the open conversation.
 *
 *  1. Fetch every leaf from the server (32 bytes a message), so the tree spans
 *     the whole history rather than the page on screen.
 *  2. Recompute, on this device, the leaf of every message actually loaded. If
 *     the server's list disagrees with a message it served, that is reported.
 *  3. Compare the result with the checkpoint this browser saved last time; a
 *     difference names the message — modified, removed, back-dated or deleted.
 *  4. Save a new checkpoint while nothing is wrong. While something is, keep
 *     the old one, so the warning survives a reload until it is acknowledged.
 */
export function useTranscriptTree({ myId, peerId, messages }) {
  const [server, setServer]   = useState({ peerId: null, entries: null, error: false });
  const [local, setLocal]     = useState(() => new Map());
  const [tree, setTree]       = useState(null);
  const [verdict, setVerdict] = useState(null);
  const [reloadKey, setReloadKey] = useState(0);
  const leafCache   = useRef(new Map());
  const verdictFor  = useRef(null);
  // While the caller is swapping in a freshly fetched history, no verdict is
  // reached and nothing is checkpointed — otherwise a half-updated view (new
  // server leaves, old messages) could be judged, or worse, saved.
  const suspended   = useRef(false);
  const key = myId && peerId ? checkpointKey(myId, peerId) : null;

  // 1. The server's leaves, per conversation.
  useEffect(() => {
    setServer({ peerId, entries: null, error: false });
    setLocal(new Map());
    setTree(null);
    setVerdict(null);
    verdictFor.current = null;
    leafCache.current.clear();
    if (!peerId) return undefined;

    let cancelled = false;
    api.get(`/api/messages/${peerId}/leaves`)
      .then(({ data }) => {
        if (cancelled) return;
        setServer({
          peerId,
          error: false,
          entries: (data.leaves || []).map(e => ({ ...e, id: String(e.id), fromId: String(e.fromId) })),
        });
      })
      .catch(() => { if (!cancelled) setServer({ peerId, entries: [], error: true }); });
    return () => { cancelled = true; };
  }, [peerId, reloadKey]);

  // 2. This device's own leaves for what it holds. Keyed so reactions and read
  //    receipts — which aren't part of a leaf — don't trigger a recompute.
  const messagesKey = useMemo(() => messages
    .filter(m => isServerId(m.id) && m.fromId && (m.payload || m.deleted))
    .map(m => `${m.id}:${m.deleted ? 1 : 0}:${new Date(m.timestamp).getTime()}`)
    .join('|'), [messages]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const next = new Map();
      for (const m of messages) {
        if (!isServerId(m.id) || !m.fromId || (!m.payload && !m.deleted)) continue;
        const cacheKey = `${m.id}:${m.deleted ? 1 : 0}:${new Date(m.timestamp).getTime()}`;
        let leaf = leafCache.current.get(cacheKey);
        if (!leaf) {
          leaf = await leafForMessage({
            fromId: m.fromId, id: m.id, timestamp: m.timestamp, payload: m.payload, deleted: m.deleted,
          });
          if (leafCache.current.size > LEAF_CACHE_LIMIT) leafCache.current.clear();
          leafCache.current.set(cacheKey, leaf);
        }
        next.set(String(m.id), {
          id: String(m.id), fromId: String(m.fromId), timestamp: m.timestamp, deleted: !!m.deleted, leaf,
        });
      }
      if (!cancelled) setLocal(next);
    })();
    return () => { cancelled = true; };
    // messagesKey is the distillation of `messages` that a leaf depends on.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [messagesKey, reloadKey]);

  // The server's list, with every leaf this device computed itself taking its
  // place — what the tree commits to is what this device actually received.
  const entries = useMemo(() => {
    if (server.peerId !== peerId || !server.entries) return null;
    const byId = new Map(server.entries.map(e => [e.id, e]));
    for (const [id, e] of local) byId.set(id, e);
    return sortEntries([...byId.values()]);
  }, [server, local, peerId]);

  // A message the server served whose leaf doesn't match the server's own list.
  const mismatches = useMemo(() => {
    if (!server.entries) return [];
    const listed = new Map(server.entries.map(e => [e.id, e]));
    const out = [];
    for (const [id, e] of local) {
      const s = listed.get(id);
      if (!s?.leaf) continue;
      if (e.deleted && !s.deleted) continue;     // deleted after the list was fetched
      if (s.leaf !== e.leaf) out.push({ kind: 'served', id, timestamp: e.timestamp });
    }
    return out;
  }, [server, local]);

  useEffect(() => {
    if (!entries) { setTree(null); return undefined; }
    let cancelled = false;
    buildTree(entries.map(e => e.leaf)).then(t => { if (!cancelled) setTree(t); });
    return () => { cancelled = true; };
  }, [entries]);

  // 3. Once per opened conversation: against the last checkpoint.
  useEffect(() => {
    if (!entries || !key || server.error || suspended.current || verdictFor.current === peerId) return;
    verdictFor.current = peerId;
    (async () => {
      const checkpoint = await loadCheckpoint(key);
      const result = await compareWithCheckpoint(checkpoint, entries);
      setVerdict({ ...result, peerId, checkedAt: Date.now(), checkpointAt: checkpoint?.savedAt || null });
    })();
  }, [entries, key, peerId, server.error]);

  // 4. Remember what was verified, while nothing is wrong.
  const persist = useCallback(async () => {
    if (!key || !entries || !tree || tree.size !== entries.length) return;
    await saveCheckpoint(key, {
      entries: entries.map(e => ({
        id: e.id, leaf: e.leaf, deleted: !!e.deleted, timestamp: new Date(e.timestamp).toISOString(),
      })),
      root: tree.root,
      size: tree.size,
      savedAt: Date.now(),
    });
  }, [key, entries, tree]);

  useEffect(() => {
    if (suspended.current || !verdict || verdict.peerId !== peerId || verdict.status === 'tampered' || mismatches.length) return undefined;
    const t = setTimeout(persist, 600);
    return () => clearTimeout(t);
  }, [persist, verdict, mismatches, peerId]);

  /** The user has seen the warning and accepts the history as it now stands. */
  const acceptCurrent = useCallback(async () => {
    await persist();
    setVerdict(v => (v ? { ...v, status: 'ok', findings: [], accepted: true } : v));
  }, [persist]);

  /** Stop judging until reload(): call before replacing the loaded history. */
  const suspend = useCallback(() => {
    suspended.current = true;
    verdictFor.current = null;
    setVerdict(null);
  }, []);

  /** Re-fetch every leaf and re-verify against the checkpoint, which is kept. */
  const reload = useCallback(() => {
    suspended.current = false;
    setReloadKey(k => k + 1);
  }, []);

  /** Forget this conversation's checkpoint — used when the chat is cleared. */
  const reset = useCallback(async () => {
    if (key) await clearCheckpoint(key);
    suspended.current = false;
    setReloadKey(k => k + 1);
  }, [key]);

  /** A message's position in the tree (0-based), or -1. */
  const indexOf = useCallback(
    (id) => (entries ? entries.findIndex(e => e.id === String(id)) : -1),
    [entries],
  );

  const proofFor = useCallback(async (id) => {
    if (!tree || !entries || tree.size !== entries.length) return null;
    const index = entries.findIndex(e => e.id === String(id));
    if (index < 0) return null;
    const path = inclusionProof(tree, index);
    const leaf = entries[index].leaf;
    const verified = await verifyInclusion({ leaf, index, size: tree.size, path, root: tree.root });
    return { index, size: tree.size, leaf, path, root: tree.root, verified };
  }, [tree, entries]);

  const rootAt = useCallback(async (size) => {
    if (!entries) return null;
    const n = Math.min(size ?? entries.length, entries.length);
    return { size: n, root: await merkleRoot(entries.slice(0, n).map(e => e.leaf)) };
  }, [entries]);

  const ready = !!(tree && entries && verdict && tree.size === entries.length);
  const status = !peerId ? null
    : server.error ? 'unavailable'
    : !ready ? 'checking'
    : mismatches.length ? 'tampered'
    : verdict.status;

  return {
    status,
    root: tree?.root || null,
    size: tree?.size || 0,
    findings: [...mismatches, ...(verdict?.findings || [])],
    appended: verdict?.appended || 0,
    checkpointAt: verdict?.checkpointAt || null,
    ready,
    acceptCurrent,
    reset,
    suspend,
    reload,
    indexOf,
    proofFor,
    rootAt,
  };
}
