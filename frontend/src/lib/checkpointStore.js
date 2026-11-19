/**
 * Per-device memory of the transcript leaves this browser last verified, one
 * record per conversation. IndexedDB rather than localStorage: a long chat is
 * tens of kilobytes of hashes, and localStorage is a few megabytes shared by
 * everything. If IndexedDB is unavailable (private mode, blocked storage) the
 * tree still works — it just has nothing to compare against next time.
 */
const DB = 'qchat';
const STORE = 'transcripts';
const memory = new Map();

let dbPromise = null;
function open() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    try {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    } catch (err) {
      reject(err);
    }
  }).catch(() => null);
  return dbPromise;
}

async function run(mode, fn) {
  const db = await open();
  if (!db) return undefined;
  return new Promise((resolve) => {
    try {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => resolve(undefined);
    } catch {
      resolve(undefined);
    }
  });
}

export const checkpointKey = (me, peer) => `${me}:${peer}`;

export async function loadCheckpoint(key) {
  const stored = await run('readonly', s => s.get(key));
  return stored ?? memory.get(key) ?? null;
}

export async function saveCheckpoint(key, checkpoint) {
  memory.set(key, checkpoint);
  await run('readwrite', s => s.put(checkpoint, key));
}

export async function clearCheckpoint(key) {
  memory.delete(key);
  await run('readwrite', s => s.delete(key));
}
