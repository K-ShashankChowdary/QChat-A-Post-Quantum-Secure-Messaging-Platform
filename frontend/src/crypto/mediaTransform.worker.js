/**
 * Worker half of the media transform, for browsers that expose
 * RTCRtpScriptTransform (Firefox, Safari). Chrome takes the main-thread
 * createEncodedStreams path instead and never loads this file.
 *
 * The transform must run here rather than on the main thread because
 * RTCRtpScriptTransform only delivers frames to a worker.
 */
import { deriveMediaKeys, makeTransform } from './mediaCrypto';

let keysPromise = null;
// Mirrors the main-thread control object: the page posts 'passthrough' when the
// peer can't seal frames.
const control = { sealed: true };
self.onmessage = (e) => {
  if (e.data?.type === 'passthrough') control.sealed = false;
};

/** Keys are derived once per worker and shared by every track it handles. */
function keysFor(masterSecret, isInitiator) {
  if (!keysPromise) keysPromise = deriveMediaKeys(new Uint8Array(masterSecret), isInitiator);
  return keysPromise;
}

self.onrtctransform = async (event) => {
  const { transformer } = event;
  const { mode, masterSecret, isInitiator } = transformer.options || {};
  if (!masterSecret) return;

  const { encryptKey, decryptKey } = await keysFor(masterSecret, isInitiator);
  const key = mode === 'encrypt' ? encryptKey : decryptKey;

  transformer.readable
    .pipeThrough(makeTransform(
      key,
      mode,
      (info) => self.postMessage({ type: 'media-crypto-error', ...info }),
      // Without this the page never learns a frame opened, and the call badge
      // sat on "Negotiating…" for the whole call on Firefox and Safari.
      (info) => self.postMessage({ type: 'media-crypto-first', ...info }),
      control,
    ))
    .pipeTo(transformer.writable)
    .catch(() => { /* the call ended and the pipe closed; nothing to recover */ });
};
