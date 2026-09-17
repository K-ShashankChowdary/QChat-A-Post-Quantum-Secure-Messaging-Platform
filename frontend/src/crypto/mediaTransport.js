/**
 * Wires the frame cipher into a live RTCPeerConnection.
 *
 * Two incompatible browser APIs do the same job, so both are supported:
 *   - Chrome/Edge: sender.createEncodedStreams(), piped on the main thread.
 *   - Firefox/Safari: RTCRtpScriptTransform, which only delivers frames to a
 *     worker, so one is spun up for them.
 * Anything else gets no second layer, and the caller is told so plainly rather
 * than being left to assume the media is protected when it is not.
 */
import { deriveMediaKeys, makeTransform, mediaTransformSupport } from './mediaCrypto';

export { mediaTransformSupport };

/** Chrome needs this flag at construction time; it cannot be turned on later. */
export function withEncodedTransforms(rtcConfig) {
  return mediaTransformSupport() === 'encoded-streams'
    ? { ...rtcConfig, encodedInsertableStreams: true }
    : rtcConfig;
}

function makeWorker() {
  return new Worker(new URL('./mediaTransform.worker.js', import.meta.url), { type: 'module' });
}

/**
 * Create the per-call media crypto context.
 * `masterSecret` is 32 random bytes that travelled inside the ML-KEM-sealed
 * offer, so it is already post-quantum protected in transit.
 */
export async function createMediaCrypto({ masterSecret, isInitiator, onError, onFirst }) {
  const support = mediaTransformSupport();
  if (support === 'none') return { support, applyToSender: () => {}, applyToReceiver: () => {}, close: () => {} };

  let worker = null;
  let keys = null;
  // Which directions actually got a transform wired. The caller uses this
  // rather than API presence, so the UI can never claim media is sealed when
  // attachment failed and the frames are going out in the clear.
  const attached = { encrypt: false, decrypt: false };

  if (support === 'script-transform') {
    worker = makeWorker();
    worker.onmessage = (e) => {
      if (e.data?.type === 'media-crypto-error') onError?.(e.data);
      if (e.data?.type === 'media-crypto-first') onFirst?.(e.data);
    };
  } else {
    keys = await deriveMediaKeys(masterSecret, isInitiator);
  }

  const attach = (rtpObject, mode) => {
    try {
      if (support === 'script-transform') {
        rtpObject.transform = new RTCRtpScriptTransform(worker, {
          mode,
          // Uint8Array is structured-cloneable; the key never leaves the client.
          masterSecret,
          isInitiator,
        });
        return;
      }

      const streams = rtpObject.createEncodedStreams();
      const key = mode === 'encrypt' ? keys.encryptKey : keys.decryptKey;
      streams.readable
        .pipeThrough(makeTransform(key, mode, onError, onFirst))
        .pipeTo(streams.writable)
        .catch(() => { /* call ended; the pipe closing here is expected */ });
      attached[mode] = true;
    } catch (err) {
      onError?.({ mode, message: err?.message || 'could not attach transform' });
    }
  };

  return {
    support,
    attached,
    applyToSender: (sender) => attach(sender, 'encrypt'),
    applyToReceiver: (receiver) => attach(receiver, 'decrypt'),
    close: () => worker?.terminate(),
  };
}
