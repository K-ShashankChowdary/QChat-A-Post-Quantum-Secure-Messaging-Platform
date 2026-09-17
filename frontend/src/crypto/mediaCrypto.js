/**
 * Post-quantum protected media for WebRTC calls.
 *
 * WebRTC already encrypts media with DTLS-SRTP, but that handshake is ECDHE —
 * classical, and therefore harvestable now and breakable by a quantum computer
 * later. The same "harvest now, decrypt later" problem the messages solve.
 *
 * So we add a second layer *inside* the transport: every encoded frame is
 * sealed with AES-256-GCM under a key that reached the other party through
 * ML-KEM-768. SRTP still wraps it on the wire; a recording of that traffic is
 * now useless without the lattice key, which is the point.
 *
 * Frame layout on the wire:
 *
 *   [ header: h bytes, plaintext ][ AES-GCM ciphertext+tag ][ IV: 12 ][ h: 1 ]
 *
 * The leading header stays readable because the packetizer and any relay need
 * the codec metadata to fragment and forward the frame. Encrypting it produces
 * a stream nothing can transport. h is written into the trailer so the receiver
 * never has to guess a codec-specific value.
 */

const IV_BYTES = 12;
const KDF_INFO = 'QChat/v1/media-frame';

/**
 * Unencrypted prefix, by frame kind. These cover the codec headers that must
 * stay in the clear (VP8/VP9 payload descriptors, Opus TOC byte).
 */
function headerBytesFor(frame) {
  // `frame.type` is undefined on audio frames and 'key'/'delta' on video, so it
  // identifies the kind without touching RTCEncodedAudioFrame — which is not a
  // global in every context, and referencing a missing one throws a
  // ReferenceError that would silently drop every frame.
  if (frame.type === 'key') return 10;
  if (frame.type === 'delta') return 3;
  return 1;
}

/**
 * Derive one AES key per direction. Both sides hold the same master secret, so
 * separate keys keep the two directions in separate IV spaces — a random 96-bit
 * IV makes collision negligible anyway, but there is no reason to share a space
 * when splitting it is one extra HKDF call.
 */
export async function deriveMediaKeys(masterSecret, isInitiator) {
  const base = await crypto.subtle.importKey('raw', masterSecret, 'HKDF', false, ['deriveKey']);
  const enc = new TextEncoder();

  const mk = async (label, usage) => crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: enc.encode(`${KDF_INFO}/${label}`),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );

  // The caller writes on the "a" key and reads the "b" key; the callee mirrors.
  return {
    encryptKey: await mk(isInitiator ? 'a' : 'b', 'encrypt'),
    decryptKey: await mk(isInitiator ? 'b' : 'a', 'decrypt'),
  };
}

/** Seal one encoded frame in place. */
export async function encryptFrame(frame, key) {
  const data = new Uint8Array(frame.data);
  const h = Math.min(headerBytesFor(frame), data.length);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));

  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: data.subarray(0, h) },
    key,
    data.subarray(h),
  ));

  const out = new Uint8Array(h + sealed.length + IV_BYTES + 1);
  out.set(data.subarray(0, h), 0);
  out.set(sealed, h);
  out.set(iv, h + sealed.length);
  out[out.length - 1] = h;

  frame.data = out.buffer;
  return frame;
}

/** Open one encoded frame in place. Throws if the frame was tampered with. */
export async function decryptFrame(frame, key) {
  const data = new Uint8Array(frame.data);
  if (data.length < IV_BYTES + 2) throw new Error('SHORT_FRAME');

  const h = data[data.length - 1];
  const ivStart = data.length - 1 - IV_BYTES;
  if (h > ivStart) throw new Error('BAD_FRAME_HEADER');

  const iv = data.subarray(ivStart, ivStart + IV_BYTES);

  const opened = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: data.subarray(0, h) },
    key,
    data.subarray(h, ivStart),
  ));

  const out = new Uint8Array(h + opened.length);
  out.set(data.subarray(0, h), 0);
  out.set(opened, h);

  frame.data = out.buffer;
  return frame;
}

/**
 * A frame that fails to open is dropped, not passed through. Passing it would
 * hand the decoder ciphertext and produce a corrupt picture that looks like a
 * network fault rather than a security one. Dropping shows a freeze, which is
 * the honest signal.
 */
export function makeTransform(key, mode, onError, onFirst) {
  let failures = 0;
  let seen = 0;
  return new TransformStream({
    async transform(frame, controller) {
      try {
        controller.enqueue(mode === 'encrypt'
          ? await encryptFrame(frame, key)
          : await decryptFrame(frame, key));
        // One line per direction, so the log proves the pipeline ran rather
        // than only proving it was attached.
        if (++seen === 1) onFirst?.({ mode });
        failures = 0;
      } catch (err) {
        // Report sparsely: a key mismatch fails on every frame, and reporting
        // at 30fps would bury everything else in the log.
        failures++;
        if (failures === 1 || failures % 150 === 0) {
          onError?.({ mode, failures, message: err?.message || 'frame failed' });
        }
      }
    },
  });
}

/** Which Encoded Transform API this browser offers, if any. */
export function mediaTransformSupport() {
  if (typeof window === 'undefined') return 'none';
  // createEncodedStreams is checked FIRST on purpose. Chrome supports both
  // APIs, and the script-transform path needs a worker module to load before
  // any frame moves — one more thing to fail, with no upside here. The
  // main-thread path has no such step, so it is the default wherever it exists
  // and RTCRtpScriptTransform is the fallback for Firefox and Safari.
  if (typeof RTCRtpSender !== 'undefined'
      && typeof RTCRtpSender.prototype.createEncodedStreams === 'function') return 'encoded-streams';
  if (typeof window.RTCRtpScriptTransform === 'function') return 'script-transform';
  return 'none';
}
