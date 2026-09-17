import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

// Generates ML-KEM-768 keys and returns public/private Uint8Arrays
export async function generateKeyPair() {
  try {
    const keys = ml_kem768.keygen();
    return {
      publicKey: keys.publicKey,
      privateKey: keys.secretKey
    };
  } catch (error) {
    console.error('Key generation failed:', error);
    throw new Error('KEYGEN_FAILED');
  }
}

// Hashes the shared secret and imports it as a raw 256-bit AES-GCM key
async function deriveAESKey(sharedSecret) {
  try {
    const hash = await crypto.subtle.digest('SHA-256', sharedSecret);
    return await crypto.subtle.importKey(
      'raw',
      hash,
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt']
    );
  } catch (error) {
    console.error('Failed to derive AES key:', error);
    throw new Error('KEY_DERIVATION_FAILED');
  }
}

// Wraps a message in ML-KEM + AES-256-GCM hybrid encryption
export async function encryptMessage(text, recipientPublicKey) {
  if (!text) throw new Error('EMPTY_MESSAGE');
  if (!recipientPublicKey || recipientPublicKey.byteLength !== 1184) {
    throw new Error(`INVALID_PUBLIC_KEY: expected 1184 bytes, got ${recipientPublicKey?.byteLength}`);
  }

  try {
    // Encapsulate against recipient public key to generate the shared secret
    const { sharedSecret, cipherText: encapsulatedKey } = ml_kem768.encapsulate(recipientPublicKey);

    // Swap the shared secret for an AES key
    const aesKey = await deriveAESKey(sharedSecret);

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(text);

    // Encrypt the payload
    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      encodedData
    );

    // AES-GCM appends a 16-byte auth tag at the end of the ciphertext buffer. Need to split them.
    const encryptedArray = new Uint8Array(encryptedBuffer);
    const ciphertext = encryptedArray.slice(0, -16);
    const authTag = encryptedArray.slice(-16);

    return {
      encapsulatedKey: b64encode(encapsulatedKey),
      nonce: b64encode(iv),
      ciphertext: b64encode(ciphertext),
      authTag: b64encode(authTag),
      timestamp: Date.now()
    };
  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error('ENCRYPTION_FAILED');
  }
}

// Decrypts payload by decapsulating the shared secret and unwrapping the AES cipher
export async function decryptMessage(payload, myPrivateKey) {
  if (!payload || !payload.encapsulatedKey || !payload.nonce || !payload.ciphertext || !payload.authTag) {
    throw new Error('INVALID_PAYLOAD_STRUCTURE');
  }

  try {
    const encapKey = b64decode(payload.encapsulatedKey);
    const iv = b64decode(payload.nonce);
    const ciphertext = b64decode(payload.ciphertext);
    const authTag = b64decode(payload.authTag);

    // Decapsulate the shared secret using our private key
    const sharedSecret = ml_kem768.decapsulate(encapKey, myPrivateKey);

    // Rebuild the AES key
    const aesKey = await deriveAESKey(sharedSecret);

    // WebCrypto AES-GCM expects the ciphertext and auth tag to be a single concatenated buffer
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext);
    combined.set(authTag, ciphertext.length);

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      combined
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('DECRYPTION_FAILED');
  }
}

/* ─────────────────────────────────────────────────────────────────────────
   Payload v2

   Two changes over v1, both version-tagged so existing messages keep working:

   1. HKDF-SHA256 with a random salt and context string replaces the bare
      SHA-256(sharedSecret) used as an AES key. A hash is not a KDF: HKDF is the
      standard construction, binds the key to a context, and is what a reviewer
      expects next to a NIST-standardised KEM.

   2. The content is encrypted ONCE under a random content-encryption key (CEK),
      and only that 32-byte CEK is wrapped to each party via ML-KEM. v1 encrypted
      the whole message twice (once per party), which doubled both the lattice
      work and the stored bytes — painful for a 2MB attachment.
   ───────────────────────────────────────────────────────────────────────── */

export const PAYLOAD_VERSION = 2;
const KDF_INFO_WRAP = 'QChat/v2/cek-wrap';
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const CEK_BYTES = 32;

/** HKDF-SHA256 -> AES-256-GCM key. */
async function deriveWrapKey(sharedSecret, salt, usages) {
  const base = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode(KDF_INFO_WRAP) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}

/** WebCrypto wants ciphertext and tag contiguous; we store them apart. */
function joinCipherAndTag(ciphertextB64, authTagB64) {
  const ct = b64decode(ciphertextB64);
  const tag = b64decode(authTagB64);
  const joined = new Uint8Array(ct.length + tag.length);
  joined.set(ct);
  joined.set(tag, ct.length);
  return joined;
}

function splitCipherAndTag(buffer) {
  const arr = new Uint8Array(buffer);
  return {
    ciphertext: b64encode(arr.slice(0, -TAG_BYTES)),
    authTag: b64encode(arr.slice(-TAG_BYTES)),
  };
}

/**
 * Encrypt once, wrap the key for everyone who should be able to read it.
 * `recipients` is [{ id, publicKey: Uint8Array }] — normally the peer and
 * yourself, so you can still read your own history.
 */
export async function encryptForRecipients(text, recipients) {
  if (typeof text !== 'string' || text.length === 0) throw new Error('EMPTY_MESSAGE');
  if (!Array.isArray(recipients) || recipients.length === 0) throw new Error('NO_RECIPIENTS');

  try {
    const cek = crypto.getRandomValues(new Uint8Array(CEK_BYTES));
    const contentKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const sealed = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      contentKey,
      new TextEncoder().encode(text)
    );

    const keys = {};
    for (const recipient of recipients) {
      const pub = recipient?.publicKey;
      if (!pub || pub.byteLength !== 1184) {
        throw new Error(`INVALID_PUBLIC_KEY: expected 1184 bytes, got ${pub?.byteLength}`);
      }

      const { sharedSecret, cipherText: encapsulatedKey } = ml_kem768.encapsulate(pub);
      const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
      const wrapKey = await deriveWrapKey(sharedSecret, salt, ['encrypt']);
      const wrapIv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
      const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: wrapIv }, wrapKey, cek);

      keys[String(recipient.id)] = {
        encapsulatedKey: b64encode(encapsulatedKey),
        salt: b64encode(salt),
        nonce: b64encode(wrapIv),
        ...splitCipherAndTag(wrapped),
      };
    }

    return {
      v: PAYLOAD_VERSION,
      keys,
      nonce: b64encode(iv),
      ...splitCipherAndTag(sealed),
      timestamp: Date.now(),
    };
  } catch (error) {
    if (String(error.message).startsWith('INVALID_PUBLIC_KEY')) throw error;
    console.error('Encryption failed:', error);
    throw new Error('ENCRYPTION_FAILED');
  }
}

/**
 * Decrypt either format. v2 unwraps the CEK addressed to `myUserId`; anything
 * else falls back to the v1 path so old messages keep opening.
 */
export async function decryptEnvelope(payload, myUserId, myPrivateKey) {
  if (payload?.v !== PAYLOAD_VERSION) return decryptMessage(payload, myPrivateKey);

  const wrapped = payload.keys?.[String(myUserId)];
  if (!wrapped) throw new Error('NO_KEY_FOR_RECIPIENT');

  try {
    const sharedSecret = ml_kem768.decapsulate(b64decode(wrapped.encapsulatedKey), myPrivateKey);
    const wrapKey = await deriveWrapKey(sharedSecret, b64decode(wrapped.salt), ['decrypt']);
    const cek = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64decode(wrapped.nonce) },
      wrapKey,
      joinCipherAndTag(wrapped.ciphertext, wrapped.authTag)
    );

    const contentKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['decrypt']);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64decode(payload.nonce) },
      contentKey,
      joinCipherAndTag(payload.ciphertext, payload.authTag)
    );

    return new TextDecoder().decode(plain);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('DECRYPTION_FAILED');
  }
}

/* ─── Password-wrapped key backup ───
   The private key must never leave the device in the clear, but a key that
   exists in exactly one browser is one cleared-site-data away from orphaning
   every message ever sent to it. So we store an ENCRYPTED copy server-side:
   PBKDF2 stretches the password into an AES-256-GCM key, and only the resulting
   ciphertext is uploaded. The server holds a blob it cannot open.

   Honest limit: the server also receives the password at sign-in to check it
   against the bcrypt hash, so this defends against a stolen database — the
   realistic threat — not against a malicious server. Deriving a separate
   client-side auth value so the raw password never leaves the browser would
   close that gap, and is the natural next step. */

export const KEY_BACKUP_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;   // OWASP guidance for PBKDF2-HMAC-SHA256
const BACKUP_SALT_BYTES = 16;

async function deriveBackupKey(password, salt, iterations, usages) {
  const base = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}

/** Encrypt the private key under the password. Returns an opaque, storable blob. */
export async function wrapPrivateKey(privateKey, password) {
  if (!privateKey || privateKey.length !== ML_KEM_768_SECRET_KEY_BYTES) {
    throw new Error('INVALID_PRIVATE_KEY');
  }
  if (typeof password !== 'string' || password.length === 0) throw new Error('EMPTY_PASSWORD');

  const salt = crypto.getRandomValues(new Uint8Array(BACKUP_SALT_BYTES));
  const key = await deriveBackupKey(password, salt, PBKDF2_ITERATIONS, ['encrypt']);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, privateKey)
  );

  return {
    v: KEY_BACKUP_VERSION,
    kdf: 'PBKDF2-SHA256',
    iterations: PBKDF2_ITERATIONS,
    salt: b64encode(salt),
    nonce: b64encode(nonce),
    ciphertext: b64encode(sealed.slice(0, -16)),
    authTag: b64encode(sealed.slice(-16)),
  };
}

/** Recover the private key from a backup blob. Throws if the password is wrong. */
export async function unwrapPrivateKey(backup, password) {
  if (!backup || backup.v !== KEY_BACKUP_VERSION) throw new Error('UNSUPPORTED_BACKUP');
  if (typeof password !== 'string' || password.length === 0) throw new Error('EMPTY_PASSWORD');

  try {
    const salt = b64decode(backup.salt);
    const key = await deriveBackupKey(password, salt, backup.iterations || PBKDF2_ITERATIONS, ['decrypt']);

    const ct = b64decode(backup.ciphertext);
    const tag = b64decode(backup.authTag);
    const joined = new Uint8Array(ct.length + tag.length);
    joined.set(ct);
    joined.set(tag, ct.length);

    const plain = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(backup.nonce) }, key, joined)
    );
    if (plain.length !== ML_KEM_768_SECRET_KEY_BYTES) throw new Error('bad length');
    return plain;
  } catch {
    // AES-GCM authentication failing is what a wrong password looks like.
    throw new Error('WRONG_PASSWORD');
  }
}

/* ─── Key identity ───
   FIPS 203 encodes the decapsulation key as dk_PKE ‖ ek ‖ H(ek) ‖ z, so a
   stored private key still carries its own public key. That lets the client
   prove whether the key on this device is the one the account advertises —
   the difference between "these messages are lost" and "this device is wrong". */

export const ML_KEM_768_SECRET_KEY_BYTES = 2400;
export const ML_KEM_768_PUBLIC_KEY_BYTES = 1184;
const DK_PKE_BYTES = 1152;

export function publicKeyFromSecretKey(secretKey) {
  if (!secretKey || secretKey.length !== ML_KEM_768_SECRET_KEY_BYTES) return null;
  return secretKey.slice(DK_PKE_BYTES, DK_PKE_BYTES + ML_KEM_768_PUBLIC_KEY_BYTES);
}

/** Short, human-comparable fingerprint of a public key. */
export async function keyFingerprint(publicKey) {
  if (!publicKey || publicKey.length === 0) return null;
  const digest = await crypto.subtle.digest('SHA-256', publicKey);
  return [...new Uint8Array(digest).slice(0, 8)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase()
    .match(/.{4}/g)
    .join(' ');
}

// Builds a rolling SHA-256 hash chain of the conversation history
export async function calculateIntegrity(messages) {
  if (!messages || messages.length === 0) return '0x0000...';
  
  try {
    let currentHash = new Uint8Array(32);
    const encoder = new TextEncoder();

    for (const msg of messages) {
      // Concat previous hash with current message data (including direction)
      const direction = msg.isMine ? 'out' : 'in';
      const data = encoder.encode(msg.text + msg.timestamp + direction);
      const combined = new Uint8Array(currentHash.length + data.length);
      combined.set(currentHash);
      combined.set(data, currentHash.length);
      
      const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
      currentHash = new Uint8Array(hashBuffer);
    }

    return b64encode(currentHash).slice(0, 16) + '...';
  } catch (error) {
    console.error('Integrity check failed:', error);
    throw new Error('INTEGRITY_CALCULATION_FAILED');
  }
}

// Convert Uint8Array to Base64 using chunking to prevent max call stack limits and memory bloat
export function b64encode(uint8) {
  const chunkSize = 8192;
  let binary = '';
  for (let i = 0; i < uint8.byteLength; i += chunkSize) {
    binary += String.fromCharCode.apply(null, uint8.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

// Convert Base64 back to Uint8Array
export function b64decode(b64) {
  if (typeof b64 !== 'string') return new Uint8Array();
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    arr[i] = bin.charCodeAt(i);
  }
  return arr;
}
