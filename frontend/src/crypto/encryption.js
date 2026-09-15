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
