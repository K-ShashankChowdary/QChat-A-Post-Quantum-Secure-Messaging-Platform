/**
 * Measure the cost of every core operation, with the same code the browser
 * runs (report Table 5.2).
 *
 *   npm run bench                 # crypto, integrity, phishing model
 *   npm run bench -- --toxicity   # also the hate-speech transformer (downloads ~110 MB once)
 *
 * Prints a Markdown table of median and 95th-percentile times. Node's crypto
 * is close to, but not identical with, a browser's; the in-app protocol
 * console logs the live per-message figures.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import * as tf from '@tensorflow/tfjs';
import { encryptForRecipients, decryptEnvelope } from '../src/crypto/encryption.js';
import { leafForMessage, buildTree, inclusionProof, verifyInclusion } from '../src/crypto/merkle.js';
import { loadPhishingModel, analyzePhishing } from '../src/ai/phishing.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const RUNS = Number(process.env.RUNS || 200);
const rows = [];

async function measure(name, technology, fn, runs = RUNS) {
  for (let i = 0; i < Math.min(10, runs); i++) await fn();   // warm-up
  const times = [];
  for (let i = 0; i < runs; i++) {
    const t0 = performance.now();
    await fn();
    times.push(performance.now() - t0);
  }
  times.sort((a, b) => a - b);
  const pick = (q) => times[Math.min(times.length - 1, Math.floor(q * times.length))];
  rows.push({ name, technology, median: pick(0.5), p95: pick(0.95), runs });
}

const fmt = (ms) => (ms < 0.1 ? `${(ms * 1000).toFixed(0)} µs` : `${ms.toFixed(2)} ms`);

// ── Post-quantum key exchange ──
await measure('Key pair generation', 'ML-KEM-768 (FIPS 203)', () => ml_kem768.keygen());
const alice = ml_kem768.keygen();
const bob = ml_kem768.keygen();
await measure('Encapsulation', 'ML-KEM-768', () => ml_kem768.encapsulate(bob.publicKey));
const { cipherText } = ml_kem768.encapsulate(bob.publicKey);
await measure('Decapsulation', 'ML-KEM-768', () => ml_kem768.decapsulate(cipherText, bob.secretKey));

// ── A whole message, as sent: one AES-256-GCM pass, the key wrapped to 2 parties ──
const text = 'Are we still meeting at 5? Bring the report draft.';
const recipients = [{ id: 'bob', publicKey: bob.publicKey }, { id: 'alice', publicKey: alice.publicKey }];
await measure('Encrypt a message (2 recipients)', 'ML-KEM-768 ×2 + HKDF-SHA256 + AES-256-GCM', () => encryptForRecipients(text, recipients));
const payload = await encryptForRecipients(text, recipients);
await measure('Decrypt a message', 'ML-KEM-768 + HKDF-SHA256 + AES-256-GCM', () => decryptEnvelope(payload, 'bob', bob.secretKey));

// ── Integrity ──
const msg = { fromId: 'a', id: '6aff05bb30c95ef6b9ad5f2c', timestamp: new Date(), payload };
await measure('Merkle leaf for one message', 'SHA-256 (RFC 6962 leaf)', () => leafForMessage(msg));
const leaves = await Promise.all(Array.from({ length: 1000 }, (_, i) => leafForMessage({ ...msg, id: String(i) })));
await measure('Merkle root over 1,000 messages', 'SHA-256 tree', () => buildTree(leaves), 30);
const tree = await buildTree(leaves);
const proof = inclusionProof(tree, 517);
await measure('Verify one inclusion proof (n = 1,000)', 'RFC 9162 audit path, 10 hashes', () =>
  verifyInclusion({ leaf: leaves[517], index: 517, size: 1000, path: proof, root: tree.root }));

// ── On-device AI ──
await tf.setBackend('cpu');
const dir = path.join(here, '..', 'public', 'models', 'phishing');
const m = JSON.parse(fs.readFileSync(path.join(dir, 'model.json'), 'utf8'));
const w = fs.readFileSync(path.join(dir, 'weights.bin'));
await loadPhishingModel({
  artifacts: { modelTopology: m.modelTopology, weightSpecs: m.weightsManifest[0].weights, weightData: w.buffer.slice(w.byteOffset, w.byteOffset + w.byteLength) },
  meta: JSON.parse(fs.readFileSync(path.join(dir, 'meta.json'), 'utf8')),
});
const lure = 'URGENT: your account is suspended. Verify your password at http://paypa1-secure.xyz/login';
await measure('Phishing classification', 'TensorFlow.js dense network', () => analyzePhishing(lure));

if (process.argv.includes('--toxicity')) {
  const { loadToxicityModel, analyzeToxicity } = await import('../src/ai/toxicity.js');
  await loadToxicityModel();
  await measure('Hate-speech classification', 'Transformers.js toxic-bert (ONNX, int8)', () => analyzeToxicity('you are a worthless idiot'), 50);
}

console.log(`\nQChat benchmark — Node ${process.version}, ${os.cpus()[0]?.model || 'unknown CPU'}, ${RUNS} runs\n`);
console.log('| Operation | Algorithm / technology | Median | p95 |');
console.log('|---|---|---|---|');
for (const r of rows) console.log(`| ${r.name} | ${r.technology} | ${fmt(r.median)} | ${fmt(r.p95)} |`);
