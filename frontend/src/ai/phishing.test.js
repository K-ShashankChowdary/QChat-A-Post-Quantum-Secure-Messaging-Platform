// `npm test`. Checks the phishing features and the committed TensorFlow.js
// model, running exactly the code the browser runs — no browser needed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import * as tf from '@tensorflow/tfjs';
import { extractUrls, registeredDomain, computeSignals, featurize, explain, FEATURE_DIM } from './phishingFeatures.js';
import { loadPhishingModel, analyzePhishing, decide } from './phishing.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = JSON.parse(fs.readFileSync(path.join(here, 'fixtures.json'), 'utf8'));
const MODEL_DIR = path.join(here, '..', '..', 'public', 'models', 'phishing');

test('URLs are found in free text, with and without a scheme', () => {
  const urls = extractUrls('see http://user@evil.com:8080/a?b=1, bit.ly/x and www.example.co.uk/path.');
  assert.deepEqual(urls.map(u => u.host), ['evil.com', 'bit.ly', 'example.co.uk']);
  assert.equal(urls[0].at, true);
  assert.equal(extractUrls('version 3.5 is out, e.g. today').length, 0);
});

test('registrable domain handles second-level country domains', () => {
  assert.equal(registeredDomain('login.secure.paypal.com'), 'paypal.com');
  assert.equal(registeredDomain('www.bbc.co.uk'), 'bbc.co.uk');
});

test('look-alike domains are caught, real brand domains are not', () => {
  assert.equal(computeSignals('go to paypa1-secure.com/verify').values.lookalike, 1);
  assert.equal(computeSignals('amaz0n-orders.co').values.lookalike, 1);
  assert.equal(computeSignals('https://www.paypal.com/signin').values.lookalike, 0);
  assert.equal(computeSignals('https://accounts.google.com').values.lookalike, 0);
});

test('signals: raw IPs, shorteners, risky TLDs, credential requests, urgency', () => {
  const s = computeSignals('URGENT: account suspended, send your password and OTP to http://10.0.0.1/x or bit.ly/a or win.xyz').values;
  for (const key of ['ipHost', 'shortener', 'riskyTld', 'plainHttp', 'credential', 'urgency']) assert.equal(s[key] > 0, true, key);
});

test('features are a fixed-size, deterministic vector', () => {
  const a = featurize('hello there https://example.com').vector;
  const b = featurize('hello there https://example.com').vector;
  assert.equal(a.length, FEATURE_DIM);
  assert.deepEqual(Array.from(a), Array.from(b));
});

test('explanations are human-readable and name the brand', () => {
  const reasons = explain(computeSignals('verify your password at paypa1-secure.com'));
  assert.ok(reasons.some(r => r.includes('paypal')));
  assert.ok(reasons.some(r => r.includes('password')));
});

test('decision policy: a grey-zone score needs a reason, a certain one does not', () => {
  assert.equal(decide(0.6, [], 0.55, { requireReason: true, override: 0.9 }), false);
  assert.equal(decide(0.6, ['asks for a password'], 0.55, { requireReason: true, override: 0.9 }), true);
  assert.equal(decide(0.95, [], 0.55, { requireReason: true, override: 0.9 }), true);
  assert.equal(decide(0.4, ['contains several links'], 0.55, { requireReason: true, override: 0.9 }), false);
});

async function loadFromDisk() {
  const model = JSON.parse(fs.readFileSync(path.join(MODEL_DIR, 'model.json'), 'utf8'));
  const weights = fs.readFileSync(path.join(MODEL_DIR, 'weights.bin'));
  const meta = JSON.parse(fs.readFileSync(path.join(MODEL_DIR, 'meta.json'), 'utf8'));
  return loadPhishingModel({
    artifacts: {
      modelTopology: model.modelTopology,
      weightSpecs: model.weightsManifest[0].weights,
      weightData: weights.buffer.slice(weights.byteOffset, weights.byteOffset + weights.byteLength),
    },
    meta,
  });
}

test('the trained model flags phishing and leaves ordinary chat alone', async () => {
  await tf.setBackend('cpu');
  const meta = await loadFromDisk();
  assert.equal(meta.features.total, FEATURE_DIM, 'model was trained on this feature layout');

  const falseAlarms = fixtures.safeChat.filter(t => analyzePhishing(t).flagged);
  const missed = fixtures.phishing.filter(t => !analyzePhishing(t).flagged);
  assert.ok(falseAlarms.length <= 1, `false alarms on ordinary chat: ${JSON.stringify(falseAlarms)}`);
  assert.ok(missed.length <= 1, `missed phishing: ${JSON.stringify(missed)}`);
});

test('TC-04 (report Table 5.1): a deceptive URL with credential harvesting is flagged, with reasons', async () => {
  await loadFromDisk();
  const r = analyzePhishing(fixtures.tc04);
  assert.equal(r.flagged, true);
  assert.ok(r.reasons.length >= 2, JSON.stringify(r.reasons));
  assert.ok(r.ms < 50, `inference took ${r.ms} ms`);
});

test('hostile input cannot stall feature extraction (no quadratic regex backtracking)', () => {
  for (const text of ['a.'.repeat(50_000), 'ab-'.repeat(30_000), `http://${'a-'.repeat(30_000)}.com`, 'x'.repeat(200_000)]) {
    const t0 = performance.now();
    featurize(text);
    assert.ok(performance.now() - t0 < 250, `took ${(performance.now() - t0).toFixed(0)} ms on ${text.slice(0, 12)}…`);
  }
  // Long but ordinary hosts are still found.
  assert.deepEqual(extractUrls('see a.b.c.d.e.f.g.example.com now').map(u => u.host), ['a.b.c.d.e.f.g.example.com']);
});
