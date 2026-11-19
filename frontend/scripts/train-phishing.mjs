/**
 * Train the on-device phishing model (TensorFlow.js) and write it to
 * public/models/phishing/, where the browser loads it from.
 *
 *   npm run train:phishing            # downloads the datasets once, trains, evaluates, saves
 *
 * Data — ealvaradob/phishing-dataset on Hugging Face (Apache-2.0), a cleaned,
 * de-duplicated compilation of:
 *   - texts.json: ~20k SMS and email bodies, phishing/smishing/spam vs. legitimate
 *   - urls.json:  ~836k URLs, phishing vs. legitimate (we sample 30k, balanced)
 * URLs are half kept bare and half dropped into neutral chat sentences ("can
 * you check {url}"), so the model learns links as they appear in a chat. The
 * same templates are used for both classes, so they carry no label signal.
 *
 * The features come from src/ai/phishingFeatures.js — the very file the
 * browser uses — so training and inference can't drift apart. Everything is
 * seeded, so a re-run on the same data reproduces the same model.
 */
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import * as tf from '@tensorflow/tfjs';
import { featurize, explain, FEATURE_DIM, WORD_DIM, URL_DIM, SIGNAL_DIM } from '../src/ai/phishingFeatures.js';
import { decide, POLICY } from '../src/ai/phishing.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(here, '..', 'public', 'models', 'phishing');
const DATA = process.env.DATA_DIR || path.join(os.homedir(), '.cache', 'qchat-datasets');
const BASE = 'https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main';
const SEED = 20260418;
const EPOCHS = Number(process.env.EPOCHS || 6);
const URL_SAMPLE = 30_000;

/* ── seeded randomness ── */
function mulberry32(a) {
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(SEED);
const shuffle = (arr) => {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
};

async function dataset(name) {
  fs.mkdirSync(DATA, { recursive: true });
  const file = path.join(DATA, name);
  if (!fs.existsSync(file)) {
    console.log(`Downloading ${name} …`);
    const res = await fetch(`${BASE}/${name}`);
    if (!res.ok) throw new Error(`Download failed: ${res.status} ${res.statusText}`);
    fs.writeFileSync(file, Buffer.from(await res.arrayBuffer()));
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

const TEMPLATES = [
  (u) => u,
  (u) => `can you check ${u}`,
  (u) => `here is the link ${u}`,
  (u) => `${u} have a look`,
  (u) => `saw this today ${u}`,
  (u) => `open this one ${u} and tell me what you think`,
];

async function loadSamples() {
  const texts = await dataset('texts.json');
  const urls = await dataset('urls.json');

  const samples = texts
    .filter(t => typeof t.text === 'string' && t.text.trim().length > 0)
    .map(t => ({ text: t.text.slice(0, 1500), label: t.label, kind: t.text.length < 300 ? 'short' : 'email' }));

  const byLabel = [urls.filter(u => u.label === 0), urls.filter(u => u.label === 1)];
  for (const group of byLabel) {
    shuffle(group);
    for (const u of group.slice(0, URL_SAMPLE / 2)) {
      const template = TEMPLATES[Math.floor(rand() * TEMPLATES.length)];
      samples.push({ text: template(u.text), label: u.label, kind: 'url' });
    }
  }
  return shuffle(samples);
}

function split(samples) {
  const test = [], val = [], train = [];
  for (const s of samples) {
    const r = rand();
    (r < 0.15 ? test : r < 0.25 ? val : train).push(s);
  }
  return { train, val, test };
}

function batches(samples, size) {
  return tf.data.generator(function* () {
    for (let i = 0; i < samples.length; i += size) {
      const chunk = samples.slice(i, i + size);
      const xs = new Float32Array(chunk.length * FEATURE_DIM);
      chunk.forEach((s, j) => xs.set(featurize(s.text).vector, j * FEATURE_DIM));
      yield {
        xs: tf.tensor2d(xs, [chunk.length, FEATURE_DIM]),
        ys: tf.tensor2d(chunk.map(s => [s.label]), [chunk.length, 1]),
      };
    }
  });
}

function buildModel() {
  const model = tf.sequential();
  model.add(tf.layers.dense({
    inputShape: [FEATURE_DIM], units: 32, activation: 'relu',
    kernelInitializer: tf.initializers.glorotUniform({ seed: SEED }),
    kernelRegularizer: tf.regularizers.l2({ l2: 1e-5 }),
  }));
  model.add(tf.layers.dropout({ rate: 0.2, seed: SEED }));
  model.add(tf.layers.dense({
    units: 1, activation: 'sigmoid',
    kernelInitializer: tf.initializers.glorotUniform({ seed: SEED + 1 }),
  }));
  model.compile({ optimizer: tf.train.adam(2e-3), loss: 'binaryCrossentropy', metrics: ['accuracy'] });
  return model;
}

function predict(model, samples) {
  const out = [];
  for (let i = 0; i < samples.length; i += 512) {
    const chunk = samples.slice(i, i + 512);
    const xs = new Float32Array(chunk.length * FEATURE_DIM);
    chunk.forEach((s, j) => xs.set(featurize(s.text).vector, j * FEATURE_DIM));
    const t = tf.tensor2d(xs, [chunk.length, FEATURE_DIM]);
    const p = model.predict(t);
    out.push(...p.dataSync());
    tf.dispose([t, p]);
  }
  return out;
}

const reasonsOf = (samples) => samples.map(s => explain(featurize(s.text).signals));

/** `flag(i)` decides sample i; defaults to the bare probability threshold. */
function metrics(samples, scores, threshold, flag = (i) => scores[i] >= threshold) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  samples.forEach((s, i) => {
    const yes = flag(i);
    if (yes && s.label === 1) tp++; else if (yes) fp++; else if (s.label === 1) fn++; else tn++;
  });
  const precision = tp / Math.max(tp + fp, 1);
  const recall = tp / Math.max(tp + fn, 1);
  return {
    n: samples.length,
    accuracy: +((tp + tn) / Math.max(samples.length, 1)).toFixed(4),
    precision: +precision.toFixed(4),
    recall: +recall.toFixed(4),
    f1: +(2 * precision * recall / Math.max(precision + recall, 1e-9)).toFixed(4),
    falsePositiveRate: +(fp / Math.max(fp + tn, 1)).toFixed(4),
  };
}

/** Threshold that maximises F1 on validation data, never below 0.5. */
function pickThreshold(samples, scores) {
  let best = { t: 0.5, f1: -1 };
  for (let t = 0.5; t <= 0.95; t += 0.01) {
    const m = metrics(samples, scores, t);
    if (m.f1 > best.f1) best = { t: +t.toFixed(2), f1: m.f1 };
  }
  return best.t;
}

async function save(model, meta) {
  fs.mkdirSync(OUT, { recursive: true });
  await model.save(tf.io.withSaveHandler(async (artifacts) => {
    fs.writeFileSync(path.join(OUT, 'weights.bin'), Buffer.from(artifacts.weightData));
    fs.writeFileSync(path.join(OUT, 'model.json'), JSON.stringify({
      format: 'layers-model',
      generatedBy: `TensorFlow.js tfjs-layers v${tf.version.tfjs}`,
      convertedBy: null,
      modelTopology: artifacts.modelTopology,
      weightsManifest: [{ paths: ['weights.bin'], weights: artifacts.weightSpecs }],
    }));
    return { modelArtifactsInfo: { dateSaved: new Date(), modelTopologyType: 'JSON' } };
  }));
  fs.writeFileSync(path.join(OUT, 'meta.json'), JSON.stringify(meta, null, 2) + '\n');
}

const t0 = Date.now();
const samples = await loadSamples();
const { train, val, test } = split(samples);
console.log(`Samples: ${samples.length} (train ${train.length}, val ${val.length}, test ${test.length})`);
console.log(`Features: ${FEATURE_DIM} = ${WORD_DIM} word + ${URL_DIM} url + ${SIGNAL_DIM} signals`);

const model = buildModel();
for (let epoch = 1; epoch <= EPOCHS; epoch++) {
  shuffle(train);
  const h = await model.fitDataset(batches(train, 256), { epochs: 1, verbose: 0 });
  console.log(`epoch ${epoch}/${EPOCHS}  loss ${h.history.loss[0].toFixed(4)}  acc ${h.history.acc[0].toFixed(4)}`);
}

const valScores = predict(model, val);
const threshold = pickThreshold(val, valScores);

// The deployed rule needs a concrete reason only in the grey zone between the
// threshold and `override`. Pick the override on validation data: best F1
// while keeping false alarms on legitimate messages at or under 4%.
const valReasons = reasonsOf(val);
let policy = { ...POLICY };
let bestF1 = -1;
for (const override of [0.7, 0.75, 0.8, 0.85, 0.9, 0.95, 0.97]) {
  const candidate = { requireReason: true, override };
  const m = metrics(val, valScores, threshold, (i) => decide(valScores[i], valReasons[i], threshold, candidate));
  if (m.falsePositiveRate <= 0.04 && m.f1 > bestF1) { bestF1 = m.f1; policy = candidate; }
}
const testScores = predict(model, test);
const testReasons = reasonsOf(test);
// Two views: the bare model, and the deployed policy (decide(): the score
// must also come with at least one concrete indicator), which is what users see.
const evaluate = (idx) => {
  const sub = idx.map(i => test[i]);
  const scores = idx.map(i => testScores[i]);
  const reasons = idx.map(i => testReasons[i]);
  return {
    model: metrics(sub, scores, threshold),
    deployed: metrics(sub, scores, threshold, (j) => decide(scores[j], reasons[j], threshold, policy)),
  };
};
const all = test.map((_, i) => i);
const overall = evaluate(all);
const byKind = {};
for (const kind of ['short', 'email', 'url']) byKind[kind] = evaluate(all.filter(i => test[i].kind === kind));

const meta = {
  name: 'qchat-phishing',
  version: 1,
  framework: `TensorFlow.js ${tf.version.tfjs}`,
  architecture: `Dense(${FEATURE_DIM}→32, ReLU) → Dropout(0.2) → Dense(32→1, sigmoid)`,
  features: { total: FEATURE_DIM, word: WORD_DIM, url: URL_DIM, signals: SIGNAL_DIM },
  threshold,
  policy,
  dataset: {
    source: 'huggingface.co/datasets/ealvaradob/phishing-dataset (texts.json + 30k sampled urls.json)',
    license: 'Apache-2.0',
    train: train.length, validation: val.length, test: test.length,
  },
  test: { overall, byKind },
  seed: SEED,
  epochs: EPOCHS,
  trainedAt: new Date().toISOString(),
};
await save(model, meta);
console.log(JSON.stringify(meta.test, null, 2));
console.log(`Saved to ${path.relative(process.cwd(), OUT)} in ${Math.round((Date.now() - t0) / 1000)}s (threshold ${threshold})`);
