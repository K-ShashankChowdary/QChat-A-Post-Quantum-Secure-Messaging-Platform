/**
 * On-device hate-speech and abuse detection with Transformers.js (Xenova).
 *
 * Model: Xenova/toxic-bert — Detoxify's BERT fine-tuned on the Jigsaw toxic
 * comment data, exported to ONNX and quantised (~110 MB, downloaded once and
 * cached by the browser). It scores six labels independently: toxic,
 * severe_toxic, obscene, threat, insult, identity_hate. Inference runs in
 * WebAssembly inside a Web Worker; the message text never leaves the device.
 */
import { pipeline, env } from '@xenova/transformers';

export const TOXICITY_MODEL = 'Xenova/toxic-bert';

// Probability at which each label counts. `toxic` is the general one; the
// specific labels fire lower because they are rarer and more serious.
const THRESHOLDS = { toxic: 0.7, severe_toxic: 0.4, threat: 0.5, identity_hate: 0.4, insult: 0.75, obscene: 0.85 };

const DESCRIBE = {
  identity_hate: 'hate speech targeting a group',
  threat: 'threatening',
  severe_toxic: 'severely abusive',
  insult: 'insulting',
  obscene: 'obscene',
  toxic: 'abusive or toxic',
};
const PRIORITY = ['identity_hate', 'threat', 'severe_toxic', 'insult', 'obscene', 'toxic'];

let classifier = null;

// BERT reads up to 512 tokens, but in browser WebAssembly a full-length input
// takes seconds — long enough for a pasted wall of text to stall the queue and
// make the user's own draft check time out. Abuse shows in the first lines;
// 128 tokens (~90 words) keeps the worst case well under a second.
const MAX_TOKENS = 128;
const MAX_CHARS = 600;

/**
 * Configure where model files come from. With `local`, everything (weights and
 * the ONNX Runtime WebAssembly) is served by QChat itself from public/models/,
 * fetched there once by `npm run fetch-models`, and nothing is requested from
 * a third party at all. Otherwise weights come from the Hugging Face hub.
 */
export function configureTransformers({ local, base = '/models' }) {
  env.allowLocalModels = !!local;
  env.allowRemoteModels = !local;
  if (local) {
    env.localModelPath = `${base}/hf/`;
    env.backends.onnx.wasm.wasmPaths = `${base}/ort/`;
  }
  // Threads need cross-origin isolation, which a dev server doesn't have.
  env.backends.onnx.wasm.numThreads = 1;
}

export async function loadToxicityModel(onProgress) {
  classifier = await pipeline('text-classification', TOXICITY_MODEL, {
    quantized: true,
    progress_callback: onProgress,
  });
  classifier.tokenizer.model_max_length = MAX_TOKENS;
  return classifier;
}

export const toxicityReady = () => !!classifier;

/** Turn the six label scores into a verdict. Exported for tests. */
export function judgeToxicity(scores) {
  const hits = PRIORITY.filter(label => (scores[label] ?? 0) >= THRESHOLDS[label]);
  return {
    flagged: hits.length > 0,
    category: hits[0] || null,
    description: hits[0] ? DESCRIBE[hits[0]] : null,
    labels: hits,
  };
}

/** Score one message. Returns { flagged, category, description, labels, scores, ms }. */
export async function analyzeToxicity(text) {
  if (!classifier) throw new Error('TOXICITY_MODEL_NOT_LOADED');
  const t0 = performance.now();
  const out = await classifier(String(text).slice(0, MAX_CHARS), { topk: null });
  const scores = Object.fromEntries(out.map(r => [r.label, +r.score.toFixed(4)]));
  return { ...judgeToxicity(scores), scores, ms: +(performance.now() - t0).toFixed(1) };
}
