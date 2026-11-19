/**
 * On-device phishing detection — a small TensorFlow.js network over the
 * features in phishingFeatures.js, trained by scripts/train-phishing.mjs.
 *
 * Inference is a single dense pass over ~3k numbers, well under a millisecond
 * once the model is loaded, and nothing about the message leaves the device:
 * the only network request is for the model file itself, served by QChat.
 */
import * as tf from '@tensorflow/tfjs';
import { featurize, explain, FEATURE_DIM } from './phishingFeatures.js';

/**
 * The verdict is the model's probability, but a warning must also be able to
 * say *why*. Requiring at least one concrete indicator (a suspicious link, a
 * request for credentials, urgency, a lure) keeps the model from flagging an
 * ordinary sentence merely because it resembles training spam; a near-certain
 * score is flagged regardless.
 */
export const POLICY = { requireReason: true, override: 0.97 };

export function decide(score, reasons, threshold, policy = POLICY) {
  if (score >= policy.override) return true;
  if (score < threshold) return false;
  return policy.requireReason ? reasons.length > 0 : true;
}

let model = null;
let meta = null;

/** Load from a URL (browser) or from in-memory artifacts (Node tests). */
export async function loadPhishingModel(source = '/models/phishing/') {
  if (typeof source === 'string') {
    const base = source.endsWith('/') ? source : `${source}/`;
    [model, meta] = await Promise.all([
      tf.loadLayersModel(`${base}model.json`),
      fetch(`${base}meta.json`).then(r => r.json()),
    ]);
  } else {
    model = await tf.loadLayersModel(tf.io.fromMemory(source.artifacts));
    meta = source.meta;
  }
  // One throwaway prediction so the first real message doesn't pay for setup.
  tf.tidy(() => model.predict(tf.zeros([1, FEATURE_DIM])));
  return meta;
}

export const phishingReady = () => !!model;

/** Score one message. Returns { score, flagged, reasons, ms }. */
export function analyzePhishing(text) {
  if (!model) throw new Error('PHISHING_MODEL_NOT_LOADED');
  const t0 = (typeof performance !== 'undefined' ? performance : Date).now();
  const { vector, signals } = featurize(text);
  const score = tf.tidy(() => model.predict(tf.tensor2d(vector, [1, FEATURE_DIM])).dataSync()[0]);
  const reasons = explain(signals);
  const flagged = decide(score, reasons, meta?.threshold ?? 0.5, meta?.policy || POLICY);
  const ms = (typeof performance !== 'undefined' ? performance : Date).now() - t0;
  return { score: +score.toFixed(4), flagged, reasons, ms: +ms.toFixed(2) };
}
