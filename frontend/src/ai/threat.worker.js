/**
 * The AI layer's worker. Both models live here, off the main thread, so a
 * 100 MB transformer loading or a 60 ms inference never stalls typing,
 * scrolling or a video call.
 *
 * Protocol (postMessage):
 *   page → worker  { type: 'init', base }
 *                  { type: 'analyze', id, text }
 *   worker → page  { type: 'status', phishing, toxicity, progress, local, error? }
 *                  { type: 'result', id, phishing, toxicity, ms }
 *
 * The only network traffic is fetching model files. Message text arrives by
 * postMessage and leaves the same way; nothing here can send it anywhere else.
 */
import * as tf from '@tensorflow/tfjs';
import { loadPhishingModel, analyzePhishing, phishingReady } from './phishing.js';
import { configureTransformers, loadToxicityModel, analyzeToxicity, toxicityReady } from './toxicity.js';

const status = { phishing: 'loading', toxicity: 'loading', progress: 0, local: false };
const post = (msg) => self.postMessage(msg);
const report = (patch) => { Object.assign(status, patch); post({ type: 'status', ...status }); };

async function init(base) {
  // The network is tiny; the CPU backend avoids needing WebGL in a worker.
  await tf.setBackend('cpu');

  loadPhishingModel(`${base}/phishing/`)
    .then(() => report({ phishing: 'ready' }))
    .catch(err => report({ phishing: 'error', error: `phishing: ${err.message}` }));

  // Model files served by QChat itself if `npm run fetch-models` was run;
  // otherwise the Hugging Face hub. Detected with a manifest, because a dev
  // server answers a missing file with index.html rather than a 404.
  let local = false;
  try {
    const res = await fetch(`${base}/hf/manifest.json`, { cache: 'no-store' });
    local = res.ok && (await res.json())?.models?.includes('Xenova/toxic-bert');
  } catch { /* not present */ }
  configureTransformers({ local, base });
  report({ local });

  const files = new Map();
  try {
    await loadToxicityModel((p) => {
      if (p.status !== 'progress' || !p.total) return;
      files.set(p.file, { loaded: p.loaded, total: p.total });
      let loaded = 0, total = 0;
      for (const f of files.values()) { loaded += f.loaded; total += f.total; }
      report({ progress: Math.round((loaded / total) * 100) });
    });
    report({ toxicity: 'ready', progress: 100 });
  } catch (err) {
    report({ toxicity: 'error', error: `toxicity: ${err.message}` });
  }
}

async function analyze(id, text) {
  const t0 = performance.now();
  const result = { type: 'result', id, phishing: null, toxicity: null };
  if (phishingReady()) {
    try { result.phishing = analyzePhishing(text); } catch { /* skip */ }
  }
  if (toxicityReady()) {
    try { result.toxicity = await analyzeToxicity(text); } catch { /* skip */ }
  }
  result.ms = +(performance.now() - t0).toFixed(1);
  post(result);
}

self.onmessage = (e) => {
  const msg = e.data || {};
  if (msg.type === 'init') init(msg.base || '/models');
  else if (msg.type === 'analyze') analyze(msg.id, msg.text);
};
