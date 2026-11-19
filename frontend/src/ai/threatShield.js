/**
 * Main-thread handle on the AI worker: start it once, ask it about a message,
 * and follow its loading status. Used by the chat for incoming messages (warn
 * on the bubble) and outgoing ones (stop and ask before sending).
 */
const PREF_KEY = 'qchat_ai_shield';

let worker = null;
let seq = 0;
const pending = new Map();
const listeners = new Set();
let status = { phishing: 'off', toxicity: 'off', progress: 0, local: false };

function emit() { for (const fn of listeners) fn(status); }

/** Is the shield switched on? A per-browser preference; on unless turned off. */
export function shieldEnabled() {
  try { return localStorage.getItem(PREF_KEY) !== 'off'; } catch { return true; }
}

export function setShieldEnabled(on) {
  try { localStorage.setItem(PREF_KEY, on ? 'on' : 'off'); } catch { /* storage blocked */ }
  if (on) startShield();
}

export function startShield(base = '/models') {
  if (worker || typeof Worker === 'undefined') return;
  worker = new Worker(new URL('./threat.worker.js', import.meta.url), { type: 'module' });
  status = { ...status, phishing: 'loading', toxicity: 'loading' };
  emit();
  worker.onmessage = (e) => {
    const msg = e.data || {};
    if (msg.type === 'status') {
      const rest = { ...msg };
      delete rest.type;
      status = { ...status, ...rest };
      emit();
    } else if (msg.type === 'result') {
      const resolve = pending.get(msg.id);
      pending.delete(msg.id);
      resolve?.(msg);
    }
  };
  worker.onerror = () => {
    status = { ...status, phishing: 'error', toxicity: 'error', error: 'The AI worker failed to start' };
    emit();
  };
  worker.postMessage({ type: 'init', base });
}

export function onShieldStatus(fn) {
  listeners.add(fn);
  fn(status);
  return () => listeners.delete(fn);
}

export const shieldStatus = () => status;

/**
 * Analyse one message. Resolves to { phishing, toxicity, ms } — either part is
 * null while its model is still loading — or null after `timeoutMs`, so a slow
 * model can never hold a message up for long.
 */
export function analyzeMessage(text, timeoutMs = 4000) {
  if (!worker || !text || !String(text).trim()) return Promise.resolve(null);
  const id = ++seq;
  return new Promise((resolve) => {
    const timer = setTimeout(() => { pending.delete(id); resolve(null); }, timeoutMs);
    pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
    worker.postMessage({ type: 'analyze', id, text: String(text) });
  });
}

/** One-line summary of a verdict, or null if nothing was flagged. */
export function describeThreat(result) {
  if (!result) return null;
  const parts = [];
  // Abuse can read as "scammy" to a phishing model trained on spam. With no
  // phishing indicator at all and the toxicity model already flagging it,
  // the abuse label is the honest one.
  const phishingOnlyByScore = result.phishing?.flagged && result.phishing.reasons.length === 0;
  if (result.phishing?.flagged && !(phishingOnlyByScore && result.toxicity?.flagged)) parts.push({ kind: 'phishing', title: 'Possible phishing', detail: result.phishing.reasons });
  if (result.toxicity?.flagged) parts.push({ kind: 'toxicity', title: `Flagged as ${result.toxicity.description}`, detail: [] });
  return parts.length ? parts : null;
}
