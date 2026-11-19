/**
 * Feature extraction for the on-device phishing model.
 *
 * Pure JavaScript with no dependencies, so the exact same code turns text into
 * numbers when the model is trained (scripts/train-phishing.mjs, in Node) and
 * when it runs in the browser. A model is only as good as the agreement
 * between those two, and sharing one file is how that agreement is kept.
 *
 * A message becomes one Float32Array of FEATURE_DIM numbers, in three blocks:
 *
 *   [0, WORD_DIM)                   hashed word unigrams + bigrams, log-scaled, L2-normalised
 *   [WORD_DIM, WORD_DIM+URL_DIM)    hashed character trigrams of every URL's host + path
 *   [.., FEATURE_DIM)               SIGNALS — hand-built indicators, each scaled to [0, 1]
 *
 * Hashing ("the hashing trick") maps an unbounded vocabulary into a fixed-size
 * vector without shipping a dictionary: a token's bucket is FNV-1a(token) mod
 * the block size. The signals are also what the UI shows as "why this was
 * flagged", so the explanation and the model see the same facts.
 */

export const WORD_DIM = 2048;
export const URL_DIM = 1024;

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cutt.ly', 'ow.ly', 'rb.gy', 'shorturl.at',
  'tiny.cc', 'buff.ly', 'rebrand.ly', 'bitly.com', 'lnkd.in', 'v.gd', 's.id', 't.ly', 'shorte.st',
]);

const RISKY_TLDS = new Set([
  'xyz', 'top', 'click', 'zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'rest', 'country',
  'kim', 'loan', 'review', 'support', 'live', 'icu', 'buzz', 'cam', 'monster', 'sbs', 'cyou',
]);

// Brand → domains it legitimately uses. A host that names the brand without
// being one of these (paypal-secure-login.com, amaz0n.verify-account.xyz) is
// the classic look-alike.
const BRANDS = {
  paypal: ['paypal.com', 'paypal.me'],
  amazon: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazonaws.com', 'amzn.to'],
  apple: ['apple.com', 'icloud.com'],
  icloud: ['icloud.com', 'apple.com'],
  google: ['google.com', 'gmail.com', 'google.co.in', 'googleusercontent.com', 'goo.gl'],
  gmail: ['gmail.com', 'google.com'],
  microsoft: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'microsoftonline.com'],
  outlook: ['outlook.com', 'live.com', 'microsoft.com', 'office.com'],
  office365: ['office.com', 'microsoft.com', 'microsoftonline.com'],
  netflix: ['netflix.com'],
  facebook: ['facebook.com', 'fb.com', 'fb.me'],
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com', 'wa.me'],
  linkedin: ['linkedin.com', 'lnkd.in'],
  dropbox: ['dropbox.com'],
  ebay: ['ebay.com', 'ebay.in'],
  chase: ['chase.com'],
  wellsfargo: ['wellsfargo.com'],
  bankofamerica: ['bankofamerica.com'],
  coinbase: ['coinbase.com'],
  binance: ['binance.com'],
  steam: ['steampowered.com', 'steamcommunity.com'],
  dhl: ['dhl.com', 'dhl.de'],
  fedex: ['fedex.com'],
  usps: ['usps.com'],
  irs: ['irs.gov'],
  sbi: ['onlinesbi.sbi', 'sbi.co.in', 'onlinesbi.com'],
  hdfc: ['hdfcbank.com', 'hdfc.com'],
  icici: ['icicibank.com'],
  axisbank: ['axisbank.com'],
  paytm: ['paytm.com'],
  phonepe: ['phonepe.com'],
  flipkart: ['flipkart.com'],
};

const CREDENTIAL = [
  'password', 'passcode', 'otp', 'pin', 'cvv', 'login', 'log in', 'sign in', 'signin', 'verify',
  'verification', 'confirm your', 'account details', 'bank details', 'card details', 'kyc',
  'ssn', 'social security', 'credentials', 'update your account', 'reset your',
];
const URGENCY = [
  'urgent', 'immediately', 'suspended', 'suspend', 'locked', 'blocked', 'expire', 'expires',
  'expired', 'within 24 hours', '24 hrs', 'final notice', 'act now', 'last chance', 'unusual activity',
  'unauthorized', 'deactivated', 'limited time', 'action required', 'asap',
];
const LURE = [
  'won', 'winner', 'prize', 'lottery', 'free', 'gift card', 'cash', 'reward', 'refund', 'claim',
  'congratulations', 'selected', 'bonus', 'jackpot', 'offer', '£', '$', '₹', 'rs.', 'inr',
];

/** The hand-built indicators, in a fixed order. `label` is shown to the user. */
export const SIGNALS = [
  { key: 'hasUrl',        label: 'contains a link' },
  { key: 'manyUrls',      label: 'contains several links' },
  { key: 'ipHost',        label: 'link points to a raw IP address' },
  { key: 'shortener',     label: 'link hides its destination behind a URL shortener' },
  { key: 'riskyTld',      label: 'link uses a domain ending often abused for scams' },
  { key: 'atInUrl',       label: 'link contains "@", which can disguise the real host' },
  { key: 'hyphenHost',    label: 'link host is padded with hyphens' },
  { key: 'deepSubdomain', label: 'link buries the real domain under many subdomains' },
  { key: 'plainHttp',     label: 'link is not encrypted (http://)' },
  { key: 'punycode',      label: 'link uses look-alike (punycode) characters' },
  { key: 'lookalike',     label: 'link imitates a known brand but is not its real domain' },
  { key: 'digitsInHost',  label: 'link host is full of digits' },
  { key: 'longUrl',       label: 'link is unusually long' },
  { key: 'credential',    label: 'asks for a password, OTP, PIN or account details' },
  { key: 'urgency',       label: 'pressures you to act urgently' },
  { key: 'lure',          label: 'dangles a prize, refund or money' },
  { key: 'shouting',      label: 'written in capitals or with many "!"' },
  { key: 'length',        label: 'message length' },
];
export const SIGNAL_DIM = SIGNALS.length;
export const FEATURE_DIM = WORD_DIM + URL_DIM + SIGNAL_DIM;

// Signals that count as reasons in an explanation (length is context, not a reason).
const REASON_KEYS = new Set(SIGNALS.map(s => s.key).filter(k => !['hasUrl', 'length'].includes(k)));

/** 32-bit FNV-1a. Fast, dependency-free and identical in every JS engine. */
export function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

const URL_RE = /\b(?:(?:https?:\/\/|www\.)[^\s<>"'()]+|[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.[a-z]{2,24}(?:\/[^\s<>"'()]*)?)/gi;
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu', 'nic']);
const DELEET = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', 8: 'b' };

/** Pull URLs out of free text and split each into host and the rest. */
export function extractUrls(text) {
  const found = [];
  for (const match of String(text).matchAll(URL_RE)) {
    let raw = match[0].replace(/[.,;:!?)\]]+$/, '');
    // "e.g." or "3.5" style false positives: no letters in the last label.
    const scheme = /^https?:\/\//i.test(raw);
    let rest = raw.replace(/^https?:\/\//i, '');
    let at = false;
    const slash = rest.search(/[/?#]/);
    let authority = slash === -1 ? rest : rest.slice(0, slash);
    const path = slash === -1 ? '' : rest.slice(slash);
    if (authority.includes('@')) { at = true; authority = authority.split('@').pop(); }
    const host = authority.replace(/:\d+$/, '').replace(/^www\./i, '').toLowerCase();
    if (!host.includes('.') || !/[a-z]/i.test(host.split('.').pop())) {
      if (!IPV4.test(host)) continue;
    }
    found.push({ raw, host, path, scheme: scheme ? raw.slice(0, raw.indexOf(':')).toLowerCase() : null, at: at || path.includes('@') });
  }
  return found;
}

/** Best-effort registrable domain: example.co.uk, example.com. */
export function registeredDomain(host) {
  const labels = host.split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const tld = labels[labels.length - 1];
  const sld = labels[labels.length - 2];
  const take = tld.length === 2 && SECOND_LEVEL.has(sld) ? 3 : 2;
  return labels.slice(-take).join('.');
}

const deleet = (s) => s.replace(/[0134578]/g, d => DELEET[d]);

function brandImpersonated(host) {
  const domain = registeredDomain(host);
  const flat = deleet(host.replace(/[^a-z0-9]/g, ''));
  for (const [brand, official] of Object.entries(BRANDS)) {
    if (!flat.includes(brand)) continue;
    const legit = official.some(d => host === d || host.endsWith(`.${d}`) || domain === d);
    if (!legit) return brand;
  }
  return null;
}

const countHits = (text, list) => list.reduce((n, w) => n + (text.includes(w) ? 1 : 0), 0);

/** Every hand-built indicator for a message, as numbers in [0, 1], plus details for explanations. */
export function computeSignals(text) {
  const raw = String(text || '');
  const lower = raw.toLowerCase();
  const urls = extractUrls(raw);
  const letters = raw.replace(/[^a-z]/gi, '');
  const upperRatio = letters.length >= 12 ? raw.replace(/[^A-Z]/g, '').length / letters.length : 0;
  const bangs = (raw.match(/!/g) || []).length;

  let brand = null;
  const v = {
    hasUrl: urls.length > 0 ? 1 : 0,
    manyUrls: Math.min(Math.max(urls.length - 1, 0) / 3, 1),
    ipHost: urls.some(u => IPV4.test(u.host)) ? 1 : 0,
    shortener: urls.some(u => SHORTENERS.has(u.host)) ? 1 : 0,
    riskyTld: urls.some(u => RISKY_TLDS.has(u.host.split('.').pop())) ? 1 : 0,
    atInUrl: urls.some(u => u.at) ? 1 : 0,
    hyphenHost: urls.some(u => (u.host.match(/-/g) || []).length >= 2) ? 1 : 0,
    deepSubdomain: urls.some(u => !IPV4.test(u.host) && u.host.split('.').length >= 5) ? 1 : 0,
    plainHttp: urls.some(u => u.scheme === 'http') ? 1 : 0,
    punycode: urls.some(u => u.host.includes('xn--')) ? 1 : 0,
    lookalike: urls.some(u => (brand = brand || brandImpersonated(u.host))) ? 1 : 0,
    digitsInHost: urls.some(u => !IPV4.test(u.host) && (u.host.match(/\d/g) || []).length >= 4) ? 1 : 0,
    longUrl: urls.some(u => u.raw.length > 75) ? 1 : 0,
    credential: Math.min(countHits(lower, CREDENTIAL) / 2, 1),
    urgency: Math.min(countHits(lower, URGENCY) / 2, 1),
    lure: Math.min(countHits(lower, LURE) / 3, 1),
    shouting: Math.min(Math.max(upperRatio - 0.3, 0) * 2 + Math.min(bangs, 4) / 8, 1),
    length: Math.min(Math.log1p(raw.length) / Math.log1p(2000), 1),
  };
  return { values: v, urls, brand };
}

function tokens(lower) {
  return lower
    .replace(/https?:\/\/\S+/g, ' urltoken ')
    .split(/[^a-z0-9£$₹]+/)
    .filter(t => t.length > 1 && t.length < 30);
}

function addHashed(vec, offset, dim, key) {
  vec[offset + (fnv1a(key) % dim)] += 1;
}

function logNormalise(vec, offset, dim) {
  let sq = 0;
  for (let i = offset; i < offset + dim; i++) {
    if (vec[i] > 0) { vec[i] = Math.log1p(vec[i]); sq += vec[i] * vec[i]; }
  }
  if (sq > 0) {
    const n = Math.sqrt(sq);
    for (let i = offset; i < offset + dim; i++) if (vec[i] > 0) vec[i] /= n;
  }
}

/** Text → the model's input vector, plus the signal details used to explain a verdict. */
export function featurize(text) {
  const vec = new Float32Array(FEATURE_DIM);
  const lower = String(text || '').toLowerCase().slice(0, 4000);

  const words = tokens(lower);
  for (let i = 0; i < words.length; i++) {
    addHashed(vec, 0, WORD_DIM, `w:${words[i]}`);
    if (i + 1 < words.length) addHashed(vec, 0, WORD_DIM, `b:${words[i]}_${words[i + 1]}`);
  }
  logNormalise(vec, 0, WORD_DIM);

  const signals = computeSignals(text);
  for (const u of signals.urls) {
    const s = `^${u.host}${u.path.slice(0, 120)}$`;
    for (let i = 0; i + 3 <= s.length; i++) addHashed(vec, WORD_DIM, URL_DIM, s.slice(i, i + 3));
  }
  logNormalise(vec, WORD_DIM, URL_DIM);

  SIGNALS.forEach((s, i) => { vec[WORD_DIM + URL_DIM + i] = signals.values[s.key]; });
  return { vector: vec, signals };
}

/** Human-readable reasons for a message, strongest first. */
export function explain(signals) {
  const out = [];
  for (const s of SIGNALS) {
    if (!REASON_KEYS.has(s.key) || signals.values[s.key] < 0.5) continue;
    out.push(s.key === 'lookalike' && signals.brand
      ? `link imitates ${signals.brand} but is not its real domain`
      : s.label);
  }
  const order = ['lookalike', 'credential', 'ipHost', 'atInUrl', 'punycode', 'urgency', 'shortener', 'riskyTld', 'lure'];
  return out.sort((a, b) => {
    const ia = order.findIndex(k => SIGNALS.find(s => s.key === k)?.label === a || (k === 'lookalike' && a.startsWith('link imitates')));
    const ib = order.findIndex(k => SIGNALS.find(s => s.key === k)?.label === b || (k === 'lookalike' && b.startsWith('link imitates')));
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });
}
