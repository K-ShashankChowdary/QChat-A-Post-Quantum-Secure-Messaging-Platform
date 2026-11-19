// `npm run test:toxicity`. Runs the real Xenova/toxic-bert model (downloads
// ~110 MB once into the Transformers.js cache) — TC-05 of the report.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadToxicityModel, analyzeToxicity } from './toxicity.js';

const SAFE = ['hey, are we still on for lunch tomorrow?', 'this exam was so hard lol', 'can you send me the slides', 'i hate mondays'];
const ABUSIVE = [
  'you are a worthless idiot and everyone hates you',
  'I will find you and kill you',
  'shut up you stupid moron',
];

test('TC-05 (report Table 5.1): abusive text is flagged by the local transformer, ordinary text is not', { timeout: 600_000 }, async () => {
  await loadToxicityModel();
  for (const t of SAFE) assert.equal((await analyzeToxicity(t)).flagged, false, t);
  for (const t of ABUSIVE) {
    const r = await analyzeToxicity(t);
    assert.equal(r.flagged, true, t);
    assert.ok(r.description);
  }
  const threat = await analyzeToxicity('I will find you and kill you');
  assert.equal(threat.category, 'threat');
});
