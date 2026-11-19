// `npm test`. The verdict rules on top of toxic-bert's six label scores.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { judgeToxicity } from './toxicity.js';

const zero = { toxic: 0, severe_toxic: 0, obscene: 0, threat: 0, insult: 0, identity_hate: 0 };

test('clean text is not flagged', () => {
  assert.equal(judgeToxicity({ ...zero, toxic: 0.05 }).flagged, false);
});

test('the most serious label names the verdict', () => {
  const r = judgeToxicity({ ...zero, toxic: 0.93, insult: 0.8, identity_hate: 0.5 });
  assert.equal(r.flagged, true);
  assert.equal(r.category, 'identity_hate');
  assert.equal(r.description, 'hate speech targeting a group');
});

test('a threat is flagged even when general toxicity is moderate', () => {
  const r = judgeToxicity({ ...zero, toxic: 0.6, threat: 0.62 });
  assert.equal(r.category, 'threat');
});

test('mild profanity alone does not trip the obscene label', () => {
  assert.equal(judgeToxicity({ ...zero, toxic: 0.55, obscene: 0.6 }).flagged, false);
});
