// Run with `npm test` (node --test). Pure WebCrypto, no browser needed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  toHex, fromHex, hashLeaf, hashNode, buildTree, merkleRoot, inclusionProof,
  verifyInclusion, canonicalJson, leafForMessage, sortEntries, compareWithCheckpoint,
} from './merkle.js';

const sha = async (...parts) => {
  const buf = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0; for (const p of parts) { buf.set(p, o); o += p.length; }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
};

/** RFC 6962 §2.1 written literally, as an independent reference. */
async function referenceRoot(leafHashes) {
  const n = leafHashes.length;
  if (n === 0) return sha();
  if (n === 1) return leafHashes[0];
  let k = 1; while (k * 2 < n) k *= 2;
  return sha(Uint8Array.of(1), await referenceRoot(leafHashes.slice(0, k)), await referenceRoot(leafHashes.slice(k)));
}

const leavesOf = async (n) => Promise.all(
  Array.from({ length: n }, (_, i) => hashLeaf(new TextEncoder().encode(`message ${i}`))),
);

test('known Certificate Transparency test vectors', async () => {
  // The leaf inputs and roots used by the reference CT implementation.
  const inputs = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657',
    '606162636465666768696a6b6c6d6e6f'];
  const roots = [
    '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
    'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
    'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
    'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
    '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
    '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
    'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
    '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
  ];
  const leaves = await Promise.all(inputs.map(h => hashLeaf(fromHex(h)).then(toHex)));
  for (let n = 1; n <= 8; n++) {
    assert.equal(await merkleRoot(leaves.slice(0, n)), roots[n - 1], `root of ${n}`);
  }
  assert.equal(await merkleRoot([]), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});

test('bottom-up tree matches the RFC 6962 recursive definition for 0..100 leaves', async () => {
  for (let n = 0; n <= 100; n++) {
    const leaves = await leavesOf(n);
    assert.equal(await merkleRoot(leaves.map(toHex)), toHex(await referenceRoot(leaves)), `n=${n}`);
  }
});

test('every inclusion proof verifies, for every leaf of every tree up to 64', async () => {
  for (let n = 1; n <= 64; n++) {
    const leaves = (await leavesOf(n)).map(toHex);
    const tree = await buildTree(leaves);
    for (let i = 0; i < n; i++) {
      const path = inclusionProof(tree, i);
      assert.ok(path.length <= Math.ceil(Math.log2(n)), `path length n=${n} i=${i}`);
      assert.ok(await verifyInclusion({ leaf: leaves[i], index: i, size: n, path, root: tree.root }), `n=${n} i=${i}`);
    }
  }
});

test('a proof fails for the wrong leaf, index, size, sibling or root', async () => {
  const leaves = (await leavesOf(13)).map(toHex);
  const tree = await buildTree(leaves);
  const path = inclusionProof(tree, 6);
  const ok = { leaf: leaves[6], index: 6, size: 13, path, root: tree.root };
  assert.ok(await verifyInclusion(ok));
  assert.equal(await verifyInclusion({ ...ok, leaf: leaves[7] }), false);
  assert.equal(await verifyInclusion({ ...ok, index: 7 }), false);
  // A size that changes the shape of the path must fail. (A size with the same
  // shape, like 14 here, legitimately describes the same root.)
  assert.equal(await verifyInclusion({ ...ok, size: 7 }), false);
  assert.equal(await verifyInclusion({ ...ok, size: 6 }), false);
  assert.equal(await verifyInclusion({ ...ok, root: leaves[0] }), false);
  const bent = path.map((s, i) => (i === 1 ? { ...s, hash: leaves[0] } : s));
  assert.equal(await verifyInclusion({ ...ok, path: bent }), false);
  assert.equal(await verifyInclusion({ ...ok, path: path.slice(1) }), false);
});

test('an odd node is promoted, not duplicated (no CVE-2012-2459)', async () => {
  const [a, b, c] = (await leavesOf(3)).map(toHex);
  assert.notEqual(await merkleRoot([a, b, c]), await merkleRoot([a, b, c, c]));
});

test('domain separation: a node hash is not a leaf hash of the same bytes', async () => {
  const [l, r] = await leavesOf(2);
  const asNode = await hashNode(l, r);
  const asLeaf = await hashLeaf(new Uint8Array([...l, ...r]));
  assert.notEqual(toHex(asNode), toHex(asLeaf));
});

test('canonical JSON ignores key order and nesting order of keys', () => {
  assert.equal(canonicalJson({ b: 1, a: { d: [1, { z: 2, y: 3 }], c: 'x' } }),
               canonicalJson({ a: { c: 'x', d: [1, { y: 3, z: 2 }] }, b: 1 }));
});

test('leaf changes with sender, id, timestamp or payload, and not with key order', async () => {
  const base = { fromId: 'u1', id: 'm1', timestamp: '2026-01-01T00:00:00.000Z', payload: { v: 2, nonce: 'n', keys: { a: 1 } } };
  const leaf = await leafForMessage(base);
  assert.equal(leaf, await leafForMessage({ ...base, payload: { keys: { a: 1 }, nonce: 'n', v: 2 } }));
  assert.notEqual(leaf, await leafForMessage({ ...base, fromId: 'u2' }));
  assert.notEqual(leaf, await leafForMessage({ ...base, id: 'm2' }));
  assert.notEqual(leaf, await leafForMessage({ ...base, timestamp: '2026-01-01T00:00:00.001Z' }));
  assert.notEqual(leaf, await leafForMessage({ ...base, payload: { ...base.payload, nonce: 'm' } }));
  assert.notEqual(leaf, await leafForMessage({ ...base, deleted: true }));
});

test('checkpoint comparison names what changed', async () => {
  const mk = async (id, t, text, deleted = false) => ({
    id, timestamp: t, deleted,
    leaf: await leafForMessage({ fromId: 'u1', id, timestamp: t, payload: { text }, deleted }),
  });
  const old = sortEntries([
    await mk('a', '2026-01-01T00:00:01Z', 'one'),
    await mk('b', '2026-01-01T00:00:02Z', 'two'),
    await mk('c', '2026-01-01T00:00:03Z', 'three'),
  ]);
  const checkpoint = { entries: old, root: await merkleRoot(old.map(e => e.leaf)) };

  const same = await compareWithCheckpoint(checkpoint, [...old, await mk('d', '2026-01-01T00:00:04Z', 'four')]);
  assert.equal(same.status, 'ok');
  assert.equal(same.appended, 1);
  assert.equal(same.prefixRoot, checkpoint.root);

  const edited = await compareWithCheckpoint(checkpoint, [old[0], await mk('b', '2026-01-01T00:00:02Z', 'TWO'), old[2]]);
  assert.equal(edited.status, 'tampered');
  assert.deepEqual(edited.findings.map(f => [f.kind, f.id]), [['modified', 'b']]);

  const retimed = await compareWithCheckpoint(checkpoint, sortEntries([old[0], await mk('b', '2026-01-01T00:00:09Z', 'two'), old[2]]));
  assert.deepEqual(retimed.findings.map(f => [f.kind, f.id]), [['modified', 'b']]);

  const dropped = await compareWithCheckpoint(checkpoint, [old[0], old[2]]);
  assert.deepEqual(dropped.findings.map(f => [f.kind, f.id]), [['removed', 'b']]);

  const backdated = await compareWithCheckpoint(checkpoint, sortEntries([...old, await mk('x', '2026-01-01T00:00:02.500Z', 'forged')]));
  assert.deepEqual(backdated.findings.map(f => [f.kind, f.id]), [['inserted', 'x']]);

  const deleted = await compareWithCheckpoint(checkpoint, [old[0], await mk('b', '2026-01-01T00:00:02Z', '', true), old[2]]);
  assert.equal(deleted.status, 'benign');

  assert.equal((await compareWithCheckpoint(null, old)).status, 'first');
});
