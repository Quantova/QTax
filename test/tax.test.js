// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const { network, stamper, iso, failing, proofs, SEED } = require('./chain');

const qstampBase = path.dirname(require.resolve('@quantovainc/qstamp'));
const { core } = require(require.resolve('@quantovainc/qcore', { paths: [qstampBase] }));

async function paid() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = { intake: q.generateKey(), assessor: q.generateKey(), officer: q.generateKey(), stranger: q.generateKey() };
  const t0 = now - 80000;
  const filing = await at(q.file({ key: K.intake, taxpayerRef: q.commitParty('NL-1').ref, period: '2025', form: 'IB', content: Buffer.from('return'), receivedAt: iso(t0) }), t0 + 5);
  const other = await at(q.file({ key: K.intake, taxpayerRef: q.commitParty('NL-2').ref, period: '2025', form: 'IB', content: Buffer.from('other return'), receivedAt: iso(t0) }), t0 + 5);
  const assessment = await at(q.assess({ key: K.assessor, filing, outcome: Buffer.from('ok'), currency: 'EUR', refundDue: '1000', decidedAt: iso(t0 + 10) }), t0 + 15);
  const foreign = await at(q.assess({ key: K.assessor, filing: other, outcome: Buffer.from('ok'), currency: 'EUR', refundDue: '10', decidedAt: iso(t0 + 10) }), t0 + 15);
  const rogue = await at(q.assess({ key: K.stranger, filing, outcome: Buffer.from('other'), currency: 'EUR', refundDue: '9000', decidedAt: iso(t0 + 30) }), t0 + 35);
  const refund = await at(q.refund({ key: K.officer, assessment, amount: '500', first: true, paidAt: iso(t0 + 20) }), t0 + 25);
  net.chain.block(now);
  const opts = Object.assign({ type: 'refund', assessment, filing, allSupplied: true, refunds: [refund], otherAssessments: [assessment], intakeKeys: [q.keyId(K.intake)], assessorKeys: [q.keyId(K.assessor)], officerKeys: [q.keyId(K.officer)] }, net.opts);
  return { net, refund, assessment, foreign, rogue, opts };
}

test('a refund with only its own assessment supplied stays valid', async () => {
  const p = await paid();
  const r = await q.verify(p.refund, Object.assign({}, p.opts, { otherAssessments: [p.assessment] }));
  assert.strictEqual(r.status, 'valid', failing(r).join('\n'));
});

test('a malformed, untrusted or foreign supplied assessment makes the result invalid', async () => {
  const p = await paid();
  for (const bad of [{ format: 'qtax/1', junk: true }, p.rogue, p.foreign]) {
    const r = await q.verify(p.refund, Object.assign({}, p.opts, { otherAssessments: [p.assessment, bad] }));
    assert.strictEqual(r.status, 'invalid', failing(r).join('\n'));
    assert.ok(r.checks.some((c) => /^supplied assessment 2$/.test(c.name) && !c.ok));
  }
});

test('a malformed earlier refund supplied with a later refund makes the result invalid', async () => {
  const p = await paid();
  const o = Object.assign({}, p.opts, { previousRefunds: [{ junk: 1 }] });
  delete o.refunds;
  const r = await q.verify(p.refund, o);
  assert.strictEqual(r.status, 'invalid', failing(r).join('\n'));
});

test('verification refuses to fall back to the local clock', async () => {
  const p = await paid();
  const stale = p.net.clients.map((c) => Object.assign({}, c, { nodeInfo: async () => ({ chain_id: p.net.chain.chainId, genesis_hash: p.net.chain.genesis, head_height: p.refund.anchor.anchor.height }) }));
  await assert.rejects(q.verify(p.refund, Object.assign({}, p.opts, { trustCustomEndpoints: true, clients: stale })), (e) => e.code === 'QTAX_NO_CHAIN_TIME');
  const given = await q.verify(p.refund, Object.assign({}, p.opts, { trustCustomEndpoints: true, clients: stale, at: new Date().toISOString() }));
  assert.strictEqual(given.status, 'valid', failing(given).join('\n'));
});

test('an anchor that is not proven makes the result indeterminate and never valid', async () => {
  const p = await paid();
  try {
    proofs(false);
    const r = await q.verify(p.refund, p.opts);
    assert.strictEqual(r.status, 'indeterminate');
    assert.ok(r.checks.some((c) => c.name === 'anchor proof' && !c.ok && c.indeterminate));
    const lax = await q.verify(p.refund, Object.assign({}, p.opts, { requireAnchor: false }));
    assert.notStrictEqual(lax.status, 'valid');
  } finally {
    proofs(true);
  }
});

test('endpoints chosen by the caller need trustCustomEndpoints, loopback needs allowLoopback and the anchor sender is checked', async () => {
  const p = await paid();
  const o = Object.assign({}, p.opts, { at: new Date().toISOString() });
  delete o.trustCustomEndpoints;
  const untrusted = await q.verify(p.refund, o);
  assert.strictEqual(untrusted.status, 'indeterminate');
  const loop = Object.assign({}, p.opts, { at: new Date().toISOString(), rpc: 'http://127.0.0.1:9' });
  delete loop.clients;
  const lr = await q.verify(p.refund, loop);
  assert.strictEqual(lr.status, 'indeterminate');
  assert.ok(lr.checks.some((c) => /loopback/.test(c.detail)));
  const wrong = await q.verify(p.refund, Object.assign({}, p.opts, { expectedSender: core.address(new Uint8Array(32).fill(9), 0) }));
  assert.strictEqual(wrong.status, 'invalid');
  const right = await q.verify(p.refund, Object.assign({}, p.opts, { expectedSender: core.address(SEED, 0) }));
  assert.strictEqual(right.status, 'valid', failing(right).join('\n'));
});
