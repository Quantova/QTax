// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const { network, stamper, iso } = require('./chain');

const never = () => new Promise(() => {});

async function world() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = { intake: q.generateKey(), assessor: q.generateKey(), officer: q.generateKey() };
  const t0 = now - 80000;
  const filing = await at(q.file({ key: K.intake, taxpayerRef: q.commitParty('NL-1').ref, period: '2026 Q3', form: 'VAT', content: Buffer.from('return'), receivedAt: iso(t0) }), t0 + 5);
  const assessment = await at(q.assess({ key: K.assessor, filing, outcome: Buffer.from('a'), currency: 'EUR', refundDue: '5000', decidedAt: iso(t0 + 100) }), t0 + 105);
  const refund = await at(q.refund({ key: K.officer, assessment, amount: '3000', first: true, paidAt: iso(now - 200) }), now - 100);
  const roles = { intakeKeys: [q.keyId(K.intake)], assessorKeys: [q.keyId(K.assessor)], officerKeys: [q.keyId(K.officer)] };
  const check = (more, clients) => {
    net.chain.block(now);
    const opts = clients ? { clients, trustCustomEndpoints: true } : net.opts;
    return q.verify(refund, Object.assign({ type: 'refund', assessment, filing, allSupplied: true, refunds: [refund], otherAssessments: [assessment] }, roles, opts, more));
  };
  return { net, check };
}

async function timed(work) {
  const started = Date.now();
  let timer;
  const cap = new Promise((resolve) => { timer = setTimeout(() => resolve('still running'), 5000); });
  try {
    const out = await Promise.race([work, cap]);
    return { out, ms: Date.now() - started };
  } finally {
    clearTimeout(timer);
  }
}

test('a key registry that never answers cannot hold verification past its time limit', async () => {
  const w = await world();
  const { out, ms } = await timed(w.check({ keyStatus: never, keyStatusTimeoutMs: 3600000, deadlineMs: 400 }));
  assert.notStrictEqual(out, 'still running');
  assert.ok(ms < 4000, String(ms));
  assert.strictEqual(out.status, 'indeterminate');
  assert.ok(out.checks.some((c) => c.name === 'time limit' && !c.ok && c.indeterminate));
  assert.ok(!out.checks.some((c) => /key status$/.test(c.name) && c.ok));
});

test('a gateway that stops answering cannot hold verification past its time limit', async () => {
  const w = await world();
  const stalled = w.net.clients.map((c) => Object.assign({}, c, { block: never, events: never, transaction: never }));
  const { out, ms } = await timed(w.check({ at: new Date().toISOString(), deadlineMs: 600 }, stalled));
  assert.notStrictEqual(out, 'still running');
  assert.ok(ms < 4000, String(ms));
  assert.strictEqual(out.status, 'indeterminate');
  assert.strictEqual(out.valid, false);
  assert.ok(out.checks.some((c) => c.name === 'time limit' && !c.ok && c.indeterminate));
});

test('a chain time that never arrives ends at the time limit with no result', async () => {
  const w = await world();
  const stalled = w.net.clients.map((c) => Object.assign({}, c, { nodeInfo: never }));
  const { out, ms } = await timed(w.check({ deadlineMs: 300 }, stalled).then(() => 'resolved', (e) => e));
  assert.notStrictEqual(out, 'still running');
  assert.ok(ms < 4000, String(ms));
  assert.strictEqual(out.code, 'QTAX_NO_CHAIN_TIME');
});

test('the time limit is a whole number of milliseconds within an hour', async () => {
  const w = await world();
  for (const deadlineMs of [0, -1, 1.5, 3600001, '100', null]) {
    await assert.rejects(w.check({ deadlineMs, at: new Date().toISOString() }), (e) => e.code === 'QTAX_INVALID_INPUT', String(deadlineMs));
  }
  const ok = await w.check({ deadlineMs: 3600000 });
  assert.strictEqual(ok.status, 'valid');
});

test('setting the wall clock back does not stretch the time limit', async () => {
  const w = await world();
  const real = Date.now;
  let calls = 0;
  Date.now = () => {
    calls += 1;
    return calls > 3 ? real() - 3600000 : real();
  };
  let out;
  let ms;
  try {
    ({ out, ms } = await timed(w.check({ at: new Date(real()).toISOString(), keyStatus: never, keyStatusTimeoutMs: 3000, deadlineMs: 400 })));
  } finally {
    Date.now = real;
  }
  assert.notStrictEqual(out, 'still running');
  assert.ok(ms < 2500, String(ms));
  assert.ok(out.checks.some((c) => c.name === 'time limit' && !c.ok));
});
