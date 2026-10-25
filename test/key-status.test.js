// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const { network, stamper, iso, failing , PARTY_SECRET } = require('./chain');

async function world() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = { intake: q.generateKey(), assessor: q.generateKey(), officer: q.generateKey() };
  const t0 = now - 80000;
  const filing = await at(q.file({ forms: ['IB', 'ITR', 'VAT'], key: K.intake, taxpayer: 'NL-1', partySecret: PARTY_SECRET, ledger: false, period: '2026-Q3', form: 'VAT', content: Buffer.from('return'), receivedAt: iso(t0) }), t0 + 5);
  const assessment = await at(q.assess({ ledger: false, key: K.assessor, filing, outcome: Buffer.from('a'), currency: 'EUR', refundDue: '5000', decidedAt: iso(t0 + 100) }), t0 + 105);
  const refund = await at(q.refund({ ledger: false, key: K.officer, assessment, amount: '3000', first: true, paidAt: iso(now - 200) }), now - 100);
  const check = (env, more, keys) => {
    net.chain.block(now);
    const roles = Object.assign({ partySecretId: q.partySecretId(PARTY_SECRET), forms: ['IB', 'ITR', 'VAT'], intakeKeys: [q.keyId(K.intake)], assessorKeys: [q.keyId(K.assessor)], officerKeys: [q.keyId(K.officer)] }, keys);
    return q.verify(env, Object.assign({ type: 'refund', assessment, filing, otherFilings: [filing], allSupplied: true, refunds: [refund], otherAssessments: [assessment] }, roles, net.opts, more));
  };
  return { now, K, t0, refund, check, officer: q.keyId(K.officer) };
}

const statusOf = (r) => r.checks.filter((c) => /key status$/.test(c.name));

test('a key the registry revoked before a record was anchored makes the record invalid', async () => {
  const w = await world();
  const ok = await w.check(w.refund, { keyStatus: async () => ({ revoked: false }) });
  assert.strictEqual(ok.status, 'valid', failing(ok).join('\n'));
  assert.ok(statusOf(ok).length >= 3 && statusOf(ok).every((c) => c.ok));
  const retired = (id) => (id === w.officer ? { revoked: true, revokedAt: w.now - 3600 } : { revoked: false });
  const bad = await w.check(w.refund, { keyStatus: retired });
  assert.strictEqual(bad.status, 'invalid');
  assert.ok(bad.checks.some((c) => c.name === 'officer key status' && !c.ok && !c.indeterminate));
  const later = await w.check(w.refund, { keyStatus: (id) => (id === w.officer ? { revoked: true, revokedAt: w.now - 10 } : { revoked: false }) });
  assert.strictEqual(later.status, 'valid', failing(later).join('\n'));
});

test('a registry answer that is malformed, fails or is late leaves the result indeterminate', async () => {
  const w = await world();
  for (const keyStatus of [() => ({ revoked: 'yes' }), () => ({ revoked: true, revokedAt: 1.5 }), () => { throw new Error('down'); }, () => new Promise(() => {})]) {
    const r = await w.check(w.refund, { keyStatus, keyStatusTimeoutMs: 50 });
    assert.strictEqual(r.status, 'indeterminate', failing(r).join('\n'));
  }
  await assert.rejects(w.check(w.refund, { keyStatus: 'no' }), (e) => e.code === 'QTAX_INVALID_INPUT');
  await assert.rejects(w.check(w.refund, { keyStatusTimeoutMs: 10 }), (e) => e.code === 'QTAX_INVALID_INPUT');
});

test('a trusted key may carry the period it is trusted for, enforced against proven anchor times', async () => {
  const w = await world();
  const until = (s) => ({ officerKeys: [{ key: w.officer, until: iso(s) }] });
  const inPeriod = await w.check(w.refund, {}, until(w.now - 50));
  assert.strictEqual(inPeriod.status, 'valid', failing(inPeriod).join('\n'));
  const after = await w.check(w.refund, {}, until(w.now - 150));
  assert.strictEqual(after.status, 'invalid');
  assert.ok(after.checks.some((c) => c.name === 'officer key period' && !c.ok));
  const before = await w.check(w.refund, {}, { officerKeys: [{ key: w.officer, from: iso(w.now - 60) }] });
  assert.strictEqual(before.status, 'invalid');
  const bare = Object.assign({}, w.refund);
  delete bare.anchor;
  const open = await w.check(bare, {}, until(w.now - 50));
  assert.strictEqual(open.status, 'indeterminate');
  await assert.rejects(w.check(w.refund, {}, { officerKeys: [{ key: w.officer, until: 'soon' }] }), (e) => e.code === 'QTAX_INVALID_INPUT');
  await assert.rejects(w.check(w.refund, {}, { officerKeys: [{ key: w.officer, from: iso(w.now), until: iso(w.now - 10) }] }), (e) => e.code === 'QTAX_INVALID_INPUT');
});
