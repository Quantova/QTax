// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const { network, stamper, iso, failing , PARTY_SECRET } = require('./chain');

const dirs = [];
test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'qtax-series-'));
  dirs.push(d);
  return d;
}

async function world() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = { intake: q.generateKey(), assessor: q.generateKey(), officer: q.generateKey(), officer2: q.generateKey() };
  const t0 = now - 80000;
  const filing = await at(q.file({ key: K.intake, taxpayer: 'NL-1', partySecret: PARTY_SECRET, ledger: false, period: '2026 Q3', form: 'VAT', content: Buffer.from('return'), receivedAt: iso(t0) }), t0 + 5);
  const assessment = await at(q.assess({ ledger: false, key: K.assessor, filing, outcome: Buffer.from('a'), currency: 'EUR', refundDue: '5000', decidedAt: iso(t0 + 100) }), t0 + 105);
  const refund1 = await at(q.refund({ ledger: false, key: K.officer, assessment, amount: '3000', first: true, paidAt: iso(t0 + 200) }), t0 + 205);
  const refund2 = await at(q.refund({ ledger: false, key: K.officer, assessment, amount: '2000', previous: refund1, paidAt: iso(t0 + 300) }), t0 + 305);
  const roles = { intakeKeys: [q.keyId(K.intake)], assessorKeys: [q.keyId(K.assessor)], officerKeys: [q.keyId(K.officer), q.keyId(K.officer2)] };
  const check = (env, type, more) => {
    net.chain.block(now);
    return q.verify(env, Object.assign({ type, filing, otherFilings: [filing], allSupplied: true }, type === 'refund' ? { assessment } : {}, roles, net.opts, more));
  };
  return { now, K, at, t0, filing, assessment, refund1, refund2, check };
}

test('every refund held for the return is given as refunds, and a second first refund is invalid', async () => {
  const w = await world();
  const ok = await w.check(w.refund2, 'refund', { refunds: [w.refund1, w.refund2], otherAssessments: [w.assessment] });
  assert.strictEqual(ok.status, 'valid', failing(ok).join('\n'));
  const sibling = await w.at(q.refund({ ledger: false, key: w.K.officer2, assessment: w.assessment, amount: '3000', first: true, paidAt: iso(w.t0 + 210) }), w.t0 + 215);
  const declared = await w.check(sibling, 'refund', {});
  assert.strictEqual(declared.status, 'indeterminate');
  assert.ok(declared.checks.some((c) => c.name === 'completeness' && !c.ok && c.indeterminate));
  const noAssessments = await w.check(sibling, 'refund', { refunds: [sibling] });
  assert.strictEqual(noAssessments.status, 'indeterminate');
  assert.ok(noAssessments.checks.some((c) => c.name === 'completeness' && !c.ok && c.indeterminate));
  const all = await w.check(sibling, 'refund', { refunds: [w.refund1, w.refund2, sibling], otherAssessments: [w.assessment] });
  assert.strictEqual(all.status, 'invalid');
  assert.ok(all.checks.some((c) => c.name === 'conflicting refund' && !c.ok));
  const older = await w.check(w.refund2, 'refund', { previousRefunds: [w.refund1], otherAssessments: [w.assessment] });
  assert.strictEqual(older.status, 'valid', failing(older).join('\n'));
  await assert.rejects(w.check(w.refund2, 'refund', { refunds: [w.refund1], previousRefunds: [w.refund1], otherAssessments: [w.assessment] }), (e) => e.code === 'QTAX_INVALID_INPUT');
});

test('an assessment declared complete without the other assessments of the return is indeterminate', async () => {
  const w = await world();
  const second = await w.at(q.assess({ ledger: false, key: w.K.assessor, filing: w.filing, outcome: Buffer.from('b'), currency: 'EUR', refundDue: '9000', decidedAt: iso(w.t0 + 110) }), w.t0 + 115);
  const bare = await w.check(second, 'assessment', {});
  assert.strictEqual(bare.status, 'indeterminate');
  const full = await w.check(second, 'assessment', { otherAssessments: [w.assessment, second] });
  assert.strictEqual(full.status, 'invalid');
});

test('with a ledger a second first refund or assessment and a refund after a stale previous are refused', async () => {
  const w = await world();
  const dir = folder();
  const filing = await w.at(q.file({ key: w.K.intake, taxpayer: 'NL-2', partySecret: PARTY_SECRET, ledger: false, period: '2026 Q3', form: 'VAT', content: Buffer.from('second return'), receivedAt: iso(w.t0 + 10) }), w.t0 + 15);
  const assess = (refundDue, more) => q.assess(Object.assign({ key: w.K.assessor, filing, outcome: Buffer.from('o ' + refundDue), currency: 'EUR', refundDue, decidedAt: iso(w.t0 + 120), ledger: dir }, more));
  const a1 = await assess('5000');
  await assert.rejects(assess('9000'), (e) => e.code === 'QTAX_LEDGER');
  const pay = (key, amount, more) => q.refund(Object.assign({ key, assessment: a1, amount, paidAt: iso(w.t0 + 220), ledger: dir }, more));
  const results = await Promise.allSettled([pay(w.K.officer, '3000', { first: true }), pay(w.K.officer2, '3000', { first: true })]);
  assert.strictEqual(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.strictEqual(results.find((r) => r.status === 'rejected').reason.code, 'QTAX_LEDGER');
  const r1 = results.find((r) => r.status === 'fulfilled').value;
  const r2 = await pay(w.K.officer, '1000', { previous: r1 });
  await assert.rejects(pay(w.K.officer, '1000', { previous: r1 }), (e) => e.code === 'QTAX_LEDGER');
  assert.deepStrictEqual(await q.ledgerLatest(dir, 'refund', q.refOf(filing)), r2);
  const plain = q.refund({ ledger: false, key: w.K.officer, assessment: a1, amount: '1', first: true, paidAt: iso(w.t0 + 230) });
  assert.strictEqual(typeof plain.then, 'undefined');
});
