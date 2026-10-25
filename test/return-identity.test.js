// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const q = require('..');
const { network, PARTY_SECRET } = require('./chain');

const FORMS = ['IB', 'ITR', 'VAT', 'VAT100'];
const OTHER_SECRET = Uint8Array.from({ length: 32 }, (_, i) => (91 + 7 * i) & 255);

function world() {
  const now = Date.now();
  const net = network(Math.floor(now / 1000));
  const intake = q.generateKey();
  const assessor = q.generateKey();
  const officer = q.generateKey();
  const iso = (ms) => new Date(ms).toISOString();
  const file = (more) => q.file(Object.assign({ forms: FORMS, key: intake, taxpayer: 'NL-123456789', partySecret: PARTY_SECRET, ledger: false, period: '2025-01', form: 'VAT', contentDigest: 'a'.repeat(64), contentSize: 10, receivedAt: iso(now - 7200000) }, more));
  const base = (type, more) => Object.assign({ type, partySecretId: q.partySecretId(PARTY_SECRET), forms: FORMS, intakeKeys: [q.keyId(intake)], assessorKeys: [q.keyId(assessor)], officerKeys: [q.keyId(officer)], requireAnchor: false, at: iso(now) }, net.opts, more);
  return { now, iso, intake, assessor, officer, file, base };
}

function failing(r) {
  return JSON.stringify(r.checks.filter((c) => !c.ok));
}

test('a period is accepted only as YYYY, YYYY-MM or YYYY-Qn and every other spelling is refused', () => {
  const w = world();
  for (const period of ['2025', '2025-01', '2025-12', '2025-Q1', '2025-q4']) assert.ok(w.file({ period }), period);
  for (const period of ['202501', '01/2025', '2025-1', '2025 01', '2025-13', '2025-Q5', 'Jan 2025', '2025-001', '']) {
    assert.throws(() => w.file({ period }), (e) => e.code === 'QTAX_INVALID_INPUT' && /YYYY, YYYY-MM or YYYY-Qn/.test(e.message), period);
  }
  assert.strictEqual(w.file({ period: '2025-q4' }).statement.period, '2025-Q4');
});

test('a form is a code from the list of the authority and a code outside it is refused', () => {
  const w = world();
  assert.ok(w.file({ form: 'VAT100' }));
  for (const form of ['VAT return', 'vat', 'V', 'VAT-100', 'PAYE']) {
    assert.throws(() => w.file({ form }), (e) => e.code === 'QTAX_INVALID_INPUT', form);
  }
  assert.throws(() => w.file({ forms: undefined }), (e) => e.code === 'QTAX_INVALID_INPUT' && /forms/.test(e.message));
});

test('the same return filed twice through the ledger is refused however the period was written', async () => {
  const w = world();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qtax-identity-'));
  try {
    await w.file({ ledger: dir, period: '2025-Q1' });
    await assert.rejects(w.file({ ledger: dir, period: '2025-q1' }), (e) => e.code === 'QTAX_LEDGER');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a filing never verifies valid without the other filings held for its return', async () => {
  const w = world();
  const filing = w.file();
  const r = await q.verify(filing, w.base('filing'));
  assert.strictEqual(r.valid, false);
  assert.ok(r.checks.some((c) => c.name === 'duplicate return' && !c.ok), failing(r));
  const ok = await q.verify(filing, w.base('filing', { otherFilings: [filing], contentDigest: 'a'.repeat(64) }));
  assert.strictEqual(ok.status, 'valid', failing(ok));
});

test('a filing made with another party secret never verifies valid for the authority', async () => {
  const w = world();
  const own = w.file();
  const other = w.file({ partySecret: OTHER_SECRET });
  assert.notStrictEqual(own.statement.taxpayerRef, other.statement.taxpayerRef);
  const r = await q.verify(other, w.base('filing', { otherFilings: [own, other] }));
  assert.strictEqual(r.valid, false);
  assert.ok(r.checks.some((c) => c.name === 'party secret' && !c.ok), failing(r));
  const missing = await q.verify(own, Object.assign(w.base('filing', { otherFilings: [own] }), { partySecretId: undefined }));
  assert.strictEqual(missing.valid, false);
  assert.strictEqual(missing.status, 'indeterminate');
});

test('another original of the same taxpayer and period under another form leaves the filing indeterminate', async () => {
  const w = world();
  const vat = w.file({ form: 'VAT' });
  const vat100 = w.file({ form: 'VAT100' });
  const r = await q.verify(vat100, w.base('filing', { otherFilings: [vat, vat100] }));
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.status, 'indeterminate');
  assert.ok(r.checks.some((c) => c.name === 'other form' && !c.ok), failing(r));
});

test('an assessment of a filing that a later amendment replaced is refused through the ledger and never verifies valid', async () => {
  const w = world();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'qtax-amend-'));
  try {
    const original = await w.file({ ledger: dir });
    const amendment = await w.file({ ledger: dir, amends: original, receivedAt: w.iso(w.now - 5400000) });
    const assess = (filing) => q.assess({ ledger: dir, key: w.assessor, filing, currency: 'EUR', refundDue: '5000', outcomeDigest: 'b'.repeat(64), decidedAt: w.iso(w.now - 3600000) });
    await assert.rejects(assess(original), (e) => e.code === 'QTAX_LEDGER' && /amended the filing/.test(e.message));
    const current = await assess(amendment);
    assert.strictEqual(current.statement.filingRef, q.refOf(amendment));
    const stale = q.assess({ ledger: false, key: w.assessor, filing: original, currency: 'EUR', refundDue: '5000', outcomeDigest: 'b'.repeat(64), decidedAt: w.iso(w.now - 3600000) });
    const r = await q.verify(stale, w.base('assessment', { filing: original, otherFilings: [original, amendment], otherAssessments: [], allSupplied: true }));
    assert.strictEqual(r.valid, false);
    assert.ok(r.checks.some((c) => c.name === 'latest filing' && !c.ok), failing(r));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
