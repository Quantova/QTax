// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const { network , PARTY_SECRET } = require('./chain');

function assessed() {
  const now = Date.now();
  const net = network(Math.floor(now / 1000));
  const intake = q.generateKey();
  const assessor = q.generateKey();
  const filing = q.file({ forms: ['IB', 'ITR', 'VAT'], key: intake, taxpayer: 'TIN 1', partySecret: PARTY_SECRET, ledger: false, period: '2025', form: 'ITR', contentDigest: 'a'.repeat(64), contentSize: 10, receivedAt: new Date(now - 7200000).toISOString() });
  const first = q.assess({ ledger: false, key: assessor, filing, currency: 'EUR', refundDue: '500', outcomeDigest: 'b'.repeat(64), decidedAt: new Date(now - 3600000).toISOString() });
  const second = q.assess({ ledger: false, key: assessor, filing, currency: 'EUR', refundDue: '0', outcomeDigest: 'c'.repeat(64), supersedes: first, decidedAt: new Date(now - 1800000).toISOString() });
  const base = Object.assign({ type: 'assessment', partySecretId: q.partySecretId(PARTY_SECRET), forms: ['IB', 'ITR', 'VAT'], intakeKeys: [q.keyId(intake)], assessorKeys: [q.keyId(assessor)], filing, otherFilings: [filing], requireAnchor: false, at: new Date(now).toISOString() }, net.opts);
  return { first, second, base };
}

test('an assessment is never valid without the declaration that every assessment of the return was supplied', async () => {
  const s = assessed();
  const r = await q.verify(s.first, s.base);
  assert.strictEqual(r.valid, false);
  assert.strictEqual(r.status, 'indeterminate');
  assert.ok(r.checks.some((c) => c.name === 'completeness' && !c.ok));
});

test('a superseded assessment is never valid once the later one is supplied', async () => {
  const s = assessed();
  for (const extra of [{ allSupplied: true, otherAssessments: [s.second] }, { otherAssessments: [s.second] }]) {
    const r = await q.verify(s.first, Object.assign({}, s.base, extra));
    assert.strictEqual(r.valid, false);
    assert.ok(r.checks.some((c) => c.name === 'current' && !c.ok), JSON.stringify(r.checks.filter((c) => !c.ok)));
  }
});

test('the current assessment is valid when every assessment of the return is declared supplied', async () => {
  const s = assessed();
  const r = await q.verify(s.second, Object.assign({ allSupplied: true, previous: s.first, otherAssessments: [s.first] }, s.base));
  assert.strictEqual(r.status, 'valid', JSON.stringify(r.checks.filter((c) => !c.ok)));
  await assert.rejects(q.verify(s.first, Object.assign({ allSupplied: 'yes' }, s.base)), (e) => e.code === 'QTAX_INVALID_INPUT');
});
