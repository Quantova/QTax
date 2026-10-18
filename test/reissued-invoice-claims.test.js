// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const { network, stamper, iso, failing } = require('./chain');

test('a claim on a re-issued copy of an invoice already claimed is invalid', async () => {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = { seller: q.generateKey(), buyer: q.generateKey(), other: q.generateKey() };
  const t0 = now - 80000;
  const invoice = (key, id, doc, t) => at(q.invoice({ key, invoiceId: id, buyer: q.describeKey(K.buyer), document: Buffer.from(doc), currency: 'EUR', total: '1210', tax: '210', issuedAt: iso(t) }), t + 5);
  const original = await invoice(K.seller, 'INV 1', 'inv', t0);
  const first = await at(q.claim({ key: K.buyer, invoice: original, claimedAt: iso(t0 + 100) }), t0 + 105);
  const copy = await invoice(K.seller, 'inv-1', 'inv again', t0 + 200);
  const sameDoc = await invoice(K.seller, 'INV 77', 'inv', t0 + 210);
  const unrelated = await invoice(K.other, 'INV 1', 'other seller', t0 + 220);
  const claimOf = (inv, t) => at(q.claim({ key: K.buyer, invoice: inv, claimedAt: iso(t) }), t + 5);
  const check = (claim, inv, more) => {
    net.chain.block(now);
    return q.verify(claim, Object.assign({ type: 'claim', invoice: inv, sellerKeyId: inv.statement.sellerKeyId }, net.opts, more));
  };
  const byId = await claimOf(copy, t0 + 300);
  const r1 = await check(byId, copy, { otherClaims: [first], otherInvoices: [original] });
  assert.strictEqual(r1.status, 'invalid');
  assert.ok(r1.checks.some((c) => c.name === 'double claim' && !c.ok && !c.indeterminate));
  const byDoc = await claimOf(sameDoc, t0 + 310);
  const r2 = await check(byDoc, sameDoc, { otherClaims: [first], otherInvoices: [original] });
  assert.strictEqual(r2.status, 'invalid');
  const unknown = await check(byId, copy, { otherClaims: [first] });
  assert.strictEqual(unknown.status, 'indeterminate');
  const fine = await claimOf(unrelated, t0 + 320);
  const r3 = await check(fine, unrelated, { otherClaims: [first], otherInvoices: [original] });
  assert.strictEqual(r3.status, 'valid', failing(r3).join('\n'));
  const firstAgain = await check(first, original, { otherClaims: [byId], otherInvoices: [copy] });
  assert.strictEqual(firstAgain.status, 'valid', failing(firstAgain).join('\n'));
});
