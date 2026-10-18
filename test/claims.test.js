// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const q = require('..');
const F = require('../lib/format');
const native = require('../lib/native');
const { network, stamper, iso, failing } = require('./chain');

function signAs(key, type, statement) {
  const pk = native.publicKey(key);
  const sig = native.sign(key, F.payload(type, statement), Uint8Array.from(crypto.randomBytes(32)));
  return { format: F.FORMAT, type, algorithm: F.ALGORITHM, signer: { id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') }, statement, signature: Buffer.from(sig).toString('base64') };
}

async function world() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 3600);
  const at = stamper(q, net);
  const seller = q.generateKey();
  const buyer = q.generateKey();
  const intruder = q.generateKey();
  const t0 = now - 3000;
  const invoice = await at(q.invoice({ key: seller, buyer: q.keyId(buyer), invoiceId: 'INV-2026-0042', document: Buffer.from('invoice pdf'), currency: 'EUR', total: '121000', tax: '21000', issuedAt: iso(t0) }), t0 + 5);
  const invoiceRef = F.refOf(F.parse(invoice));
  const foreignClaim = (key, offset) => signAs(key, 'claim', { claimId: crypto.randomBytes(16).toString('hex'), buyerKeyId: q.keyId(key), invoiceRef, claimedAt: iso(t0 + offset), note: '' });
  const forged = await at(foreignClaim(intruder, 10), t0 + 15);
  const sellers = await at(foreignClaim(seller, 11), t0 + 16);
  const genuine = await at(q.claim({ key: buyer, invoice, claimedAt: iso(t0 + 60) }), t0 + 65);
  return { now, net, at, seller, buyer, intruder, t0, invoice, invoiceRef, foreignClaim, forged, sellers, genuine };
}

function opts(w, extra) {
  return Object.assign({ type: 'claim', invoice: w.invoice, sellerKeyId: q.keyId(w.seller) }, w.net.opts, extra);
}

test('a claim signed by any key other than the buyer on the invoice never counts as a double claim', async () => {
  const w = await world();
  w.net.chain.block(w.now);
  const alone = await q.verify(w.genuine, opts(w, { otherClaims: [] }));
  assert.strictEqual(alone.status, 'valid', failing(alone).join('\n'));
  for (const other of [w.forged, w.sellers]) {
    const r = await q.verify(w.genuine, opts(w, { otherClaims: [other] }));
    assert.strictEqual(r.status, 'valid', failing(r).join('\n'));
    assert.ok(r.checks.find((c) => c.name === 'double claim').ok);
  }
  const control = await q.verify(w.forged, opts(w, { otherClaims: [] }));
  assert.strictEqual(control.status, 'invalid');
});

test('an earlier claim by the buyer on the same invoice still makes a later one invalid', async () => {
  const w = await world();
  const second = await w.at(q.claim({ key: w.buyer, invoice: w.invoice, claimedAt: iso(w.t0 + 120) }), w.t0 + 125);
  w.net.chain.block(w.now);
  const later = await q.verify(second, opts(w, { otherClaims: [w.forged, w.genuine] }));
  assert.strictEqual(later.status, 'invalid');
  assert.match(later.checks.find((c) => c.name === 'double claim' && !c.ok).detail, /already claimed/);
  const first = await q.verify(w.genuine, opts(w, { otherClaims: [second] }));
  assert.strictEqual(first.status, 'valid', failing(first).join('\n'));
});

test('other claims cannot be judged without the invoice, so the result is indeterminate', async () => {
  const w = await world();
  w.net.chain.block(w.now);
  const r = await q.verify(w.genuine, Object.assign({ type: 'claim', sellerKeyId: q.keyId(w.seller), otherClaims: [w.forged] }, w.net.opts));
  assert.strictEqual(r.status, 'indeterminate', failing(r).join('\n'));
  const dc = r.checks.find((c) => c.name === 'double claim');
  assert.ok(dc && !dc.ok && dc.indeterminate);
});

test('claims by other keys cost no anchor checks and the anchor checks of buyer claims are capped', async () => {
  const w = await world();
  w.net.chain.block(w.now);
  await q.verify(w.genuine, opts(w, { otherClaims: [] }));
  let before = w.net.chain.reads;
  await q.verify(w.genuine, opts(w, { otherClaims: [] }));
  const baseline = w.net.chain.reads - before;
  const many = [];
  for (let i = 0; i < 40; i += 1) many.push(Object.assign({}, w.foreignClaim(w.intruder, 70 + i), { anchor: w.forged.anchor }));
  before = w.net.chain.reads;
  const r = await q.verify(w.genuine, opts(w, { otherClaims: many }));
  assert.strictEqual(w.net.chain.reads - before, baseline);
  assert.strictEqual(r.status, 'valid', failing(r).join('\n'));
  const own = [];
  for (let i = 0; i < 20; i += 1) own.push(q.claim({ key: w.buyer, invoice: w.invoice, claimedAt: iso(w.t0 + 200 + i) }));
  const anchored = await w.at(own, w.t0 + 230);
  w.net.chain.block(w.now + 1);
  before = w.net.chain.reads;
  await q.verify(w.genuine, opts(w, { otherClaims: anchored.slice(0, 16) }));
  const sixteen = w.net.chain.reads - before;
  before = w.net.chain.reads;
  const capped = await q.verify(w.genuine, opts(w, { otherClaims: anchored }));
  assert.strictEqual(w.net.chain.reads - before, sixteen);
  assert.ok(sixteen > baseline);
  assert.strictEqual(capped.status, 'indeterminate', failing(capped).join('\n'));
  assert.match(capped.checks.find((c) => c.name === 'double claim').detail, /more than 16/);
});

test('options are read only from the object given and never from Object.prototype', async () => {
  const w = await world();
  w.net.chain.block(w.now);
  const plain = q.claim({ key: w.buyer, invoice: w.invoice, claimedAt: iso(w.now - 30) });
  const before = await q.verify(plain, opts(w, { otherClaims: [] }));
  assert.strictEqual(before.status, 'indeterminate');
  try {
    Object.prototype.requireAnchor = false;
    Object.prototype.allSupplied = true;
    const after = await q.verify(plain, opts(w, { otherClaims: [] }));
    assert.strictEqual(after.status, 'indeterminate', failing(after).join('\n'));
  } finally {
    delete Object.prototype.requireAnchor;
    delete Object.prototype.allSupplied;
  }
});
