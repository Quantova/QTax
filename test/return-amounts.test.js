'use strict';

const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const F = require('../lib/format');
const native = require('../lib/native');
const { network, stamper, iso, failing } = require('./chain');
const { mulberry32, iterations, describe } = require('./fuzz');

const ROUNDS = iterations(50);

function tools(rng) {
  const int = (n) => Math.floor(rng() * n);
  const digits = (len) => {
    let s = String(1 + int(9));
    for (let i = 1; i < len; i += 1) s += String(int(10));
    return s;
  };
  const below = (n) => (n <= 0n ? 0n : BigInt(digits(n.toString().length + 3)) % n);
  const hex = (n) => Array.from({ length: n }, () => int(16).toString(16)).join('');
  const bytes = (n) => Uint8Array.from({ length: n }, () => int(256));
  const pick = (a) => a[int(a.length)];
  return { int, digits, below, hex, bytes, pick };
}

function signRaw(r, type, st, key) {
  const sig = native.sign(key, F.payload(type, st), r.bytes(32));
  return { format: F.FORMAT, type, algorithm: F.ALGORITHM, signer: { id: q.keyId(key), publicKey: Buffer.from(q.publicKey(key)).toString('base64') }, statement: st, signature: Buffer.from(sig).toString('base64') };
}

function edited(env, field, value) {
  const out = JSON.parse(JSON.stringify(env));
  out.statement[field] = value;
  return out;
}

function otherAmount(r, old) {
  const n = BigInt(old);
  const options = [
    () => (n + 1n).toString(),
    () => (n > 1n ? (n - 1n).toString() : '2'),
    () => old + '0',
    () => '0' + old,
    () => (n * 2n).toString(),
    () => '-' + old,
    () => old + '.0',
    () => Number(old),
    () => r.digits(1 + r.int(30)),
    () => old + ' ',
    () => '1e' + old.length,
  ];
  for (;;) {
    const v = r.pick(options)();
    if (v !== old) return v;
  }
}

async function books(rng) {
  const r = tools(rng);
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = { intake: q.generateKey(), assessor: q.generateKey(), officer: q.generateKey(), stranger: q.generateKey() };
  const roles = { intakeKeys: [q.keyId(K.intake)], assessorKeys: [q.keyId(K.assessor)], officerKeys: [q.keyId(K.officer)] };
  let t = now - 80000;
  const next = () => (t += 20);
  const content = Buffer.from('return ' + r.hex(12));
  const filing = await at(q.file({ key: K.intake, taxpayerRef: q.commitParty('NL-' + r.digits(9)).ref, period: '2025', form: 'IB', content, receivedAt: iso(next()) }), t + 1);
  const due = BigInt(r.digits(2 + r.int(28)));
  const assessment = await at(q.assess({ key: K.assessor, filing, outcome: Buffer.from('decision ' + due), currency: 'EUR', refundDue: due.toString(), decidedAt: iso(next()) }), t + 1);
  const a1 = 1n + r.below(due - 1n);
  const first = await at(q.refund({ key: K.officer, assessment, amount: a1.toString(), first: true, paidAt: iso(next()) }), t + 1);
  const a2 = 1n + r.below(due - a1);
  const second = await at(q.refund({ key: K.officer, assessment, amount: a2.toString(), previous: first, paidAt: iso(next()) }), t + 1);
  const forge = (key, fields) => {
    const st = Object.assign({}, second.statement, { refundId: r.hex(32), officerKeyId: q.keyId(key), paidAt: iso(next()) }, fields);
    return at(signRaw(r, 'refund', st, key), t + 1);
  };
  const check = (refund, supplied) => {
    net.chain.block(now);
    const s = supplied || {};
    return q.verify(refund, Object.assign({ type: 'refund', assessment: s.assessment || assessment, filing, previousRefunds: s.previous || [first], otherAssessments: [s.assessment || assessment], allSupplied: true, at: iso(now) }, roles, net.opts));
  };
  return { r, K, next, assessment, first, second, due, a1, a2, forge, check };
}

const failed = (res, name) => res.checks.some((c) => c.name === name && !c.ok);

test('a refund, its earlier refund or its assessment with an amount edited after signing never verifies valid', async (t) => {
  const rng = mulberry32(0x7a0001);
  const counts = { rounds: ROUNDS, edits: 0 };
  for (let round = 0; round < ROUNDS; round += 1) {
    const b = await books(rng);
    const honest = await b.check(b.second);
    assert.strictEqual(honest.status, 'valid', failing(honest).join('\n'));
    const targets = [
      ['second', 'amount'], ['second', 'paidTotal'], ['first', 'amount'], ['first', 'paidTotal'], ['assessment', 'refundDue'],
    ];
    for (let k = 0; k < 5; k += 1) {
      const [which, field] = b.r.pick(targets);
      const value = otherAmount(b.r, b[which].statement[field]);
      const env = edited(b[which], field, value);
      const res = which === 'second' ? await b.check(env) : which === 'first' ? await b.check(b.second, { previous: [env] }) : await b.check(b.second, { assessment: env });
      assert.strictEqual(res.status, 'invalid', which + ' ' + field + ' edited to ' + describe(value) + ' verified ' + res.status);
      counts.edits += 1;
    }
  }
  t.diagnostic(JSON.stringify(counts));
});

test('a refund signed again by the payment officer with amounts that do not add up or that exceed the refund due never verifies valid, while a consistent one does', async (t) => {
  const rng = mulberry32(0x7a0002);
  const counts = { rounds: ROUNDS, amount: 0, paidTotal: 0, overDue: 0, consistent: 0, stranger: 0, firstMismatch: 0, assessmentDue: 0 };
  for (let round = 0; round < ROUNDS; round += 1) {
    const b = await books(rng);
    const { a1, a2, due } = b;
    const sum = a1 + a2;
    if (sum - 1n >= 2n) {
      let amount = 1n + b.r.below(sum - 1n);
      if (amount === a2) amount = amount === 1n ? 2n : amount - 1n;
      const res = await b.check(await b.forge(b.K.officer, { amount: amount.toString() }));
      assert.strictEqual(res.status, 'invalid', 'amount ' + amount + ' with paid total ' + sum + ' after ' + a1 + ' verified ' + res.status);
      assert.ok(failed(res, 'refund chain'), failing(res).join('\n'));
      counts.amount += 1;
    }
    let paidTotal = a2 + 1n + b.r.below(due + a1);
    if (paidTotal === sum) paidTotal += 1n;
    const bad = await b.check(await b.forge(b.K.officer, { paidTotal: paidTotal.toString() }));
    assert.strictEqual(bad.status, 'invalid', 'paid total ' + paidTotal + ' instead of ' + sum + ' verified ' + bad.status);
    assert.ok(failed(bad, 'refund chain'), failing(bad).join('\n'));
    counts.paidTotal += 1;
    const over = due - a1 + 1n + b.r.below(1000n);
    const high = await b.check(await b.forge(b.K.officer, { amount: over.toString(), paidTotal: (a1 + over).toString() }));
    assert.strictEqual(high.status, 'invalid', 'refunds totalling ' + (a1 + over) + ' above the ' + due + ' due verified ' + high.status);
    assert.ok(failed(high, 'refund total'), failing(high).join('\n'));
    counts.overDue += 1;
    const fair = 1n + b.r.below(due - a1);
    const ok = await b.check(await b.forge(b.K.officer, { amount: fair.toString(), paidTotal: (a1 + fair).toString() }));
    assert.strictEqual(ok.status, 'valid', 'a consistent refund of ' + fair + ' signed directly was refused, ' + failing(ok).join('\n'));
    counts.consistent += 1;
    const foreign = await b.check(await b.forge(b.K.stranger, {}));
    assert.strictEqual(foreign.status, 'invalid', 'a refund signed by a key that is not a trusted officer verified ' + foreign.status);
    assert.ok(failed(foreign, 'officer'), failing(foreign).join('\n'));
    counts.stranger += 1;
    const lone = Object.assign({}, b.first.statement, { refundId: b.r.hex(32), paidTotal: (a1 + 1n + b.r.below(due)).toString(), paidAt: iso(b.next()) });
    const loneRes = await b.check(signRaw(b.r, 'refund', lone, b.K.officer), { previous: [] });
    assert.strictEqual(loneRes.status, 'invalid', 'a first refund whose paid total differs from its amount verified ' + loneRes.status);
    counts.firstMismatch += 1;
    const lower = (a1 + a2 > 1n ? b.r.below(a1 + a2) : 0n).toString();
    const reassessed = signRaw(b.r, 'assessment', Object.assign({}, b.assessment.statement, { assessmentId: b.r.hex(32), refundDue: lower }), b.K.assessor);
    const lowRes = await b.check(b.second, { assessment: reassessed });
    assert.strictEqual(lowRes.status, 'invalid', 'a refund checked against an assessment signed again with a refund due of ' + lower + ' verified ' + lowRes.status);
    counts.assessmentDue += 1;
  }
  t.diagnostic(JSON.stringify(counts));
});

test('an invoice whose total or tax was changed is never valid and never supports a claim on the original invoice', async (t) => {
  const rng = mulberry32(0x7a0003);
  const r = tools(rng);
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const seller = q.generateKey();
  const buyer = q.generateKey();
  const stranger = q.generateKey();
  const counts = { rounds: ROUNDS * 2, unsigned: 0, taxAboveTotal: 0, otherSeller: 0, claimAgainstChanged: 0 };
  let tt = now - 80000;
  const common = Object.assign({ at: iso(now) }, net.opts);
  for (let round = 0; round < ROUNDS * 2; round += 1) {
    const total = BigInt(r.digits(1 + r.int(30)));
    const tax = r.below(total + 1n);
    const document = Buffer.from('invoice ' + round + ' ' + r.hex(8));
    const invoice = await at(q.invoice({ key: seller, invoiceId: 'INV-' + r.digits(6), buyer: q.keyId(buyer), document, currency: 'EUR', total: total.toString(), tax: tax.toString(), issuedAt: iso((tt += 20)) }), tt + 1);
    const claim = await at(q.claim({ key: buyer, invoice, claimedAt: iso((tt += 20)) }), tt + 1);
    net.chain.block(now);
    const vInvoice = (env) => q.verify(env, Object.assign({ type: 'invoice', sellerKeyId: q.keyId(seller), document }, common));
    const vClaim = (inv) => q.verify(claim, Object.assign({ type: 'claim', sellerKeyId: q.keyId(seller), invoice: inv, otherClaims: [] }, common));
    const honest = await vInvoice(invoice);
    assert.strictEqual(honest.status, 'valid', failing(honest).join('\n'));
    const honestClaim = await vClaim(invoice);
    assert.strictEqual(honestClaim.status, 'valid', failing(honestClaim).join('\n'));
    const field = r.pick(['total', 'tax']);
    const value = otherAmount(r, invoice.statement[field]);
    const changed = edited(invoice, field, value);
    const res = await vInvoice(changed);
    assert.strictEqual(res.status, 'invalid', 'invoice ' + field + ' edited to ' + describe(value) + ' verified ' + res.status);
    const cres = await vClaim(changed);
    assert.strictEqual(cres.status, 'invalid', 'a claim verified against an invoice whose ' + field + ' became ' + describe(value));
    counts.unsigned += 1;
    const above = signRaw(r, 'invoice', Object.assign({}, invoice.statement, { tax: (total + 1n + r.below(1000n)).toString() }), seller);
    assert.strictEqual((await vInvoice(above)).status, 'invalid', 'an invoice with tax above its total verified');
    counts.taxAboveTotal += 1;
    const resigned = signRaw(r, 'invoice', Object.assign({}, invoice.statement, { sellerKeyId: q.keyId(stranger), total: (total + 1n).toString() }), stranger);
    assert.strictEqual((await vInvoice(resigned)).status, 'invalid', 'an invoice signed by another seller verified');
    counts.otherSeller += 1;
    const moved = r.digits(1 + r.int(30));
    const sellerResigned = await at(signRaw(r, 'invoice', Object.assign({}, invoice.statement, { total: moved, tax: '0' }), seller), (tt += 20));
    net.chain.block(now);
    const moveRes = await vClaim(sellerResigned);
    assert.strictEqual(moveRes.status, 'invalid', 'a claim verified against an invoice signed again with total ' + moved);
    assert.ok(failed(moveRes, 'invoice'), failing(moveRes).join('\n'));
    counts.claimAgainstChanged += 1;
  }
  t.diagnostic(JSON.stringify(counts));
});

test('a filing whose content size was changed never verifies against the return it describes', async (t) => {
  const rng = mulberry32(0x7a0004);
  const r = tools(rng);
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const intake = q.generateKey();
  const counts = { rounds: ROUNDS, unsigned: 0, resigned: 0 };
  let tt = now - 80000;
  for (let round = 0; round < ROUNDS; round += 1) {
    const content = Buffer.from('return ' + r.hex(2 + r.int(200)));
    const filing = await at(q.file({ key: intake, taxpayerRef: q.commitParty('NL-' + r.digits(9)).ref, period: '2025', form: 'IB', content, receivedAt: iso((tt += 20)) }), tt + 1);
    net.chain.block(now);
    const v = (env) => q.verify(env, Object.assign({ type: 'filing', content, intakeKeys: [q.keyId(intake)], at: iso(now) }, net.opts));
    const honest = await v(filing);
    assert.strictEqual(honest.status, 'valid', failing(honest).join('\n'));
    const size = r.pick([content.length + 1, content.length - 1, 0, content.length * 2, content.length + 1 + r.int(1e6)]);
    const res = await v(edited(filing, 'contentSize', size));
    assert.strictEqual(res.status, 'invalid', 'content size edited to ' + size + ' verified ' + res.status);
    counts.unsigned += 1;
    const again = await at(signRaw(r, 'filing', Object.assign({}, filing.statement, { filingId: r.hex(32), contentSize: size }), intake), (tt += 20));
    net.chain.block(now);
    const res2 = await v(again);
    assert.strictEqual(res2.status, 'invalid', 'a filing signed again with content size ' + size + ' verified ' + res2.status);
    assert.ok(failed(res2, 'content'), failing(res2).join('\n'));
    counts.resigned += 1;
  }
  t.diagnostic(JSON.stringify(counts));
});
