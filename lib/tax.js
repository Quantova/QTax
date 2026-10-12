// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireSeed(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  return key;
}

function generateKey() {
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  if (seed.every((b) => b === 0)) throw new Error('the secure random source returned only zeros');
  return seed;
}

function publicKey(key) {
  return native.publicKey(requireSeed(key));
}

function keyId(key) {
  return F.keyIdOf(publicKey(key));
}

function describeKey(key) {
  const pk = publicKey(key);
  return { format: 'qtax-key/1', algorithm: F.ALGORITHM, id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') };
}

function randomHex(n) {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Buffer.from(b).toString('hex');
}

function textOption(value, max, what, required) {
  const v = value === undefined ? '' : value;
  const p = F.textProblem(v, max, what, required);
  if (p) F.reject(p);
  return v;
}

function timeOption(value, what) {
  const v = value === undefined ? new Date().toISOString() : value;
  const p = F.timeProblem(v, what);
  if (p) F.reject(p);
  return v;
}

function keyIdFrom(value, what) {
  if (typeof value === 'string') {
    if (!/^[0-9a-f]{64}$/.test(value)) F.reject(what + ' is a key id of 64 lowercase hex characters');
    return value;
  }
  if (value instanceof Uint8Array) return F.keyIdOf(value);
  if (value && typeof value === 'object' && value.format === 'qtax-key/1' && typeof value.publicKey === 'string') {
    const raw = Buffer.from(value.publicKey, 'base64');
    if (raw.toString('base64') !== value.publicKey) F.reject(what + ' holds a public key that is not canonical base64');
    const id = F.keyIdOf(raw);
    if (value.id !== undefined && value.id !== id) F.reject(what + ' names an id that does not match its public key');
    return id;
  }
  F.reject(what + ' is a key id, a public key or a qtax-key/1 description');
}

function digestOption(options, bytesKey, digestKey, what) {
  const given = [bytesKey, digestKey].filter((k) => options[k] !== undefined);
  if (given.length !== 1) F.reject('give exactly one of ' + bytesKey + ' or ' + digestKey);
  if (options[bytesKey] !== undefined) {
    if (!(options[bytesKey] instanceof Uint8Array)) F.reject(bytesKey + ' is a Uint8Array');
    return { digest: F.sha3(options[bytesKey]).toString('hex'), size: options[bytesKey].length };
  }
  const d = options[digestKey];
  if (typeof d !== 'string' || !/^[0-9a-f]{64}$/.test(d)) F.reject(digestKey + ' is 64 lowercase hex characters, the SHA3-256 of ' + what);
  return { digest: d, size: null };
}

function sign(type, statement, key) {
  const pk = publicKey(key);
  const problem = F.statementProblem(type, statement);
  if (problem) F.reject(problem);
  const message = F.payload(type, statement);
  const rnd = new Uint8Array(32);
  globalThis.crypto.getRandomValues(rnd);
  let signature;
  try {
    signature = native.sign(key, message, rnd);
  } finally {
    rnd.fill(0);
  }
  if (!native.verify(pk, message, signature)) throw new Error('the new signature did not verify, nothing was produced');
  return {
    format: F.FORMAT,
    type,
    algorithm: F.ALGORITHM,
    signer: { id: F.keyIdOf(pk), publicKey: Buffer.from(pk).toString('base64') },
    statement,
    signature: Buffer.from(signature).toString('base64'),
  };
}

function article(word) {
  return (/^[aeiou]/.test(word) ? 'an ' : 'a ') + word;
}

function signatureOk(p) {
  return p.signerId === F.keyIdOf(p.publicKey) && p.signerId === F.boundKey(p) && native.verify(p.publicKey, F.payload(p.type, p.statement), p.signature);
}

function signedEnvelope(envelope, type, what) {
  let p;
  try {
    p = F.parse(envelope);
  } catch (e) {
    F.reject(what + ' is not a valid envelope, ' + e.message);
  }
  if (p.type !== type) F.reject(what + ' must be ' + article(type) + ' envelope');
  if (!signatureOk(p)) F.reject(what + ' is not validly signed by the key it names');
  return p;
}

function commitParty(identity) {
  F.partyIdentity(identity);
  const salt = new Uint8Array(32);
  globalThis.crypto.getRandomValues(salt);
  return { salt, ref: F.partyRef(salt, identity) };
}

function file(options) {
  if (!options || typeof options !== 'object') F.reject('file needs options');
  requireSeed(options.key);
  if (typeof options.taxpayerRef !== 'string' || !/^[0-9a-f]{64}$/.test(options.taxpayerRef)) F.reject('taxpayerRef is the 64 hex character commitment from commitParty');
  const content = digestOption(options, 'content', 'contentDigest', 'the return');
  let size = content.size;
  if (size === null) {
    size = options.contentSize;
    if (typeof size !== 'number' || !Number.isSafeInteger(size) || size < 0) F.reject('contentSize is required with contentDigest');
  }
  const period = textOption(options.period, F.LABEL_MAX, 'period', true);
  const form = textOption(options.form, F.LABEL_MAX, 'form', true);
  const receivedAt = timeOption(options.receivedAt, 'receivedAt');
  let amends = '';
  let rootRef = '';
  if (options.amends !== undefined) {
    const prev = signedEnvelope(options.amends, 'filing', 'the filing amended');
    if (prev.statement.taxpayerRef !== options.taxpayerRef) F.reject('an amendment must concern the same taxpayer as the filing it amends');
    if (prev.statement.period !== period || prev.statement.form !== form) F.reject('an amendment must concern the same period and form as the filing it amends');
    if (Date.parse(receivedAt) < Date.parse(prev.statement.receivedAt)) F.reject('an amendment cannot be received before the filing it amends');
    amends = F.refOf(prev);
    rootRef = F.rootOf(prev);
  }
  return sign('filing', {
    filingId: randomHex(16),
    authorityKeyId: keyId(options.key),
    taxpayerRef: options.taxpayerRef,
    period,
    form,
    contentDigest: content.digest,
    contentSize: size,
    amends,
    rootRef,
    receivedAt,
    note: textOption(options.note, F.NOTE_MAX, 'note', false),
  }, options.key);
}

function invoice(options) {
  if (!options || typeof options !== 'object') F.reject('invoice needs options');
  requireSeed(options.key);
  const doc = digestOption(options, 'document', 'invoiceDigest', 'the invoice document');
  return sign('invoice', {
    invoiceId: textOption(options.invoiceId, F.LABEL_MAX, 'invoiceId', true),
    sellerKeyId: keyId(options.key),
    buyerKeyId: keyIdFrom(options.buyer, 'buyer'),
    invoiceDigest: doc.digest,
    currency: options.currency,
    total: options.total,
    tax: options.tax,
    issuedAt: timeOption(options.issuedAt, 'issuedAt'),
    note: textOption(options.note, F.NOTE_MAX, 'note', false),
  }, options.key);
}

function claim(options) {
  if (!options || typeof options !== 'object') F.reject('claim needs options');
  requireSeed(options.key);
  const inv = signedEnvelope(options.invoice, 'invoice', 'invoice');
  const buyer = keyId(options.key);
  if (buyer !== inv.statement.buyerKeyId) F.reject('only the buyer named on the invoice can claim it');
  const claimedAt = timeOption(options.claimedAt, 'claimedAt');
  if (Date.parse(claimedAt) < Date.parse(inv.statement.issuedAt)) F.reject('an invoice cannot be claimed before it was issued');
  return sign('claim', {
    claimId: randomHex(16),
    buyerKeyId: buyer,
    invoiceRef: F.refOf(inv),
    claimedAt,
    note: textOption(options.note, F.NOTE_MAX, 'note', false),
  }, options.key);
}

function assess(options) {
  if (!options || typeof options !== 'object') F.reject('assess needs options');
  requireSeed(options.key);
  const filing = signedEnvelope(options.filing, 'filing', 'filing');
  const assessor = keyId(options.key);
  if (assessor === filing.statement.authorityKeyId) F.reject('the assessor must not hold the key that received the filing');
  const outcome = digestOption(options, 'outcome', 'outcomeDigest', 'the assessment document');
  const decidedAt = timeOption(options.decidedAt, 'decidedAt');
  if (Date.parse(decidedAt) < Date.parse(filing.statement.receivedAt)) F.reject('an assessment cannot be decided before the filing was received');
  const filingRef = F.refOf(filing);
  const rootFilingRef = F.rootOf(filing);
  let seq = 1;
  let supersedes = '';
  if (options.supersedes !== undefined) {
    const prev = signedEnvelope(options.supersedes, 'assessment', 'the assessment superseded');
    if (prev.statement.rootFilingRef !== rootFilingRef) F.reject('an assessment can only supersede an assessment of the same return or of a filing it amends');
    if (options.currency !== prev.statement.currency) F.reject('a superseding assessment keeps the currency of the assessment it supersedes');
    if (Date.parse(decidedAt) < Date.parse(prev.statement.decidedAt)) F.reject('an assessment cannot be decided before the assessment it supersedes');
    if (prev.statement.seq >= F.SEQ_MAX) F.reject('this filing has reached the largest number of assessments');
    seq = prev.statement.seq + 1;
    supersedes = F.refOf(prev);
  }
  return sign('assessment', {
    assessmentId: randomHex(16),
    assessorKeyId: assessor,
    filingRef,
    rootFilingRef,
    seq,
    supersedes,
    outcomeDigest: outcome.digest,
    currency: options.currency,
    refundDue: options.refundDue === undefined ? '0' : options.refundDue,
    decidedAt,
    note: textOption(options.note, F.NOTE_MAX, 'note', false),
  }, options.key);
}

function refund(options) {
  if (!options || typeof options !== 'object') F.reject('refund needs options');
  requireSeed(options.key);
  const a = signedEnvelope(options.assessment, 'assessment', 'assessment');
  const officer = keyId(options.key);
  if (officer === a.statement.assessorKeyId) F.reject('the payment officer must not hold the key that decided the assessment');
  if (options.currency !== undefined && options.currency !== a.statement.currency) F.reject('a refund is paid in the currency of its assessment');
  if (typeof options.amount !== 'string' || !/^[1-9][0-9]{0,29}$/.test(options.amount)) F.reject('amount is a whole number of minor units greater than zero');
  if ((options.previous === undefined) === (options.first !== true)) F.reject('give the previous refund on this filing, or first set to true when no refund has been paid on it');
  const paidAt = timeOption(options.paidAt, 'paidAt');
  if (Date.parse(paidAt) < Date.parse(a.statement.decidedAt)) F.reject('a refund cannot be paid before its assessment was decided');
  let seq = 1;
  let prevRefundRef = '';
  let paidTotal = BigInt(options.amount);
  if (options.previous !== undefined) {
    const prev = signedEnvelope(options.previous, 'refund', 'the previous refund');
    if (prev.statement.rootFilingRef !== a.statement.rootFilingRef) F.reject('the previous refund was paid on another return');
    if (prev.statement.currency !== a.statement.currency) F.reject('the previous refund was paid in another currency');
    if (prev.statement.assessmentSeq > a.statement.seq) F.reject('the previous refund relied on a later assessment than this one');
    if (Date.parse(paidAt) < Date.parse(prev.statement.paidAt)) F.reject('a refund cannot be paid before the previous refund on the filing');
    if (prev.statement.seq >= F.SEQ_MAX) F.reject('this filing has reached the largest number of refunds');
    seq = prev.statement.seq + 1;
    prevRefundRef = F.refOf(prev);
    paidTotal += BigInt(prev.statement.paidTotal);
  }
  if (paidTotal > BigInt(a.statement.refundDue)) F.reject('this refund would take the refunds on the filing above the refund due on the assessment');
  return sign('refund', {
    refundId: randomHex(16),
    officerKeyId: officer,
    rootFilingRef: a.statement.rootFilingRef,
    assessmentRef: F.refOf(a),
    assessmentSeq: a.statement.seq,
    seq,
    prevRefundRef,
    currency: a.statement.currency,
    amount: options.amount,
    paidTotal: paidTotal.toString(),
    paidAt,
    note: textOption(options.note, F.NOTE_MAX, 'note', false),
  }, options.key);
}

function batch(envelopes) {
  const list = Array.isArray(envelopes) ? envelopes : [envelopes];
  if (list.length === 0) F.reject('at least one envelope is needed');
  const copies = list.map((e) => {
    try {
      return F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
  });
  const parsed = copies.map((e) => {
    const p = F.parse(e);
    if (!signatureOk(p)) F.reject('an envelope is not validly signed by the key it names');
    return p;
  });
  return { copies, parsed };
}

function attach(copies, receipts) {
  if (!Array.isArray(receipts) || receipts.length !== copies.length) throw new Error('the anchoring returned an unexpected number of receipts');
  return copies.map((e, i) => Object.assign({}, e, { anchor: receipts[i] }));
}

async function anchor(envelopes, options) {
  const { copies, parsed } = batch(envelopes);
  if (parsed.some((p) => p.anchor !== undefined)) F.reject('an envelope is already anchored');
  if (!options || typeof options !== 'object') F.reject('anchor needs the stamping options of a funded Quantova account');
  const records = parsed.map((p) => ({ alg: 'sha3-256', digest: F.anchorDigest(p) }));
  return attach(copies, await qstamp.stamp(Object.assign({}, options, { records, kind: F.KIND })));
}

async function complete(envelopes, pending, options) {
  const plain = (Array.isArray(envelopes) ? envelopes : [envelopes]).map((e) => {
    let c;
    try {
      c = F.plainCopy(e);
    } catch (err) {
      return F.reject('an envelope is not plain data');
    }
    if (c && typeof c === 'object' && !Array.isArray(c)) delete c.anchor;
    return c;
  });
  const { copies, parsed } = batch(plain);
  let p;
  try {
    p = F.plainCopy(pending);
  } catch (e) {
    F.reject('the pending stamp is not plain data');
  }
  if (!p || typeof p !== 'object' || !Array.isArray(p.records) || p.records.length !== parsed.length || String(p.kind) !== String(F.KIND)) {
    F.reject('the pending stamp does not belong to these envelopes');
  }
  parsed.forEach((c, i) => {
    const r = p.records[i];
    if (!r || r.alg !== 'sha3-256' || r.digest !== F.anchorDigest(c).toString('hex')) F.reject('the pending stamp does not belong to these envelopes, or they are in another order');
  });
  return attach(copies, await qstamp.complete(p, options || {}));
}

module.exports = {
  generateKey, publicKey, keyId, describeKey, keyIdFrom, commitParty, file, invoice, claim, assess, refund, anchor, complete, signedEnvelope, signatureOk,
};
