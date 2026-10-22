'use strict';

const q = require('..');
const { network, stamper, iso , PARTY_SECRET } = require('./chain');

async function honest() {
  const now = Math.floor(Date.now() / 1000);
  const net = network(now - 86400);
  const at = stamper(q, net);
  const K = { intake: q.generateKey(), assessor: q.generateKey(), officer: q.generateKey(), seller: q.generateKey(), buyer: q.generateKey() };
  const t0 = now - 80000;
  const content = Buffer.from('income tax return 2025');
  const document = Buffer.from('invoice scan');
  const outcome = Buffer.from('assessment decision');
  const filing = await at(q.file({ key: K.intake, taxpayer: 'NL-123456789', partySecret: PARTY_SECRET, ledger: false, period: '2025', form: 'IB', content, receivedAt: iso(t0) }), t0 + 5);
  const invoice = await at(q.invoice({ key: K.seller, invoiceId: 'INV-2025-0042', buyer: q.keyId(K.buyer), document, currency: 'EUR', total: '121000', tax: '21000', issuedAt: iso(t0 + 10) }), t0 + 15);
  const claim = await at(q.claim({ key: K.buyer, invoice, claimedAt: iso(t0 + 20) }), t0 + 25);
  const assessment = await at(q.assess({ ledger: false, key: K.assessor, filing, outcome, currency: 'EUR', refundDue: '5000', decidedAt: iso(t0 + 30) }), t0 + 35);
  const first = await at(q.refund({ ledger: false, key: K.officer, assessment, amount: '2000', first: true, paidAt: iso(t0 + 40) }), t0 + 45);
  const refund = await at(q.refund({ ledger: false, key: K.officer, assessment, amount: '1500', previous: first, paidAt: iso(t0 + 50) }), t0 + 55);
  net.chain.block(now);
  const roles = { intakeKeys: [q.keyId(K.intake)], assessorKeys: [q.keyId(K.assessor)], officerKeys: [q.keyId(K.officer)] };
  const common = Object.assign({ at: iso(now) }, net.opts);
  const options = {
    filing: Object.assign({ type: 'filing', content }, roles, common),
    invoice: Object.assign({ type: 'invoice', sellerKeyId: q.keyId(K.seller), document }, common),
    claim: Object.assign({ type: 'claim', sellerKeyId: q.keyId(K.seller), invoice, otherClaims: [] }, common),
    assessment: Object.assign({ type: 'assessment', outcome, filing, otherAssessments: [], otherFilings: [filing], allSupplied: true }, roles, common),
    refund: Object.assign({ type: 'refund', assessment, filing, previousRefunds: [first], otherAssessments: [assessment], otherFilings: [filing], allSupplied: true }, roles, common),
  };
  return { q, net, now, K, at, roles, options, all: { filing, invoice, claim, assessment, refund }, first };
}

module.exports = { honest };
