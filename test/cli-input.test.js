'use strict';

const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert');
const q = require('..');
const F = require('../lib/format');
const { cliCampaign, runCli, tempDir, SAYS_VALID } = require('./fuzz');

const BIN = path.join(__dirname, '..', 'bin', 'qtax.js');
const ENVELOPE_MAX = 1024 * 1024;

function records() {
  const now = Date.now();
  const iso = (ms) => new Date(ms).toISOString();
  const K = { intake: q.generateKey(), assessor: q.generateKey(), officer: q.generateKey(), seller: q.generateKey(), buyer: q.generateKey() };
  const content = Buffer.from('income tax return 2025');
  const filing = q.file({ key: K.intake, taxpayerRef: q.commitParty('NL-123456789').ref, period: '2025', form: 'IB', content, receivedAt: iso(now - 600000) });
  const assessment = q.assess({ key: K.assessor, filing, outcome: Buffer.from('decision'), currency: 'EUR', refundDue: '5000', decidedAt: iso(now - 500000) });
  const invoice = q.invoice({ key: K.seller, invoiceId: 'INV-2025-0042', buyer: q.keyId(K.buyer), document: Buffer.from('scan'), currency: 'EUR', total: '121000', tax: '21000', issuedAt: iso(now - 400000) });
  const claim = q.claim({ key: K.buyer, invoice, claimedAt: iso(now - 300000) });
  return { at: iso(now), K, filing, assessment, invoice, claim, contentDigest: F.sha3(content).toString('hex') };
}

async function control(argv, file, env) {
  fs.writeFileSync(file, JSON.stringify(env));
  const r = await runCli(BIN, argv);
  assert.strictEqual(r.code, 0, r.out + r.err);
  assert.ok(SAYS_VALID.test(r.out), r.out);
}

test('hostile invoice files make every command that reads an envelope exit non zero quickly and never print VALID', async (t) => {
  const w = records();
  const dir = tempDir('qtax-ok');
  try {
    const good = path.join(dir, 'invoice.json');
    const claim = path.join(dir, 'claim.json');
    const pending = path.join(dir, 'pending.json');
    fs.writeFileSync(claim, JSON.stringify(w.claim));
    fs.writeFileSync(pending, JSON.stringify({ records: [], kind: '1101' }));
    const tail = ['--allow-unanchored', '--at', w.at];
    const seller = ['--seller', q.keyId(w.K.seller)];
    await control(['verify', good, '--type', 'invoice'].concat(seller, tail), good, w.invoice);
    await control(['verify', claim, '--type', 'claim', '--invoice', good].concat(seller, tail), good, w.invoice);
    const results = await cliCampaign({
      bin: BIN,
      tag: 'qtax-cli',
      cap: ENVELOPE_MAX,
      validText: JSON.stringify(w.invoice),
      commands: [
        (file) => ['verify', file, '--type', 'invoice'].concat(seller, tail),
        (file) => ['verify', file, '--type', 'invoice'].concat(seller, tail, ['--json']),
        (file) => ['verify', claim, '--type', 'claim', '--invoice', file].concat(seller, tail),
        (file) => ['complete', file, '--pending', pending],
      ],
    });
    t.diagnostic(results.length + ' runs, slowest ' + Math.max(...results.map((r) => r.ms)) + ' ms');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('hostile filing files make verify exit non zero quickly and never print VALID, also when given as the filing of an assessment', async (t) => {
  const w = records();
  const dir = tempDir('qtax-ok');
  try {
    const good = path.join(dir, 'filing.json');
    const assessment = path.join(dir, 'assessment.json');
    fs.writeFileSync(assessment, JSON.stringify(w.assessment));
    const tail = ['--allow-unanchored', '--at', w.at];
    const intake = ['--intake', q.keyId(w.K.intake)];
    const assessed = ['--type', 'assessment', '--assessor', q.keyId(w.K.assessor), '--all-supplied'].concat(intake);
    await control(['verify', good, '--type', 'filing', '--content-digest', w.contentDigest].concat(intake, tail), good, w.filing);
    await control(['verify', assessment, '--filing', good].concat(assessed, tail), good, w.filing);
    const results = await cliCampaign({
      bin: BIN,
      tag: 'qtax-cli',
      cap: ENVELOPE_MAX,
      validText: JSON.stringify(w.filing),
      commands: [
        (file) => ['verify', file, '--type', 'filing', '--content-digest', w.contentDigest].concat(intake, tail),
        (file) => ['verify', assessment, '--filing', file].concat(assessed, tail, ['--json']),
      ],
    });
    t.diagnostic(results.length + ' runs, slowest ' + Math.max(...results.map((r) => r.ms)) + ' ms');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
