// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const test = require('node:test');
const assert = require('node:assert');
const { spawnSync } = require('child_process');
const { honest } = require('./honest');
const { iso } = require('./chain');

const BIN = path.join(__dirname, '..', 'bin', 'qtax.js');
const dirs = [];

test.after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

function folder() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'qtax-series-'));
  dirs.push(d);
  return d;
}

const refused = (e) => e.code === 'QTAX_LEDGER';

function state(q, name, seq, env) {
  return JSON.stringify({ format: 'qtax-series/1', series: name, seq, ref: q.refOf(env), envelope: env }) + '\n';
}

function store(answer) {
  let text = null;
  return {
    async read() {
      return text;
    },
    async compareAndSwap(name, expected, next) {
      if (answer === true && expected === text) text = next;
      return answer;
    },
  };
}

test('a custom ledger store is trusted only when compareAndSwap answers exactly true', async () => {
  const w = await honest();
  const { q, K, all } = w;
  const assess = (ledger) => q.assess({ key: K.assessor, filing: all.filing, outcome: Buffer.from('decision'), currency: 'EUR', refundDue: '5000', decidedAt: iso(w.now - 60), ledger });
  const held = 'qtax.assessment.' + all.assessment.statement.rootFilingRef;
  const withAssessment = (s) => ({ read: async (name) => (name === held ? state(q, held, 1, all.assessment) : s.read(name)), compareAndSwap: s.compareAndSwap });
  const refund = (ledger) => q.refund({ key: K.officer, assessment: all.assessment, amount: '1000', first: true, paidAt: iso(w.now - 60), ledger: withAssessment(ledger) });
  for (const make of [assess, refund]) {
    assert.strictEqual((await make(store(true))).statement.seq, 1);
    await assert.rejects(make(store(false)), (e) => refused(e) && /another/.test(e.message));
    for (const odd of [{ acknowledged: true, matchedCount: 0, modifiedCount: 0 }, 1, 'true', null, undefined, [true]]) {
      await assert.rejects(make(store(odd)), (e) => refused(e) && /true or false/.test(e.message), String(odd));
    }
  }
});

test('a ledger entry whose position, type or return differs from the envelope inside it is refused', async () => {
  const w = await honest();
  const { q, all, first } = w;
  const root = all.refund.statement.rootFilingRef;
  const fixed = (text) => ({ read: async () => text, compareAndSwap: async () => false });
  const name = 'qtax.refund.' + root;
  assert.deepStrictEqual(await q.ledgerLatest(fixed(state(q, name, 2, all.refund)), 'refund', root), all.refund);
  await assert.rejects(q.ledgerLatest(fixed(state(q, name, 1, all.refund)), 'refund', root), refused);
  await assert.rejects(q.ledgerLatest(fixed(state(q, name, 3, all.refund)), 'refund', root), refused);
  await assert.rejects(q.ledgerLatest(fixed(state(q, 'qtax.assessment.' + root, 2, all.refund)), 'assessment', root), refused);
  await assert.rejects(q.ledgerLatest(fixed(state(q, 'qtax.assessment.' + root, 1, first)), 'assessment', root), refused);
  const other = 'cd'.repeat(32);
  await assert.rejects(q.ledgerLatest(fixed(state(q, 'qtax.refund.' + other, 2, all.refund)), 'refund', other), refused);
});

test('the folder ledger never follows a symbolic link, refuses an entry filed under another position and reads without listing the folder', async () => {
  const w = await honest();
  const { q, all, first } = w;
  const root = all.refund.statement.rootFilingRef;
  const name = 'qtax.refund.' + root;
  const dir = folder();
  const outside = folder();
  fs.writeFileSync(path.join(outside, 'entry.json'), state(q, name, 1, first));
  if (process.platform !== 'win32') {
    fs.symlinkSync(path.join(outside, 'entry.json'), path.join(dir, name + '.1.json'));
    await assert.rejects(q.ledgerLatest(dir, 'refund', root), (e) => refused(e) && /not a small regular file/.test(e.message));
    fs.rmSync(path.join(dir, name + '.1.json'));
  }
  fs.writeFileSync(path.join(dir, name + '.1.json'), state(q, name, 1, first));
  fs.writeFileSync(path.join(dir, name + '.2.json'), state(q, name, 1, first));
  await assert.rejects(q.ledgerLatest(dir, 'refund', root), (e) => refused(e) && /does not hold position 2/.test(e.message));
  fs.writeFileSync(path.join(dir, name + '.2.json'), state(q, name, 2, all.refund));
  fs.writeFileSync(path.join(dir, 'qtax.assessment.' + root + '.1.json'), state(q, 'qtax.assessment.' + root, 1, all.assessment));
  for (let i = 0; i < 200; i += 1) fs.writeFileSync(path.join(dir, 'qtax.refund.' + crypto.randomBytes(32).toString('hex') + '.1.json'), '');
  const list = fs.readdirSync;
  fs.readdirSync = () => {
    throw new Error('the folder was listed');
  };
  try {
    assert.deepStrictEqual(await q.ledgerLatest(dir, 'refund', root), all.refund);
  } finally {
    fs.readdirSync = list;
  }
  const third = await q.refund({ key: w.K.officer, assessment: all.assessment, amount: '500', previous: all.refund, paidAt: iso(w.now - 30), ledger: dir });
  assert.strictEqual(third.statement.seq, 3);
  assert.deepStrictEqual(await q.ledgerLatest(dir, 'refund', root), third);
  fs.rmSync(path.join(dir, name + '.2.json'));
  const before = fs.readdirSync(dir).length;
  await assert.rejects(q.refund({ key: w.K.officer, assessment: all.assessment, amount: '500', previous: first, paidAt: iso(w.now - 20), ledger: dir }), (e) => refused(e) && /missing a record/.test(e.message));
  assert.strictEqual(fs.readdirSync(dir).length, before);
});

test('the command line refuses an assessment or a refund unless --ledger or --no-ledger is given', async () => {
  const w = await honest();
  const { K, all } = w;
  const dir = folder();
  const write = (file, value) => {
    fs.writeFileSync(path.join(dir, file), typeof value === 'string' ? value : JSON.stringify(value), { mode: 0o600 });
    return path.join(dir, file);
  };
  const assessor = write('assessor.key', Buffer.from(K.assessor).toString('hex') + '\n');
  const officer = write('officer.key', Buffer.from(K.officer).toString('hex') + '\n');
  const filing = write('filing.json', all.filing);
  const outcome = write('outcome.pdf', 'decision');
  const ledger = path.join(dir, 'ledger');
  fs.mkdirSync(ledger);
  const due = write('due.txt', '5000\n');
  const run = (args, input) => spawnSync(process.execPath, [BIN].concat(args), { encoding: 'utf8', cwd: dir, input });
  const assess = (more, out) => run(['assess', '--key', assessor, '--filing', filing, '--outcome', outcome, '--currency', 'EUR', '--refund-due-file', due, '--out', path.join(dir, out)].concat(more));
  const bare = assess([], 'a0.json');
  assert.strictEqual(bare.status, 64, bare.stderr);
  assert.match(bare.stderr, /an assessment is part of the series of its return, so give --ledger/);
  const both = assess(['--ledger', ledger, '--no-ledger'], 'a1.json');
  assert.strictEqual(both.status, 64, both.stderr);
  assert.match(both.stderr, /not both/);
  const one = assess(['--ledger', ledger], 'a2.json');
  assert.strictEqual(one.status, 0, one.stderr);
  const two = assess(['--ledger', ledger], 'a3.json');
  assert.strictEqual(two.status, 1, two.stderr);
  assert.match(two.stderr, /already holds/);
  assert.strictEqual(assess(['--no-ledger'], 'a4.json').status, 0);
  const assessment = path.join(dir, 'a2.json');
  const refund = (more, out) => run(['refund', '--key', officer, '--assessment', assessment, '--amount-file', '-', '--first', '--out', path.join(dir, out)].concat(more), '1000\n');
  const rbare = refund([], 'r0.json');
  assert.strictEqual(rbare.status, 64, rbare.stderr);
  assert.match(rbare.stderr, /a refund is part of the series of its return/);
  assert.ok(!fs.existsSync(path.join(dir, 'r0.json')));
  assert.strictEqual(refund(['--ledger', ledger], 'r1.json').status, 0);
  const again = refund(['--ledger', ledger], 'r2.json');
  assert.strictEqual(again.status, 1, again.stderr);
  assert.strictEqual(refund(['--no-ledger'], 'r3.json').status, 0);
  const help = run(['help']);
  assert.match(help.stdout, /\(--ledger DIR \| --no-ledger\)/);
});

test('a QTax ledger folder any user can write is refused', async () => {
  const w = await honest();
  const { q, all } = w;
  const root = all.refund.statement.rootFilingRef;
  const open = folder();
  fs.chmodSync(open, 0o777);
  await assert.rejects(q.ledgerLatest(open, 'refund', root), (e) => refused(e) && /every user of this machine/.test(e.message));
});

test('a QTax ledger under a folder any user can change, or with an access control list, is refused', async () => {
  const w = await honest();
  const { q, all } = w;
  const root = all.refund.statement.rootFilingRef;
  const open = folder();
  fs.chmodSync(open, 0o777);
  const inside = path.join(open, 'ledger');
  fs.mkdirSync(inside, { mode: 0o700 });
  await assert.rejects(q.ledgerLatest(inside, 'refund', root), (e) => refused(e) && /above the ledger can be changed by another user/.test(e.message));
  const listed = folder();
  const acl = process.platform === 'darwin'
    ? spawnSync('chmod', ['+a', 'everyone allow add_file,delete_child', listed])
    : spawnSync('setfacl', ['-m', 'u:nobody:rwx', listed]);
  if (acl.status === 0) await assert.rejects(q.ledgerLatest(listed, 'refund', root), (e) => refused(e) && /access control list/.test(e.message));
});

test('a QTax ledger reached through a symbolic link or a parent that another user can change is refused, and a name past the largest position never blocks it', async () => {
  const w = await honest();
  const { q, all } = w;
  const root = all.refund.statement.rootFilingRef;
  const CODE = 'QTAX_LEDGER';
  const OPEN = (d) => q.ledgerLatest(d, 'refund', root);
  const stray = folder();
  fs.writeFileSync(path.join(stray, 'qtax.refund.' + root + '.1000001.json'), 'stray');
  assert.strictEqual(await q.ledgerLatest(stray, 'refund', root), null);

  const parentAcl = folder();
  const underAcl = path.join(parentAcl, 'ledger');
  fs.mkdirSync(underAcl, { mode: 0o700 });
  const set = process.platform === 'darwin' ? spawnSync('chmod', ['+a', 'everyone allow add_file,delete_child,add_subdirectory', parentAcl]) : spawnSync('setfacl', ['-m', 'u:nobody:rwx', parentAcl]);
  if (set.status === 0) await assert.rejects(OPEN(underAcl), (e) => e.code === CODE && /can be changed by another user/.test(e.message));
  const safeTarget = folder();
  const openHolder = folder();
  fs.chmodSync(openHolder, 0o777);
  const linkInOpen = path.join(openHolder, 'ledger');
  fs.symlinkSync(safeTarget, linkInOpen);
  await assert.rejects(OPEN(linkInOpen), (e) => e.code === CODE && /can be changed by another user/.test(e.message));
  const openTop = folder();
  fs.chmodSync(openTop, 0o777);
  const realUp = folder();
  fs.mkdirSync(path.join(realUp, 'ledger'), { mode: 0o700 });
  fs.symlinkSync(realUp, path.join(openTop, 'up'));
  await assert.rejects(OPEN(path.join(openTop, 'up', 'ledger')), (e) => e.code === CODE && /can be changed by another user/.test(e.message));
  const chainOwn = folder();
  const chainOpen = folder();
  fs.chmodSync(chainOpen, 0o777);
  const chainTarget = folder();
  fs.mkdirSync(path.join(chainTarget, 'ledger'), { mode: 0o700 });
  fs.symlinkSync(chainTarget, path.join(chainOpen, 'L2'));
  fs.symlinkSync(path.join(chainOpen, 'L2'), path.join(chainOwn, 'L1'));
  await assert.rejects(OPEN(path.join(chainOwn, 'L1', 'ledger')), (e) => e.code === CODE && /can be changed by another user/.test(e.message));
  const homeLike = folder();
  if (process.platform === 'darwin') spawnSync('chmod', ['+a', 'everyone deny delete', homeLike]);
  const denied = path.join(homeLike, 'ledger');
  fs.mkdirSync(denied, { mode: 0o700 });
  await OPEN(denied);
  if (process.platform === 'darwin') spawnSync('chmod', ['-a', 'everyone deny delete', homeLike]);
});
