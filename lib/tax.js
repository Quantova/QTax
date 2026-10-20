// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const qstamp = require('@quantovainc/qstamp');
const native = require('./native');
const F = require('./format');

function requireProvingQstamp() {
  const dir = path.dirname(require.resolve('@quantovainc/qstamp/package.json'));
  const [major, minor] = String(require(path.join(dir, 'package.json')).version).split('.').map((n) => parseInt(n, 10));
  const released = major > 0 || (major === 0 && minor >= 3);
  const staged = fs.existsSync(path.join(dir, 'lib', 'deadline.js')) && fs.existsSync(path.join(dir, 'lib', 'finality.js'));
  if (typeof qstamp.isProven !== 'function' || !(released || staged)) {
    throw new Error('the installed Qstamp is older than 0.3.0 and cannot prove anchors');
  }
}
requireProvingQstamp();

function own(value) {
  if (value === undefined || value === null) return Object.create(null);
  if (typeof value !== 'object' || Array.isArray(value) || ArrayBuffer.isView(value) || value instanceof ArrayBuffer) F.reject('the options are a plain object');
  return Object.assign(Object.create(null), value);
}

function requireSeed(key) {
  if (!((ArrayBuffer.isView(key) && key instanceof Uint8Array)) || key.length !== 32 || !(key.buffer instanceof ArrayBuffer)) {
    F.reject('a signing key is a 32 byte Uint8Array seed, kept by its holder and wiped with fill(0) after use');
  }
  if (new Set(key).size < 13) F.reject('a signing key made of too few different byte values is refused, draw one with generateKey');
  return key;
}

const HIDDEN = 'SecretKey [hidden]';

class SecretKey extends Uint8Array {
  static get [Symbol.species]() {
    return Uint8Array;
  }

  toJSON() {
    return HIDDEN;
  }

  toString() {
    return HIDDEN;
  }

  toLocaleString() {
    return HIDDEN;
  }

  [require('util').inspect.custom]() {
    return HIDDEN;
  }
}

function generateKey() {
  const seed = new SecretKey(32);
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
  if ((ArrayBuffer.isView(value) && value instanceof Uint8Array)) return F.keyIdOf(value);
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
    if (!((ArrayBuffer.isView(options[bytesKey]) && options[bytesKey] instanceof Uint8Array))) F.reject(bytesKey + ' is a Uint8Array');
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
  options = own(options);
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
  options = own(options);
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
  options = own(options);
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
  options = own(options);
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
  const statement = {
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
  };
  if (options.ledger === undefined) return sign('assessment', statement, options.key);
  return inLedger('assessment', rootFilingRef, seq, supersedes, statement, ledgerOf(options.ledger), Uint8Array.from(options.key));
}

function refund(options) {
  if (!options || typeof options !== 'object') F.reject('refund needs options');
  options = own(options);
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
  const statement = {
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
  };
  if (options.ledger === undefined) return sign('refund', statement, options.key);
  return inLedger('refund', a.statement.rootFilingRef, seq, prevRefundRef, statement, ledgerOf(options.ledger), Uint8Array.from(options.key));
}

function ledgerError(message) {
  const e = new Error(String(message).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/gu, '?'));
  e.code = 'QTAX_LEDGER';
  return e;
}

const SERIES_FORMAT = 'qtax-series/1';
const SERIES_NAME = /^qtax\.(assessment|refund)\.([0-9a-f]{64})$/;
const SERIES_FILE_MAX = 9999999;
const SERIES_MAX = 65536;
const FC = fs.constants;
const CREATE_FLAGS = FC.O_WRONLY | FC.O_CREAT | FC.O_EXCL | (FC.O_NOFOLLOW || 0);
const READ_FLAGS = FC.O_RDONLY | (FC.O_NOFOLLOW || 0) | (FC.O_NONBLOCK || 0);

function seriesText(name, seq, envelope) {
  return JSON.stringify({ format: SERIES_FORMAT, series: name, seq, ref: F.refOf(F.parse(envelope)), envelope }) + '\n';
}

function headOf(text, name) {
  if (text === null || text === undefined) return null;
  const damaged = () => ledgerError('the ledger entry of the series ' + name + ' is damaged, nothing was signed');
  if (typeof text !== 'string' || text.length > SERIES_MAX) throw damaged();
  let h;
  try {
    h = JSON.parse(text);
  } catch (e) {
    throw damaged();
  }
  if (!h || h.format !== SERIES_FORMAT || h.series !== name || !Number.isSafeInteger(h.seq) || h.seq < 1 || typeof h.ref !== 'string' || !/^[0-9a-f]{64}$/.test(h.ref)) throw damaged();
  let p;
  try {
    p = F.parse(h.envelope);
  } catch (e) {
    throw damaged();
  }
  if (F.refOf(p) !== h.ref || !signatureOk(p) || seriesText(name, h.seq, h.envelope) !== text) throw damaged();
  const s = SERIES_NAME.exec(name);
  if (!s || p.type !== s[1] || p.statement.rootFilingRef !== s[2] || p.statement.seq !== h.seq) throw damaged();
  return { seq: h.seq, ref: h.ref, envelope: h.envelope };
}

function readEntry(file, seq) {
  const bad = () => ledgerError('the ledger entry ' + path.basename(file) + ' is not a small regular file');
  let fd;
  try {
    fd = fs.openSync(file, READ_FLAGS);
  } catch (e) {
    if (e.code === 'ELOOP') throw bad();
    throw ledgerError('the ledger entry ' + path.basename(file) + ' could not be opened (' + e.code + ')');
  }
  let text;
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > SERIES_MAX) throw bad();
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < buf.length) {
      const n = fs.readSync(fd, buf, off, buf.length - off, off);
      if (n === 0) break;
      off += n;
    }
    text = buf.subarray(0, off).toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
  let h = null;
  try {
    h = JSON.parse(text);
  } catch (e) {
    h = null;
  }
  if (!h || h.seq !== seq) throw ledgerError('the ledger entry ' + path.basename(file) + ' does not hold position ' + seq + ' of its series, nothing was signed');
  return text;
}

function syncDir(dir) {
  try {
    const fd = fs.openSync(dir, 'r');
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch (e) {
    if (e.code !== 'EISDIR' && e.code !== 'EPERM' && e.code !== 'EINVAL') throw e;
  }
}

const WRITE_RIGHTS = /\b(add_file|add_subdirectory|delete_child|delete|write|append|writeattr|writeextattr|writesecurity|chown)\b/;

function listing(file, args, dir) {
  try {
    return execFileSync(file, args, { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    throw ledgerError('the permissions of the folder ' + (typeof dir === 'string' ? dir.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, '?').slice(0, 200) : 'of type ' + typeof dir) + ' could not be read');
  }
}

function aclLetsOthersWrite(dir) {
  if (process.platform === 'win32') return false;
  if (process.platform === 'darwin') {
    return listing('/bin/ls', ['-lde', dir], dir).split('\n').some((l) => /^\s*\d+: /.test(l) && / allow /.test(l) && WRITE_RIGHTS.test(l));
  }
  for (const tool of ['/usr/bin/getfacl', '/bin/getfacl']) {
    if (fs.existsSync(tool)) {
      return listing(tool, ['-cp', dir], dir).split('\n').some((l) => /^(default:)?(user|group):[^:]+:[r-]w/.test(l.trim()));
    }
  }
  let version = '';
  try {
    version = execFileSync('/bin/ls', ['--version'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch (e) {
    version = '';
  }
  if (!/GNU coreutils/.test(version)) throw ledgerError('access control lists cannot be read on this system, install getfacl so the ledger folder can be checked');
  return /^.{10}\+/.test(listing('/bin/ls', ['-ld', dir], dir));
}

function exposedPlace(dir, ownerUid, depth, includeLast, sharedGid) {
  const self = typeof process.getuid === 'function' ? process.getuid() : null;
  const safe = (p, st) => (self === null || st.uid === 0 || st.uid === self || st.uid === ownerUid) && !((st.mode & 0o002) && !(st.mode & 0o1000)) && !((st.mode & 0o020) && !(st.mode & 0o1000) && !(st.uid === 0 && st.gid === 0) && st.gid !== sharedGid) && !aclLetsOthersWrite(p);
  if (depth > 32) throw ledgerError('the ledger folder is reached through too many symbolic links');
  const full = path.resolve(dir);
  const parts = full.split(path.sep).filter(Boolean);
  let cur = path.parse(full).root;
  if (!safe(cur, fs.statSync(cur))) return cur;
  for (let i = 0; i < parts.length; i += 1) {
    const next = path.join(cur, parts[i]);
    const last = i === parts.length - 1;
    const st = fs.lstatSync(next);
    if (st.isSymbolicLink()) {
      const target = path.resolve(path.dirname(next), fs.readlinkSync(next));
      const bad = exposedPlace(target, ownerUid, depth + 1, !last || includeLast, sharedGid);
      if (bad) return bad;
      cur = fs.realpathSync(target);
      continue;
    }
    if ((!last || includeLast) && !safe(next, st)) return next;
    cur = next;
  }
  return null;
}

function folderLedger(dir) {
  if (process.platform === 'win32') throw ledgerError('the folder ledger checks the owner, mode and access list of every folder, which Windows does not expose, so on Windows give a ledger store of your own with read and compareAndSwap');
  if (typeof dir !== 'string' || dir.length === 0) F.reject('a ledger folder is a path');
  let placed = null;
  const base = () => {
    let st;
    try {
      st = fs.statSync(dir);
    } catch (e) {
      throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' could not be opened');
    }
    if (!st.isDirectory()) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' is not a folder');
    if (placed && (placed.dev !== st.dev || placed.ino !== st.ino)) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' was moved or replaced after it was first checked, nothing was signed');
    if (st.mode & 0o002) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' can be written by every user of this machine, restrict it to the signers of the authority');
    if (placed === null) {
      if (aclLetsOthersWrite(fs.realpathSync(dir))) throw ledgerError('the ledger folder ' + dir.slice(0, 200) + ' carries an access control list that lets others write, remove it so that only its mode decides who may write');
      const above = exposedPlace(dir, st.uid, 0, false, st.mode & 0o020 ? st.gid : null);
      if (above) throw ledgerError('the folder ' + above.slice(0, 200) + ' above the ledger can be changed by another user, so the ledger could be replaced, move the ledger under folders only its signers control');
      placed = { dev: st.dev, ino: st.ino };
    }
    return dir;
  };
  const check = (name) => {
    if (typeof name !== 'string' || !SERIES_NAME.test(name)) F.reject('a ledger entry is named qtax, the record type and the reference of the original return');
  };
  const held = (root, name, seq) => {
    try {
      fs.lstatSync(path.join(root, name + '.' + seq + '.json'));
      return true;
    } catch (e) {
      if (e.code === 'ENOENT') return false;
      throw ledgerError('the ledger entry ' + name + '.' + seq + '.json could not be read (' + e.code + ')');
    }
  };
  const top = (root, name) => {
    if (!held(root, name, 1)) return 0;
    let low = 1;
    let high = 2;
    while (high <= SERIES_FILE_MAX && held(root, name, high)) {
      low = high;
      high *= 2;
    }
    high = Math.min(high, SERIES_FILE_MAX + 1);
    while (high - low > 1) {
      const mid = Math.floor((low + high) / 2);
      if (held(root, name, mid)) low = mid;
      else high = mid;
    }
    return low;
  };
  const highest = (root, name) => {
    let files;
    try {
      files = fs.readdirSync(root);
    } catch (e) {
      throw ledgerError('the ledger folder could not be listed (' + e.code + ')');
    }
    const prefix = name + '.';
    let best = 0;
    for (const f of files) {
      if (!f.startsWith(prefix) || !f.endsWith('.json')) continue;
      const n = f.slice(prefix.length, -5);
      if (/^[1-9][0-9]{0,6}$/.test(n) && Number(n) <= F.SEQ_MAX && Number(n) > best) best = Number(n);
    }
    return best;
  };
  const store = {
    async read(name) {
      check(name);
      const root = base();
      const seq = top(root, name);
      if (seq === 0) return null;
      return readEntry(path.join(root, name + '.' + seq + '.json'), seq);
    },
    async compareAndSwap(name, expected, next) {
      check(name);
      const root = base();
      const want = headOf(next, name);
      if (want === null) F.reject('the next state of a series names its latest record');
      const have = headOf(expected, name);
      if (want.seq !== (have ? have.seq + 1 : 1)) return false;
      if ((await store.read(name)) !== expected) return false;
      const last = highest(root, name);
      if (last !== want.seq - 1) {
        if (last > want.seq - 1 && top(root, name) === last) return false;
        throw ledgerError('the ledger of ' + name + ' is missing a record below its latest one, the file ' + name + '.' + last + '.json lies above the last record that follows on without a gap, so it is damaged and nothing was signed, restore the whole folder from its backup or remove that file if it does not belong to the return');
      }
      const file = path.join(root, name + '.' + want.seq + '.json');
      const tmp = path.join(root, '.' + name + '.' + want.seq + '.' + crypto.randomBytes(16).toString('hex') + '.tmp');
      try {
        const fd = fs.openSync(tmp, CREATE_FLAGS, 0o600);
        try {
          fs.writeSync(fd, next);
          fs.fsyncSync(fd);
        } finally {
          fs.closeSync(fd);
        }
        try {
          fs.linkSync(tmp, file);
        } catch (e) {
          if (e.code === 'EEXIST') return false;
          throw ledgerError('the ledger entry could not be written (' + e.code + ')');
        }
        syncDir(root);
        return true;
      } finally {
        fs.rmSync(tmp, { force: true });
      }
    },
  };
  return store;
}

function ledgerOf(value) {
  if (typeof value === 'string') return folderLedger(value);
  if (value && typeof value === 'object' && typeof value.read === 'function' && typeof value.compareAndSwap === 'function') return value;
  F.reject('ledger is the folder of the series ledger, or an object with read and compareAndSwap that stores each value atomically');
}

async function inLedger(type, rootFilingRef, seq, prevRef, statement, store, key) {
  try {
    const name = 'qtax.' + type + '.' + rootFilingRef;
    const text = await store.read(name);
    const head = headOf(text, name);
    if (seq === 1 && head !== null) throw ledgerError('the ledger already holds ' + type + ' ' + head.seq + ' of this return, so this ' + type + ' cannot be the first, name the latest ' + type + ' of the return');
    if (seq > 1 && (head === null || head.ref !== prevRef || head.seq !== seq - 1)) {
      throw ledgerError('the ' + type + ' named as previous is not the latest ' + type + ' of this return in the ledger, which holds ' + (head ? type + ' ' + head.seq : 'none') + ', nothing was signed');
    }
    const env = sign(type, statement, key);
    const swapped = await store.compareAndSwap(name, text, seriesText(name, seq, env));
    if (typeof swapped !== 'boolean') throw ledgerError('the ledger store answered compareAndSwap with ' + (swapped === null ? 'null' : typeof swapped) + ' where true or false was expected, nothing was issued, read the latest record of the return before trying again');
    if (swapped !== true) {
      throw ledgerError('another ' + type + ' was recorded for this return while this one was signed, nothing was issued, read the latest record and try again');
    }
    return env;
  } finally {
    key.fill(0);
  }
}

async function ledgerLatest(ledger, type, rootFilingRef) {
  if (type !== 'assessment' && type !== 'refund') F.reject('type is assessment or refund');
  if (typeof rootFilingRef !== 'string' || !/^[0-9a-f]{64}$/.test(rootFilingRef)) F.reject('the original return is named by its reference, 64 lowercase hex characters');
  const name = 'qtax.' + type + '.' + rootFilingRef;
  const head = headOf(await ledgerOf(ledger).read(name), name);
  return head === null ? null : head.envelope;
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
  return attach(copies, await qstamp.stamp(Object.assign(own(options), { records, kind: F.KIND })));
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
  return attach(copies, await qstamp.complete(p, own(options)));
}

const OPTIONS_OF = {
  anchor: ['allowLoopback', 'client', 'clients', 'deadlineMs', 'endpointAllowList', 'index', 'maxFee', 'meter', 'network', 'onPending', 'rpc', 'seed', 'signal', 'timeoutMs', 'trustCustomEndpoints', 'trustSingleEndpoint', 'until'],
  assess: ['currency', 'decidedAt', 'filing', 'key', 'ledger', 'note', 'outcome', 'outcomeDigest', 'refundDue', 'supersedes'],
  claim: ['claimedAt', 'invoice', 'key', 'note'],
  file: ['amends', 'content', 'contentDigest', 'contentSize', 'form', 'key', 'note', 'period', 'receivedAt', 'taxpayerRef'],
  invoice: ['buyer', 'currency', 'document', 'invoiceDigest', 'invoiceId', 'issuedAt', 'key', 'note', 'tax', 'total'],
  refund: ['amount', 'assessment', 'currency', 'first', 'key', 'ledger', 'note', 'paidAt', 'previous'],
};

function onlyKnown(name, options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options) || ArrayBuffer.isView(options)) return;
  const unknown = Object.keys(options).find((k) => !OPTIONS_OF[name].includes(k));
  if (unknown !== undefined) F.reject('the option ' + unknown.replace(/[^A-Za-z0-9_]/g, '?').slice(0, 40) + ' is not an option of ' + name + ', so nothing was signed');
}

function strict(name, fn, at, isAsync) {
  return function strictly(...args) {
    try {
      onlyKnown(name, args[at]);
    } catch (e) {
      if (isAsync) return Promise.reject(e);
      throw e;
    }
    return fn.apply(this, args);
  };
}

module.exports = {
  generateKey, publicKey, keyId, describeKey, keyIdFrom, commitParty, file, invoice, claim, assess, refund, anchor, complete, signedEnvelope, signatureOk, folderLedger, ledgerLatest,
};
Object.assign(module.exports, {
  anchor: strict('anchor', anchor, 1, true),
  assess: strict('assess', assess, 0, false),
  claim: strict('claim', claim, 0, false),
  file: strict('file', file, 0, false),
  invoice: strict('invoice', invoice, 0, false),
  refund: strict('refund', refund, 0, false),
});
