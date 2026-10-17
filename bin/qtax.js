#!/usr/bin/env node
// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const qx = require('..');

const ENVELOPE_MAX = 1024 * 1024;
const KEY_JSON_MAX = 64 * 1024;
const FILE_MAX = 64 * 1024 * 1024 * 1024;

const HELP = `qtax, post quantum tax integrity for governments with Quantova time proofs

  qtax keygen <keyfile>
  qtax key <keyfile>
  qtax commit-party --identity-file FILE --salt-out FILE
  qtax file --key <intake keyfile> --taxpayer-ref HEX --period TEXT --form TEXT (--content FILE | --content-digest HEX --content-size N)
            [--amends FILE] [--note TEXT] --out FILE
  qtax invoice --key <seller keyfile> --invoice-id TEXT --buyer KEY (--document FILE | --invoice-digest HEX)
               --currency CODE --total N --tax N [--note TEXT] --out FILE
  qtax claim --key <buyer keyfile> --invoice FILE [--note TEXT] --out FILE
  qtax assess --key <assessor keyfile> --filing FILE (--outcome FILE | --outcome-digest HEX) --currency CODE --refund-due N
              [--supersedes FILE] [--note TEXT] --out FILE
  qtax refund --key <officer keyfile> --assessment FILE --amount N (--previous-refund FILE | --first) [--note TEXT] --out FILE
  qtax anchor <envelope>... --seed-file <file> [--index N] [--rpc URL] [--max-fee N]
  qtax complete <envelope>... --pending FILE [--tx ID] [--rpc URL]
  qtax verify <envelope> --type TYPE [options for that type] [--allow-unanchored] [--at TIME] [--max-anchor-delay SECONDS]
              [--rpc URL] [--json]

Verify options by type
  filing      --intake KEY... (--content FILE | --content-digest HEX) [--previous FILE]
              [--taxpayer-identity-file FILE --taxpayer-salt-file FILE]
  invoice     --seller KEY [--document FILE]
  claim       --seller KEY --invoice FILE
  assessment  --intake KEY... --assessor KEY... --filing FILE [--root FILE] [--previous FILE] [--outcome FILE] [--other-assessment FILE]...
              [--all-supplied]
  refund      --intake KEY... --assessor KEY... --officer KEY... --assessment FILE --filing FILE [--root FILE] [--previous-refund FILE]...
              [--other-assessment FILE]... [--all-supplied]

A KEY is a 64 hex character key id or a qtax-key/1 file written by the key command. Intake, assessor and officer keys
are separate roles and a key may hold only one of them. Amounts are whole numbers of minor units and a CODE is three
capital letters, normally an ISO 4217 currency code. Documents are hashed with SHA3-256 as they are read and never
leave this machine. A taxpayer is named only by a salted commitment from commit-party, whose salt file stays with the
authority, and identities are read from files only, so they never appear in the shell history or the process list.
A refund names the previous refund on the same return, or --first when none has been paid. A refund or an assessment is
valid only with --all-supplied, which declares that every refund and assessment held for the return was given. When the
filing is an amendment, --root gives the original return it belongs to.

If anchor is interrupted after its transaction may have been sent, it keeps a pending stamp beside each envelope and
refuses to anchor them again. Finish it with complete, giving the same envelopes in the same order.

Exit codes are 0 for valid, 1 for invalid, refused or an error, 2 for indeterminate and 64 for usage errors.`;

function usageError(message) {
  const e = new Error(message);
  e.usage = true;
  return e;
}

const SPEC = {
  keygen: { flags: ['force'], values: [] },
  key: { flags: [], values: [] },
  'commit-party': { flags: [], values: ['identity-file', 'salt-out'] },
  file: { flags: ['force'], values: ['key', 'taxpayer-ref', 'period', 'form', 'content', 'content-digest', 'content-size', 'amends', 'note', 'out'] },
  invoice: { flags: ['force'], values: ['key', 'invoice-id', 'buyer', 'document', 'invoice-digest', 'currency', 'total', 'tax', 'note', 'out'] },
  claim: { flags: ['force'], values: ['key', 'invoice', 'note', 'out'] },
  assess: { flags: ['force'], values: ['key', 'filing', 'outcome', 'outcome-digest', 'currency', 'refund-due', 'supersedes', 'note', 'out'] },
  refund: { flags: ['force', 'first'], values: ['key', 'assessment', 'amount', 'previous-refund', 'note', 'out'] },
  anchor: { flags: [], values: ['seed-file', 'index', 'rpc', 'max-fee'] },
  complete: { flags: [], values: ['pending', 'tx', 'rpc'] },
  verify: { flags: ['allow-unanchored', 'all-supplied', 'json'], values: ['type', 'seller', 'content', 'content-digest', 'document', 'outcome', 'previous', 'invoice', 'filing', 'root', 'assessment', 'taxpayer-identity-file', 'taxpayer-salt-file', 'at', 'max-anchor-delay', 'rpc'], multi: ['intake', 'assessor', 'officer', 'previous-refund', 'other-assessment'] },
};

const VERIFY_COMMON = ['type', 'allow-unanchored', 'json', 'at', 'max-anchor-delay', 'rpc'];
const VERIFY_BY_TYPE = {
  filing: ['intake', 'content', 'content-digest', 'previous', 'taxpayer-identity-file', 'taxpayer-salt-file'],
  invoice: ['seller', 'document'],
  claim: ['seller', 'invoice'],
  assessment: ['intake', 'assessor', 'filing', 'root', 'previous', 'outcome', 'other-assessment', 'all-supplied'],
  refund: ['intake', 'assessor', 'officer', 'assessment', 'filing', 'root', 'previous-refund', 'other-assessment', 'all-supplied'],
};
const IDENTITY_FILE_MAX = 4096;

function parse(command, argv) {
  const spec = SPEC[command];
  const positional = [];
  const flags = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const name = a.slice(2);
    if (spec.flags.includes(name)) {
      if (flags[name]) throw usageError('--' + name + ' was given twice');
      flags[name] = true;
    } else if (spec.values.includes(name) || (spec.multi || []).includes(name)) {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) throw usageError('--' + name + ' needs a value');
      if (v.length === 0) throw usageError('--' + name + ' was given an empty value');
      i += 1;
      if ((spec.multi || []).includes(name)) (flags[name] = flags[name] || []).push(v);
      else if (flags[name] !== undefined) throw usageError('--' + name + ' was given twice');
      else flags[name] = v;
    } else {
      throw usageError('unknown option ' + safe(a).slice(0, 40));
    }
  }
  return { positional, flags };
}

function hexNibble(code) {
  if (code >= 48 && code <= 57) return code - 48;
  if (code >= 97 && code <= 102) return code - 87;
  if (code >= 65 && code <= 70) return code - 55;
  return -1;
}

function readSeed(file, what) {
  if (!file) throw usageError(what + ' is required');
  const fd = openRegular(file, 'key file');
  const raw = Buffer.allocUnsafeSlow(131);
  const seed = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw usageError('the key file must be a regular file');
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the key file ' + file + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the key file ' + file + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    if (n > 66) throw usageError('the key file must hold only a 32 byte seed as 64 hex characters');
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13 || raw[end - 1] === 32)) end -= 1;
    if (end !== 64) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[2 * i]);
      const lo = hexNibble(raw[2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the key file must hold a 32 byte seed as 64 hex characters');
      seed[i] = (hi << 4) | lo;
    }
    return seed;
  } catch (e) {
    seed.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function openRegular(file, what) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  let fd;
  try {
    fd = fs.openSync(file, flags);
  } catch (e) {
    throw usageError(e.code === 'ELOOP' ? 'the ' + what + ' must not be a symbolic link' : 'the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  if (!fs.fstatSync(fd).isFile()) {
    fs.closeSync(fd);
    throw usageError('the ' + what + ' must be a regular file');
  }
  return fd;
}

function statOf(file) {
  try {
    return fs.lstatSync(file);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
}

const pendingTemp = new Set();

function cleanupTemp() {
  for (const t of pendingTemp) {
    try {
      fs.rmSync(t, { force: true });
    } catch (e) {
      continue;
    }
  }
}

for (const [sig, code] of [['SIGINT', 130], ['SIGTERM', 143], ['SIGHUP', 129]]) {
  process.on(sig, () => {
    cleanupTemp();
    process.exit(code);
  });
}

function atomicWrite(dest, data, force) {
  const existing = statOf(dest);
  if (existing && existing.isSymbolicLink()) throw usageError('refusing to write through the symbolic link ' + safe(dest));
  if (existing && !existing.isFile()) throw usageError('something other than a file exists at ' + safe(dest));
  if (existing && !force) throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
  const dir = path.dirname(dest);
  const tmp = path.join(dir, '.' + path.basename(dest) + '.' + crypto.randomBytes(6).toString('hex') + '.tmp');
  pendingTemp.add(tmp);
  try {
    const fd = fs.openSync(tmp, 'wx', 0o600);
    try {
      fs.fchmodSync(fd, 0o600);
      fs.writeSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    if (force) {
      fs.renameSync(tmp, dest);
    } else {
      try {
        fs.linkSync(tmp, dest);
      } catch (e) {
        if (e.code === 'EEXIST') throw usageError('a file already exists at ' + safe(dest) + ', pass --force to replace it');
        throw e;
      }
      fs.rmSync(tmp, { force: true });
    }
    try {
      const dfd = fs.openSync(dir, 'r');
      try {
        fs.fsyncSync(dfd);
      } finally {
        fs.closeSync(dfd);
      }
    } catch (e) {
      if (e.code !== 'EISDIR' && e.code !== 'EPERM' && e.code !== 'EINVAL') throw e;
    }
  } finally {
    fs.rmSync(tmp, { force: true });
    pendingTemp.delete(tmp);
  }
}

function readJson(file, what, invalidExit, limit) {
  const max = limit || ENVELOPE_MAX;
  const fd = openRegular(file, what);
  const buf = Buffer.alloc(max + 1);
  let n;
  try {
    n = fs.readSync(fd, buf, 0, buf.length, 0);
  } finally {
    fs.closeSync(fd);
  }
  const bad = (message) => {
    const e = new Error(message);
    if (invalidExit) e.invalid = true;
    else e.usage = true;
    return e;
  };
  if (n > max) throw bad('the ' + what + ' is larger than ' + max + ' bytes');
  try {
    return JSON.parse(buf.subarray(0, n).toString('utf8'));
  } catch (e) {
    throw bad('the ' + what + ' ' + safe(file) + ' is not valid JSON');
  }
}

function asciiJson(value) {
  return JSON.stringify(value, null, 2).replace(/[\u007f-\uffff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function safe(value) {
  return String(value).replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb\u00ad\u180e\ufe00-\ufe0f\u{e0000}-\u{e007f}]/gu, '?');
}

function withSeed(file, what, fn) {
  const seed = readSeed(file, what);
  try {
    return fn(seed);
  } finally {
    seed.fill(0);
  }
}

async function cmdKeygen(positional, flags) {
  if (positional.length !== 1) throw usageError('keygen takes one key file path');
  const seed = qx.generateKey();
  const text = Buffer.alloc(65);
  try {
    const digits = '0123456789abcdef';
    for (let i = 0; i < 32; i += 1) {
      text[2 * i] = digits.charCodeAt(seed[i] >> 4);
      text[2 * i + 1] = digits.charCodeAt(seed[i] & 15);
    }
    text[64] = 10;
    atomicWrite(positional[0], text, flags.force);
    console.log('key id ' + qx.keyId(seed));
  } finally {
    seed.fill(0);
    text.fill(0);
  }
  return 0;
}

async function cmdKey(positional) {
  if (positional.length !== 1) throw usageError('key takes one key file path');
  const desc = withSeed(positional[0], 'a key file', (seed) => qx.describeKey(seed));
  process.stdout.write(asciiJson(desc) + '\n');
  return 0;
}

function need(flags, name) {
  if (flags[name] === undefined) throw usageError('--' + name + ' is required');
  return flags[name];
}

function readAll(fd, what, max) {
  const size = fs.fstatSync(fd).size;
  if (size > max) {
    const err = new Error('the ' + what + ' is larger than ' + max + ' bytes');
    err.invalid = true;
    throw err;
  }
  const buf = Buffer.alloc(size);
  let off = 0;
  while (off < size) {
    const n = fs.readSync(fd, buf, off, size - off, off);
    if (n === 0) break;
    off += n;
  }
  return buf.subarray(0, off);
}

function seqFlag(value, name) {
  if (!/^\d{1,9}$/.test(value)) throw usageError('--' + name + ' is a whole number');
  return Number(value);
}

function distinctFiles(files) {
  const seen = new Set();
  for (const f of files) {
    const st = statOf(f);
    if (!st || !st.isFile()) throw usageError('the envelope ' + safe(f) + ' is not a regular file');
    const id = st.dev + ':' + st.ino;
    if (seen.has(id)) throw usageError('the envelope ' + safe(f) + ' was given twice');
    seen.add(id);
    try {
      fs.accessSync(path.dirname(f), fs.constants.W_OK);
      fs.accessSync(f, fs.constants.W_OK);
    } catch (e) {
      throw usageError('the envelope ' + safe(f) + ' or its folder is not writable, so the anchor could not be saved');
    }
  }
}

function pendingPath(file) {
  return file + '.pending.json';
}

function saveAnchored(files, anchored) {
  let lost = false;
  anchored.forEach((env, i) => {
    try {
      atomicWrite(files[i], asciiJson(env) + '\n', true);
      console.log('anchored ' + safe(files[i]) + ' in transaction ' + safe(env.anchor.anchor.tx));
    } catch (e) {
      lost = true;
      console.error('the anchored envelope could not be written to ' + safe(files[i]) + ', it follows on standard output');
      process.stdout.write(asciiJson(env) + '\n');
    }
  });
  return lost ? 1 : 0;
}

async function cmdAnchor(positional, flags) {
  if (positional.length === 0) throw usageError('anchor takes one or more envelopes');
  if (positional.length > BATCH_MAX) throw usageError('at most ' + BATCH_MAX + ' envelopes can be anchored at once');
  for (const f of positional) if (Buffer.byteLength(path.basename(pendingPath(f))) > 200) throw usageError('the name of ' + safe(f) + ' is too long to keep a pending stamp beside it');
  distinctFiles(positional);
  for (const f of positional) {
    if (statOf(pendingPath(f))) throw usageError('an unfinished anchor exists in ' + safe(pendingPath(f)) + ', finish it with complete first');
  }
  const pendingFile = pendingPath(positional[0]);
  const envs = positional.map((f) => readJson(f, 'envelope', true, ENVELOPE_MAX));
  let index = 0;
  if (flags.index !== undefined) index = seqFlag(flags.index, 'index');
  const seed = readSeed(flags['seed-file'] || process.env.QSTAMP_SEED_FILE, '--seed-file of a funded Quantova account');
  let saved = false;
  const keep = (pending) => {
    const text = asciiJson(pending) + '\n';
    for (const f of positional) atomicWrite(pendingPath(f), text, saved);
    saved = true;
  };
  let anchored;
  try {
    anchored = await qx.anchor(envs, { seed, index, network: 'testnet', rpc: flags.rpc, maxFee: flags['max-fee'], onPending: keep });
  } catch (e) {
    if (e && e.pending && typeof e.pending === 'object') {
      let message = 'the anchoring transaction may already have been sent, ' + friendly(e);
      try {
        keep(e.pending);
        message += ', the pending stamp was saved in ' + safe(pendingFile) + ', finish it with qtax complete ' + positional.map(safe).join(' ') + ' --pending ' + safe(pendingFile);
      } catch (e2) {
        message += ', the pending stamp could not be saved and follows on standard error, keep it to finish the anchor';
        process.stderr.write(asciiJson(e.pending) + '\n');
      }
      throw new Error(message);
    }
    throw e;
  } finally {
    seed.fill(0);
  }
  const code = saveAnchored(positional, anchored);
  if (code === 0 && saved) for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  return code;
}

async function cmdComplete(positional, flags) {
  if (positional.length === 0) throw usageError('complete takes the envelopes given to anchor, in the same order');
  if (positional.length > BATCH_MAX) throw usageError('at most ' + BATCH_MAX + ' envelopes can be completed at once');
  distinctFiles(positional);
  const pendingFile = need(flags, 'pending');
  const pending = readJson(pendingFile, 'pending stamp');
  if (flags.tx !== undefined) {
    if (!/^QTX1[0-9A-Z]{20,120}$/.test(flags.tx)) throw usageError('--tx is the QTX1 identifier of the stamp transaction');
    if (pending && typeof pending === 'object' && typeof pending.tx === 'string' && pending.tx !== flags.tx) throw usageError('the pending stamp already names another transaction');
    if (pending && typeof pending === 'object') pending.tx = flags.tx;
  }
  const envs = positional.map((f) => readJson(f, 'envelope', true, ENVELOPE_MAX)).map((e) => {
    if (e && typeof e === 'object' && !Array.isArray(e)) delete e.anchor;
    return e;
  });
  const anchored = await qx.complete(envs, pending, { rpc: flags.rpc });
  const code = saveAnchored(positional, anchored);
  if (code === 0) {
    fs.rmSync(pendingFile, { force: true });
    for (const f of positional) fs.rmSync(pendingPath(f), { force: true });
  }
  return code;
}

const BATCH_MAX = 1000;
const SALT_PREFIX = 'qtax-salt/1 ';

async function hashFile(file, what) {
  let fh;
  try {
    fh = await fs.promises.open(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
  } catch (e) {
    throw usageError('the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  const h = crypto.createHash('sha3-256');
  const buf = Buffer.alloc(1024 * 1024);
  let size = 0;
  try {
    if (!(await fh.stat()).isFile()) throw usageError('the ' + what + ' must be a regular file');
    for (;;) {
      const { bytesRead } = await fh.read(buf, 0, buf.length, null);
      if (bytesRead === 0) break;
      size += bytesRead;
      if (size > FILE_MAX) throw usageError('the ' + what + ' is larger than ' + FILE_MAX + ' bytes');
      h.update(buf.subarray(0, bytesRead));
    }
  } finally {
    await fh.close();
  }
  return { digest: h.digest('hex'), size };
}

function openPublic(file, what) {
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK || 0));
  } catch (e) {
    throw usageError('the ' + what + ' ' + safe(file) + ' could not be opened');
  }
  if (!fs.fstatSync(fd).isFile()) {
    fs.closeSync(fd);
    throw usageError('the ' + what + ' must be a regular file');
  }
  return fd;
}

function readSmall(file, what, max) {
  const fd = openPublic(file, what);
  try {
    return readAll(fd, what, max);
  } finally {
    fs.closeSync(fd);
  }
}

function saltText(salt) {
  const digits = '0123456789abcdef';
  const out = Buffer.allocUnsafeSlow(SALT_PREFIX.length + 65);
  out.write(SALT_PREFIX, 0, 'ascii');
  for (let i = 0; i < 32; i += 1) {
    out[SALT_PREFIX.length + 2 * i] = digits.charCodeAt(salt[i] >> 4);
    out[SALT_PREFIX.length + 2 * i + 1] = digits.charCodeAt(salt[i] & 15);
  }
  out[out.length - 1] = 10;
  return out;
}

function readSalt(file) {
  const fd = openRegular(file, 'salt file');
  const raw = Buffer.allocUnsafeSlow(200);
  const salt = new Uint8Array(32);
  try {
    const st = fs.fstatSync(fd);
    if (process.platform !== 'win32') {
      if ((st.mode & 0o077) !== 0) throw usageError('the salt file ' + safe(file) + ' is readable by other users, restrict it with chmod 600');
      if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw usageError('the salt file ' + safe(file) + ' is not owned by the current user');
    }
    const n = fs.readSync(fd, raw, 0, raw.length, 0);
    let end = n;
    while (end > 0 && (raw[end - 1] === 10 || raw[end - 1] === 13)) end -= 1;
    if (end !== SALT_PREFIX.length + 64 || raw.subarray(0, SALT_PREFIX.length).toString('ascii') !== SALT_PREFIX) throw usageError('the salt file must hold a qtax-salt/1 line written by commit-party');
    for (let i = 0; i < 32; i += 1) {
      const hi = hexNibble(raw[SALT_PREFIX.length + 2 * i]);
      const lo = hexNibble(raw[SALT_PREFIX.length + 2 * i + 1]);
      if (hi < 0 || lo < 0) throw usageError('the salt file must hold a qtax-salt/1 line written by commit-party');
      salt[i] = (hi << 4) | lo;
    }
    return salt;
  } catch (e) {
    salt.fill(0);
    throw e;
  } finally {
    raw.fill(0);
    fs.closeSync(fd);
  }
}

function identityOf(file, follow) {
  let st = null;
  try {
    st = follow ? fs.statSync(file) : fs.lstatSync(file);
  } catch (e) {
    st = null;
  }
  let dir = path.dirname(path.resolve(file));
  try {
    dir = fs.realpathSync(dir);
  } catch (e) {
    dir = path.dirname(path.resolve(file));
  }
  return { path: path.join(dir, path.basename(file)).normalize('NFC').toLowerCase(), ino: st ? st.dev + ':' + st.ino : null, st };
}

function checkPaths(dests, sources) {
  const seen = [];
  const clash = (a, b) => a.path === b.path || (a.ino !== null && a.ino === b.ino);
  for (const [flag, f] of sources) if (f !== undefined) seen.push([flag, identityOf(f, true)]);
  for (const [flag, f, mayExist] of dests) {
    if (f === undefined) continue;
    const id = identityOf(f, false);
    if (id.st && id.st.isSymbolicLink()) throw usageError('refusing to write through the symbolic link ' + safe(f));
    if (id.st && !id.st.isFile()) throw usageError('something other than a file exists at ' + safe(f));
    if (id.st && !mayExist) throw usageError('a file already exists at ' + safe(f) + (flag === '--salt-out' ? ', a salt file is never replaced' : ', pass --force to replace it'));
    for (const [other, oid] of seen) if (clash(id, oid)) throw usageError(flag + ' must not be the same file as ' + other);
    seen.push([flag, id]);
  }
}

function hexFlag(value, name) {
  if (!/^[0-9a-f]{64}$/.test(value)) throw usageError('--' + name + ' is 64 lowercase hex characters');
  return value;
}

function capList(list, name, max) {
  const l = list || [];
  if (l.length > max) throw usageError('at most ' + max + ' values can be given for --' + name);
  return l;
}

function keyRef(value, name) {
  if (/^[0-9a-f]{64}$/.test(value)) return value;
  const desc = readJson(value, name + ' key', false, KEY_JSON_MAX);
  if (!desc || desc.format !== 'qtax-key/1' || typeof desc.publicKey !== 'string') throw usageError('--' + name + ' is a key id or a qtax-key/1 file');
  return desc;
}

function sizeFlag(value) {
  if (!/^\d{1,15}$/.test(value)) throw usageError('--content-size is a whole number of bytes');
  return Number(value);
}

function writeEnvelope(file, env, force) {
  atomicWrite(file, asciiJson(env) + '\n', force);
}

function identityFrom(flags, fileFlag) {
  if (flags[fileFlag] === undefined) throw usageError('--' + fileFlag + ' is required, identities are read from a file so they never appear in the shell history or the process list');
  const raw = readSmall(flags[fileFlag], 'identity file', IDENTITY_FILE_MAX);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch (e) {
    throw usageError('the identity file must be UTF-8 text');
  }
  return text.replace(/\r?\n$/, '');
}

async function digestFrom(flags, fileFlag, digestFlag, what, required) {
  if (flags[fileFlag] !== undefined && flags[digestFlag] !== undefined) throw usageError('give --' + fileFlag + ' or --' + digestFlag + ', not both');
  if (flags[fileFlag] !== undefined) return hashFile(flags[fileFlag], what);
  if (flags[digestFlag] !== undefined) return { digest: hexFlag(flags[digestFlag], digestFlag), size: null };
  if (required) throw usageError('give --' + fileFlag + ' or --' + digestFlag);
  return null;
}

function amountFlag(value, name) {
  if (!/^(0|[1-9][0-9]{0,29})$/.test(value)) throw usageError('--' + name + ' is a whole number of minor units');
  return value;
}

async function cmdCommitParty(positional, flags) {
  if (positional.length) throw usageError('commit-party takes options only');
  const out = need(flags, 'salt-out');
  checkPaths([['--salt-out', out, false]], [['--identity-file', flags['identity-file']]]);
  const c = qx.commitParty(identityFrom(flags, 'identity-file'));
  const text = saltText(c.salt);
  try {
    atomicWrite(out, text, false);
  } finally {
    text.fill(0);
    c.salt.fill(0);
  }
  console.log('party commitment ' + c.ref + ', salt written to ' + safe(out));
  return 0;
}

async function cmdFile(positional, flags) {
  if (positional.length) throw usageError('file takes options only');
  const out = need(flags, 'out');
  checkPaths([['--out', out, !!flags.force]], [['--key', flags.key], ['--content', flags.content], ['--amends', flags.amends]]);
  const opts = { taxpayerRef: hexFlag(need(flags, 'taxpayer-ref'), 'taxpayer-ref'), period: need(flags, 'period'), form: need(flags, 'form'), note: flags.note };
  if (flags.content !== undefined && flags['content-size'] !== undefined) throw usageError('--content-size goes with --content-digest, the size of --content is measured');
  const c = await digestFrom(flags, 'content', 'content-digest', 'return file', true);
  opts.contentDigest = c.digest;
  opts.contentSize = c.size !== null ? c.size : sizeFlag(need(flags, 'content-size'));
  if (flags.amends !== undefined) opts.amends = readJson(flags.amends, 'amended filing', true);
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qx.file(Object.assign({ key: seed }, opts)));
  writeEnvelope(out, env, flags.force);
  console.log('filing ' + env.statement.filingId + ' sealed as ' + qx.refOf(env) + ', written to ' + safe(out));
  return 0;
}

async function cmdInvoice(positional, flags) {
  if (positional.length) throw usageError('invoice takes options only');
  const out = need(flags, 'out');
  checkPaths([['--out', out, !!flags.force]], [['--key', flags.key], ['--document', flags.document]]);
  const d = await digestFrom(flags, 'document', 'invoice-digest', 'invoice document', true);
  const opts = { invoiceId: need(flags, 'invoice-id'), buyer: keyRef(need(flags, 'buyer'), 'buyer'), invoiceDigest: d.digest, currency: need(flags, 'currency'), total: amountFlag(need(flags, 'total'), 'total'), tax: amountFlag(need(flags, 'tax'), 'tax'), note: flags.note };
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qx.invoice(Object.assign({ key: seed }, opts)));
  writeEnvelope(out, env, flags.force);
  console.log('invoice ' + safe(env.statement.invoiceId) + ' sealed as ' + qx.refOf(env) + ', written to ' + safe(out));
  return 0;
}

async function cmdClaim(positional, flags) {
  if (positional.length) throw usageError('claim takes options only');
  const out = need(flags, 'out');
  checkPaths([['--out', out, !!flags.force]], [['--key', flags.key], ['--invoice', flags.invoice]]);
  const inv = readJson(need(flags, 'invoice'), 'invoice', true);
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qx.claim({ key: seed, invoice: inv, note: flags.note }));
  writeEnvelope(out, env, flags.force);
  console.log('claim ' + env.statement.claimId + ' sealed as ' + qx.refOf(env) + ', written to ' + safe(out));
  return 0;
}

async function cmdAssess(positional, flags) {
  if (positional.length) throw usageError('assess takes options only');
  const out = need(flags, 'out');
  checkPaths([['--out', out, !!flags.force]], [['--key', flags.key], ['--filing', flags.filing], ['--outcome', flags.outcome], ['--supersedes', flags.supersedes]]);
  const filing = readJson(need(flags, 'filing'), 'filing', true);
  const o = await digestFrom(flags, 'outcome', 'outcome-digest', 'assessment document', true);
  const opts = { filing, outcomeDigest: o.digest, currency: need(flags, 'currency'), refundDue: amountFlag(need(flags, 'refund-due'), 'refund-due'), note: flags.note };
  if (flags.supersedes !== undefined) opts.supersedes = readJson(flags.supersedes, 'superseded assessment', true);
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qx.assess(Object.assign({ key: seed }, opts)));
  writeEnvelope(out, env, flags.force);
  console.log('assessment ' + env.statement.assessmentId + ' sealed as ' + qx.refOf(env) + ', written to ' + safe(out));
  return 0;
}

async function cmdRefund(positional, flags) {
  if (positional.length) throw usageError('refund takes options only');
  const out = need(flags, 'out');
  if ((flags['previous-refund'] === undefined) === !flags.first) throw usageError('give --previous-refund with the last refund on this filing, or --first when none has been paid, exactly one');
  checkPaths([['--out', out, !!flags.force]], [['--key', flags.key], ['--assessment', flags.assessment], ['--previous-refund', flags['previous-refund']]]);
  const assessment = readJson(need(flags, 'assessment'), 'assessment', true);
  const opts = { assessment, amount: amountFlag(need(flags, 'amount'), 'amount'), note: flags.note };
  if (flags.first) opts.first = true;
  else opts.previous = readJson(flags['previous-refund'], 'previous refund', true);
  const env = withSeed(need(flags, 'key'), '--key', (seed) => qx.refund(Object.assign({ key: seed }, opts)));
  writeEnvelope(out, env, flags.force);
  console.log('refund ' + env.statement.seq + ' on the filing, ' + env.statement.refundId + ' of ' + env.statement.amount + ' ' + env.statement.currency + ', total paid ' + env.statement.paidTotal + ', sealed as ' + qx.refOf(env) + ', written to ' + safe(out));
  return 0;
}

async function cmdVerify(positional, flags) {
  if (positional.length !== 1) throw usageError('verify takes one envelope');
  const type = need(flags, 'type');
  if (!qx.TYPES.includes(type)) throw usageError('--type is one of ' + qx.TYPES.join(', '));
  const allowed = new Set(VERIFY_COMMON.concat(VERIFY_BY_TYPE[type]));
  for (const k of Object.keys(flags)) if (!allowed.has(k)) throw usageError('--' + k + ' does not apply when verifying ' + (type === 'invoice' || type === 'assessment' ? 'an ' : 'a ') + type);
  const env = readJson(positional[0], 'envelope', true);
  const opts = { type, requireAnchor: !flags['allow-unanchored'] };
  for (const [flag, name] of [['intake', 'intakeKeys'], ['assessor', 'assessorKeys'], ['officer', 'officerKeys']]) {
    const list = capList(flags[flag], flag, 64);
    if (list.length) opts[name] = list.map((k) => keyRef(k, flag));
  }
  if (flags.seller !== undefined) opts.sellerKeyId = keyRef(flags.seller, 'seller');
  if (flags['max-anchor-delay'] !== undefined) opts.maxAnchorDelay = seqFlag(flags['max-anchor-delay'], 'max-anchor-delay');
  const c = await digestFrom(flags, 'content', 'content-digest', 'return file', false);
  if (c) opts.contentDigest = c.digest;
  if (flags.document !== undefined) opts.invoiceDigest = (await hashFile(flags.document, 'invoice document')).digest;
  if (flags.outcome !== undefined) opts.outcomeDigest = (await hashFile(flags.outcome, 'assessment document')).digest;
  const prevWhat = type === 'filing' ? 'amended filing' : 'superseded assessment';
  for (const [flag, name, what] of [['previous', 'previous', prevWhat], ['invoice', 'invoice', 'invoice'], ['filing', 'filing', 'filing'], ['assessment', 'assessment', 'assessment'], ['root', 'root', 'original return']]) {
    if (flags[flag] !== undefined) opts[name] = readJson(flags[flag], what, true);
  }
  if (flags['previous-refund']) opts.previousRefunds = capList(flags['previous-refund'], 'previous-refund', 500).map((f) => readJson(f, 'refund', true));
  if (flags['other-assessment']) opts.otherAssessments = capList(flags['other-assessment'], 'other-assessment', 500).map((f) => readJson(f, 'assessment', true));
  const hasIdentity = flags['taxpayer-identity-file'] !== undefined;
  if (hasIdentity !== (flags['taxpayer-salt-file'] !== undefined)) throw usageError('a taxpayer identity and --taxpayer-salt-file go together');
  if (hasIdentity) opts.taxpayer = { identity: identityFrom(flags, 'taxpayer-identity-file'), salt: readSalt(flags['taxpayer-salt-file']) };
  if (flags.at !== undefined) opts.at = flags.at;
  if (flags['all-supplied']) opts.allSupplied = true;
  if (flags.rpc) opts.rpc = flags.rpc;
  let res;
  try {
    res = await qx.verify(env, opts);
  } finally {
    if (opts.taxpayer) opts.taxpayer.salt.fill(0);
  }
  if (flags.json) {
    process.stdout.write(asciiJson(res) + '\n');
  } else {
    if (res.type) console.log('type  ' + res.type);
    for (const ch of res.checks) console.log((ch.ok ? 'ok    ' : ch.transport ? 'retry ' : ch.indeterminate ? 'open  ' : 'FAIL  ') + safe(ch.name) + '  ' + safe(ch.detail));
    if ((res.endpoints || []).length) {
      console.log('endpoints  ' + res.endpoints.map(safe).join(', '));
      if (res.officialEndpoints === false) console.log('notice  anchor times were confirmed by an endpoint that is not the official one for this network, so they are only as reliable as that endpoint');
    }
    console.log(res.status.toUpperCase());
  }
  return res.status === 'valid' ? 0 : res.status === 'indeterminate' ? 2 : 1;
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return command ? 0 : 64;
  }
  if (!Object.hasOwn(SPEC, command)) throw usageError('unknown command ' + safe(command).slice(0, 40));
  const { positional, flags } = parse(command, rest);
  const run = { keygen: cmdKeygen, key: cmdKey, 'commit-party': cmdCommitParty, file: cmdFile, invoice: cmdInvoice, claim: cmdClaim, assess: cmdAssess, refund: cmdRefund, anchor: cmdAnchor, complete: cmdComplete, verify: cmdVerify }[command];
  return run(positional, flags);
}

function friendly(e) {
  if (e && typeof e.syscall === 'string' && typeof e.code === 'string') return 'a file could not be ' + (e.syscall === 'open' || e.syscall === 'read' ? 'opened' : 'written') + ' (' + e.code + ')';
  return (e && e.message) || String(e);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    console.error(safe(friendly(e)).slice(0, 600));
    const evidence = /not a valid envelope|not validly signed|must be an? (filing|invoice|claim|assessment|refund) envelope|does not belong to these|only the buyer named|above the refund due|already anchored|signature that does not verify|not signed by the key it names|was paid on another return|paid in another currency|relied on a later assessment|same return|must not hold the key|cannot be paid before the previous refund|decided before the assessment it supersedes|amendment cannot be received before|cannot be claimed before|cannot be decided before|cannot be paid before its assessment|same taxpayer|same period and form/;
    process.exitCode = e && (e.usage || (e.code === 'QTAX_INVALID_INPUT' && !evidence.test(e.message || ''))) ? 64 : 1;
  },
);
