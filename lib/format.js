// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const nodeCrypto = require('crypto');

const FORMAT = 'qtax/1';
const ALGORITHM = 'ML-DSA-65';
const KIND = 1101;
const TYPES = Object.freeze(['filing', 'invoice', 'claim', 'assessment', 'refund']);
const KEY_DOMAIN = Buffer.from('quantova/qtax/key/1', 'ascii');
const REF_DOMAIN = Buffer.from('quantova/qtax/ref/1', 'ascii');
const ANCHOR_DOMAIN = Buffer.from('quantova/qtax/anchor/1', 'ascii');
const PARTY_DOMAIN = Buffer.from('quantova/qtax/party/1', 'ascii');
const MAGIC = Buffer.from('QTAX', 'ascii');
const VERSION = 1;
const PUBLIC_KEY_BYTES = 1952;
const SIGNATURE_BYTES = 3309;
const LABEL_MAX = 64;
const NOTE_MAX = 1000;
const SEQ_MAX = 1000000;
const PARTY_MAX = 256;
const HEX32 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{32}$/;
const CURRENCY = /^[A-Z]{3}$/;
const AMOUNT = /^(0|[1-9][0-9]{0,29})$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u115f\u1160\u3164\uffa0]/u;
const FIELDS = Object.freeze({
  filing: Object.freeze(['filingId', 'authorityKeyId', 'taxpayerRef', 'period', 'form', 'contentDigest', 'contentSize', 'amends', 'rootRef', 'receivedAt', 'note']),
  invoice: Object.freeze(['invoiceId', 'sellerKeyId', 'buyerKeyId', 'invoiceDigest', 'currency', 'total', 'tax', 'issuedAt', 'note']),
  claim: Object.freeze(['claimId', 'buyerKeyId', 'invoiceRef', 'claimedAt', 'note']),
  assessment: Object.freeze(['assessmentId', 'assessorKeyId', 'filingRef', 'rootFilingRef', 'seq', 'supersedes', 'outcomeDigest', 'currency', 'refundDue', 'decidedAt', 'note']),
  refund: Object.freeze(['refundId', 'officerKeyId', 'rootFilingRef', 'assessmentRef', 'assessmentSeq', 'seq', 'prevRefundRef', 'currency', 'amount', 'paidTotal', 'paidAt', 'note']),
});
const SIGNER = Object.freeze({ filing: 'authorityKeyId', invoice: 'sellerKeyId', claim: 'buyerKeyId', assessment: 'assessorKeyId', refund: 'officerKeyId' });
const CLAIMED = Object.freeze({ filing: 'receivedAt', invoice: 'issuedAt', claim: 'claimedAt', assessment: 'decidedAt', refund: 'paidAt' });

function fail(message) {
  const e = new Error('the envelope is not valid, ' + message);
  e.code = 'QTAX_INVALID_ENVELOPE';
  throw e;
}

function reject(message) {
  const e = new Error(message);
  e.code = 'QTAX_INVALID_INPUT';
  throw e;
}

function sha3(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function keyIdOf(publicKey) {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== PUBLIC_KEY_BYTES) reject('a public key is ' + PUBLIC_KEY_BYTES + ' bytes');
  return sha3(KEY_DOMAIN, Buffer.from([0]), publicKey).toString('hex');
}

function textProblem(value, max, what, required) {
  if (typeof value !== 'string') return what + ' must be text';
  if (required && value.length === 0) return what + ' must not be empty';
  if (value.length > max) return what + ' is longer than ' + max + ' characters';
  if (!value.isWellFormed()) return what + ' holds a broken Unicode surrogate';
  if (value.normalize('NFC') !== value) return what + ' must be in Unicode normal form C';
  if (UNSAFE_TEXT.test(value)) return what + ' holds control, invisible or direction characters';
  return null;
}

function timeProblem(value, what) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return what + ' must be an ISO 8601 UTC time with milliseconds and a Z suffix';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) return what + ' is not a real calendar time';
  return null;
}

function pattern(value, re, what, rule) {
  if (typeof value !== 'string' || !re.test(value)) return what + ' must be ' + rule;
  return null;
}

function optionalDigest(value, what) {
  if (value === '') return null;
  return pattern(value, HEX32, what, 'empty or 64 lowercase hex characters');
}

function sameKeys(obj, fields) {
  return Object.keys(obj).sort().join(',') === fields.slice().sort().join(',');
}

function field(buf) {
  if (buf.length > 0xffff) reject('a signed field is too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(buf.length);
  return Buffer.concat([len, buf]);
}

function u64(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return field(b);
}

function decodeBase64(value, bytes, what) {
  if (typeof value !== 'string' || value.length !== Math.ceil(bytes / 3) * 4) fail(what + ' must be base64 of ' + bytes + ' bytes');
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value || raw.length !== bytes) fail(what + ' is not canonical base64 of ' + bytes + ' bytes');
  return raw;
}

function exactKeys(obj, required, optional, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const allowed = new Set(required.concat(optional));
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(where + ' holds an unexpected field');
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) fail(where + ' is missing ' + k);
}

function plainCopy(value, depth) {
  const d = depth === undefined ? 0 : depth;
  if (d > 6) throw new Error('nested too deeply');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('not a finite number');
    return value;
  }
  if (typeof value !== 'object') throw new Error('not plain data');
  const proto = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (proto !== Array.prototype) throw new Error('not a plain array');
    if (value.length > 4096) throw new Error('a list is too long');
    const out = [];
    for (let i = 0; i < value.length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(value, i);
      if (!desc || !('value' in desc)) throw new Error('not plain data');
      out.push(plainCopy(desc.value, d + 1));
    }
    return out;
  }
  if (proto !== Object.prototype && proto !== null) throw new Error('not a plain object');
  const out = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new Error('not plain data');
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!('value' in desc) || !desc.enumerable) throw new Error('not plain data');
    Object.defineProperty(out, key, { value: plainCopy(desc.value, d + 1), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

function partyIdentity(identity) {
  if (typeof identity !== 'string' || !identity.isWellFormed()) reject('the party identity must be well formed text');
  const id = identity.normalize('NFC');
  const p = textProblem(id, PARTY_MAX, 'the party identity', true);
  if (p) reject(p);
  return id;
}

function partyRef(salt, identity) {
  if (!(salt instanceof Uint8Array) || salt.length !== 32) reject('the party salt is 32 bytes');
  return sha3(PARTY_DOMAIN, Buffer.from([0]), salt, Buffer.from(partyIdentity(identity), 'utf8')).toString('hex');
}

function seqProblem(value, what) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1 || value > SEQ_MAX) return what + ' must be a whole number from 1 to ' + SEQ_MAX;
  return null;
}

function amountProblem(value, what) {
  if (typeof value !== 'string' || !AMOUNT.test(value)) return what + ' must be a whole number of minor units without leading zeros';
  return null;
}

function statementProblem(type, st) {
  if (st === null || typeof st !== 'object' || Array.isArray(st)) return 'the statement must be an object';
  if (!TYPES.includes(type)) return 'type must be one of ' + TYPES.join(', ');
  if (!sameKeys(st, FIELDS[type])) return 'a ' + type + ' statement holds exactly ' + FIELDS[type].join(', ');
  const id = (k) => pattern(st[k], HEX16, k, '32 lowercase hex characters');
  const key = (k) => pattern(st[k], HEX32, k, '64 lowercase hex characters');
  const note = textProblem(st.note, NOTE_MAX, 'note', false);
  if (type === 'filing') {
    return id('filingId') || key('authorityKeyId') || key('taxpayerRef')
      || textProblem(st.period, LABEL_MAX, 'period', true) || textProblem(st.form, LABEL_MAX, 'form', true)
      || key('contentDigest')
      || (typeof st.contentSize === 'number' && Number.isSafeInteger(st.contentSize) && st.contentSize >= 0 && !Object.is(st.contentSize, -0) ? null : 'contentSize must be a whole number of bytes from 0')
      || optionalDigest(st.amends, 'amends') || optionalDigest(st.rootRef, 'rootRef') || timeProblem(st.receivedAt, 'receivedAt') || note
      || ((st.amends === '') !== (st.rootRef === '') ? 'only an original filing names no root filing' : null);
  }
  if (type === 'invoice') {
    const p = textProblem(st.invoiceId, LABEL_MAX, 'invoiceId', true) || key('sellerKeyId') || key('buyerKeyId') || key('invoiceDigest')
      || pattern(st.currency, CURRENCY, 'currency', 'a three letter ISO 4217 code')
      || amountProblem(st.total, 'total') || amountProblem(st.tax, 'tax') || timeProblem(st.issuedAt, 'issuedAt') || note;
    if (p) return p;
    if (BigInt(st.tax) > BigInt(st.total)) return 'tax cannot exceed the invoice total';
    if (st.sellerKeyId === st.buyerKeyId) return 'the seller and the buyer must be different parties';
    return null;
  }
  if (type === 'claim') {
    return id('claimId') || key('buyerKeyId') || key('invoiceRef') || timeProblem(st.claimedAt, 'claimedAt') || note;
  }
  if (type === 'assessment') {
    const p = id('assessmentId') || key('assessorKeyId') || key('filingRef') || key('rootFilingRef') || seqProblem(st.seq, 'seq') || optionalDigest(st.supersedes, 'supersedes')
      || key('outcomeDigest') || pattern(st.currency, CURRENCY, 'currency', 'a three letter code') || amountProblem(st.refundDue, 'refundDue')
      || timeProblem(st.decidedAt, 'decidedAt') || note;
    if (p) return p;
    if ((st.seq === 1) !== (st.supersedes === '')) return 'only the first assessment of a filing supersedes nothing';
    return null;
  }
  const p = id('refundId') || key('officerKeyId') || key('rootFilingRef') || key('assessmentRef') || seqProblem(st.assessmentSeq, 'assessmentSeq')
    || seqProblem(st.seq, 'seq') || optionalDigest(st.prevRefundRef, 'prevRefundRef') || pattern(st.currency, CURRENCY, 'currency', 'a three letter code')
    || amountProblem(st.amount, 'amount') || amountProblem(st.paidTotal, 'paidTotal') || timeProblem(st.paidAt, 'paidAt') || note;
  if (p) return p;
  if (st.amount === '0') return 'a refund amount must be greater than zero';
  if ((st.seq === 1) !== (st.prevRefundRef === '')) return 'only the first refund on a return names no previous refund';
  if (st.seq === 1 && st.paidTotal !== st.amount) return 'the paid total of the first refund on a filing is its amount';
  if (st.seq > 1 && BigInt(st.paidTotal) <= BigInt(st.amount)) return 'the paid total must include the earlier refunds on the filing';
  return null;
}

const ascii = (s) => field(Buffer.from(s, 'ascii'));
const utf8 = (s) => field(Buffer.from(s, 'utf8'));
const hex = (s) => field(Buffer.from(s, 'hex'));

function payload(type, st) {
  const parts = [MAGIC, Buffer.from([VERSION]), ascii(type)];
  if (type === 'filing') {
    parts.push(hex(st.filingId), hex(st.authorityKeyId), hex(st.taxpayerRef), utf8(st.period), utf8(st.form), hex(st.contentDigest), u64(st.contentSize), hex(st.amends), hex(st.rootRef), ascii(st.receivedAt));
  } else if (type === 'invoice') {
    parts.push(utf8(st.invoiceId), hex(st.sellerKeyId), hex(st.buyerKeyId), hex(st.invoiceDigest), ascii(st.currency), ascii(st.total), ascii(st.tax), ascii(st.issuedAt));
  } else if (type === 'claim') {
    parts.push(hex(st.claimId), hex(st.buyerKeyId), hex(st.invoiceRef), ascii(st.claimedAt));
  } else if (type === 'assessment') {
    parts.push(hex(st.assessmentId), hex(st.assessorKeyId), hex(st.filingRef), hex(st.rootFilingRef), u64(st.seq), hex(st.supersedes), hex(st.outcomeDigest), ascii(st.currency), ascii(st.refundDue), ascii(st.decidedAt));
  } else {
    parts.push(hex(st.refundId), hex(st.officerKeyId), hex(st.rootFilingRef), hex(st.assessmentRef), u64(st.assessmentSeq), u64(st.seq), hex(st.prevRefundRef), ascii(st.currency), ascii(st.amount), ascii(st.paidTotal), ascii(st.paidAt));
  }
  parts.push(utf8(st.note));
  return Buffer.concat(parts);
}

function parse(envelope) {
  let env;
  try {
    env = plainCopy(envelope);
  } catch (e) {
    fail('it is not plain data');
  }
  exactKeys(env, ['format', 'type', 'algorithm', 'signer', 'statement', 'signature'], ['anchor'], 'the envelope');
  if (env.format !== FORMAT) fail('format must be ' + FORMAT);
  if (env.algorithm !== ALGORITHM) fail('algorithm must be ' + ALGORITHM);
  if (!TYPES.includes(env.type)) fail('type must be one of ' + TYPES.join(', '));
  exactKeys(env.signer, ['id', 'publicKey'], [], 'signer');
  if (typeof env.signer.id !== 'string' || !HEX32.test(env.signer.id)) fail('signer.id must be 64 lowercase hex characters');
  const publicKey = decodeBase64(env.signer.publicKey, PUBLIC_KEY_BYTES, 'signer.publicKey');
  const problem = statementProblem(env.type, env.statement);
  if (problem) fail(problem);
  const signature = decodeBase64(env.signature, SIGNATURE_BYTES, 'signature');
  const anchor = Object.prototype.hasOwnProperty.call(env, 'anchor') ? env.anchor : undefined;
  return { type: env.type, signerId: env.signer.id, publicKey, statement: env.statement, signature, anchor };
}

function refOf(parsed) {
  return sha3(REF_DOMAIN, Buffer.from([0]), payload(parsed.type, parsed.statement), parsed.signature).toString('hex');
}

function anchorDigest(parsed) {
  return sha3(ANCHOR_DOMAIN, Buffer.from([0]), payload(parsed.type, parsed.statement), parsed.signature);
}

function rootOf(filing) {
  return filing.statement.rootRef || refOf(filing);
}

function boundKey(parsed) {
  return parsed.statement[SIGNER[parsed.type]];
}

module.exports = {
  FORMAT, ALGORITHM, KIND, TYPES, FIELDS, SIGNER, CLAIMED, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, LABEL_MAX, NOTE_MAX, SEQ_MAX,
  sha3, keyIdOf, partyIdentity, partyRef, textProblem, timeProblem, statementProblem, payload, parse, refOf, anchorDigest, boundKey, rootOf, reject, plainCopy,
};
