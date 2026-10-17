// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const qstamp = require('@quantovainc/qstamp');
const F = require('./format');
const T = require('./tax');

const CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_ANCHOR_DELAY_S = 24 * 60 * 60;
const ANCHOR_DELAY_MAX_S = 366 * 24 * 60 * 60;
const LIST_MAX = 500;
const PASS = ['rpc', 'client', 'clients', 'contract', 'trustCustomContract'];
const COMMON = ['type', 'requireAnchor', 'at', 'maxAnchorDelay'].concat(PASS);
const ROLES = ['intakeKeys', 'assessorKeys', 'officerKeys'];
const ALLOWED = {
  filing: ROLES.concat(['content', 'contentDigest', 'taxpayer', 'previous']),
  invoice: ['sellerKeyId', 'document', 'invoiceDigest'],
  claim: ['sellerKeyId', 'invoice'],
  assessment: ROLES.concat(['outcome', 'outcomeDigest', 'filing', 'root', 'previous', 'otherAssessments', 'allSupplied']),
  refund: ROLES.concat(['assessment', 'filing', 'root', 'previousRefunds', 'otherAssessments', 'allSupplied']),
};

function plain(text) {
  return String(text).replace(/:\s+/g, ', ').replace(/;\s*/g, ', ').slice(0, 300);
}

function statusOf(checks) {
  if (checks.some((c) => !c.ok && !c.transport && !c.indeterminate)) return 'invalid';
  if (checks.some((c) => !c.ok)) return 'indeterminate';
  return 'valid';
}

function finish(checks, extra, net) {
  const status = statusOf(checks);
  const seen = net ? { endpoints: [...net.endpoints], officialEndpoints: net.official } : { endpoints: [], officialEndpoints: null };
  return Object.assign({ valid: status === 'valid', status }, extra, seen, { checks: checks.map((c) => Object.assign({}, c)) });
}

function anchorOptions(opts) {
  const out = {};
  for (const k of PASS) if (opts[k] !== undefined) out[k] = opts[k];
  return out;
}

function article(word) {
  return (/^[aeiou]/.test(word) ? 'an ' : 'a ') + word;
}

function iso(ms) {
  return new Date(ms).toISOString();
}

function keyList(opts, name) {
  const v = opts[name];
  if (v === undefined) return null;
  if (!Array.isArray(v) || v.length === 0 || v.length > 64) F.reject(name + ' is a list of 1 to 64 trusted keys');
  return new Set(v.map((k, i) => T.keyIdFrom(k, name + ' ' + (i + 1))));
}

function rolesOf(opts) {
  const roles = { intake: keyList(opts, 'intakeKeys'), assessor: keyList(opts, 'assessorKeys'), officer: keyList(opts, 'officerKeys') };
  const names = Object.keys(roles);
  for (let i = 0; i < names.length; i += 1) {
    for (let j = i + 1; j < names.length; j += 1) {
      const a = roles[names[i]];
      const b = roles[names[j]];
      if (a && b) for (const k of a) if (b.has(k)) F.reject('the key ' + k + ' is trusted as both ' + names[i] + ' and ' + names[j] + ', a key may hold only one role');
    }
  }
  return roles;
}

function needRole(roles, name, label) {
  if (roles[name] === null) F.reject('the trusted ' + label + ' keys are required, give ' + name + 'Keys so an attacker cannot substitute a key of its own');
  return roles[name];
}

function digestGiven(opts, bytesKey, digestKey) {
  const given = [bytesKey, digestKey].filter((k) => opts[k] !== undefined);
  if (given.length > 1) F.reject('give ' + bytesKey + ' or ' + digestKey + ', not both');
  if (given.length === 0) return null;
  if (opts[bytesKey] !== undefined) {
    if (!(opts[bytesKey] instanceof Uint8Array)) F.reject(bytesKey + ' is a Uint8Array');
    return { digest: F.sha3(opts[bytesKey]).toString('hex'), size: opts[bytesKey].length };
  }
  if (typeof opts[digestKey] !== 'string' || !/^[0-9a-f]{64}$/.test(opts[digestKey])) F.reject(digestKey + ' is 64 lowercase hex characters');
  return { digest: opts[digestKey], size: null };
}

function atOf(opts) {
  if (opts.at === undefined) return Date.now();
  const tp = F.timeProblem(opts.at, 'at');
  if (tp) F.reject(tp);
  return Date.parse(opts.at);
}

function delayOf(opts) {
  if (opts.maxAnchorDelay === undefined) return DEFAULT_ANCHOR_DELAY_S * 1000;
  const v = opts.maxAnchorDelay;
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 60 || v > ANCHOR_DELAY_MAX_S) F.reject('maxAnchorDelay is a whole number of seconds from 60 to ' + ANCHOR_DELAY_MAX_S);
  return v * 1000;
}

function claimedMs(p) {
  return Date.parse(p.statement[F.CLAIMED[p.type]]);
}

function order(earlier, later, ctx, label, message) {
  if (claimedMs(earlier) > claimedMs(later)) ctx.add(label, false, message);
}

async function checkAnchor(p, ctx, label) {
  const { add } = ctx;
  const receipt = p.anchor;
  if (receipt === undefined) {
    if (ctx.req) add(label, false, 'not anchored, so its time is only the claim of its signer', false, true);
    else add(label, true, 'not anchored, the time is the claim of the signer and was not proven');
    return null;
  }
  try {
    if (receipt === null || typeof receipt !== 'object' || Array.isArray(receipt)) {
      add(label, false, 'the anchor is not a Qstamp receipt');
      return null;
    }
    if (receipt.kind !== String(F.KIND)) {
      add(label, false, 'the anchor was not recorded under the QTax record kind');
      return null;
    }
    if (!receipt.record || receipt.record.alg !== 'sha3-256') {
      add(label, false, 'the anchor does not record a SHA3 digest');
      return null;
    }
    const result = await qstamp.verify(receipt, Object.assign(anchorOptions(ctx.opts), { digest: F.anchorDigest(p) }));
    for (const e of result.endpoints || []) ctx.net.endpoints.add(e);
    if ((result.endpoints || []).length) ctx.net.official = ctx.net.official !== false && result.officialEndpoints === true;
    for (const c of result.checks) add(label + ' ' + c.name, c.ok, c.detail, c.transport);
    if (result.status !== 'valid') return null;
    const ms = receipt.anchor.time * 1000;
    const claimed = claimedMs(p);
    if (claimed > ms + CLOCK_SKEW_MS) {
      add(label + ' time', false, 'the stated time is later than the anchor time ' + iso(ms));
      return null;
    }
    if (ms - claimed > ctx.delayMs) {
      add(label + ' time', false, 'anchored at ' + iso(ms) + ', more than ' + Math.round(ctx.delayMs / 3600000) + ' hours after its stated time, so the stated time is not proven', false, true);
      return null;
    }
    if (ctx.atGiven && ms > ctx.atMs) {
      add(label + ' time', false, 'anchored at ' + iso(ms) + ', after the time given for verification, so it was not proven at that time', false, true);
      return null;
    }
    add(label + ' time', true, 'recorded by ' + iso(ms));
    return { ms };
  } catch (e) {
    add(label, false, 'the anchor could not be checked, ' + ((e && e.message) || 'unknown error'));
    return null;
  }
}

function linked(ctx, name, type, ref, label) {
  const { opts, add } = ctx;
  if (opts[name] === undefined) {
    add(label, false, 'the ' + type + ' this record relies on was not supplied', false, true);
    return null;
  }
  let p;
  try {
    p = F.parse(opts[name]);
  } catch (e) {
    add(label, false, 'the ' + type + ' supplied is not valid, ' + e.message);
    return null;
  }
  if (p.type !== type || F.refOf(p) !== ref) {
    add(label, false, 'the ' + type + ' supplied is not the one this record names');
    return null;
  }
  if (!T.signatureOk(p)) {
    add(label, false, 'the ' + type + ' supplied is not validly signed');
    return null;
  }
  add(label, true, 'the ' + type + ' this record names is supplied and validly signed');
  return p;
}

function trusted(set, keyIdValue, ctx, label, role) {
  const ok = set.has(keyIdValue);
  ctx.add(label, ok, ok ? 'signed by a trusted ' + role : 'signed by a key that is not a trusted ' + role);
  return ok;
}

function contentCheck(ctx, bytesKey, digestKey, want, size, label, required) {
  const c = digestGiven(ctx.opts, bytesKey, digestKey);
  if (!c) {
    if (required) ctx.add(label, false, 'the document was not supplied, so it is unknown whether this record describes it', false, true);
    return null;
  }
  const same = c.digest === want && (size === undefined || c.size === null || c.size === size);
  ctx.add(label, same, same ? 'the document matches the fingerprint that was signed' : 'the document differs from the one that was signed');
  return same;
}

function envelopeList(ctx, name, max) {
  const v = ctx.opts[name];
  if (v === undefined) return null;
  if (!Array.isArray(v) || v.length > max) F.reject(name + ' is a list of at most ' + max + ' envelopes');
  return v;
}

async function verifyFiling(p, ctx) {
  const st = p.statement;
  const intake = needRole(ctx.roles, 'intake', 'intake');
  trusted(intake, st.authorityKeyId, ctx, 'intake', 'intake key');
  contentCheck(ctx, 'content', 'contentDigest', st.contentDigest, st.contentSize, 'content', true);
  if (ctx.opts.taxpayer !== undefined) {
    const tp = ctx.opts.taxpayer;
    if (!tp || typeof tp !== 'object' || !(tp.salt instanceof Uint8Array)) F.reject('taxpayer is an object with identity and a 32 byte salt');
    const same = F.partyRef(tp.salt, tp.identity) === st.taxpayerRef;
    ctx.add('taxpayer', same, same ? 'the taxpayer matches the private commitment in the filing' : 'the taxpayer or its salt differs from the commitment in the filing');
  }
  if (st.amends !== '') {
    const prev = linked(ctx, 'previous', 'filing', st.amends, 'amended filing');
    if (prev) {
      trusted(intake, prev.statement.authorityKeyId, ctx, 'amended filing intake', 'intake key');
      const same = prev.statement.taxpayerRef === st.taxpayerRef && prev.statement.period === st.period && prev.statement.form === st.form && st.rootRef === F.rootOf(prev);
      ctx.add('amendment', same, same ? 'the amendment concerns the same taxpayer, period and form' : 'the amendment concerns a different taxpayer, period or form');
      order(prev, p, ctx, 'amendment order', 'the amendment is dated before the filing it amends');
      await checkAnchor(prev, ctx, 'amended filing anchor');
    }
  }
  return { filingId: st.filingId, taxpayerRef: st.taxpayerRef, period: st.period, form: st.form, amends: st.amends || null };
}

function sellerOf(ctx, what) {
  if (ctx.opts.sellerKeyId === undefined) F.reject('the expected seller' + what + ' is required, give sellerKeyId');
  return T.keyIdFrom(ctx.opts.sellerKeyId, 'sellerKeyId');
}

async function verifyInvoice(p, ctx) {
  const st = p.statement;
  const seller = sellerOf(ctx, '');
  ctx.add('seller', seller === st.sellerKeyId, seller === st.sellerKeyId ? 'issued by the expected seller' : 'issued by a different seller than expected');
  contentCheck(ctx, 'document', 'invoiceDigest', st.invoiceDigest, undefined, 'document', false);
  return { invoiceId: st.invoiceId, sellerKeyId: st.sellerKeyId, buyerKeyId: st.buyerKeyId, currency: st.currency, total: st.total, tax: st.tax };
}

async function verifyClaim(p, ctx) {
  const st = p.statement;
  const seller = sellerOf(ctx, ' of the claimed invoice');
  const inv = linked(ctx, 'invoice', 'invoice', st.invoiceRef, 'invoice');
  let invoiceInfo = null;
  if (inv) {
    const sellerOk = inv.statement.sellerKeyId === seller;
    ctx.add('seller', sellerOk, sellerOk ? 'the invoice was issued by the expected seller' : 'the invoice was issued by a different seller than expected');
    const buyerOk = inv.statement.buyerKeyId === st.buyerKeyId;
    ctx.add('buyer', buyerOk, buyerOk ? 'the claim is signed by the buyer named on the invoice' : 'the claim is signed by a party that is not the buyer on the invoice');
    order(inv, p, ctx, 'claim order', 'the invoice is claimed before it was issued');
    await checkAnchor(inv, ctx, 'invoice anchor');
    invoiceInfo = { invoiceId: inv.statement.invoiceId, currency: inv.statement.currency, total: inv.statement.total, tax: inv.statement.tax };
  }
  return { claimId: st.claimId, buyerKeyId: st.buyerKeyId, invoice: invoiceInfo };
}

async function verifyAssessment(p, ctx) {
  const st = p.statement;
  const intake = needRole(ctx.roles, 'intake', 'intake');
  const assessors = needRole(ctx.roles, 'assessor', 'assessor');
  trusted(assessors, st.assessorKeyId, ctx, 'assessor', 'assessor');
  contentCheck(ctx, 'outcome', 'outcomeDigest', st.outcomeDigest, undefined, 'outcome', false);
  const filing = linked(ctx, 'filing', 'filing', st.filingRef, 'filing');
  if (filing) {
    trusted(intake, filing.statement.authorityKeyId, ctx, 'filing intake', 'intake key');
    const apart = filing.statement.authorityKeyId !== st.assessorKeyId;
    ctx.add('separation', apart, apart ? 'the filing was received and assessed by different keys' : 'the same key received the filing and assessed it');
    const rooted = F.rootOf(filing) === st.rootFilingRef;
    ctx.add('return', rooted, rooted ? 'the assessment names the original return of the filing' : 'the assessment names a different original return from its filing');
    order(filing, p, ctx, 'assessment order', 'the assessment is dated before the filing was received');
    await checkAnchor(filing, ctx, 'filing anchor');
    await rootCheck(filing, ctx, intake);
  }
  if (st.supersedes !== '') {
    const prev = linked(ctx, 'previous', 'assessment', st.supersedes, 'superseded assessment');
    if (prev) {
      trusted(assessors, prev.statement.assessorKeyId, ctx, 'superseded assessor', 'assessor');
      const same = prev.statement.rootFilingRef === st.rootFilingRef && prev.statement.seq + 1 === st.seq && prev.statement.currency === st.currency;
      ctx.add('supersession', same, same ? 'it replaces assessment ' + prev.statement.seq + ' of the same return in the same currency' : 'it does not follow the assessment it supersedes on the same return');
      order(prev, p, ctx, 'supersession order', 'the assessment is dated before the assessment it supersedes');
      await checkAnchor(prev, ctx, 'superseded assessment anchor');
    }
  }
  const others = parsedList(ctx, 'otherAssessments', 'assessment', st.rootFilingRef, assessors, 'assessor', 'supplied assessment');
  if (others) {
    assessmentForks(p, others.map, ctx);
    assessmentLine(p, others.map, ctx, ctx.opts.allSupplied === true);
    const later = [...others.map.values()].filter((o) => o.statement.seq > st.seq).map((o) => o.statement.seq);
    if (later.length) ctx.add('current', false, 'assessment ' + Math.max(...later) + ' of this return replaces this assessment', false, true);
  }
  if (ctx.opts.allSupplied !== true) {
    ctx.add('completeness', false, 'the verifier did not declare that every assessment held for this return was supplied, so a later assessment may replace this one', false, true);
  } else {
    ctx.add('completeness', true, 'the verifier declared that every assessment held for this return was supplied');
  }
  return { assessmentId: st.assessmentId, filingRef: st.filingRef, rootFilingRef: st.rootFilingRef, seq: st.seq, supersedes: st.supersedes || null, currency: st.currency, refundDue: st.refundDue };
}

async function rootCheck(filing, ctx, intake) {
  if (filing.statement.rootRef === '') return;
  const root = linked(ctx, 'root', 'filing', filing.statement.rootRef, 'original return');
  if (!root) return;
  trusted(intake, root.statement.authorityKeyId, ctx, 'original return intake', 'intake key');
  const same = root.statement.amends === '' && root.statement.taxpayerRef === filing.statement.taxpayerRef && root.statement.period === filing.statement.period && root.statement.form === filing.statement.form;
  ctx.add('original return', same, same ? 'the original return is an original filing for the same taxpayer, period and form' : 'the record named as the original return is not an original filing for the same taxpayer, period and form');
  order(root, filing, ctx, 'original return order', 'the amendment is dated before the original return');
  await checkAnchor(root, ctx, 'original return anchor');
}

function supersededCheck(r, a, others, ctx, anchorMs, label) {
  for (const o of others.values()) {
    if (o.statement.seq <= r.statement.assessmentSeq) continue;
    if (claimedMs(o) <= claimedMs(r)) {
      ctx.add(label, false, 'refund ' + r.statement.seq + ' was paid against assessment ' + r.statement.assessmentSeq + ' after assessment ' + o.statement.seq + ' had replaced it');
      continue;
    }
    const replacedAt = o.anchorMs !== undefined ? Math.min(o.anchorMs, claimedMs(o)) : claimedMs(o);
    if (anchorMs === null || anchorMs === undefined || anchorMs > replacedAt) {
      ctx.add(label, false, 'assessment ' + o.statement.seq + ' replaced assessment ' + r.statement.assessmentSeq + ' before refund ' + r.statement.seq + ' was anchored, so it is not proven that the refund was paid first', false, true);
    }
  }
  if (a && BigInt(r.statement.paidTotal) > BigInt(a.statement.refundDue)) {
    ctx.add(label, false, 'refund ' + r.statement.seq + ' took the total paid to ' + r.statement.paidTotal + ', above the ' + a.statement.refundDue + ' due on its own assessment');
  }
}

function assessmentLine(a, map, ctx, strict) {
  let cur = a;
  while (cur.statement.seq > 1) {
    const prev = map ? map.get(cur.statement.supersedes) : undefined;
    if (!prev) {
      ctx.add('assessment line', false, 'assessment ' + (cur.statement.seq - 1) + ' of this return was not supplied' + (strict ? ', although every record was declared supplied' : ''), false, !strict);
      return false;
    }
    if (prev.statement.seq + 1 !== cur.statement.seq) {
      ctx.add('assessment line', false, 'assessment ' + cur.statement.seq + ' does not follow assessment ' + prev.statement.seq);
      return false;
    }
    cur = prev;
  }
  ctx.add('assessment line', true, 'every earlier assessment of this return is supplied');
  return true;
}

function assessmentForks(a, map, ctx) {
  const bySeq = new Map([[a.statement.seq, F.refOf(a)]]);
  let clash = false;
  for (const [ref, o] of map) {
    const held = bySeq.get(o.statement.seq);
    if (held !== undefined && held !== ref) {
      ctx.add('conflicting assessment', false, 'two different assessments hold position ' + o.statement.seq + ' on this return');
      clash = true;
    } else {
      bySeq.set(o.statement.seq, ref);
    }
  }
  return !clash;
}

function parsedList(ctx, name, type, rootFilingRef, trustedSet, role, label) {
  const list = envelopeList(ctx, name, LIST_MAX);
  if (list === null) return null;
  const out = new Map();
  let ok = true;
  list.forEach((env, i) => {
    let r;
    try {
      r = F.parse(env);
    } catch (e) {
      ctx.add(label + ' ' + (i + 1), false, 'not a valid envelope, ' + e.message);
      ok = false;
      return;
    }
    if (r.type !== type || !T.signatureOk(r)) {
      ctx.add(label + ' ' + (i + 1), false, 'not ' + article(type) + ' validly signed by the key it names');
      ok = false;
      return;
    }
    if (r.statement.rootFilingRef !== rootFilingRef) {
      ctx.add(label + ' ' + (i + 1), false, 'it concerns another return');
      ok = false;
      return;
    }
    if (!trustedSet.has(r.signerId)) {
      ctx.add(label + ' ' + (i + 1), false, 'signed by a key that is not a trusted ' + role);
      ok = false;
      return;
    }
    out.set(F.refOf(r), r);
  });
  return { map: out, ok };
}

async function refundChain(p, ctx, officers, others) {
  const st = p.statement;
  const supplied = parsedList(ctx, 'previousRefunds', 'refund', st.rootFilingRef, officers, 'payment officer', 'supplied refund');
  if (st.seq === 1 && supplied === null) {
    ctx.add('refund chain', true, 'the first refund on this return');
    return true;
  }
  if (supplied === null) {
    const strict = ctx.opts.allSupplied === true;
    ctx.add('refund chain', false, 'the earlier refunds on this return were not supplied' + (strict ? ', although every record was declared supplied' : ', so the total paid is not proven'), false, !strict);
    return false;
  }
  const chain = new Map([[F.refOf(p), p]]);
  let cur = p;
  let complete = true;
  while (cur.statement.seq > 1) {
    const prev = supplied.map.get(cur.statement.prevRefundRef);
    if (!prev) {
      ctx.add('refund chain', false, 'refund ' + (cur.statement.seq - 1) + ' on this return was not supplied' + (ctx.opts.allSupplied === true ? ', although every record was declared supplied' : ''), false, ctx.opts.allSupplied !== true);
      complete = false;
      break;
    }
    const n = prev.statement.seq;
    const linkOk = n + 1 === cur.statement.seq
      && BigInt(prev.statement.paidTotal) + BigInt(cur.statement.amount) === BigInt(cur.statement.paidTotal)
      && prev.statement.currency === cur.statement.currency
      && prev.statement.assessmentSeq <= cur.statement.assessmentSeq;
    if (!linkOk) {
      ctx.add('refund chain', false, 'refund ' + cur.statement.seq + ' does not continue refund ' + n + ' in position, total, currency or assessment');
      complete = false;
      break;
    }
    order(prev, cur, ctx, 'refund chain order', 'refund ' + cur.statement.seq + ' is dated before refund ' + n);
    const pa = await checkAnchor(prev, ctx, 'refund ' + n + ' anchor');
    if (others) {
      const own = [...others.values()].find((o) => F.refOf(o) === prev.statement.assessmentRef) || null;
      supersededCheck(prev, own, others, ctx, pa ? pa.ms : null, 'refund ' + n + ' assessment');
    }
    chain.set(F.refOf(prev), prev);
    cur = prev;
  }
  if (complete) ctx.add('refund chain', true, 'every earlier refund on this return is supplied and adds up to the paid total ' + st.paidTotal);
  const bySeq = new Map();
  for (const r of chain.values()) bySeq.set(r.statement.seq, F.refOf(r));
  const flagged = new Set();
  for (const [ref, r] of supplied.map) {
    if (chain.has(ref)) continue;
    const held = bySeq.get(r.statement.seq);
    if (held !== undefined && held !== ref) {
      if (!flagged.has(r.statement.seq)) ctx.add('conflicting refund', false, 'two different refunds hold position ' + r.statement.seq + ' on this return');
      flagged.add(r.statement.seq);
    } else {
      bySeq.set(r.statement.seq, ref);
    }
  }
  return complete && supplied.ok;
}

async function verifyRefund(p, ctx) {
  const st = p.statement;
  const intake = needRole(ctx.roles, 'intake', 'intake');
  const assessors = needRole(ctx.roles, 'assessor', 'assessor');
  const officers = needRole(ctx.roles, 'officer', 'payment officer');
  trusted(officers, st.officerKeyId, ctx, 'officer', 'payment officer');
  let others = null;
  const a = linked(ctx, 'assessment', 'assessment', st.assessmentRef, 'assessment');
  if (a) {
    trusted(assessors, a.statement.assessorKeyId, ctx, 'assessment assessor', 'assessor');
    const apart = a.statement.assessorKeyId !== st.officerKeyId;
    ctx.add('separation', apart, apart ? 'the assessment and the refund were signed by different keys' : 'the same key decided the assessment and paid the refund');
    const same = a.statement.rootFilingRef === st.rootFilingRef && a.statement.seq === st.assessmentSeq && a.statement.currency === st.currency;
    ctx.add('assessment link', same, same ? 'paid on the return, assessment and currency of the assessment' : 'the refund does not match the return, position or currency of its assessment');
    order(a, p, ctx, 'refund order', 'the refund is dated before its assessment was decided');
    const aa = await checkAnchor(a, ctx, 'assessment anchor');
    ctx.aAnchorMs = aa ? aa.ms : undefined;
    const filing = linked(ctx, 'filing', 'filing', a.statement.filingRef, 'filing');
    if (filing) {
      trusted(intake, filing.statement.authorityKeyId, ctx, 'filing intake', 'intake key');
      order(filing, a, ctx, 'assessment order', 'the assessment is dated before the filing was received');
      const three = filing.statement.authorityKeyId !== a.statement.assessorKeyId && filing.statement.authorityKeyId !== st.officerKeyId;
      ctx.add('three keys', three, three ? 'the filing, the assessment and the refund were signed by three different keys' : 'the filing was signed by the key of the assessor or of the officer');
      const rooted = F.rootOf(filing) === st.rootFilingRef;
      ctx.add('return', rooted, rooted ? 'the refund is chained on the original return of the filing' : 'the refund is chained on a different return from its filing');
      await checkAnchor(filing, ctx, 'filing anchor');
      await rootCheck(filing, ctx, intake);
    }
    const due = BigInt(a.statement.refundDue);
    const within = BigInt(st.paidTotal) <= due;
    ctx.add('refund total', within, within ? 'refunds on this return total ' + st.paidTotal + ', within the ' + due + ' due' : 'refunds on this return total ' + st.paidTotal + ', above the ' + due + ' due');
    others = parsedList(ctx, 'otherAssessments', 'assessment', st.rootFilingRef, assessors, 'assessor', 'supplied assessment');
    if (a.statement.seq > 1 || others) assessmentLine(a, others ? others.map : null, ctx, ctx.opts.allSupplied === true);
    if (others) {
      assessmentForks(a, others.map, ctx);
      for (const o of others.map.values()) {
        if (o.statement.seq > a.statement.seq && claimedMs(o) > claimedMs(p)) {
          const oa = await checkAnchor(o, ctx, 'assessment ' + o.statement.seq + ' anchor');
          if (oa) o.anchorMs = oa.ms;
        }
      }
      supersededCheck(p, a, others.map, ctx, ctx.self ? ctx.self.ms : null, 'superseded');
    }
  }
  let replacing = others ? new Map(others.map) : null;
  if (a) {
    replacing = replacing || new Map();
    const aRef = F.refOf(a);
    if (!replacing.has(aRef)) replacing.set(aRef, Object.assign(a, { anchorMs: ctx.aAnchorMs }));
  }
  await refundChain(p, ctx, officers, replacing);
  if (ctx.opts.allSupplied !== true) {
    ctx.add('completeness', false, 'the verifier did not declare that every refund and assessment held for this return was supplied, so a conflicting record could be missing', false, true);
  } else {
    ctx.add('completeness', true, 'the verifier declared that every refund and assessment held for this return was supplied');
  }
  return { refundId: st.refundId, rootFilingRef: st.rootFilingRef, seq: st.seq, currency: st.currency, amount: st.amount, paidTotal: st.paidTotal };
}

async function verify(envelope, options) {
  if (options === null || typeof options !== 'object') F.reject('options is an object naming the expected type and the trusted keys');
  const opts = options;
  if (!F.TYPES.includes(opts.type)) F.reject('type is required and is one of ' + F.TYPES.join(', '));
  const allowed = new Set(COMMON.concat(ALLOWED[opts.type]));
  for (const k of Object.keys(opts)) if (!allowed.has(k)) F.reject('the option ' + k + ' does not apply to ' + article(opts.type));
  if (opts.allSupplied !== undefined && typeof opts.allSupplied !== 'boolean') F.reject('allSupplied is true or false');
  const ctx = {
    opts,
    req: opts.requireAnchor !== false,
    atMs: atOf(opts),
    atGiven: opts.at !== undefined,
    delayMs: delayOf(opts),
    roles: rolesOf(opts),
    checks: [],
    net: { endpoints: new Set(), official: null },
  };
  ctx.add = (name, ok, detail, transport, indeterminate) => ctx.checks.push({ name, ok: !!ok, detail: plain(detail), transport: !!transport, indeterminate: !!indeterminate });
  let p;
  try {
    p = F.parse(envelope);
  } catch (e) {
    ctx.add('format', false, e.message);
    return finish(ctx.checks, { type: null }, ctx.net);
  }
  if (p.type !== opts.type) {
    ctx.add('format', false, article(p.type) + ' was given where ' + article(opts.type) + ' was expected');
    return finish(ctx.checks, { type: p.type }, ctx.net);
  }
  ctx.add('format', true, 'a well formed ' + p.type + ' record');
  const sigOk = T.signatureOk(p);
  ctx.add('signature', sigOk, sigOk ? 'the ML-DSA-65 signature is valid' : 'the signature does not verify or does not belong to the key named in the record');
  const base = { type: p.type, ref: F.refOf(p), signerKeyId: p.signerId };
  if (!sigOk) return finish(ctx.checks, base, ctx.net);
  if (claimedMs(p) > ctx.atMs + CLOCK_SKEW_MS) ctx.add('time', false, 'the record is dated after the time of verification');
  ctx.self = await checkAnchor(p, ctx, 'anchor');
  const run = { filing: verifyFiling, invoice: verifyInvoice, claim: verifyClaim, assessment: verifyAssessment, refund: verifyRefund }[p.type];
  const extra = await run(p, ctx);
  return finish(ctx.checks, Object.assign(base, extra, { anchoredAt: ctx.self ? iso(ctx.self.ms) : null }), ctx.net);
}

module.exports = { verify };
