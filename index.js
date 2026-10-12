// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const T = require('./lib/tax');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: T.generateKey,
  publicKey: T.publicKey,
  keyId: T.keyId,
  describeKey: T.describeKey,
  commitParty: T.commitParty,
  file: T.file,
  invoice: T.invoice,
  claim: T.claim,
  assess: T.assess,
  refund: T.refund,
  anchor: T.anchor,
  complete: T.complete,
  verify,
  refOf: (envelope) => F.refOf(T.signedEnvelope(envelope, F.parse(envelope).type, 'the envelope')),
  anchorDigest: (envelope) => F.anchorDigest(T.signedEnvelope(envelope, F.parse(envelope).type, 'the envelope')).toString('hex'),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
};
