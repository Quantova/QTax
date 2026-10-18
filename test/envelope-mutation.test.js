'use strict';

const test = require('node:test');
const assert = require('node:assert');
const F = require('../lib/format');
const { campaign, mutator, canon } = require('./fuzz');
const { honest } = require('./honest');
const { failing } = require('./chain');

const CODE = 'QTAX_';
const valid = (r) => r.status === 'valid' || r.valid === true;
const article = (word) => (/^[aeiou]/.test(word) ? 'an ' : 'a ') + word;

function stringsOf(v, out) {
  if (typeof v === 'string' && v.length < 200) out.push(v);
  else if (v && typeof v === 'object') for (const k of Object.keys(v)) stringsOf(v[k], out);
  return out;
}

let world;
async function setup() {
  if (!world) world = await honest();
  return world;
}

F.TYPES.forEach((type, n) => {
  test('a changed ' + type + ' envelope never verifies valid, every refusal carries the ' + CODE + ' code and each check ends within the time bound', async (t) => {
    const w = await setup();
    const base = w.all[type];
    const opts = w.options[type];
    const honestResult = await w.q.verify(base, opts);
    assert.strictEqual(honestResult.status, 'valid', failing(honestResult).join('\n'));
    const stats = await campaign({
      name: type,
      seed: 0x7a40 + n,
      base,
      pool: stringsOf([w.all, w.first], []),
      code: CODE,
      check: (m) => w.q.verify(m, opts),
      valid,
    });
    t.diagnostic(JSON.stringify(stats));
  });

  test('a changed Qstamp receipt never lets ' + article(type) + ' verify valid', async (t) => {
    const w = await setup();
    const base = w.all[type];
    const opts = w.options[type];
    const honestResult = await w.q.verify(base, opts);
    assert.strictEqual(honestResult.status, 'valid', failing(honestResult).join('\n'));
    const stats = await campaign({
      name: type + ' receipt',
      seed: 0x7ac0 + n,
      base: base.anchor,
      pool: stringsOf(Object.values(w.all).concat([w.first]).map((e) => e.anchor), []),
      code: CODE,
      check: (r) => w.q.verify(Object.assign({}, base, { anchor: r }), opts),
      valid,
    });
    t.diagnostic(JSON.stringify(stats));
  });
});

test('the mutation stream is the same for the same seed', () => {
  const a = mutator(11);
  const b = mutator(11);
  const base = { format: 'qtax/1', statement: { total: '121000', tax: '21000' }, signature: 'QUJDREVGR0hJSktMTU5PUA==' };
  for (let i = 0; i < 200; i += 1) assert.strictEqual(canon(a.mutate(base, i).value), canon(b.mutate(base, i).value));
});
