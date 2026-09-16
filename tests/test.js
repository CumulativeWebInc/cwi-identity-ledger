'use strict';
/* CWI Identity Ledger — real tests, zero dependencies. Run: node --test tests/test.js */
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const IL = require('../identity.js');
const nacl = require('../vendor/nacl.js');

const ROOT = path.join(__dirname, '..');
const readJSON = p => JSON.parse(fs.readFileSync(p, 'utf8'));

function freshCard(over = {}) {
  const kp = IL.generateKeypair();
  const card = IL.assembleCard(Object.assign({
    name: 'Test Agent', controller: 'Test Controller',
    venues: [{ venue: 'test-venue', handle: 'test_handle' }],
    claims: ['test claim'],
    issued_at: '2026-09-16T12:00:00.000Z', expires_at: '2027-09-16T12:00:00.000Z',
  }, over), kp);
  return { card, kp };
}
const NOW = Date.parse('2026-09-16T13:00:00.000Z');

/* ---------- canonicalization ---------- */
test('canonical: key order does not affect output', () => {
  const a = { z: 1, a: { d: 4, c: 3 }, m: [3, 2] };
  const b = { m: [3, 2], a: { c: 3, d: 4 }, z: 1 };
  assert.equal(IL.canonical(a), IL.canonical(b));
});
test('canonical: nested objects sorted recursively', () => {
  assert.equal(IL.canonical({ b: { z: 1, a: 2 }, a: 0 }), '{"a":0,"b":{"a":2,"z":1}}');
});
test('canonical: unicode passes through deterministically', () => {
  const s = IL.canonical({ e: 'héllo 🎺 日本語' });
  assert.equal(s, '{"e":"héllo 🎺 日本語"}');
  assert.equal(s, IL.canonical(JSON.parse(s)));
});
test('canonical: no whitespace anywhere', () => {
  const s = IL.canonical({ a: [1, 2], b: { c: 'x' } });
  assert.ok(!/\s/.test(s), 'whitespace found: ' + s);
});
test('canonical: survives JSON serialize/parse roundtrip', () => {
  const card = freshCard().card;
  assert.equal(IL.canonical(JSON.parse(JSON.stringify(card))), IL.canonical(card));
});

/* ---------- keygen / sign / verify ---------- */
test('keygen: 32-byte public key and 32-byte seed, base64', () => {
  const kp = IL.generateKeypair();
  assert.equal(IL.b64decode(kp.publicKeyB64).length, 32);
  assert.equal(IL.b64decode(kp.privateKeyB64).length, 32);
  const kp2 = IL.generateKeypair();
  assert.notEqual(kp.publicKeyB64, kp2.publicKeyB64);
});
test('sign/verify roundtrip (node provider)', () => {
  const kp = IL.generateKeypair();
  const msg = IL.utf8Encode('hello ledger');
  const sig = IL.signBytes(msg, kp.privateKeyB64);
  assert.equal(sig.length, 64);
  assert.ok(IL.verifyBytes(msg, sig, IL.b64decode(kp.publicKeyB64)));
});
test('cross-env: vendored nacl verifies node-signed bytes', () => {
  const kp = IL.generateKeypair();
  const msg = IL.utf8Encode('cross env check');
  const sig = IL.signBytes(msg, kp.privateKeyB64); // node signs
  assert.ok(nacl.sign.detached.verify(msg, sig, IL.b64decode(kp.publicKeyB64)));
});
test('cross-env: node verifies nacl-signed bytes', () => {
  const kp = IL.generateKeypair();
  const msg = IL.utf8Encode('cross env check 2');
  const pair = nacl.sign.keyPair.fromSeed(IL.b64decode(kp.privateKeyB64));
  const sig = nacl.sign.detached(msg, pair.secretKey);
  assert.ok(IL.verifyBytes(msg, sig, IL.b64decode(kp.publicKeyB64)));
});

/* ---------- verification statuses ---------- */
test('verify: freshly minted card is VALID', () => {
  const { card } = freshCard();
  const r = IL.verifyCard(card, { now: NOW });
  assert.equal(r.status, 'VALID');
  assert.deepEqual(r.reasons, []);
});
test('verify: wrong key -> TAMPERED', () => {
  const { card } = freshCard();
  const other = IL.generateKeypair();
  card.public_key = other.publicKeyB64; // attacker swaps the key
  const r = IL.verifyCard(card, { now: NOW });
  assert.equal(r.status, 'TAMPERED');
});
test('verify: tampered payload (name) -> TAMPERED', () => {
  const { card } = freshCard();
  card.name = 'Evil Agent';
  const r = IL.verifyCard(card, { now: NOW });
  assert.equal(r.status, 'TAMPERED');
});
test('verify: tampered signature bytes -> TAMPERED', () => {
  const { card } = freshCard();
  const sig = IL.b64decode(card.signature); sig[0] ^= 1;
  card.signature = IL.b64encode(sig);
  const r = IL.verifyCard(card, { now: NOW });
  assert.equal(r.status, 'TAMPERED');
});
test('verify: malformed signature -> INVALID_SIGNATURE, garbage -> MALFORMED', () => {
  const { card } = freshCard();
  card.signature = 'not-base64!!';
  assert.equal(IL.verifyCard(card, { now: NOW }).status, 'MALFORMED'); // fails schema format
  const { card: c2 } = freshCard();
  c2.signature = IL.b64encode(new Uint8Array(10)); // well-formed base64, wrong length
  assert.equal(IL.verifyCard(c2, { now: NOW }).status, 'INVALID_SIGNATURE');
});
test('verify: expired card -> EXPIRED', () => {
  const { card } = freshCard({ expires_at: '2026-09-16T12:30:00.000Z' });
  const r = IL.verifyCard(card, { now: NOW });
  assert.equal(r.status, 'EXPIRED');
});
test('verify: not-yet-valid card -> NOT_YET_VALID', () => {
  const { card } = freshCard({ issued_at: '2026-09-17T12:00:00.000Z', expires_at: '2027-09-17T12:00:00.000Z' });
  const r = IL.verifyCard(card, { now: NOW });
  assert.equal(r.status, 'NOT_YET_VALID');
});
test('verify: revoked card -> REVOKED', () => {
  const { card } = freshCard();
  const list = IL.emptyRevocationList();
  IL.appendRevocation(list, card.id, '2026-09-16T14:00:00.000Z', 'key rotation test');
  const r = IL.verifyCard(card, { now: NOW, revocations: list });
  assert.equal(r.status, 'REVOKED');
});
test('verify: unknown card id is not revoked against genesis list', () => {
  const list = IL.emptyRevocationList();
  const r = IL.checkRevocations('idc_00000000000000000000000000', list);
  assert.equal(r.chainValid, true);
  assert.equal(r.revoked, false);
});

/* ---------- schema validation ---------- */
test('schema: missing field rejected', () => {
  const { card } = freshCard(); delete card.claims;
  assert.equal(IL.validateCard(card).ok, false);
});
test('schema: extra field rejected', () => {
  const { card } = freshCard(); card.evil = true;
  const v = IL.validateCard(card);
  assert.equal(v.ok, false);
  assert.ok(v.reasons.some(r => r.includes('extra field')));
});
test('schema: bad-typed fields rejected', () => {
  const { card } = freshCard();
  card.venues = 'moltbook'; card.claims = 'not an array'; card.name = 42;
  assert.equal(IL.validateCard(card).ok, false);
});
test('schema: bad id format rejected', () => {
  const { card } = freshCard(); card.id = 'fake-id';
  assert.equal(IL.validateCard(card).ok, false);
});
test('schema: issued_at after expires_at rejected', () => {
  const { card } = freshCard();
  card.issued_at = '2027-09-16T12:00:00.000Z'; card.expires_at = '2026-09-16T12:00:00.000Z';
  assert.equal(IL.validateCard(card).ok, false);
});

/* ---------- revocation chain ---------- */
test('revocation: entry hash recomputes and chain links', () => {
  const list = IL.emptyRevocationList();
  const e = IL.appendRevocation(list, 'idc_AAAAAAAAAAAAAAAAAAAAAAAAAA', '2026-09-16T14:00:00.000Z', 'test');
  assert.equal(e.hash, IL.hashRevocationEntry(e));
  assert.equal(e.prev_hash, list.genesis);
  const c = IL.checkRevocations('idc_AAAAAAAAAAAAAAAAAAAAAAAAAA', list);
  assert.equal(c.chainValid, true); assert.equal(c.revoked, true);
});
test('revocation: tampered entry hash -> chain invalid', () => {
  const list = IL.emptyRevocationList();
  IL.appendRevocation(list, 'idc_AAAAAAAAAAAAAAAAAAAAAAAAAA', '2026-09-16T14:00:00.000Z', 'test');
  list.entries[0].reason = 'changed';
  const c = IL.checkRevocations('idc_AAAAAAAAAAAAAAAAAAAAAAAAAA', list);
  assert.equal(c.chainValid, false);
});
test('revocation: broken prev_hash link -> chain invalid', () => {
  const list = IL.emptyRevocationList();
  IL.appendRevocation(list, 'idc_AAAAAAAAAAAAAAAAAAAAAAAAAA', '2026-09-16T14:00:00.000Z', 'a');
  IL.appendRevocation(list, 'idc_BBBBBBBBBBBBBBBBBBBBBBBBBB', '2026-09-16T15:00:00.000Z', 'b');
  list.entries[1].prev_hash = 'deadbeef';
  list.entries[1].hash = IL.hashRevocationEntry(list.entries[1]);
  assert.equal(IL.checkRevocations('x', list).chainValid, false);
});

/* ---------- deep links ---------- */
test('parseCardParam: full URL with ?card=', () => {
  const id = 'idc_01M2NB3XBWXW4H8TS640MBMF43';
  assert.equal(IL.parseCardParam('https://cumulativewebinc.github.io/cwi-identity-ledger/?card=' + id), id);
});
test('parseCardParam: rejects missing / malformed ids', () => {
  assert.equal(IL.parseCardParam('https://example.com/?card=nope'), null);
  assert.equal(IL.parseCardParam('https://example.com/'), null);
  assert.equal(IL.parseCardParam(null), null);
});
test('parseCardParam: bare query string works', () => {
  const id = 'idc_01M2NB3XBWXW4H8TS640MBMF43';
  assert.equal(IL.parseCardParam('card=' + id), id);
});

/* ---------- venue binding ---------- */
test('venue binding preserved through sign/serialize/verify roundtrip', () => {
  const venues = [{ venue: 'moltbook', handle: 'muse_cwi' }, { venue: 'github', handle: 'org-member' }];
  const { card } = freshCard({ venues });
  const restored = JSON.parse(JSON.stringify(card));
  assert.equal(IL.verifyCard(restored, { now: NOW }).status, 'VALID');
  assert.deepEqual(restored.venues, venues);
});

/* ---------- real dogfood artifacts ---------- */
test('dogfood: cards.json lists exactly 10 cards', () => {
  const idx = readJSON(path.join(ROOT, 'cards.json'));
  assert.equal(idx.schema, IL.SCHEMA_INDEX);
  assert.equal(idx.cards.length, 10);
});
test('dogfood: all 10 card files exist and ids are unique + well-formed', () => {
  const idx = readJSON(path.join(ROOT, 'cards.json'));
  const ids = new Set();
  for (const e of idx.cards) {
    const p = path.join(ROOT, e.url);
    assert.ok(fs.existsSync(p), 'missing ' + e.url);
    ids.add(e.id);
    assert.match(e.id, /^idc_[0-9A-HJKMNP-TV-Z]{26}$/);
  }
  assert.equal(ids.size, 10);
});
test('dogfood: all 10 cards are schema-valid and signatures VERIFY', () => {
  const idx = readJSON(path.join(ROOT, 'cards.json'));
  for (const e of idx.cards) {
    const card = readJSON(path.join(ROOT, e.url));
    assert.equal(card.id, e.id, 'id mismatch in ' + e.url);
    assert.equal(IL.validateCard(card).ok, true, 'schema invalid: ' + e.id);
    const r = IL.verifyCard(card, { now: NOW, revocations: readJSON(path.join(ROOT, 'revocations.json')) });
    assert.equal(r.status, 'VALID', e.id + ' -> ' + r.status + ' ' + r.reasons.join('; '));
  }
});
test('dogfood: controller is Cumulative Web Inc on all cards', () => {
  const idx = readJSON(path.join(ROOT, 'cards.json'));
  for (const e of idx.cards) {
    const card = readJSON(path.join(ROOT, e.url));
    assert.equal(card.controller, 'Cumulative Web Inc');
  }
});
test('dogfood: revocations.json is a valid empty chain', () => {
  const rev = readJSON(path.join(ROOT, 'revocations.json'));
  assert.equal(rev.schema, IL.SCHEMA_REVOCATIONS);
  assert.deepEqual(rev.entries, []);
  assert.equal(rev.genesis, IL.genesisHash());
});
test('dogfood: no private key material in the repo tree', () => {
  const priv = readJSON(path.join(process.env.HOME, 'workspace/cwi-company/identity/private-keys.json'));
  assert.equal(priv.cards.length, 10);
  const seeds = priv.cards.map(c => c.privateKeyB64);
  const walk = dir => fs.readdirSync(dir, { withFileTypes: true }).flatMap(d => {
    const p = path.join(dir, d.name);
    return d.isDirectory() ? walk(p) : [p];
  });
  for (const f of walk(ROOT)) {
    if (!/\.(json|js|html|md)$/.test(f)) continue;
    const content = fs.readFileSync(f, 'utf8');
    for (const s of seeds) assert.ok(!content.includes(s), 'private key leak in ' + f);
  }
});
test('sha256 self-test vector', () => {
  assert.equal(IL.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(IL.sha256Hex(''), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});
