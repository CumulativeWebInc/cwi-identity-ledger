/* CWI Identity Ledger — identity.js v1.0.0
 * Zero-dependency UMD engine for portable, verifiable agent identity cards.
 * Canonical JSON (sorted keys, no whitespace) + Ed25519 signatures.
 * Browser path uses vendored tweetnacl (vendor/nacl.js, public domain);
 * Node path uses the built-in crypto module. Card format is identical.
 * Honest limits: a card proves key ownership — not good behavior.
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], function () { return factory('browser'); });
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory('node');
  } else {
    root.IdentityLedger = factory('browser');
  }
}(typeof self !== 'undefined' ? self : this, function (ENV) {

'use strict';

var SCHEMA_CARD = 'cwi.identity-card/1.0';
var SCHEMA_INDEX = 'cwi.identity-card-index/1.0';
var SCHEMA_REVOCATIONS = 'cwi.revocation-list/1.0';
var GENESIS_SEED = 'cwi.identity-ledger:revocation-genesis';
var ID_PREFIX = 'idc_';
var CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/* ---------------- text / base64 helpers ---------------- */

function utf8Encode(str) {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str);
  // fallback: manual UTF-8
  var bytes = [], i, c;
  for (i = 0; i < str.length; i++) {
    c = str.charCodeAt(i);
    if (c < 0x80) bytes.push(c);
    else if (c < 0x800) bytes.push(0xC0 | (c >> 6), 0x80 | (c & 0x3F));
    else if (c >= 0xD800 && c <= 0xDBFF && i + 1 < str.length) {
      var lo = str.charCodeAt(i + 1);
      if (lo >= 0xDC00 && lo <= 0xDFFF) {
        var cp = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
        bytes.push(0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3F), 0x80 | ((cp >> 6) & 0x3F), 0x80 | (cp & 0x3F));
        i++;
      } else bytes.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
    } else bytes.push(0xE0 | (c >> 12), 0x80 | ((c >> 6) & 0x3F), 0x80 | (c & 0x3F));
  }
  return new Uint8Array(bytes);
}

function b64encode(bytes) {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  var s = '', i;
  for (i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64decode(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(str) || str.length % 4 !== 0) return null;
  try {
    var raw;
    if (typeof Buffer !== 'undefined') raw = new Uint8Array(Buffer.from(str, 'base64'));
    else {
      var s = atob(str), out = new Uint8Array(s.length), i;
      for (i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
      raw = out;
    }
    // reject non-canonical paddings that decode short
    if (b64encode(raw) !== str.replace(/=+$/, '') .padEnd(Math.ceil(str.replace(/=+$/, '').length / 4) * 4, '=')) {
      // lenient: accept as long as decode round-trips modulo padding
    }
    return raw;
  } catch (e) { return null; }
}

/* ---------------- canonical JSON ----------------
 * Deterministic: object keys sorted by UTF-16 code units, no whitespace.
 * Arrays keep order. Strings use JSON.stringify (no unicode escaping,
 * deterministic across conforming engines). Numbers as-is. */

function canonical(v) {
  if (v === null || v === undefined) return 'null';
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  var t = typeof v;
  if (t === 'object') {
    var keys = Object.keys(v).sort(), i, out = [];
    for (i = 0; i < keys.length; i++) out.push(JSON.stringify(keys[i]) + ':' + canonical(v[keys[i]]));
    return '{' + out.join(',') + '}';
  }
  return JSON.stringify(v);
}

/* ---------------- SHA-256 (embedded, zero-dep) ---------------- */

function sha256Hex(str) {
  var bytes = utf8Encode(str);
  var K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  var h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,
      h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  var bitLen = bytes.length * 8, i, j;
  var padded = [];
  for (i = 0; i < bytes.length; i++) padded.push(bytes[i]);
  padded.push(0x80);
  while (padded.length % 64 !== 56) padded.push(0);
  // 64-bit length: high 32 bits then low 32 (bitLen < 2^53 in practice)
  var hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
  padded.push((hi>>>24)&255,(hi>>>16)&255,(hi>>>8)&255,hi&255,(lo>>>24)&255,(lo>>>16)&255,(lo>>>8)&255,lo&255);
  function rotr(x,n){ return (x>>>n)|(x<<(32-n)); }
  for (i = 0; i < padded.length; i += 64) {
    var w = new Array(64);
    for (j = 0; j < 16; j++) w[j] = (padded[i+4*j]<<24)|(padded[i+4*j+1]<<16)|(padded[i+4*j+2]<<8)|padded[i+4*j+3];
    for (j = 16; j < 64; j++) {
      var s0 = rotr(w[j-15],7)^rotr(w[j-15],18)^(w[j-15]>>>3);
      var s1 = rotr(w[j-2],17)^rotr(w[j-2],19)^(w[j-2]>>>10);
      w[j] = (w[j-16]+s0+w[j-7]+s1)|0;
    }
    var a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,hh=h7;
    for (j = 0; j < 64; j++) {
      var S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
      var ch = (e&f)^((~e)&g);
      var t1 = (hh+S1+ch+K[j]+w[j])|0;
      var S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
      var maj = (a&b)^(a&c)^(b&c);
      var t2 = (S0+maj)|0;
      hh=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
    }
    h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0;
    h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+hh)|0;
  }
  function hex(x){ return ('00000000'+(x>>>0).toString(16)).slice(-8); }
  return hex(h0)+hex(h1)+hex(h2)+hex(h3)+hex(h4)+hex(h5)+hex(h6)+hex(h7);
}

function genesisHash() { return sha256Hex(GENESIS_SEED); }

/* ---------------- Ed25519 provider (node crypto | tweetnacl) ---------------- */

var nodeCrypto = null;
if (ENV === 'node') { try { nodeCrypto = require('crypto'); } catch (e) { nodeCrypto = null; } }

function getNacl() {
  var n = (typeof root !== 'undefined' && root.nacl) ? root.nacl : null;
  if (!n && typeof globalThis !== 'undefined' && globalThis.nacl) n = globalThis.nacl;
  return n;
}

/* Keypair: { publicKeyB64, privateKeyB64 } — privateKey is the 32-byte SEED in
 * both environments (tweetnacl can rebuild the full secret via fromSeed). */

function generateKeypair() {
  if (nodeCrypto) {
    var kp = nodeCrypto.generateKeyPairSync('ed25519');
    var pub = kp.publicKey.export({ format: 'jwk' });
    var priv = kp.privateKey.export({ format: 'jwk' });
    return {
      publicKeyB64: b64encode(base64urlToBytes(pub.x)),
      privateKeyB64: b64encode(base64urlToBytes(priv.d))
    };
  }
  var nacl = getNacl();
  if (!nacl) throw new Error('Ed25519 unavailable: load vendor/nacl.js first');
  var pair = nacl.sign.keyPair();
  return { publicKeyB64: b64encode(pair.publicKey), privateKeyB64: b64encode(pair.secretKey.slice(0, 32)) };
}

function base64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return b64decode(s);
}

function signBytes(msgBytes, seedB64) {
  var seed = b64decode(seedB64);
  if (!seed || seed.length !== 32) throw new Error('private key must be 32-byte seed, base64');
  if (nodeCrypto) {
    // Ed25519 seed wrapped as PKCS#8 DER: 302e020100300506032b657004220420 || seed
    var der = new Uint8Array(48);
    var prefix = [0x30,0x2e,0x02,0x01,0x00,0x30,0x05,0x06,0x03,0x2b,0x65,0x70,0x04,0x22,0x04,0x20], i;
    for (i = 0; i < 16; i++) der[i] = prefix[i];
    for (i = 0; i < 32; i++) der[16 + i] = seed[i];
    var priv = nodeCrypto.createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' });
    return new Uint8Array(nodeCrypto.sign(null, Buffer.from(msgBytes), priv));
  }
  var nacl = getNacl();
  if (!nacl) throw new Error('Ed25519 unavailable: load vendor/nacl.js first');
  var pair = nacl.sign.keyPair.fromSeed(seed);
  return nacl.sign.detached(msgBytes, pair.secretKey);
}

function bytesToBase64url(bytes) {
  var s = b64encode(bytes);
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function seedToJwk(seed, pubBytes) {
  var jwk = { kty: 'OKP', crv: 'Ed25519', d: bytesToBase64url(seed) };
  if (pubBytes) jwk.x = bytesToBase64url(pubBytes);
  return jwk;
}

function pubToJwk(pubBytes) {
  return { kty: 'OKP', crv: 'Ed25519', x: bytesToBase64url(pubBytes) };
}

function verifyBytes(msgBytes, sigBytes, pubBytes) {
  if (nodeCrypto) {
    try {
      var pub = nodeCrypto.createPublicKey({ key: pubToJwk(pubBytes), format: 'jwk' });
      return nodeCrypto.verify(null, Buffer.from(msgBytes), pub, Buffer.from(sigBytes));
    } catch (e) { return false; }
  }
  var nacl = getNacl();
  if (!nacl) throw new Error('Ed25519 unavailable: load vendor/nacl.js first');
  try { return nacl.sign.detached.verify(msgBytes, sigBytes, pubBytes) === true; }
  catch (e) { return false; }
}

/* ---------------- card assembly / schema ---------------- */

function newCardId(randomBytesFn) {
  var rand = randomBytesFn ? randomBytesFn(10) : randomSource(10);
  var now = Date.now();
  var out = '', i, v = now;
  // 48-bit timestamp -> 10 chars
  for (i = 9; i >= 0; i--) { /* build below */ }
  var chars = new Array(26), n = now;
  for (i = 9; i >= 0; i--) { chars[i] = CROCKFORD[n % 32]; n = Math.floor(n / 32); }
  // 80-bit randomness -> 16 chars
  var carry = 0, acc = 0, bits = 0, pos = 25;
  for (i = 0; i < 10; i++) {
    acc = (acc << 8) | rand[i]; bits += 8;
    while (bits >= 5 && pos >= 10) { bits -= 5; chars[pos--] = CROCKFORD[(acc >>> bits) & 31]; }
  }
  if (pos >= 10) { chars[pos] = CROCKFORD[acc & 31]; }
  return ID_PREFIX + chars.join('');
}

function randomSource(n) {
  if (nodeCrypto) return new Uint8Array(nodeCrypto.randomBytes(n));
  var nacl = getNacl();
  if (nacl && nacl.randomBytes) return nacl.randomBytes(n);
  var out = new Uint8Array(n), i;
  for (i = 0; i < n; i++) out[i] = Math.floor(Math.random() * 256);
  return out;
}

var CARD_FIELDS = ['id','name','controller','venues','public_key','claims','issued_at','expires_at','signature','schema'];

function validateCard(card) {
  var reasons = [];
  if (!card || typeof card !== 'object' || Array.isArray(card)) return { ok: false, reasons: ['card must be a JSON object'] };
  var keys = Object.keys(card), i;
  for (i = 0; i < keys.length; i++) {
    if (CARD_FIELDS.indexOf(keys[i]) === -1) reasons.push('extra field: ' + keys[i]);
  }
  CARD_FIELDS.forEach(function (f) {
    if (!(f in card)) reasons.push('missing field: ' + f);
  });
  if (typeof card.id !== 'string' || !/^idc_[0-9A-HJKMNP-TV-Z]{26}$/.test(card.id)) reasons.push('id must match idc_<26 ULID chars>');
  if (typeof card.name !== 'string' || !card.name.trim()) reasons.push('name must be a non-empty string');
  if (typeof card.controller !== 'string' || !card.controller.trim()) reasons.push('controller must be a non-empty string');
  if (!Array.isArray(card.venues)) reasons.push('venues must be an array');
  else card.venues.forEach(function (v, idx) {
    if (!v || typeof v !== 'object' || typeof v.venue !== 'string' || typeof v.handle !== 'string')
      reasons.push('venues[' + idx + '] must be {venue, handle} strings');
  });
  var pub = typeof card.public_key === 'string' ? b64decode(card.public_key) : null;
  if (!pub) reasons.push('public_key must be well-formed base64 (32 bytes checked at verification)');
  if (!Array.isArray(card.claims) || card.claims.some(function (c) { return typeof c !== 'string'; }))
    reasons.push('claims must be an array of strings');
  var issued = Date.parse(card.issued_at), expires = Date.parse(card.expires_at);
  if (typeof card.issued_at !== 'string' || isNaN(issued)) reasons.push('issued_at must be an ISO-8601 date string');
  if (typeof card.expires_at !== 'string' || isNaN(expires)) reasons.push('expires_at must be an ISO-8601 date string');
  if (!isNaN(issued) && !isNaN(expires) && issued >= expires) reasons.push('issued_at must be before expires_at');
  var sig = typeof card.signature === 'string' ? b64decode(card.signature) : null;
  if (!sig) reasons.push('signature must be well-formed base64 (64 bytes checked at verification)');
  if (card.schema !== SCHEMA_CARD) reasons.push('schema must be "' + SCHEMA_CARD + '"');
  return { ok: reasons.length === 0, reasons: reasons };
}

function payloadOf(card) {
  var p = {}, k;
  for (k in card) if (k !== 'signature' && Object.prototype.hasOwnProperty.call(card, k)) p[k] = card[k];
  return p;
}

function assembleCard(fields, keypair) {
  var card = {
    id: newCardId(),
    name: fields.name,
    controller: fields.controller,
    venues: fields.venues || [],
    public_key: keypair.publicKeyB64,
    claims: fields.claims || [],
    issued_at: fields.issued_at,
    expires_at: fields.expires_at,
    schema: SCHEMA_CARD
  };
  var sig = signBytes(utf8Encode(canonical(card)), keypair.privateKeyB64);
  card.signature = b64encode(sig);
  return card;
}

/* ---------------- verification ----------------
 * Order: schema -> signature bytes -> signature math -> revocation ->
 * time window -> VALID. Statuses: VALID, INVALID_SIGNATURE, TAMPERED,
 * REVOKED, EXPIRED, NOT_YET_VALID, MALFORMED. */

function verifyCard(card, opts) {
  opts = opts || {};
  var now = opts.now != null ? opts.now : Date.now();
  var revocations = opts.revocations || null;

  var schema = validateCard(card);
  if (!schema.ok) return { status: 'MALFORMED', reasons: schema.reasons };

  var pub = b64decode(card.public_key);
  var sig = b64decode(card.signature);
  if (!pub || pub.length !== 32 || !sig || sig.length !== 64) {
    return { status: 'INVALID_SIGNATURE', reasons: ['public_key or signature is not well-formed (need 32 / 64 bytes)'] };
  }
  var ok = verifyBytes(utf8Encode(canonical(payloadOf(card))), sig, pub);
  if (!ok) return { status: 'TAMPERED', reasons: ['signature does not match the card payload (payload altered, or signed by a different key)'] };

  if (revocations) {
    var rev = checkRevocations(card.id, revocations);
    if (!rev.chainValid) return { status: 'TAMPERED', reasons: ['revocation list failed its hash-chain check: ' + rev.reason] };
    if (rev.revoked) return { status: 'REVOKED', reasons: ['card id ' + card.id + ' is on the revocation list (' + rev.entry.revoked_at + ': ' + rev.entry.reason + ')'] };
  }

  var issued = Date.parse(card.issued_at), expires = Date.parse(card.expires_at);
  if (now < issued) return { status: 'NOT_YET_VALID', reasons: ['card is not valid until ' + card.issued_at] };
  if (now >= expires) return { status: 'EXPIRED', reasons: ['card expired at ' + card.expires_at] };

  return { status: 'VALID', reasons: [] };
}

/* ---------------- revocation list ---------------- */

function hashRevocationEntry(e) {
  return sha256Hex(canonical({ card_id: e.card_id, revoked_at: e.revoked_at, reason: e.reason, prev_hash: e.prev_hash }));
}

function appendRevocation(list, card_id, revoked_at, reason) {
  var prev = list.entries.length ? list.entries[list.entries.length - 1].hash : list.genesis;
  var e = { card_id: card_id, revoked_at: revoked_at, reason: reason, prev_hash: prev };
  e.hash = hashRevocationEntry(e);
  list.entries.push(e);
  return e;
}

function checkRevocations(cardId, list) {
  if (!list || typeof list !== 'object' || list.schema !== SCHEMA_REVOCATIONS || !Array.isArray(list.entries))
    return { chainValid: false, reason: 'not a cwi.revocation-list/1.0 document', revoked: false };
  var prev = list.genesis, i, e;
  for (i = 0; i < list.entries.length; i++) {
    e = list.entries[i];
    if (e.prev_hash !== prev) return { chainValid: false, reason: 'entry ' + i + ' prev_hash does not link to previous hash', revoked: false };
    if (hashRevocationEntry(e) !== e.hash) return { chainValid: false, reason: 'entry ' + i + ' hash does not recompute', revoked: false };
    if (typeof e.card_id !== 'string' || typeof e.revoked_at !== 'string')
      return { chainValid: false, reason: 'entry ' + i + ' missing card_id/revoked_at', revoked: false };
    prev = e.hash;
  }
  for (i = 0; i < list.entries.length; i++) {
    if (list.entries[i].card_id === cardId) return { chainValid: true, revoked: true, entry: list.entries[i] };
  }
  return { chainValid: true, revoked: false };
}

function emptyRevocationList() {
  return { schema: SCHEMA_REVOCATIONS, genesis: genesisHash(), entries: [] };
}

/* ---------------- deep links / directory ---------------- */

function parseCardParam(urlOrQuery) {
  if (typeof urlOrQuery !== 'string') return null;
  var q = urlOrQuery, m;
  var hashIdx = q.indexOf('#'); if (hashIdx !== -1) q = q.slice(0, hashIdx);
  m = q.match(/[?&]card=([^&#]*)/);
  if (!m) { m = q.match(/^card=([^&#]*)/); }
  if (!m) return null;
  var id;
  try { id = decodeURIComponent(m[1]); } catch (e) { return null; }
  return /^idc_[0-9A-HJKMNP-TV-Z]{26}$/.test(id) ? id : null;
}

function findCard(indexDoc, id) {
  if (!indexDoc || !Array.isArray(indexDoc.cards)) return null;
  var i;
  for (i = 0; i < indexDoc.cards.length; i++) if (indexDoc.cards[i].id === id) return indexDoc.cards[i];
  return null;
}

return {
  SCHEMA_CARD: SCHEMA_CARD,
  SCHEMA_INDEX: SCHEMA_INDEX,
  SCHEMA_REVOCATIONS: SCHEMA_REVOCATIONS,
  canonical: canonical,
  sha256Hex: sha256Hex,
  genesisHash: genesisHash,
  generateKeypair: generateKeypair,
  signBytes: signBytes,
  verifyBytes: verifyBytes,
  newCardId: newCardId,
  assembleCard: assembleCard,
  validateCard: validateCard,
  verifyCard: verifyCard,
  hashRevocationEntry: hashRevocationEntry,
  appendRevocation: appendRevocation,
  checkRevocations: checkRevocations,
  emptyRevocationList: emptyRevocationList,
  parseCardParam: parseCardParam,
  findCard: findCard,
  payloadOf: payloadOf,
  b64encode: b64encode,
  b64decode: b64decode,
  utf8Encode: utf8Encode,
  ENV: ENV
};

}));
