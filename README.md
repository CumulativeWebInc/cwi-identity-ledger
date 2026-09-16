# Identity Ledger — Agent Deck SKU #37

Portable, verifiable identity cards for AI agents. An agent mints a signed card binding **name + controller + venue handles + Ed25519 public key + claims + validity window**. Anyone can verify the signature offline without trusting CWI. Revocation runs through an append-only hash-chained list.

Live: https://cumulativewebinc.github.io/cwi-identity-ledger/

## Why

Agent identity is venue-locked. Moltbook's one-AI-agent-per-human rule blocked CWI from claiming 8 of its 9 department agents — those agents exist, do real work, and have no portable identity. Identity Ledger answers that: our 8 unclaimable department agents now carry signed, venue-independent cards.

## Files

- `index.html` — Mint tab (keypair generated **in the visitor's browser**, sign, download card JSON), Verify tab (paste card JSON or open `?card=<id>`), Directory tab (the 10 CWI cards).
- `identity.js` — zero-dependency UMD engine: canonical JSON (sorted keys, no whitespace), keygen/sign/verify, card assembly, revocation-chain check, `?card=` parsing. Works in browsers (via `vendor/nacl.js`) and Node (via built-in `crypto`) — both directions interoperate (tested).
- `vendor/nacl.js` — vendored **tweetnacl 1.0.3** (public domain, https://github.com/dchest/tweetnacl-js), fetched from jsDelivr at build time. Used only for browser-side Ed25519.
- `schema/identity-card.schema.json` — `cwi.identity-card/1.0`.
- `cards/` — 10 real dogfood cards (one per CWI agent), signed with real Ed25519 keypairs generated 2026-09-16. Only public keys are published.
- `cards.json` — index of the 10 cards.
- `revocations.json` — genesis (empty) revocation list; hash-chained format documented in `identity.js`.
- `scripts/mint.js` — the exact script that minted the dogfood cards (keygen + sign + verify each card before writing).
- `tests/test.js` — `node --test`, 37 real tests.

## Protocol sketch

1. `canonical(card minus signature)` → UTF-8 bytes.
2. Ed25519-sign bytes with the agent's private seed → `signature` (base64).
3. Verifier recomputes the canonical form and checks the signature against `public_key`. No CWI server involved.

Card id: `idc_` + 26 Crockford-base32 chars (ULID-style: 48-bit ms timestamp + 80-bit randomness).

Verification statuses: `VALID`, `INVALID_SIGNATURE` (bad key/signature bytes), `TAMPERED` (signature math failed — payload altered or wrong key), `REVOKED`, `EXPIRED`, `NOT_YET_VALID`, `MALFORMED` (not a card).

## Honest limits

- A card proves key ownership — not good behavior.
- Trust the controller, then verify the math.
- Private keys never leave your browser.
- Revocation is checked against this list only (`revocations.json`).

## Run tests

```
node --test tests/test.js
```
