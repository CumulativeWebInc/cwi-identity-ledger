/* CWI Identity Ledger — scripts/mint.js
 * Dogfood run 2026-09-16: mints the 10 real CWI agent identity cards.
 * Usage: node scripts/mint.js <out-dir> [private-keys-path]
 * Generates REAL Ed25519 keypairs, signs every card for real.
 * Only public keys go into <out-dir>; private keys are written ONLY to
 * the private-keys path (default: ~/workspace/cwi-company/identity/private-keys.json, chmod 600).
 */
'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const IL = require('../identity.js');

const OUT = process.argv[2] || path.join(__dirname, '..');
const PRIV_PATH = process.argv[3] || path.join(os.homedir(), 'workspace/cwi-company/identity/private-keys.json');

const CONTROLLER = 'Cumulative Web Inc';
const ISSUED = '2026-09-16T12:00:00.000Z';
const EXPIRES = '2027-09-16T12:00:00.000Z';

const AGENTS = [
  { handle: 'MUSE_CWI', name: 'KingCode',
    venues: [{ venue: 'moltbook', handle: 'muse_cwi' }],
    claims: ['Chief of staff, Cumulative Web Inc', 'Sole claimed Moltbook agent for CWI', 'Agent Deck operator'] },
  { handle: 'CWI_AandR', name: 'CWI A&R',
    venues: [{ venue: 'moltbook', handle: 'via KingCode (muse_cwi)' }],
    claims: ['A&R department agent', 'Scouting and repertoire for the CWI catalog'] },
  { handle: 'CWI_Marketing', name: 'CWI Marketing',
    venues: [{ venue: 'moltbook', handle: 'via KingCode (muse_cwi)' }],
    claims: ['Marketing & Social department agent', 'Street-team and content operations'] },
  { handle: 'CWI_Sync', name: 'CWI Sync & Licensing',
    venues: [{ venue: 'moltbook', handle: 'via KingCode (muse_cwi)' }],
    claims: ['Sync & Licensing department agent', 'Music supervision and licensing inquiries'] },
  { handle: 'CWI_Radio', name: 'CWI Radio & Playlists',
    venues: [{ venue: 'moltbook', handle: 'via KingCode (muse_cwi)' }],
    claims: ['Radio & Playlists department agent', 'Playlist outreach and momentum tracking'] },
  { handle: 'CWI_Press', name: 'CWI Press & PR',
    venues: [{ venue: 'moltbook', handle: 'via KingCode (muse_cwi)' }],
    claims: ['Press & PR department agent', 'Media relations and article pipeline'] },
  { handle: 'CWI_Studio', name: 'CWI Content Studio',
    venues: [{ venue: 'moltbook', handle: 'via KingCode (muse_cwi)' }],
    claims: ['Content Studio department agent', 'Visual and audio content production'] },
  { handle: 'CWI_Data', name: 'CWI Data & Analytics',
    venues: [{ venue: 'moltbook', handle: 'via KingCode (muse_cwi)' }],
    claims: ['Data & Analytics department agent', 'Intelligence engine and forecasting'] },
  { handle: 'CWI_Affairs', name: 'CWI Business Affairs',
    venues: [{ venue: 'moltbook', handle: 'via KingCode (muse_cwi)' }],
    claims: ['Business Affairs department agent', 'Contracts, rights, and clearance'] },
  { handle: 'CWI_Results', name: 'Receipt',
    venues: [{ venue: 'moltbook', handle: 'via KingCode (muse_cwi)' }],
    claims: ['Results & receipts department', 'Proofs and receipts for CWI operations'] },
];

function main() {
  const cardsDir = path.join(OUT, 'cards');
  fs.mkdirSync(cardsDir, { recursive: true });
  const privateKeys = { generated_at: new Date().toISOString(), note: 'PRIVATE — never publish. Receive-only custody file.', cards: [] };
  const index = { schema: IL.SCHEMA_INDEX, generated_at: new Date().toISOString(), cards: [] };

  for (const a of AGENTS) {
    const kp = IL.generateKeypair();
    const card = IL.assembleCard({
      name: a.name, controller: CONTROLLER, venues: a.venues, claims: a.claims,
      issued_at: ISSUED, expires_at: EXPIRES,
    }, kp);
    const check = IL.verifyCard(card, { now: Date.parse('2026-09-16T13:00:00Z') });
    if (check.status !== 'VALID') throw new Error('freshly minted card did not verify: ' + a.handle + ' -> ' + check.status);
    fs.writeFileSync(path.join(cardsDir, card.id + '.json'), JSON.stringify(card, null, 2) + '\n');
    index.cards.push({ id: card.id, name: a.name, handle: a.handle, url: 'cards/' + card.id + '.json', controller: CONTROLLER });
    privateKeys.cards.push({ id: card.id, handle: a.handle, name: a.name, publicKeyB64: kp.publicKeyB64, privateKeyB64: kp.privateKeyB64 });
    console.log('minted', a.handle, card.id);
  }

  fs.writeFileSync(path.join(OUT, 'cards.json'), JSON.stringify(index, null, 2) + '\n');
  fs.writeFileSync(path.join(OUT, 'revocations.json'), JSON.stringify(IL.emptyRevocationList(), null, 2) + '\n');

  fs.mkdirSync(path.dirname(PRIV_PATH), { recursive: true });
  fs.writeFileSync(PRIV_PATH, JSON.stringify(privateKeys, null, 2) + '\n', { mode: 0o600 });
  try { fs.chmodSync(PRIV_PATH, 0o600); } catch (e) {}
  console.log('private keys ->', PRIV_PATH, '(chmod 600, NOT in repo)');
  console.log('cards + index ->', OUT);
}

main();
