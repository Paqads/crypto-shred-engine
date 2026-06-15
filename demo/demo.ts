/**
 * A narrated walkthrough of the crypto-shredding engine. Run it with:
 *
 *     node demo/demo.ts
 *
 * It stands up a throwaway store, encrypts a sensitive record, crypto-shreds it,
 * proves the erasure with a signed certificate, shows a regulator could verify
 * that certificate offline, demonstrates that tampering with the ledger is
 * caught, and finishes with a record that expires itself on a retention timer.
 */

import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CryptoShredEngine, ShreddedError } from '../src/engine.ts';
import type { LedgerEntry } from '../src/types.ts';

const C = {
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  cyan: (s: string) => `\x1b[36m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
};

function h(title: string): void {
  console.log('\n' + C.bold(C.cyan('▌ ' + title)));
}
function line(): void {
  console.log(C.dim('  ' + '─'.repeat(64)));
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const dir = mkdtempSync(join(tmpdir(), 'cryptoshred-demo-'));

try {
  console.log(C.bold('\n  Crypto-Shredding + Proof-of-Deletion Engine — live demo'));
  console.log(C.dim(`  store: ${dir}`));

  // ── 1. Initialize ────────────────────────────────────────────────────────
  h('1. Initialize the store');
  const engine = CryptoShredEngine.init(dir, { issuer: 'Acme Health Records' });
  console.log(`  Generated a 256-bit KEK and an Ed25519 ledger signing key.`);
  console.log(`  Anyone can verify our certificates with this public key:`);
  console.log(C.dim('  ' + engine.signingPublicPem.trim().split('\n').join('\n  ')));

  // ── 2. Store a sensitive record ──────────────────────────────────────────
  h('2. Encrypt a patient record under its own unique key');
  const patient = JSON.stringify({
    mrn: 'PT-0001',
    name: 'Dana Okafor',
    dob: '1984-02-19',
    note: 'Diagnosis: Type 2 diabetes. Started on metformin 500mg.',
  });
  const record = engine.put(patient, { id: 'PT-0001' });
  console.log(`  Record id:       ${C.bold(record.id)}`);
  console.log(`  Its private DEK: ${record.dekId}`);
  line();
  console.log('  What actually lands on disk (records/PT-0001.json) — ciphertext only:');
  const onDisk = JSON.parse(readFileSync(join(dir, 'records', 'PT-0001.json'), 'utf8'));
  console.log(C.dim('    iv:         ' + onDisk.sealed.iv));
  console.log(C.dim('    ciphertext: ' + onDisk.sealed.ciphertext));
  console.log(C.dim('    tag:        ' + onDisk.sealed.tag));
  console.log('  No plaintext, no name, no diagnosis. ' + C.green('✓'));

  // ── 3. Read it back ──────────────────────────────────────────────────────
  h('3. Authorized read (the key still exists)');
  console.log('  ' + C.green(engine.get('PT-0001').toString('utf8')));

  // ── 4. Crypto-shred ──────────────────────────────────────────────────────
  h('4. Honour a "right to be forgotten" request — destroy the key');
  const keyPath = join(dir, 'keys', `${record.dekId}.json`);
  console.log(`  Wrapped DEK on disk before: ${existsSync(keyPath) ? C.green('present') : C.red('absent')}`);
  const shredEntry = engine.shred('PT-0001', 'GDPR Art. 17 erasure request #4471');
  console.log(`  Wrapped DEK on disk after:  ${existsSync(keyPath) ? C.green('present') : C.red('absent (destroyed)')}`);
  console.log(`  Signed SHRED event #${shredEntry.seq} appended to the ledger at ${shredEntry.timestamp}.`);

  // ── 5. Prove the data is now unrecoverable ───────────────────────────────
  h('5. The ciphertext is still there — but it is now permanently locked');
  console.log('  records/PT-0001.json still holds the same ciphertext bytes.');
  console.log('  Attempting an authorized read now:');
  try {
    engine.get('PT-0001');
    console.log('  ' + C.red('decrypted?! (this should never happen)'));
  } catch (e) {
    if (e instanceof ShreddedError) console.log('  ' + C.green('✓ ' + e.message));
    else throw e;
  }

  // ── 6. Issue a Certificate of Erasure ────────────────────────────────────
  h('6. Issue a signed Certificate of Erasure');
  const cert = engine.proveDeletion('PT-0001');
  console.log(`  algorithm:        ${cert.algorithm}`);
  console.log(`  key fingerprint:  ${cert.keyFingerprint}`);
  console.log(`  created / erased: ${cert.createdAt}  →  ${cert.destroyedAt}`);
  console.log('  attestations:');
  console.log(`    key absent from store:    ${cert.attestations.keyAbsentFromStore ? C.green('yes') : C.red('no')}`);
  console.log(`    ciphertext undecryptable: ${cert.attestations.ciphertextUndecryptable ? C.green('yes') : C.red('no')}`);
  console.log(`    ledger chain valid:       ${cert.attestations.ledgerChainValid ? C.green('yes') : C.red('no')}`);

  // ── 7. A regulator verifies it offline ───────────────────────────────────
  h('7. A regulator verifies the certificate — offline, public key only');
  const verdict = CryptoShredEngine.verifyCertificate(cert);
  for (const [name, ok] of Object.entries(verdict.checks)) {
    console.log(`  ${ok ? C.green('✓') : C.red('✗')} ${name}`);
  }
  console.log('  Verdict: ' + (verdict.valid ? C.green(C.bold('VALID — erasure proven ✓')) : C.red('INVALID')));

  // ── 8. Tamper-evidence ───────────────────────────────────────────────────
  h('8. Could someone quietly rewrite history? The ledger says no.');
  const ledgerFile = join(dir, 'ledger.jsonl');
  const entries = readFileSync(ledgerFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as LedgerEntry);
  console.log('  Forging a back-dated SHRED time on the erasure event...');
  entries[shredEntry.seq].timestamp = '2009-01-03T18:15:05.000Z';
  writeFileSync(ledgerFile, entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
  const tampered = engine.verifyLedger();
  console.log(
    `  Ledger verification: ${tampered.valid ? C.red('passed (bad!)') : C.green(`✓ rejected — "${tampered.reason}" at seq ${tampered.brokenAt}`)}`,
  );

  // ── 9. Data that expires itself ──────────────────────────────────────────
  h('9. Retention rules: data that crypto-expires on schedule');
  engine.registerPolicy({ name: 'lab-results-1s', retentionMs: 1000, description: 'demo: 1-second retention' });
  engine.put('Transient lab result: glucose 142 mg/dL', { id: 'LAB-9', policy: 'lab-results-1s' });
  console.log('  Stored LAB-9 under a 1-second retention policy.');
  console.log('  Readable now: ' + C.green(`"${engine.get('LAB-9').toString('utf8')}"`));
  console.log('  Waiting for the retention window to elapse, then sweeping...');
  await sleep(1100);
  const swept = engine.sweepRetention();
  console.log(`  Sweep auto-shredded: ${C.yellow(swept.expired.join(', ') || '(none)')}`);
  try {
    engine.get('LAB-9');
    console.log('  ' + C.red('still readable?!'));
  } catch (e) {
    if (e instanceof ShreddedError) console.log('  ' + C.green('✓ LAB-9 expired itself — key gone, data unrecoverable'));
    else throw e;
  }

  line();
  console.log(C.bold('\n  Recap: ') + 'unique key per record → destroy the key to delete → prove it with');
  console.log('  a signed, tamper-evident, offline-verifiable certificate. ' + C.green('That is crypto-shredding.\n'));
} finally {
  rmSync(dir, { recursive: true, force: true });
}
