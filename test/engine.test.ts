/**
 * Tests for the crypto-shredding engine. Run with: `node --test` (or `npm test`).
 * Uses Node's built-in test runner — no test framework dependency.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CryptoShredEngine, ShreddedError } from '../src/engine.ts';
import { canonical, seal, open, generateKey } from '../src/crypto.ts';
import type { LedgerEntry } from '../src/types.ts';

function freshStore(): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'cryptoshred-test-'));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('AES-256-GCM round-trips and authenticates', () => {
  const key = generateKey();
  const sealed = seal(key, Buffer.from('top secret'), Buffer.from('rec-1'));
  assert.equal(open(key, sealed).toString('utf8'), 'top secret');

  // Wrong key fails.
  assert.throws(() => open(generateKey(), sealed));
  // Tampered ciphertext fails (GCM integrity).
  const tampered = { ...sealed, ciphertext: Buffer.from('zzzz').toString('base64') };
  assert.throws(() => open(key, tampered));
});

test('put → get round-trips through envelope encryption', () => {
  const { dir, cleanup } = freshStore();
  try {
    const engine = CryptoShredEngine.init(dir);
    const rec = engine.put('hello world', { id: 'r1' });
    assert.equal(engine.get('r1').toString('utf8'), 'hello world');
    // Nothing readable on disk.
    const raw = readFileSync(join(dir, 'records', 'r1.json'), 'utf8');
    assert.ok(!raw.includes('hello world'));
    assert.ok(engine.hasKey(rec.dekId));
  } finally {
    cleanup();
  }
});

test('every record gets a distinct key', () => {
  const { dir, cleanup } = freshStore();
  try {
    const engine = CryptoShredEngine.init(dir);
    const a = engine.put('a', { id: 'a' });
    const b = engine.put('b', { id: 'b' });
    assert.notEqual(a.dekId, b.dekId);
    const fa = engine.ledgerEntries().find((e) => e.recordId === 'a')!.keyFingerprint;
    const fb = engine.ledgerEntries().find((e) => e.recordId === 'b')!.keyFingerprint;
    assert.notEqual(fa, fb);
  } finally {
    cleanup();
  }
});

test('shred destroys the key and makes the record permanently unrecoverable', () => {
  const { dir, cleanup } = freshStore();
  try {
    const engine = CryptoShredEngine.init(dir);
    const rec = engine.put('forget me', { id: 'r1' });
    const keyPath = join(dir, 'keys', `${rec.dekId}.json`);
    assert.ok(existsSync(keyPath));

    engine.shred('r1', 'erasure request');

    assert.ok(!existsSync(keyPath), 'wrapped DEK file must be gone');
    assert.throws(() => engine.get('r1'), ShreddedError);

    // The ciphertext is still on disk — only the key is gone.
    const raw = JSON.parse(readFileSync(join(dir, 'records', 'r1.json'), 'utf8'));
    assert.ok(raw.sealed.ciphertext.length > 0);
    assert.equal(raw.shredded, true);
  } finally {
    cleanup();
  }
});

test('shred is idempotent', () => {
  const { dir, cleanup } = freshStore();
  try {
    const engine = CryptoShredEngine.init(dir);
    engine.put('x', { id: 'r1' });
    const first = engine.shred('r1');
    const second = engine.shred('r1');
    assert.equal(first.seq, second.seq);
    // Only one SHRED event recorded.
    assert.equal(engine.ledgerEntries().filter((e) => e.action === 'SHRED').length, 1);
  } finally {
    cleanup();
  }
});

test('certificate of erasure verifies offline', () => {
  const { dir, cleanup } = freshStore();
  try {
    const engine = CryptoShredEngine.init(dir, { issuer: 'TestCo' });
    engine.put('phi', { id: 'r1' });
    engine.shred('r1', 'gdpr');
    const cert = engine.proveDeletion('r1');

    const result = CryptoShredEngine.verifyCertificate(cert);
    assert.ok(result.valid, JSON.stringify(result.checks));
    assert.equal(cert.issuer, 'TestCo');
    assert.equal(cert.algorithm, 'AES-256-GCM');
  } finally {
    cleanup();
  }
});

test('proveDeletion refuses a record that is not shredded', () => {
  const { dir, cleanup } = freshStore();
  try {
    const engine = CryptoShredEngine.init(dir);
    engine.put('still here', { id: 'r1' });
    assert.throws(() => engine.proveDeletion('r1'), /not shredded/);
  } finally {
    cleanup();
  }
});

test('a tampered certificate fails verification', () => {
  const { dir, cleanup } = freshStore();
  try {
    const engine = CryptoShredEngine.init(dir);
    engine.put('phi', { id: 'r1' });
    engine.shred('r1');
    const cert = engine.proveDeletion('r1');

    // Flip the fingerprint the certificate attests to.
    const forged = { ...cert, keyFingerprint: 'deadbeef'.repeat(8) };
    const result = CryptoShredEngine.verifyCertificate(forged);
    assert.equal(result.valid, false);
    assert.equal(result.checks.certSignatureValid, false);
  } finally {
    cleanup();
  }
});

test('ledger detects tampering with any past entry', () => {
  const { dir, cleanup } = freshStore();
  try {
    const engine = CryptoShredEngine.init(dir);
    engine.put('a', { id: 'a' });
    engine.put('b', { id: 'b' });
    engine.shred('a');
    assert.ok(engine.verifyLedger().valid);

    // Rewrite a past entry's metadata directly in the file.
    const file = join(dir, 'ledger.jsonl');
    const entries = readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l) as LedgerEntry);
    entries[0].recordId = 'tampered';
    writeFileSync(file, entries.map((e) => JSON.stringify(e)).join('\n') + '\n');

    const r = engine.verifyLedger();
    assert.equal(r.valid, false);
    assert.equal(r.brokenAt, 0);
  } finally {
    cleanup();
  }
});

test('retention policy auto-shreds expired records on sweep', () => {
  const { dir, cleanup } = freshStore();
  try {
    const engine = CryptoShredEngine.init(dir);
    engine.registerPolicy({ name: 'short', retentionMs: 50 });
    engine.put('ephemeral', { id: 'r1', policy: 'short' });

    // Not yet due.
    assert.equal(engine.sweepRetention(Date.now()).expired.length, 0);
    // Simulate time passing by sweeping with a future clock.
    const future = Date.now() + 1000;
    const { expired } = engine.sweepRetention(future);
    assert.deepEqual(expired, ['r1']);
    assert.throws(() => engine.get('r1'), ShreddedError);

    // The auto-erasure is recorded as an EXPIRE event and is provable.
    const cert = engine.proveDeletion('r1');
    assert.ok(CryptoShredEngine.verifyCertificate(cert).valid);
  } finally {
    cleanup();
  }
});

test('store persists across open()', () => {
  const { dir, cleanup } = freshStore();
  try {
    CryptoShredEngine.init(dir).put('persist me', { id: 'r1' });
    const reopened = CryptoShredEngine.open(dir);
    assert.equal(reopened.get('r1').toString('utf8'), 'persist me');
  } finally {
    cleanup();
  }
});

test('canonical JSON is deterministic regardless of key order', () => {
  assert.equal(canonical({ b: 1, a: 2 }), canonical({ a: 2, b: 1 }));
  assert.equal(canonical({ a: [1, { y: 2, x: 3 }] }), '{"a":[1,{"x":3,"y":2}]}');
});

test('AAD binds ciphertext — substituting the AAD fails authentication', () => {
  const key = generateKey();
  const sealed = seal(key, Buffer.from('bound data'), Buffer.from('record:r1'));
  // The correct AAD opens it.
  assert.equal(open(key, sealed).toString('utf8'), 'bound data');
  // Re-labelling the ciphertext as a different record breaks GCM authentication,
  // even though the key is identical.
  const moved = { ...sealed, aad: Buffer.from('record:r2').toString('base64') };
  assert.throws(() => open(key, moved));
});
