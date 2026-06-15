/**
 * CryptoShredEngine — the orchestrator.
 *
 * Model (envelope encryption):
 *
 *     plaintext --seal(DEK)-->  ciphertext            (stored in records/)
 *     DEK       --seal(KEK)-->  wrapped DEK           (stored in keys/, the ONLY copy)
 *     SHA-256(DEK), SHA-256(ciphertext)               (committed in the signed ledger)
 *
 * Every record gets its own random 256-bit DEK. To erase a record we destroy
 * its wrapped DEK — the single existing copy of that key — and append a signed
 * SHRED event to the tamper-evident ledger. The ciphertext can stay exactly
 * where it is; without the key it is permanently, provably unrecoverable.
 */

import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import {
  ALGORITHM_LABEL,
  canonical,
  fingerprint,
  generateKey,
  generateSigningKeys,
  open as openSealed,
  seal,
  sha256hex,
  signData,
  verifyData,
  wipe,
} from './crypto.ts';
import { FileKeystore } from './keystore.ts';
import { Ledger } from './ledger.ts';
import { RetentionManager } from './retention.ts';
import type {
  ErasureCertificate,
  LedgerEntry,
  RecordEntry,
  RetentionPolicy,
} from './types.ts';

const CERT_VERSION = '1.0';

/** Thrown when reading a record whose key has been crypto-shredded. */
export class ShreddedError extends Error {
  readonly recordId: string;
  constructor(recordId: string) {
    super(`record "${recordId}" has been crypto-shredded — ciphertext exists but is permanently unrecoverable`);
    this.name = 'ShreddedError';
    this.recordId = recordId;
  }
}

export interface PutOptions {
  /** Use a specific record id instead of a generated UUID. */
  id?: string;
  /** Name of a registered retention policy that governs auto-expiry. */
  policy?: string;
}

export interface EngineConfig {
  version: string;
  algorithm: string;
  issuer: string;
  createdAt: string;
}

export class CryptoShredEngine {
  readonly dir: string;
  private readonly kek: Buffer;
  private readonly signingPrivatePem: string;
  readonly signingPublicPem: string;
  readonly issuer: string;
  private readonly keystore: FileKeystore;
  private readonly ledger: Ledger;
  readonly retention: RetentionManager;

  private constructor(dir: string, kek: Buffer, privatePem: string, publicPem: string, issuer: string) {
    this.dir = dir;
    this.kek = kek;
    this.signingPrivatePem = privatePem;
    this.signingPublicPem = publicPem;
    this.issuer = issuer;
    this.keystore = new FileKeystore(dir);
    this.ledger = new Ledger(join(dir, 'ledger.jsonl'), privatePem, publicPem);
    this.retention = new RetentionManager();
    mkdirSync(this.recordsDir, { recursive: true });
    this.loadPolicies();
  }

  // ---- lifecycle -----------------------------------------------------------

  /** Create a brand-new store: generates the KEK and the ledger signing keys. */
  static init(dir: string, opts: { issuer?: string } = {}): CryptoShredEngine {
    if (existsSync(join(dir, 'config.json'))) {
      throw new Error(`a store already exists at ${dir} — use CryptoShredEngine.open()`);
    }
    mkdirSync(dir, { recursive: true });
    const kek = generateKey();
    const { privatePem, publicPem } = generateSigningKeys();
    const issuer = opts.issuer ?? 'crypto-shred-engine';
    const config: EngineConfig = {
      version: CERT_VERSION,
      algorithm: ALGORITHM_LABEL,
      issuer,
      createdAt: new Date().toISOString(),
    };
    // In production the KEK belongs in an HSM/KMS and the signing key in a
    // hardware token; here we persist them with 0600 perms for a self-contained demo.
    writeFileSync(join(dir, 'master.kek'), kek.toString('base64'), { mode: 0o600 });
    writeFileSync(join(dir, 'ledger.key'), privatePem, { mode: 0o600 });
    writeFileSync(join(dir, 'ledger.pub'), publicPem, { mode: 0o644 });
    writeFileSync(join(dir, 'config.json'), JSON.stringify(config, null, 2));
    return new CryptoShredEngine(dir, kek, privatePem, publicPem, issuer);
  }

  /** Open an existing store. */
  static open(dir: string): CryptoShredEngine {
    if (!existsSync(join(dir, 'config.json'))) {
      throw new Error(`no store at ${dir} — use CryptoShredEngine.init()`);
    }
    const config = JSON.parse(readFileSync(join(dir, 'config.json'), 'utf8')) as EngineConfig;
    const kek = Buffer.from(readFileSync(join(dir, 'master.kek'), 'utf8'), 'base64');
    const privatePem = readFileSync(join(dir, 'ledger.key'), 'utf8');
    const publicPem = readFileSync(join(dir, 'ledger.pub'), 'utf8');
    return new CryptoShredEngine(dir, kek, privatePem, publicPem, config.issuer);
  }

  // ---- core operations -----------------------------------------------------

  /** Encrypt and store a payload under its own fresh DEK. */
  put(plaintext: string | Buffer, opts: PutOptions = {}): RecordEntry {
    const id = opts.id ?? randomUUID();
    if (existsSync(this.recordPath(id))) throw new Error(`record "${id}" already exists`);
    if (opts.policy && !this.retention.get(opts.policy)) {
      throw new Error(`unknown retention policy "${opts.policy}" — register it first`);
    }

    const dekId = randomUUID();
    const dek = generateKey();
    try {
      const aad = Buffer.from(id, 'utf8'); // bind ciphertext to this record id
      const sealed = seal(dek, Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8'), aad);
      const ciphertextHash = sha256hex(sealed.ciphertext);
      const fp = fingerprint(dek);

      // Envelope: the DEK lives only as ciphertext under the KEK.
      this.keystore.put({
        dekId,
        recordId: id,
        wrappedDek: seal(this.kek, dek),
        fingerprint: fp,
        createdAt: new Date().toISOString(),
      });

      const record: RecordEntry = {
        id,
        dekId,
        policy: opts.policy,
        createdAt: new Date().toISOString(),
        sealed,
        ciphertextHash,
        shredded: false,
      };
      this.writeRecord(record);

      this.ledger.append({
        action: 'CREATE',
        recordId: id,
        dekId,
        keyFingerprint: fp,
        ciphertextHash,
        metadata: opts.policy ? { policy: opts.policy } : undefined,
      });
      return record;
    } finally {
      wipe(dek);
    }
  }

  /** Decrypt and return a record's plaintext. Throws {@link ShreddedError} if erased. */
  get(id: string): Buffer {
    const record = this.requireRecord(id);
    if (record.shredded) throw new ShreddedError(id);
    const keyEntry = this.keystore.get(record.dekId);
    if (!keyEntry) throw new ShreddedError(id); // key gone even if flag missed
    const dek = openSealed(this.kek, keyEntry.wrappedDek);
    try {
      return openSealed(dek, record.sealed);
    } finally {
      wipe(dek);
    }
  }

  /**
   * Crypto-shred a record: destroy its DEK and record a signed SHRED event.
   * Idempotent — shredding an already-shredded record returns the original event.
   */
  shred(id: string, reason?: string, action: 'SHRED' | 'EXPIRE' = 'SHRED'): LedgerEntry {
    const record = this.requireRecord(id);
    if (record.shredded) {
      const existing = this.ledger.entriesFor(id).find((e) => e.action === 'SHRED' || e.action === 'EXPIRE');
      if (existing) return existing;
    }

    // Fingerprint must be captured before the key is destroyed; fall back to the
    // CREATE ledger entry if the key file is already gone.
    const keyEntry = this.keystore.get(record.dekId);
    const fp =
      keyEntry?.fingerprint ??
      this.ledger.entriesFor(id).find((e) => e.action === 'CREATE')?.keyFingerprint ??
      '';

    this.keystore.destroy(record.dekId);

    record.shredded = true;
    record.shreddedAt = new Date().toISOString();
    this.writeRecord(record);

    return this.ledger.append({
      action,
      recordId: id,
      dekId: record.dekId,
      keyFingerprint: fp,
      ciphertextHash: record.ciphertextHash,
      metadata: reason ? { reason } : undefined,
    });
  }

  // ---- proof ---------------------------------------------------------------

  /**
   * Produce a signed, self-contained Certificate of Erasure for a shredded
   * record. The certificate embeds the public key, so anyone can verify it
   * offline with {@link CryptoShredEngine.verifyCertificate}.
   */
  proveDeletion(id: string): ErasureCertificate {
    const record = this.requireRecord(id);
    if (!record.shredded) {
      throw new Error(`record "${id}" is not shredded — there is nothing to prove`);
    }

    const entries = this.ledger.entriesFor(id);
    const createEntry = entries.find((e) => e.action === 'CREATE');
    const shredEntry = entries.find((e) => e.action === 'SHRED' || e.action === 'EXPIRE');
    if (!createEntry || !shredEntry) {
      throw new Error(`ledger is missing CREATE/SHRED events for "${id}"`);
    }

    // Live attestations, checked at issuance time.
    const keyAbsentFromStore = !this.keystore.has(record.dekId);
    const ciphertextIntact = sha256hex(record.sealed.ciphertext) === record.ciphertextHash;
    const ledgerChainValid = this.ledger.verify().valid;

    const unsigned: Omit<ErasureCertificate, 'signature'> = {
      version: CERT_VERSION,
      recordId: id,
      keyFingerprint: shredEntry.keyFingerprint || createEntry.keyFingerprint,
      ciphertextHash: record.ciphertextHash,
      algorithm: ALGORITHM_LABEL,
      createdAt: createEntry.timestamp,
      destroyedAt: shredEntry.timestamp,
      ledgerEntries: [createEntry, shredEntry],
      ledgerHead: this.ledger.head(),
      attestations: {
        keyAbsentFromStore,
        // The ciphertext is intact yet there is no key path to open it.
        ciphertextUndecryptable: keyAbsentFromStore && ciphertextIntact,
        ledgerChainValid,
      },
      issuer: this.issuer,
      publicKey: this.signingPublicPem,
      issuedAt: new Date().toISOString(),
    };

    const signature = signData(this.signingPrivatePem, canonical(unsigned));
    return { ...unsigned, signature };
  }

  /**
   * Verify a Certificate of Erasure with nothing but the certificate itself.
   * Checks the issuer signature, every embedded ledger signature, the internal
   * hash chain of those entries, and cross-field consistency.
   */
  static verifyCertificate(cert: ErasureCertificate): { valid: boolean; checks: Record<string, boolean> } {
    const { signature, ...unsigned } = cert;

    const certSignatureValid = verifyData(cert.publicKey, canonical(unsigned), signature);

    // Each embedded ledger event must hash-recompute and verify on its own.
    const ledgerEntriesAuthentic = cert.ledgerEntries.every((e) => Ledger.verifyEntry(e, cert.publicKey));

    const create = cert.ledgerEntries.find((e) => e.action === 'CREATE');
    const shred = cert.ledgerEntries.find((e) => e.action === 'SHRED' || e.action === 'EXPIRE');

    const fingerprintConsistent =
      !!create && !!shred && create.keyFingerprint === cert.keyFingerprint && shred.keyFingerprint === cert.keyFingerprint;
    const ciphertextConsistent =
      !!create && !!shred && create.ciphertextHash === cert.ciphertextHash && shred.ciphertextHash === cert.ciphertextHash;
    const recordConsistent = !!create && !!shred && create.recordId === cert.recordId && shred.recordId === cert.recordId;
    const attestationsHold =
      cert.attestations.keyAbsentFromStore &&
      cert.attestations.ciphertextUndecryptable &&
      cert.attestations.ledgerChainValid;

    const checks = {
      certSignatureValid,
      ledgerEntriesAuthentic,
      fingerprintConsistent,
      ciphertextConsistent,
      recordConsistent,
      attestationsHold,
    };
    return { valid: Object.values(checks).every(Boolean), checks };
  }

  // ---- retention -----------------------------------------------------------

  registerPolicy(policy: RetentionPolicy): void {
    this.retention.register(policy);
    this.savePolicies();
  }

  /** Auto-shred every record whose retention period has elapsed. */
  sweepRetention(now: number = Date.now()): { expired: string[]; entries: LedgerEntry[] } {
    const due = this.retention.due(this.listRecords(), now);
    const entries = due.map((r) => this.shred(r.id, `retention policy "${r.policy}" elapsed`, 'EXPIRE'));
    return { expired: due.map((r) => r.id), entries };
  }

  // ---- introspection -------------------------------------------------------

  verifyLedger() {
    return this.ledger.verify();
  }

  ledgerEntries(): LedgerEntry[] {
    return this.ledger.all();
  }

  getRecord(id: string): RecordEntry | null {
    return existsSync(this.recordPath(id)) ? (JSON.parse(readFileSync(this.recordPath(id), 'utf8')) as RecordEntry) : null;
  }

  listRecords(): RecordEntry[] {
    if (!existsSync(this.recordsDir)) return [];
    return readdirSync(this.recordsDir)
      .filter((f) => f.endsWith('.json'))
      .map((f) => JSON.parse(readFileSync(join(this.recordsDir, f), 'utf8')) as RecordEntry);
  }

  /** True if the wrapped DEK is still present (i.e. the record is readable). */
  hasKey(dekId: string): boolean {
    return this.keystore.has(dekId);
  }

  // ---- internals -----------------------------------------------------------

  private get recordsDir(): string {
    return join(this.dir, 'records');
  }
  private recordPath(id: string): string {
    return join(this.recordsDir, `${encodeURIComponent(id)}.json`);
  }
  private writeRecord(record: RecordEntry): void {
    writeFileSync(this.recordPath(record.id), JSON.stringify(record, null, 2));
  }
  private requireRecord(id: string): RecordEntry {
    const record = this.getRecord(id);
    if (!record) throw new Error(`record "${id}" not found`);
    return record;
  }
  private get policiesPath(): string {
    return join(this.dir, 'policies.json');
  }
  private savePolicies(): void {
    writeFileSync(this.policiesPath, JSON.stringify(this.retention.list(), null, 2));
  }
  private loadPolicies(): void {
    if (!existsSync(this.policiesPath)) return;
    const policies = JSON.parse(readFileSync(this.policiesPath, 'utf8')) as RetentionPolicy[];
    for (const p of policies) this.retention.register(p);
  }
}
