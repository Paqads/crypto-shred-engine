/**
 * The erasure ledger: an append-only, hash-chained, Ed25519-signed log of every
 * key's birth (CREATE) and destruction (SHRED / EXPIRE).
 *
 * Each entry's `entryHash` covers its own core fields *and* the previous entry's
 * hash, so the entries form a chain. Each `entryHash` is then signed. To forge
 * or remove a past event you'd have to re-hash and re-sign every entry after it
 * — which is impossible without the private key. That's what upgrades deletion
 * from an assertion ("we ran DELETE") to a proof.
 */

import { appendFileSync, readFileSync, existsSync } from 'node:fs';
import { canonical, sha256hex, signData, verifyData } from './crypto.ts';
import type { LedgerAction, LedgerEntry } from './types.ts';

export const GENESIS_HASH = '0'.repeat(64);

/** The fields that are hashed (and therefore signed). Order-independent via canonical(). */
function coreOf(e: Omit<LedgerEntry, 'entryHash' | 'signature'>): string {
  return canonical({
    seq: e.seq,
    timestamp: e.timestamp,
    action: e.action,
    recordId: e.recordId,
    dekId: e.dekId,
    keyFingerprint: e.keyFingerprint,
    ciphertextHash: e.ciphertextHash,
    metadata: e.metadata ?? null,
    prevHash: e.prevHash,
  });
}

export interface NewLedgerEvent {
  action: LedgerAction;
  recordId: string;
  dekId: string;
  keyFingerprint: string;
  ciphertextHash: string;
  metadata?: Record<string, unknown>;
}

export interface VerificationResult {
  valid: boolean;
  length: number;
  /** seq of the first entry that failed, if any. */
  brokenAt?: number;
  reason?: string;
}

export class Ledger {
  private readonly file: string;
  private readonly privatePem: string;
  private readonly publicPem: string;

  constructor(file: string, privatePem: string, publicPem: string) {
    this.file = file;
    this.privatePem = privatePem;
    this.publicPem = publicPem;
  }

  /** Append a new signed event and return the committed entry. */
  append(event: NewLedgerEvent): LedgerEntry {
    const entries = this.all();
    const prev = entries.at(-1);
    const core: Omit<LedgerEntry, 'entryHash' | 'signature'> = {
      seq: entries.length,
      timestamp: new Date().toISOString(),
      action: event.action,
      recordId: event.recordId,
      dekId: event.dekId,
      keyFingerprint: event.keyFingerprint,
      ciphertextHash: event.ciphertextHash,
      metadata: event.metadata,
      prevHash: prev ? prev.entryHash : GENESIS_HASH,
    };
    const entryHash = sha256hex(coreOf(core));
    const signature = signData(this.privatePem, entryHash);
    const entry: LedgerEntry = { ...core, entryHash, signature };
    appendFileSync(this.file, JSON.stringify(entry) + '\n');
    return entry;
  }

  /** All entries in order. */
  all(): LedgerEntry[] {
    if (!existsSync(this.file)) return [];
    return readFileSync(this.file, 'utf8')
      .split('\n')
      .filter((line) => line.trim().length > 0)
      .map((line) => JSON.parse(line) as LedgerEntry);
  }

  /** Entries touching one record (typically its CREATE and SHRED). */
  entriesFor(recordId: string): LedgerEntry[] {
    return this.all().filter((e) => e.recordId === recordId);
  }

  /** entryHash of the newest link — the current chain head. */
  head(): string {
    const last = this.all().at(-1);
    return last ? last.entryHash : GENESIS_HASH;
  }

  verify(): VerificationResult {
    return Ledger.verifyEntries(this.all(), this.publicPem);
  }

  /**
   * Pure, dependency-free verification used both internally and by the offline
   * certificate verifier. Recomputes every hash, checks every chain link, and
   * verifies every signature against the public key.
   */
  static verifyEntries(entries: LedgerEntry[], publicPem: string): VerificationResult {
    let prevHash = GENESIS_HASH;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      if (e.seq !== i) {
        return { valid: false, length: entries.length, brokenAt: e.seq, reason: 'sequence gap' };
      }
      if (e.prevHash !== prevHash) {
        return { valid: false, length: entries.length, brokenAt: e.seq, reason: 'broken chain link' };
      }
      const recomputed = sha256hex(coreOf(e));
      if (recomputed !== e.entryHash) {
        return { valid: false, length: entries.length, brokenAt: e.seq, reason: 'entry hash mismatch (tampered fields)' };
      }
      if (!verifyData(publicPem, e.entryHash, e.signature)) {
        return { valid: false, length: entries.length, brokenAt: e.seq, reason: 'invalid signature' };
      }
      prevHash = e.entryHash;
    }
    return { valid: true, length: entries.length };
  }

  /**
   * Verify a single entry in isolation: its `entryHash` recomputes from its core
   * fields (so no field was altered) and its signature is authentic. This is the
   * sound check for a certificate, whose embedded entries are a non-contiguous
   * subset of the full chain and so can't be re-linked end-to-end.
   */
  static verifyEntry(entry: LedgerEntry, publicPem: string): boolean {
    if (sha256hex(coreOf(entry)) !== entry.entryHash) return false;
    return verifyData(publicPem, entry.entryHash, entry.signature);
  }
}
