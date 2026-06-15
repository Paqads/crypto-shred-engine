/**
 * Shared data shapes for the crypto-shredding engine.
 *
 * Everything that touches disk is plain JSON so a store is fully inspectable:
 * you can `cat` a record and see only ciphertext, and watch a key file vanish
 * the moment a record is shredded.
 */

/** An AES-256-GCM sealed blob. All fields are base64. */
export interface Sealed {
  /** 96-bit GCM nonce (unique per seal). */
  iv: string;
  /** Encrypted payload. */
  ciphertext: string;
  /** 128-bit GCM authentication tag. */
  tag: string;
  /** Optional additional authenticated data (bound, not encrypted). */
  aad?: string;
}

/** Lifecycle events recorded in the tamper-evident ledger. */
export type LedgerAction = 'CREATE' | 'SHRED' | 'EXPIRE';

/**
 * One link in the append-only erasure ledger.
 *
 * The chain is built by hashing each entry's core fields together with the
 * previous entry's hash, then signing the result with Ed25519. Altering any
 * past entry breaks every hash and signature that follows it.
 */
export interface LedgerEntry {
  seq: number;
  /** ISO-8601 issuance time. */
  timestamp: string;
  action: LedgerAction;
  recordId: string;
  dekId: string;
  /** SHA-256 of the raw Data Encryption Key — a commitment that this exact key existed, without revealing it. */
  keyFingerprint: string;
  /** SHA-256 of the record's ciphertext — binds the event to specific encrypted data. */
  ciphertextHash: string;
  /** Optional free-form context (e.g. shred reason, retention policy). */
  metadata?: Record<string, unknown>;
  /** entryHash of the previous link (genesis = 64 zeroes). */
  prevHash: string;
  /** SHA-256 over the canonical core fields above. */
  entryHash: string;
  /** base64 Ed25519 signature over entryHash. */
  signature: string;
}

/** A stored, encrypted record. The plaintext never touches disk. */
export interface RecordEntry {
  id: string;
  dekId: string;
  /** Name of the retention policy governing auto-expiry, if any. */
  policy?: string;
  createdAt: string;
  /** The payload, sealed under this record's unique DEK. */
  sealed: Sealed;
  ciphertextHash: string;
  shredded: boolean;
  shreddedAt?: string;
}

/**
 * A wrapped Data Encryption Key. This is the ONLY copy of the DEK that exists,
 * and it lives encrypted under the Key Encryption Key (KEK). Destroying this
 * file is the act of crypto-shredding: the DEK is gone, the record's ciphertext
 * becomes permanently undecryptable.
 */
export interface KeyEntry {
  dekId: string;
  recordId: string;
  /** The DEK, sealed under the KEK (envelope encryption). */
  wrappedDek: Sealed;
  /** SHA-256 of the raw DEK — matches the ledger commitment. */
  fingerprint: string;
  createdAt: string;
}

/** A retention rule: records older than retentionMs auto-shred on the next sweep. */
export interface RetentionPolicy {
  name: string;
  retentionMs: number;
  description?: string;
}

/**
 * A self-contained, independently verifiable proof that a record has been
 * cryptographically erased. Hand this to a regulator or auditor; they need
 * only the public key (embedded) to verify it offline.
 */
export interface ErasureCertificate {
  version: string;
  recordId: string;
  keyFingerprint: string;
  ciphertextHash: string;
  algorithm: string;
  createdAt: string;
  destroyedAt: string;
  /** The CREATE and SHRED ledger links for this record. */
  ledgerEntries: LedgerEntry[];
  /** entryHash of the newest ledger link at issuance — anchors these entries in the chain. */
  ledgerHead: string;
  attestations: {
    /** The wrapped DEK is no longer present in the keystore. */
    keyAbsentFromStore: boolean;
    /** A decrypt attempt against the surviving ciphertext failed. */
    ciphertextUndecryptable: boolean;
    /** The ledger chain verified intact end-to-end. */
    ledgerChainValid: boolean;
  };
  issuer: string;
  /** Ed25519 public key (PEM) — the verification anchor. */
  publicKey: string;
  issuedAt: string;
  /** base64 Ed25519 signature over the canonical certificate (minus this field). */
  signature: string;
}
