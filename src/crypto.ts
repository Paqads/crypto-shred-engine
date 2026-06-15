/**
 * Crypto primitives — a thin, opinionated wrapper over Node's built-in
 * `node:crypto`. No third-party code touches key material.
 *
 *   - AES-256-GCM authenticated encryption (seal / open)
 *   - Random 256-bit key generation (DEKs and the KEK)
 *   - SHA-256 fingerprints (key commitments) and content hashes
 *   - Deterministic canonical JSON (so hashes/signatures are reproducible)
 *   - Ed25519 signing / verification for the erasure ledger
 */

import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  createHash,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as edSign,
  verify as edVerify,
  timingSafeEqual,
} from 'node:crypto';
import type { Sealed } from './types.ts';

const ALGORITHM = 'aes-256-gcm';
export const ALGORITHM_LABEL = 'AES-256-GCM';
const KEY_BYTES = 32; // 256-bit
const IV_BYTES = 12; // 96-bit nonce, the GCM-recommended size
const TAG_BYTES = 16; // 128-bit authentication tag

/** Generate a fresh 256-bit key (used for both DEKs and the KEK). */
export function generateKey(): Buffer {
  return randomBytes(KEY_BYTES);
}

/**
 * Encrypt `plaintext` under `key` with AES-256-GCM and a fresh random nonce.
 * Optional `aad` is authenticated but not encrypted (e.g. a record id), so
 * ciphertext can't be silently moved between records.
 */
export function seal(key: Buffer, plaintext: Buffer, aad?: Buffer): Sealed {
  if (key.length !== KEY_BYTES) throw new Error(`key must be ${KEY_BYTES} bytes`);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  if (aad) cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    iv: iv.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ...(aad ? { aad: aad.toString('base64') } : {}),
  };
}

/**
 * Decrypt a {@link Sealed} blob. Throws if the key is wrong, the data was
 * tampered with, or the AAD doesn't match — GCM gives us integrity for free.
 */
export function open(key: Buffer, sealed: Sealed): Buffer {
  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(sealed.iv, 'base64'), {
    authTagLength: TAG_BYTES,
  });
  if (sealed.aad) decipher.setAAD(Buffer.from(sealed.aad, 'base64'));
  decipher.setAuthTag(Buffer.from(sealed.tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(sealed.ciphertext, 'base64')),
    decipher.final(),
  ]);
}

/**
 * SHA-256 of a raw key, hex-encoded. Used as a *commitment*: because a DEK is
 * 256 bits of full entropy, this hash is binding (can't find another key with
 * the same fingerprint) and hiding (can't recover the key from it). It proves a
 * specific key existed without ever revealing the key.
 */
export function fingerprint(key: Buffer): string {
  return createHash('sha256').update(key).digest('hex');
}

/** SHA-256 of arbitrary content, hex-encoded. */
export function sha256hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Deterministic JSON: object keys sorted recursively. Two structurally-equal
 * values always produce the same string, so hashes and signatures over JSON
 * are stable across machines and runs.
 */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const obj = value as Record<string, unknown>;
  const body = Object.keys(obj)
    .sort()
    .filter((k) => obj[k] !== undefined)
    .map((k) => JSON.stringify(k) + ':' + canonical(obj[k]))
    .join(',');
  return '{' + body + '}';
}

export interface SigningKeyPair {
  privatePem: string;
  publicPem: string;
}

/** Generate an Ed25519 keypair (PEM). The public key is the auditor's anchor. */
export function generateSigningKeys(): SigningKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { privatePem: privateKey, publicPem: publicKey };
}

/** Sign data with an Ed25519 private key (PEM in, base64 signature out). */
export function signData(privatePem: string, data: string | Buffer): string {
  const key = createPrivateKey(privatePem);
  return edSign(null, Buffer.from(data), key).toString('base64');
}

/** Verify an Ed25519 signature. Never throws — returns false on any problem. */
export function verifyData(publicPem: string, data: string | Buffer, signatureB64: string): boolean {
  try {
    const key = createPublicKey(publicPem);
    return edVerify(null, Buffer.from(data), key, Buffer.from(signatureB64, 'base64'));
  } catch {
    return false;
  }
}

/** Constant-time hex-string comparison (for fingerprint checks). */
export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/**
 * Best-effort in-memory wipe. Note: in a garbage-collected runtime this cannot
 * guarantee every copy of the key is gone (see README "Threat model"). The
 * durable guarantee comes from destroying the persisted wrapped DEK.
 */
export function wipe(buf: Buffer): void {
  buf.fill(0);
}
