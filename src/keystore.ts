/**
 * The keystore holds wrapped Data Encryption Keys — one file per DEK. Each file
 * is the *only* copy of its key (encrypted under the KEK). Crypto-shredding is
 * literally `destroy(dekId)`: the wrapped DEK is overwritten and unlinked, and
 * from that instant the matching record's ciphertext can never be decrypted.
 */

import { mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, readdirSync, statSync, openSync, fsyncSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { KeyEntry } from './types.ts';

export class FileKeystore {
  readonly dir: string;

  constructor(baseDir: string) {
    this.dir = join(baseDir, 'keys');
    mkdirSync(this.dir, { recursive: true });
  }

  private path(dekId: string): string {
    return join(this.dir, `${dekId}.json`);
  }

  /** Persist a wrapped DEK. */
  put(entry: KeyEntry): void {
    writeFileSync(this.path(entry.dekId), JSON.stringify(entry, null, 2), { mode: 0o600 });
  }

  /** Load a wrapped DEK, or null if it has been shredded / never existed. */
  get(dekId: string): KeyEntry | null {
    const p = this.path(dekId);
    if (!existsSync(p)) return null;
    return JSON.parse(readFileSync(p, 'utf8')) as KeyEntry;
  }

  has(dekId: string): boolean {
    return existsSync(this.path(dekId));
  }

  /**
   * Crypto-shred: overwrite the wrapped-DEK file with random bytes, flush to
   * disk, then unlink it. Returns false if the key was already gone.
   *
   * Caveat: on copy-on-write / journaling / wear-leveling storage, overwrite
   * is best-effort — see the README threat model. The cryptographic guarantee
   * does not depend on the overwrite: once this file is unlinked, the DEK has
   * no surviving representation anywhere in the system.
   */
  destroy(dekId: string): boolean {
    const p = this.path(dekId);
    if (!existsSync(p)) return false;
    try {
      const size = statSync(p).size;
      const fd = openSync(p, 'r+');
      try {
        // Two overwrite passes, then truncate by writing zero-length isn't
        // portable, so we just scribble random bytes and fsync.
        for (let pass = 0; pass < 2; pass++) {
          const noise = randomBytes(Math.max(size, 64));
          writeFileSync(fd, noise);
          fsyncSync(fd);
        }
      } finally {
        closeSync(fd);
      }
    } catch {
      // Overwrite is best-effort; unlink is the operation that matters.
    }
    rmSync(p, { force: true });
    return true;
  }

  /** List the dekIds currently held (i.e. not yet shredded). */
  list(): string[] {
    if (!existsSync(this.dir)) return [];
    return readdirSync(this.dir)
      .filter((f) => f.endsWith('.json'))
      .map((f) => f.slice(0, -'.json'.length));
  }
}
