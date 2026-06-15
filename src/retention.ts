/**
 * Retention policies make data expire itself. A record is tagged with a policy;
 * once `createdAt + retentionMs` is in the past, the next sweep crypto-shreds it
 * automatically. This is retention-limit enforcement that you can *prove* was
 * carried out, because each expiry lands in the signed erasure ledger.
 */

import type { RecordEntry, RetentionPolicy } from './types.ts';

export class RetentionManager {
  private readonly policies = new Map<string, RetentionPolicy>();

  register(policy: RetentionPolicy): void {
    if (policy.retentionMs <= 0) throw new Error('retentionMs must be positive');
    this.policies.set(policy.name, policy);
  }

  get(name: string): RetentionPolicy | undefined {
    return this.policies.get(name);
  }

  list(): RetentionPolicy[] {
    return [...this.policies.values()];
  }

  /** When (epoch ms) a record is due to expire, or null if it has no policy. */
  expiresAt(record: RecordEntry): number | null {
    if (!record.policy) return null;
    const policy = this.policies.get(record.policy);
    if (!policy) return null;
    return new Date(record.createdAt).getTime() + policy.retentionMs;
  }

  /** Live, not-yet-shredded records whose retention period has elapsed. */
  due(records: RecordEntry[], now: number = Date.now()): RecordEntry[] {
    return records.filter((r) => {
      if (r.shredded) return false;
      const expiry = this.expiresAt(r);
      return expiry !== null && expiry <= now;
    });
  }

  toJSON(): RetentionPolicy[] {
    return this.list();
  }
}
