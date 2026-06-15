#!/usr/bin/env node
/**
 * cryptoshred — command-line interface to the crypto-shredding engine.
 *
 *   cryptoshred init [--issuer NAME] [--store DIR]
 *   cryptoshred put "<text>" [--id ID] [--policy NAME]      (text "-" reads stdin)
 *   cryptoshred get <id>
 *   cryptoshred shred <id> [--reason TEXT]
 *   cryptoshred prove <id> [--out cert.json]
 *   cryptoshred verify-cert <cert.json>
 *   cryptoshred verify-ledger
 *   cryptoshred ls
 *   cryptoshred ledger
 *   cryptoshred policy add <name> <retentionMs> [--desc TEXT]
 *   cryptoshred policy ls
 *   cryptoshred sweep
 *
 * Global: --store DIR (default ./.cryptostore)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { CryptoShredEngine, ShreddedError } from '../src/engine.ts';
import type { ErasureCertificate } from '../src/types.ts';

function parseArgs(argv: string[]): { positional: string[]; flags: Record<string, string | boolean> } {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function readStdin(): string {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

const { positional, flags } = parseArgs(process.argv.slice(2));
const command = positional[0];
const storeDir = resolve(String(flags.store ?? './.cryptostore'));

function open(): CryptoShredEngine {
  return CryptoShredEngine.open(storeDir);
}

function die(msg: string): never {
  console.error(`error: ${msg}`);
  process.exit(1);
}

try {
  switch (command) {
    case 'init': {
      const engine = CryptoShredEngine.init(storeDir, { issuer: flags.issuer ? String(flags.issuer) : undefined });
      console.log(`initialized store at ${engine.dir}`);
      console.log(`issuer: ${engine.issuer}`);
      console.log(`ledger public key written to ${join(engine.dir, 'ledger.pub')}`);
      break;
    }

    case 'put': {
      const engine = open();
      let text = positional[1];
      if (text === '-' || text === undefined) text = readStdin();
      if (!text) die('nothing to store (pass text or pipe via stdin)');
      const record = engine.put(text, {
        id: flags.id ? String(flags.id) : undefined,
        policy: flags.policy ? String(flags.policy) : undefined,
      });
      console.log(`stored record ${record.id}`);
      console.log(`  dek:        ${record.dekId}`);
      console.log(`  ciphertext: ${record.sealed.ciphertext.slice(0, 48)}...`);
      if (record.policy) console.log(`  policy:     ${record.policy}`);
      break;
    }

    case 'get': {
      const engine = open();
      const id = positional[1] ?? die('usage: get <id>');
      try {
        process.stdout.write(engine.get(id).toString('utf8') + '\n');
      } catch (e) {
        if (e instanceof ShreddedError) die(e.message);
        throw e;
      }
      break;
    }

    case 'shred': {
      const engine = open();
      const id = positional[1] ?? die('usage: shred <id>');
      const entry = engine.shred(id, flags.reason ? String(flags.reason) : undefined);
      console.log(`shredded ${id} at ${entry.timestamp}`);
      console.log(`  key fingerprint: ${entry.keyFingerprint}`);
      console.log(`  ledger seq:      ${entry.seq}`);
      break;
    }

    case 'prove': {
      const engine = open();
      const id = positional[1] ?? die('usage: prove <id>');
      const cert = engine.proveDeletion(id);
      const out = flags.out ? String(flags.out) : '';
      if (out) {
        writeFileSync(out, JSON.stringify(cert, null, 2));
        console.log(`certificate of erasure written to ${out}`);
      } else {
        console.log(JSON.stringify(cert, null, 2));
      }
      break;
    }

    case 'verify-cert': {
      const file = positional[1] ?? die('usage: verify-cert <cert.json>');
      const cert = JSON.parse(readFileSync(file, 'utf8')) as ErasureCertificate;
      const result = CryptoShredEngine.verifyCertificate(cert);
      console.log(`certificate for record ${cert.recordId}: ${result.valid ? 'VALID ✓' : 'INVALID ✗'}`);
      for (const [k, v] of Object.entries(result.checks)) {
        console.log(`  ${v ? '✓' : '✗'} ${k}`);
      }
      process.exit(result.valid ? 0 : 2);
      break;
    }

    case 'verify-ledger': {
      const engine = open();
      const r = engine.verifyLedger();
      if (r.valid) {
        console.log(`ledger VALID ✓ (${r.length} entries, chain intact and signed)`);
      } else {
        console.log(`ledger INVALID ✗ — ${r.reason} at seq ${r.brokenAt}`);
        process.exit(2);
      }
      break;
    }

    case 'ls': {
      const engine = open();
      const records = engine.listRecords().sort((a, b) => a.createdAt.localeCompare(b.createdAt));
      if (records.length === 0) console.log('(no records)');
      for (const r of records) {
        const state = r.shredded ? 'SHREDDED' : engine.hasKey(r.dekId) ? 'live' : 'SHREDDED';
        console.log(`${state.padEnd(9)} ${r.id}  ${r.policy ? `[${r.policy}] ` : ''}created ${r.createdAt}`);
      }
      break;
    }

    case 'ledger': {
      const engine = open();
      for (const e of engine.ledgerEntries()) {
        console.log(`#${e.seq} ${e.action.padEnd(6)} ${e.recordId}  ${e.timestamp}  ${e.entryHash.slice(0, 16)}…`);
      }
      break;
    }

    case 'policy': {
      const engine = open();
      const sub = positional[1];
      if (sub === 'add') {
        const name = positional[2] ?? die('usage: policy add <name> <retentionMs>');
        const ms = Number(positional[3]);
        if (!Number.isFinite(ms) || ms <= 0) die('retentionMs must be a positive number');
        engine.registerPolicy({ name, retentionMs: ms, description: flags.desc ? String(flags.desc) : undefined });
        console.log(`registered policy "${name}" (retentionMs=${ms})`);
      } else if (sub === 'ls' || sub === undefined) {
        const policies = engine.retention.list();
        if (policies.length === 0) console.log('(no policies)');
        for (const p of policies) console.log(`${p.name}  retentionMs=${p.retentionMs}${p.description ? `  — ${p.description}` : ''}`);
      } else {
        die(`unknown policy subcommand "${sub}"`);
      }
      break;
    }

    case 'sweep': {
      const engine = open();
      const { expired } = engine.sweepRetention();
      if (expired.length === 0) console.log('nothing due for expiry');
      else {
        console.log(`auto-shredded ${expired.length} expired record(s):`);
        for (const id of expired) console.log(`  ${id}`);
      }
      break;
    }

    default: {
      const usage = [
        'cryptoshred — crypto-shredding + proof-of-deletion engine',
        '',
        'Commands:',
        '  init [--issuer NAME]                  create a new store',
        '  put "<text>" [--id ID] [--policy P]   encrypt + store ("-" reads stdin)',
        '  get <id>                              decrypt + print',
        '  shred <id> [--reason TEXT]            destroy the key (crypto-shred)',
        '  prove <id> [--out cert.json]          issue a Certificate of Erasure',
        '  verify-cert <cert.json>               verify a certificate offline',
        '  verify-ledger                         check the chain is intact + signed',
        '  ls                                    list records and their state',
        '  ledger                                print the erasure ledger',
        '  policy add <name> <ms> [--desc T]     register a retention policy',
        '  policy ls                             list retention policies',
        '  sweep                                 auto-shred expired records',
        '',
        'Global:  --store DIR   (default ./.cryptostore)',
      ].join('\n');
      console.log(usage);
      if (command) die(`unknown command "${command}"`);
    }
  }
} catch (e) {
  die((e as Error).message);
}
