// Convert OpenTechAlyzer's MIT fingerprint definitions to portable JSON.
// Usage: node scripts/update_builtin_fingerprints.mjs /path/to/opentechalyzer
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import vm from 'node:vm';

const source = resolve(process.argv[2] ?? '');
const files = [
  'platforms', 'frameworks', 'infrastructure', 'analytics', 'commerce',
  'ecommerce-global', 'services', 'libraries', 'selfhosted',
];
const all = [];
for (const file of files) {
  const input = readFileSync(resolve(source, `src/fingerprints/${file}.ts`), 'utf8');
  const names = [...input.matchAll(/export const (\w+): Fingerprint\[\] =/g)].map(m => m[1]);
  const code = input.replace(/^import type .*\n/mg, '')
    .replace(/export const (\w+): Fingerprint\[\] =/g, 'const $1 =');
  const data = vm.runInNewContext(`${code}\n[${names.join(',')}].flat()`, {}, { timeout: 3000 });
  all.push(...data);
}
const sorted = all.sort((a, b) => a.name.localeCompare(b.name));
writeFileSync('teardown/data/fingerprints.json', JSON.stringify(sorted, null, 2) + '\n');
process.stdout.write(`${sorted.length} fingerprints written\n`);
