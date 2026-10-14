// Credential bundle check (spec §10.3, §13): the credential page's chunk graph
// shares no file with any other entry and its chunks never mention web storage
// or a service worker.
//
//   node ci/check-credential-bundle.mjs <dist dir>
//
// Reads Vite's <dist>/.vite/manifest.json (build.manifest: true).
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const CREDENTIAL_ENTRIES = ['credential.html', 'credential-windows.html'];
export const FORBIDDEN = [
  'localStorage',
  'sessionStorage',
  'indexedDB',
  'BroadcastChannel',
  'serviceWorker',
];

/** Every file reachable from a manifest key: its chunk, static and dynamic imports, css, assets. */
function closure(manifest, starts) {
  const files = new Set();
  const seen = new Set();
  const visit = (key) => {
    if (seen.has(key)) return;
    seen.add(key);
    const chunk = manifest[key];
    if (!chunk) return;
    if (chunk.file) files.add(chunk.file);
    for (const f of chunk.css ?? []) files.add(f);
    for (const f of chunk.assets ?? []) files.add(f);
    for (const k of chunk.imports ?? []) visit(k);
    for (const k of chunk.dynamicImports ?? []) visit(k);
  };
  starts.forEach(visit);
  return files;
}

/**
 * Manifest keys of everything a built credential page loads. Two html entries
 * with one script make Vite emit that script as a shared (non-entry) chunk, so
 * the manifest has no key for the page itself; the page's own script and link
 * tags are the reliable seed.
 */
function credentialSeeds(manifest, readText) {
  const hrefs = new Set();
  for (const page of CREDENTIAL_ENTRIES) {
    const html = readText(page);
    if (html === undefined) continue;
    for (const m of html.matchAll(/(?:src|href)="\/?([^"]+)"/g)) hrefs.add(m[1]);
  }
  return Object.keys(manifest).filter(
    (k) => manifest[k].isEntry === true && CREDENTIAL_ENTRIES.includes(k)
      ? true
      : hrefs.has(manifest[k].file),
  );
}

/**
 * Pure check. `manifest` is the parsed manifest, `readText(path)` returns a
 * dist-relative file's text (undefined if absent). Returns a list of problems
 * (empty means pass).
 */
export function checkBundle(manifest, readText) {
  const problems = [];
  const seeds = credentialSeeds(manifest, readText);
  if (seeds.length === 0) {
    problems.push('no credential entry found (manifest or built credential pages)');
  }
  const credentialFiles = closure(manifest, seeds);
  const others = Object.keys(manifest).filter(
    (k) => manifest[k].isEntry && !seeds.includes(k),
  );
  for (const e of others) {
    for (const f of closure(manifest, [e])) {
      if (credentialFiles.has(f)) {
        problems.push(`${f} is shared by a credential entry and ${e}`);
      }
    }
  }
  for (const f of credentialFiles) {
    if (!f.endsWith('.js')) continue;
    const text = readText(f) ?? '';
    for (const word of FORBIDDEN) {
      if (text.includes(word)) {
        problems.push(`${f} contains ${word}`);
      }
    }
  }
  return problems;
}

function main(argv) {
  const dist = argv[2];
  if (!dist) {
    console.error('usage: check-credential-bundle.mjs <dist dir>');
    return 2;
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(join(dist, '.vite', 'manifest.json'), 'utf8'));
  } catch (e) {
    console.error(`cannot read ${join(dist, '.vite', 'manifest.json')}: ${e.message}`);
    return 2;
  }
  const read = (f) => (existsSync(join(dist, f)) ? readFileSync(join(dist, f), 'utf8') : undefined);
  const problems = checkBundle(manifest, read);
  for (const p of problems) console.error(`check-credential-bundle: ${p}`);
  if (problems.length === 0) console.log('check-credential-bundle: ok');
  return problems.length === 0 ? 0 : 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv));
}
