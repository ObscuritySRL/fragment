import { hex, type Image } from './binary';
export type Signature = { bytes: Uint8Array; mask: string };
export function parseTable(source: string, name: string): Signature[] {
  const body = source.split(`${name}[]`)[1]?.split('};')[0];
  if (!body) throw new Error(`Missing signature table ${name}`);
  const result = [...body.matchAll(/\{\s*"((?:\\x[0-9a-f]{2})+)"\s*,\s*"([x?]+)"\s*\}/gi)].map(m => {
    const bytes = Uint8Array.from([...m[1].matchAll(/\\x([0-9a-f]{2})/gi)], n => parseInt(n[1], 16));
    if (bytes.length !== m[2].length) throw new Error('Signature/mask length mismatch');
    return { bytes, mask: m[2] };
  });
  if (!result.length) throw new Error(`Empty signature table ${name}`);
  return result;
}
export function matches(code: Uint8Array, sig: Signature, offset = 0) {
  return offset >= 0 && offset + sig.mask.length <= code.length &&
    [...sig.mask].every((m, i) => m === '?' || code[offset + i] === sig.bytes[i]);
}
export async function verify(sourcePath: string, paths: string[], load: (path: string) => Promise<Image>, linux = false) {
  if (!paths.length) throw new Error('Supply one or more actual libcurl binaries; no implicit machine-specific paths');
  const source = await Bun.file(sourcePath).text();
  let checked = 0, failed = 0;
  for (const path of paths) {
    const image = await load(path);
    let region = source;
    if (linux) {
      const block = source.split('#if defined(__x86_64__)')[1]?.split('#endif')[0]?.split('#else');
      if (!block || ![62, 183].includes(image.machine)) throw new Error('Only x86-64/aarch64 signature tables are supported');
      region = block[image.machine === 62 ? 0 : 1];
    } else if (image.machine !== 0x8664) throw new Error('Windows fallback signatures are x64-only');
    for (const [name, table] of [['curl_easy_setopt', 'kSetoptSigs'], ['curl_url_set', 'kUrlSetSigs']]) {
      const entry = image.symbols.get(name);
      if (!entry || entry.offset === null) { console.log(`[SKIP] ${path} ${name}: no function bytes`); continue; }
      checked++;
      const code = image.data.subarray(entry.offset, entry.offset + 64);
      const hit = parseTable(region, table).flatMap((sig, i) => matches(code, sig) ? [i] : []);
      if (!hit.length) failed++;
      console.log(`[${hit.length ? 'PASS' : 'FAIL'}] ${path} ${name}: matching signatures=${hit.join(',') || 'none'} bytes=${hex(code.subarray(0, 24))}`);
    }
  }
  console.log(`${checked} function entries checked, ${failed} without matching fallback (export hooks may still work)`);
  if (!checked || failed) process.exitCode = 1;
}
