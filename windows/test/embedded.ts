import { Binary } from '../../test/binary';
import { Matrix, type Env } from '../../test/harness';
import { matches, parseTable } from '../../test/signatures';
import { exports } from './pe';

/** Exercise real curl with its hook exports hidden and an unrelated DLL name.
 * Keep its function bodies and mapped name strings intact; only the host gets
 * the original setopt RVA. Missing/incompatible corpus fixtures are SKIP.
 */
export async function embeddedCases(m: Matrix, lib: string, build: string, dll: string, env: Env) {
  const image = await exports(lib);
  const setopt = image.symbols.get('curl_easy_setopt');
  const sigs = parseTable(await Bun.file(`${import.meta.dir}/../main.c`).text(), 'kSetoptSigs');
  if (image.machine !== 0x8664 || !setopt || setopt.offset === null ||
      !sigs.some(sig => matches(image.data, sig, setopt.offset!))) {
    m.skip('embedded curl', `${lib}: no supported x64 setopt fallback fixture`);
    return;
  }

  const b = new Binary(image.data);
  const pe = b.u32(0x3c), opt = pe + 24;
  const sectionTable = opt + b.u16(pe + 20);
  function offset(rva: number, size: number) {
    for (let i = 0; i < b.u16(pe + 6); i++) {
      const s = sectionTable + i * 40, start = b.u32(s + 12);
      if (rva >= start && rva + size <= start + b.u32(s + 16)) {
        const at = b.u32(s + 20) + rva - start;
        b.range(at, size);
        return at;
      }
    }
    throw new Error('Fixture export RVA has no file bytes');
  }
  const directory = offset(b.u32(opt + 112), 40);
  const count = b.u32(directory + 20);
  const functions = offset(b.u32(directory + 28), count * 4);
  const hidden = new Set(['curl_easy_setopt', 'curl_url_set'].map(name => image.symbols.get(name)?.address));
  for (let i = 0; i < count; i++) {
    const at = functions + i * 4;
    if (hidden.has(b.u32(at))) b.view.setUint32(at, 0, true);
  }
  const fixture = `${build}/embedded-client.dll`;
  await Bun.write(fixture, image.data);
  const url = 'http://127.0.0.1:19999/embedded';
  const base = [`${build}/host.exe`, dll, fixture, url, '--setopt-rva', String(setopt.address), '--post'];
  for (const [name, args, extra, proxied] of [
    ['already loaded', ['--preload'], {}, true],
    ['loaded later', [], {}, true],
    ['bare negative control', ['--noinject'], {}, false],
    ['disabled negative control', [], { FRAGMENT_ENABLED: '0' }, false],
  ] as [string, string[], Env, boolean][]) {
    await m.request(`embedded curl ${name}`, [...base, ...args], {
      port: proxied ? 19020 : 19999, path: proxied ? `/${url}` : '/embedded',
      method: 'POST', body: 'embedded=hello',
    }, { ...env, ...extra });
  }
}
