import { Binary, inspect, type Image, type SymbolEntry } from '../../test/binary';
export function parsePE(data: Uint8Array): Image {
  const b = new Binary(data);
  if (b.u16(0) !== 0x5a4d) throw new Error('Not an MZ image');
  const pe = b.u32(0x3c);
  if (b.u32(pe) !== 0x4550) throw new Error('Not a PE image');
  const opt = pe + 24, magic = b.u16(opt), optSize = b.u16(pe + 20);
  if (magic !== 0x20b && magic !== 0x10b) throw new Error('Unsupported PE optional header');
  const dd = opt + (magic === 0x20b ? 112 : 96);
  if (dd + 8 > opt + optSize) throw new Error('Missing PE export directory');
  const exp = b.u32(dd), expSize = b.u32(dd + 4);
  const sections = Array.from({ length: b.u16(pe + 6) }, (_, i) => {
    const s = opt + optSize + i * 40;
    return { rva: b.u32(s + 12), raw: b.u32(s + 20), size: b.u32(s + 16) };
  });
  function offset(rva: number, size = 1): number {
    if (rva < b.u32(opt + 60)) { b.range(rva, size); return rva; }
    const s = sections.find(s => rva >= s.rva && rva + size <= s.rva + s.size);
    if (!s) throw new Error(`RVA 0x${rva.toString(16)} has no file bytes`);
    const at = s.raw + rva - s.rva; b.range(at, size); return at;
  }
  const symbols = new Map<string, SymbolEntry>();
  if (exp) {
    const e = offset(exp, 40), functions = b.u32(e + 20), names = b.u32(e + 24);
    const f = offset(b.u32(e + 28), functions * 4);
    const n = offset(b.u32(e + 32), names * 4), o = offset(b.u32(e + 36), names * 2);
    for (let i = 0; i < names; i++) {
      const ordinal = b.u16(o + i * 2);
      if (ordinal >= functions) throw new Error('Export ordinal out of bounds');
      const address = b.u32(f + ordinal * 4);
      const name = b.string(offset(b.u32(n + i * 4)));
      symbols.set(name, { address, offset: !address || (address >= exp && address < exp + expSize) ? null : offset(address) });
    }
  }
  return { data, symbols, machine: b.u16(pe + 4) };
}
export async function exports(path: string) { return parsePE(new Uint8Array(await Bun.file(path).arrayBuffer())); }
if (import.meta.main) {
  if (!Bun.argv[2]) throw new Error('Usage: bun windows/test/pe.ts <PE file> [export names...]');
  inspect(await exports(Bun.argv[2]), Bun.argv.slice(3));
}
