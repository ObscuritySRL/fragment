import { Binary, inspect, type Image, type SymbolEntry } from '../../test/binary';
export function parseELF(data: Uint8Array): Image {
  const b = new Binary(data, data[5] === 1);
  if (data[0] !== 0x7f || data[1] !== 69 || data[2] !== 76 || data[3] !== 70 || data[4] !== 2 || ![1, 2].includes(data[5]))
    throw new Error('Expected ELF64 (little or big endian)');
  const start = b.u64(40), stride = b.u16(58), count = b.u16(60);
  if (stride < 64) throw new Error('Invalid ELF section entry size');
  b.range(start, stride * count);
  const sections = Array.from({ length: count }, (_, i) => {
    const s = start + i * stride;
    return { type: b.u32(s + 4), address: b.u64(s + 16), offset: b.u64(s + 24),
      size: b.u64(s + 32), link: b.u32(s + 40), stride: b.u64(s + 56) };
  });
  const symbols = new Map<string, SymbolEntry>();
  for (const section of sections) {
    if (![2, 11].includes(section.type)) continue;
    if (section.stride < 24 || section.size % section.stride) throw new Error('Invalid symbol stride');
    const strings = sections[section.link];
    if (!strings) throw new Error('Missing string table');
    b.range(strings.offset, strings.size); b.range(section.offset, section.size);
    for (let p = section.offset; p < section.offset + section.size; p += section.stride) {
      const nameIndex = b.u32(p), index = b.u16(p + 6), address = b.u64(p + 8);
      if (!nameIndex || !index) continue;
      const name = b.string(strings.offset + nameIndex, strings.offset + strings.size).split('@')[0];
      const owner = sections[index];
      let offset: number | null = null;
      if (owner && owner.type !== 8 && address >= owner.address && address - owner.address < owner.size) {
        offset = owner.offset + address - owner.address; b.range(offset, 1);
      }
      if (!symbols.has(name)) symbols.set(name, { address, offset });
    }
  }
  return { data, symbols, machine: b.u16(18) };
}
export async function symbols(path: string) { return parseELF(new Uint8Array(await Bun.file(path).arrayBuffer())); }
if (import.meta.main) {
  if (!Bun.argv[2]) throw new Error('Usage: bun linux/test/elf.ts <ELF file> [symbol names...]');
  inspect(await symbols(Bun.argv[2]), Bun.argv.slice(3));
}
