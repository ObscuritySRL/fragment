import { test, expect } from 'bun:test';
import { Binary } from './binary';
import { parsePE } from '../windows/test/pe';
import { parseELF } from '../linux/test/elf';
import { matches, parseTable } from './signatures';

test('malformed binaries and unsafe offsets are rejected', () => {
  for (const data of [new Uint8Array(), new Uint8Array(64), Uint8Array.of(0x4d, 0x5a)]) {
    expect(() => parsePE(data)).toThrow();
    expect(() => parseELF(data)).toThrow();
  }
  const b = new Binary(new Uint8Array(8).fill(255));
  expect(() => b.u64(0)).toThrow();
  expect(() => b.string(0)).toThrow();
  expect(() => b.u32(-1)).toThrow();
  expect(() => b.u32(6)).toThrow();
});
test('masked signatures reject short inputs and malformed tables', () => {
  const [sig] = parseTable(String.raw`kSigs[] = {{ "\x55\x00\x90", "x?x" }};`, 'kSigs');
  expect(matches(Uint8Array.of(0x55, 0xfe, 0x90), sig)).toBe(true);
  expect(matches(Uint8Array.of(0x55, 0xfe), sig)).toBe(false);
  expect(matches(Uint8Array.of(0x54, 0xfe, 0x90), sig)).toBe(false);
  expect(() => parseTable(String.raw`kSigs[] = {{ "\x55", "xx" }};`, 'kSigs')).toThrow();
});
test('every source signature has matching pattern and mask lengths', async () => {
  for (const platform of ['windows', 'linux']) {
    const source = await Bun.file(`${import.meta.dir}/../${platform}/main.c`).text();
    for (const name of ['kSetoptSigs', 'kUrlSetSigs']) {
      const blocks = source.split(`${name}[]`).slice(1);
      expect(blocks.length).toBeGreaterThan(0);
      for (const block of blocks) expect(parseTable(`${name}[]${block}`, name).length).toBeGreaterThan(0);
    }
  }
});

test('Clang setopt signatures distinguish the observed curl 8.22 false match', async () => {
  const source = await Bun.file(`${import.meta.dir}/../windows/main.c`).text();
  const sigs = parseTable(source, 'kSetoptSigs');
  const fromHex = (s: string) => Uint8Array.from(s.match(/../g)!, b => parseInt(b, 16));
  const real822 = fromHex('f30f1efa555657534883ec28488d6c24204c8945404c894d48b82b0000004885c90f84a10000008139addbdec00f8595');
  const real820 = fromHex('f30f1efa5556574883ec30488d6c24304c8945304c894d38b82b0000004885c9742e89d64c8d45304c8945f84889cf');
  expect(sigs.filter(s => matches(real822, s))).toHaveLength(1);
  expect(sigs.filter(s => matches(real820, s))).toHaveLength(1);
  // This generic prefix was accepted by the old signature with no evidence of
  // which API followed it. Neither of the new exact bodies may accept it.
  const generic = fromHex('f30f1efa5556574883ec30488d6c24304c8945304c894d38b82b0000004885c9');
  expect(sigs.some(s => matches(generic, s))).toBe(false);
});
