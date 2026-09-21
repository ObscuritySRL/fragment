/** Bounds-checked file-image readers for the offline inspection tools. */
export class Binary {
  view: DataView;
  constructor(public bytes: Uint8Array, public little = true) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  range(at: number, size: number) {
    if (!Number.isSafeInteger(at) || !Number.isSafeInteger(size) || at < 0 || size < 0 || at + size > this.bytes.length)
      throw new Error(`Invalid file range ${at}+${size}/${this.bytes.length}`);
  }
  u16(at: number) { this.range(at, 2); return this.view.getUint16(at, this.little); }
  u32(at: number) { this.range(at, 4); return this.view.getUint32(at, this.little); }
  u64(at: number) {
    this.range(at, 8); const n = Number(this.view.getBigUint64(at, this.little));
    if (!Number.isSafeInteger(n)) throw new Error('64-bit value exceeds JS safe integer range');
    return n;
  }
  string(at: number, end = this.bytes.length) {
    this.range(at, end - at);
    const nul = this.bytes.indexOf(0, at);
    if (nul < at || nul >= end) throw new Error('Unterminated binary string');
    return new TextDecoder('latin1').decode(this.bytes.subarray(at, nul));
  }
}
export type SymbolEntry = { address: number; offset: number | null };
export type Image = { data: Uint8Array; symbols: Map<string, SymbolEntry>; machine: number };
export function hex(bytes: Uint8Array) { return [...bytes].map(b => b.toString(16).padStart(2, '0')).join(''); }
export function inspect(image: Image, wanted: string[]) {
  for (const name of wanted.length ? wanted : ['curl_easy_setopt']) {
    const entry = image.symbols.get(name.split('@')[0]);
    console.log(`${name}: ${!entry ? 'NOT DEFINED' : `0x${entry.address.toString(16)} ${entry.offset === null ? '(no file bytes / forwarded export)' : hex(image.data.subarray(entry.offset, entry.offset + 48))}`}`);
  }
}
