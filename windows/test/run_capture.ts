import { Matrix, run } from '../../test/harness';
import { parseCapture, type DataEvent } from '../../tools/observe';

if (process.platform !== 'win32') throw new Error('Native capture sink tests require Windows');
const build = Bun.env.FRAGMENT_TEST_BUILD ?? `${import.meta.dir}/../build`;
const host = `${build}/capturetest.exe`;
if (!await Bun.file(host).exists()) throw new Error('Build native fixtures with windows/test/build_test.bat first');
const matrix = new Matrix([]);
const path = `${build}/capture-sink-${crypto.randomUUID()}.jsonl`;
try {
  const result = await run([host, path]);
  const rows = parseCapture(await Bun.file(path).text());
  const data = rows.filter((r): r is DataEvent => r.type === 'data');
  matrix.check('sink binary encoding, bounds, concurrent whole records and write failure', result.rc === 0 &&
    rows.length === 85 && data.length === 82 &&
    Buffer.from(data[0]!.data, 'base64').equals(Buffer.from([0, 255, 128, 34, 92, 10])) &&
    data[1]!.truncated && data[1]!.captured === 1024 * 1024 && data[1]!.length === 1024 * 1024 + 17 &&
    Buffer.from(data[1]!.data, 'base64').every(b => b === 0xa5) &&
    new Set(data.slice(2).map(r => r.connection)).size === 4 &&
    data.slice(2).every(r => r.captured === 3 && r.direction === 'in'), result.out.trim());
  const before = await Bun.file(path).text();
  const repeated = await run([host, path]);
  matrix.check('sink never overwrites existing captures', repeated.rc === 7 && await Bun.file(path).text() === before);
  const missing = await run([host, `${build}/missing-${crypto.randomUUID()}/capture.jsonl`]);
  matrix.check('unwritable path fails explicitly', missing.rc === 7 && missing.out.includes('cannot create output'));
} finally { matrix.finish(); }
