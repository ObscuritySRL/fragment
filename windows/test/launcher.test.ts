import { test, expect } from 'bun:test';
import { run } from '../../test/harness';

const build = Bun.env.FRAGMENT_TEST_BUILD ?? `${import.meta.dir}/../build`;
test('launcher preserves empty, quoted, Unicode, and long arguments', async () => {
  const args = ['', 'a"b', 'C:\\space dir\\', 'tab\there', '\\\\"', '日本語 😀', 'x'.repeat(9000)];
  const host = `${build}/host_args.exe`;
  const bare = await run([host, ...args]);
  expect(bare.rc).toBe(0);
  expect(JSON.parse(bare.out.trim())).toEqual(args);
  const launched = await run([`${build}/fragment.exe`, '--off', '--dll', `${build}/Fragment.dll`, '--', host, ...args]);
  expect(launched.rc).toBe(0);
  const json = launched.out.split(/\r?\n/).find(line => line.startsWith('["'));
  expect(JSON.parse(json!)).toEqual(args);
});
