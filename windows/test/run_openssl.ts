/** Exported OpenSSL observation: deterministic semantics plus optional real TLS. */
import { Matrix, mustRun, run } from '../../test/harness';

if (process.platform !== 'win32') throw new Error('OpenSSL observation tests require Windows');
const root = `${import.meta.dir}/..`;
const build = Bun.env.FRAGMENT_TEST_BUILD ?? `${root}/build`;
const dll = Bun.env.FRAGMENT_TEST_DLL ?? `${build}/Fragment.dll`;
if (!Bun.argv.includes('--no-build')) {
  await mustRun(['cmd.exe', '/c', `${root}/build.bat`]);
  await mustRun(['cmd.exe', '/c', `${root}/test/build_test.bat`]);
}
const matrix = new Matrix([]);
const unit = await run([`${build}/openssltest.exe`]);
matrix.check('OpenSSL deterministic observer semantics', unit.rc === 0, unit.out.trim());
const mockA = `${build}/mockssl.dll`, mockB = `${build}/mockssl-${crypto.randomUUID()}.dll`;
if (!await Bun.file(mockA).exists()) throw new Error(`Missing mandatory fixture: ${mockA}`);
await Bun.write(mockB, Bun.file(mockA));
for (const mode of ['bare', 'off', 'delayed', 'swept']) {
  const capture = `${build}/openssl-mock-${crypto.randomUUID()}.jsonl`;
  const result = await run([`${build}/host_openssl_mock.exe`, dll, mockA, mockB, mode === 'off' ? 'delayed' : mode],
    { FRAGMENT_MODE: 'observe', FRAGMENT_CAPTURE_FILE: capture, ...(mode === 'off' ? { FRAGMENT_ENABLED: '0' } : {}) });
  let error: string | undefined;
  try {
    const text = await Bun.file(capture).exists() ? await Bun.file(capture).text() : '';
    if (text && !text.endsWith('\n')) throw new Error('Incomplete record');
    const rows = text ? text.trimEnd().split('\n').map(line => JSON.parse(line)) : [];
    const data = rows.filter(row => row.type === 'data' && row.backend === 'openssl');
    if (mode === 'bare' || mode === 'off') {
      if (data.length) error = 'Negative control captured bytes';
    } else {
      const groups = new Map<number, { out: Buffer[]; in: Buffer[] }>();
      for (const row of data) {
        if (row.direction !== 'in' && row.direction !== 'out') throw new Error('Invalid direction');
        const bytes = Buffer.from(row.data, 'base64');
        if (bytes.length !== row.length || row.length !== row.captured || row.truncated) throw new Error('Invalid byte count');
        let group = groups.get(row.connection);
        if (!group) { group = { out: [], in: [] }; groups.set(row.connection, group); }
        group[row.direction as 'in' | 'out'].push(bytes);
      }
      const streams = [...groups.values()].map(group =>
        `${Buffer.concat(group.out).toString('hex')}/${Buffer.concat(group.in).toString('hex')}`).sort();
      const wanted = Array.from({ length: 3 }, () => ['6100ff7a/7200ff78', '636c656172/', '6e6577/']).flat().sort();
      if (JSON.stringify(streams) !== JSON.stringify(wanted) || data.length !== 15) error = 'Streams duplicated, merged, or lost';
      if (rows.filter(row => row.type === 'backend' && row.backend === 'openssl' && row.ready).length !== 3)
        error = 'Expected three independent loaded module generations';
      if (rows.some(row => row.type === 'gap' && row.backend === 'openssl')) error = 'Unexpected gap';
    }
  } catch (caught) { error = String(caught); }
  matrix.check(`OpenSSL exported mock ${mode}: parallel libraries and real reload`, result.rc === 0 && !error,
    error || result.rc !== 0 ? `${error ?? ''} exit=${result.rc}\n${result.out}\n${capture}` : 'Exact streams, partial counts, no duplicates, lifecycle IDs');
}
const option = Bun.argv.indexOf('--libssl');
if (option >= 0 && !Bun.argv[option + 1]) throw new Error('--libssl requires an absolute DLL path');
const library = (option >= 0 ? Bun.argv[option + 1] : undefined) ??
  Bun.argv.find(argument => argument.startsWith('--libssl='))?.slice('--libssl='.length) ?? Bun.env.FRAGMENT_TEST_OPENSSL;
if (library && !await Bun.file(library).exists()) throw new Error(`Requested OpenSSL fixture is missing: ${library}`);
if (!library) {
  matrix.skip('OpenSSL real TLS integration', 'Set FRAGMENT_TEST_OPENSSL or --libssl to a matching libssl DLL');
  matrix.finish();
} else {
  const requestBody = Buffer.from([102, 114, 97, 103, 0, 255, 128, 13, 10]);
  const responseBody = Buffer.from([111, 107, 0, 254, 129, 13, 10, 33]);
  const requestBytes = Buffer.concat([Buffer.from(
    'POST /openssl/binary?source=exports HTTP/1.1\r\nHost: localhost\r\n' +
    `Content-Length: ${requestBody.length}\r\nConnection: close\r\n\r\n`), requestBody]);
  type Hit = { method: string; path: string; body: Buffer };
  type Event = { type: string; backend?: string; ready?: boolean; connection?: number;
    direction?: string; captured?: number; length?: number; data?: string; truncated?: boolean; seq: number };
  let hits: Hit[] = [];
  const server = Bun.serve({ hostname: '127.0.0.1', port: 0,
    tls: { cert: Bun.file(`${import.meta.dir}/fixtures/schannel-localhost-cert.pem`),
      key: Bun.file(`${import.meta.dir}/fixtures/schannel-localhost-key.pem`) },
    async fetch(request) {
      const url = new URL(request.url);
      hits.push({ method: request.method, path: url.pathname + url.search,
        body: Buffer.from(await request.arrayBuffer()) });
      return new Response(responseBody, { headers: { 'content-length': String(responseBody.length), connection: 'close' } });
    },
  });
  const filter = Bun.argv.find(arg => arg.startsWith('--filter='))?.slice('--filter='.length);
  function verify(rows: Event[], count: number): string | undefined {
    if (!rows.some(row => row.type === 'backend' && row.backend === 'openssl' && row.ready)) return 'No OpenSSL readiness record';
    if (rows.some(row => row.type === 'gap' && row.backend === 'openssl')) return 'Unexpected OpenSSL capture gap';
    const connections = new Map<number, { out: Buffer[]; in: Buffer[] }>();
    let previous = 0;
    for (const row of rows.filter(row => row.type === 'data' && row.backend === 'openssl')) {
      if (!row.connection || !row.data || (row.direction !== 'out' && row.direction !== 'in') || row.seq <= previous)
        return 'Invalid event identity/order';
      previous = row.seq;
      const bytes = Buffer.from(row.data, 'base64');
      if (bytes.toString('base64') !== row.data || row.captured !== bytes.length ||
          row.length !== bytes.length || row.truncated !== false) return 'Capture byte counts differ';
      let pair = connections.get(row.connection);
      if (!pair) { pair = { out: [], in: [] }; connections.set(row.connection, pair); }
      pair[row.direction].push(bytes);
    }
    if (connections.size !== count) return `Connections ${connections.size}/${count}`;
    for (const [id, streams] of connections) {
      if (!Buffer.concat(streams.out).equals(requestBytes)) return `Connection ${id}: outgoing bytes differ or duplicate`;
      const response = Buffer.concat(streams.in), split = response.indexOf('\r\n\r\n');
      if (split < 0 || response.subarray(0, 12).toString() !== 'HTTP/1.1 200' ||
          !response.subarray(split + 4).equals(responseBody)) return `Connection ${id}: incoming bytes differ or duplicate`;
    }
  }
  async function test(name: string, options: { api?: string; load?: string; off?: boolean; bare?: boolean;
      launch?: boolean; iterations?: number; threads?: number; lifetime?: string } = {}) {
    if (filter && !name.includes(filter)) return;
    const capture = `${build}/openssl-capture-${crypto.randomUUID()}.jsonl`;
    const count = (options.iterations ?? 1) * (options.threads ?? 1) * (options.lifetime === 'reload' ? 2 : 1);
    const host = [`${build}/host_openssl.exe`, dll, library!, String(server.port), options.api ?? 'legacy',
      options.bare || options.launch ? 'bare' : options.load ?? 'delayed',
      String(options.iterations ?? 1), String(options.threads ?? 1), options.lifetime ?? 'new'];
    hits = [];
    const command = options.launch ? [`${build}/fragment.exe`, '--dll', dll, '--observe', capture,
      ...(options.off ? ['--off'] : []), '--', ...host] : host;
    const result = await run(command, { FRAGMENT_MODE: 'observe', FRAGMENT_CAPTURE_FILE: capture,
      ...(options.off && !options.launch ? { FRAGMENT_ENABLED: '0' } : {}),
      ...(Bun.argv.includes('--debug') ? { FRAGMENT_LOG_LEVEL: 'debug', FRAGMENT_LOG_FILE: `${capture}.log` } : {}),
    }, 90_000);
    try {
      const text = await Bun.file(capture).exists() ? await Bun.file(capture).text() : '';
      if (text && !text.endsWith('\n')) throw new Error('Incomplete capture record');
      const rows: Event[] = text ? text.trimEnd().split('\n').map(line => JSON.parse(line)) : [];
      const error = options.bare || options.off ? rows.some(row => row.type === 'data') ? 'Negative control recorded data' : undefined
        : verify(rows, count);
      const traffic = hits.length === count && hits.every(hit => hit.method === 'POST' &&
        hit.path === '/openssl/binary?source=exports' && hit.body.equals(requestBody));
      matrix.check(name, result.rc === 0 && traffic && !error,
        result.rc !== 0 || !traffic || error ? `${error ?? ''} exit=${result.rc}, hits=${hits.length}/${count}\n${result.out.slice(-4500)}\n${capture}`
        : `${count} exact binary round trips and retry semantics preserved`);
    } catch (error) { matrix.check(name, false, `${error}\n${result.out.slice(-4500)}\n${capture}`); }
  }
  try {
    console.log(`OpenSSL fixture library: ${library}`);
    await test('bare OpenSSL negative control', { bare: true });
    await test('disabled OpenSSL observation', { off: true });
    await test('SSL_read/write, delayed libssl');
    await test('SSL_read/write, already loaded libssl', { load: 'swept' });
    await test('SSL_read_ex/write_ex accepted counts', { api: 'ex' });
    await test('OpenSSL launcher observation', { launch: true, api: 'ex' });
    await test('OpenSSL launcher --off', { launch: true, off: true });
    await test('OpenSSL SSL_clear starts a new stream ID', { api: 'ex', iterations: 3, lifetime: 'reuse' });
    await test('OpenSSL FreeLibrary/load lifecycle', { lifetime: 'reload' });
    await test('OpenSSL concurrent contexts and reuse 4 x 8', { api: 'ex', threads: 4, iterations: 8 });
  } finally { server.stop(true); matrix.finish(); }
}
