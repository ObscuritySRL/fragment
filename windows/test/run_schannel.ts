/** Native SSPI/TLS observations, using only a loopback TLS fixture and Bun. */
import { Matrix, mustRun, run, type Env } from '../../test/harness';

if (process.platform !== 'win32') throw new Error('Schannel tests require Windows');
const root = `${import.meta.dir}/..`;
const build = Bun.env.FRAGMENT_TEST_BUILD ?? `${root}/build`;
const dll = Bun.env.FRAGMENT_TEST_DLL ?? `${build}/Fragment.dll`;
const host = `${build}/host_schannel.exe`;
const launcher = `${build}/fragment.exe`;
if (!Bun.argv.includes('--no-build')) {
  await mustRun(['cmd.exe', '/c', `${root}/build.bat`, Bun.argv.includes('--debug') ? 'Debug' : 'Release']);
  await mustRun(['cmd.exe', '/c', `${root}/test/build_test.bat`]);
}
for (const file of [dll, host, launcher, `${build}/schanneltest.exe`])
  if (!await Bun.file(file).exists()) throw new Error(`Missing ${file}`);

const matrix = new Matrix([]);
const requestBody = Buffer.from([102, 114, 97, 103, 0, 255, 128, 13, 10]);
const responseBody = Buffer.from([111, 107, 0, 254, 129, 13, 10, 33]);
const requestBytes = Buffer.concat([Buffer.from(
  'POST /schannel/binary?source=sspi HTTP/1.1\r\nHost: localhost\r\n' +
  `Content-Length: ${requestBody.length}\r\nConnection: close\r\n\r\n`), requestBody]);
type Hit = { method: string; path: string; body: Buffer };
type Event = {
  v: number; type: string; session: string; seq: number; time: number; pid: number; tid: number;
  backend?: string; ready?: boolean; connection?: number; direction?: string;
  length?: number; captured?: number; truncated?: boolean; data?: string;
};
let hits: Hit[] = [];
const server = Bun.serve({ hostname: '127.0.0.1', port: 0,
  tls: {
    cert: Bun.file(`${import.meta.dir}/fixtures/schannel-localhost-cert.pem`),
    key: Bun.file(`${import.meta.dir}/fixtures/schannel-localhost-key.pem`),
  },
  async fetch(request) {
    const url = new URL(request.url);
    hits.push({ method: request.method, path: url.pathname + url.search,
      body: Buffer.from(await request.arrayBuffer()) });
    return new Response(responseBody, { headers: { 'content-length': String(responseBody.length), connection: 'close' } });
  },
});
const invalidTls = Bun.listen({ hostname: '127.0.0.1', port: 0,
  socket: { data(socket) { socket.end('This is not a TLS server.\r\n'); } },
});
const capturePath = () => `${build}/schannel-capture-${crypto.randomUUID()}.jsonl`;
async function events(path: string): Promise<Event[]> {
  if (!await Bun.file(path).exists()) return [];
  const text = await Bun.file(path).text();
  if (!text) return [];
  if (!text.endsWith('\n')) throw new Error('Capture ends with a partial JSONL record');
  return text.trimEnd().split('\n').map(line => JSON.parse(line));
}
const debug: Env = Bun.argv.includes('--debug') ? { FRAGMENT_LOG_LEVEL: 'debug', FRAGMENT_LOG_CONSOLE: '1' } : {};
const filter = Bun.argv.find(argument => argument.startsWith('--filter='))?.slice('--filter='.length);
function captureEnvironment(path: string): Env {
  return { FRAGMENT_MODE: 'observe', FRAGMENT_CAPTURE_FILE: path, ...debug };
}
function verifyCapture(rows: Event[], count: number): string | undefined {
  const payloads = rows.filter(row => row.type === 'data' && row.backend === 'schannel');
  if (!rows.some(row => row.type === 'session')) return 'Missing capture session metadata';
  if (!rows.some(row => row.type === 'backend' && row.backend === 'schannel' && row.ready))
    return 'Missing Schannel backend readiness metadata';
  if (!payloads.length) return 'No plaintext captured';
  const connections = new Map<number, { out: Buffer[]; in: Buffer[] }>();
  let previous = 0;
  for (const row of payloads) {
    if (row.v !== 1 || row.backend !== 'schannel' || !row.connection || !row.session ||
        !row.pid || !row.tid || !row.time || !row.seq || row.seq <= previous)
      return `Invalid event identity/order: ${JSON.stringify(row)}`;
    previous = row.seq;
    if (row.direction !== 'out' && row.direction !== 'in') return 'Invalid direction';
    if (typeof row.data !== 'string') return 'Missing base64 payload';
    const bytes = Buffer.from(row.data, 'base64');
    if (bytes.toString('base64') !== row.data || row.captured !== bytes.length ||
        row.length !== bytes.length || row.truncated !== false) return 'Byte count or encoding mismatch';
    let connection = connections.get(row.connection);
    if (!connection) { connection = { out: [], in: [] }; connections.set(row.connection, connection); }
    connection[row.direction].push(bytes);
  }
  if (connections.size !== count) return `Expected ${count} distinct contexts, got ${connections.size}`;
  for (const [id, streams] of connections) {
    if (!Buffer.concat(streams.out).equals(requestBytes)) return `Context ${id}: outgoing bytes differ`;
    const response = Buffer.concat(streams.in);
    const separator = response.indexOf('\r\n\r\n');
    if (separator < 0 || !response.subarray(0, 12).equals(Buffer.from('HTTP/1.1 200')) ||
        !response.subarray(separator + 4).equals(responseBody)) return `Context ${id}: incoming bytes differ`;
  }
  return undefined;
}
async function test(name: string, options: {
  api?: string; load?: string; launch?: boolean; off?: boolean; capture?: boolean;
  threads?: number; iterations?: number; failedHandshake?: boolean; probes?: boolean; extra?: Env; unicode?: boolean;
} = {}) {
  if (filter && !name.includes(filter)) return;
  const path = options.unicode ? `${build}/schannel-ü-測試-${crypto.randomUUID()}.jsonl` : capturePath();
  const count = (options.threads ?? 1) * (options.iterations ?? 1);
  const command = [host, dll, String(options.failedHandshake ? invalidTls.port : server.port),
    options.api ?? 'exports', options.launch ? 'bare' : options.load ?? 'delayed',
    String(options.threads ?? 1), String(options.iterations ?? 1), ...(options.probes ? ['probes'] : [])];
  const env = { ...captureEnvironment(path), ...options.extra };
  if (options.off && !options.launch) env.FRAGMENT_ENABLED = '0';
  hits = [];
  const result = await run(options.launch ? [launcher, '--dll', dll, '--observe', path,
    ...(options.off ? ['--off'] : []), '--', ...command] : command, env, 90_000);
  try {
    const rows = await events(path);
    const expectedCapture = options.capture ?? !options.off;
    const error = expectedCapture ? verifyCapture(rows, count) :
      rows.some(row => row.type === 'data') ? 'Negative control captured plaintext' : undefined;
    const expectedHits = options.failedHandshake ? 0 : count;
    const trafficOk = hits.length === expectedHits && hits.every(hit => hit.method === 'POST' &&
      hit.path === '/schannel/binary?source=sspi' && hit.body.equals(requestBody));
    const exitOk = options.failedHandshake ? result.rc !== 0 : result.rc === 0;
    matrix.check(name, !error && trafficOk && exitOk,
      error || !trafficOk || !exitOk ?
        `${error ?? ''} exit=${result.rc}; requests=${hits.length}/${expectedHits}\n${result.out.slice(-4000)}\nCapture: ${path}` :
        `${expectedHits} exact binary round trip(s), ${rows.filter(row => row.type === 'data').length} data records`);
  } catch (error) { matrix.check(name, false, `${error}\n${result.out.slice(-4000)}\nCapture: ${path}`); }
}

async function testModeIsolation() {
  const name = 'observation leaves WinHTTP destinations unchanged';
  if (filter && !name.includes(filter)) return;
  const winhttp = `${build}/host_winhttp.exe`;
  if (!await Bun.file(winhttp).exists()) { matrix.skip(name, 'host_winhttp.exe unavailable'); return; }
  const observed: Hit[] = [];
  let proxyHits = 0;
  const origin = Bun.serve({ hostname: '127.0.0.1', port: 0, async fetch(request) {
    observed.push({ method: request.method, path: new URL(request.url).pathname,
      body: Buffer.from(await request.arrayBuffer()) });
    return new Response('origin');
  } });
  const proxy = Bun.serve({ hostname: '127.0.0.1', port: 0,
    fetch() { ++proxyHits; return new Response('unexpected redirection'); } });
  try {
    const path = capturePath();
    const result = await run([winhttp, dll, `http://127.0.0.1:${origin.port}/unchanged`, 'post'], {
      ...captureEnvironment(path), FRAGMENT_PROXY: `http://127.0.0.1:${proxy.port}`,
    });
    const rows = await events(path);
    matrix.check(name, result.rc === 0 && proxyHits === 0 && observed.length === 1 &&
      observed[0]!.method === 'POST' && observed[0]!.path === '/unchanged' &&
      observed[0]!.body.toString() === 'fragment-body=hello' &&
      !rows.some(row => row.type === 'data'),
      `exit=${result.rc}, origin requests=${observed.length}, proxy requests=${proxyHits}`);
  } catch (error) { matrix.check(name, false, String(error)); }
  finally { origin.stop(true); proxy.stop(true); }
}

async function testConfigurationFailures() {
  const existing = capturePath();
  const sentinel = 'Existing capture must remain unchanged.\n';
  await Bun.write(existing, sentinel);
  const missingParent = `${build}/missing-${crypto.randomUUID()}/capture.jsonl`;
  for (const entry of [
    { name: 'capture refuses existing output without overwriting', path: existing, launch: true,
      env: captureEnvironment(existing), preserve: true },
    { name: 'capture fails for a missing output directory', path: missingParent, launch: true,
      env: captureEnvironment(missingParent), preserve: false },
    { name: 'observe without a capture path fails DLL load', path: '', launch: false,
      env: { FRAGMENT_MODE: 'observe', ...debug }, preserve: false },
    { name: 'unknown FRAGMENT_MODE fails DLL load', path: '', launch: false,
      env: { FRAGMENT_MODE: 'unsupported-mode', ...debug }, preserve: false },
  ]) {
    if (filter && !entry.name.includes(filter)) continue;
    hits = [];
    const command = [host, dll, String(server.port), 'exports', entry.launch ? 'bare' : 'delayed'];
    const result = await run(entry.launch ? [launcher, '--dll', dll, '--observe', entry.path, '--', ...command] :
      command, entry.env);
    const preserved = !entry.preserve || await Bun.file(existing).text() === sentinel;
    matrix.check(entry.name, result.rc !== 0 && hits.length === 0 && preserved,
      `exit=${result.rc}, requests=${hits.length}, existing file preserved=${preserved}`);
  }
}

try {
  const unit = await run([`${build}/schanneltest.exe`]);
  matrix.check('Schannel deterministic observer semantics', unit.rc === 0, unit.out.trim());
  await test('bare Schannel negative control', { load: 'bare', capture: false });
  await test('bare unsuccessful message probes preserve TLS', { load: 'bare', capture: false, probes: true });
  await test('disabled observation negative control', { off: true, capture: false });
  await test('SSPI exports, delayed provider', {});
  await test('SSPI exports, existing provider', { load: 'swept' });
  await test('cached InitSecurityInterfaceA message pointers', { api: 'table-a', load: 'swept' });
  await test('cached InitSecurityInterfaceW message pointers', { api: 'table-w', load: 'swept' });
  await test('InitSecurityInterfaceA after observation starts', { api: 'table-a' });
  await test('InitSecurityInterfaceW after observation starts', { api: 'table-w' });
  await test('launcher observes native Schannel', { launch: true });
  await test('launcher preserves Unicode capture path', { launch: true, unicode: true });
  await test('launcher --off overrides --observe', { launch: true, off: true, capture: false });
  await test('failed TLS handshake emits no plaintext', { failedHandshake: true, capture: false });
  await test('failed encryption and incomplete decryption emit no plaintext', { probes: true });
  await test('observation preserves application proxy environment', {
    extra: { HTTP_PROXY: 'http://127.0.0.1:9', FRAGMENT_TEST_EXPECT_PROXY: 'http://127.0.0.1:9' },
  });
  await testModeIsolation();
  await testConfigurationFailures();
  await test('concurrent contexts and handle reuse: 4 x 8', { api: 'table-w', load: 'swept', threads: 4, iterations: 8 });
} finally {
  server.stop(true);
  invalidTls.stop(true);
  matrix.finish();
}
