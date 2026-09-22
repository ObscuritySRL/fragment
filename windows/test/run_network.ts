/** Raw TCP/UDP observations; local fixture sockets only, no external traffic. */
import { Matrix, mustRun, run, type Env } from '../../test/harness';
import { parseCapture } from '../../tools/observe';

if (process.platform !== 'win32') throw new Error('Winsock tests require Windows');
const root = `${import.meta.dir}/..`;
const build = Bun.env.FRAGMENT_TEST_BUILD ?? `${root}/build`;
const dll = Bun.env.FRAGMENT_TEST_DLL ?? `${build}/Fragment.dll`;
const host = `${build}/host_network.exe`;
const launcher = `${build}/fragment.exe`;
const stateTest = `${build}/networktest.exe`;
if (!Bun.argv.includes('--no-build')) {
  await mustRun(['cmd.exe', '/c', `${root}/build.bat`]);
  await mustRun(['cmd.exe', '/c', `${root}/test/build_test.bat`]);
}
for (const file of [dll, host, launcher, stateTest]) if (!await Bun.file(file).exists()) throw new Error(`Missing ${file}`);
const stateResult = await mustRun([stateTest]);
console.log(`[PASS] Winsock observer state tests: ${stateResult.out.trim()}`);
const matrix = new Matrix([]);
const request = Buffer.from([102, 114, 97, 103, 0, 255, 128, 13, 10]);
const response = Buffer.from([111, 107, 0, 254, 129, 13, 10, 33]);
const filter = Bun.argv.find(argument => argument.startsWith('--filter='))?.slice(9);
let hits: { transport: string; data: Buffer }[] = [];

async function servers(hostname: string) {
  const tcp = Bun.listen<{ bytes: Buffer }>({ hostname, port: 0,
    socket: {
      open(socket) { socket.data = { bytes: Buffer.alloc(0) }; },
      data(socket, bytes) {
        socket.data.bytes = Buffer.concat([socket.data.bytes, Buffer.from(bytes)]);
        if (socket.data.bytes.length >= request.length) {
          hits.push({ transport: 'tcp', data: socket.data.bytes });
          socket.end(response);
        }
      },
    },
  });
  try {
    const udp = await Bun.udpSocket({ hostname, port: 0,
      socket: { data(socket, bytes, port, address) {
        hits.push({ transport: 'udp', data: Buffer.from(bytes) });
        socket.send(response, port, address);
      } },
    });
    return { tcp, udp, close() { tcp.stop(true); udp.close(); } };
  } catch (error) { tcp.stop(true); throw error; }
}
const ipv4 = await servers('127.0.0.1');
let ipv6: Awaited<ReturnType<typeof servers>> | undefined;
try { ipv6 = await servers('::1'); }
catch (error) { matrix.skip('IPv6 fixtures', `IPv6 loopback unavailable: ${error}`); }

type Network = {
  connection: number; event: string; transport: string; local: string; remote: string;
  bytes: number; status: string; error: number;
};
async function test(name: string, mode = 'sync', options: {
  raw?: boolean; off?: boolean; bare?: boolean; launch?: boolean; iterations?: number;
} = {}) {
  if (filter && !name.includes(filter)) return;
  if (mode === 'ipv6' && !ipv6) return;
  const server = mode === 'ipv6' ? ipv6! : ipv4;
  const path = `${build}/network-capture-${crypto.randomUUID()}.jsonl`;
  const environment: Env = { FRAGMENT_MODE: 'observe', FRAGMENT_CAPTURE_FILE: path,
    ...(options.raw ? { FRAGMENT_SOCKET_DATA: '1' } : {}),
    ...(options.off ? { FRAGMENT_ENABLED: '0' } : {}),
    ...(Bun.argv.includes('--debug') ? { FRAGMENT_LOG_LEVEL: 'debug' } : {}) };
  const command = [host, dll, String(server.tcp.port), String(server.udp.port), mode,
    options.bare || options.launch ? 'bare' : 'load', String(options.iterations ?? 1)];
  hits = [];
  const result = await run(options.launch ? [launcher, '--dll', dll, '--observe', path,
    ...(options.raw ? ['--socket-data'] : []), ...(options.off ? ['--off'] : []), '--', ...command] : command,
    environment, 60_000);
  try {
    const rows = await Bun.file(path).exists() ? parseCapture(await Bun.file(path).text()) : [];
    const events = rows.filter(row => row.type === 'network') as (Network & { type: 'network' })[];
    const data = rows.filter(row => row.type === 'data');
    const negative = options.off || options.bare;
    const count = mode === 'failure' ? 0 : options.iterations ?? 1;
    let error = result.rc ? `fixture exit=${result.rc}` : '';
    if (!error && (hits.length !== count * 2 || hits.some(hit => !hit.data.equals(request))))
      error = `Unexpected origin traffic: ${hits.length}/${count * 2} requests`;
    if (!error && negative && events.length) error = 'Negative control emitted socket activity';
    if (!error && !negative) {
      if (!rows.some(row => row.type === 'backend' && row.backend === 'winsock' && row.ready))
        error = 'Missing backend activation';
      else if (!events.length) error = 'Missing socket events';
      else if (mode === 'failure') {
        if (!events.some(row => row.event === 'recv' && row.status === 'failed' && row.error === 10038 && row.bytes === 0))
          error = 'Missing failed INVALID_SOCKET receive';
        if (!events.some(row => row.event === 'recv' && row.status === 'would-block' && row.error === 10035 && row.bytes === 0))
          error = 'Would-block call was lost or mislabeled';
      } else {
        const sockets = new Map<number, Network[]>();
        for (const row of events) {
          const records = sockets.get(row.connection) ?? [];
          records.push(row); sockets.set(row.connection, records);
        }
        if (sockets.size !== count * 2 || sockets.has(0)) error = `Expected ${count * 2} distinct socket lifetimes, got ${sockets.size}`;
        for (const [id, activity] of sockets) {
          if (error) break;
          const transport = activity[0].transport;
          const remotePort = transport === 'tcp' ? server.tcp.port : server.udp.port;
          if (!['tcp', 'udp'].includes(transport) || !activity.every(row => row.transport === transport))
            error = `Socket ${id}: missing/mixed transport`;
          if (!activity.some(row => row.remote.endsWith(`:${remotePort}`)) || activity.some(row => !row.local))
            error = `Socket ${id}: missing numeric endpoint`;
          if (mode === 'ipv6' && activity.some(row => !row.local.startsWith('['))) error = 'IPv6 endpoint formatting failed';
          if (activity.filter(row => row.event === 'closesocket' && row.status === 'completed').length !== 1)
            error = `Socket ${id}: close/lifetime event missing`;
          const outbound = activity.filter(row => /send/i.test(row.event));
          const inbound = activity.filter(row => /recv/i.test(row.event));
          const sum = (records: Network[]) => records.reduce((amount, row) => amount + row.bytes, 0);
          if (mode === 'async-send') {
            if (outbound.length !== 1 || outbound.some(row => !['pending', 'completed-unmeasured'].includes(row.status)) || sum(outbound))
              error = 'Overlapped send incorrectly counted bytes';
          } else if (sum(outbound) !== request.length) error = `Socket ${id}: duplicate or incorrect send count`;
          if (mode === 'pending') {
            if (inbound.length !== 1 || inbound[0].status !== 'pending' || inbound[0].error !== 997 || sum(inbound))
              error = 'Pending receive incorrectly reported completion/bytes';
          } else if (sum(inbound) !== response.length) error = `Socket ${id}: duplicate or incorrect receive count`;
          if (options.raw) {
            for (const direction of ['out', 'in'] as const) {
              const chunks = data.filter(row => row.connection === id && row.direction === direction);
              const bytes = Buffer.concat(chunks.map(row => Buffer.from(row.data, 'base64')));
              const omitted = (direction === 'in' && mode === 'pending') || (direction === 'out' && mode === 'async-send');
              if (omitted ? chunks.length !== 0 : !bytes.equals(direction === 'out' ? request : response))
                error = `Socket ${id}: optional raw ${direction} bytes differ`;
              if (omitted && !rows.some(row => row.type === 'gap' && row.connection === id && row.direction === direction))
                error = `Socket ${id}: asynchronous raw omission lacks gap event`;
              if (chunks.some(row => row.backend !== 'winsock')) error = 'Raw socket bytes mislabeled as TLS plaintext';
            }
          }
        }
      }
    }
    if (!error && (!options.raw || negative || mode === 'failure') && data.length) error = 'Unexpected payload capture';
    matrix.check(name, !error, error ? `${error}\n${result.out.slice(-2500)}\nCapture: ${path}` :
      `${count * 2} untouched TCP/UDP exchanges; ${events.length} API events; ${data.length} raw chunks`);
  } catch (error) { matrix.check(name, false, `${error}\n${result.out.slice(-2500)}\nCapture: ${path}`); }
}

try {
  await test('bare network negative control', 'sync', { bare: true, raw: true });
  await test('disabled network negative control', 'sync', { off: true, raw: true });
  await test('TCP and UDP synchronous metadata');
  await test('Winsock scatter/gather synchronous metadata', 'wsa');
  await test('overlapped receive pending is not a completed transfer', 'pending');
  await test('overlapped send counts remain explicitly unmeasured', 'async-send');
  await test('IPv6 TCP and UDP endpoints', 'ipv6');
  await test('failed calls and would-block preserve Winsock errors', 'failure');
  await test('socket lifetimes remain distinct after reuse', 'wsa', { iterations: 12 });
  await test('optional raw TCP and UDP preserve binary bytes', 'sync', { raw: true });
  await test('optional raw scatter/gather preserve binary bytes', 'wsa', { raw: true });
  await test('optional raw asynchronous receive omissions are explicit', 'pending', { raw: true });
  await test('optional raw asynchronous send omissions are explicit', 'async-send', { raw: true });
  await test('launcher enables network observation', 'sync', { launch: true });
  await test('launcher enables optional raw socket bytes', 'sync', { launch: true, raw: true });
} finally { ipv4.close(); ipv6?.close(); matrix.finish(); }
