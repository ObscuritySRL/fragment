import { Matrix, mustRun, type Env } from '../../test/harness';
import { redirectCases } from '../../test/redirects';

if (process.platform !== 'win32') throw new Error('WinHTTP tests require Windows');
const root = `${import.meta.dir}/..`;
const build = Bun.env.FRAGMENT_TEST_BUILD ?? `${root}/build`;
const dll = Bun.env.FRAGMENT_TEST_DLL ?? `${build}/Fragment.dll`;
const host = `${build}/host_winhttp.exe`;
const launcher = `${build}/fragment.exe`;
if (!Bun.argv.includes('--no-build')) {
  await mustRun(['cmd.exe', '/c', `${root}/build.bat`, Bun.argv.includes('--debug') ? 'Debug' : 'Release']);
  await mustRun(['cmd.exe', '/c', `${root}/test/build_test.bat`]);
}
for (const f of [dll, host, launcher]) if (!await Bun.file(f).exists()) throw new Error(`Missing ${f}`);
const m = new Matrix();
const debugOptions: Env = Bun.argv.includes('--debug') ? { FRAGMENT_LOG_LEVEL: 'debug', FRAGMENT_LOG_CONSOLE: '1' } : {};
const debug = { FRAGMENT_PROXY: 'http://127.0.0.1:19020', ...debugOptions };
async function request(name: string, url: string, mode = '', args: string[] = [], env: Env = {},
  port = 19020, path = `/${url}`, count = 1, body = '') {
  await m.request(name, [host, dll, url, mode, ...args],
    { port, path, method: mode === 'post' ? 'POST' : 'GET', body }, { ...debug, ...env }, count);
}
try {
  await redirectCases(m.check.bind(m), (url, proxy, disabled) => ({
    cmd: [host, dll, url], env: { FRAGMENT_PROXY: proxy, FRAGMENT_ENABLED: disabled ? '0' : '1' },
  }));
  for (const url of ['http://127.0.0.1:19999/basic', 'https://example.com/secure',
    'https://example.com:8443/port', 'http://example.com:8080/port',
    'https://example.com/a/b?x=1&y=2', 'https://example.com/']) await request(url, url);
  await request('POST method and body', 'https://example.com/post', 'post', [], {}, 19020,
    '/https://example.com/post', 1, 'fragment-body=hello');
  for (const mode of ['appproxy', 'setoptproxy'])
    await request(mode, `https://example.com/${mode}`, mode, ['127.0.0.1:19999']);
  await request('already loaded WinHTTP', 'https://example.com/sweep', 'swept');
  await request('alternate proxy', 'https://example.com/alt', '', [],
    { FRAGMENT_PROXY: 'http://127.0.0.1:19021' }, 19021);
  for (const [name, mode, env] of [
    ['bare negative control', 'bare', {}], ['disabled', '', { FRAGMENT_ENABLED: '0' }],
    ['disable overrides enabled', '', { FRAGMENT_ENABLED: '1', FRAGMENT_DISABLE: '1' }],
  ] as [string, string, Env][]) await request(name, 'http://127.0.0.1:19999/control', mode, [], env, 19999, '/control');
  await request('proxy mount', 'https://example.com/mount', '', [],
    { FRAGMENT_PROXY: 'http://127.0.0.1:19020/inspect' }, 19020, '/inspect/https://example.com/mount');
  await request('unusable host preserves app proxy', 'http://example.com/inert', 'appproxy', ['127.0.0.1:19021'],
    { FRAGMENT_PROXY: 'http://:19020' }, 19021, '/inert');
  await request('session cascade cleanup', 'https://example.com/session', 'sessiononly', ['8'], {},
    19020, '/https://example.com/session', 8);
  await m.request('launcher injects passive WinHTTP host', [launcher, '--dll', dll, '--',
    host, dll, 'https://example.com/injected', 'bare'], { port: 19020, path: '/https://example.com/injected' }, debug);
  await request('concurrency 8 x 60', 'https://example.com/stress', 'stress', ['8', '60'], {},
    19020, '/https://example.com/stress', 480);
} finally { m.finish(); }

