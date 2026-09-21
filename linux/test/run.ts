import { Matrix, mustRun, run, environment, type Env } from '../../test/harness';

if (process.platform !== 'linux') throw new Error('Linux tests require Linux');
const root = `${import.meta.dir}/..`;
const b = `${root}/build`;
const lib = `${b}/libfragment.so`;
if (!Bun.argv.includes('--no-build')) {
  await mustRun(['bash', `${root}/build.sh`]);
  await mustRun(['bash', `${root}/test/build_test.sh`]);
}
const m = new Matrix();
const config = { FRAGMENT_TEST_ORIGIN_PORT: '19999', FRAGMENT_PROXY: 'http://127.0.0.1:19020', LD_PRELOAD: lib };
const url = 'http://127.0.0.1:19999/curl';
const expected = { port: 19020, path: `/${url}` };
async function plain(name: string, cmd: string[], env: Env = {}) {
  const { rc, out } = await run(cmd, env);
  m.check(name, rc === 0, out.trim());
}
try {
  for (const exe of ['hooktest', 'decodetest32', 'decodetest64']) await plain(exe, [`${b}/${exe}`]);
  for (const exe of ['host_mock', 'host_mock_static']) await plain(exe, [`${b}/${exe}`], { LD_PRELOAD: lib });
  if (await Bun.file(`${b}/host`).exists()) {
    for (const mode of ['', 'dlopen', 'port']) await m.request(`curl ${mode || 'URL'}`, [`${b}/host`, url, mode], expected, config);
    for (const mode of ['full', 'parts']) await m.request(`URL API ${mode}`,
      [`${b}/host_urlapi`, mode, url, 'curl'], expected, config);
    await m.request('transitive curl', [`${b}/host_plugin`, `${b}/libplugin.so`, url], expected, config);
    for (const mode of ['auto', 'interpose', 'hook']) await m.request(`loader=${mode}`, [`${b}/host`, url],
      expected, { ...config, FRAGMENT_LOADER: mode });
    await m.request('alternate proxy', [`${b}/host`, url], { ...expected, port: 19021 },
      { ...config, FRAGMENT_PROXY: 'http://127.0.0.1:19021' });
    await m.request('off switch', [`${b}/host`, url], { port: 19999, path: '/curl' }, { ...config, FRAGMENT_ENABLED: '0' });
    await m.request('bare negative control', [`${b}/host`, url], { port: 19999, path: '/curl' });
    await m.request('concurrency 8 x 60', [`${b}/host_stress`, url, '8', '60'], expected, config, 480);
    const curl = Bun.which('curl');
    if (curl) {
      const base = [curl, '-sS', '-o', '/dev/null', '--max-time', '8'];
      for (const [name, args] of [
        ['connect-to', ['--connect-to', '::127.0.0.1:19999']],
        ['resolve', ['--resolve', '127.0.0.1:19020:192.0.2.1']],
        ['proxy', ['--proxy', 'http://127.0.0.1:19999']],
      ] as [string, string[]][]) await m.request(`neutralize ${name}`, [...base, ...args, url], expected, config);
      await m.request('neutralize environment proxy', [...base, url], expected,
        { ...config, http_proxy: 'http://127.0.0.1:19999' });
      await m.request('connect-to negative control', [...base, '--connect-to', '::127.0.0.1:19021', url],
        { port: 19021, path: '/curl' });
      await m.request('environment proxy negative control', [...base, url], { port: 19021, path: '/curl' },
        { http_proxy: 'http://127.0.0.1:19021' });
      const audit = { FRAGMENT_PROXY: config.FRAGMENT_PROXY, LD_AUDIT: lib, FRAGMENT_LOADER: 'audit' };
      await m.request('audit call sites', [...base, url], expected, audit);
      await m.request('audit misses captured pointer (negative control)', [`${b}/host`, url], { port: 19999, path: '/curl' }, audit);
      await m.request('launcher preload', [`${b}/fragment`, '--proxy', config.FRAGMENT_PROXY, '--', ...base, url], expected);
    } else m.skip('curl executable matrix', 'curl unavailable');
    // Never alter the machine-wide ptrace policy from a test runner.
    const policy = Bun.file('/proc/sys/kernel/yama/ptrace_scope');
    if (!await policy.exists() || (await policy.text()).trim() === '0') {
      m.hits = [];
      const child = Bun.spawn([`${b}/host`, url, 'loop:40:150'], { env: environment({ FRAGMENT_PROXY: config.FRAGMENT_PROXY }), stdout: 'ignore', stderr: 'ignore' });
      const timer = setTimeout(() => child.kill(), 30_000);
      try {
        await Bun.sleep(1000);
        const before = m.hits.slice();
        const injection = await run([`${b}/fragment`, '--pid', String(child.pid)]);
        const boundary = m.hits.length;
        const rc = await child.exited;
        const after = m.hits.slice(boundary);
        m.check('live PID injection', injection.rc === 0 && rc === 0 && before.length > 0 &&
          before.every(h => h.port === 19999) && after.length > 0 && after.every(h => h.port === 19020 && h.path === expected.path), injection.out);
      } finally { clearTimeout(timer); if (child.exitCode === null) { child.kill(); await child.exited; } }
    } else m.skip('live PID injection', 'ptrace policy restricts attachment');
  } else m.skip('real curl matrix', 'install libcurl development files and rebuild');
  for (const [arch, cc, qemu, prefix] of [
    ['x64', 'x86_64-linux-gnu-gcc', 'qemu-x86_64', '/usr/x86_64-linux-gnu'],
    ['i386', 'i686-linux-gnu-gcc', 'qemu-i386', '/usr/i686-linux-gnu'],
    ['armv7', 'arm-linux-gnueabihf-gcc', 'qemu-arm', '/usr/arm-linux-gnueabihf'],
  ]) {
    if (!Bun.which(cc) || !Bun.which(qemu)) { m.skip(arch, 'cross compiler/emulator unavailable'); continue; }
    await mustRun(['bash', `${root}/test/build_test.sh`, arch]);
    for (const exe of ['hooktest', 'host_mock', 'host_mock_static']) await plain(`${arch} ${exe}`,
      [qemu, '-L', prefix, ...(exe === 'hooktest' ? [] : ['-E', `LD_PRELOAD=${b}/${arch}/libfragment.so`]), `${b}/${arch}/${exe}`]);
  }
} finally { m.finish(); }

