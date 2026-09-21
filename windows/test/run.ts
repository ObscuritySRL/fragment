import { Matrix, mustRun, run, type Env } from '../../test/harness';

if (process.platform !== 'win32') throw new Error('Use linux/test/run.ts on Linux');
const root = `${import.meta.dir}/..`;
const build = `${root}/build`;
const dll = `${build}/Fragment.dll`;
const corpus = `${import.meta.dir}/curl`;
if (!Bun.argv.includes('--no-build')) {
  await mustRun(['cmd.exe', '/c', `${root}/build.bat`]);
  await mustRun(['cmd.exe', '/c', `${root}/test/build_test.bat`]);
}
const m = new Matrix();
const config = { FRAGMENT_TEST_ORIGIN_PORT: '19999', FRAGMENT_PROXY: 'http://127.0.0.1:19020' };
const url = 'http://127.0.0.1:19999/curl';
const expected = { port: 19020, path: `/${url}` };
async function hostCase(name: string, lib: string, args: string[] = [], env: Env = {}, proxy = true) {
  await m.request(name, [`${build}/host.exe`, dll, lib, url, ...args],
    proxy ? expected : { port: 19999, path: '/curl' }, { ...config, ...env });
}
try {
  for (const [name, cmd] of [
    ['hook engine', [`${build}/hooktest.exe`]],
    ['mock curl', [`${build}/host_mock.exe`, dll, `${build}/mockcurl.dll`]],
  ] as [string, string[]][]) {
    const { rc, out } = await run(cmd);
    m.check(name, rc === 0, out.trim());
  }
  const libs = new Set<string>();
  for await (const path of new Bun.Glob('libcurl*.dll').scan({ cwd: corpus, absolute: true })) libs.add(path);
  for (let i = 2; i < Bun.argv.length; i++) if (Bun.argv[i] === '--libcurl') libs.add(Bun.argv[++i]);
  if (!libs.size) m.skip('real shared curl matrix', 'stage test/curl/libcurl*.dll or supply --libcurl <path>');
  for (const lib of libs) {
    console.log(`Testing actual library: ${lib}`);
    await hostCase('export URL rewrite', lib);
    await hostCase('bare negative control', lib, ['--noinject'], {}, false);
    await hostCase('off switch', lib, [], { FRAGMENT_ENABLED: '0' }, false);
    await hostCase('PORT neutralization', lib, ['port']);
    await hostCase('LoadLibraryEx', lib, ['ldrex']);
    for (const mode of ['auto', 'notify', 'ldrloaddll', 'loadlibrary'])
      await hostCase(`loader=${mode}`, lib, [], { FRAGMENT_LOADER: mode });
    await hostCase('legacy loader misses LoadLibraryEx (negative control)', lib,
      ['ldrex'], { FRAGMENT_LOADER: 'loadlibrary' }, false);
    await m.request('alternate proxy', [`${build}/host.exe`, dll, lib, url],
      { ...expected, port: 19021 }, { FRAGMENT_PROXY: 'http://127.0.0.1:19021' });
    for (const mode of ['full', 'parts']) await m.request(`URL API ${mode}`,
      [`${build}/host_urlapi.exe`, dll, lib, mode, url, 'curl'], expected, config);
    await m.request('concurrency 8 x 60', [`${build}/host_stress.exe`, dll, lib, url, '8', '60'], expected, config, 480);
    await m.request('launcher injects passive curl host', [`${build}/fragment.exe`, '--dll', dll, '--',
      `${build}/host.exe`, dll, lib, url, '--noinject'], expected, config);
  }
  const executables = [...new Bun.Glob('curl*.exe').scanSync({ cwd: corpus, absolute: true })];
  for (let i = 2; i < Bun.argv.length; i++) if (Bun.argv[i] === '--curl') executables.push(Bun.argv[++i]);
  if (!executables.length) m.skip('static curl matrix', 'stage test/curl/curl*.exe or supply --curl <path>');
  for (const curl of executables) {
    console.log(`Testing actual executable: ${curl}`);
    const base = [curl, '-sS', '-o', 'NUL', '--max-time', '8'];
    for (const [name, args] of [
      ['basic', []], ['proxy', ['--proxy', 'http://127.0.0.1:19999']],
      ['resolve', ['--resolve', '127.0.0.1:19020:192.0.2.1']],
      ['connect-to', ['--connect-to', '::127.0.0.1:19999']],
    ] as [string, string[]][]) await m.request(`static ${name}`,
      [`${build}/fragment.exe`, '--dll', dll, '--', ...base, ...args, url], expected, config);
    await m.request('environment proxy neutralization', [`${build}/fragment.exe`, '--dll', dll, '--', ...base, url],
      expected, { ...config, http_proxy: 'http://127.0.0.1:19999', ALL_PROXY: 'http://127.0.0.1:19999' });
    await m.request('static bare negative control', [...base, url], { port: 19999, path: '/curl' });
  }
  if (await Bun.file(`${build}/plugin.dll`).exists()) {
    for (const mode of ['auto', 'ldrloaddll']) await m.request(`transitive dependency (${mode})`,
      [`${build}/host_plugin.exe`, dll, `${build}/plugin.dll`, corpus, url],
      mode === 'auto' ? expected : { port: 19999, path: '/curl' }, { ...config, FRAGMENT_LOADER: mode });
  } else m.skip('transitive dependency', 'requires libcurl-cfw820.dll corpus fixture');
} finally { m.finish(); }

