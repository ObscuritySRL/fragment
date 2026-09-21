import { forward } from '../tools/proxy';
import { run, type Env } from './harness';

/** Exercise the real client, not just a forwarded response header. */
export async function redirectCases(
  check: (name: string, ok: boolean, detail?: string) => void,
  client: (url: string, proxy: string, disabled: boolean) => { cmd: string[]; env: Env },
) {
  for (const [status, location] of [[302, '/next'], [307, '../next'], [308, '?next=1']] as const) {
    const originHits: { path: string; proxied: boolean }[] = [];
    const proxyHits: string[] = [];
    const origin = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: req => {
      const url = new URL(req.url);
      originHits.push({ path: url.pathname + url.search, proxied: req.headers.get('x-fragment-probe') === '1' });
      return url.pathname === '/dir/start' && !url.search
        ? new Response(null, { status, headers: { location } }) : new Response('redirect complete');
    } });
    const proxy = Bun.serve({ hostname: '127.0.0.1', port: 0, fetch: req => {
      proxyHits.push(req.url.slice(req.url.indexOf('/', req.url.indexOf('://') + 3)));
      const headers = new Headers(req.headers);
      headers.set('x-fragment-probe', '1');
      return forward(new Request(req, { headers }));
    } });
    try {
      const start = new URL('/dir/start', origin.url);
      const end = new URL(location, start);
      for (const disabled of [false, true]) {
        originHits.length = proxyHits.length = 0;
        const { cmd, env } = client(start.href, proxy.url.href, disabled);
        const result = await run(cmd, env);
        const expectedProxy = disabled ? [] : [`/${start.href}`, `/${end.href}`];
        const expectedOrigin = [start, end].map(url => ({ path: url.pathname + url.search, proxied: !disabled }));
        check(`redirect ${status} ${location}${disabled ? ' disabled control' : ''}`,
          result.rc === 0 && JSON.stringify(proxyHits) === JSON.stringify(expectedProxy) &&
          JSON.stringify(originHits) === JSON.stringify(expectedOrigin),
          `exit=${result.rc}, proxy=${JSON.stringify(proxyHits)}, origin=${JSON.stringify(originHits)}${result.rc ? result.out : ''}`);
      }
    } finally { origin.stop(true); proxy.stop(true); }
  }
}
