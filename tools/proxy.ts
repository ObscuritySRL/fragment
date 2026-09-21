/** Bun-native Fragment forwarding proxy: bun tools/proxy.ts [port]. */
const hop = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade'];
function endToEnd(headers: Headers) {
  const result = new Headers(headers);
  const connection = (result.get('connection') ?? '').split(',').map(s => s.trim()).filter(Boolean);
  for (const name of [...hop, ...connection]) result.delete(name);
  return result;
}
export async function forward(request: Request): Promise<Response> {
  const raw = request.url.slice(request.url.indexOf('/', request.url.indexOf('://') + 3) + 1);
  let target: URL;
  try {
    target = new URL(raw);
    if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password) throw new Error();
  } catch { return new Response('Expected /http(s)://host/path\n', { status: 400 }); }
  const headers = endToEnd(request.headers);
  headers.delete('host');
  headers.delete('content-length');
  try {
    const response = await fetch(target, {
      method: request.method, headers,
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
      redirect: 'manual', decompress: false, signal: AbortSignal.timeout(30_000),
    });
    const responseHeaders = endToEnd(response.headers);
    // The client sees the proxy URL as its base. Resolve upstream redirects
    // here so /next, ../next, and ?page=2 retain the original authority/path.
    // Keep the destination on this proxy: automatic WinHTTP redirects need
    // not call the hooked public connection/request APIs again.
    const location = responseHeaders.get('location');
    if (location && response.status >= 300 && response.status < 400) {
      try {
        const next = new URL(location, target);
        if (['http:', 'https:'].includes(next.protocol))
          responseHeaders.set('location', `${new URL(request.url).origin}/${next.href}`);
      }
      catch { /* Preserve malformed upstream values for the client to reject. */ }
    }
    return new Response(response.body, { status: response.status, statusText: response.statusText,
      headers: responseHeaders });
  } catch (error) {
    console.error(`Upstream request failed: ${error}`);
    return new Response('Upstream request failed\n', { status: 502 });
  }
}
if (import.meta.main) {
  const port = Number(Bun.argv[2] ?? 9020);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Port must be 1..65535');
  const server = Bun.serve({ hostname: '127.0.0.1', port, fetch: async request => {
    const response = await forward(request);
    console.log(`${request.method} ${request.url} -> ${response.status}`);
    return response;
  } });
  console.log(`Fragment proxy listening on ${server.url}`);
}
