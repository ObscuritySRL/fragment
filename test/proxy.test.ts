import { test, expect } from 'bun:test';
import { forward } from '../tools/proxy';

test('proxy preserves request body, upstream status, and compressed bytes', async () => {
  const compressed = Bun.gzipSync('compressed response');
  const origin = Bun.serve({ port: 0, hostname: '127.0.0.1', fetch: async req => {
    expect(req.method).toBe('POST');
    expect(await req.text()).toBe('payload');
    expect(req.headers.get('x-hop')).toBeNull();
    return new Response(compressed, { status: 201, headers: { 'content-encoding': 'gzip' } });
  } });
  try {
    const response = await forward(new Request(`http://127.0.0.1:9020/${origin.url}path?q=1`, {
      method: 'POST', body: 'payload', headers: { connection: 'x-hop', 'x-hop': 'removed' },
    }));
    expect(response.status).toBe(201);
    expect(response.headers.get('content-encoding')).toBe('gzip');
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(compressed);
  } finally { origin.stop(true); }
});
test('proxy rejects malformed targets and preserves redirect responses', async () => {
  expect((await forward(new Request('http://localhost/not-a-url'))).status).toBe(400);
  expect((await forward(new Request('http://localhost/file:///example'))).status).toBe(400);
  const origin = Bun.serve({ port: 0, fetch: () => new Response(null, { status: 302, headers: { location: '/next' } }) });
  try {
    const response = await forward(new Request(`http://localhost/${origin.url}`));
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('/next');
  } finally { origin.stop(true); }
});
