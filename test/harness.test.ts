import { test, expect } from 'bun:test';
import { Matrix } from './harness';

test('recording harness rejects wrong methods, bodies, exits and extra traffic', async () => {
  const m = new Matrix([0]);
  const port = m.servers[0].port!;
  const url = `http://127.0.0.1:${port}/probe`;
  async function check(code: string, wanted: Record<string, unknown> = {}) {
    await m.request('harness negative control', [process.execPath, '-e', code],
      { port, path: '/probe', ...wanted });
  }
  try {
    await check(`await fetch('${url}')`);
    expect(m.passed).toBe(1);
    await check(`await fetch('${url}', {method:'POST'})`);
    await check(`await fetch('${url}'); process.exit(7)`);
    await check(`await fetch('${url}'); await fetch('${url}')`);
    await check(`await fetch('${url}', {method:'POST',body:'wrong'})`, { method: 'POST', body: 'right' });
    expect(m.failed).toBe(4);
  } finally { m.stop(); }
});
