/** Shared Bun-native process and HTTP recording harness. No external services. */
export type Env = Record<string, string>;
export function environment(extra: Env = {}): Env {
  return { ...Object.fromEntries(Object.entries(Bun.env).filter(([k, v]) =>
    v !== undefined && !/^FRAGMENT_|^LD_PRELOAD$|^LD_AUDIT$|^(https?|all|no)_proxy$/i.test(k))), ...extra } as Env;
}
export async function run(cmd: string[], env: Env = {}, timeout = 40_000) {
  const child = Bun.spawn(cmd, { env: environment(env), stdout: 'pipe', stderr: 'pipe', stdin: 'ignore' });
  const timer = setTimeout(() => child.kill(), timeout);
  try {
    const [rc, stdout, stderr] = await Promise.all([child.exited,
      new Response(child.stdout).text(), new Response(child.stderr).text()]);
    return { rc, out: stdout + stderr };
  } finally { clearTimeout(timer); }
}
export async function mustRun(cmd: string[], env: Env = {}, timeout = 600_000) {
  const result = await run(cmd, env, timeout);
  if (result.rc !== 0) throw new Error(`${cmd.join(' ')}: exit ${result.rc}\n${result.out}`);
  return result;
}
export type Hit = { port: number; method: string; path: string; body: string };
export class Matrix {
  hits: Hit[] = [];
  passed = 0;
  failed = 0;
  skipped = 0;
  servers: ReturnType<typeof Bun.serve>[] = [];
  constructor(ports = [19020, 19021, 19999]) {
    try {
      for (const port of ports) this.servers.push(Bun.serve({ hostname: '127.0.0.1', port,
        fetch: async (req, server) => {
          // Slice the raw request URL; URL.pathname would normalize embedded paths.
          const path = req.url.slice(req.url.indexOf('/', req.url.indexOf('://') + 3));
          this.hits.push({ port: server.port!, method: req.method, path, body: await req.text() });
          return new Response(req.method === 'HEAD' ? null : 'ok', { headers: { connection: 'close' } });
        } }));
    } catch (error) { this.stop(); throw error; }
  }
  check(name: string, ok: boolean, detail = '') {
    ok ? this.passed++ : this.failed++;
    console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name}${detail ? `: ${detail}` : ''}`);
  }
  skip(name: string, reason: string) { this.skipped++; console.log(`[SKIP] ${name}: ${reason}`); }
  async request(name: string, cmd: string[], expected: Partial<Hit> & { port: number; path: string },
    env: Env = {}, count = 1) {
    this.hits = [];
    const { rc, out } = await run(cmd, env, 120_000);
    const want = { method: 'GET', body: '', ...expected };
    const ok = rc === 0 && this.hits.length === count && this.hits.every(hit =>
      Object.entries(want).every(([k, v]) => hit[k as keyof Hit] === v));
    this.check(name, ok, ok ? `${count} request(s), exact destination/method/body` :
      `exit=${rc}; hits=${JSON.stringify(this.hits.slice(0, 4))}\n${out.slice(-2500)}`);
  }
  stop() { for (const server of this.servers) server.stop(true); }
  finish() {
    this.stop();
    console.log(`${this.passed} passed, ${this.failed} failed, ${this.skipped} skipped`);
    if (this.failed || !this.passed) process.exitCode = 1;
  }
}

