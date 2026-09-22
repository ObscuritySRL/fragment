import { describe, expect, test } from 'bun:test';
import { parseCapture, renderCapture, type DataEvent } from '../tools/observe';

const header = { v: 1, session: 'test', seq: 1, time: 1000, pid: 9, tid: 10 } as const;
const session = { ...header, type: 'session', mode: 'observe' };
const payload = Buffer.from([0, 255, 0x3c, 0x2f, 0x80, 0x0a]);
const data: DataEvent = { ...header, seq: 2, type: 'data', backend: 'schannel', connection: 1,
  direction: 'out', length: payload.length, captured: payload.length, truncated: false, data: payload.toString('base64') };
const jsonl = (...records: unknown[]) => records.map(r => JSON.stringify(r)).join('\n') + '\n';

describe('TLS observation reports', () => {
  test('preserves arbitrary binary bytes, directions, and connection identity', () => {
    const events = parseCapture(jsonl(session, data, { ...data, seq: 3, direction: 'in', connection: 2 }));
    expect(Buffer.from((events[1] as DataEvent).data, 'base64')).toEqual(payload);
    expect((events[2] as DataEvent).connection).toBe(2);
    expect((events[2] as DataEvent).direction).toBe('in');
  });
  test('rejects missing chunks, malformed bytes, and incomplete files', () => {
    expect(() => parseCapture(jsonl(session, { ...data, seq: 3 }))).toThrow('missing');
    expect(() => parseCapture(jsonl(session, { ...data, captured: 5 }))).toThrow();
    expect(() => parseCapture(jsonl(session, { ...data, data: '!!!!!!==' }))).toThrow('base64');
    expect(() => parseCapture(jsonl(session) + '{"type":')).toThrow('incomplete');
    expect(() => parseCapture(jsonl(data))).toThrow();
    expect(() => parseCapture('')).toThrow('empty');
  });
  test('requires explicit, accurate truncation', () => {
    expect(() => parseCapture(jsonl(session, { ...data, length: 20 }))).toThrow();
    const events = parseCapture(jsonl(session, { ...data, length: 20, truncated: true }));
    expect((events[1] as DataEvent).truncated).toBe(true);
  });
  test('preserves explicit gaps and never labels pending I/O bytes as completed', () => {
    const network = { ...header, seq: 2, type: 'network', backend: 'winsock', connection: 1,
      event: 'WSARecv', transport: 'tcp', local: '127.0.0.1:100', remote: '127.0.0.1:200',
      bytes: 0, status: 'pending', error: 997 };
    const gap = { ...header, seq: 3, type: 'gap', backend: 'winsock', connection: 0,
      direction: 'in', reason: 'capture-failure' };
    expect(parseCapture(jsonl(session, network, gap))).toHaveLength(3);
    expect(() => parseCapture(jsonl(session, { ...network, bytes: 12 }))).toThrow('pending');
    expect(renderCapture(parseCapture(jsonl(session, network, gap)))).toContain('capture-failure');
  });
  test('escapes hostile metadata and never inserts plaintext as markup', () => {
    const hostile = { ...data, backend: '</script><img src=x onerror=alert(1)>' };
    const html = renderCapture(parseCapture(jsonl(session, hostile)));
    expect(html).not.toContain(hostile.backend);
    expect(html).toContain('\\u003c/script>');
    expect(html).not.toContain('innerHTML');
    expect(html).toContain("connect-src 'none'");
  });
});
