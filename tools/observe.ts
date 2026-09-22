/** Offline viewer for Fragment's byte-stream observations. No server or CDN. */
import { resolve } from 'node:path';

type Base = { v: 1; type: string; session: string; seq: number; time: number; pid: number; tid: number };
export type DataEvent = Base & { type: 'data'; backend: string; connection: number;
  direction: 'out' | 'in'; length: number; captured: number; truncated: boolean; data: string };
export type CaptureEvent = DataEvent | (Base & { type: 'session'; mode: 'observe' }) |
  (Base & { type: 'backend'; backend: string; ready: boolean }) |
  (Base & { type: 'gap'; backend: string; connection: number; direction: string; reason: string }) |
  (Base & { type: 'network'; backend: 'winsock'; connection: number; event: string; transport: string;
    local: string; remote: string; bytes: number; status: string; error: number });

const natural = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0;
function check(ok: unknown, line: number, message: string): asserts ok {
  if (!ok) throw new Error(`Capture line ${line}: ${message}`);
}

export function parseCapture(text: string): CaptureEvent[] {
  const records: CaptureEvent[] = [];
  const sequences = new Map<string, number>();
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index].trim();
    if (!line) continue;
    let event: any;
    try { event = JSON.parse(line); }
    catch { throw new Error(`Capture line ${index + 1}: invalid or incomplete JSON; retry after the target finishes`); }
    const n = index + 1;
    check(event && event.v === 1 && typeof event.session === 'string' && event.session.length <= 128 &&
      natural(event.seq) && event.seq > 0 && natural(event.time) && natural(event.pid) && natural(event.tid), n,
      'invalid record header or unsupported capture version');
    const key = `${event.session}/${event.pid}`;
    const previous = sequences.get(key);
    check(event.seq === (previous ?? 0) + 1, n, 'missing, duplicated, or out-of-order record');
    check(previous !== undefined || event.type === 'session', n, 'missing session header');
    if (event.type === 'session') {
      check(previous === undefined && event.mode === 'observe', n, 'invalid or duplicate session header');
    } else if (event.type === 'backend') {
      check(typeof event.backend === 'string' && typeof event.ready === 'boolean', n, 'invalid backend status');
    } else if (event.type === 'data') {
      check(typeof event.backend === 'string' && natural(event.connection) && event.connection > 0 &&
        (event.direction === 'out' || event.direction === 'in') && natural(event.length) &&
        natural(event.captured) && event.captured > 0 && event.captured <= 1024 * 1024 &&
        event.length >= event.captured && event.truncated === (event.length > event.captured) &&
        typeof event.data === 'string', n, 'invalid byte-stream record');
      check(event.data.length === 4 * Math.ceil(event.captured / 3) &&
        /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(event.data), n, 'invalid base64');
      const bytes = Buffer.from(event.data, 'base64');
      check(bytes.length === event.captured && bytes.toString('base64') === event.data, n, 'invalid byte count or base64 padding');
    } else if (event.type === 'gap') {
      check(typeof event.backend === 'string' && natural(event.connection) &&
        typeof event.direction === 'string' && typeof event.reason === 'string', n, 'invalid gap record');
    } else if (event.type === 'network') {
      check(event.backend === 'winsock' && natural(event.connection) && typeof event.event === 'string' &&
        ['tcp', 'udp', 'unknown'].includes(event.transport) && typeof event.local === 'string' &&
        typeof event.remote === 'string' && natural(event.bytes) && natural(event.error) &&
        ['completed', 'completed-unmeasured', 'pending', 'would-block', 'failed', 'eof'].includes(event.status), n, 'invalid network event');
      check(event.status !== 'pending' || event.bytes === 0, n, 'pending I/O must not claim completed bytes');
    } else {
      throw new Error(`Capture line ${n}: unknown record type ${String(event.type)}`);
    }
    sequences.set(key, event.seq);
    records.push(event as CaptureEvent);
  }
  if (!records.length) throw new Error('Capture is empty');
  return records;
}

export function renderCapture(events: CaptureEvent[]): string {
  // Escape '<' even inside JSON strings: payloads must never end a script tag.
  const json = JSON.stringify(events).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
  return `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>Fragment · Traffic observations</title>
<style>
:root{color-scheme:dark;font:15px system-ui,sans-serif;background:#0f1722;color:#dce5ef}
body{max-width:1400px;margin:36px auto;padding:0 24px}h1{font-size:28px;margin:0 0 10px}p{line-height:1.5;color:#aab9cb}
small{color:#aab9cb}label{display:inline-flex;gap:8px;align-items:center}select,input{font:inherit;background:#192538;color:inherit;padding:9px;border:1px solid #47566a;border-radius:5px}
.controls{display:flex;gap:18px;flex-wrap:wrap;margin:24px 0}.notice{background:#253147;padding:12px;border-left:3px solid #77b5ef}.warn{border-color:#f6bf58;color:#f6d59a}
.streams{display:grid;grid-template-columns:1fr 1fr;gap:18px}.panel{min-width:0;background:#162131;border:1px solid #34435a;border-radius:8px;padding:18px}.panel h2{font-size:18px;margin:0 0 8px}
pre{font:13px/1.55 ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere;max-height:68vh;overflow:auto;tab-size:4}
@media(max-width:850px){.streams{grid-template-columns:1fr}body{padding:0 14px}}.empty{padding:24px}
table{border-collapse:collapse;width:100%;font:13px ui-monospace,Consolas,monospace}th,td{padding:9px;text-align:left;border-bottom:1px solid #34435a;white-space:nowrap}th{color:#aab9cb}.network{overflow:auto;max-height:50vh}h2{font-size:20px}
</style>
<h1>Fragment <small> / Traffic observations</small></h1>
<p>TLS plaintext, socket activity, and optional raw socket bytes. Payload chunks are not HTTP messages or proof of delivery. Raw socket bytes may be encrypted.</p>
<p id="summary" class="notice"></p><p id="warning" class="notice warn" hidden></p>
<h2>Socket activity</h2><p id="networkSummary"></p><label>Filter endpoints or API <input id="networkFilter" type="search" placeholder="127.0.0.1, udp, pending..."></label>
<div class="network"><table><thead><tr><th>Time</th><th>PID / connection</th><th>API</th><th>Transport</th><th>Local</th><th>Remote</th><th>Bytes</th><th>Status / error</th></tr></thead><tbody id="network"></tbody></table></div>
<h2>Payload bytes</h2><p>Schannel/OpenSSL entries contain TLS plaintext; Winsock entries contain raw bytes. Use chunks to inspect UDP datagrams separately.</p>
<div class="controls"><label>Connection <select id="connection"></select></label><label>Display <select id="format"><option value="text">UTF-8 text</option><option value="hex">Hex bytes</option><option value="chunks">Individual chunks (hex)</option></select></label></div>
<div class="streams"><section class="panel"><h2>Outbound</h2><small id="outCount"></small><pre id="out"></pre></section><section class="panel"><h2>Inbound</h2><small id="inCount"></small><pre id="in"></pre></section></div>
<script type="application/json" id="records">${json}</script>
<script>
'use strict';
const records=JSON.parse(document.getElementById('records').textContent);
const groups=new Map();let captured=0;
for(const r of records){if(r.type!=='data'&&r.type!=='gap')continue;const key=r.session+'/'+r.pid+'/'+r.connection;
if(!groups.has(key))groups.set(key,[]);groups.get(key).push(r);if(r.type==='data')captured+=r.captured;}
const statuses=records.filter(r=>r.type==='backend');
const networks=records.filter(r=>r.type==='network');
document.getElementById('summary').textContent=groups.size+' payload context(s) · '+captured.toLocaleString()+' captured bytes · '+networks.length+' socket events · active backends: '+([...new Set(statuses.filter(s=>s.ready).map(s=>s.backend))].join(', ')||'none recorded');
function drawNetwork(){const query=document.getElementById('networkFilter').value.toLowerCase();const selected=networks.filter(r=>[r.event,r.transport,r.local,r.remote,r.status,String(r.pid)].join(' ').toLowerCase().includes(query));
const body=document.getElementById('network');body.replaceChildren();for(const r of selected.slice(0,2000)){const tr=document.createElement('tr');for(const value of [new Date(r.time).toISOString(),r.pid+' / '+r.connection,r.event,r.transport,r.local||'unknown',r.remote||'unknown',r.bytes,r.status+(r.error?' / '+r.error:'')]){const td=document.createElement('td');td.textContent=String(value);tr.appendChild(td);}body.appendChild(tr);}
document.getElementById('networkSummary').textContent=selected.length+' matching events'+(selected.length>2000?' (first 2,000 displayed)':'')+'. Pending calls are submissions; later asynchronous completion is not recorded. Socket IDs and TLS context IDs are separate, not automatically correlated. Socket bytes may be encrypted.';}
document.getElementById('networkFilter').addEventListener('input',drawNetwork);drawNetwork();
const choices=document.getElementById('connection');
for(const [key,rows] of groups){const option=document.createElement('option');option.value=key;option.textContent='PID '+rows[0].pid+' · connection '+rows[0].connection+' · '+rows[0].backend+' · '+new Date(rows[0].time).toISOString();choices.appendChild(option);}
function decode(rows){let size=0;for(const r of rows)size+=r.captured;const bytes=new Uint8Array(size);let offset=0;for(const r of rows){const s=atob(r.data);for(let i=0;i<s.length;i++)bytes[offset++]=s.charCodeAt(i);}return bytes;}
function hex(bytes){const rows=[];for(let i=0;i<bytes.length;i+=16){const chunk=bytes.subarray(i,i+16);rows.push(i.toString(16).padStart(8,'0')+'  '+Array.from(chunk,b=>b.toString(16).padStart(2,'0')).join(' ').padEnd(47,' ')+'  '+Array.from(chunk,b=>b>=32&&b<127?String.fromCharCode(b):'.').join(''));}return rows.join('\\n');}
function draw(){const rows=groups.get(choices.value)||[];const warning=document.getElementById('warning');
const truncated=rows.some(r=>r.truncated||r.type==='gap')||records.some(r=>r.type==='gap'&&r.connection===0);warning.hidden=groups.size>0&&!truncated;
warning.textContent=groups.size===0?'No plaintext was recorded. A loaded DLL or ready backend does not establish traffic coverage. The process may use another TLS stack, issue no requests, or delegate networking to a child.':'This connection contains capture gaps or truncated chunks. Missing bytes are marked below; the stream is incomplete.';
for(const dir of ['out','in']){const parts=rows.filter(r=>r.direction===dir);const total=parts.reduce((n,r)=>n+(r.captured||0),0);
document.getElementById(dir+'Count').textContent=parts.length+' chunk(s) · '+total.toLocaleString()+' bytes · '+(rows[0]?.backend==='winsock'?'raw socket data':dir==='out'?'accepted for encryption':'successfully decrypted');
// A gap must not be silently concatenated across: decode contiguous segments.
let output=[],pending=[];const format=document.getElementById('format').value;function flush(){if(!pending.length)return;const bytes=decode(pending);output.push(format==='text'?new TextDecoder().decode(bytes):hex(bytes));pending=[];}
for(const r of parts){if(r.type==='gap'){flush();output.push('\\n[Capture gap: '+r.reason+']\\n');continue;}if(format==='chunks'){flush();output.push('\\nChunk '+r.seq+' · '+r.captured+' bytes · '+new Date(r.time).toISOString()+'\\n');}pending.push(r);if(r.truncated){flush();output.push('\\n[Missing '+(r.length-r.captured)+' bytes after capture limit]\\n');}}flush();
document.getElementById(dir).textContent=output.join('')||'No bytes captured in this direction.';}}
choices.addEventListener('change',draw);document.getElementById('format').addEventListener('change',draw);draw();
</script></html>`;
}

if (import.meta.main) {
  try {
    const args = Bun.argv.slice(2);
    if (args.includes('--help') || args.includes('-h')) {
      console.log('Usage: bun tools/observe.ts <capture.jsonl> [--out <report.html>]\nCreates an offline viewer; the JSONL retains exact binary bytes.');
    } else {
      if (args.length !== 1 && !(args.length === 3 && args[1] === '--out')) throw new Error('Usage: bun tools/observe.ts <capture.jsonl> [--out <report.html>]');
      const input = Bun.file(args[0]);
      if (!await input.exists()) throw new Error(`Capture not found: ${args[0]}`);
      if (input.size > 128 * 1024 * 1024) throw new Error('Capture exceeds viewer limit (128 MiB); inspect the JSONL with a streaming tool');
      const output = resolve(args[2] ?? args[0] + '.html');
      if (output === resolve(args[0]) || await Bun.file(output).exists()) throw new Error('Choose a new output file; existing files are never overwritten');
      const records = parseCapture(await input.text());
      await Bun.write(output, renderCapture(records));
      console.log(`Viewer: ${output}\n${records.filter(r => r.type === 'data').length} payload chunks. Keep the JSONL for exact bytes.`);
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    process.exitCode = 1;
  }
}
