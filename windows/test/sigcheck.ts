import { exports } from './pe';
import { verify } from '../../test/signatures';
if (!Bun.argv[2]) throw new Error('Usage: bun windows/test/sigcheck.ts <main.c> <libcurl.dll> [...]');
await verify(Bun.argv[2], Bun.argv.slice(3), exports);
