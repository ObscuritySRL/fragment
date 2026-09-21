import { symbols } from './elf';
import { verify } from '../../test/signatures';
if (!Bun.argv[2]) throw new Error('Usage: bun linux/test/sigcheck.ts <main.c> <libcurl.so> [...]');
await verify(Bun.argv[2], Bun.argv.slice(3), symbols, true);
