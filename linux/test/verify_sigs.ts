import { symbols } from './elf';
import { verify } from '../../test/signatures';
await verify(`${import.meta.dir}/../main.c`, Bun.argv.slice(2), symbols, true);
