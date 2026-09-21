import { exports } from './pe';
import { verify } from '../../test/signatures';
await verify(`${import.meta.dir}/../main.c`, Bun.argv.slice(2), exports);
