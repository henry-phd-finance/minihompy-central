import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
for(const [dir,name] of [['_shared','tokens'],['_shared','cors'],['_shared','validation'],['identity-api','handler'],['identity-page','handler']]) {
 const ts=await readFile(new URL(`../supabase/functions/${dir}/${name}.ts`,import.meta.url),'utf8');
 const stripped=ts.replace(/\/\/[^\n]*/g,'').trim();
 assert.match(stripped,new RegExp(`^export (?:\\*|\\{[^}]+\\}) from ["']\\./${name}\\.js["'];?$`));
 await readFile(new URL(`../supabase/functions/${dir}/${name}.js`,import.meta.url));
}
for(const dir of ['identity-api','identity-page'])assert.match(await readFile(new URL(`../supabase/functions/${dir}/index.ts`,import.meta.url),'utf8'),/from "\.\/handler\.ts"/);
console.log('PASS: deployed TS adapters and Node tests use the same JS implementations.');
