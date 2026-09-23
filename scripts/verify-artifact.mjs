import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
const files=await readdir('_site');
for(const file of ['login.html','complete.html','visit.html','logout.html','login-flow.js','visit-flow.js'])assert.ok(files.includes(file));
for(const file of files) {
 assert.ok(/^(?:[a-z-]+\.(?:html|js|css)|\.nojekyll)$/.test(file));
 if(!file.endsWith('.html'))continue;
 for(const [,link] of (await readFile('_site/'+file,'utf8')).matchAll(/(?:src|href)="([^"#?]+)(?:[?#][^"]*)?"/g)) {
  if(/^(?:https?:|data:)/.test(link))continue;
  assert.ok(files.includes(link),`Missing ${link} from ${file}`);
 }
}
console.log('PASS: central Pages login/complete/visit/logout dependencies included; backend excluded.');
