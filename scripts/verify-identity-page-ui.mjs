import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { handleIdentityPageRequest } from '../supabase/functions/identity-page/handler.js';
for (const route of ['login', 'complete', 'logout']) {
  const response = await handleIdentityPageRequest(new Request(`https://central.test/${route}?site_id=b`), { centralPageUrl: 'https://central.github.io/hub' });
  assert.equal(response.status, 302);
  assert.equal(response.headers.get('Location'), `https://central.github.io/hub/${route}.html?site_id=b`);
  assert.equal(response.headers.get('Referrer-Policy'), 'no-referrer');
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
}
const login = await readFile(new URL('../public/login.html', import.meta.url), 'utf8');
assert.ok(!login.includes('type="password"'));
assert.match(login, /autocomplete="username"/);
console.log('PASS: one static login UI; legacy login/complete/logout redirect without embedding credentials.');
