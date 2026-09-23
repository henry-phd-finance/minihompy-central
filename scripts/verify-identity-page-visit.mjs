import assert from 'node:assert/strict';
import { handleIdentityPageRequest, normalizePagePath } from '../supabase/functions/identity-page/handler.js';
for (const prefix of ['', '/identity-page', '/functions/v1/identity-page']) {
  const req = new Request(`https://central.test${prefix}/visit?site_id=b&return_path=%2Fhome%2F`);
  const res = await handleIdentityPageRequest(req, { centralPageUrl: 'https://central.github.io/hub/' });
  assert.equal(res.status, 302); assert.equal(res.headers.get('Location'), 'https://central.github.io/hub/visit.html?site_id=b&return_path=%2Fhome%2F');
  assert.equal(normalizePagePath(prefix + '/visit/'), '/visit');
}
assert.equal((await handleIdentityPageRequest(new Request('https://central.test/unknown'))).status, 404);
assert.equal((await handleIdentityPageRequest(new Request('https://central.test/visit'), { centralPageUrl: 'javascript:alert(1)' })).status, 503);
console.log('PASS: legacy Edge visit routes forward to canonical static Pages with query preserved.');
