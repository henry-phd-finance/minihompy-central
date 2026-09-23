import assert from 'node:assert/strict';
import { createIdentityDb } from './helpers/identity-db.mjs';
import { handleIdentityApiRequest } from '../supabase/functions/identity-api/handler.js';
import { signToken } from '../supabase/functions/_shared/tokens.js';

const memberId = '11111111-1111-4111-8111-111111111111';
const siteId = '22222222-2222-4222-8222-222222222222';
const ownerId = '33333333-3333-4333-8333-333333333333';
const secret = 'test-only-central-secret-of-at-least-32-bytes';
const { pg, db } = await createIdentityDb({ beforeUpgrade: async pg => {
  await pg.query("insert into private.identity_members(id,handle,display_name,session_version) values($1,'legacy','Legacy',4)", [memberId]);
  await pg.query("insert into private.identity_sites(id,member_id,origin,base_path,homepage_url,login_url,supabase_project_ref) values($1,$2,'https://legacy.github.io','/home/','https://legacy.github.io/home/','https://legacy.github.io/home/login/','aaaaaaaaaaaaaaaaaaaa')", [siteId, memberId]);
  await pg.query('insert into private.identity_bindings(site_id,member_id,local_user_id) values($1,$2,$3)', [siteId, memberId, ownerId]);
} });
try {
  const member = (await pg.query('select * from private.identity_members where id=$1', [memberId])).rows[0];
  const site = (await pg.query('select * from private.identity_sites where id=$1', [siteId])).rows[0];
  const binding = (await pg.query('select * from private.identity_bindings where site_id=$1', [siteId])).rows[0];
  assert.equal(member.session_version, 5); assert.equal(site.verification_status, 'needs_reverification');
  assert.equal(binding.local_user_id, ownerId); assert.equal(site.member_id, memberId); assert.equal(site.status, 'active');
  const options = { supabaseClient: db, centralSecret: secret, allowedOrigins: new Set() };
  const now = Math.floor(Date.now()/1000);
  const oldSession = await signToken({ kind: 'central_session', sub: memberId, session_version: 4, iat: now, exp: now + 3600 }, secret);
  // Even after re-verification, an old UUID-only session must remain invalid.
  await pg.query("update private.identity_sites set verification_status='verified' where id=$1", [siteId]);
  const response = await handleIdentityApiRequest(new Request('https://central.test/visits/issue', {
    method: 'POST', body: JSON.stringify({ central_session: oldSession, target_site_id: siteId }),
  }), options);
  assert.equal(response.status, 200);
  const result = await response.json(); assert.equal(result.status, 'anonymous'); assert.equal(result.session_invalid, true);
  const legacyVisit = await signToken({ kind: 'visit_ticket', sub: memberId, aud: siteId, attempt_id: 'legacy', return_path: '/home/', iat: now, exp: now + 60 }, secret);
  const resolved = await handleIdentityApiRequest(new Request('https://central.test/visits/resolve', {
    method: 'POST', body: JSON.stringify({ visit_token: legacyVisit, site_id: siteId }),
  }), options);
  assert.equal(resolved.status, 200); assert.equal((await resolved.json()).status, 'anonymous');
  console.log('PASS: upgrading populated legacy tables preserves IDs/bindings and invalidates old sessions.');
} finally { await pg.close(); }
