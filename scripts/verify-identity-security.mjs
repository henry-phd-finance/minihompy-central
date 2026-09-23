import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { handleIdentityApiRequest, getCentralSecret } from '../supabase/functions/identity-api/handler.js';
import { signToken, verifyToken } from '../supabase/functions/_shared/tokens.js';
import { sha256, randomSecret, siteProposal } from '../supabase/functions/_shared/auth-proof.js';
import { createIdentityDb } from './helpers/identity-db.mjs';

const SECRET = 'test-only-central-secret-of-at-least-32-bytes';
const ownerA = '11111111-1111-4111-8111-111111111111';
const ownerB = '22222222-2222-4222-8222-222222222222';
const stranger = '33333333-3333-4333-8333-333333333333';
const refA = 'aaaaaaaaaaaaaaaaaaaa', refB = 'bbbbbbbbbbbbbbbbbbbb';
const verifier = randomSecret(), challenge = await sha256(verifier);
const access = who => `header.${who}.signature`;
const proposal = (name, ref) => ({ handle: name, display_name: name, origin: `https://${name}.github.io`, base_path: '/minihompy/',
  homepage_url: `https://${name}.github.io/minihompy/`, login_url: `https://${name}.github.io/minihompy/login/`,
  supabase_project_ref: ref, supabase_publishable_key: 'sb_publishable_testpublickey1234' });
const pages = new Map(), calls = [];
let failAuth = false, failPages = false, anonymous = false, admin = true;
const fetcher = async (url, init) => {
  calls.push({ url, init });
  assert.equal(init.redirect, 'error');
  assert.ok(init.signal);
  if (url.includes('.github.io/')) {
    assert.equal(init.headers?.Authorization, undefined, 'Auth credential must never go to Pages');
    if (failPages) return new Response('redirect', { status: 302 });
    return pages.has(url) ? Response.json(pages.get(url)) : new Response('', { status: 404 });
  }
  const auth = init.headers.Authorization;
  const ref = new URL(url).hostname.split('.')[0];
  const valid = (auth === `Bearer ${access('alice')}` && ref === refA) || (auth === `Bearer ${access('bob')}` && ref === refB) || auth === `Bearer ${access('stranger')}`;
  if (!valid || failAuth) return Response.json({ error: 'invalid token' }, { status: 401 });
  const id = auth.includes('.alice.') ? ownerA : auth.includes('.bob.') ? ownerB : stranger;
  if (url.endsWith('/auth/v1/user')) return Response.json({ id, role: 'authenticated', is_anonymous: anonymous });
  assert.ok(url.endsWith('/rest/v1/rpc/is_minihompy_admin'));
  return Response.json(admin);
};
const { pg, db } = await createIdentityDb();
const options = { supabaseClient: db, centralSecret: SECRET, allowedOrigins: new Set(['https://central.github.io', 'https://alice.github.io', 'https://bob.github.io']), fetcher };
async function request(path, body, credential, expected = 200, overrides = {}) {
  const response = await handleIdentityApiRequest(new Request('https://central.test' + path, {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...(credential ? { Authorization: `Bearer ${credential}` } : {}) }, body: JSON.stringify(body),
  }), { ...options, ...overrides });
  const result = await response.json();
  assert.equal(response.status, expected, `${path}: ${JSON.stringify(result)}`);
  assert.equal(response.headers.get('Cache-Control'), 'no-store');
  return result;
}
async function register(name, ref, credential) {
  const pending = await request('/sites', proposal(name, ref), credential, 202);
  pages.set(pending.verification_url, pending.verification_file);
  const verified = await request('/sites/verify', { registration_id: pending.registration_id }, credential);
  return { ...verified, pending };
}
let checks = 0;
const passed = name => { checks++; console.log(`PASS ${checks}: ${name}`); };
try {
  assert.throws(() => getCentralSecret({ centralSecret: '' }));
  await request('/login-intents', {}, null, 503, { centralSecret: '' });
  const oldSecret = process.env.CENTRAL_TOKEN_SECRET, oldJwt = process.env.JWT_SECRET;
  delete process.env.CENTRAL_TOKEN_SECRET; process.env.JWT_SECRET = SECRET;
  try { assert.throws(() => getCentralSecret()); } finally {
    if (oldSecret === undefined) delete process.env.CENTRAL_TOKEN_SECRET; else process.env.CENTRAL_TOKEN_SECRET = oldSecret;
    if (oldJwt === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = oldJwt;
  }
  const tsEntry = await readFile(new URL('../supabase/functions/identity-api/handler.ts', import.meta.url), 'utf8');
  assert.match(tsEntry, /from "\.\/handler.js"/);
  passed('missing dedicated key fails closed; production and tests share handler');

  await request('/sites', proposal('alice', refA), null, 401);
  for (const bad of [
    { origin: 'http://alice.github.io' }, { origin: 'https://127.0.0.1' }, { origin: 'https://alice.github.io.evil.test' },
    { origin: 'https://alice.github.io:444' }, { login_url: 'https://evil.github.io/login/' },
    { login_url: 'javascript:alert(1)' }, { login_url: 'https://alice.github.io/outside/' },
    { base_path: '/minihompy/../' }, { supabase_project_ref: 'localhost' }, { supabase_publishable_key: 'sb_secret_should-not-be-stored' },
  ]) await request('/sites', { ...proposal('alice', refA), ...bad }, access('alice'), 400);
  const serviceKey = 'x.' + btoa(JSON.stringify({ role: 'service_role', ref: refA })) + '.x';
  assert.throws(() => siteProposal({ ...proposal('alice', refA), supabase_publishable_key: serviceKey }));
  passed('registration validates hosting boundaries, paths, project refs and public-only keys');

  await request('/sites', proposal('alice', refA), access('bob'), 401);
  anonymous = true; await request('/sites', proposal('alice', refA), access('alice'), 403); anonymous = false;
  admin = false; await request('/sites', proposal('alice', refA), access('alice'), 403); admin = true;
  const pending = await request('/sites', proposal('alice', refA), access('alice'), 202);
  assert.equal((await pg.query('select count(*)::int as n from private.identity_members')).rows[0].n, 0);
  await request('/sites/verify', { registration_id: pending.registration_id }, access('alice'), 403);
  pages.set(pending.verification_url, { ...pending.verification_file, challenge: randomSecret() });
  await request('/sites/verify', { registration_id: pending.registration_id }, access('alice'), 403);
  pages.set(pending.verification_url, pending.verification_file);
  failPages = true; await request('/sites/verify', { registration_id: pending.registration_id }, access('alice'), 403); failPages = false;
  await request('/sites/verify', { registration_id: pending.registration_id }, access('stranger'), 403);
  const alice = await request('/sites/verify', { registration_id: pending.registration_id }, access('alice'));
  await request('/sites/verify', { registration_id: pending.registration_id }, access('alice'), 409);
  const bob = await register('bob', refB, access('bob'));
  passed('both Pages control and a permanent local admin are required; registration is single-use');

  // A conflicting registration cannot leave an orphan member or consume its challenge.
  const conflict = await request('/sites', { ...proposal('other', refA) }, access('alice'), 202);
  pages.set(conflict.verification_url, conflict.verification_file);
  await request('/sites/verify', { registration_id: conflict.registration_id }, access('alice'), 409);
  assert.equal((await pg.query("select count(*)::int as n from private.identity_members where handle='other'")).rows[0].n, 0);
  assert.equal((await pg.query('select consumed_at from private.identity_registrations where id=$1', [conflict.registration_id])).rows[0].consumed_at, null);
  passed('registration and binding creation roll back atomically on a duplicate project');

  const loginBody = { handle: 'alice', return_site_id: bob.site_id, return_path: '/minihompy/#/board', code_challenge: challenge };
  await request('/login-intents', { ...loginBody, code_challenge: undefined }, null, 400);
  await request('/login-intents', { ...loginBody, handle: 'missing' }, null, 404);
  await request('/login-intents', { ...loginBody, return_path: '//evil.test/' }, null, 400);
  const intent = await request('/login-intents', loginBody);
  const intentClaims = await verifyToken(intent.login_intent, 'login_intent', SECRET);
  assert.ok(intentClaims.jti); assert.equal(intentClaims.site_id, alice.site_id);
  assert.equal(new URL(intent.redirect_url).origin, 'https://alice.github.io');
  const context = await request('/login-context', { login_intent: intent.login_intent, site_id: alice.site_id });
  assert.equal(context.handle, 'alice'); assert.equal(context.return_site_id, bob.site_id);
  assert.equal(context.code_challenge, undefined); assert.equal(context.owner_user_id, undefined);
  await request('/login-context', { login_intent: intent.login_intent, site_id: bob.site_id }, null, 403);
  await request('/login-context', { login_intent: intent.login_intent + 'x', site_id: alice.site_id }, null, 400);
  const activateBody = { site_id: alice.site_id, login_intent: intent.login_intent, local_user_id: ownerA };
  await request('/activation-tickets', activateBody, null, 401);
  await request('/activation-tickets', activateBody, access('bob'), 401);
  await request('/activation-tickets', activateBody, access('stranger'), 403);
  await request('/activation-tickets', { ...activateBody, site_id: bob.site_id }, access('alice'), 403);
  await request('/activation-tickets', { ...activateBody, local_user_id: stranger }, access('alice'), 403);
  failAuth = true; await request('/activation-tickets', activateBody, access('alice'), 401); failAuth = false;
  anonymous = true; await request('/activation-tickets', activateBody, access('alice'), 403); anonymous = false;
  admin = false; await request('/activation-tickets', activateBody, access('alice'), 403); admin = true;
  await request('/activation-tickets', { ...activateBody, login_intent: intent.login_intent + 'x' }, access('alice'), 400);
  const expiredIntent = await signToken({ ...intentClaims, iat: 1, exp: 2 }, SECRET);
  await request('/activation-tickets', { ...activateBody, login_intent: expiredIntent }, access('alice'), 400);
  passed('UUID-only, wrong-project, forged/expired token, anonymous and wrong-owner requests are rejected');

  const activationResponses = await Promise.all([0, 1].map(() => handleIdentityApiRequest(new Request('https://central.test/activation-tickets', {
    method: 'POST', headers: { Authorization: `Bearer ${access('alice')}`, 'Content-Type': 'application/json' }, body: JSON.stringify(activateBody),
  }), options)));
  assert.deepEqual(activationResponses.map(r => r.status).sort(), [200, 409]);
  const ticket = (await activationResponses.find(r => r.ok).json()).activation_ticket;
  await request('/login-context', { login_intent: intent.login_intent, site_id: alice.site_id }, null, 409);
  await request('/sessions/complete', { activation_ticket: ticket }, null, 400);
  await request('/sessions/complete', { activation_ticket: ticket, code_verifier: randomSecret() }, null, 409);
  const completes = await Promise.all([0, 1].map(() => handleIdentityApiRequest(new Request('https://central.test/sessions/complete', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ activation_ticket: ticket, code_verifier: verifier }),
  }), options)));
  assert.deepEqual(completes.map(r => r.status).sort(), [200, 409]);
  const session = await completes.find(r => r.ok).json();
  const claims = await verifyToken(session.central_session, 'central_session', SECRET);
  assert.equal(claims.sub, alice.member_id); assert.equal(session.return_url, 'https://bob.github.io/minihompy/#/board');
  const visit = await request('/visits/issue', { central_session: session.central_session, target_site_id: bob.site_id, return_path: '/minihompy/#/board' });
  const resolved = await request('/visits/resolve', { visit_token: visit.visit_ticket, site_id: bob.site_id });
  assert.equal(resolved.profile.id, alice.member_id); assert.equal(resolved.profile.handle, 'alice');
  assert.equal(resolved.profile.local_user_id, undefined);
  await request('/visits/resolve', { visit_token: visit.visit_ticket, site_id: alice.site_id }, null, 403);
  passed('intent and activation replay are rejected; browser verifier required; A is identified on B');

  // Completion rechecks the binding, session version and both sites after activation.
  for (const mutation of [
    ["update private.identity_bindings set status='revoked' where site_id=$1", "update private.identity_bindings set status='active' where site_id=$1"],
    ["update private.identity_sites set verification_status='needs_reverification' where id=$1", "update private.identity_sites set verification_status='verified' where id=$1"],
    ["update private.identity_members set session_version=session_version+1 where id=(select member_id from private.identity_sites where id=$1)", null],
  ]) {
    const i = await request('/login-intents', loginBody);
    const t = await request('/activation-tickets', { site_id: alice.site_id, login_intent: i.login_intent }, access('alice'));
    await pg.query(mutation[0], [alice.site_id]);
    await request('/sessions/complete', { activation_ticket: t.activation_ticket, code_verifier: verifier }, null, 409);
    if (mutation[1]) await pg.query(mutation[1], [alice.site_id]);
  }
  const invalidOldSession = await request('/visits/issue', { central_session: session.central_session, target_site_id: bob.site_id });
  assert.equal(invalidOldSession.session_invalid, true);
  passed('revocation and ownership changes between exchanges invalidate login');

  await pg.query("update private.identity_sites set verification_status='needs_reverification' where id=$1", [alice.site_id]);
  await request('/login-intents', loginBody, null, 400);
  await request('/visits/issue', { target_site_id: alice.site_id }, null, 400);
  const reverify = await request('/sites/reverify', { site_id: alice.site_id, supabase_publishable_key: proposal('alice', refA).supabase_publishable_key }, access('alice'), 202);
  pages.set(reverify.verification_url, reverify.verification_file);
  const preserved = await request('/sites/verify', { registration_id: reverify.registration_id }, access('alice'));
  assert.equal(preserved.member_id, alice.member_id); assert.equal(preserved.site_id, alice.site_id);
  await request('/sites/reverify', { site_id: alice.site_id, supabase_publishable_key: proposal('alice', refA).supabase_publishable_key }, access('stranger'), 403);
  passed('legacy sites require re-verification; IDs and existing owner bindings are preserved');

  for (const role of ['anon', 'authenticated']) {
    await pg.exec(`reset role; set role ${role}`);
    await assert.rejects(() => pg.query('select * from private.identity_login_attempts'), /permission denied/);
    await assert.rejects(() => pg.query('select private.identity_verify_registration($1,$2)', [pending.registration_id, ownerA]), /permission denied/);
    await pg.exec('reset role; set role service_role');
  }
  const stored = JSON.stringify((await pg.query('select to_jsonb(r) as record from private.identity_registrations r')).rows) + JSON.stringify((await pg.query('select to_jsonb(a) as record from private.identity_login_attempts a')).rows);
  assert.ok(!stored.includes(access('alice')) && !stored.includes(access('bob')) && !stored.includes(verifier));
  const preflight = await handleIdentityApiRequest(new Request('https://central.test/activation-tickets', { method: 'OPTIONS', headers: { Origin: 'https://alice.github.io', 'Access-Control-Request-Headers': 'authorization' } }), options);
  assert.equal(preflight.status, 204); assert.match(preflight.headers.get('Access-Control-Allow-Headers'), /Authorization/);
  passed('private tables/RPCs deny browser roles; credentials/verifiers are not persisted; CORS allows bearer header');
  // A stored intent/activation has its own deadline, independent of JWT tolerance.
  const expiring = await request('/login-intents', loginBody);
  const expiringClaims = await verifyToken(expiring.login_intent, 'login_intent', SECRET);
  await pg.query("update private.identity_login_attempts set intent_expires_at=now()-interval '1 second' where id=$1", [expiringClaims.jti]);
  await request('/activation-tickets', { login_intent: expiring.login_intent, site_id: alice.site_id }, access('alice'), 409);
  const i2 = await request('/login-intents', loginBody);
  const t2 = await request('/activation-tickets', { login_intent: i2.login_intent, site_id: alice.site_id }, access('alice'));
  const t2Claims = await verifyToken(t2.activation_ticket, 'activation_ticket', SECRET);
  await pg.query("update private.identity_login_attempts set activation_expires_at=now()-interval '1 second' where activation_id=$1", [t2Claims.jti]);
  await request('/sessions/complete', { activation_ticket: t2.activation_ticket, code_verifier: verifier }, null, 409);
  await request('/sessions/complete', { activation_ticket: i2.login_intent, code_verifier: verifier }, null, 400);
  await request('/sessions/complete', { activation_ticket: t2.activation_ticket + 'x', code_verifier: verifier }, null, 400);
  const expiredRegistration = await request('/sites', proposal('expired', refA), access('alice'), 202);
  await pg.query("update private.identity_registrations set expires_at=now()-interval '1 second' where id=$1", [expiredRegistration.registration_id]);
  await request('/sites/verify', { registration_id: expiredRegistration.registration_id }, access('alice'), 409);
  await request('/login-intents', { ...loginBody, return_site_id: undefined }, null, 400);
  passed('database deadlines, token kind/tampering and required return site are enforced');

  const brokenDb = { ...db, async rpc() { return { data: null, error: { code: 'XX000' } }; } };
  await request('/login-intents', loginBody, null, 503, { supabaseClient: brokenDb });
  const unavailableFetch = async () => { throw new Error('network failure must not expose any tokens'); };
  await request('/sites', proposal('offline', refA), access('alice'), 401, { fetcher: unavailableFetch });
  passed('database and remote Auth failure do not issue credentials');
  console.log(`All ${checks} central security groups passed (real SQL via PGlite, mocked external Auth/Pages HTTP).`);
} finally { await pg.close(); }
