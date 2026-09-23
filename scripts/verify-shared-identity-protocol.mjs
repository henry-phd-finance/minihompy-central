import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  signToken,
  verifyToken,
  MAX_TOKEN_BYTES,
  CLOCK_TOLERANCE_SECONDS,
} from '../supabase/functions/_shared/tokens.js';
import {
  validateHandle,
  validateDisplayName,
  validateOrigin,
  validateRelativePath,
} from '../supabase/functions/_shared/validation.js';
import {
  getCorsHeaders,
  handleCorsPreflight,
} from '../supabase/functions/_shared/cors.js';

console.log('=== Starting Minihompy Central Protocol Verification ===\n');

const SECRET = 'test-central-secret-key-1234567890-minihompy';
const WRONG_SECRET = 'wrong-central-secret-key-0987654321-minihompy';
const now = Math.floor(Date.now() / 1000);

// --- 1. Token Issuance and Verification for All 4 Types ---
console.log('1. Testing token issuance and verification for all 4 types...');

// 1.1 Login Intent
const loginIntentPayload = {
  kind: 'login_intent',
  sub: 'member-uuid-1',
  return_site_id: 'site-uuid-b',
  return_path: '/minihompy/#/board',
  iat: now,
  exp: now + 300,
};
const loginIntentToken = await signToken(loginIntentPayload, SECRET);
const verifiedLoginIntent = await verifyToken(loginIntentToken, 'login_intent', SECRET, now);
assert.equal(verifiedLoginIntent.kind, 'login_intent');
assert.equal(verifiedLoginIntent.sub, 'member-uuid-1');
assert.equal(verifiedLoginIntent.return_site_id, 'site-uuid-b');
assert.equal(verifiedLoginIntent.return_path, '/minihompy/#/board');

// 1.2 Activation Ticket
const activationPayload = {
  kind: 'activation_ticket',
  sub: 'member-uuid-1',
  site_id: 'site-uuid-a',
  local_user_id: 'local-user-uuid-a',
  return_site_id: 'site-uuid-b',
  return_path: '/minihompy/#/guestbook',
  iat: now,
  exp: now + 120,
};
const activationToken = await signToken(activationPayload, SECRET);
const verifiedActivation = await verifyToken(activationToken, 'activation_ticket', SECRET, now);
assert.equal(verifiedActivation.kind, 'activation_ticket');
assert.equal(verifiedActivation.local_user_id, 'local-user-uuid-a');

// 1.3 Central Session Token
const centralSessionPayload = {
  kind: 'central_session',
  sub: 'member-uuid-1',
  session_version: 1,
  iat: now,
  exp: now + 30 * 86400,
};
const centralSessionToken = await signToken(centralSessionPayload, SECRET);
const verifiedSession = await verifyToken(centralSessionToken, 'central_session', SECRET, now);
assert.equal(verifiedSession.kind, 'central_session');
assert.equal(verifiedSession.session_version, 1);

// 1.4 Visit Ticket (Identified)
const visitIdentifiedPayload = {
  kind: 'visit_ticket',
  sub: 'member-uuid-1',
  aud: 'site-uuid-b',
  attempt_id: 'attempt-xyz-789',
  return_path: '/minihompy/#/photos',
  iat: now,
  exp: now + 60,
};
const visitIdentifiedToken = await signToken(visitIdentifiedPayload, SECRET);
const verifiedVisitIdentified = await verifyToken(visitIdentifiedToken, 'visit_ticket', SECRET, now);
assert.equal(verifiedVisitIdentified.kind, 'visit_ticket');
assert.equal(verifiedVisitIdentified.sub, 'member-uuid-1');
assert.equal(verifiedVisitIdentified.aud, 'site-uuid-b');
assert.equal(verifiedVisitIdentified.attempt_id, 'attempt-xyz-789');

// 1.5 Visit Ticket (Anonymous)
const visitAnonPayload = {
  kind: 'visit_ticket',
  sub: null,
  aud: 'site-uuid-b',
  attempt_id: 'attempt-xyz-anon',
  return_path: '/minihompy/#/home',
  iat: now,
  exp: now + 60,
};
const visitAnonToken = await signToken(visitAnonPayload, SECRET);
const verifiedVisitAnon = await verifyToken(visitAnonToken, 'visit_ticket', SECRET, now);
assert.equal(verifiedVisitAnon.sub, null);

console.log('   ✓ All 4 token types issued and verified successfully.');

// --- 2. Tampering & Security Checks ---
console.log('2. Testing tampering detection and security boundaries...');

await assert.rejects(
  verifyToken(loginIntentToken, 'login_intent', WRONG_SECRET, now),
  /토큰 서명이 일치하지 않거나 변조되었습니다/
);

const parts = loginIntentToken.split('.');
const tamperedPayloadPart = parts[1].slice(0, -1) + (parts[1].slice(-1) === 'A' ? 'B' : 'A');
const tamperedToken = `${parts[0]}.${tamperedPayloadPart}.${parts[2]}`;
await assert.rejects(
  verifyToken(tamperedToken, 'login_intent', SECRET, now),
  /토큰 서명이 일치하지 않거나 변조되었습니다/
);

const tamperedSigToken = `${parts[0]}.${parts[1]}.${parts[2].slice(0, -1) + 'X'}`;
await assert.rejects(
  verifyToken(tamperedSigToken, 'login_intent', SECRET, now),
  /토큰 서명이 일치하지 않거나 변조되었습니다/
);

await assert.rejects(
  verifyToken(loginIntentToken, 'central_session', SECRET, now),
  /예상하지 않은 토큰 종류입니다/
);

const headerNone = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
const tokenNone = `${headerNone}.${parts[1]}.${parts[2]}`;
await assert.rejects(
  verifyToken(tokenNone, 'login_intent', SECRET, now),
  /지원하지 않는 서명 알고리즘입니다/
);

console.log('   ✓ Tampering, key mismatch, kind confusion, and alg:none correctly rejected.');

// --- 3. Expiration and Clock Tolerance ---
console.log('3. Testing expiration and 30-second clock tolerance...');

const expiredPayload = {
  kind: 'visit_ticket',
  sub: 'member-1',
  aud: 'site-b',
  attempt_id: 'att-1',
  return_path: '/',
  iat: now - 100,
  exp: now - 40,
};
const expiredToken = await signToken(expiredPayload, SECRET);
await assert.rejects(
  verifyToken(expiredToken, 'visit_ticket', SECRET, now),
  /토큰 유효 시간이 만료되었습니다/
);

const slightClockSkewPayload = {
  kind: 'visit_ticket',
  sub: 'member-1',
  aud: 'site-b',
  attempt_id: 'att-2',
  return_path: '/',
  iat: now - 80,
  exp: now - 20,
};
const slightSkewToken = await signToken(slightClockSkewPayload, SECRET);
const verifiedSkew = await verifyToken(slightSkewToken, 'visit_ticket', SECRET, now);
assert.equal(verifiedSkew.attempt_id, 'att-2');

const futurePayload = {
  kind: 'visit_ticket',
  sub: 'member-1',
  aud: 'site-b',
  attempt_id: 'att-3',
  return_path: '/',
  iat: now + 50,
  exp: now + 110,
};
const futureToken = await signToken(futurePayload, SECRET);
await assert.rejects(
  verifyToken(futureToken, 'visit_ticket', SECRET, now),
  /토큰 발행 시각이 현재 시각보다 미래입니다/
);

console.log('   ✓ Clock tolerance (±30s) and expiration boundaries verified.');

// --- 4. Maximum Size Bounds (4 KiB) ---
console.log('4. Testing token size limit (4 KiB)...');

const largePayload = {
  kind: 'visit_ticket',
  sub: 'member-1',
  aud: 'site-b',
  attempt_id: 'att-large',
  return_path: '/',
  iat: now,
  exp: now + 60,
  data: 'x'.repeat(4500),
};
await assert.rejects(
  signToken(largePayload, SECRET),
  /토큰 크기가 최대 허용치\(4KiB\)를 초과했습니다/
);

console.log('   ✓ 4 KiB size limit strictly enforced.');

// --- 5. URL, Origin and Handle Validation ---
console.log('5. Testing origin, path, handle, and display name validation...');

assert.equal(validateHandle('Henry91_Jung'), 'henry91_jung');
assert.equal(validateHandle('  user.test-1  '), 'user.test-1');
assert.throws(() => validateHandle('a'), /handle은 2~30자의/);
assert.throws(() => validateHandle('a'.repeat(31)), /handle은 2~30자의/);
assert.throws(() => validateHandle('user name'), /handle은 2~30자의/);
assert.throws(() => validateHandle('한글유저'), /handle은 2~30자의/);

assert.equal(validateDisplayName('  홍길동  '), '홍길동');
assert.throws(() => validateDisplayName(''), /표시 이름은 제어 문자 없이/);
assert.throws(() => validateDisplayName('a'.repeat(51)), /표시 이름은 제어 문자 없이/);
assert.throws(() => validateDisplayName('이름\n줄바꿈'), /표시 이름은 제어 문자 없이/);

assert.equal(validateOrigin('https://a.github.io'), 'https://a.github.io');
assert.equal(validateOrigin('https://custom.domain.com:8443'), 'https://custom.domain.com:8443');
assert.throws(() => validateOrigin('http://a.github.io'), /HTTPS 프로토콜만 허용됩니다/);
assert.equal(validateOrigin('http://localhost:3000', true), 'http://localhost:3000');
assert.equal(validateOrigin('http://127.0.0.1:8080', true), 'http://127.0.0.1:8080');
assert.throws(() => validateOrigin('https://a.github.io/minihompy/'), /origin에는 경로, 쿼리, 해시를 포함할 수 없습니다/);
assert.throws(() => validateOrigin('https://user:pass@a.github.io'), /origin에 사용자 인증 정보를 포함할 수 없습니다/);

const basePath = '/minihompy/';
assert.equal(validateRelativePath('/minihompy/#/board', basePath), '/minihompy/#/board');
assert.equal(validateRelativePath('/minihompy/page?tab=1#/diary', basePath), '/minihompy/page?tab=1#/diary');
assert.equal(validateRelativePath('', basePath), '/minihompy/');
assert.throws(() => validateRelativePath('/minihompy/../other', basePath), /등록된 기본 경로\(base_path\)를 벗어날 수 없습니다/);
assert.throws(() => validateRelativePath('/other-path', basePath), /등록된 기본 경로\(base_path\)를 벗어날 수 없습니다/);
assert.throws(() => validateRelativePath('//malicious.com/evil', basePath), /외부 스킴이나 프로토콜 상대 경로는 허용되지 않습니다/);
assert.throws(() => validateRelativePath('javascript:alert(1)', basePath), /외부 스킴이나 프로토콜 상대 경로는 허용되지 않습니다/);
assert.throws(() => validateRelativePath('/minihompy/\\test', basePath), /허용되지 않는 제어 문자 또는 역슬래시가 포함되어 있습니다/);

console.log('   ✓ Origin, relative path, traversal prevention, handle, and display name verified.');

// --- 6. Dynamic CORS Headers ---
console.log('6. Testing dynamic CORS origin validation...');

const allowed = new Set(['https://a.github.io', 'https://b.github.io']);
const corsA = getCorsHeaders('https://a.github.io', allowed);
assert.equal(corsA['Access-Control-Allow-Origin'], 'https://a.github.io');
assert.equal(corsA['Vary'], 'Origin');

const corsDisallowed = getCorsHeaders('https://evil.com', allowed);
assert.equal(corsDisallowed['Access-Control-Allow-Origin'], undefined);
assert.equal(corsDisallowed['Vary'], 'Origin');

const preflightReq = new Request('https://central.api/health', {
  method: 'OPTIONS',
  headers: { 'Origin': 'https://a.github.io' },
});
const preflightRes = handleCorsPreflight(preflightReq, allowed);
assert.equal(preflightRes.status, 204);
assert.equal(preflightRes.headers.get('Access-Control-Allow-Origin'), 'https://a.github.io');

const preflightBadReq = new Request('https://central.api/health', {
  method: 'OPTIONS',
  headers: { 'Origin': 'https://evil.com' },
});
const preflightBadRes = handleCorsPreflight(preflightBadReq, allowed);
assert.equal(preflightBadRes.status, 403);

console.log('   ✓ Dynamic CORS with Vary: Origin and preflight response verified.');

// --- 7. SQL Migration Integrity Check ---
console.log('7. Verifying Central SQL migration schema integrity...');

const migrationSql = await readFile(
  new URL('../supabase/migrations/202609180001_identity.sql', import.meta.url),
  'utf8'
);

assert(migrationSql.includes('create schema if not exists private;'), 'Must create private schema');
assert(migrationSql.includes('revoke all on schema private from public, anon, authenticated;'), 'Must secure private schema');
assert(migrationSql.includes('create table if not exists private.identity_members'), 'Must create identity_members');
assert(migrationSql.includes('create table if not exists private.identity_sites'), 'Must create identity_sites');
assert(migrationSql.includes('create table if not exists private.identity_bindings'), 'Must create identity_bindings');
assert(migrationSql.includes('alter table private.identity_members enable row level security;'), 'Must enable RLS on identity_members');
assert(migrationSql.includes('alter table private.identity_sites enable row level security;'), 'Must enable RLS on identity_sites');
assert(migrationSql.includes('alter table private.identity_bindings enable row level security;'), 'Must enable RLS on identity_bindings');

console.log('   ✓ Central SQL migration schema, RLS, and security revocations verified.');

console.log('\n=============================================================');
console.log('ALL PROTOCOL & CORE SECURITY TESTS PASSED (100% SUCCESS)');
console.log('=============================================================\n');
