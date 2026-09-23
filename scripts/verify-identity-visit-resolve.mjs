/**
 * Minihompy Central Identity API - Step C6 Verification Script
 * Tests:
 * 1. POST /visits/resolve input validation (missing token, missing site_id, inactive site)
 * 2. Token security (tampering, expiration > 60s, audience mismatch 403)
 * 3. Anonymous visit ticket resolution (sub: null -> anonymous status, profile: null)
 * 4. Identified visit ticket resolution (sub: alice -> identified, strict public profile)
 * 5. Invalidation fallback (suspended member -> anonymous fallback)
 * 6. End-to-end integration flow (POST /visits/issue -> POST /visits/resolve)
 */

import assert from 'node:assert/strict';
import { handleIdentityApiRequest } from '../supabase/functions/identity-api/handler.js';
import { signToken } from '../supabase/functions/_shared/tokens.js';

console.log('=== Starting Minihompy Central API Step C6 Verification ===\n');

const SECRET = 'test-central-secret-key-1234567890-minihompy';
const now = Math.floor(Date.now() / 1000);

// Mock DB State
const mockMembers = [
  {
    id: '11111111-1111-4111-8111-111111111111',
    handle: 'alice',
    display_name: '앨리스',
    status: 'active',
    verification_status: 'verified',
    session_version: 1,
    email: 'alice@private.com', // sensitive
  },
  {
    id: '33333333-3333-4333-8333-333333333333',
    handle: 'suspended_user',
    display_name: '정지유저',
    status: 'suspended',
    session_version: 1,
  },
];

const mockSites = [
  {
    id: 'site-aaaa-1111',
    member_id: '11111111-1111-4111-8111-111111111111',
    origin: 'https://alice.github.io',
    base_path: '/minihompy/',
    homepage_url: 'https://alice.github.io/minihompy',
    login_url: 'https://alice.github.io/minihompy/?login=1',
    status: 'active',
    verification_status: 'verified',
  },
  {
    id: 'site-bbbb-2222',
    member_id: '22222222-2222-4222-8222-222222222222',
    origin: 'https://bob.github.io',
    base_path: '/cyworld/',
    homepage_url: 'https://bob.github.io/cyworld',
    login_url: 'https://bob.github.io/cyworld/?login=1',
    status: 'active',
    verification_status: 'verified',
  },
  {
    id: 'site-suspended-9999',
    member_id: '33333333-3333-4333-8333-333333333333',
    origin: 'https://suspended.github.io',
    base_path: '/',
    homepage_url: 'https://suspended.github.io/',
    login_url: 'https://suspended.github.io/?login=1',
    status: 'suspended',
  },
];

function createMockSupabaseClient() {
  return {
    from(table) {
      if (table === 'identity_members') {
        return {
          select(fields) {
            let filtered = [...mockMembers];
            const builder = {
              eq(col, val) {
                filtered = filtered.filter((row) => row[col] === val);
                return builder;
              },
              maybeSingle() {
                return Promise.resolve({ data: filtered[0] || null, error: null });
              },
              then(resolve) {
                resolve({ data: filtered, error: null });
              },
            };
            return builder;
          },
        };
      }
      if (table === 'identity_sites') {
        return {
          select(fields) {
            let filtered = [...mockSites];
            const builder = {
              eq(col, val) {
                filtered = filtered.filter((row) => row[col] === val);
                return builder;
              },
              maybeSingle() {
                return Promise.resolve({ data: filtered[0] || null, error: null });
              },
              then(resolve) {
                resolve({ data: filtered, error: null });
              },
            };
            return builder;
          },
        };
      }
      throw new Error(`Unknown table: ${table}`);
    },
  };
}

const mockSupabase = createMockSupabaseClient();
const allowedOrigins = new Set(['https://alice.github.io', 'https://bob.github.io']);
const options = {
  supabaseClient: mockSupabase,
  allowedOrigins,
  centralSecret: SECRET,
};

// Helper: create visit ticket
async function createVisitTicket(overrides = {}) {
  const payload = {
    kind: 'visit_ticket',
    session_version: 1,
    sub: '11111111-1111-4111-8111-111111111111',
    aud: 'site-bbbb-2222',
    attempt_id: 'attempt-c6-test-123',
    return_path: '/cyworld/#/guestbook',
    iat: now,
    exp: now + 60,
    ...overrides,
  };
  return signToken(payload, SECRET);
}

// --- Test 1: Input Validation ---
console.log('1. Testing input validation for POST /visits/resolve...');
{
  // 1.1 Missing token
  const reqMissingToken = new Request('https://central.api/visits/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ site_id: 'site-bbbb-2222' }),
  });
  const resMissingToken = await handleIdentityApiRequest(reqMissingToken, options);
  assert.equal(resMissingToken.status, 400);

  // 1.2 Missing site_id
  const reqMissingSite = new Request('https://central.api/visits/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ visit_token: 'dummy-token' }),
  });
  const resMissingSite = await handleIdentityApiRequest(reqMissingSite, options);
  assert.equal(resMissingSite.status, 400);

  // 1.3 Inactive site_id
  const reqInactiveSite = new Request('https://central.api/visits/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ visit_token: 'dummy-token', site_id: 'site-suspended-9999' }),
  });
  const resInactiveSite = await handleIdentityApiRequest(reqInactiveSite, options);
  assert.equal(resInactiveSite.status, 400);

  console.log('   ✓ Missing token, missing site_id, and inactive site rejected with 400.');
}

// --- Test 2: Token Security & Audience Mismatch ---
console.log('\n2. Testing token security & cross-site audience check...');
{
  const validTicket = await createVisitTicket();

  // 2.1 Tampered token
  const reqTampered = new Request('https://central.api/visits/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ visit_token: validTicket + 'corrupt', site_id: 'site-bbbb-2222' }),
  });
  const resTampered = await handleIdentityApiRequest(reqTampered, options);
  assert.equal(resTampered.status, 400);

  // 2.2 Expired token (exceeding 30s clock tolerance)
  const expiredTicket = await createVisitTicket({ exp: now - 100 });
  const reqExpired = new Request('https://central.api/visits/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ visit_token: expiredTicket, site_id: 'site-bbbb-2222' }),
  });
  const resExpired = await handleIdentityApiRequest(reqExpired, options);
  assert.equal(resExpired.status, 400);

  // 2.3 Audience mismatch (ticket was issued for site B, but presented to site A)
  const reqAudMismatch = new Request('https://central.api/visits/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ visit_token: validTicket, site_id: 'site-aaaa-1111' }),
  });
  const resAudMismatch = await handleIdentityApiRequest(reqAudMismatch, options);
  assert.equal(resAudMismatch.status, 403);
  const audBody = await resAudMismatch.json();
  assert.match(audBody.error, /대상 사이트가 일치하지 않습니다/);

  console.log('   ✓ Tampered tokens, expired tokens, and cross-site audience spoofing strictly rejected.');
}

// --- Test 3: Anonymous Visit Ticket Resolution ---
console.log('\n3. Testing anonymous visit ticket resolution...');
{
  const anonTicket = await createVisitTicket({
    sub: null,
    attempt_id: 'anon-attempt-xyz',
    return_path: '/cyworld/#/home',
  });
  const reqAnon = new Request('https://central.api/visits/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ visit_token: anonTicket, site_id: 'site-bbbb-2222' }),
  });
  const resAnon = await handleIdentityApiRequest(reqAnon, options);
  assert.equal(resAnon.status, 200);

  const data = await resAnon.json();
  assert.equal(data.status, 'anonymous');
  assert.equal(data.visitor, null);
  assert.equal(data.profile, null);
  assert.equal(data.attempt_id, 'anon-attempt-xyz');
  assert.equal(data.return_path, '/cyworld/#/home');

  console.log('   ✓ Anonymous tickets properly resolve with status: anonymous and null profile.');
}

// --- Test 4: Identified Visit Ticket Resolution ---
console.log('\n4. Testing identified visit ticket resolution & public profile security...');
{
  const validTicket = await createVisitTicket();
  const reqIdentified = new Request('https://central.api/visits/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ visit_token: validTicket, site_id: 'site-bbbb-2222' }),
  });
  const resIdentified = await handleIdentityApiRequest(reqIdentified, options);
  assert.equal(resIdentified.status, 200);

  const data = await resIdentified.json();
  assert.equal(data.status, 'identified');
  assert.equal(data.attempt_id, 'attempt-c6-test-123');
  assert.equal(data.return_path, '/cyworld/#/guestbook');

  // Verify profile fields
  assert.ok(data.profile);
  assert.equal(data.profile.id, '11111111-1111-4111-8111-111111111111');
  assert.equal(data.profile.handle, 'alice');
  assert.equal(data.profile.display_name, '앨리스');
  assert.equal(data.profile.homepage_url, 'https://alice.github.io/minihompy');

  // Strict leakage check: No email, no session_version, no keys
  const allowedKeys = new Set(['id', 'handle', 'display_name', 'homepage_url']);
  for (const key of Object.keys(data.profile)) {
    assert.ok(allowedKeys.has(key), `Forbidden private field leaked: ${key}`);
  }
  assert.equal(data.profile.email, undefined);

  console.log('   ✓ Identified ticket successfully resolved with clean public profile.');
}

// --- Test 5: Suspended Member Fallback ---
console.log('\n5. Testing suspended member fallback to anonymous...');
{
  const suspendedMemberTicket = await createVisitTicket({
    sub: '33333333-3333-4333-8333-333333333333', // suspended_user
  });
  const reqSuspended = new Request('https://central.api/visits/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ visit_token: suspendedMemberTicket, site_id: 'site-bbbb-2222' }),
  });
  const resSuspended = await handleIdentityApiRequest(reqSuspended, options);
  assert.equal(resSuspended.status, 200);

  const data = await resSuspended.json();
  assert.equal(data.status, 'anonymous');
  assert.equal(data.profile, null);

  console.log('   ✓ Suspended member visit ticket safely downgraded to anonymous.');
}

// --- Test 6: End-to-End Flow: Issue -> Resolve ---
console.log('\n6. Testing End-to-End visit flow (POST /visits/issue -> POST /visits/resolve)...');
{
  // 6.1 Create valid central_session
  const sessionPayload = {
    kind: 'central_session',
    sub: '11111111-1111-4111-8111-111111111111',
    session_version: 1,
    iat: now,
    exp: now + 30 * 86400,
  };
  const centralSession = await signToken(sessionPayload, SECRET);

  // 6.2 Issue visit ticket
  const reqIssue = new Request('https://central.api/visits/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      central_session: centralSession,
      target_site_id: 'site-bbbb-2222',
      return_path: '/cyworld/#/board?post_id=77',
      attempt_id: 'e2e-attempt-flow-001',
    }),
  });
  const resIssue = await handleIdentityApiRequest(reqIssue, options);
  assert.equal(resIssue.status, 200);
  const issueData = await resIssue.json();
  assert.ok(issueData.visit_ticket);

  // 6.3 Resolve visit ticket as site B
  const reqResolve = new Request('https://central.api/visits/resolve', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      visit_token: issueData.visit_ticket,
      site_id: 'site-bbbb-2222',
    }),
  });
  const resResolve = await handleIdentityApiRequest(reqResolve, options);
  assert.equal(resResolve.status, 200);
  const resolveData = await resResolve.json();

  assert.equal(resolveData.status, 'identified');
  assert.equal(resolveData.attempt_id, 'e2e-attempt-flow-001');
  assert.equal(resolveData.return_path, '/cyworld/#/board?post_id=77');
  assert.equal(resolveData.profile.handle, 'alice');
  assert.equal(resolveData.profile.homepage_url, 'https://alice.github.io/minihompy');

  console.log('   ✓ End-to-end Issue -> Resolve pipeline completely verified!');
}

console.log('\n=============================================================');
console.log('ALL STEP C6 VISITS RESOLVE TESTS PASSED (100% SUCCESS)');
console.log('=============================================================\n');
