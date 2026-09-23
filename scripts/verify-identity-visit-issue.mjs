/**
 * Minihompy Central Identity API - Step C5 Verification Script
 * Tests:
 * 1. POST /visits/issue input validation (missing target_site_id, inactive site, bad path)
 * 2. Anonymous visit ticket issuance (null/missing central_session)
 * 3. Identified visit ticket issuance (valid central_session)
 * 4. Invalidation fallback (expired token, suspended member, session_version mismatch)
 * 5. Fragment URL formatting (#vt=...&path=...) and 60-second TTL
 */

import assert from 'node:assert/strict';
import { handleIdentityApiRequest } from '../supabase/functions/identity-api/handler.js';
import { signToken, verifyToken } from '../supabase/functions/_shared/tokens.js';

console.log('=== Starting Minihompy Central API Step C5 Verification ===\n');

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
    session_version: 3,
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

// Helper: create session token
async function createSessionToken(overrides = {}) {
  const payload = {
    kind: 'central_session',
    sub: '11111111-1111-4111-8111-111111111111',
    session_version: 3,
    iat: now,
    exp: now + 30 * 86400,
    ...overrides,
  };
  return signToken(payload, SECRET);
}

// --- Test 1: Input Validation ---
console.log('1. Testing input validation for POST /visits/issue...');
{
  // 1.1 Missing target_site_id
  const reqMissingSite = new Request('https://central.api/visits/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ return_path: '/cyworld/' }),
  });
  const resMissingSite = await handleIdentityApiRequest(reqMissingSite, options);
  assert.equal(resMissingSite.status, 400);

  // 1.2 Inactive / suspended target site
  const reqSuspendedSite = new Request('https://central.api/visits/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_site_id: 'site-suspended-9999', return_path: '/' }),
  });
  const resSuspendedSite = await handleIdentityApiRequest(reqSuspendedSite, options);
  assert.equal(resSuspendedSite.status, 400);

  // 1.3 Bad return_path (traversal outside base_path)
  const reqBadPath = new Request('https://central.api/visits/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_site_id: 'site-bbbb-2222', return_path: '/evil/path' }),
  });
  const resBadPath = await handleIdentityApiRequest(reqBadPath, options);
  assert.equal(resBadPath.status, 400);

  console.log('   ✓ Missing site, inactive site, and invalid return paths rejected with 400.');
}

// --- Test 2: Anonymous Visit Ticket Issuance ---
console.log('\n2. Testing anonymous visit ticket issuance...');
{
  const reqAnon = new Request('https://central.api/visits/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target_site_id: 'site-bbbb-2222',
      return_path: '/cyworld/#/guestbook',
      attempt_id: 'client-attempt-12345',
    }),
  });
  const resAnon = await handleIdentityApiRequest(reqAnon, options);
  assert.equal(resAnon.status, 200);

  const data = await resAnon.json();
  assert.equal(data.status, 'anonymous');
  assert.equal(data.session_invalid, false);
  assert.equal(data.attempt_id, 'client-attempt-12345');
  assert.equal(data.target_site_id, 'site-bbbb-2222');
  assert.ok(data.visit_ticket);
  assert.ok(data.return_url.includes('#vt='));
  assert.ok(data.return_url.includes('path='));

  // Verify ticket payload
  const ticketPayload = await verifyToken(data.visit_ticket, 'visit_ticket', SECRET, now);
  assert.equal(ticketPayload.kind, 'visit_ticket');
  assert.equal(ticketPayload.sub, null); // anonymous!
  assert.equal(ticketPayload.aud, 'site-bbbb-2222');
  assert.equal(ticketPayload.attempt_id, 'client-attempt-12345');
  assert.equal(ticketPayload.exp - ticketPayload.iat, 60); // 60 seconds TTL

  console.log('   ✓ Anonymous visit ticket safely issued with sub: null and 60-second TTL.');
}

// --- Test 3: Identified Visit Ticket Issuance ---
console.log('\n3. Testing identified visit ticket issuance with valid central_session...');
{
  const sessionToken = await createSessionToken();
  const reqIdentified = new Request('https://central.api/visits/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      central_session: sessionToken,
      target_site_id: 'site-bbbb-2222',
      return_path: '/cyworld/#/board?post_id=99',
      attempt_id: 'guard-attempt-98765',
    }),
  });
  const resIdentified = await handleIdentityApiRequest(reqIdentified, options);
  assert.equal(resIdentified.status, 200);

  const data = await resIdentified.json();
  assert.equal(data.status, 'identified');
  assert.equal(data.session_invalid, false);
  assert.equal(data.attempt_id, 'guard-attempt-98765');
  assert.ok(data.visit_ticket);

  // Verify ticket payload
  const ticketPayload = await verifyToken(data.visit_ticket, 'visit_ticket', SECRET, now);
  assert.equal(ticketPayload.kind, 'visit_ticket');
  assert.equal(ticketPayload.sub, '11111111-1111-4111-8111-111111111111'); // Alice's ID!
  assert.equal(ticketPayload.aud, 'site-bbbb-2222');
  assert.equal(ticketPayload.attempt_id, 'guard-attempt-98765');
  assert.equal(ticketPayload.return_path, '/cyworld/#/board?post_id=99');
  assert.equal(ticketPayload.exp - ticketPayload.iat, 60);

  console.log('   ✓ Identified visit ticket safely issued with Alice sub ID and return path.');
}

// --- Test 4: Invalidation Fallback ---
console.log('\n4. Testing invalidation fallbacks (version mismatch, expired token, suspended user)...');
{
  // 4.1 Session version mismatch (e.g. admin revoked sessions, token has version 1, DB has version 3)
  const oldVersionSession = await createSessionToken({ session_version: 1 });
  const reqOldVersion = new Request('https://central.api/visits/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      central_session: oldVersionSession,
      target_site_id: 'site-bbbb-2222',
      return_path: '/cyworld/',
    }),
  });
  const resOldVersion = await handleIdentityApiRequest(reqOldVersion, options);
  assert.equal(resOldVersion.status, 200);
  const oldData = await resOldVersion.json();
  assert.equal(oldData.status, 'anonymous');
  assert.equal(oldData.session_invalid, true); // tells client/central to clear invalid localStorage

  const oldTicketPayload = await verifyToken(oldData.visit_ticket, 'visit_ticket', SECRET, now);
  assert.equal(oldTicketPayload.sub, null); // downgraded to anonymous

  // 4.2 Expired session token
  const expiredSession = await createSessionToken({ exp: now - 3600 });
  const reqExpired = new Request('https://central.api/visits/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      central_session: expiredSession,
      target_site_id: 'site-bbbb-2222',
      return_path: '/cyworld/',
    }),
  });
  const resExpired = await handleIdentityApiRequest(reqExpired, options);
  assert.equal(resExpired.status, 200);
  const expiredData = await resExpired.json();
  assert.equal(expiredData.status, 'anonymous');
  assert.equal(expiredData.session_invalid, true);

  // 4.3 Suspended user session
  const suspendedSession = await createSessionToken({
    sub: '33333333-3333-4333-8333-333333333333',
    session_version: 1,
  });
  const reqSuspended = new Request('https://central.api/visits/issue', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      central_session: suspendedSession,
      target_site_id: 'site-bbbb-2222',
      return_path: '/cyworld/',
    }),
  });
  const resSuspended = await handleIdentityApiRequest(reqSuspended, options);
  assert.equal(resSuspended.status, 200);
  const suspendedData = await resSuspended.json();
  assert.equal(suspendedData.status, 'anonymous');
  assert.equal(suspendedData.session_invalid, true);

  console.log('   ✓ Invalid/expired/revoked sessions seamlessly fall back to anonymous ticket with session_invalid: true.');
}

console.log('\n=============================================================');
console.log('ALL STEP C5 VISITS ISSUE TESTS PASSED (100% SUCCESS)');
console.log('=============================================================\n');
