/**
 * Minihompy Central Identity API - Step C2 Verification Script
 * Tests:
 * 1. GET /health with wildcard CORS
 * 2. Origin validation & 403 Forbidden for disallowed origins (OPTIONS & GET)
 * 3. Dynamic CORS headers for allowed origins
 * 4. Path normalization (/functions/v1/identity-api/directory, /identity-api/directory)
 * 5. Parameter validation (missing handle/q, invalid handle, short query)
 * 6. Public visitor profile schema compliance (id, handle, display_name, homepage_url only)
 * 7. Active status filtering (suspended member or site exclusion)
 */

import assert from 'node:assert/strict';
import { handleIdentityApiRequest } from '../supabase/functions/identity-api/handler.js';

console.log('=== Starting Minihompy Central API Step C2 Verification ===\n');

// Mock Database
const mockMembers = [
  {
    id: '11111111-1111-4111-8111-111111111111',
    handle: 'alice',
    display_name: '앨리스',
    status: 'active',
    verification_status: 'verified',
    session_version: 1,
    email: 'alice@secret.com', // sensitive
  },
  {
    id: '22222222-2222-4222-8222-222222222222',
    handle: 'bob',
    display_name: '밥',
    status: 'active',
    verification_status: 'verified',
    session_version: 1,
  },
  {
    id: '33333333-3333-4333-8333-333333333333',
    handle: 'suspended_user',
    display_name: '정지유저',
    status: 'suspended',
    session_version: 1,
  },
  {
    id: '44444444-4444-4444-8444-444444444444',
    handle: 'site_suspended_user',
    display_name: '사이트정지유저',
    status: 'active',
    verification_status: 'verified',
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
    id: 'site-dddd-4444',
    member_id: '44444444-4444-4444-8444-444444444444',
    origin: 'https://suspended.github.io',
    base_path: '/',
    homepage_url: 'https://suspended.github.io/',
    login_url: 'https://suspended.github.io/?login=1',
    status: 'suspended', // site suspended
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
              ilike(col, val) {
                const pattern = val.replace(/%/g, '').toLowerCase();
                filtered = filtered.filter((row) => String(row[col]).toLowerCase().includes(pattern));
                return builder;
              },
              limit(n) {
                filtered = filtered.slice(0, n);
                return builder;
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
              in(col, values) {
                filtered = filtered.filter((row) => values.includes(row[col]));
                return builder;
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
const allowedOrigins = new Set(['https://alice.github.io', 'https://bob.github.io', 'http://localhost:8000']);
const options = {
  supabaseClient: mockSupabase,
  allowedOrigins,
};

// --- Test 1: GET /health ---
console.log('1. Testing GET /health endpoint...');
{
  const req = new Request('https://central.api/health', {
    method: 'GET',
    headers: { Origin: 'https://random-unknown-origin.com' },
  });
  const res = await handleIdentityApiRequest(req, options);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), '*');
  const body = await res.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.identity_protocol, 2);
  assert.ok(body.timestamp);
  console.log('   ✓ Health check returned 200 OK with Access-Control-Allow-Origin: *');
}

// --- Test 2: CORS Preflight & 403 Forbidden for Disallowed Origins ---
console.log('\n2. Testing CORS preflight and origin security...');
{
  // 2.1 Preflight from allowed origin
  const preflightGood = new Request('https://central.api/directory?handle=alice', {
    method: 'OPTIONS',
    headers: { Origin: 'https://alice.github.io' },
  });
  const resGood = await handleIdentityApiRequest(preflightGood, options);
  assert.equal(resGood.status, 204);
  assert.equal(resGood.headers.get('Access-Control-Allow-Origin'), 'https://alice.github.io');
  assert.equal(resGood.headers.get('Vary'), 'Origin');

  // 2.2 Preflight from disallowed origin -> 403
  const preflightBad = new Request('https://central.api/directory?handle=alice', {
    method: 'OPTIONS',
    headers: { Origin: 'https://malicious.com' },
  });
  const resBad = await handleIdentityApiRequest(preflightBad, options);
  assert.equal(resBad.status, 403);

  // 2.3 GET from disallowed origin -> 403 Forbidden
  const getBad = new Request('https://central.api/directory?handle=alice', {
    method: 'GET',
    headers: { Origin: 'https://malicious.com' },
  });
  const resGetBad = await handleIdentityApiRequest(getBad, options);
  assert.equal(resGetBad.status, 403);
  const badBody = await resGetBad.json();
  assert.equal(badBody.error, 'Forbidden: Origin not allowed');

  console.log('   ✓ Allowed origins accept CORS; disallowed origins strictly receive 403 Forbidden.');
}

// --- Test 3: Path Normalization ---
console.log('\n3. Testing path normalization for Supabase Functions...');
{
  const paths = [
    'https://central.api/directory?handle=alice',
    'https://central.api/identity-api/directory?handle=alice',
    'https://central.api/functions/v1/identity-api/directory?handle=alice',
  ];

  for (const urlStr of paths) {
    const req = new Request(urlStr, {
      method: 'GET',
      headers: { Origin: 'https://alice.github.io' },
    });
    const res = await handleIdentityApiRequest(req, options);
    assert.equal(res.status, 200, `Failed for path: ${urlStr}`);
    const body = await res.json();
    assert.equal(body.items.length, 1);
    assert.equal(body.items[0].handle, 'alice');
  }
  console.log('   ✓ Direct, /identity-api, and /functions/v1/identity-api prefixes properly routed.');
}

// --- Test 4: Input Validation for GET /directory ---
console.log('\n4. Testing input validation for GET /directory...');
{
  // 4.1 Missing both handle and q -> 400 Bad Request
  const reqMissing = new Request('https://central.api/directory', {
    method: 'GET',
    headers: { Origin: 'https://alice.github.io' },
  });
  const resMissing = await handleIdentityApiRequest(reqMissing, options);
  assert.equal(resMissing.status, 400);
  const missingBody = await resMissing.json();
  assert.match(missingBody.error, /handle 또는 검색어/);

  // 4.2 Invalid handle format (contains invalid characters) -> 400
  const reqInvalidHandle = new Request('https://central.api/directory?handle=INVALID_HANDLE!', {
    method: 'GET',
    headers: { Origin: 'https://alice.github.io' },
  });
  const resInvalidHandle = await handleIdentityApiRequest(reqInvalidHandle, options);
  assert.equal(resInvalidHandle.status, 400);

  // 4.3 Query too short (< 2 characters) -> 400
  const reqShortQ = new Request('https://central.api/directory?q=a', {
    method: 'GET',
    headers: { Origin: 'https://alice.github.io' },
  });
  const resShortQ = await handleIdentityApiRequest(reqShortQ, options);
  assert.equal(resShortQ.status, 400);

  console.log('   ✓ Input validation prevents full table dump and enforces valid handle/query formats.');
}

// --- Test 5: Exact Handle Query & Public Profile Schema Compliance ---
console.log('\n5. Testing exact handle query and public profile schema...');
{
  const req = new Request('https://central.api/directory?handle=Alice', { // Case insensitivity
    method: 'GET',
    headers: { Origin: 'https://alice.github.io' },
  });
  const res = await handleIdentityApiRequest(req, options);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.items.length, 1);

  const profile = body.items[0];
  assert.equal(profile.id, '11111111-1111-4111-8111-111111111111');
  assert.equal(profile.handle, 'alice');
  assert.equal(profile.display_name, '앨리스');
  assert.equal(profile.homepage_url, 'https://alice.github.io/minihompy');

  // Verify STRICT data leakage prevention (no email, no session_version, no keys)
  const allowedKeys = new Set(['id', 'handle', 'display_name', 'homepage_url']);
  const actualKeys = Object.keys(profile);
  for (const key of actualKeys) {
    assert.ok(allowedKeys.has(key), `Forbidden key leaked in public profile: ${key}`);
  }
  assert.equal(profile.email, undefined);
  assert.equal(profile.session_version, undefined);

  console.log('   ✓ Public visitor profile strictly restricted to (id, handle, display_name, homepage_url).');
}

// --- Test 6: Active Status Filtering ---
console.log('\n6. Testing active status filtering (suspended users and sites)...');
{
  // 6.1 Suspended member -> empty items
  const reqSuspended = new Request('https://central.api/directory?handle=suspended_user', {
    method: 'GET',
    headers: { Origin: 'https://alice.github.io' },
  });
  const resSuspended = await handleIdentityApiRequest(reqSuspended, options);
  assert.equal(resSuspended.status, 200);
  const bodySuspended = await resSuspended.json();
  assert.deepEqual(bodySuspended.items, []);

  // 6.2 Active member with suspended site -> empty items
  const reqSiteSuspended = new Request('https://central.api/directory?handle=site_suspended_user', {
    method: 'GET',
    headers: { Origin: 'https://alice.github.io' },
  });
  const resSiteSuspended = await handleIdentityApiRequest(reqSiteSuspended, options);
  assert.equal(resSiteSuspended.status, 200);
  const bodySiteSuspended = await resSiteSuspended.json();
  assert.deepEqual(bodySiteSuspended.items, []);

  // 6.3 Non-existent user -> empty items
  const reqNotFound = new Request('https://central.api/directory?handle=ghost_user', {
    method: 'GET',
    headers: { Origin: 'https://alice.github.io' },
  });
  const resNotFound = await handleIdentityApiRequest(reqNotFound, options);
  assert.equal(resNotFound.status, 200);
  const bodyNotFound = await resNotFound.json();
  assert.deepEqual(bodyNotFound.items, []);

  console.log('   ✓ Suspended members, suspended sites, and non-existent handles safely return empty items.');
}

// --- Test 7: Search Query (q=...) ---
console.log('\n7. Testing search query (q=...)...');
{
  const req = new Request('https://central.api/directory?q=li', {
    method: 'GET',
    headers: { Origin: 'https://alice.github.io' },
  });
  const res = await handleIdentityApiRequest(req, options);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.items.length, 1);
  assert.equal(body.items[0].handle, 'alice');

  console.log('   ✓ Search query filters active members correctly.');
}

console.log('\n=============================================================');
console.log('ALL STEP C2 DIRECTORY API TESTS PASSED (100% SUCCESS)');
console.log('=============================================================\n');
